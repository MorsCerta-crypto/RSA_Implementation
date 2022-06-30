
"""
7. Encryption Schemes
7.1.  RSAES-OAEP
7.1.1.  Encryption Operation - RSAES-OAEP: rsaes_oaep_encrypt
"""

import base64
import os
from typing import Optional
from conversion import integer_to_octet_string, octet_string_to_integer
from crypto import rsa_encryption
from hashf import Hasher
from keys import PublicKey,PrivateKey
from errors import DecryptionError, EncryptionError, DecodingError
from utils import byte_xor



class OAEP:
    """
    7.1.2.  Decryption Operation - RSAES-OAEP: rsaes_oaep_decrypt
    This class implements the RSAES-OAEP decryption operation.
    """
    
    
    def __init__(self, public_key:PublicKey, 
                 private_key:PrivateKey, 
                 hasher:Hasher = Hasher('sha1')):
        """
        Initialize the OAEP class.
        """
        self.public_key = public_key
        self.private_key = private_key
        self.hasher = hasher

    def check_lengths_encrypt(self,M:bytes,L:bytes):
        """
        Checks if lengths of message and label are correct.
        """
        length_message = len(M)
        length_label_hash = len(self.hasher.hash_func(L))
        if length_message > (self.public_key.n_octet_length - length_label_hash - 2):
            raise EncryptionError("message too long")
        
    def check_lengths_decrypt(self, ciphertext:bytes, label:bytes):
        """
        throw decryption exception if 
        1. label is longer than hash length
        2. or cypertext is not equally long as n_octet_length
        3. or n_octet_length is smaller than hash-output * 2 + 2 multiple of hash length
        """
        
        hasher_out_length = len(self.hasher.hash_func(b""))
        hasher_max_input_length = self.hasher.get_hash_input_limit
        
        if len(label)> hasher_max_input_length:
            raise DecryptionError("label is too long")
        
        if len(ciphertext) != self.private_key.n_octet_length:
            raise DecryptionError("ciphertext is too long")
        
        if self.private_key.n_octet_length < (2*hasher_out_length) + 2:
            raise DecryptionError("ciphertext is too short")

    
    
    def encrypt(self,message:bytes,label:bytes=b"")->bytes:
        """
        Encrypts message using public key with label to be associated with the message.
        """
        encoded = self.rsa_oaep_encode(message, label)
        # encrypt with public key and interger representation of message
        rsa_encrypted = rsa_encryption(self.public_key,message = octet_string_to_integer(encoded))
        # convert back to bytes
        return integer_to_octet_string(rsa_encrypted, self.public_key.n_octet_length)
    
        
    def rsa_oaep_encode(self, M:bytes, L:bytes=b"")->bytes:
        """
        Encryption function: encrypts message using public key with label to be associated with the message.
        """
        # check lengths
        self.check_lengths_encrypt(M, L)
        # create hash of label
        label_hash = self.hasher.hash_func(L)
        # find out lenghts
        length_message = len(M)
        length_label_hash = len(label_hash)
        ps = b"\x00" * (self.public_key.n_octet_length - length_message - 2*length_label_hash - 2)
        db = label_hash + ps + b"\x01" + M
        seed = os.urandom(length_label_hash)
        #seed = b'\xc3\x11-\xe9\xb00\x17w\x9cB\xd6\xf3\xaeW\x12\xaee\xa0\xa7\xdc'
        db_mask = self.hasher.gen_mask(seed, 
                                self.public_key.n_octet_length-length_label_hash-1)
        masked_db = byte_xor(db,db_mask)
        seed_mask = self.hasher.gen_mask(masked_db, 
                                  length_label_hash)
        masked_seed = byte_xor(seed,seed_mask)
        return b"\x00" + masked_seed + masked_db
    
    def decrypt(self,ciphertext:bytes,label:Optional[bytes]=None)->bytes:
        """
        Decrypts ciphertext using private key with label to be associated with the message.
        """
        if not label:
            label = b""
        decrypted = self.rsa_oaep_decrypt(ciphertext, label)
        decoded = self.oaep_decoding(decrypted, label)
        return decoded    
    
    def rsa_oaep_decrypt(self, ciphertext:bytes, label:bytes)->bytes:
        """steps for oaep decryption:"""
        # check lengths
        self.check_lengths_decrypt(ciphertext, label)
        # convert cipher to int representation
        cipher_int = octet_string_to_integer(ciphertext)
        # decrypt cipher using private key
        m = pow(cipher_int, self.private_key.d, self.private_key.n)
        # convert m to bytes
        decrypted = integer_to_octet_string(m, self.private_key.n_octet_length)
        # decode enrypted message
        return decrypted
 
    
    def oaep_decoding(self, ciphertext:bytes, label:bytes)->bytes:
        """
        Decryption function: decrypts message using private key.
        """

        lHash = self.hasher.hash_func(label)
        hlen = len(lHash)
        
        Y, maskedSeed, maskedDB = ciphertext[:1], ciphertext[1:1 + hlen], ciphertext[1 + hlen:]
        seedMask = self.hasher.gen_mask(maskedDB, hlen)
        seed = byte_xor(maskedSeed,seedMask)
        dbMask = self.hasher.gen_mask(seed, self.private_key.n_octet_length - hlen - 1)
        DB = byte_xor(maskedDB,dbMask)
        # seperate DB into lHash, PS, M
        _lHash = DB[:hlen]
        # find length of 0x00 padding
        padding = [DB[i] for i in range(hlen, len(DB)) if DB[i] == 0]
        # seperator must be in the next index
        max_index = len(padding) + hlen
        # check if the padding is separated by 1 from the message
        if DB[max_index]!=0x01: # seperator is not in correct place
            print(DB.index(0x01),max_index-DB.index(0x01))
            raise DecodingError()
        if lHash != _lHash:
            raise DecodingError()
        if octet_string_to_integer(Y) != 0:
            raise DecodingError()
            
        return DB[max_index+1:]

    

if __name__ == "__main__":
    
    from cryptography.x509 import load_pem_x509_certificate
    import cryptography.hazmat.primitives.asymmetric.padding as pd
    import cryptography.hazmat.primitives.hashes as h

    #from keys import KeyGenerator
    #k_gen = KeyGenerator()
    #private_key, public_key = k_gen.new_keys(n_bits=1024)
    # private_key = PrivateKey(d=11735087165628077683640682915753637121509919746244075937916619100077935316512993501342040032149388471728377983206593646720826424691463561393641592341965372625814541781670926217902840567482470301228650165406518091523357969962574320676219734859660095967028794489015189980296886270393029716933498933653118809001, p=11897064171352949677367428139275226992095671907288407399327822587720034658254527002262444428004939035532387185069684235188875007835517367774572951980025003, q=11080686001804698685086957605280542649201546458596506970198176871517658266964136168781703388020749110822165607456281239686215712946637901152634969360581403, n=131827632426082846615145601002699025716900173193280425907309130264279678923262265186399259099584242761683700357458095273421803461605150398192507548391392656810113495877114850548780407269362143205278366894555606441351929460085320359931154034119969558322902286062320895135635491392185984170810702938950556819209, e=65537)
    # public_key = PublicKey(n=131827632426082846615145601002699025716900173193280425907309130264279678923262265186399259099584242761683700357458095273421803461605150398192507548391392656810113495877114850548780407269362143205278366894555606441351929460085320359931154034119969558322902286062320895135635491392185984170810702938950556819209, e=65537)
    # hasher = Hasher('sha1')
    # oaep = OAEP(public_key,private_key,hasher)
    # message = b"Hello World!"
    
    # cipher = oaep.encrypt(message,label=b"first label")
    # message = oaep.decrypt(cipher,label=b"first label")
    
    # print(message)
    #
    #
    #
    #
    #
    from conversion import octet_string_to_integer, integer_to_octet_string
    from openssl import read_private_key, read_public_key, load_hazmat_private_key, load_hazmat_public_key
    private_key = read_private_key("RSA_Implementation/private_key.pem")
    public_key = read_public_key("RSA_Implementation/public_key.pem")
    private_key_openssl = load_hazmat_private_key("RSA_Implementation/private_key.pem")
    public_key_openssl = load_hazmat_public_key("RSA_Implementation/public_key.pem")
    #public_key_openssl = private_key_openssl.public_key()
    hasher = Hasher('sha1')
    oaep = OAEP(public_key,private_key,hasher)
    
    # Plaintext
    message = b"Hello World!"
    # Encrytion Implemented
    encrypted = oaep.encrypt(message)
    # Encryption with OpenSSL
    openssl_enc = public_key_openssl.encrypt(message,pd.OAEP(
                        mgf=pd.MGF1(algorithm=h.SHA1()),
                        algorithm=h.SHA1(),
                        label=None
                    ))
    # Make sure the Encoded messages are not equal
    assert encrypted != openssl_enc
    # Decryption Implemented with encoded message from OpenSSL    
    decrypted = oaep.decrypt(openssl_enc,label=b"")
    # Decryption with OpenSSL
    openssl_decrypted = private_key_openssl.decrypt(
                                            encrypted,
                                            padding = pd.OAEP(
                                                mgf=pd.MGF1(algorithm=h.SHA1()),
                                                            algorithm=h.SHA1(),
                                                            label=None))
    
    assert decrypted == openssl_decrypted == message
    print("Kompatibel")