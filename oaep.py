
"""
7. Encryption Schemes
7.1.  RSAES-OAEP
7.1.1.  Encryption Operation - RSAES-OAEP: rsaes_oaep_encrypt
"""

import os
from typing import Optional
from conversion import integer_to_octet_string, octet_string_to_integer
from crypto import rsa_encryption
from hashf import Hasher
from keys import PublicKey,PrivateKey
from errors import DecryptionError, EncryptionError, DecodingError
from utils import byte_xor



class OAEP:
    
    
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
        seed = b'\xc3\x11-\xe9\xb00\x17w\x9cB\xd6\xf3\xaeW\x12\xaee\xa0\xa7\xdc'
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
        m = pow(cipher_int, private_key.d, private_key.n)
        # convert m to bytes
        decrypted = integer_to_octet_string(m, private_key.n_octet_length)
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
            raise DecodingError()
        if lHash != _lHash:
            raise DecodingError()
        if octet_string_to_integer(Y) != 0:
            raise DecodingError()
            
        return DB[max_index+1:]

    

if __name__ == "__main__":

    from keys import KeyGenerator
    k_gen = KeyGenerator()
    private_key, public_key = k_gen.new_keys(n_bits=2048)
    hasher = Hasher('sha1')
    oaep = OAEP(public_key,private_key,hasher)
    message = b"Hello World!"
    
    cipher = oaep.encrypt(message)
    message = oaep.decrypt(cipher)
    
    print(message)