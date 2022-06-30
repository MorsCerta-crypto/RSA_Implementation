"""
5.2 Signature and Verification Primitives
5.2.1.  RSASP1 - RSA Signature Primitive: rsa_sign
5.2.2.  RSAVP1 - RSA Verification Primitive: rsa_verify
"""


from math import ceil
from typing import Optional
from keys import PrivateKey,PublicKey
from errors import EncodingError, InvalidSignatureError
from conversion import octet_string_to_integer,integer_to_octet_string
from hashf import Hasher  
from primes import RandomNumberGenerator
from utils import byte_xor, size

MAX_BIT_LENGTH = 2^256

class SignaturGenerator:
    
    def __init__(self,private_key: PrivateKey, public_key: PublicKey, salt_length:int=8):
        self.hasher = Hasher("sha1")
        self.randint_gen = RandomNumberGenerator()
        self.private_key = private_key
        self.public_key = public_key
        self.salt_length = salt_length
        self.em_bits = size(self.private_key.n) -1
        self.h_len = self.hasher.output_length
    
    def sign(self,message:bytes)->bytes:
        """
        Signature function (RSA-PSS) signs message using private key.
        """
        #emBits = size(self.private_key.n)
        encoded = self.emsa_pss_encode(message)
        converted = octet_string_to_integer(encoded)
        signature = self.rsa_sign(converted)
        return integer_to_octet_string(signature,self.private_key.n_octet_length)
    
    def rsa_sign(self,message:int)->int:
        """
        Returns the signature of the message.
        """
        assert isinstance(message,int), "message must be an integer"
        if message>=self.private_key.n or message<0:
            raise ValueError("message representative out of range")
        return pow(message,self.private_key.d,self.private_key.n)


    def rsa_validate(self,signature:int)->int:
        """
        Returns the message of the signature
        """
        assert isinstance(signature,int), "signature must be an integer"
        if signature>=self.public_key.n or signature<0:
            raise ValueError("signature representative out of range")
        return pow(signature,self.public_key.e,self.public_key.n)
    
    def verify(self,message:bytes,signature:bytes)->bool:
        """
        Verifies the signature of the message. True is returned if the signature is valid.
        """
        if len(signature) != self.public_key.n_octet_length:
            raise InvalidSignatureError()
        converted = octet_string_to_integer(signature)
        try:
            validated = self.rsa_validate(converted)
        except ValueError:
            raise InvalidSignatureError()
        decoded = integer_to_octet_string(validated,self.public_key.n_octet_length)
        
        
        verified = self.emsa_pss_verify(message,decoded)
        if verified:
            return True
        return False
    
    def emsa_pss_verify(self,message:bytes,signature:bytes)->bool:
        """
        Verifies the signature of the message.
        """
        # step 1
        # if length of message is greater than the hash input limit, retrun "inconsistent"
        if len(message) > self.hasher.get_hash_input_limit:
            raise ValueError("inconsistent")
        # step 2
        message_hash = self.hasher.hash_func(message)
        # aemBits = octet_string_to_integer(signature).bit_length()
        # emBits = aemBits
            
        emLen = ceil(self.em_bits/8.0) 
        
        if self.em_bits < self.h_len*8 + self.salt_length*8 + 9:
            raise ValueError("inconsistent")
        # step 3
        if emLen < (self.h_len + self.salt_length + 2):
            raise ValueError("inconsistent")
        # step 4
        if signature[-1:] != b'\xbc':
            raise ValueError("inconsistent")
        # step 5
        split_len = emLen-self.h_len-1
        maskedDB = signature[:split_len]
        H = signature[split_len:split_len+self.h_len]
        # step 6
        num_zeros = 8 * emLen - self.em_bits
        bit_mask = int('1'*num_zeros + '0'*(8-num_zeros), 2)
        # check if the number of zeros is correct
        if maskedDB[0]&bit_mask != 0:
            raise ValueError("inconsistent")
        
        # step 7
        dbMask = self.hasher.gen_mask(H,emLen - self.h_len -1)
        # step 8
        DB = byte_xor(maskedDB,dbMask)

        #step 9
        #Set the leftmost 8emLen - emBits bits of the leftmost octet in DB to zero.
        numzeros = 8 * emLen - self.em_bits
        bitmask  = int('0'*numzeros + '1'*(8-numzeros), 2)

        # set bits to zero and append to masked_db   
        DB = integer_to_octet_string(DB[0]&bitmask,1) + DB[1:]
        #step 9
        
        # step 10
        length_zeros = emLen - self.h_len - self.salt_length - 2
        
        db_list = list(DB)[:length_zeros]
        for value in db_list:
            if not value == 0:
                raise ValueError("inconsistent")
        # get index of db_list where value is 1
        index = list(DB).index(1)
        #print(index,db_list[length_zeros-5:len(db_list)], len(db_list))
        next_values = DB[length_zeros]
        if next_values != 1:
            raise ValueError("inconsistent")
        
        # step 11
        if self.salt_length == 0:
            salt = b""
        salt = DB[-self.salt_length:]
        # step 12
        M_ = b"\x00" * 8 + message_hash + salt
        # step 13
        H_ = self.hasher.hash_func(M_)
        # step 14
        if H != H_:
            raise ValueError("inconsistent")
        return True
        
    
    def emsa_pss_encode(self,message:bytes)->bytes:
        """
        Encodes message using EMSA-PSS.
        """
        # if emBits is None:
        #     emBits =  (8*self.hasher.output_length) + 8 * self.salt_length + 9
        #     #Round to the next byte
        #     emBits = int(ceil(emBits / 8.0)) * 8
        assert self.em_bits > ((8 * self.h_len) + (8 * self.salt_length) + 9)
        assert self.em_bits.bit_length() <= MAX_BIT_LENGTH
        
        if len(message) > self.hasher.get_hash_input_limit:
            raise EncodingError("message too long")
        
        mHash = self.hasher.hash_func(message)
        emLen = ceil(self.em_bits/8)
        
        if emLen < (self.h_len + self.salt_length + 2):
            raise EncodingError()
        
        random_salt = self.randint_gen._get_random_bits(self.salt_length*8)
        _message = b"\x00" * 8 + mHash + random_salt
        _hash = self.hasher.hash_func(_message)
        
        ps = b"\x00" * (emLen - self.salt_length - self.h_len - 2)
        db = ps + b"\x01" + random_salt
        
        #assert len(db) == (emLen - self.hasher.output_length - 1)
        dbMask = self.hasher.gen_mask(_hash,emLen - self.h_len - 1)
        masked_db = byte_xor(db, dbMask)
        
        numzeros = (8*emLen)-self.em_bits
        intmask = int('0'*numzeros + '1'*(8-numzeros), 2)
        #print("binmask", bin(intmask))
        # set bits to zero and append to masked_db   
        masked_db = integer_to_octet_string(masked_db[0]&intmask,1) + masked_db[1:]
        encoded_message = masked_db + _hash + b"\xbc"
        
        byte_length_message = ceil(octet_string_to_integer(encoded_message).bit_length()/8)
        #max_byte_length = ceil(MAX_BIT_LENGTH/8)
        #print(byte_length_message, emLen)
        #assert byte_length_message == emLen, f"{byte_length_message}, {emLen} {octet_string_to_integer(encoded_message).bit_length()} != {self.em_bits}"
        return encoded_message
    
if __name__ == "__main__":
    # print("Signature Generator")
    # from keys import KeyGenerator
    # key_gen = KeyGenerator()
    # d = 58779556182818738985986705225610661686329506542428894442645744302725530691009890590870011667581511671292654634043341751985805234217673686768024575517293113812247521040485962275309835477719534415625922345556511910861441495386930853169799551016774891012483392240899599379705790574930347658844076243628008827321
    # p = 617876237888196012858393099267522069639213486113619473053497484282649554261637088998713590804835147379133713797266162140867244360067453
    # q = 160508708975866499036717045208421794007876132466659291439412556580671489272109445462119195038230477195107406303319373369121427728954736432538640278754340031368275267278628567
    # e = 65537
    # n = 99174517250299711580583649573175242255669666871023413616035685821582347009672661731942639720368908951458607902358172345078745659061444446730577178777624305102938825970138073309727899452703453274911167794242325995553531331009122599377432863654353475567653086474811947212796569343366961268620824869377452729851
    
    # print("generating keys")
    # message = b"Crypto"
    # private_key,public_key = key_gen.gen_keypair(p=p,q=q,exponent=e)
    # #private_key,public_key = key_gen.new_keys(n_bits=1024,exponent=e)
    # print(private_key,public_key)
    # s = SignaturGenerator(private_key=private_key,
    #                       public_key=public_key,
    #                       salt_length=1)
    # print("signing message")
    # res = s.sign(message=message)
    
    # verify = s.verify(signature=res,message=message)
    # print("valid?:",verify)
    
    import cryptography.hazmat.primitives.asymmetric.padding as pd
    import cryptography.hazmat.primitives.hashes as h
    from conversion import octet_string_to_integer, integer_to_octet_string
    from openssl import read_private_key, read_public_key, load_hazmat_private_key, load_hazmat_public_key
    private_key = read_private_key("RSA_Implementation/private_key.pem")
    public_key = read_public_key("RSA_Implementation/public_key.pem")
    private_key_openssl = load_hazmat_private_key("RSA_Implementation/private_key.pem")
    public_key_openssl = load_hazmat_public_key("RSA_Implementation/public_key.pem")
    #public_key_openssl = private_key_openssl.public_key()
    
    s = SignaturGenerator(private_key=private_key,
                          public_key=public_key,
                          salt_length=8)
    # Plaintext
    message = b"Hello World!"
    # Encrytion Implemented
    sign = s.sign(message)
    # Encryption with OpenSSL
    openssl_sign = private_key_openssl.sign(message,
                                            pd.PSS(
                                                    mgf=pd.MGF1(h.SHA1()),
                                                    salt_length=8,
                                                ),  # type: ignore
                                           h.SHA1()) # type: ignore
    # Make sure the Encoded messages are not equal
    assert sign != openssl_sign
    # Decryption Implemented with encoded message from OpenSSL    
    verified = s.verify(message,openssl_sign)
    # Decryption with OpenSSL
    public_key_openssl.verify(
                            sign,
                            message,
                            pd.PSS(
                                    mgf=pd.MGF1(algorithm=h.SHA1()),
                                    salt_length = 8),# type: ignore
                            h.SHA1()) # type: ignore
    
    assert verified == True
    print("Kompatibel")