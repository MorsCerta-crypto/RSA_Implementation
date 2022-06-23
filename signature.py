"""
5.2 Signature and Verification Primitives
5.2.1.  RSASP1 - RSA Signature Primitive: rsa_sign
5.2.2.  RSAVP1 - RSA Verification Primitive: rsa_verify
"""


from math import ceil
from keys import PrivateKey,PublicKey
from errors import EncodingError, InvalidSignatureError
from conversion import octet_string_to_integer,integer_to_octet_string
from hashf import Hasher  
from primes import RandomNumberGenerator
from utils import byte_xor, set_bit

MAX_BIT_LENGTH = 2^256

class SignaturGenerator:
    
    def __init__(self,private_key: PrivateKey, public_key: PublicKey):
        self.hasher = Hasher("sha1")
        self.randint_gen = RandomNumberGenerator()
        self.private_key = private_key
        self.public_key = public_key
    
    def sign(self,message:bytes,salt_length:int,emBits:int)->bytes:
        """
        Signature function (RSA-PSS) signs message using private key.
        """
        encoded = self.emsa_pss_encode(message,emBits=emBits,sLen=salt_length)
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
    
    def emsa_pss_verify(self,message:bytes,signature:bytes,sLen:int=8)->bool:
        """
        Verifies the signature of the message.
        """
        # step 1
        # if length of message is greater than the hash input limit, retrun "inconsistent"
        if len(message) > self.hasher.get_hash_input_limit:
            raise ValueError("inconsistent")
        # step 2
        message_hash = self.hasher.hash_func(message)
        hLen = len(message_hash)
        emBits = octet_string_to_integer(signature).bit_length()
        emLen = ceil(emBits/8) 
        # step 3
        if emLen < (self.hasher.output_length + sLen + 2):
            raise ValueError("inconsistent")
        # step 4
        if signature[-1:] != b'\xbc':
            raise ValueError("inconsistent")
        # step 5
        split_len = emLen-hLen-1
        maskedDB = signature[:split_len]
        H = signature[split_len:split_len+hLen]
        # step 6
        # binary string of masked_db
        bin_masked_db = bin(maskedDB[0])
        #number of zeros that are expected
        zero_string = "0"*(8*emLen - emBits)
        # check if the number of zeros is correct
        if not bin_masked_db.startswith(zero_string):
            raise ValueError("inconsistent")
        
        # step 7
        dbMask = self.hasher.gen_mask(H,emLen - hLen -1)
        # step 8
        DB = byte_xor(maskedDB,dbMask)
        # step 9
        lmask = 0
        for _ in range((8*emLen)-emBits):
            lmask = lmask >> 1 | 0x80
        # set bits to zero and append to masked_db   
        DB = integer_to_octet_string(DB[0]&~lmask,1) + DB[1:]
        # step 10
        length_zeros = emLen - hLen - sLen - 2
        
        db_list = list(DB)[:length_zeros]
        for value in db_list:
            if not value == 0:
                raise ValueError("inconsistent")
        
        next_values = DB[length_zeros]
        if next_values != 1:
            raise ValueError("inconsistent")
        
        # step 11
        salt = DB[-sLen:]
        # step 12
        M_ = b"\x00" * 8 + message_hash + salt
        # step 13
        H_ = self.hasher.hash_func(M_)
        # step 14
        if H != H_:
            raise ValueError("inconsistent")
        
        return True
        
    
    def emsa_pss_encode(self,message:bytes,emBits:int,sLen:int=8)->bytes:
        """
        Encodes message using EMSA-PSS.
        """
        assert emBits > ((8 * self.hasher.output_length) + (8 * sLen) + 9)
        assert emBits.bit_length() <= MAX_BIT_LENGTH
        
        if len(message) > self.hasher.get_hash_input_limit:
            raise EncodingError("message too long")
        
        mHash = self.hasher.hash_func(message)
        emLen = ceil(emBits/8)
        
        if emLen < (self.hasher.output_length + sLen + 2):
            raise EncodingError()
        
        random_salt = self.randint_gen._get_random_bits(sLen*8)
        _message = b"\x00" * 8 + mHash + random_salt
        _hash = self.hasher.hash_func(_message)
        
        ps = b"\x00" * (emLen - sLen - self.hasher.output_length - 2)
        db = ps + b"\x01" + random_salt
        
        #assert len(db) == (emLen - self.hasher.output_length - 1)
        dbMask = self.hasher.gen_mask(_hash,emLen - self.hasher.output_length - 1)
        masked_db = byte_xor(db, dbMask)
        
        lmask = 0
        for _ in range((8*emLen)-emBits):
            lmask = lmask >> 1 | 0x80
        # set bits to zero and append to masked_db   
        masked_db = integer_to_octet_string(masked_db[0]&~lmask,1) + masked_db[1:]
        encoded_message = masked_db + _hash + b"\xbc"
        
        byte_length_message = ceil(octet_string_to_integer(encoded_message).bit_length()/8)
        max_byte_length = ceil(MAX_BIT_LENGTH/8)
        assert byte_length_message == emLen
        return encoded_message
    
if __name__ == "__main__":
    print("Signature Generator")
    from keys import KeyGenerator
    key_gen = KeyGenerator()
    d = 58779556182818738985986705225610661686329506542428894442645744302725530691009890590870011667581511671292654634043341751985805234217673686768024575517293113812247521040485962275309835477719534415625922345556511910861441495386930853169799551016774891012483392240899599379705790574930347658844076243628008827321
    p = 617876237888196012858393099267522069639213486113619473053497484282649554261637088998713590804835147379133713797266162140867244360067453
    q = 160508708975866499036717045208421794007876132466659291439412556580671489272109445462119195038230477195107406303319373369121427728954736432538640278754340031368275267278628567
    e = 65537
    n = 99174517250299711580583649573175242255669666871023413616035685821582347009672661731942639720368908951458607902358172345078745659061444446730577178777624305102938825970138073309727899452703453274911167794242325995553531331009122599377432863654353475567653086474811947212796569343366961268620824869377452729851
    
    print("generating keys")
    private_key,public_key = key_gen.gen_keypair(p=p,q=q,exponent=e)
    #private_key,public_key = key_gen.new_keys(n_bits=1024,exponent=e)
    print(private_key,public_key)
    s = SignaturGenerator(private_key=private_key,
                          public_key=public_key)
    print("signing message")
    emBits = n.bit_length() -1
    res = s.sign(message=b"Cryptographie",salt_length=8,emBits=emBits)
    
    verify = s.verify(signature=res,message=b"Cryptographie")
    print("valid?:",verify)