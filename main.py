
import time
from typing import Optional
from rsa_logic.oaep import OAEP
from rsa_logic.keys import KeyGenerator
from utils.primes import PrimeGenerator
from rsa_logic.signature import SignaturGenerator

class RSA:
    
    def __init__(self, n_bits = 60, salt_length = 5) -> None:
        """ generate keys and use oaep and ssl padding for encryption """
        self.n_bits = n_bits
        self.key_generator = KeyGenerator()
        self.prime_generator = PrimeGenerator()
        
        self.private_key,self.public_key = self.get_keys()
        
        self.encryptor = OAEP(private_key=self.private_key,
                              public_key=self.public_key)
        
        self.signer = SignaturGenerator(private_key=self.private_key,
                                        public_key=self.public_key,
                                        salt_length=salt_length)
        

    
    def get_keys(self):
        start = time.time()
        private_key, public_key = self.key_generator.new_keys(n_bits=self.n_bits)
        end = time.time()
        print("Time for Key Generation: ", end-start, "s for ", self.n_bits, "bits")
        return private_key,public_key

    def encrypt(self,message:str, label:Optional[str] = None)->bytes:
        transformed_message = message.encode("ascii")
        if not label: transformed_label = b""
        else: transformed_label = label.encode("ascii")
        ciphertext = self.encryptor.encrypt(transformed_message, transformed_label)
        return ciphertext
        
    def decrypt(self, ciphertext:bytes, label:Optional[str]=None)->str:
        if not label: transformed_label = b""
        else: transformed_label = label.encode("ascii")
        message = self.encryptor.decrypt(ciphertext,transformed_label)
        return message.decode("ascii")
    
    def sign(self,message:str)->bytes:
        transformed_message = message.encode("ascii")
        signature = self.signer.sign(transformed_message)
        return signature
    
    def verify(self,message:str,signature:bytes)->bool:
        transformed_message = message.encode("ascii")
        valid = self.signer.verify(message=transformed_message,signature=signature)
        return valid
    
if __name__ == "__main__":
    rsa = RSA(n_bits=2048,salt_length=8)
    message = "Hello World"
    # Encryption
    cipher_text = rsa.encrypt(message,label="test")
    #Decryption
    plain_text = rsa.decrypt(cipher_text,label="test")
    # Result has to be the same as the original message
    assert plain_text == message,"Decryption failed"
    #Signature
    sign = rsa.sign(message)
    # Verification
    valid = rsa.verify(message,sign)
    # signature has to be valid
    assert valid, "Signature is not valid"
    print("Encryption and Decryption/ Signing and Validation successful")