
from typing import Optional
from oaep import OAEP
from keys import KeyGenerator
from primes import PrimeGenerator
from signature import SignaturGenerator

class BasicEncryption:
    
    def __init__(self, n_bits = 60) -> None:
        """ generate keys """
        self.n_bits = n_bits
        self.key_generator = KeyGenerator()
        self.prime_generator = PrimeGenerator()
        self.private_key,self.public_key = self.get_keys()
        self.encryptor = OAEP(private_key=self.private_key,
                              public_key=self.public_key)
        self.signer = SignaturGenerator(private_key=self.private_key,
                                        public_key=self.public_key)
        

    
    def get_keys(self):
        private_key, public_key = self.key_generator.new_keys(n_bits=self.n_bits)
        return private_key,public_key

    def encrypt(self,message:str, label:Optional[str] = None)->bytes:
        transformed_message = message.encode("ascii")
        if not label: transformed_label = b""
        else: transformed_label = label.encode("ascii")
        ciphertext = self.encryptor.encrypt(transformed_message, transformed_label)
        return ciphertext
        
    def decrypt(self, ciphertext:bytes, label:Optional[bytes]=None)->str:
        message = self.encryptor.decrypt(ciphertext,label)
        return message.decode("ascii")
    
    def sign(self,message:str,salt_length=8)->bytes:
        transformed_message = message.encode("ascii")
        emBits = self.private_key.n.bit_length() - 1
        signature = self.signer.sign(transformed_message,salt_length=salt_length,emBits=emBits)
        return signature
    
    def verify(self,message:str,signature:bytes)->bool:
        transformed_message = message.encode("ascii")
        valid = self.signer.verify(message=transformed_message,signature=signature)
        return valid
    
    
    
if __name__=="__main__":
    message = "Hello World"
    be = BasicEncryption(n_bits=1024)
    cipher = be.encrypt(message)
    ans = be.decrypt(cipher)
    
    signed = be.sign(message)
    verfied = be.verify(signature=signed,message=message)
    print("decoded:",ans)