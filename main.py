
import time
from typing import Optional
from oaep import OAEP
from keys import KeyGenerator
from primes import PrimeGenerator
from signature import SignaturGenerator

class BasicEncryption:
    
    def __init__(self, n_bits = 60, salt_length = 5) -> None:
        """ generate keys """
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
        
    def decrypt(self, ciphertext:bytes, label:Optional[bytes]=None)->str:
        message = self.encryptor.decrypt(ciphertext,label)
        return message.decode("ascii")
    
    def sign(self,message:str,salt_length=8)->bytes:
        transformed_message = message.encode("ascii")
        signature = self.signer.sign(transformed_message)
        return signature
    
    def verify(self,message:str,signature:bytes)->bool:
        transformed_message = message.encode("ascii")
        valid = self.signer.verify(message=transformed_message,signature=signature)
        return valid
    
    def time(self):
        runs = 100
        message = "This is a test message"
        start = time.time()
        for _ in range(runs):
            cipher = be.encrypt(message)
            ans = be.decrypt(cipher)
            assert ans == message
        end = time.time()
        print("\nTime for ENCRPYTION AND DECRYPTION: ", end-start,"s.\nAVERAGE TIME:",(end-start)/runs, "s")
        
        start = time.time()
        for _ in range(runs):
            signed = be.sign(message)
            verified = be.verify(signature=signed,message=message)
            assert verified==True
        end = time.time()
        print("\nTime for SIGNATURE AND VERIFICATION: ", end-start,"s.\nAVERAGE TIME:",(end-start)/runs, "s")
        
    
    
if __name__=="__main__":
    be = BasicEncryption(n_bits=2048)

    be.time()