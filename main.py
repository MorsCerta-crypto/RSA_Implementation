
from typing import Optional
from oaep import OAEP
from keys import KeyGenerator
from primes import PrimeGenerator

class BasicEncryption:
    
    def __init__(self, keylength = 60) -> None:
        """ generate keys """
        self.keylength = keylength
        self.key_generator = KeyGenerator()
        self.prime_generator = PrimeGenerator()
        self.private_key,self.public_key = self.get_keys()
        self.encryptor = OAEP(private_key=self.private_key,
                              public_key=self.public_key)
        


    def gen_pq(self)->tuple[int,int]:
        p,q = self.prime_generator.get_primes_p_q(n_bits=self.keylength)
        print("p,q",p,q)
        return p,q
    
    def get_keys(self):
        p,q = self.gen_pq()
        private_key, public_key = self.key_generator.gen_keypair(p=p,q=q)
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
    
    
    
if __name__=="__main__":
    be = BasicEncryption(keylength=80)
    cipher = be.encrypt("Hello")
    ans = be.decrypt(cipher)
    print("decoded:",ans)