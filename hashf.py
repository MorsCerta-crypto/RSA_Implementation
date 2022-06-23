
import hashlib
from typing import Callable, Optional
from conversion import integer_to_octet_string
from math import ceil

HASH_LIMITATIONS = {
    "sha1": 2^61 - 1,
    "md5": 2^64 - 1
}

class Hasher:
    """ 
    this class can be extended with other hash functions that can be selected with hash_name
    it is used to generate hashes and masks for RSA encryption
    """
    def __init__(self,hash_name:str, hash_func:Optional[Callable]=None):
        self.hash_name = hash_name
        if hash_name == "sha1":
            self.hash_func = self.sha1
        elif not hash_func:
            raise ValueError("hash_func not defined")
        else:
            raise NotImplementedError(f"{hash_name} not implemented")
        
        self.output_length = len(self.hash_func(b''))
    
    @property
    def get_hash_input_limit(self) -> int:
        limit = HASH_LIMITATIONS.get(self.hash_name, None)
        if not limit:
            raise ValueError(f"{self.hash_name} has no limit implemented")
        return limit
        
    def sha1(self,message):
        hasher = hashlib.sha1()
        hasher.update(message)
        return hasher.digest()
    
    def gen_mask(self, seed: bytes, mlen: int) -> bytes:
        """ MGF1 mask generation function with SHA-1 """
        t = b''
        hlen = len(self.hash_func(b''))
        for c in range(0, ceil(mlen / hlen)):
            octet_c = integer_to_octet_string(c, 4)
            t += self.hash_func(seed + octet_c)
        return t[:mlen]

    
    