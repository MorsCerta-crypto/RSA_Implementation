from dataclasses import dataclass
import random
from typing import Optional
from errors import KeyGenError
from primes import PrimeGenerator



DEFAULT_EXPONENT = 65537


class KeyGenerator:
    def __init__(self):
        self.private_key = None
        self.prime_generator = PrimeGenerator()
    
    def euclid(self, a: int, b: int) -> int:
        """
        Calculates the greatest common divisor of a and b.
        """
        while b != 0:
            a, b = b, a % b
        return a
    
    def gen_keypair(self, q: int, p:int, exponent: Optional[int] = DEFAULT_EXPONENT) -> tuple:
        """Generate RSA keys of nbits bits. Returns (privateKey, publicKey)."""

        # Regenerate p and q values, until calculate_keys doesn't raise a
        # ValueError.
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        if exponent != None:
            assert self.euclid(phi,exponent) == 1
        else:
            while True:
                exponent = random.randrange(1,phi)
                if self.euclid(phi, exponent) == 1:
                    break
        d = self.inverse(exponent, phi)
        return PrivateKey(d=d,p=p,q=q,n=n), PublicKey(n, e=exponent)
        
    
    def extend_euclid(self, a: int, b: int) -> tuple[int, int, int]:
        """Calculates the extended Euclid algorithm for two integers a and b.
        Returns a tuple (gcd, x, y) where gcd is the greatest common divisor of a and b,
        x and y are the coefficients of the Bezout identity.
        """

        if b == 0:
            return 1,0,a

        x, y, q = self.extend_euclid(b, a % b)

        return y, x - (a // b) * y, q
    
    def inverse(self, a: int, b: int) -> int:
        '''Calculate the Modular Inverse'''
        # d * e = 1 (mod phi) <=> d * e + k * phi = 1
        x, y, q = self.extend_euclid(a, b)
        if q != 1:
            raise KeyGenError("not relative prime")
        else:
            return x % b
        
    def new_keys(self, n_bits: int, exponent: Optional[int] = DEFAULT_EXPONENT, n_processes: int = 8) -> tuple:
        """Generate a new pair of RSA keys of nbits bits. Returns (privateKey, publicKey)."""
        if n_processes < 1:
            raise KeyGenError("n_processes must be at least 1")
        p,q = self.prime_generator.get_primes_p_q(n_bits//2, n_processes=n_processes)
        return self.gen_keypair(p, q, exponent)
        



@dataclass
class PrivateKey:
    """
    Private key class
    """
    d: int 
    p: int
    q: int
    n: int
    
    @property
    def n_octet_length(self)->int:
        """ reuturns the key length in bytes """
        return self.n.bit_length()//8

    

@dataclass
class PublicKey:
    """
    Public key class
    """
    n: int      # n = p*q RSA Modulus
    e :int      # e = public exponent
    
    @property
    def n_octet_length(self) -> int:
        """ return the length in octets of the RSA modulus n """
        return self.n.bit_length() // 8

if __name__ == "__main__":

    rsa = KeyGenerator()
    pub_key, prv_key = rsa.new_keys(n_bits=512, exponent=DEFAULT_EXPONENT, n_processes=8)
    (pub_key)
    print(prv_key)