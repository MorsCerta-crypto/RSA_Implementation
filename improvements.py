
""" https://fardapaper.ir/mohavaha/uploads/2018/01/Fardapaper-Design-and-implementation-of-an-improved-RSA-algorithm.pdf"""

import random
from keys import DEFAULT_EXPONENT


class SPEEDRSA:
    
    
    def key_gen_speedup(self,p,q,n,sec,b,k,c,e=DEFAULT_EXPONENT):
        
        # compute b distinct primes
        self.get_distinct_primes(b)
        
        phi = (p-1)*(q-1)
        
        d = e ** -1 % phi
        
        r = []
        for i in range(b):
            r.append(d % (p[i] - 1))
        
        
    def get_distinct_primes(self,b):
        # get b distinct primes
        self.primes = []
        for i in range(b):
            while True:
                p = random.randint(2**(i+1), 2**(i+2))
                if self.is_prime_trial_division(p):
                    self.primes.append(p)
                    break
    
    def is_prime_trial_division(self,n):
        pass