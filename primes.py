


from math import ceil, sqrt
from multiprocessing import Pipe, Process
import multiprocessing
from multiprocessing.connection import Connection
import os
import struct
from typing import Optional


class PrimeGenerator:
    
    def __init__(self, n_bits: int = 60) -> None:
        self.n_bits = n_bits
        self.rn_gen = RandomNumberGenerator()
    
    
    def get_primes_p_q(self, n_bits: int, n_processes:int = 8) -> tuple[int, int]:
        """Returns two primes of nbits bits"""
        
        def primes_ok(p:int,q:int)->bool:
            if p == q:
                return False
            # make sure length of n is nbits
            n = p * q
            
            print("Error:", n.bit_length() - (n_bits * 2))
            if n.bit_length() == n_bits * 2:
                return True
            return False
        
        # offset between prime numbers
        offset = n_bits // 8
        p_bits = n_bits + offset
        q_bits = n_bits - offset
        print("Generating prime numbers p and q of", p_bits,"and",q_bits, "bits")
        # Get a random number
        p = self.find_prime_n_processes(p_bits,n_processes)
        q = self.find_prime_n_processes(q_bits,n_processes)

        change_p = False
        while not primes_ok(p=p, q=q):
            # Change p on one iteration and q on the other
            if change_p:
                p = self.find_prime_n_processes(p_bits,n_processes)
            else:
                q = self.find_prime_n_processes(q_bits,n_processes)

            change_p = not change_p
        # p sollte größer als q sein:
        # http://www.di-mgt.com.au/rsa_alg.html#crt
        return max(p,q), min(p,q)
    
    def is_prime(self, number: int) -> bool:
        """Test if n is prime"""
        # negative numbers, 0 or 1
        if number <= 1: return False         
        # 2 and 3
        if number <= 3: return True         
        # divisable by 2 or 3
        if number % 2 == 0 or number % 3 == 0:
            return False
        for i in range(5, ceil(sqrt(number)) + 1, 2):
            if number % i == 0:
                return False
        return True
    
    def is_prime_miller(self,number:int)->int:
        """ checks if number is prime using Miller-Rabin primality test """
        # prime numbers under 10 are known
        if number < 10: return number in [2,3,5,7]
        # if even, it is not prime
        if not (number&1): return False
        # get the rounds based on the number of bits
        num_rounds = self._get_primality_testing_rounds(number)
        return self.primality_test(number,num_rounds)
    
    def _get_primality_testing_rounds(self,number:int)->int:
        """Returns the number of primality testing rounds for a given number"""
        # https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
        bitsize = number.bit_length()
        # probability of not being prime is at most 1/2^rounds
        if bitsize >= 1536: return 3
        if bitsize >= 1024: return 4
        if bitsize >= 512: return 7
        return 9
    
    def primality_test(self,number:int,num_rounds:int)->bool:
        """return a 1/2^num_rounds probability that number is prime"""
         # prevent potential infinite loop when d = 0
        if number < 2:
            return False
        
        # Decompose (n - 1) to write it as (2 ** r) * d
        # While d is even, divide it by 2 and increase the exponent.
        d = number - 1
        exponent = 0

        while not (d & 1):
            exponent += 1
            d >>= 1

        # Test k rounds of Miller-Rabin
        for _ in range(num_rounds):
            # Generate random integer a, where 2 <= a <= (n - 2)
            a = self.rn_gen.get_random_int_below(number - 3) + 1
            x = pow(a, d, number)
            if x == 1 or x == number - 1: continue
            for _ in range(exponent - 1):
                x = pow(x, 2, number)
                # n is composite.
                if x == 1: return False
                # Exit inner loop and continue with next witness.
                if x == number - 1: break
            # If loop doesn't break, n is composite.
            else: return False
        return True
    
    def get_prime(self,n_bits:int)->int:
        """ return a prime number of n_bits bits """#

        while True:
            integer = self.rn_gen.get_random_odd_int(n_bits)
            
            if self.is_prime_miller(integer):
                return integer
    
    def get_prime_pipe(self,n_bits:int, sender:Connection)->None:
        """ return a prime number of n_bits bits """#

        while True:
            integer = self.rn_gen.get_random_odd_int(n_bits)
            
            if self.is_prime_miller(integer):
                if sender:
                    sender.send(integer)
                    return
         
            
            
    def find_prime_n_processes(self,n_bits:int,n_processes:int)->int:
        """ find a prime number of n_bits bits using n_processes processes """
        # create a list of n_processes processes
        if n_processes > multiprocessing.cpu_count():
            n_processes = multiprocessing.cpu_count()
        print(f"using {n_processes} Processes to find prime numbers")
        receiver,sender = Pipe(duplex=False)
        try:
            processes = [Process(target=self.get_prime_pipe, args=(n_bits,sender)) for _ in range(n_processes)]

            for process in processes:
                process.start()
            
            for process in processes:
                process.join()
            
            result = receiver.recv()
        finally:
            receiver.close()
            sender.close()
        
        for process in processes:
            process.terminate()
            
        return result
    
class RandomNumberGenerator:
    
    
    def _get_random_bits(self,n_bits:int)->bytes:
        """ creates a random byte string of n_bits bits """
        # read random n_bits bits
        n_bytes, r_bits = divmod(n_bits, 8)
        # Get the random bytes
        random_data = os.urandom(n_bytes)
        # Add the remaining random bits
        if r_bits > 0:
            #convert unicode to int: ord
            random_value = ord(os.urandom(1))
            # verschiebe alle Bits um 8-r_bits Stellen nach rechts 
            # Achtung: r_bits>8 schiebt nach links!
            random_value >>= 8 - r_bits
            # Addition der zufälligen Daten auf Bytes von random_value
            random_data = struct.pack("B", random_value) + random_data
        return random_data   
    
    def get_random_int(self,n_bits:int)->int:
        """ finds a random integer of n_bits bits """
        random_bits = self._get_random_bits(n_bits)
        value =  int.from_bytes(random_bits, "big", signed=False)
        # set n_bits-1-st Bit to 1
        value |= 1 << (n_bits - 1)
        # if max size is given test if integer is too large
        
        return value
    
    def get_random_int_below(self,max_size:int)->int:
        """ return a random integer between 0 and max_size-1 """
        bits = max_size.bit_length()
        tries = 0
        while True:
            value = self.get_random_int(bits)
            # value matches condition
            if value <= max_size: break
            # every 5 runs decrease bitsize by 1
            if tries % 5 == 0: bits -= 1
            tries += 1
        return value
        
    def get_random_odd_int(self,n_bits:int)->int:  
        """ returns a random odd integer of n_bits bits """  
        value = self.get_random_int(n_bits)
        odd_int = value | 1
        return odd_int
    

            
            
if __name__ == "__main__":
    pg = PrimeGenerator()
    # p, q = pg.get_primes_p_q(40)
    # print(p, q)
    print("running multiprocessing")
    results = pg.find_prime_n_processes(80,8)
    print("results:",results)
    import time

    
    primes = list()
    start = time.time()
    for i in range(2^16,2^128):
        if pg.is_prime(i):
            primes.append(i)
    end = time.time()
    print("is prime took:", end - start)
    print("isprime found", len(primes), "primes")
    
    
    primes = list()
    start = time.time()
    for i in range(2^16,2^128):
        if pg.is_prime_miller(i):
            primes.append(i)
    end = time.time()
    print("is prime took:", end - start)
    print("isprime found", len(primes), "primes")