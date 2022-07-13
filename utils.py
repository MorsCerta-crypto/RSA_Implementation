
import numpy as np


def byte_xor(data: bytes, mask: bytes) -> bytes:
        '''Byte-by-byte XOR of two byte arrays'''
        masked = b''
        ldata = len(data)
        lmask = len(mask)
        for i in range(max(ldata, lmask)):
            if i < ldata and i < lmask:
                masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
            elif i < ldata:
                masked += data[i].to_bytes(1, byteorder='big')
            else:
                break
        return masked
    

def modular_pow(base: int, exponent: int, modulus: int) -> int:
    """
    Computes base^exponent mod modulus modular.
    """
    if modulus == 1:
        return np.zeros_like(base)
    
    result = np.ones_like(base)
    base = base % modulus
    if 1 & exponent:
        r = base
    while exponent:
        if exponent % 2 == 1:
            result = (result*base) % modulus
        exponent >>= 1
        base = (base * base) % modulus
    return result

def modexp_lr_k_ary(a, b, n, k=5):
    """ Compute a ** b (mod n)

        K-ary LR method, with a customizable 'k'.
    """
    base = 2 << (k - 1)

    # Precompute the table of exponents
    table = [1] * base
    for i in range(1, base):
        table[i] = table[i - 1] * a % n

    # Just like the binary LR method, just with a
    # different base
    #
    r = 1
    for digit in reversed(_digits_of_n(b, base)):
        for i in range(k):
            r = r * r % n
        if digit:
            r = r * table[int(digit)] % n

    return r

def _digits_of_n(n, b):
    """ Return the list of the digits in the base 'b'
        representation of n, from LSB to MSB
    """
    digits = []

    while n:
        digits.append(n % b)
        n = n//b

    return digits


def set_bit(bit_array, index, to_value):
    """Set the index:th bit of v to 1 if x is truthy, else to 0, and return the new value."""
    mask = 1 << index   # Compute mask, an integer with just bit 'index' set.
    bit_array &= ~mask          # Clear the bit indicated by the mask (if x is False)
    if to_value:
        bit_array |= mask         # If x was True, set the bit indicated by the mask.
    return bit_array            # Return the result, we're done.

def size (N):
    """size(N:long) : int
    Returns the size of the number N in bits.
    """
    bits = 0
    while N >> bits:
        bits += 1
    return bits


def byte_xor_conversion(b1: bytes, b2: bytes) -> bytes:
    """Byte-by-byte XOR of two byte arrays"""
    int1 = int.from_bytes(b1, byteorder='big')
    int2 = int.from_bytes(b2, byteorder='big')
    xor = int1 ^ int2
    return xor.to_bytes(min(len(b1),len(b2)), byteorder='big')

def sxor(s1,s2):    
    """XOR two strings together"""
    return bytes([a ^ b for a,b in zip(s1,s2)])





 