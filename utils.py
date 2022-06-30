
import os


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
    r = 1
    if 1 & exponent:
        r = base
    while exponent:
        exponent >>= 1
        base = (base * base) % modulus
        if exponent & 1: r = (r * base) % modulus
    return r

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

def byte_xor2(b1: bytes, b2: bytes) -> bytes:
    """Byte-by-byte XOR of two byte arrays"""
    xor = bytes(a ^ b for a, b in zip(b1, b2))
    if len(b1)==len(b2):
        return xor
    else: 
        max_bytes = max(b1,b2,key=len)
        min_len = min(len(b1), len(b2))
        xor += max_bytes[min_len:]
        return xor


def byte_xor3(b1: bytes, b2: bytes) -> bytes:
    """Byte-by-byte XOR of two byte arrays"""
    l1,l2 = len(b1),len(b2)
    l = min(l1,l2)
    int1 = int.from_bytes(b1[l1-l:], byteorder='big')
    int2 = int.from_bytes(b2[l2-l:], byteorder='big')
    xor = int1 ^ int2
    max_b = max(b1,b2,key=len)
    bytes_string = max_b[:abs(l1-l2)] + xor.to_bytes(min(l1,l2), byteorder='big')

    return bytes_string 

if __name__ == "__main__":
    from conversion import octet_string_to_integer, integer_to_octet_string
    b1 = os.urandom(128)
    b2 = os.urandom(128)
    print(byte_xor(b1, b2), byte_xor2(b1, b2), byte_xor3(b1, b2))
    assert byte_xor(b1, b2) == byte_xor2(b1, b2) 
    assert byte_xor(b1,b2) == byte_xor3(b1, b2)
    
    runs = 1000
    import time
    start = time.time()
    for run in range(runs):
        bxor = byte_xor(b1, b2)
    end = time.time()
    print("AVG time fpr byte_xor1:", (end - start) / runs)
    
    start = time.time()
    for run in range(runs):
        bxor = byte_xor2(b1, b2)
    end = time.time()
    print("AVG time fpr byte_xor2:", (end - start) / runs)
    
    start = time.time()
    for run in range(runs):
        bxor = byte_xor3(b1, b2)
    end = time.time()
    print("AVG time fpr byte_xor3:", (end - start) / runs)
    
    bxor = byte_xor2(b1,b2)
    int_b2 = octet_string_to_integer(b2)
    int_b1 = octet_string_to_integer(b1)
    xor = int_b1^int_b2
    b2_xor = integer_to_octet_string(xor, len(b1))
    
    assert b2_xor == bxor
    import time

    # base = 100_101
    # powers = list()
    # start = time.time()
    # for i in range(10_000,20_000):
    #     powers.append(modular_pow(base, i, 24))
    # end = time.time()
    # print("modular took:", end - start)
    # print("made", len(powers),"exponentiations",powers[-1])
    
    # powers = list()
    # start = time.time()
    # for i in range(10_000,20_000):
    #     powers.append(pow(base, i, 24))
    # end = time.time()
    # print("pow took:", end - start)
    # print("made", len(powers), "exponentiations",powers[-1])