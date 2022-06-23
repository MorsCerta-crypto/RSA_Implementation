
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


if __name__ == "__main__":
    import time

    base = 100_101
    powers = list()
    start = time.time()
    for i in range(10_000,20_000):
        if i % 500 == 0:
            print("run", i)
        powers.append(modular_pow(base, i, 24))
    end = time.time()
    print("modular took:", end - start)
    print("made", len(powers),"exponentiations",powers[-1])
    
    powers = list()
    start = time.time()
    for i in range(10_000,20_000):
        if i % 500 == 0:
            print("run", i)
        powers.append(pow(base, i, 24))
    end = time.time()
    print("pow took:", end - start)
    print("made", len(powers), "exponentiations",powers[-1])