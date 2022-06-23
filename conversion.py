
"""
4. Data Conversion Primitives
4.1 I2OSP - Integer to Octet String Conversion Primitive: integer_to_octet_string
4.2 OS2IP - Octet String to Integer Primitive: octet_string_to_integer
"""
ALPHABET ='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ,.?!:;-\'\"'

def integer_to_octet_string(x:int, length:int)->bytes:
    """
    Converts a nonnegative integer to an octet string of a given length.
    """
    assert x >= 0, "integer must be positive"
    assert length >= 0, "length must be positive"
    if x >= 256 ** length:
        raise ValueError("integer too large")
    # write the integer x in its unique length-digit representation in bas 256
    return x.to_bytes(length, byteorder="big")
        
def octet_string_to_integer(octet:bytes)->int:
    """
    Converts an octet string to a nonnegative integer.
    """
    return int.from_bytes(octet,byteorder="big",signed=False)

def string_to_integer(string:str)->int:
    """
    Converts a string to an integer.
    """
    n=0
    for letter in string:
        n = 100 * n + ALPHABET.index(letter)
    return n

def integer_to_string(x:int)->str:
    """
    Converts an integer to a string.
    """
    s = ""
    while x > 0:
        s = ALPHABET[x % 100] + s
        x //= 100
    return s