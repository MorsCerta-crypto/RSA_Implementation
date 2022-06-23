"""
5. Cryptographic primitives
5.1 Encryption and Decryption Primitives
5.1.1 RSAEP - RSA Encryption Primitive: rsa_encryption
5.1.2 RSADP - RSA Decryption Primitive: rsa_decryption

"""


from keys import PublicKey,PrivateKey

def rsa_encryption(public_key:PublicKey,message:int)->int:
    """
    Encryption function (RSA) encrypts message using public key.
    """
    assert isinstance(message,int), "message must be an integer"
    if message >= public_key.n or message < 0:
        raise ValueError("message representation out of range")
    return pow(message,public_key.e,public_key.n)


def rsa_decryption(private_key:PrivateKey,ciphertext:int)->int:
    """
    Decryption function (RSA) decrypts ciphertext using private key.
    """
    assert isinstance(ciphertext,int), "ciphertext must be an integer"
    if ciphertext >= private_key.n or ciphertext < 0:
        raise ValueError("ciphertext representation out of range")
    return pow(ciphertext,private_key.d,private_key.n)
 