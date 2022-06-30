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
 
 
 
if __name__=="__main__":
    from conversion import octet_string_to_integer, integer_to_octet_string
    from openssl import read_private_key, read_public_key, read_encrypted_message, read_decrypted_message
    private_key = read_private_key("/Users/macbook/projects/crypto/RSA/RSA_Implementation/private_key.pem")    
    public_key = read_public_key("/Users/macbook/projects/crypto/RSA/RSA_Implementation/public_key.pem")
    message = read_decrypted_message("/Users/macbook/projects/crypto/RSA/RSA_Implementation/plaintext.txt")
    print("Nachricht: ",message,len(message))
    print(message == b'Hello World!', message)
    #leng = len("cPJG2arM9tl8t7BvmBQ7vTppy56jBZ6KvqqRzQExieJrz6mMdAm0HwV87keJxkSZlaa8pFqcovyapdEXS5MwgInGHhRhB81b6CfA8zZ+C5UZcAR2RAlfxtIhZgLxg8joIeBK3cidVeYcilEX/QN2eeKOid8iI3nhb0+LXYwcdwuMT+w5cC8IADeGJM8QU1W7AEJhuqWN1mtqN2VTrmtS/iaN6LueuYw0ejxyANl2hgFzIKxdjXhTE3oEpUZ18U/h39EOG+uRNJ79B1OOnWsSdmYKgbVFs99KCVCnKtx/M0w4nU4bZzNYdVbyGM8VWcNp9ReRY3UDyEg0og5jCc9OFQ==")
    int_encrypted = rsa_encryption(public_key,octet_string_to_integer(message))
    encrypted = integer_to_octet_string(int_encrypted,public_key.n_octet_length)
    print("Verschlüsselt: ", encrypted)
    openssl_enc = read_encrypted_message("/Users/macbook/projects/crypto/RSA/RSA_Implementation/ciphertext.txt")
    if encrypted == openssl_enc:
        print("Verschlüsselung OK")
    decrypted = integer_to_octet_string(rsa_decryption(private_key,octet_string_to_integer(encrypted)),public_key.n_octet_length)
    print("Entschlüsselt: ", decrypted)
    
