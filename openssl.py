
    
import os
import rsa
from conversion import octet_string_to_integer
#from cryptography.hazmat.backends import default_backend  
#from cryptography.hazmat.primitives import serialization  
from cryptography.hazmat.primitives.asymmetric import rsa as r
from keys import PrivateKey
from keys import PublicKey


    
def read_private_key(filename:str)->PrivateKey:
    with open(filename,"rb") as privatefile:
        keydata = privatefile.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata,'PEM')

    return PrivateKey(n=privkey.n,
                      d=privkey.d,
                      p=privkey.p,
                      q=privkey.q,
                      e=privkey.e)

def read_public_key(filename: str)->PublicKey:
    """
    Reads a public key from a file.
    :param filename: path to the file containing the public key
    :return: a PublicKey object
    """
    import rsa
    with open(filename, "rb") as publicfile:
        keydata = publicfile.read()
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(keydata)

    return PublicKey(pubkey.n, pubkey.e)

def read_encrypted_message(file:str):
    with open(file,"rb") as f:
        content = f.read()
    return content

def read_decrypted_message(file:str):
    with open(file,"rb") as f:
        content = f.read()
    return content

def load_hazmat_public_key(file):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    with open(file,"rb") as f:
        pem_data = f.read()
    key = load_pem_public_key(pem_data)
    return key

def load_hazmat_private_key(file):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    with open(file,"rb") as f:
        pem_data = f.read()
    key = load_pem_private_key(pem_data,None)
    return key

if __name__=="__main__":
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
                                    public_exponent=65537,
                                    key_size=2048)
    public_key = private_key.public_key()
    # prk = read_private_key("/Users/macbook/projects/crypto/RSA/RSA_Implementation/private_key.pem")
    # puk = read_public_key("/Users/macbook/projects/crypto/RSA/RSA_Implementation/public_key.pem")
    message = read_decrypted_message("/Users/macbook/projects/crypto/RSA/RSA_Implementation/plaintext_oaep.txt")
    encrypted_message = read_encrypted_message("/Users/macbook/projects/crypto/RSA/RSA_Implementation/ciphertext_oaep.txt")
    # print("Private key:", prk)
    # print("Public key:", puk)
    # print("Message:", message)
    # print("Encrypted message:", len(encrypted_message))
    # hkp = load_hazmat_public_key("/Users/macbook/projects/crypto/RSA/RSA_Implementation/public_key.pem")
    # hkpr = load_hazmat_private_key("/Users/macbook/projects/crypto/RSA/RSA_Implementation/private_key.pem")
    # hazart_public_key = hkp.public_key()
    import cryptography.hazmat.primitives.asymmetric.padding as pd
    import cryptography.hazmat.primitives.hashes as h
    res = public_key.encrypt(plaintext=message,padding=pd.OAEP(mgf=pd.MGF1(algorithm=h.SHA1()),algorithm=h.SHA1(),label=None))
    if res==encrypted_message:
        print("Success")
    plaintext = private_key.decrypt(ciphertext=res,padding=pd.OAEP(mgf=pd.MGF1(algorithm=h.SHA1()),algorithm=h.SHA1(),label=None))