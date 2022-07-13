
    
import rsa
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


    