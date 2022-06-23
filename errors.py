

# Define Custom Errors
class DecryptionError(Exception):
    """ Error while decrypting"""
    pass

class EncryptionError(Exception):
    """ Error while encrypting"""
    pass

class DecodingError(Exception):
    """ Error while decoding """
    pass

class EncodingError(Exception):
    """ Error while encoding """
    pass

class InvalidSignatureError(Exception):
    """ Errror while verifying signature """
    pass

class KeyGenError(Exception):
    pass
