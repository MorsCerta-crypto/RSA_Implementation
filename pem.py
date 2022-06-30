
import base64
import typing

#from keys import PublicKey


FlexiText = typing.Union[str, bytes]

def load_pem(contents: FlexiText, pem_marker: FlexiText) -> bytes:
    """Loads a PEM file.
    :param contents: the contents of the file to interpret
    :param pem_marker: the marker of the PEM content, such as 'RSA PRIVATE KEY'
        when your file has '-----BEGIN RSA PRIVATE KEY-----' and
        '-----END RSA PRIVATE KEY-----' markers.
    :return: the base64-decoded content between the start and end markers.
    @raise ValueError: when the content is invalid, for example when the start
        marker cannot be found.
    """

    # We want bytes, not text. If it's text, it can be converted to ASCII bytes.
    if not isinstance(contents, bytes):
        contents = contents.encode("ascii")

    (pem_start, pem_end) = _markers(pem_marker)
    pem_lines = [line for line in _pem_lines(contents, pem_start, pem_end)]

    # Base64-decode the contents
    pem = b"".join(pem_lines)
    return base64.standard_b64decode(pem)


def save_pem(contents: bytes, pem_marker: FlexiText) -> bytes:
    """Saves a PEM file.
    :param contents: the contents to encode in PEM format
    :param pem_marker: the marker of the PEM content, such as 'RSA PRIVATE KEY'
        when your file has '-----BEGIN RSA PRIVATE KEY-----' and
        '-----END RSA PRIVATE KEY-----' markers.
    :return: the base64-encoded content between the start and end markers, as bytes.
    """

    (pem_start, pem_end) = _markers(pem_marker)

    b64 = base64.standard_b64encode(contents).replace(b"\n", b"")
    pem_lines = [pem_start]

    for block_start in range(0, len(b64), 64):
        block = b64[block_start : block_start + 64]
        pem_lines.append(block)

    pem_lines.append(pem_end)
    pem_lines.append(b"")

    return b"\n".join(pem_lines)



def _markers(pem_marker: FlexiText) -> typing.Tuple[bytes, bytes]:
    """
    Returns the start and end PEM markers, as bytes.
    """

    if not isinstance(pem_marker, bytes):
        pem_marker = pem_marker.encode("ascii")

    return (
        b"-----BEGIN " + pem_marker + b"-----",
        b"-----END " + pem_marker + b"-----",
    )
    

def _pem_lines(contents: bytes, pem_start: bytes, pem_end: bytes) -> typing.Iterator[bytes]:
    """Generator over PEM lines between pem_start and pem_end."""

    in_pem_part = False
    seen_pem_start = False

    for line in contents.splitlines():
        line = line.strip()

        # Skip empty lines
        if not line:
            continue

        # Handle start marker
        if line == pem_start:
            if in_pem_part:
                raise ValueError('Seen start marker "%r" twice' % pem_start)

            in_pem_part = True
            seen_pem_start = True
            continue

        # Skip stuff before first marker
        if not in_pem_part:
            continue

        # Handle end marker
        if in_pem_part and line == pem_end:
            in_pem_part = False
            break

        # Load fields
        if b":" in line:
            continue

        yield line

    # Do some sanity checks
    if not seen_pem_start:
        raise ValueError('No PEM start marker "%r" found' % pem_start)

    if in_pem_part:
        raise ValueError('No PEM end marker "%r" found' % pem_end)



def load_pkcs1_openssl_pem(cls, keyfile: bytes):
    """Loads a PKCS#1.5 PEM-encoded public key file from OpenSSL.
    These files can be recognised in that they start with BEGIN PUBLIC KEY
    rather than BEGIN RSA PUBLIC KEY.
    The contents of the file before the "-----BEGIN PUBLIC KEY-----" and
    after the "-----END PUBLIC KEY-----" lines is ignored.
    :param keyfile: contents of a PEM-encoded file that contains the public
        key, from OpenSSL.
    :type keyfile: bytes
    :return: a PublicKey object
    """

    der = load_pem(keyfile, "PUBLIC KEY")
    return cls.load_pkcs1_openssl_der(der)

def load_pkcs1_openssl_der(cls, keyfile: bytes):
    """Loads a PKCS#1 DER-encoded public key file from OpenSSL.
    :param keyfile: contents of a DER-encoded file that contains the public
        key, from OpenSSL.
    :return: a PublicKey object
    """

    from pyasn1.codec.der import decoder
    from pyasn1.type import univ

    (keyinfo, _) = decoder.decode(keyfile, asn1Spec=OpenSSLPubKey())

    if keyinfo["header"]["oid"] != univ.ObjectIdentifier("1.2.840.113549.1.1.1"):
        raise TypeError("This is not a DER-encoded OpenSSL-compatible public key")

    return cls._load_pkcs1_der(keyinfo["key"][1:])



def _save_pkcs1_pem(self) -> bytes:
    """Saves a PKCS#1 PEM-encoded public key file.
    :return: contents of a PEM-encoded file that contains the public key.
    :rtype: bytes
    """

    der = self._save_pkcs1_der()
    return save_pem(der, "RSA PUBLIC KEY")

def _save_pkcs1_der(self) -> bytes:
    """Saves the public key in PKCS#1 DER format.
    :returns: the DER-encoded public key.
    :rtype: bytes
    """

    from pyasn1.codec.der import encoder

    # Create the ASN object
    asn_key = AsnPubKey()
    asn_key.setComponentByName("modulus", self.n)
    asn_key.setComponentByName("publicExponent", self.e)
    #pubk = PublicKey(n=self.n, e=self.e)
    #return encoder.encode(pubk)
    return encoder.encode(asn_key)



from pyasn1.type import univ, namedtype, tag

class PubKeyHeader(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("oid", univ.ObjectIdentifier()),
        namedtype.NamedType("parameters", univ.Null()),
    )
    
class OpenSSLPubKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("header", PubKeyHeader()),
        # This little hack (the implicit tag) allows us to get a Bit String as Octet String
        namedtype.NamedType(
            "key",
            univ.OctetString().subtype(implicitTag=tag.Tag(tagClass=0, tagFormat=0, tagId=3)),
        ),
    )


class AsnPubKey(univ.Sequence):
    """ASN.1 contents of DER encoded public key:
    RSAPublicKey ::= SEQUENCE {
         modulus           INTEGER,  -- n
         publicExponent    INTEGER,  -- e
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("modulus", univ.Integer()),
        namedtype.NamedType("publicExponent", univ.Integer()),
    )
    
    
