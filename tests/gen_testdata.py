"""Generation script for test-data in our fixtures."""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from caramel.scripts.generate_ca import create_ca, subject_to_name

import caramel
import fixtures


# Subject attribs, in order.
ATTRIBS_TO_KEEP = ("C", "ST", "L", "O", "OU", "CN")
HASH = {1024: hashes.SHA1, 2048: hashes.SHA256, 4096: hashes.SHA512}
NAME_TO_OID = {
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "CN": NameOID.COMMON_NAME,
}


EXTENSIONS = [
    x509.BasicConstraints(ca=False, path_length=None),
    x509.KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    ),
]


def create_req(subject):
    """Create a normal request for the subject.

    Extensions differ from a CA request.
    """
    attrs = subject_to_name(subject)
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    req = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
    for ext in EXTENSIONS:
        req = req.add_extension(ext, critical=False)
    req = req.sign(key, hashes.SHA256())
    return key, req


def create_expired(req, ca_cert, ca_key):
    """Create an expired cert for the request."""
    before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=86400 * 10 * 366
    )
    after = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=86400 * 9 * 366
    )
    cb = x509.CertificateBuilder()
    cb = cb.serial_number(104)
    cb = cb.subject_name(req.subject)
    cb = cb.issuer_name(ca_cert.subject)
    cb = cb.public_key(req.public_key())
    cb = cb.not_valid_before(before)
    cb = cb.not_valid_after(after)
    cb = cb.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    cb = cb.add_extension(
        x509.ExtendedKeyUsage(
            [
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
            ]
        ),
        critical=True,
    )
    cb = cb.add_extension(
        x509.SubjectAlternativeName([x509.DNSName("spam.example.com")]),
        critical=False,
    )
    cb = cb.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(req.public_key()), critical=False
    )
    issuer_identifier = x509.SubjectKeyIdentifier.from_public_key(ca_cert.public_key())
    cb = cb.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=issuer_identifier.key_identifier,
            authority_cert_serial_number=ca_cert.serial_number,
            authority_cert_issuer=[x509.DirectoryName(ca_cert.subject)],
        ),
        critical=False,
    )

    bits = req.public_key().key_size
    out = cb.sign(ca_key, HASH[bits]())
    return out


def write_files(key, keyname, cert, certname):
    """Write certain files we need."""

    def writefile(data, name):
        with open(name, "w", encoding="utf8") as f:
            stream = data.decode("utf8")
            f.write(stream)

    keydata = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    writefile(keydata, keyname)

    certdata = cert.public_bytes(serialization.Encoding.PEM)
    writefile(certdata, certname)


CA_KEY_FILE = "fixtures.ca.key"
CA_CRT_FILE = "fixtures.ca.crt"


def main():
    """Generate some fixtures."""
    ca_template = fixtures.CertificateData.ca_cert.subject
    key, req, cert = create_ca(ca_template)
    write_files(key=key, keyname=CA_KEY_FILE, cert=cert, certname=CA_CRT_FILE)
    ca = caramel.models.SigningCert.from_files(CA_CRT_FILE, CA_KEY_FILE)
    del key, req, cert

    # Initial certs data
    _tkey, treq = create_req(fixtures.CSRData.initial.subject_components)
    csr_pem = treq.public_bytes(serialization.Encoding.PEM)
    csr = caramel.models.CSR("fakeshasum", csr_pem)
    cert = caramel.models.Certificate.sign(csr, ca)
    print("initial\n", csr.pem.decode("utf8"), cert.pem.decode("utf8"))

    # Empty subject cert
    _tkey, treq = create_req(fixtures.CSRData.empty_subject.subject_components)
    csr_pem = treq.public_bytes(serialization.Encoding.PEM)
    csr = caramel.models.CSR("fakeshasum", csr_pem)
    cert = caramel.models.Certificate.sign(csr, ca)
    print("empty_subject\n", csr.pem.decode("utf8"), cert.pem.decode("utf8"))

    # Good crt
    _tkey, treq = create_req(fixtures.CSRData.good.subject_components)
    csr_pem = treq.public_bytes(serialization.Encoding.PEM)
    csr = caramel.models.CSR("fakeshasum", csr_pem)
    cert = caramel.models.Certificate.sign(csr, ca)
    print("good\n", csr.pem.decode("utf8"), cert.pem.decode("utf8"))

    # Expired  crt
    _tkey, treq = create_req(fixtures.CSRData.with_expired_cert.subject_components)
    csr_pem = treq.public_bytes(serialization.Encoding.PEM)
    cert = create_expired(treq, ca.cert, ca.key)
    crt_pem = cert.public_bytes(serialization.Encoding.PEM)
    print("expired\n", csr_pem.decode("utf8"), crt_pem.decode("utf8"))


if __name__ == "__main__":
    main()
