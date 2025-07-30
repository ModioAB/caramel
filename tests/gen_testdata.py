"""Generation script for test-data in our fixtures."""

import datetime
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import caramel
import fixtures


REQ_VERSION = 0x00
VERSION = 0x2
CA_BITS = 4096
# Subject attribs, in order.
ATTRIBS_TO_KEEP = ("C", "ST", "L", "O", "OU", "CN")
CA_YEARS = 24  # Beware of unixtime ;)
HASH = {1024: hashes.SHA1, 2048: hashes.SHA256, 4096: hashes.SHA512}


def ca_life():
    """Lifetime of the CA in seconds."""
    d = datetime.date.today()
    t = datetime.date(d.year + CA_YEARS, d.month, d.day)
    return int((t - d).total_seconds())


def matching_template(req, cacert):
    """Compare required parts of subjects between two certs.

    Raises an exception on mismatch.
    """

    def later_check(subject):
        """Check that the last two fields in subject are OU, CN."""
        name_parts = list(subject)
        if name_parts[-1].rfc4514_attribute_name != "CN":
            raise ValueError("CN needs to be last in subject")
        if name_parts[-2].rfc4514_attribute_name != "OU":
            raise ValueError("OU needs to be second to last")

    later_check(req.subject)
    later_check(cacert.subject)

    # The lists do not contain the same data, so we cannot check
    # casubject == casubject_2
    # but we can run the same check twice and it ought to match
    casubject = list(cacert.subject)[:-2]
    subject = list(req.subject)[:-2]
    for ca, sub in zip(casubject, subject):
        if ca != sub:
            raise ValueError(f"Subject needs to match CA cert: {casubject}")


def sign_ca_req_inner(nreq, cakey, serial):
    """Inner signing, which does the work."""
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(serial)
    # cert.set_version(VERSION)

    name_attrs = []
    name_map = {attrib.rfc4514_attribute_name: attrib for attrib in nreq.subject}
    name_attrs = [name_map[a] for a in ATTRIBS_TO_KEEP if a in name_map]
    builder = builder.subject_name(x509.Name(name_attrs))
    builder = builder.issuer_name(nreq.subject)
    builder = builder.public_key(nreq.public_key())
    # Validity times
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(seconds=ca_life()))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    sub_identifier = x509.SubjectKeyIdentifier.from_public_key(nreq.public_key())

    builder = builder.add_extension(sub_identifier, critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=sub_identifier.key_identifier,
            authority_cert_serial_number=serial,
            authority_cert_issuer=[x509.DirectoryName(nreq.subject)],
        ),
        critical=False,
    )
    cert = builder.sign(cakey, hashes.SHA512())
    return cert


def sign_ca_req(nreq, cakey):
    """Sign a CA request. Different from normal request due to extensions."""
    # Validate Subject contents. Not necessary for CA gen, but kept anyhow
    matching_template(nreq, nreq)
    assert nreq.is_signature_valid is True
    serial = int(uuid.uuid1())
    cert2 = sign_ca_req_inner(nreq, cakey, serial)
    return cert2


NAME_TO_OID = {
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "CN": NameOID.COMMON_NAME,
}


def subject_to_name(subject):
    """Take a subject set of tuples and turn it into a list of name attributes."""
    res = []
    for k, v in subject:
        res.append(x509.NameAttribute(NAME_TO_OID[k], v))
    return res


def create_ca_req(subject):
    """Create a CA request from a subject."""
    attrs = subject_to_name(subject)
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=CA_BITS,
    )
    nreq = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(attrs))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA512())
    )
    return key, nreq


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
    req = req.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=False
    )
    req = req.add_extension(
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
        critical=False,
    )
    req = req.sign(key, hashes.SHA256())
    return key, req


def create_ca(subject):
    """Create a CA and self sign it."""
    key, req = create_ca_req(subject)
    cert = sign_ca_req(req, key)
    return key, req, cert


def create_expired(req, ca_cert, ca_key):
    """Create an expired cert for the request."""
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(104)
    builder = builder.subject_name(req.subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(req.public_key())
    before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=86400 * 10 * 366
    )
    after = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=86400 * 9 * 366
    )
    builder = builder.not_valid_before(before)
    builder = builder.not_valid_after(after)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage(
            [
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
            ]
        ),
        critical=True,
    )

    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            [
                x509.DNSName("spam.example.com"),
            ]
        ),
        critical=False,
    )
    sub_identifier = x509.SubjectKeyIdentifier.from_public_key(req.public_key())
    builder = builder.add_extension(sub_identifier, critical=False)
    issuer_identifier = x509.SubjectKeyIdentifier.from_public_key(ca_cert.public_key())

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=issuer_identifier.key_identifier,
            authority_cert_serial_number=ca_cert.serial_number,
            authority_cert_issuer=[x509.DirectoryName(ca_cert.subject)],
        ),
        critical=False,
    )

    bits = req.public_key().key_size
    out = builder.sign(ca_key, HASH[bits]())
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
    cert = create_expired(treq, ca.cert.to_cryptography(), ca.key.to_cryptography_key())
    crt_pem = cert.public_bytes(serialization.Encoding.PEM)
    print("expired\n", csr_pem.decode("utf8"), crt_pem.decode("utf8"))


if __name__ == "__main__":
    main()
