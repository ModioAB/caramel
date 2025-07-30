import datetime
import fixtures
import uuid

import OpenSSL.crypto as _crypto
import caramel
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


REQ_VERSION = 0x00
VERSION = 0x2
CA_BITS = 4096
# Subject attribs, in order.
ATTRIBS_TO_KEEP = ("C", "ST", "L", "O", "OU", "CN")
CA_YEARS = 24  # Beware of unixtime ;)

CA_EXTENSIONS = [
    # Key usage for a CA cert.
    _crypto.X509Extension(
        b"basicConstraints", critical=True, value=b"CA:true, pathlen:0"
    ),
    # no cRLSign as we do not use CRLs in caramel.
    _crypto.X509Extension(b"keyUsage", critical=True, value=b"keyCertSign"),
]

EXTENSIONS = [
    _crypto.X509Extension(b"basicConstraints", critical=False, value=b"CA:FALSE"),
    _crypto.X509Extension(
        b"keyUsage",
        critical=False,
        value=b"nonRepudiation,digitalSignature,keyEncipherment",
    ),
]


# Hack hack. :-)
def CA_LIFE():
    d = datetime.date.today()
    t = datetime.date(d.year + CA_YEARS, d.month, d.day)
    return int((t - d).total_seconds())


# adapted from models.py
def components(subject):
    comps = subject.get_components()
    return dict((n.decode("utf8"), v.decode("utf8")) for n, v in comps)


def components2(subject):
    return {attr.rfc4514_attribute_name: attr.value for attr in subject}


def matching_template(x509, cacert):
    """Takes a subject as a dict, and returns if all required fields
    match. Otherwise raises exception"""

    def later_check(subject):
        """Check that the last two fields in subject are OU, CN"""
        pair = subject[-1]
        if pair[0].decode("utf8") != "CN":
            raise ValueError("CN needs to be last in subject")

        pair = subject[-2]
        if pair[0].decode("utf8") != "OU":
            raise ValueError("OU needs to be second to last")

    def later_check_2(subject):
        """Check that the last two fields in subject are OU, CN"""
        name_parts = list(subject)
        if name_parts[-1].rfc4514_attribute_name != "CN":
            raise ValueError("CN needs to be last in subject")
        if name_parts[-2].rfc4514_attribute_name != "OU":
            raise ValueError("OU needs to be second to last")

    casubject = cacert.get_subject().get_components()
    subject = x509.get_subject().get_components()
    later_check(casubject)
    later_check(subject)

    x509_2 = x509.to_cryptography()
    later_check_2(x509_2.subject)

    cacert_2 = cacert.to_cryptography()
    later_check_2(cacert_2.subject)

    casubject = casubject[:-2]
    subject = subject[:-2]

    for ca, sub in zip(casubject, subject):
        if ca != sub:
            raise ValueError("Subject needs to match CA cert:" "{}".format(casubject))

    # The lists do not contain the same data, so we cannot check
    # casubject == casubject_2
    # but we can run the same check twice and it ought to match
    casubject_2 = list(cacert_2.subject)[:-2]
    subject_2 = list(x509_2.subject)[:-2]
    for ca, sub in zip(casubject_2, subject_2):
        if ca != sub:
            raise ValueError("Subject needs to match CA cert:" "{}".format(casubject_2))


def sign_ca_req_old(req, cacert, cakey, serial):
    request_subject = components(req.get_subject())
    cert = _crypto.X509()
    subject = cert.get_subject()
    cert.set_serial_number(serial)
    cert.set_version(VERSION)

    for attrib in ATTRIBS_TO_KEEP:
        if request_subject.get(attrib):
            setattr(subject, attrib, request_subject[attrib])

    issuer_subject = cert.get_subject()
    cert.set_issuer(issuer_subject)
    cert.set_pubkey(req.get_pubkey())

    # Validity times
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(CA_LIFE())

    cert.add_extensions(CA_EXTENSIONS)

    cacert = cert

    extension = _crypto.X509Extension(
        b"subjectKeyIdentifier", critical=False, value=b"hash", subject=cert
    )
    cert.add_extensions([extension])

    # We need subjectKeyIdentifier to be added before we can add
    # authorityKeyIdentifier.
    extension = _crypto.X509Extension(
        b"authorityKeyIdentifier",
        critical=False,
        value=b"issuer:always,keyid:always",
        issuer=cacert,
    )
    cert.add_extensions([extension])

    cert.sign(cakey, "sha512")
    return cert


def sign_ca_req_new(nreq, cakey, serial):
    assert not isinstance(cakey, _crypto.PKey)

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
    builder = builder.not_valid_after(now + datetime.timedelta(seconds=CA_LIFE()))
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


def sign_ca_req(req, cacert, cakey):
    # Validate Subject contents. Not necessary for CA gen, but kept anyhow
    matching_template(req, cacert)

    # Validate signature
    req.verify(req.get_pubkey())

    nreq = req.to_cryptography()
    assert nreq.is_signature_valid is True

    request_subject = components(req.get_subject())
    request_subject_2 = components2(nreq.subject)

    assert request_subject_2 == request_subject

    serial = int(uuid.uuid1())
    cert = sign_ca_req_old(req, cacert, cakey, serial)
    cert2 = sign_ca_req_new(nreq, cakey.to_cryptography_key(), serial)
    cert2 = _crypto.X509.from_cryptography(cert2)

    cmp_crt(cert, cert2)
    return cert


def cmp_crt(old, new):
    old_pem = _crypto.dump_certificate(_crypto.FILETYPE_PEM, old).decode("utf8")
    new_pem = _crypto.dump_certificate(_crypto.FILETYPE_PEM, new).decode("utf8")
    assert old_pem == new_pem, f"Mismatching pem\n{old_pem}\n{new_pem}\n"


def create_ca_req_old(subject, key):
    assert isinstance(key, _crypto.PKey)
    req = _crypto.X509Req()
    req.set_version(REQ_VERSION)
    req.set_pubkey(key)

    x509subject = req.get_subject()
    for k, v in subject:
        setattr(x509subject, k, v)
    req.add_extensions(CA_EXTENSIONS)
    req.sign(key, "sha512")
    return req


NAME_TO_OID = {
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "CN": NameOID.COMMON_NAME,
}


def subject_to_name(subject):

    res = []
    for k, v in subject:
        res.append(x509.NameAttribute(NAME_TO_OID[k], v))
    return res


def create_ca_req_new(subject, key):
    assert not isinstance(key, _crypto.PKey)

    attrs = subject_to_name(subject)

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
    return nreq


def create_ca_req(subject):
    key = _crypto.PKey()
    key.generate_key(_crypto.TYPE_RSA, CA_BITS)
    req = create_ca_req_old(subject, key)
    nreq = create_ca_req_new(subject, key.to_cryptography_key())

    req2 = _crypto.X509Req.from_cryptography(nreq)

    cmp_req(req, req2)
    return key, req


def create_req_old(subject, key):
    req = _crypto.X509Req()
    req.set_version(REQ_VERSION)
    req.set_pubkey(key)

    x509subject = req.get_subject()
    for k, v in subject:
        setattr(x509subject, k, v)

    req.add_extensions(EXTENSIONS)

    req.sign(key, "sha256")
    return req


def create_req_new(subject, key):

    assert not isinstance(key, _crypto.PKey)

    attrs = subject_to_name(subject)

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
    return req


def cmp_req(old, new):
    old_pem = _crypto.dump_certificate_request(_crypto.FILETYPE_PEM, old).decode("utf8")
    new_pem = _crypto.dump_certificate_request(_crypto.FILETYPE_PEM, new).decode("utf8")
    assert old_pem == new_pem, f"CSR Mismatch\n{old_pem}\n{new_pem}\n"


def create_req(subject):
    key = _crypto.PKey()
    key.generate_key(_crypto.TYPE_RSA, 2048)
    req = create_req_old(subject, key)
    req2 = create_req_new(subject, key.to_cryptography_key())

    req2 = _crypto.X509Req.from_cryptography(req2)
    cmp_req(req, req2)

    return key, req


def create_ca(subject):
    key, req = create_ca_req(subject)
    cert = sign_ca_req(req, req, key)
    return key, req, cert


def create_expired(req, ca_cert, ca_key):
    cert = create_expired_old(req, ca_cert, ca_key)
    cert2 = create_expired_new(
        req.to_cryptography(), ca_cert.to_cryptography(), ca_key.to_cryptography_key()
    )
    cert2 = _crypto.X509.from_cryptography(cert2)
    cmp_crt(cert, cert2)
    return cert


def create_expired_old(req, ca_cert, ca_key):
    cert = _crypto.X509()
    cert.set_subject(req.get_subject())
    cert.set_serial_number(104)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.set_version(caramel.models.X509_V3)
    cert.gmtime_adj_notBefore(-86400 * 10 * 366)
    cert.gmtime_adj_notAfter(-86400 * 9 * 366)
    subjectAltName = bytes("DNS:" + "spam.example.com", "utf-8")
    extensions = [
        _crypto.X509Extension(b"basicConstraints", critical=True, value=b"CA:FALSE"),
        _crypto.X509Extension(
            b"extendedKeyUsage",
            critical=True,
            value=b"clientAuth,serverAuth",
        ),
        _crypto.X509Extension(b"subjectAltName", critical=False, value=subjectAltName),
        _crypto.X509Extension(
            b"subjectKeyIdentifier",
            critical=False,
            value=b"hash",
            subject=cert,
        ),
    ]
    cert.add_extensions(extensions)
    # subjectKeyIdentifier has to be present before adding auth ident
    extensions = [
        _crypto.X509Extension(
            b"authorityKeyIdentifier",
            critical=False,
            value=b"issuer:always,keyid:always",
            issuer=ca_cert,
        )
    ]
    cert.add_extensions(extensions)
    bits = cert.get_pubkey().bits()
    cert.sign(ca_key, caramel.models.HASH[bits])
    return cert


def create_expired_new(req, ca_cert, ca_key):
    assert not isinstance(ca_key, _crypto.PKey)

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
    print(before, after)
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
    HASH = {1024: hashes.SHA1, 2048: hashes.SHA256, 4096: hashes.SHA512}

    bits = req.public_key().key_size
    out = builder.sign(ca_key, HASH[bits]())
    return out


def write_files(key, keyname, cert, certname):
    def writefile(data, name):
        with open(name, "w") as f:
            stream = data.decode("utf8")
            f.write(stream)

    _key = _crypto.dump_privatekey(_crypto.FILETYPE_PEM, key)
    writefile(_key, keyname)

    _cert = _crypto.dump_certificate(_crypto.FILETYPE_PEM, cert)
    writefile(_cert, certname)


CA_KEY_FILE = "fixtures.ca.key"
CA_CRT_FILE = "fixtures.ca.crt"


def main():
    ca_template = fixtures.CertificateData.ca_cert.subject
    key, req, cert = create_ca(ca_template)
    write_files(key=key, keyname=CA_KEY_FILE, cert=cert, certname=CA_CRT_FILE)
    ca = caramel.models.SigningCert.from_files(CA_CRT_FILE, CA_KEY_FILE)

    # Initial certs data
    tkey, treq = create_req(fixtures.CSRData.initial.subject_components)
    csr_pem = _crypto.dump_certificate_request(_crypto.FILETYPE_PEM, treq)
    csr = caramel.models.CSR("fakeshasum", csr_pem)
    cert = caramel.models.Certificate.sign(csr, ca)
    print("initial\n", csr.pem.decode("utf8"), cert.pem.decode("utf8"))

    # Empty subject cert
    tkey, treq = create_req(fixtures.CSRData.empty_subject.subject_components)
    csr_pem = _crypto.dump_certificate_request(_crypto.FILETYPE_PEM, treq)
    csr = caramel.models.CSR("fakeshasum", csr_pem)
    cert = caramel.models.Certificate.sign(csr, ca)
    print("empty_subject\n", csr.pem.decode("utf8"), cert.pem.decode("utf8"))

    # Good crt
    tkey, treq = create_req(fixtures.CSRData.good.subject_components)
    csr_pem = _crypto.dump_certificate_request(_crypto.FILETYPE_PEM, treq)
    csr = caramel.models.CSR("fakeshasum", csr_pem)
    cert = caramel.models.Certificate.sign(csr, ca)
    print("good\n", csr.pem.decode("utf8"), cert.pem.decode("utf8"))

    # Expired  crt
    tkey, treq = create_req(fixtures.CSRData.with_expired_cert.subject_components)
    csr_pem = _crypto.dump_certificate_request(_crypto.FILETYPE_PEM, treq)
    cert = create_expired(req, ca.cert, ca.key)
    crt_pem = _crypto.dump_certificate(_crypto.FILETYPE_PEM, cert)
    print("expired\n", csr_pem.decode("utf8"), crt_pem.decode("utf8"))


if __name__ == "__main__":
    main()
