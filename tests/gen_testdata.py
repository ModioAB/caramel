import caramel
import OpenSSL.crypto as _crypto
import fixtures

import datetime
import argparse
import uuid
import os
import OpenSSL.crypto as _crypto

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


def _crypto_patch():
    """hijack _crypto internal lib and violate the default text encoding.
    https://github.com/pyca/pyopenssl/pull/115 has a pull&fix for it
    https://github.com/pyca/pyopenssl/issues/129 is an open issue
    about it."""
    try:
        _crypto._lib.ASN1_STRING_set_default_mask_asc(b"utf8only")
    except AttributeError:
        # Means we have a new OpenSSL and do not need to patch.
        pass


_crypto_patch()


# Hack hack. :-)
def CA_LIFE():
    d = datetime.date.today()
    t = datetime.date(d.year + CA_YEARS, d.month, d.day)
    return int((t - d).total_seconds())


# adapted from models.py
def components(subject):
    comps = subject.get_components()
    return dict((n.decode("utf8"), v.decode("utf8")) for n, v in comps)


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

    casubject = cacert.get_subject().get_components()
    subject = x509.get_subject().get_components()
    later_check(casubject)
    later_check(subject)

    casubject = casubject[:-2]
    subject = subject[:-2]

    for ca, sub in zip(casubject, subject):
        if ca != sub:
            raise ValueError("Subject needs to match CA cert:" "{}".format(casubject))


def sign_ca_req(req, cacert, cakey):
    # Validate Subject contents. Not necessary for CA gen, but kept anyhow
    matching_template(req, cacert)

    # Validate signature
    req.verify(req.get_pubkey())
    request_subject = components(req.get_subject())

    cert = _crypto.X509()
    subject = cert.get_subject()
    cert.set_serial_number(int(uuid.uuid1()))
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


def create_ca_req(subject):
    key = _crypto.PKey()
    key.generate_key(_crypto.TYPE_RSA, CA_BITS)

    req = _crypto.X509Req()
    req.set_version(REQ_VERSION)
    req.set_pubkey(key)

    x509subject = req.get_subject()
    for k, v in subject:
        setattr(x509subject, k, v)

    req.add_extensions(CA_EXTENSIONS)

    req.sign(key, "sha512")
    return key, req


def create_req(subject):
    key = _crypto.PKey()
    key.generate_key(_crypto.TYPE_RSA, 2048)

    req = _crypto.X509Req()
    req.set_version(REQ_VERSION)
    req.set_pubkey(key)

    x509subject = req.get_subject()
    for k, v in subject:
        setattr(x509subject, k, v)

    req.add_extensions(EXTENSIONS)

    req.sign(key, "sha256")
    return key, req


def create_ca(subject):
    key, req = create_ca_req(subject)
    cert = sign_ca_req(req, req, key)
    return key, req, cert


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
cert = _crypto.X509()
cert.set_subject(treq.get_subject())
cert.set_serial_number(104)
cert.set_issuer(ca.cert.get_subject())
cert.set_pubkey(treq.get_pubkey())
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
        issuer=ca.cert,
    )
]
cert.add_extensions(extensions)
bits = cert.get_pubkey().bits()
cert.sign(ca.key, caramel.models.HASH[bits])
crt_pem = _crypto.dump_certificate(_crypto.FILETYPE_PEM, cert)
print("expired\n", csr_pem.decode("utf8"), crt_pem.decode("utf8"))
