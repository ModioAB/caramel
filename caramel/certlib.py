#! /usr/bin/env python3
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :

import datetime
import OpenSSL.crypto as _crypto

VERSION = 3
CLIENT_BITS = 2048
CA_BITS = 4096
# Bit strength => hash strength. Based on hash strenghts
HASH = {1024: "sha1",
        2048: "sha256",
        4096: "sha512"}

SUBJECT_MATCH = {"C": u"SE",
                 "ST": u"Östergötland",
                 "L": u"Linköping",
                 "O": u"Modio AB",
                 "OU": u"Caramel"}
ATTRIBS_TO_KEEP = tuple(SUBJECT_MATCH.keys()) + ('CN', )

CA_YEARS = 20
CLIENT_MONTHS = 2

CA_EXTENSIONS = [
    # Key usage for a CA cert.
    _crypto.X509Extension(b'basicConstraints', critical=True,
                          value=b'CA:true, pathlen:0'),
    # no cRLSign as we do not use CRLs in caramel.
    _crypto.X509Extension(b'keyUsage', critical=True, value=b'keyCertSign')
]


CLIENT_EXTENSIONS = [
    _crypto.X509Extension(b'basicConstraints',
                          critical=True, value=b'CA:FALSE'),
    _crypto.X509Extension(b'extendedKeyUsage',
                          critical=True, value=b'clientAuth')
]
SERVER_EXTENSIONS = [
    _crypto.X509Extension(b'basicConstraints',
                          critical=True, value=b'CA:FALSE'),
    _crypto.X509Extension(b'extendedKeyUsage',
                          critical=True, value=b'serverAuth')
]
CLIENT_SERVER_EXTENSIONS = [
    _crypto.X509Extension(b'basicConstraints',
                          critical=True, value=b'CA:FALSE'),
    _crypto.X509Extension(b'extendedKeyUsage',
                          critical=True, value=b'clientAuth,serverAuth')
]


# Hack hack. :-)
def CA_LIFE():
    d = datetime.date.today()
    t = datetime.date(d.year+CA_YEARS, d.month, d.day)
    return int((t-d).total_seconds())


def CLIENT_LIFE():
    d = datetime.date.today()
    t = datetime.date(d.year, d.month+CLIENT_MONTHS, d.day)
    return int((t-d).total_seconds())


# adapted from models.py
def components(subject):
    comps = subject.get_components()
    return dict((n.decode("utf8"), v.decode("utf8")) for n, v in comps)


def matching_template(x509, template):
    """ Takes a subject as a dict, and returns if all required fields
    match. Otherwise raises exception"""

    subject = components(x509.get_subject())
    # build a new dict of all things in subject that match SUBJECT_MATCH.
    # If our intersect is equal to SUBJECT_MATCH, they were all correct.
    # We may still have excess keys.
    intersect = {k: v for k, v in template.items()
                 if k in subject and v == subject[k]}
    if not intersect == template:
        raise ValueError("Subject either has missing or invalid keys")


def add_ca_extensions(x509, ca):
    x509.add_extensions(CA_EXTENSIONS)
    return x509


def create_req(template, key=None):
    req = _crypto.X509Req()
    req.set_version(VERSION)

    if not key:
        key = _crypto.PKey()
        key.generate_key(_crypto.TYPE_RSA, CLIENT_BITS)

    req.set_pubkey(key)
    subject = req.get_subject()
    for k, v in SUBJECT_MATCH.items():
        setattr(subject, k, v)

    for k, v in template.items():
        setattr(subject, k, v)

    req.sign(key, HASH[key.bits()])
    return key, req


def create_ca_req():
    key = _crypto.PKey()
    req = _crypto.X509Req()

    key.generate_key(_crypto.TYPE_RSA, CA_BITS)
    key, req = create_req(SUBJECT_MATCH, key)

    req.add_extensions(CA_EXTENSIONS)

    # copy in our defaults
    subject = req.get_subject()
    subject.CN = u"Caramel Signing Certificate"

    # this should be a test-case.
    subject.emailAddress = "test@this_should_get_deleted"

    req.sign(key, HASH[key.bits()])
    return key, req


def sign_req(req, cacert, cakey, Type="client", serial=0):
    if Type not in ("client", "server", "CA", "client-server"):
        raise ValueError("Mismatched type.")

    # Validate Subject contents
    matching_template(req, SUBJECT_MATCH)

    # Validate signature
    req.verify(req.get_pubkey())
    request_subject = components(req.get_subject())

    cert = _crypto.X509()
    subject = cert.get_subject()
    cert.set_serial_number(serial)
    cert.set_version(VERSION)
    for attrib in ATTRIBS_TO_KEEP:
        if request_subject.get(attrib):
            setattr(subject, attrib, request_subject[attrib])

    if Type == "CA":
        issuer_subject = cert.get_subject()
    else:
        issuer_subject = cacert.get_subject()
    cert.set_issuer(issuer_subject)
    cert.set_pubkey(req.get_pubkey())

    # Validity times
    cert.gmtime_adj_notBefore(0)
    if Type == "CA":
        cert.gmtime_adj_notAfter(CA_LIFE())
    else:
        cert.gmtime_adj_notAfter(CLIENT_LIFE())

    # Extensions for control
    if Type == "client-server":
        cert.add_extensions(CLIENT_SERVER_EXTENSIONS)
    elif Type == "client":
        cert.add_extensions(CLIENT_EXTENSIONS)
    elif Type == "server":
        cert.add_extensions(SERVER_EXTENSIONS)
    elif Type == "CA":
        cert.add_extensions(CA_EXTENSIONS)

    if Type == "CA":
        cacert = cert

    extension = _crypto.X509Extension(b"subjectKeyIdentifier",
                                      critical=False,
                                      value=b"hash",
                                      subject=cert)
    cert.add_extensions([extension])

    # We need subjectKeyIdentifier to be added before we can add
    # authorityKeyIdentifier.
    extension = _crypto.X509Extension(b"authorityKeyIdentifier",
                                      critical=False,
                                      value=b"issuer:always,keyid:always",
                                      issuer=cacert)
    cert.add_extensions([extension])

    bits = cert.get_pubkey().bits()
    cert.sign(cakey, HASH[bits])
    return cert


def create_ca():
    key, req = create_ca_req()
    cert = sign_req(req, req, key, Type="CA")
    return key, req, cert


def write_out_files(key=None, req=None, cert=None, name="testCA"):
    s = {}
    if key:
        s['key'] = _crypto.dump_privatekey(_crypto.FILETYPE_PEM, key)
    if req:
        s['csr'] = _crypto.dump_certificate_request(_crypto.FILETYPE_PEM, req)
    if cert:
        s['cert'] = _crypto.dump_certificate(_crypto.FILETYPE_PEM, cert)

    for suf, data in s.items():
        with open('.'.join((name, suf)), 'w') as f:
            st = data.decode('utf8')
            f.write(st)
