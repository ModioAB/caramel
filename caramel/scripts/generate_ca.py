#! /usr/bin/env python3
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :

import datetime
import argparse
import uuid
import os
import OpenSSL.crypto as _crypto
from pyramid.paster import bootstrap

VERSION = 0x2
CA_BITS = 4096
# Subject attribs, in order.
ATTRIBS_TO_KEEP = ("C", "ST", "L", "O", "OU", "CN")
CA_YEARS = 24  # Beware of unixtime ;)

CA_EXTENSIONS = [
    # Key usage for a CA cert.
    _crypto.X509Extension(b"basicConstraints", critical=True,
                          value=b"CA:true, pathlen:0"),
    # no cRLSign as we do not use CRLs in caramel.
    _crypto.X509Extension(b"keyUsage", critical=True, value=b"keyCertSign")
]


def _crypto_patch():
    """hijack _crypto internal lib and violate the default text encoding.
    https://github.com/pyca/pyopenssl/pull/115 has a pull&fix for it
    https://github.com/pyca/pyopenssl/issues/129 is an open issue
    about it."""
    _crypto._lib.ASN1_STRING_set_default_mask_asc(b'utf8only')

_crypto_patch()


# Hack hack. :-)
def CA_LIFE():
    d = datetime.date.today()
    t = datetime.date(d.year+CA_YEARS, d.month, d.day)
    return int((t-d).total_seconds())


# adapted from models.py
def components(subject):
    comps = subject.get_components()
    return dict((n.decode("utf8"), v.decode("utf8")) for n, v in comps)


def matching_template(x509, cacert):
    """ Takes a subject as a dict, and returns if all required fields
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

    for (ca, sub) in zip(casubject, subject):
        if ca != sub:
            raise ValueError("Subject needs to match CA cert:"
                             "{}".format(casubject))


def sign_req(req, cacert, cakey):
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

    cert.sign(cakey, "sha512")
    return cert


def create_ca_req(subject):
    key = _crypto.PKey()
    key.generate_key(_crypto.TYPE_RSA, CA_BITS)

    req = _crypto.X509Req()
    req.set_version(VERSION)
    req.set_pubkey(key)

    x509subject = req.get_subject()
    for k, v in subject:
        setattr(x509subject, k, v)

    req.add_extensions(CA_EXTENSIONS)

    req.sign(key, "sha512")
    return key, req


def create_ca(subject):
    key, req = create_ca_req(subject)
    cert = sign_req(req, req, key)
    return key, req, cert


def write_files(key, keyname, cert, certname):

    def writefile(data, name):
        with open(name, 'w') as f:
            stream = data.decode('utf8')
            f.write(stream)

    _key = _crypto.dump_privatekey(_crypto.FILETYPE_PEM, key)
    writefile(_key, keyname)

    _cert = _crypto.dump_certificate(_crypto.FILETYPE_PEM, cert)
    writefile(_cert, certname)


def cmdline():
    parser = argparse.ArgumentParser()
    parser.add_argument("inifile", help="Needed to find CA filename")
    args = parser.parse_args()
    return args


def build_ca(keyname, certname):
    print("Enter CA settings, leave blank to not include")
    subject = {}
    subject["C"] = input("C [countryName (Code, 2 letters)]: ").upper()
    if subject["C"] and len(subject["C"]) != 2:
        raise ValueError("Country codes are two letters")

    subject["ST"] = input("ST [stateOrProvinceName]: ")[:20]
    subject["L"] = input("L [localityName]: ")
    subject["O"] = input("O [Organization]: ")
    subject["OU"] = input("OU [organizationalUnitName]: ") or "Caramel"
    subject["CN"] = "Caramel Signing Certificate"
    print("CN will be '{}'".format(subject["CN"]))

    template = []
    for field in ATTRIBS_TO_KEEP:
        if field in subject and subject[field]:
            template.append((field, subject[field]))
    template = tuple(template)

    key, req, cert = create_ca(template)
    write_files(key=key, keyname=keyname,
                cert=cert, certname=certname)


def main():
    args = cmdline()
    env = bootstrap(args.inifile)
    settings, closer = env["registry"].settings, env["closer"]

    ca_cert = settings.get("ca.cert")
    ca_key = settings.get("ca.key")
    if not ca_cert:
        print("Missing 'ca.cert' in ini file")
        closer()
        exit()

    if not ca_key:
        print("Missing 'ca.cert' in ini file")
        closer()
        exit()

    for f in ca_cert, ca_key:
        if os.path.exists(f):
            print("File already exists: {}. Refusing to corrupt.".format(f))
            closer()
            exit()
        else:
            dname = os.path.dirname(f)
            os.makedirs(dname, exist_ok=True)

    print("Will write key to {}".format(ca_key))
    print("Will write cert to {}".format(ca_cert))

    build_ca(keyname=ca_key, certname=ca_cert)
