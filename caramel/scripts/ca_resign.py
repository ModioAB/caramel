#! /usr/bin/env python3
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :

import argparse
import datetime
import os
import uuid

import OpenSSL.crypto as _crypto
import dateutil.parser

X509_V3 = 0x2  # RFC 2459, 4.1.2.1

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


def cmdline():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ca-cert",
        help="Path to CA certificate to use",
        type=str,
    )
    parser.add_argument(
        "--ca-key",
        help="Path to CA key to use",
        type=str,
    )
    args = parser.parse_args()
    return args


def display_crt(cert):
    subject = cert.get_subject()
    print("Subject: ", subject)
    issuer = cert.get_issuer()
    print("Issuer: ", issuer)
    not_after = cert.get_notAfter()
    print("Not After: ", not_after, dateutil.parser.parse(not_after))
    not_before = cert.get_notBefore()
    print("Not Before: ", not_before, dateutil.parser.parse(not_before))
    pubkey = cert.get_pubkey()
    print("Pubkey", pubkey)
    serial = cert.get_serial_number()
    print("Serial No", serial)
    sig_algo = cert.get_signature_algorithm()
    print("Sig algo", sig_algo)
    version = cert.get_version()
    print("Version: ", version)
    subject_name_hash = cert.subject_name_hash()
    print("Subject name hash: ", subject_name_hash)
    ext_count = cert.get_extension_count()
    print("Ext count: ", ext_count)
    for n in range(ext_count):
        ext = cert.get_extension(n)
        name = ext.get_short_name()
        crit = ext.get_critical()
        data = ext.get_data()
        print(f"Ext {n}: {name} crit={crit}: ", ext, data)
    pem = _crypto.dump_certificate(_crypto.FILETYPE_PEM, cert)
    print(str(pem, encoding="utf8"))


def main():
    args = cmdline()
    try:
        ca_cert_path, ca_key_path = args.ca_cert, args.ca_key
    except ValueError as error:
        print(error)
        exit()

    with open(ca_key_path, "rt") as f:
        data = f.read()
        key = _crypto.load_privatekey(_crypto.FILETYPE_PEM, data)
        del data

    with open(ca_cert_path, "rt") as f:
        data = f.read()
        orig = _crypto.load_certificate(_crypto.FILETYPE_PEM, data)
        del data

    display_crt(orig)

    cert = _crypto.X509()
    cert.set_subject(orig.get_subject())
    cert.set_serial_number(orig.get_serial_number())
    cert.set_issuer(orig.get_issuer())
    cert.set_pubkey(orig.get_pubkey())
    cert.set_version(X509_V3)

    # If we just use get_notBefore and get_notAfter we do not get the same
    # data-type in the cert. For some stupid openssl-related reason
    # Instead, we need to calculate the delta from now, and use time adjust to
    # fix them, in order to get the correct offset data.
    # Why this is the case I do not know. It's ASN.1 and the difference between
    # UTCTIME and GENERAL time

    # This was the first attempt, and it does not work
    # cert.set_notBefore(orig.get_notBefore())
    # cert.set_notAfter(orig.get_notAfter())
    now = datetime.datetime.now(tz=datetime.UTC)
    before = orig.get_notBefore()
    before_ts = dateutil.parser.parse(before)
    before_delta = int((before_ts - now).total_seconds())
    print("Delta before is", before_delta)
    cert.gmtime_adj_notBefore(before_delta)

    # This won't work as we get the wrong data type.
    # before_ts_b = before_ts.strftime("%Y%m%d%H%M%SZ")
    # cert.set_notBefore(bytes(before_ts_b, "utf8"))

    after = orig.get_notAfter()
    after_ts = dateutil.parser.parse(after)
    after_delta = 1 + int((after_ts - now).total_seconds())
    print("Delta after is", after_delta)
    cert.gmtime_adj_notAfter(after_delta)

    cert.add_extensions(CA_EXTENSIONS)
    extension = _crypto.X509Extension(
        b"subjectKeyIdentifier", critical=False, value=b"hash", subject=orig
    )
    cert.add_extensions([extension])
    # We need subjectKeyIdentifier to be added before we can add
    # authorityKeyIdentifier.
    extension = _crypto.X509Extension(
        b"authorityKeyIdentifier",
        critical=False,
        value=b"issuer:always,keyid:always",
        issuer=orig,
    )
    cert.add_extensions([extension])
    cert.sign(key, "sha512")

    print("New cert")
    display_crt(cert)

    assert orig.get_notBefore() == cert.get_notBefore()
    assert (
        orig.get_notAfter() == cert.get_notAfter()
    ), f"{orig.get_notAfter()} != {cert.get_notAfter()}"


if __name__ == "__main__":
    main()
