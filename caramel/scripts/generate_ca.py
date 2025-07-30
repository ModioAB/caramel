#! /usr/bin/env python3
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
"""Generate a ca cert + key"""

import datetime
import argparse
import uuid
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from caramel.config import (
    setup_logging,
    get_appsettings,
)
from caramel import config

REQ_VERSION = 0x00
VERSION = 0x2
CA_BITS = 4096
# Subject attribs, in order.
ATTRIBS_TO_KEEP = ("C", "ST", "L", "O", "OU", "CN")
CA_YEARS = 24  # Beware of unixtime ;)

CA_EXTENSIONS = [
    # Key usage for a CA cert.
    x509.BasicConstraints(ca=True, path_length=0),
    # no cRLSign as we do not use CRLs in caramel.
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
]


def ca_life():
    """Return a ca lifetime in seconds"""
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

    # We want the attributes in a specific order, thus we first split the
    # subject, and then iterate over our chosen order, and then re-assmeble it.
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
    for extension in CA_EXTENSIONS:
        builder = builder.add_extension(extension, critical=True)

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
    res = [x509.NameAttribute(NAME_TO_OID[k], v) for k, v in subject]
    return res


def create_ca_req(subject):
    """Create a CA request (csr) from the subject."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=CA_BITS,
    )
    attrs = subject_to_name(subject)
    req = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
    for extension in CA_EXTENSIONS:
        req = req.add_extension(extension, critical=True)
    req = req.sign(key, hashes.SHA512())
    return key, req


def create_ca(subject):
    """Create a CA and self sign it."""
    key, req = create_ca_req(subject)
    cert = sign_ca_req(req, key)
    return key, req, cert


def write_files(key, keyname, cert, certname, req):
    """Write the files to disk."""

    def writefile(data, name):
        with open(name, "w", encoding="utf8") as f:
            stream = data.decode("utf8")
            f.write(stream)

    _key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    writefile(_key, keyname)

    _cert = cert.public_bytes(serialization.Encoding.PEM)
    writefile(_cert, certname)

    _req = req.public_bytes(serialization.Encoding.PEM)
    writefile(_req, f"{certname}.csr")


def cmdline():
    """Commandline parser."""
    parser = argparse.ArgumentParser()

    config.add_inifile_argument(parser)
    config.add_verbosity_argument(parser)
    config.add_ca_arguments(parser)

    args = parser.parse_args()
    return args


def prompt_subject():
    """Ask questions and return the subject."""
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
    print(f"""CN will be '{subject["CN"]}'""")

    template = []
    for field in ATTRIBS_TO_KEEP:
        if field in subject and subject[field]:
            template.append((field, subject[field]))
    template = tuple(template)
    return template


def main():
    """Main entrypoint."""
    args = cmdline()
    config_path = args.inifile

    setup_logging(config_path)
    config.configure_log_level(args)

    settings = get_appsettings(config_path)

    try:
        ca_cert_path, ca_key_path = config.get_ca_cert_key_path(args, settings)
    except ValueError as error:
        print(error)
        sys.exit()

    for f in ca_cert_path, ca_key_path:
        if os.path.exists(f):
            print(f"File already exists: {f}. Refusing to corrupt.")
            sys.exit()
        else:
            dname = os.path.dirname(f)
            os.makedirs(dname, exist_ok=True)

    print(f"Will write key to {ca_key_path}")
    print(f"Will write cert to {ca_cert_path}")

    template = prompt_subject()
    key, req, cert = create_ca(template)
    write_files(key=key, keyname=ca_key_path, cert=cert, certname=ca_cert_path, req=req)


if __name__ == "__main__":
    main()
