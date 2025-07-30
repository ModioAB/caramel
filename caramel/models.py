#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :

from cryptography import x509 as _x509
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives import serialization as _serialization


import sqlalchemy as _sa
from sqlalchemy.ext.declarative import declared_attr, as_declarative
import sqlalchemy.orm as _orm
from zope.sqlalchemy import register

from pyramid.decorator import reify as _reify
import datetime as _datetime
import dateutil.parser
import uuid
from typing import List

X509_V3 = 0x2  # RFC 2459, 4.1.2.1

# Bitlength to Hash Strength lookup table.
HASH = {
    1024: _hashes.SHA1,
    2048: _hashes.SHA256,
    4096: _hashes.SHA512,
}

# These parts of the subject _must_ match our CA key
CA_SUBJ_MATCH = ("C", "ST", "L", "O")


class SigningCert:
    """Data class to wrap signing key + cert, to help refactoring"""

    def __init__(self, cert, key=None):
        if key:
            if isinstance(key, str):
                key = key.encode("utf8")
            self.key = _serialization.load_pem_private_key(key, password=None)
        if isinstance(cert, str):
            cert = cert.encode("utf8")
        self.cert = _x509.load_pem_x509_certificate(cert)

    @classmethod
    def from_files(cls, certfile, keyfile=None):
        key = None
        if keyfile:
            with open(keyfile, "rt") as f:
                key = f.read()
        with open(certfile, "rt") as f:
            cert = f.read()

        return cls(cert, key)

    @_reify
    def not_before(self):
        return self.cert.not_valid_before_utc

    @_reify
    def pem(self):
        ret = self.cert.public_bytes(serialization.Encoding.PEM)
        return ret

    # Returns the parts we _care_ about in the subject, from a ca
    def get_ca_prefix(self, subj_match=CA_SUBJ_MATCH):
        # newer API uses strings instead of bytes, thus we decode them here
        name_map = {a.rfc4514_attribute_name: a.value for a in self.cert.subject}
        matches = tuple((n, name_map[n]) for n in subj_match if n in name_map)
        return matches


# XXX: probably error prone for cases where things are specified by string
def _fkcolumn(referent, *args, **kwargs):
    refcol = referent.property.columns[0]
    return _sa.Column(refcol.type, _sa.ForeignKey(referent), *args, **kwargs)


DBSession = _orm.scoped_session(_orm.sessionmaker())
register(DBSession)


@as_declarative()
class Base:
    __allow_unmapped__ = True

    @declared_attr  # type: ignore
    def __tablename__(cls) -> str:  # pylint: disable=no-self-argument
        return cls.__name__.lower()  # pylint: disable=no-member

    id = _sa.Column(_sa.Integer, primary_key=True)

    def save(self):
        DBSession.add(self)
        DBSession.flush()

    @classmethod
    def query(cls):
        return DBSession.query(cls)

    @classmethod
    def all(cls):
        return cls.query().all()


# XXX: not the best of names
def init_session(engine, create=False):
    DBSession.configure(bind=engine)
    if create:
        Base.metadata.create_all(engine)
    else:
        Base.metadata.bind = engine


# Upper bounds from RFC 5280
_UB_CN_LEN = 64
_UB_OU_LEN = 64

# Length of hex digest of a sha256 checksum
_SHA256_LEN = 64


class CSR(Base):
    sha256sum = _sa.Column(_sa.CHAR(_SHA256_LEN), unique=True, nullable=False)
    pem = _sa.Column(_sa.LargeBinary, nullable=False)
    orgunit = _sa.Column(_sa.String(_UB_OU_LEN))
    commonname = _sa.Column(_sa.String(_UB_CN_LEN))
    rejected = _sa.Column(_sa.Boolean(create_constraint=True))
    accessed: List["AccessLog"] = _orm.relationship(
        "AccessLog", backref="csr", order_by="AccessLog.when.desc()"
    )
    certificates: List["Certificate"] = _orm.relationship(
        "Certificate",
        backref="csr",
        order_by="Certificate.not_after.desc()",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def __init__(self, sha256sum, reqtext):
        # XXX: assert sha256(reqtext).hexdigest() == sha256sum ?
        self.sha256sum = sha256sum
        self.pem = reqtext

        req = _x509.load_pem_x509_csr(self.pem)
        if not req.is_signature_valid:
            raise ValueError("Invalid Request (invalid signature)")

        # Check for and reject reqtext with trailing content
        pem = req.public_bytes(_serialization.Encoding.PEM)
        if pem != self.pem:
            raise ValueError("invalid PEM reqtext")

        def subj_item(subject, key):
            for item in subject:
                if item.rfc4514_attribute_name == key:
                    return item.value
            return ""

        self.orgunit = subj_item(req.subject, "OU")
        self.commonname = subj_item(req.subject, "CN")
        self.rejected = False

    @_reify
    def req(self):
        req = _x509.load_pem_x509_csr(self.pem)
        if not req.is_signature_valid:
            raise ValueError("Invalid Request (invalid signature)")
        return req

    @_reify
    def subject_components(self):
        res = tuple((a.rfc4514_attribute_name, a.value) for a in self.req.subject)
        return res

    @classmethod
    def valid(cls):
        return cls.query().filter_by(rejected=False).all()

    @classmethod
    def list_csr_printable(cls):
        return (
            DBSession.query(
                CSR.id,
                CSR.commonname,
                CSR.sha256sum,
                _sa.func.max(Certificate.not_after),
            )
            .outerjoin(CSR.certificates)
            .group_by(CSR.id)
            .filter(CSR.rejected.is_(False))
            .order_by(CSR.id)
            .all()
        )

    @classmethod
    def refreshable(cls):
        """Using "valid" and looking at csr.certificates doesn't scale.
        Better to do it in the Query."""

        # Options subqueryload is to prevent thousands of small queries and
        # instead batch load the certificates at once
        all_signed = _sa.select(Certificate.csr_id)
        return (
            cls.query().filter_by(rejected=False).filter(CSR.id.in_(all_signed)).all()
        )

    @classmethod
    def unsigned(cls):
        all_signed = _sa.select(Certificate.csr_id)
        return (
            cls.query()
            .filter_by(rejected=False)
            .filter(CSR.id.notin_(all_signed))
            .all()
        )

    @classmethod
    def by_sha256sum(cls, sha256sum):
        return cls.query().filter_by(sha256sum=sha256sum).one()

    def __json__(self, request):
        url = request.route_url("cert", sha256=self.sha256sum)
        return dict(sha256=self.sha256sum, url=url)

    def __str__(self):
        return (
            "<{0.__class__.__name__} "  # auto-concatenation (no comma)
            "sha256sum={0.sha256sum:8.8}... "
            "rejected: {0.rejected!r} "
            "OU={0.orgunit!r} CN={0.commonname!r}>"
        ).format(self)

    def __repr__(self):
        return (
            "<{0.__class__.__name__} id={0.id} "  # (no comma)
            "sha256sum={0.sha256sum}>"
        ).format(self)


def utcnow():
    """Return a non timezone-aware datetime in UTC."""
    ts = _datetime.datetime.now(_datetime.timezone.utc)
    return ts.replace(tzinfo=None)


class AccessLog(Base):
    # XXX: name could be better
    when = _sa.Column(_sa.DateTime, default=utcnow)
    # XXX: name could be better, could perhaps be limited length,
    #      might not want this nullable
    addr = _sa.Column(_sa.Text)
    csr_id = _fkcolumn(CSR.id, nullable=False)

    def __init__(self, csr, addr):
        self.csr = csr
        self.addr = addr

    def __str__(self):
        return (
            "<{0.__class__.__name__} id={0.id} " "csr={0.csr.sha256sum} when={0.when}>"
        ).format(self)

    def __repr__(self):
        return "<{0.__class__.__name__} id={0.id}>".format(self)


class Extension:
    """Convenience class to make validating Extensions a bit easier"""

    critical = False
    name = None
    data = None
    text = None

    def __init__(self, ext):
        self.name = ext.oid._name
        self.critical = ext.critical
        self.data = ext.value
        self.text = str(ext)


class Certificate(Base):
    pem = _sa.Column(_sa.LargeBinary, nullable=False)
    # XXX: not_after might be enough
    not_before = _sa.Column(_sa.DateTime, nullable=False)
    not_after = _sa.Column(_sa.DateTime, nullable=False)
    csr_id = _fkcolumn(CSR.id, nullable=False)

    def __init__(self, CSR, pem, *args, **kws):
        self.pem = pem
        self.csr_id = CSR.id

        req = CSR.req
        cert_pkey = self.cert.public_key()

        # We can't compare pubkeys directly, so we just verify the signature.
        if not req.is_signature_valid:
            raise ValueError("Public key of cert cannot verify request")

        self.not_before = self.cert.not_valid_before_utc
        self.not_after = self.cert.not_valid_after_utc

    @_reify
    def cert(self):
        cert = _x509.load_pem_x509_certificate(self.pem)

        extensions = {}
        for ext in cert.extensions:
            my_ext = Extension(ext)
            extensions[my_ext.name] = my_ext
        if cert.version.value != X509_V3:
            raise ValueError("Not a x509.v3 certificate")

        ext = extensions.get("basicConstraints")
        if not ext:
            raise ValueError("Missing Basic Constraints")

        if not ext.critical:
            raise ValueError("Extended Key Usage not critical")

        ext = extensions.get("extendedKeyUsage")
        if not ext:
            raise ValueError("Missing Extended Key Usage extension")
        if not ext.critical:
            raise ValueError("Extended Key Usage not critical")
        if "TLS Web Client Authentication" in ext.text:
            pass
        if "TLS Web Server Authentication" in ext.text:
            pass
        return cert

    def __repr__(self):
        return "<{0.__class__.__name__} id={0.id}>".format(self)

    @classmethod
    def sign(cls, CSR, ca, lifetime=_datetime.timedelta(30 * 3), backdate=False):
        """Takes a CSR, signs it, generating and returning a Certificate.
        backdate causes the CA to set "notBefore" of signed certificates to
        match that of the CA Certificate. This is an ugly workaround for a
        timekeeping bug in some firmware.
        """
        assert isinstance(ca, SigningCert)

        now = _datetime.datetime.now(tz=_datetime.timezone.utc)

        notAfter = int(lifetime.total_seconds())
        # TODO: Verify that the data in DB matches csr_add rules in views.py

        cert = _x509.CertificateBuilder()
        cert = cert.subject_name(CSR.req.subject)
        cert = cert.serial_number(int(uuid.uuid1()))
        cert = cert.issuer_name(ca.cert.subject)
        cert = cert.public_key(CSR.req.public_key())
        cert = cert.not_valid_before(now)
        cert = cert.not_valid_after(now + _datetime.timedelta(seconds=notAfter))
        if backdate and ca.not_before:
            cert = cert.not_valid_before(ca.not_before)

        cert = cert.add_extension(
            _x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        cert = cert.add_extension(
            _x509.ExtendedKeyUsage(
                [
                    _x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    _x509.ExtendedKeyUsageOID.SERVER_AUTH,
                ]
            ),
            critical=True,
        )
        cert = cert.add_extension(
            _x509.SubjectAlternativeName([_x509.DNSName(CSR.commonname)]),
            critical=False,
        )
        cert = cert.add_extension(
            _x509.SubjectKeyIdentifier.from_public_key(CSR.req.public_key()),
            critical=False,
        )
        # subjectKeyIdentifier has to be present before adding auth ident
        issuer_identifier = _x509.SubjectKeyIdentifier.from_public_key(
            ca.cert.public_key()
        )

        cert = cert.add_extension(
            _x509.AuthorityKeyIdentifier(
                key_identifier=issuer_identifier.key_identifier,
                authority_cert_serial_number=ca.cert.serial_number,
                authority_cert_issuer=[_x509.DirectoryName(ca.cert.subject)],
            ),
            critical=False,
        )
        bits = CSR.req.public_key().key_size
        cert = cert.sign(ca.key, HASH[bits]())
        pem = cert.public_bytes(_serialization.Encoding.PEM)
        return cls(CSR=CSR, pem=pem)
