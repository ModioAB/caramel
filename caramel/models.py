#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :

# Make things as three-ish as possible (requires python >= 2.6)
from __future__ import (unicode_literals, print_function,
                        absolute_import, division)
# Namespace cleanup
del unicode_literals, print_function, absolute_import, division

#
# ----- End header -----
#

import sqlalchemy as _sa
from sqlalchemy.ext.declarative import (
    declarative_base as _declarative_base,
    declared_attr as _declared_attr,
    )

from sqlalchemy.ext.hybrid import (
    hybrid_property as _hybrid_property,
    )

import sqlalchemy.orm as _orm
from zope.sqlalchemy import ZopeTransactionExtension as _ZTE

import OpenSSL.crypto as _crypto
from pyramid.decorator import reify as _reify
import datetime as _datetime
import dateutil.parser as _dateutil_parser
import uuid as _uuid


X509_V3 = 0x2  # RFC 2459, 4.1.2.1

# Bitlength to Hash Strength lookup table.
HASH = {1024: "sha1",
        2048: "sha256",
        4096: "sha512"}

# These parts of the subject _must_ match our CA key
CA_SUBJ_MATCH = (b"C", b"ST", b"L", b"O")


def _crypto_patch():
    """hijack _crypto internal lib and violate the default text encoding.
    https://github.com/pyca/pyopenssl/pull/115 has a pull&fix for it
    https://github.com/pyca/pyopenssl/issues/129 is an open issue
    about it."""
    _crypto._lib.ASN1_STRING_set_default_mask_asc(b'utf8only')

_crypto_patch()


# Returns the parts we _care_ about in the subject, from a ca file
def get_ca_prefix(ca_cert, subj_match=CA_SUBJ_MATCH):
    cert = _crypto.load_certificate(_crypto.FILETYPE_PEM, ca_cert)
    subject = cert.get_subject()
    components = subject.get_components()
    matches = tuple((n.decode("utf8"), v.decode("utf8"))
                    for n, v in components
                    if n in subj_match)
    return matches


# XXX: probably error prone for cases where things are specified by string
def _fkcolumn(referent, *args, **kwargs):
    refcol = referent.property.columns[0]
    return _sa.Column(refcol.type, _sa.ForeignKey(referent), *args, **kwargs)

DBSession = _orm.scoped_session(_orm.sessionmaker(extension=_ZTE()))


class Base(object):
    @_declared_attr
    def __tablename__(cls):
        return cls.__name__.lower()

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

# XXX: Newer versions of sqlalchemy have a decorator variant 'as_declarative'
Base = _declarative_base(cls=Base)


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
    pem = _sa.Column(_sa.Text, nullable=False)
    orgunit = _sa.Column(_sa.String(_UB_OU_LEN))
    commonname = _sa.Column(_sa.String(_UB_CN_LEN))
    rejected = _sa.Column(_sa.Boolean(create_constraint=True))
    accessed = _orm.relationship("AccessLog", backref="csr",
                                 order_by="AccessLog.when.desc()")
    certificates = _orm.relationship("Certificate", backref="csr",
                                     order_by="Certificate.not_after.desc()",
                                     cascade="all, delete-orphan",
                                     lazy="subquery")

    def __init__(self, sha256sum, reqtext):
        # XXX: assert sha256(reqtext).hexdigest() == sha256sum ?
        self.sha256sum = sha256sum
        self.pem = reqtext
        # FIXME: Below 4 lines (try/except) are duped in the req() function.
        try:
            self.req.verify(self.req.get_pubkey())
        except _crypto.Error:
            raise ValueError("invalid PEM reqtext")
        # Check for and reject reqtext with trailing content
        pem = _crypto.dump_certificate_request(_crypto.FILETYPE_PEM, self.req)
        if pem != self.pem:
            raise ValueError("invalid PEM reqtext")
        self.orgunit = self.subject.OU
        self.commonname = self.subject.CN
        self.rejected = False

    @_reify
    def req(self):
        req = _crypto.load_certificate_request(_crypto.FILETYPE_PEM, self.pem)
        try:
            req.verify(req.get_pubkey())
        except _crypto.Error:
            raise ValueError("Invalid Request")
        return req

    @_reify
    def subject(self):
        return self.req.get_subject()

    @_reify
    def subject_components(self):
        components = self.subject.get_components()
        return tuple((n.decode("utf8"), v.decode("utf8"))
                     for n, v in components)

    @classmethod
    def valid(cls):
        return cls.query().filter_by(rejected=False)

    @classmethod
    def stale(cls, expiration_date):
        """ Select CSRs that will be expired by expiration_date"""
        subq = (DBSession.query(Certificate.csr_id)
                .distinct()
                .filter(Certificate.not_after < expiration_date))

        return cls.valid().filter(CSR.id.in_(subq))

    @classmethod
    def most_recent_lifetime(cls):
        """ Select CSR id and their matching not_before, not_after
        """
        from sqlalchemy.orm import aliased
        from sqlalchemy.sql.expression import and_, func

        cert = aliased(Certificate)

        subs = (DBSession.query(cert.csr_id,
                                func.max(cert.not_after)
                                .label('max'))
                         .group_by(cert.csr_id)
                         .subquery())

        certs = (DBSession.query(Certificate.csr_id,
                                 Certificate.not_before,
                                 Certificate.not_after)
                 .join(subs, and_(Certificate.csr_id == subs.columns.csr_id,
                                  Certificate.not_after == subs.columns.max)))

        # We have to do filtering in code, as SQLite can't compare DateTimes
        # .filter((Certificate.lifetime * percentage) >
        #         (Certificate.not_after - func.now())))
        return {csr_id: (not_before, not_after)
                for csr_id, not_before, not_after in certs}

    @classmethod
    def signed(cls):
        all_signed = _sa.select([Certificate.csr_id]).distinct()
        return (cls.query()
                .filter_by(rejected=False)
                .filter(CSR.id.in_(all_signed)))

    @classmethod
    def unsigned(cls):
        all_signed = _sa.select([Certificate.csr_id])
        return cls.query().filter_by(rejected=False).\
            filter(CSR.id.notin_(all_signed)).all()

    @classmethod
    def by_sha256sum(cls, sha256sum):
        return cls.query().filter_by(sha256sum=sha256sum).one()

    def __json__(self, request):
        url = request.route_url("cert", sha256=self.sha256sum)
        return dict(sha256=self.sha256sum, url=url)

    def __str__(self):
        return ("<{0.__class__.__name__} "  # auto-concatenation (no comma)
                "sha256sum={0.sha256sum:8.8}... "
                "rejected: {0.rejected!r} "
                "OU={0.orgunit!r} CN={0.commonname!r}>").format(self)

    def __repr__(self):
        return ("<{0.__class__.__name__} id={0.id} "  # (no comma)
                "sha256sum={0.sha256sum}>").format(self)


class AccessLog(Base):
    # XXX: name could be better
    when = _sa.Column(_sa.DateTime, default=_datetime.datetime.utcnow)
    # XXX: name could be better, could perhaps be limited length,
    #      might not want this nullable
    addr = _sa.Column(_sa.Text)
    csr_id = _fkcolumn(CSR.id, nullable=False)

    def __init__(self, csr, addr):
        self.csr = csr
        self.addr = addr

    def __str__(self):
        return ("<{0.__class__.__name__} id={0.id} "
                "csr={0.csr.sha256sum} when={0.when}>").format(self)

    def __repr__(self):
        return "<{0.__class__.__name__} id={0.id}>".format(self)


class Extension(object):
    """Convenience class to make validating Extensions a bit easier"""
    critical = False
    name = None
    data = None
    text = None

    def __init__(self, ext):
        self.name = ext.get_short_name()
        self.critical = bool(ext.get_critical())
        self.data = ext.get_data()
        self.text = str(ext)


class Certificate(Base):
    pem = _sa.Column(_sa.Text, nullable=False)
    # XXX: not_after might be enough
    not_before = _sa.Column(_sa.DateTime, nullable=False)
    not_after = _sa.Column(_sa.DateTime, nullable=False)
    csr_id = _fkcolumn(CSR.id, nullable=False)

    def __init__(self, CSR, pem,  *args, **kws):
        self.pem = pem
        self.csr_id = CSR.id

        req = CSR.req
        cert_pkey = self.cert.get_pubkey()

        # We can't compare pubkeys directly, so we just verify the signature.
        if not req.verify(cert_pkey):
            raise ValueError("Public key of cert cannot verify request")

        self.not_before = _dateutil_parser.parse(self.cert.get_notBefore())
        self.not_after = _dateutil_parser.parse(self.cert.get_notAfter())

    @_hybrid_property
    def lifetime(self):
        return self.not_after - self.not_before

    @_reify
    def cert(self):
        cert = _crypto.load_certificate(_crypto.FILETYPE_PEM, self.pem)

        extensions = {}
        for index in range(0, cert.get_extension_count()):
            ext = cert.get_extension(index)
            my_ext = Extension(ext)
            extensions[my_ext.name] = my_ext

        if cert.get_version() != X509_V3:
            raise ValueError("Not a x509.v3 certificate")

        ext = extensions.get(b'basicConstraints')
        if not ext:
            raise ValueError("Missing Basic Constraints")

        if not ext.critical:
            raise ValueError("Extended Key Usage not critical")

        ext = extensions.get(b'extendedKeyUsage')
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
    def sign(cls, CSR, ca_key, ca_cert, lifetime=_datetime.timedelta(30*3),
             backdate=False):
        """Takes a CSR, signs it, generating and returning a Certificate.
        backdate causes the CA to set "notBefore" of signed certificates to
        match that of the CA Certificate. This is an ugly workaround for a
        timekeeping bug in some firmware.
        """
        notAfter = int(lifetime.total_seconds())
        # Transform "raw" PEM text to usable objects
        try:
            sign_key = _crypto.load_privatekey(_crypto.FILETYPE_PEM, ca_key)
            sign_cert = _crypto.load_certificate(_crypto.FILETYPE_PEM, ca_cert)
        except _crypto.Error:
            raise ValueError("Failed to load signing key or  certificate")
        del ca_cert, ca_key

        # TODO: Verify that the data in DB matches csr_add rules in views.py

        cert = _crypto.X509()
        cert.set_subject(CSR.req.get_subject())
        cert.set_serial_number(int(_uuid.uuid1()))
        cert.set_issuer(sign_cert.get_subject())
        cert.set_pubkey(CSR.req.get_pubkey())
        cert.set_version(X509_V3)
        cert.gmtime_adj_notAfter(notAfter)
        cert.gmtime_adj_notBefore(0)
        if backdate:
            before = sign_cert.get_notBefore()
            cert.set_notBefore(before)
            del before

        subjectAltName = bytes("DNS:" + CSR.commonname, 'utf-8')
        extensions = [
            _crypto.X509Extension(b'basicConstraints',
                                  critical=True,
                                  value=b'CA:FALSE'),
            _crypto.X509Extension(b'extendedKeyUsage',
                                  critical=True,
                                  value=b'clientAuth,serverAuth'),
            _crypto.X509Extension(b"subjectAltName",
                                  critical=False,
                                  value=subjectAltName),
            _crypto.X509Extension(b"subjectKeyIdentifier",
                                  critical=False,
                                  value=b"hash",
                                  subject=cert),
        ]
        cert.add_extensions(extensions)
        # subjectKeyIdentifier has to be present before adding auth ident
        extensions = [
            _crypto.X509Extension(b"authorityKeyIdentifier",
                                  critical=False,
                                  value=b"issuer:always,keyid:always",
                                  issuer=sign_cert)
        ]
        cert.add_extensions(extensions)
        bits = cert.get_pubkey().bits()
        cert.sign(sign_key, HASH[bits])
        pem = _crypto.dump_certificate(_crypto.FILETYPE_PEM, cert)
        return cls(CSR=CSR, pem=pem)
