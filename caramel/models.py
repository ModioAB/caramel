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
import sqlalchemy.orm as _orm
from zope.sqlalchemy import ZopeTransactionExtension as _ZTE

import OpenSSL.crypto as _crypto
from pyramid.decorator import reify as _reify
import datetime as _datetime

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
    accessed = _orm.relationship("AccessLog", backref="csr",
                                 order_by="AccessLog.when.desc()")
    certificates = _orm.relationship("Certificate", backref="csr",
                                     order_by="Certificate.not_after.desc()")

    def __init__(self, sha256sum, reqtext):
        # XXX: assert sha256(reqtext).hexdigest() == sha256sum ?
        self.sha256sum = sha256sum
        self.pem = reqtext
        try:
            self.req.verify(self.req.get_pubkey())
        except _crypto.Error as err:
            raise ValueError("invalid PEM reqtext")
        self.orgunit = self.subject.OU
        self.commonname = self.subject.CN

    @_reify
    def req(self):
        req = _crypto.load_certificate_request(_crypto.FILETYPE_PEM, self.pem)
        # XXX: req.verify(req.get_pubkey()) ?
        return req

    @_reify
    def subject(self):
        return self.req.get_subject()

    @_reify
    def subject_components(self):
        compontents = self.subject.get_components()
        return tuple((n.decode("utf8"), v.decode("utf8"))
                     for n, v in compontents)

    @classmethod
    def by_sha256sum(cls, sha256sum):
        return cls.query().filter_by(sha256sum=sha256sum).one()

    def __json__(self, request):
        url = request.route_url("cert", sha256=self.sha256sum)
        return dict(sha256=self.sha256sum, url=url)

    def __str__(self):
        return ("<{0.__class__.__name__} " # auto-concatenation (no comma)
                "sha256sum={0.sha256sum:8.8}... "
                "OU={0.orgunit!r} CN={0.commonname!r}>").format(self)

    def __repr__(self):
        return ("<{0.__class__.__name__} id={0.id} " # (no comma)
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

class Certificate(Base):
    pem = _sa.Column(_sa.Text, nullable=False)
    # XXX: not_after might be enough
    not_before = _sa.Column(_sa.DateTime, nullable=False)
    not_after = _sa.Column(_sa.DateTime, nullable=False)
    csr_id = _fkcolumn(CSR.id, nullable=False)

    def __init__(self, *args, **kws):
        # TODO: stuff
        return

    def __repr__(self):
        return "<{0.__class__.__name__} id={0.id}>".format(self)
