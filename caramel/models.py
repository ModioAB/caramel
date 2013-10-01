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

from sqlalchemy import (
    Column,
    Integer,
    Text,
    CHAR,
    String,
    DateTime,
    ForeignKey,
    )

from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import (
    scoped_session,
    sessionmaker,
    relationship,
    backref,
    )

from zope.sqlalchemy import ZopeTransactionExtension

from OpenSSL import crypto
from pyramid.decorator import reify

import datetime

# XXX: probably error prone for cases where things are specified by string
def foreignkeycol(referent, *args, **kwargs):
    refcol = referent.property.columns[0]
    return Column(refcol.type, ForeignKey(referent), *args, **kwargs)

DBSession = scoped_session(sessionmaker(extension=ZopeTransactionExtension()))
Base = declarative_base()

# Upper bounds from RFC 5280
_UB_CN_LEN = 64
_UB_OU_LEN = 64

# Length of hex digest of a sha256 checksum
_SHA256_LEN = 64

class CSR(Base):
    __tablename__ = "requests"

    id = Column(Integer, primary_key=True)
    sha256sum = Column(CHAR(_SHA256_LEN), unique=True, nullable=False)
    pem = Column(Text, nullable=False)
    orgunit = Column(String(_UB_OU_LEN))
    commonname = Column(String(_UB_CN_LEN))
    accessed = relationship("AccessLog", backref="csr",
                            order_by="AccessLog.when.desc()")
    certificates = relationship("Certificate", backref="csr",
                                order_by="Certificate.not_after.desc()")

    def __init__(self, sha256sum, reqtext):
        # XXX: assert sha256(reqtext).hexdigest() == sha256sum ?
        self.sha256sum = sha256sum
        self.pem = reqtext
        self.req.verify(self.req.get_pubkey())
        self.orgunit = self.subject.OU
        self.commonname = self.subject.CN

    @reify
    def req(self):
        req = crypto.load_certificate_request(crypto.FILETYPE_PEM, self.pem)
        # XXX: req.verify(req.get_pubkey()) ?
        return req

    @reify
    def subject(self):
        return self.req.get_subject()

    def __json__(self, request):
        url = request.route_url("cert", sha256=self.sha256sum)
        return dict(sha256=self.sha256sum, url=url)

    def __str__(self):
        return (b"<{0.__class__.__name__} " # auto-concatenation (no comma)
                b"sha256sum={0.sha256sum:8.8}... "
                b"OU={0.orgunit!r} CN={0.commonname!r}>").format(self)

    def __repr__(self):
        return (b"<{0.__class__.__name__} id={0.id} " # (no comma)
                b"sha256sum={0.sha256sum}>").format(self)

class AccessLog(Base):
    __tablename__ = "accesslog"

    id = Column(Integer, primary_key=True)
    # XXX: name could be better
    when = Column(DateTime, default=datetime.datetime.utcnow)
    # XXX: name could be better, could perhaps be limited length,
    #      might not want this nullable
    addr = Column(Text)
    csr_id = foreignkeycol(CSR.id, nullable=False)

    def __init__(self, csr, addr):
        self.csr = csr
        self.addr = addr

    def __str__(self):
        return (b"<{0.__class__.__name__} id={0.id} "
                b"csr={0.csr.sha256sum} when={0.when}>").format(self)

    def __repr__(self):
        return b"<{0.__class__.__name__} id={0.id}>".format(self)

class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True)
    pem = Column(Text, nullable=False)
    # XXX: not_after might be enough
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False)
    csr_id = foreignkeycol(CSR.id, nullable=False)

    def __init__(self, *args, **kws):
        # TODO: stuff
        return

    def __repr__(self):
        return b"<{0.__class__.__name__} id={0.id}>".format(self)
