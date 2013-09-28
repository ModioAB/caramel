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
    )

from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import (
    scoped_session,
    sessionmaker,
    )

from zope.sqlalchemy import ZopeTransactionExtension

from OpenSSL import crypto
from pyramid.decorator import reify

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
