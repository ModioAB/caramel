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

from pyramid.httpexceptions import (
    HTTPLengthRequired,
    HTTPRequestEntityTooLarge,
    HTTPBadRequest,
    HTTPNotFound,
    )
from pyramid.view import view_config

from hashlib import sha256

from .models import (
    DBSession,
    CSR,
    )

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

_MAXLEN = 2 * 2**10             # should be enough for up to 4kb keys
## FIXME: figure out how we should compare client DN to CA DN
# Fixed prefix for certs created by us
_CA_PREFIX = ((b"C", b"SE"), (b"ST", b"Ostergotland"), (b"L", b"Linkoping"),
              (b"O", b"Mymodio AB"))


def raise_for_length(req, limit=_MAXLEN):
    # two possible error cases: no length specified, or length exceeds limit
    # raise appropriate exception if either applies
    # XXX: do this better somehow.
    length = req.content_length
    if not length:
        raise HTTPLengthRequired
    if length > limit:
        raise HTTPRequestEntityTooLarge(
                "Max size: {0} kB".fromat(limit / 2**10)
                )

def acceptable_subject(subject, required_prefix=_CA_PREFIX):
    # XXX: figure out how to do this properly. this is somewhat ugly.
    return all(x == y for x, y in zip(subject.get_components(),
                                      required_prefix))


@view_config(route_name="csr", request_method="POST", renderer="json")
def csr_add(request):
    # XXX: do length check in middleware? server?
    raise_for_length(request)
    sha256sum = sha256(request.body).hexdigest()
    if sha256sum != request.matchdict["sha256"]:
        raise HTTPBadRequest
    try:
        csr = CSR(sha256sum, request.body)
    except crypto.Error:
        raise HTTPBadRequest
    # XXX: figure out what to verify in subject, and how
    if not acceptable_subject(csr.subject):
        raise HTTPBadRequest
    # XXX: store things in DB
    try:
        DBSession.add(csr)
    except IntegrityError:
        raise HTTPBadRequest    # XXX: is this what we want here?
    # We've accepted the signing request, but there's been no signing yet
    request.response.status_int = 202
    # JSON-rendered data (client could calculate this itself, and often will)
    return csr

@view_config(route_name="cert", request_method="GET", renderer="json")
def cert_fetch(request):
    # XXX: JSON-renderer at the moment, to dump
    sha256sum = request.matchdict["sha256"]
    try:
        csr = DBSession.query(CSR).filter_by(sha256sum=sha256sum).one()
    except NoResultFound:
        raise HTTPNotFound
    # XXX: should add/update some sort of access log here
    # XXX: should check for cert here.
    #      for now, just say that the request has been accepted.
    request.response.status_int = 202
    return csr
