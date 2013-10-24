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

from pyramid.response import Response
from pyramid.httpexceptions import (
    HTTPLengthRequired,
    HTTPRequestEntityTooLarge,
    HTTPBadRequest,
    HTTPNotFound,
    )
from pyramid.view import view_config

from hashlib import sha256
from datetime import datetime

from .models import (
    CSR,
    AccessLog,
    )

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

_MAXLEN = 2 * 2**10             # should be enough for up to 4kb keys
## FIXME: figure out how we should compare client DN to CA DN
# Fixed prefix for certs created by us
_CA_PREFIX = (("C", "SE"), ("ST", "Ostergotland"), ("L", "Linkoping"),
              ("O", "Mymodio AB"))


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

def acceptable_subject(components, required_prefix=_CA_PREFIX):
    # XXX: figure out how to do this properly. this is somewhat ugly.
    return (len(components) >= len(required_prefix) and
            all(x == y for x, y in zip(components, required_prefix)))


@view_config(route_name="csr", request_method="POST", renderer="json")
def csr_add(request):
    # XXX: do length check in middleware? server?
    raise_for_length(request)
    sha256sum = sha256(request.body).hexdigest()
    if sha256sum != request.matchdict["sha256"]:
        raise HTTPBadRequest("hash mismatch ({0})".format(sha256sum))
    try:
        csr = CSR(sha256sum, request.body)
    except crypto.Error as err:
        raise HTTPBadRequest("crypto error: {0}".format(err))
    # XXX: figure out what to verify in subject, and how
    if not acceptable_subject(csr.subject_components):
        raise HTTPBadRequest("bad subject: {0}".format(csr.subject_components))
    # XXX: store things in DB
    try:
        csr.save()
    except IntegrityError:
        # XXX: is this what we want here?
        raise HTTPBadRequest("duplicate request")
    # We've accepted the signing request, but there's been no signing yet
    request.response.status_int = 202
    # JSON-rendered data (client could calculate this itself, and often will)
    return csr

@view_config(route_name="cert", request_method="GET", renderer="json")
def cert_fetch(request):
    # XXX: JSON-renderer at the moment, to dump
    sha256sum = request.matchdict["sha256"]
    try:
        csr = CSR.by_sha256sum(sha256sum)
    except NoResultFound:
        raise HTTPNotFound
    # XXX: Exceptions? remote_addr or client_addr?
    AccessLog(csr, request.remote_addr).save()
    if csr.certificates:
        cert = csr.certificates[0]
        if datetime.utcnow() < cert.not_after:
            # XXX: appropriate content-type is ... ?
            return Response(cert.pem,
                            content_type="application/octet-stream",
                            charset="UTF-8")
    request.response.status_int = 202
    return csr
