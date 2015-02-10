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
    HTTPForbidden,
    HTTPError
    )
from pyramid.view import view_config

from hashlib import sha256
from datetime import datetime

from .models import (
    CSR,
    AccessLog,
    get_ca_prefix,
    )

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

# Maximum length allowed for csr uploads.
# 2 kbyte should be enough for up to 4 kbit keys.
# XXX: This should probably be handled outside of app (i.e. by the
#      server), or at least be configurable.
_MAXLEN = 2 * 2**10


# Helper that opens the file.
def _get_ca_prefix(filename):
    with open(filename, 'rt') as f:
        ca_cert = f.read()
    return get_ca_prefix(ca_cert)


def raise_for_length(req, limit=_MAXLEN):
    # two possible error cases: no length specified, or length exceeds limit
    # raise appropriate exception if either applies
    length = req.content_length
    if length is None:
        raise HTTPLengthRequired
    if length > limit:
        raise HTTPRequestEntityTooLarge(
            "Max size: {0} kB".format(limit / 2**10)
            )


def raise_for_subject(components, required_prefix):
    if len(components) < len(required_prefix):
        raise ValueError("Too few subject components")
    result = [(x, y) for x, y in zip(components, required_prefix) if x != y]
    if result:
        given, required = zip(*result)
        raise ValueError("{0} do not match {1}".format(given, required))


# XXX: Is this the right way? Catch-class JSON converter of Exceptions
@view_config(context=HTTPError)
def HTTPErrorToJson(exc, request):
    exc.json_body = {
        "status": exc.code,
        "title": exc.title,
        "detail": exc.detail
    }
    exc.content_type = "application/problem+json"
    request.response = exc
    return request.response


@view_config(route_name="csr", request_method="POST", renderer="json")
def csr_add(request):
    # XXX: do length check in middleware? server?
    raise_for_length(request)
    sha256sum = sha256(request.body).hexdigest()
    if sha256sum != request.matchdict["sha256"]:
        raise HTTPBadRequest("hash mismatch ({0})".format(sha256sum))
    try:
        csr = CSR(sha256sum, request.body)
    except ValueError as err:
        raise HTTPBadRequest("crypto error: {0}".format(err))

    # Verify the parts of the subject we care about
    CA_PREFIX = _get_ca_prefix(request.registry.settings['ca.cert'])
    try:
        raise_for_subject(csr.subject_components, CA_PREFIX)
    except ValueError as err:
        raise HTTPBadRequest("Bad subject: {0}".format(err))

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
    if csr.rejected:
        raise HTTPForbidden
    if csr.certificates:
        cert = csr.certificates[0]
        if datetime.utcnow() < cert.not_after:
            # XXX: appropriate content-type is ... ?
            return Response(cert.pem,
                            content_type="application/octet-stream",
                            charset="UTF-8")
    request.response.status_int = 202
    return csr
