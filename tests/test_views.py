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

import unittest
import unittest.mock
import transaction
import datetime

from pyramid import testing
from pyramid.response import Response
from pyramid.httpexceptions import (
    HTTPLengthRequired,
    HTTPRequestEntityTooLarge,
    HTTPBadRequest,
    HTTPNotFound,
    )

from . import fixtures, ModelTestCase

from caramel.models import (
    init_session,
    DBSession,
    CSR,
    AccessLog,
    )
from caramel import views


def dummypost(fix, **args):
    req = testing.DummyRequest(**args)
    req.body = fix.pem
    req.content_length = len(req.body)
    req.matchdict["sha256"] = fix.sha256sum
    req.registry.settings['ca.cert'] = 'abc123.crt'
    return req


class TestCSRAdd(ModelTestCase):
    def setUp(self):
        super(TestCSRAdd, self).setUp()
        self.config = testing.setUp()
        # Store original
        self._from_files = views.SigningCert.from_files

        # mock instance that returns value
        _mocking = unittest.mock.Mock()
        _mocking.get_ca_prefix.return_value = fixtures.subject_prefix

        # Mock the object initializer
        views.SigningCert.from_files = unittest.mock.Mock()
        views.SigningCert.from_files.return_value = _mocking

    def tearDown(self):
        super(TestCSRAdd, self).tearDown()
        testing.tearDown()
        views.SigningCert.from_files = self._from_files

    def test_good(self):
        req = dummypost(fixtures.CSRData.good)
        csr = views.csr_add(req)
        self.assertSimilar(fixtures.CSRData.good, csr)

    def test_duplicate(self):
        req = dummypost(fixtures.CSRData.initial)
        with self.assertRaises(HTTPBadRequest):
            views.csr_add(req)

    def test_no_length(self):
        req = dummypost(fixtures.CSRData.good)
        req.content_length = None
        with self.assertRaises(HTTPLengthRequired):
            views.csr_add(req)

    def test_large(self):
        req = dummypost(fixtures.CSRData.large_body)
        with self.assertRaises(HTTPRequestEntityTooLarge):
            views.csr_add(req)

    def test_empty(self):
        req = dummypost(fixtures.CSRData.empty)
        with self.assertRaises(HTTPBadRequest):
            views.csr_add(req)

    def test_not_pem(self):
        req = dummypost(fixtures.CSRData.not_pem)
        with self.assertRaises(HTTPBadRequest):
            views.csr_add(req)

    def test_trailing_junk(self):
        req = dummypost(fixtures.CSRData.trailing_content)
        with self.assertRaises(HTTPBadRequest):
            views.csr_add(req)

    def test_leading_junk(self):
        req = dummypost(fixtures.CSRData.leading_content)
        with self.assertRaises(HTTPBadRequest):
            views.csr_add(req)

    def test_multi_pem(self):
        req = dummypost(fixtures.CSRData.multi_request)
        with self.assertRaises(HTTPBadRequest):
            views.csr_add(req)

    def test_bad_signature(self):
        req = dummypost(fixtures.CSRData.bad_signature)
        with self.assertRaises(HTTPBadRequest):
            views.csr_add(req)

    def test_bad_checksum(self):
        req = dummypost(fixtures.CSRData.bad_sha)
        with self.assertRaises(HTTPBadRequest):
            views.csr_add(req)

    def test_bad_subject(self):
        req = dummypost(fixtures.CSRData.bad_subject)
        with self.assertRaises(HTTPBadRequest):
            views.csr_add(req)


class TestCertFetch(ModelTestCase):
    def setUp(self):
        super(TestCertFetch, self).setUp()
        self.config = testing.setUp()
        self.req = testing.DummyRequest()
        self.req.remote_addr = "test"
        # TODO: ...

    def tearDown(self):
        super(TestCertFetch, self).tearDown()
        testing.tearDown()
        # TODO: ...

    def test_missing(self):
        self.req.matchdict["sha256"] = fixtures.CSRData.good.sha256sum
        accesses = len(AccessLog.all())
        with self.assertRaises(HTTPNotFound):
            views.cert_fetch(self.req)
        self.assertEqual(accesses, len(AccessLog.all()))

    def test_exists_valid(self):
        sha256sum = fixtures.CSRData.initial.sha256sum
        csr = CSR.by_sha256sum(sha256sum)
        now = datetime.datetime.utcnow()
        self.req.matchdict["sha256"] = sha256sum
        resp = views.cert_fetch(self.req)
        # Verify response contents
        self.assertIsInstance(resp, Response)
        self.assertEqual(resp.body, csr.certificates[0].pem)
        self.assertEqual(self.req.response.status_int, 200)
        # Verify there's a new AccessLog entry
        self.assertEqual(csr.accessed[0].addr, self.req.remote_addr)
        self.assertAlmostEqual(csr.accessed[0].when, now,
                               delta=datetime.timedelta(seconds=1))

    def test_exists_expired(self):
        csr = fixtures.CSRData.with_expired_cert()
        csr.save()
        now = datetime.datetime.utcnow()
        self.req.matchdict["sha256"] = csr.sha256sum
        resp = views.cert_fetch(self.req)
        # Verify response contents
        self.assertIs(resp, csr)
        self.assertEqual(self.req.response.status_int, 202)
        # Verify there's a new AccessLog entry
        self.assertEqual(csr.accessed[0].addr, self.req.remote_addr)
        self.assertAlmostEqual(csr.accessed[0].when, now,
                               delta=datetime.timedelta(seconds=1))

    def test_not_signed(self):
        csr = fixtures.CSRData.good()
        csr.save()
        now = datetime.datetime.utcnow()
        self.req.matchdict["sha256"] = csr.sha256sum
        resp = views.cert_fetch(self.req)
        # Verify response contents
        self.assertIs(resp, csr)
        self.assertEqual(self.req.response.status_int, 202)
        # Verify there's a new AccessLog entry
        self.assertEqual(csr.accessed[0].addr, self.req.remote_addr)
        self.assertAlmostEqual(csr.accessed[0].when, now,
                               delta=datetime.timedelta(seconds=1))
        pass


@unittest.skip("Example test case from scaffold, barely altered.")
class TestMyView(unittest.TestCase):
    def setUp(self):
        self.config = testing.setUp()
        from sqlalchemy import create_engine
        engine = create_engine("sqlite://")
        init_session(engine, create=True)
        from caramel.models import MyModel
        with transaction.manager:
            model = MyModel(name="one", value=55)
            model.save()

    def tearDown(self):
        DBSession.remove()
        testing.tearDown()

    def test_it(self):
        from caramel.views import my_view
        request = testing.DummyRequest()
        info = my_view(request)
        self.assertEqual(info["one"].name, "one")
        self.assertEqual(info["project"], "caramel")
