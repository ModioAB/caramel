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
import functools                # XXX: mocking subject validation
import transaction

from pyramid import testing
from pyramid.httpexceptions import (
    HTTPLengthRequired,
    HTTPRequestEntityTooLarge,
    HTTPBadRequest,
    HTTPNotFound,
    )

from . import fixtures, ModelTestCase

from caramel.models import init_session, DBSession
from caramel import views


def dummypost(fix, **args):
    req = testing.DummyRequest(**args)
    req.body = fix.pem
    req.content_length = len(req.body)
    req.matchdict["sha256"] = fix.sha256sum
    return req


class TestCSRAdd(ModelTestCase):
    def setUp(self):
        super(TestCSRAdd, self).setUp()
        self.config = testing.setUp()
        # XXX: subject validation subject to change, will probably
        #      need work here.
        self._subject_validation = views.acceptable_subject
        views.acceptable_subject = functools.partial(
            views.acceptable_subject,
            required_prefix=fixtures.subject_prefix,
            )
        # TODO: ...

    def tearDown(self):
        super(TestCSRAdd, self).tearDown()
        testing.tearDown()
        views.acceptable_subject = self._subject_validation
        # TODO: ...

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
