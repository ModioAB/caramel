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

from caramel.models import CSR
from . import fixtures, ModelTestCase

import unittest
from operator import attrgetter
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound


class TestCSR(ModelTestCase):
    def test_good(self):
        csrs = [fixtures.CSRData.initial]
        self.assertSimilarSequence(CSR.all(), csrs)
        csrs.append(fixtures.CSRData.good)
        csrs[-1]().save()
        sortkey = attrgetter("sha256sum")
        csrs.sort(key=sortkey)
        self.assertSimilarSequence(sorted(CSR.all(), key=sortkey), csrs)
        self.assertTrue(csrs[1].match(CSR.by_sha256sum(csrs[1].sha256sum)))

    def test_not_found(self):
        with self.assertRaises(NoResultFound):
            CSR.by_sha256sum(fixtures.CSRData.good.sha256sum)

    def test_not_unique(self):
        with self.assertRaises(IntegrityError):
            fixtures.CSRData.initial().save()

    def test_bad_signature(self):
        with self.assertRaises(ValueError):
            fixtures.CSRData.bad_signature().save()

    def test_truncated(self):
        with self.assertRaises(ValueError):
            fixtures.CSRData.truncated().save()

    # XXX: nose has no support for expectedFailure, so skip()-ing instead
    @unittest.skip("Expected to fail, see issue #14.")
    def test_trailing_content(self):
        with self.assertRaises(ValueError):
            fixtures.CSRData.trailing_content().save()

    @unittest.skip("Expected to fail, see issue #14.")
    def test_multi_request(self):
        with self.assertRaises(ValueError):
            fixtures.CSRData.multi_request().save()

    def test_not_pem(self):
        with self.assertRaises(ValueError):
            fixtures.CSRData.not_pem().save()
