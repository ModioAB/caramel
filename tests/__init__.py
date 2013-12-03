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
import transaction

from caramel.models import (
    init_session,
    DBSession,
    )

from . import fixtures

try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest


class ModelTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(ModelTestCase, cls).setUpClass()
        # Clear existing session, if any.
        DBSession.remove()
        from sqlalchemy import create_engine
        engine = create_engine("sqlite://")
        init_session(engine, create=True)
        with transaction.manager:
            csr = fixtures.CSRData.initial()
            csr.save()

    def setUp(self):
        super(ModelTestCase, self).setUp()
        # Always run in a fresh session
        DBSession.remove()

    def assertSimilar(self, a, b, msg=None):
        if isinstance(b, fixtures.SimilarityComparable):
            a, b = b, a
        if isinstance(a, fixtures.SimilarityComparable):
            return self.assertTrue(a.match(b), msg)
        return self.assertEqual(a, b, msg)

    def assertSimilarSequence(self, seq1, seq2, msg=None):
        for a, b in zip_longest(seq1, seq2):
            self.assertSimilar(a, b)
