#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
import unittest
from itertools import zip_longest

import transaction

from caramel.models import (
    DBSession,
    init_session,
)

from . import fixtures


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
