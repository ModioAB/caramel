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

from operator import attrgetter


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
