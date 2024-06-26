#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :

import unittest
from operator import attrgetter

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from caramel.models import (
    CSR,
    SigningCert,
)

from . import ModelTestCase, fixtures


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

    def test_trailing_content(self):
        with self.assertRaises(ValueError):
            fixtures.CSRData.trailing_content().save()

    def test_multi_request(self):
        with self.assertRaises(ValueError):
            fixtures.CSRData.multi_request().save()

    def test_not_pem(self):
        with self.assertRaises(ValueError):
            fixtures.CSRData.not_pem().save()

    def test_empty(self):
        with self.assertRaises(ValueError):
            fixtures.CSRData.empty().save()


class TestGetCAPrefix(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_blank_file(self):
        import OpenSSL

        with self.assertRaises(OpenSSL.crypto.Error):
            SigningCert("")

    def test_valid_cert(self):
        ca = SigningCert(fixtures.CertificateData.ca_cert.pem)
        ca.get_ca_prefix()

    def test_outdated_cert_should_work(self):
        ca = SigningCert(fixtures.CertificateData.expired.pem)
        ca.get_ca_prefix()

    def test_empty_returns_from_empty_subject(self):
        ca = SigningCert(fixtures.CertificateData.initial.pem)
        result = ca.get_ca_prefix()
        self.assertEqual((), result)

    def test_empty_returns_from_empty_selector(self):
        ca = SigningCert(fixtures.CertificateData.ca_cert.pem)
        result = ca.get_ca_prefix(())
        self.assertEqual((), result)

    def test_valid_returns_from_default_subject(self):
        ca = SigningCert(fixtures.CertificateData.ca_cert.pem)
        r = ca.get_ca_prefix()
        self.assertEqual(fixtures.CertificateData.ca_cert.common_subject, r)

    def test_only_CN_returns_from_CN_selector(self):
        CN_TUPLE = (("CN", "Caramel Signing Certificate"),)
        ca = SigningCert(fixtures.CertificateData.ca_cert.pem)
        result = ca.get_ca_prefix((b"CN",))
        self.assertEqual(CN_TUPLE, result)

    def test_only_wanted_returns_from_selector(self):
        SELECTED = (
            ("ST", "Östergötland"),
            ("L", "Norrköping"),
            ("OU", "Muppar Teknik"),
        )
        SELECTOR = (b"ST", b"L", b"OU")
        ca = SigningCert(fixtures.CertificateData.ca_cert.pem)
        result = ca.get_ca_prefix(SELECTOR)
        self.assertEqual(SELECTED, result)


class TestQuery(ModelTestCase):
    def test_list_items(self):
        """initial is signed, good is unsigned"""
        initial = fixtures.CSRData.initial
        good = fixtures.CSRData.good()
        good.save()
        expected = [
            (
                1,
                initial.commonname,
                initial.sha256sum,
                initial.certificates[-1].not_after,
            ),
            (2, good.commonname, good.sha256sum, None),
        ]
        self.assertEqual(CSR.list_csr_printable(), expected)

    def test_refreshable(self):
        """Good is not signed and should not be refreshable"""
        fixtures.CSRData.good().save()
        expected = [fixtures.CSRData.initial]
        self.assertSimilarSequence(CSR.refreshable(), expected)

    def test_unsigned(self):
        """Good is not signed and should be the only one"""
        good = fixtures.CSRData.good()
        good.save()
        self.assertSimilarSequence(CSR.unsigned(), [good])
