#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :

from caramel.models import (
    SubjectAltNameKinds,
    SubjectAltName,
)

from . import ModelTestCase


class TestSubjectAltName(ModelTestCase):

    def test_inits_okay(self):
        SubjectAltName(
            SubjectAltNameKinds.IP,
            "127.0.0.1",
        )
        SubjectAltName(
            SubjectAltNameKinds.DNS,
            "example.com",
        )

    def test_fails_expectedly(self):
        with self.assertRaises(ValueError):
            SubjectAltName(
                SubjectAltNameKinds.email,
                "abc@example.com",
            )

        with self.assertRaises(ValueError):
            SubjectAltName(
                SubjectAltNameKinds.URI,
                "mailto:abc@example.com"
            )

    def test_ip_converter(self):
        out = SubjectAltName.convert_ip("127.0.0.1")
        self.assertEqual(out, "127.0.0.1")

        out = SubjectAltName.convert_ip("::1")
        self.assertEqual(out, "0000:0000:0000:0000:0000:0000:0000:0001")

    def test_converters_return_strings(self):
        out = SubjectAltName.convert_ip("127.0.0.1")
        self.assertIsInstance(out, str)

        out = SubjectAltName.convert_dns("localhost.localdomain")
        self.assertIsInstance(out, str)

    def test_dns_converter_correct_version(self):
        # normalising normally
        out = SubjectAltName.convert_dns("räksmörgås.se")
        self.assertEqual(out, "xn--rksmrgs-5wao1o.se")

        # Normalizing caps
        out = SubjectAltName.convert_dns("RäksmÖrgÅs.se")
        self.assertEqual(out, "xn--rksmrgs-5wao1o.se")

        out = SubjectAltName.convert_dns("example.com")
        self.assertEqual(out, "example.com")

    def test_dns_converter_roundtrips_okay(self):
        # converted values should be passed through as-is
        out = SubjectAltName.convert_dns("xn--rksmrgs-5wao1o.se")
        self.assertEqual(out, "xn--rksmrgs-5wao1o.se")

        # bytes should roundtrip the same way unicode does
        out = SubjectAltName.convert_dns(b"xn--rksmrgs-5wao1o.se")
        self.assertEqual(out, "xn--rksmrgs-5wao1o.se")

    def test_dns_validator_binary_input(self):
        with self.assertRaises(ValueError):
            SubjectAltName.normalise_dns(b"localhost")

    def test_dns_validator_length_of_conversions(self):
        # Should work ok
        SubjectAltName.normalise_dns("A" * 63)

        with self.assertRaises(ValueError):
            SubjectAltName.normalise_dns("A" * 64)

        # Ö should cause it to expand
        with self.assertRaises(ValueError):
            SubjectAltName.normalise_dns("Ö" + "A" * 61)

    def test_outputs_ok(self):
        se = SubjectAltName(SubjectAltNameKinds.DNS, "Räksmörgås")
        self.assertEqual("DNS:räksmörgås", str(se))
        self.assertEqual(b"DNS:xn--rksmrgs-5wao1o", bytes(se))

        dns = SubjectAltName(SubjectAltNameKinds.DNS, "example.com")
        self.assertEqual(b"DNS:example.com", bytes(dns))
        self.assertEqual("DNS:example.com", str(dns))

        ip = SubjectAltName(SubjectAltNameKinds.IP, "127.0.0.1")
        self.assertEqual(b"IP:127.0.0.1", bytes(ip))
        self.assertEqual("IP:127.0.0.1", str(ip))
