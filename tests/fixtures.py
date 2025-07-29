#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
from textwrap import dedent
from hashlib import sha256
from operator import attrgetter
from datetime import datetime, timedelta
from itertools import zip_longest

from caramel import models, views

day = timedelta(days=1)
year = 365 * day  # close enough
now = datetime.now()


class defaultproperty(object):
    def __init__(self, func):
        self.__doc__ = getattr(func, "__doc__", None)
        self.func = func

    def __get__(self, obj, objtype=None):
        return self if obj is None else self.func(obj)


class SimilarityComparable(object):
    _match_excluded_attrs_ = ("match",)

    def match(self, other):
        excludes = set(getattr(self, "_match_excluded_attrs_", ()))
        attrs = [
            attr
            for attr in dir(self)
            if not attr.startswith("_") and attr not in excludes
        ]
        if not attrs:
            return True
        getter = attrgetter(*attrs)
        try:
            return getter(self) == getter(other)
        except AttributeError:
            return False


class AttributeCollection(object):
    def __init__(self, _base_=None, **kwds):
        if _base_:
            kwds = dict(_base_._attrs, **kwds)
        for k, v in kwds.items():
            setattr(self, k, v)
        self._attrs = kwds


class CSRFixture(AttributeCollection, SimilarityComparable):
    __relations = (
        "accessed",
        "certificates",
    )
    commonname: str
    pem: str
    certificates: list

    @property
    def _match_excluded_attrs_(self):
        return super(CSRFixture, self)._match_excluded_attrs_ + self.__relations

    @defaultproperty
    def sha256sum(self):
        return sha256(self.pem).hexdigest()

    def match(self, other):
        if not super(CSRFixture, self).match(other):
            return False
        for relation in self.__relations:
            related = getattr(self, relation, ())
            if related:
                other_related = getattr(other, relation, ())
                if not other_related:
                    return False
                for a, b in zip_longest(related, other_related):
                    if not a.match(b):
                        return False
        return True

    def __call__(self):
        csr = models.CSR(self.sha256sum, self.pem)
        for relation in self.__relations:
            related = getattr(self, relation, ())
            for relatee in related:
                relatee(csr).save()
        return csr


class CertificateFixture(AttributeCollection, SimilarityComparable):
    not_before: datetime
    not_after: datetime
    common_subject: tuple
    pem: str

    def __call__(self, csr):
        # FIXME: adjust when models.Certificate gets a proper __init__
        cert = models.Certificate(csr, self.pem)
        for name, value in self._attrs.items():
            setattr(cert, name, value)
        cert.csr = csr
        return cert


class AccessLogFixture(AttributeCollection, SimilarityComparable):
    when: datetime
    addr: str
    pem: str

    def __call__(self, csr):
        access = models.AccessLog(csr, self.addr)
        access.when = self.when
        return access


# "Correct" subject prefix for test data
subject_prefix = (
    ("O", "Example inc."),
    ("OU", "Example Dept"),
)


class CertificateData(object):
    initial = CertificateFixture(
        not_before=now - 2 * year,
        not_after=now + 2 * year,
        pem=dedent(
            """\
            -----BEGIN CERTIFICATE-----
            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
            d5W1
            -----END CERTIFICATE-----
            """
        ).encode("utf8"),
    )
    empty_subject = CertificateFixture(
        not_before=now - 2 * year,
        not_after=now + 2 * year,
        pem=dedent(
            """\
            -----BEGIN CERTIFICATE-----
            MIIFcTCCA1mgAwIBAgIQGXU+KGyYEfCYQnCFwkLpGzANBgkqhkiG9w0BAQsFADCB
            jjELMAkGA1UEBhMCU0UxFzAVBgNVBAgMDsOWc3RlcmfDtnRsYW5kMRQwEgYDVQQH
            DAtOb3Jya8O2cGluZzESMBAGA1UECgwJTXVwcGFyIEFCMRYwFAYDVQQLDA1NdXBw
            YXIgVGVrbmlrMSQwIgYDVQQDDBtDYXJhbWVsIFNpZ25pbmcgQ2VydGlmaWNhdGUw
            HhcNMjUwNzI5MTYyMTM2WhcNMjUxMDI3MTYyMTM2WjAaMRgwFgYDVQQDDA9mb28u
            ZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCelfEP
            IcJGLKc1x507gms1efETJyz2OISoJ+qmbLrxrlHWEb4Nt+UVEUswp4C3FLzfCEns
            8Hut0ywmg3rpN+3Wj9fnHjH+5SdSbqlURm0klghTIq/xRakWtwqU0LiUkVQU40/h
            FK+VndEDa7zmXR9wqdZ1wijvi9rEVpknXWTfXbbKqKLwOizUe8tZ01h3StYF/sYy
            HqiYwmyE0VHTX+xM50wp+M+zH1afJvtUuGhCZIGjc6UwQ0wAthAW2s3tIszW2wUk
            4Ses1udxslTqiuX8KHhDf0vwK2umpwjLTHenp7uNbaZNmWr4Y/ZVMBo5bczMXb8o
            1py6kwmOK/9ZVMPJAgMBAAGjggE8MIIBODAMBgNVHRMBAf8EAjAAMCAGA1UdJQEB
            /wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAaBgNVHREEEzARgg9mb28uZXhhbXBs
            ZS5jb20wHQYDVR0OBBYEFJ9ZRYBgP8X8FHM931dHnTh1cg/yMIHKBgNVHSMEgcIw
            gb+AFLVqhVvcehx58WPUL03pQL+7FuAHoYGUpIGRMIGOMQswCQYDVQQGEwJTRTEX
            MBUGA1UECAwOw5ZzdGVyZ8O2dGxhbmQxFDASBgNVBAcMC05vcnJrw7ZwaW5nMRIw
            EAYDVQQKDAlNdXBwYXIgQUIxFjAUBgNVBAsMDU11cHBhciBUZWtuaWsxJDAiBgNV
            BAMMG0NhcmFtZWwgU2lnbmluZyBDZXJ0aWZpY2F0ZYIQGVqWaGyYEfCYQnCFwkLp
            GzANBgkqhkiG9w0BAQsFAAOCAgEAlaaw+/TpfseqaqO83nIAKHCApwSNa7Ztpvai
            UpJLX3VSyAW5InFRnppQXLwmc7Dt4XoKyJAUb/CxiZdJGvXrAdZlXCeIGTkTEnhf
            GJxsSJqZ7cPlNk0dk0RHDUgss3jXflsmzxzZS8LFm5O1DUE41psQ+NpphzqbNRqf
            V79nXLg9srO8x95iXNxGOtjKFzDf+/mv6VNx/vE/B/x7J78VO+Dixf+s2q9ZpUEg
            X7NOeGIYBKEzdyOWTcihqwFXpwqDZWhYw349kR/LWELuso1AfENp8MbEWygCU/am
            V1sGKYxt/AgK3RajH+tKFnEHqfgIC6VIL5x8z3hT8mECGRnxawXK1LcE3vhjX4LQ
            fsXf83O9rIQQsnqobshRXMXLg0XICQlaJ+g4JhWrgRh6FGleRy8Z84hcfsmfSHnn
            WS4TezOe5kF30eNOJbSjXuCN+HWV5vUjgvnnKfnnbtW5QoW/MWqC4p51Pq2ZfAsC
            Wtv9jEnSMl2bdy9whdzK3GwxW3G0NsMnDrF4TOv+77U5zJw23GcEUfcrzquZmcJn
            5HTXiigjDz/kOcaEYChPpkhYhJweCMNVKLHDq9PDiIF/oYPs5tHAmr4CS7hu04CD
            LMyYsPkkWjRkyD+uN1IwW9+MwEZomdqB4W5HkKYA2QsG6bxHoE6F0/CpJ6+7G5gB
            sMNVaTs=
            -----END CERTIFICATE-----
            """
        ).encode("utf8"),
    )

    expired = CertificateFixture(
        not_before=initial.not_before,
        not_after=now - 1 * day,
        pem=dedent(
            """\
            -----BEGIN CERTIFICATE-----
            MIIFkjCCA3qgAwIBAgIBaDANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMCU0Ux
            FzAVBgNVBAgMDsOWc3RlcmfDtnRsYW5kMRQwEgYDVQQHDAtOb3Jya8O2cGluZzES
            MBAGA1UECgwJTXVwcGFyIEFCMRYwFAYDVQQLDA1NdXBwYXIgVGVrbmlrMSQwIgYD
            VQQDDBtDYXJhbWVsIFNpZ25pbmcgQ2VydGlmaWNhdGUwHhcNMTUwNzIyMTYzNzIz
            WhcNMTYwNzIyMTYzNzIzWjBJMRUwEwYDVQQKDAxFeGFtcGxlIGluYy4xFTATBgNV
            BAsMDEV4YW1wbGUgRGVwdDEZMBcGA1UEAwwQc3BhbS5leGFtcGxlLmNvbTCCASIw
            DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKM64wXWescJGZO9PEEVmFd0CDps
            4uLeSj8CQtPYvSVE9A7PM5UsRST3OwYBHQBF22Bs6A6s0hw45ppgwY/hNZnoaydr
            xHkpRzb0fdYJyi1kVZbaRKXmvmqcyp6CdQjHvqFQdcRROryzE9j4Qd13nHHE6tfR
            uyBCpMIYzbEmf1YvuM9zsH4Hq5anfthgYGUBDhpPjlvB1qESzx9uXHG5PH7fEhsV
            igDxH/BdfvEmuzrAGVNsT2a/g+rtn7hlQABO39+2pQxPdt+Is8QFGUx6Q1XbLC9b
            bOaeM1yeBFGciQQ39yfj+p7L46CsEWNoOGOOLojrqmEwC9SVi8Mqp0OqY/UCAwEA
            AaOCAT0wggE5MAwGA1UdEwEB/wQCMAAwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwIG
            CCsGAQUFBwMBMBsGA1UdEQQUMBKCEHNwYW0uZXhhbXBsZS5jb20wHQYDVR0OBBYE
            FDGw41ISbvpwXVdNdjdrEkEHJE2QMIHKBgNVHSMEgcIwgb+AFMNkmMv/riTDGeFW
            IGT4JpGTuUDQoYGUpIGRMIGOMQswCQYDVQQGEwJTRTEXMBUGA1UECAwOw5ZzdGVy
            Z8O2dGxhbmQxFDASBgNVBAcMC05vcnJrw7ZwaW5nMRIwEAYDVQQKDAlNdXBwYXIg
            QUIxFjAUBgNVBAsMDU11cHBhciBUZWtuaWsxJDAiBgNVBAMMG0NhcmFtZWwgU2ln
            bmluZyBDZXJ0aWZpY2F0ZYIQTdq+PmyaEfCxpXCFwkLpGzANBgkqhkiG9w0BAQsF
            AAOCAgEAtiHDuxyAJIYfx0vF5ezgNmnKU41OGyyiTEwvlNskKgX4YCGnkKYkoaep
            PDfjqjJfJsP9v+VuadJdaFuEyeWB4ODt0hELR0SDClJ+a6m9OPqc235xW8MIdosR
            LKll6PXAVcuV48UO1msj36wQfRuW6qG2eciVluPiE8KNyevND2HqmjGvozxZTKdV
            8uF1yFwwn14m8i+T72cl+asGV0htSSFAg4LMmBsg3s8/ypZQlvX4dIuzmPMJGZy4
            En8xODVa3NiHMF8u9pVW1MthvfVyhPFnzHU2XEOsDudUmu7TSUQa3kdNX1UwKwHI
            RkUgxPpWk3xxycsr2aC6hl5aGszLrFgg9N6gjNyVdiVUkS/N6jX5st6+W9F3O++s
            n6wjWbIz2Vl4fg6bVvGY6ZT5jnckdvDHauk3zMMZ+055VHb2MNl3LNXa3KCWIDby
            BTcVYn9EN98t1qZwX35bT2vp316GRnkrz3we980z2mN3kK/wBp6kge8ZRaafrvxC
            wCEJrE/SQFOSYHuXr35S/4ct0LivAoGg7lHx2tzaEHhfbvNOKlxZrpj3Zea0h5M9
            CNYHJzx3xAY8s6bX2xePI6WhoDuSjN8Rr2hYBviL5fBwioXjqedeY0kD2qFc248l
            bgpyY2Dsl+fnSnCBI2F205R6s3Y453L6ejAPf07EGVndckrL6g4=
            -----END CERTIFICATE-----
            """
        ).encode("utf8"),
    )
    ca_cert = CertificateFixture(
        not_before=initial.not_before,
        not_after=initial.not_after,
        subject=(
            ("C", "SE"),
            ("ST", "Östergötland"),
            ("L", "Norrköping"),
            ("O", "Muppar AB"),
            ("OU", "Muppar Teknik"),
            ("CN", "Caramel Signing Certificate"),
        ),
        common_subject=(
            ("C", "SE"),
            ("ST", "Östergötland"),
            ("L", "Norrköping"),
            ("O", "Muppar AB"),
        ),
        pem=dedent(
            """\
            -----BEGIN CERTIFICATE-----
            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
            7eLmmg==
            -----END CERTIFICATE-----
            """
        ).encode("utf8"),
    )
    # FIXME: add more certificates here, once we have something to test.


class AccessLogData(object):
    initial_1 = AccessLogFixture(
        when=CertificateData.initial.not_before + 30 * day,
        addr="127.0.0.1",  # XXX: bytestring or unicode string?
    )

    initial_2 = AccessLogFixture(
        when=now - 3 * day,
        addr="127.0.0.127",
    )


class CSRData(object):
    initial = CSRFixture(
        orgunit="Example Dept",
        commonname="foo.example.com",
        pem=dedent(
            """\
            -----BEGIN CERTIFICATE REQUEST-----
            MIICtjCCAZ4CAQAwSDEVMBMGA1UECgwMRXhhbXBsZSBpbmMuMRUwEwYDVQQLDAxF
            eGFtcGxlIERlcHQxGDAWBgNVBAMMD2Zvby5leGFtcGxlLmNvbTCCASIwDQYJKoZI
            hvcNAQEBBQADggEPADCCAQoCggEBAOB0nAi7Fv6UrbfFK5rXZHLmnF54kQH5pxJ8
            U1vnFZMqE+c32N7RvUOKKIlVaKT+PKHpUuqQE17f3m9dbjA8c3bq9hdRizeb3Myr
            JoDZJYHQcsxYsze67LGuhqp0heB9LQR2AmLRADFnsUxWle26Yz3qEqy8uIDdGo4s
            msjb+3fQP3kLNRt0bwYhb90XURynwrYYGkjv+4zbpXmriQkodVHnp7289pebdUAG
            RuSG0jlSwW2ATo1vQDrYe9N91otTu0K28MFvwC3SkDUtWMddpy/WIRte395Jvvpz
            ITqhxbe+3ycW8uPl3xaUG0i5+a/jtaxl2rbPAla/3qsuUXoTKh0CAwEAAaApMCcG
            CSqGSIb3DQEJDjEaMBgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwDQYJKoZIhvcN
            AQELBQADggEBAJjxx/jMg3p7jtNk3wOC67YBaI3+2PhK83cKaSNBvCkXQog5mW4N
            nWiA+fhm5itYqRc++X7uNOPQFDgvkKuP3keNJI54yiToLduSp2DCHP4H80JUN1pj
            VSs6pzJLyjcQ6ZxuXIiLvPcdVLkGk8VkTULuuKiKfErXbld9JuHUFl0oVZaStoJp
            jdbKvm5S9oGiiSQD2p3ucn4SJrJHEBQUyp6kR05P2PBAeA3kwIvkg9smc7J+lfjd
            Nk8XFpL2cMZKxwBZnaokfl4RwBr4TbeOillRcZwI3E6FmIuXQM38X8xdBdboeJX2
            IM4D5LBcVTZ82rveE0hLkmZJaIVM8bb82mg=
            -----END CERTIFICATE REQUEST-----
            """
        ).encode(
            "utf8"
        ),  # py3 dedent can't handle bytes
        subject_components=(
            ("O", "Example inc."),
            ("OU", "Example Dept"),
            ("CN", "foo.example.com"),
        ),
        accessed=[
            AccessLogData.initial_2,
            AccessLogData.initial_1,
        ],
        certificates=[
            CertificateData.initial,
        ],
    )

    empty_subject = CSRFixture(
        orgunit="Example Dept",
        commonname="foo.example.com",
        pem=dedent(
            """\
             -----BEGIN CERTIFICATE REQUEST-----
            MIICiDCCAXACAQAwGjEYMBYGA1UEAwwPZm9vLmV4YW1wbGUuY29tMIIBIjANBgkq
            hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnpXxDyHCRiynNcedO4JrNXnxEycs9jiE
            qCfqpmy68a5R1hG+DbflFRFLMKeAtxS83whJ7PB7rdMsJoN66Tft1o/X5x4x/uUn
            Um6pVEZtJJYIUyKv8UWpFrcKlNC4lJFUFONP4RSvlZ3RA2u85l0fcKnWdcIo74va
            xFaZJ11k3122yqii8Dos1HvLWdNYd0rWBf7GMh6omMJshNFR01/sTOdMKfjPsx9W
            nyb7VLhoQmSBo3OlMENMALYQFtrN7SLM1tsFJOEnrNbncbJU6orl/Ch4Q39L8Ctr
            pqcIy0x3p6e7jW2mTZlq+GP2VTAaOW3MzF2/KNacupMJjiv/WVTDyQIDAQABoCkw
            JwYJKoZIhvcNAQkOMRowGDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DANBgkqhkiG
            9w0BAQsFAAOCAQEAlXvZZ1lkZT/6OCWtCSwVF3o43vzjCL2DzQOiVP7g+kOwAcLJ
            qgIT/lboJgR7ND3G0PCfU0/ddh4FdrJSqQyKORx9nO+wUinyq3voTbzkG6KD0FTt
            u59Pp+TbjRjjpSmWA16frsqoqI01NFRQWPulpTUPrL6JNNjsz9Xzfd7kiOMDi7VW
            d9RUNTv1qmXfB/NwCiWnOzrErC/wpPeU3yRJFq0VQbKwUiY4qbkFcO43SmZ5hLF/
            KfF0Wna+m9IKRE8lykKetIDF6kdwfiq6zR2E3pnsVXOFN51ZL98kxE1VWcVnyj41
            npc1a3rcB7HOhRCC7550gxePeKNfZSsAfrGviQ==
            -----END CERTIFICATE REQUEST-----
            """
        ).encode(
            "utf8"
        ),  # py3 dedent can't handle bytes
        subject_components=(("CN", "foo.example.com"),),
        certificates=[
            CertificateData.empty_subject,
        ],
    )

    with_expired_cert = CSRFixture(
        orgunit="Example Dept",
        commonname="spam.example.com",
        pem=dedent(
            """\
            -----BEGIN CERTIFICATE REQUEST-----
            MIICtzCCAZ8CAQAwSTEVMBMGA1UECgwMRXhhbXBsZSBpbmMuMRUwEwYDVQQLDAxF
            eGFtcGxlIERlcHQxGTAXBgNVBAMMEHNwYW0uZXhhbXBsZS5jb20wggEiMA0GCSqG
            SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjOuMF1nrHCRmTvTxBFZhXdAg6bOLi3ko/
            AkLT2L0lRPQOzzOVLEUk9zsGAR0ARdtgbOgOrNIcOOaaYMGP4TWZ6Gsna8R5KUc2
            9H3WCcotZFWW2kSl5r5qnMqegnUIx76hUHXEUTq8sxPY+EHdd5xxxOrX0bsgQqTC
            GM2xJn9WL7jPc7B+B6uWp37YYGBlAQ4aT45bwdahEs8fblxxuTx+3xIbFYoA8R/w
            XX7xJrs6wBlTbE9mv4Pq7Z+4ZUAATt/ftqUMT3bfiLPEBRlMekNV2ywvW2zmnjNc
            ngRRnIkEN/cn4/qey+OgrBFjaDhjji6I66phMAvUlYvDKqdDqmP1AgMBAAGgKTAn
            BgkqhkiG9w0BCQ4xGjAYMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgXgMA0GCSqGSIb3
            DQEBCwUAA4IBAQCWAHBKO4FKfaSUzR3grc/z448OPCTHMWcuLMCTORYyQcaDq6s6
            K4rmNMWVQuqj75Lfn/Hi7Okyyou0yJnJsPUhi1d4QqUwdoracta+bVj67SN/plXk
            vKxje8BOB4hZUox1rHXw8kdN/oJD3POLMBTUdx9+aV6KOSXEZEs9iCS7PG5kSH/S
            U+h4u3BQOfEppHDzMNgdUTy/7EfMJGNz2deg88oq0/kIluYkXLsP8tH8yClbPSF2
            yezKVLjFgaVt8wqrUbtxIXY9KTHpqaqpLFN0x6KtzJWE9glntfinGx54pEZin4+R
            EfSSIOxmQwfw0179P+UcZoDpn0t7lQpZnadu
            -----END CERTIFICATE REQUEST-----
            """
        ).encode(
            "utf8"
        ),  # py3 dedent can't handle bytes
        subject_components=(
            ("O", "Example inc."),
            ("OU", "Example Dept"),
            ("CN", "spam.example.com"),
        ),
        certificates=[
            CertificateData.expired,
        ],
    )

    good = CSRFixture(
        orgunit="Example Dept",
        commonname="bar.example.com",
        pem=dedent(
            """\
            -----BEGIN CERTIFICATE REQUEST-----
            MIICtjCCAZ4CAQAwSDEVMBMGA1UECgwMRXhhbXBsZSBpbmMuMRUwEwYDVQQLDAxF
            eGFtcGxlIERlcHQxGDAWBgNVBAMMD2Jhci5leGFtcGxlLmNvbTCCASIwDQYJKoZI
            hvcNAQEBBQADggEPADCCAQoCggEBAKt5pZo0gKpU+U4UR8Kx+g3b7PQPbdkjhSDp
            WGkMPuVtWH/2epS+TNBMY12S2kpX1Ufi8ue6vbiki4qnHCsZP/oIY4gvopV7e8ku
            EwfORWVfqpeN8TrI4adQudvgJpr9Fn613hBifer2fDiBV1BvvN8lR+cUi+XfSS7W
            CjIVtThd3TqMHzFoNgepI3UiPlunQh/1aWDTw+L/poCa0GlyRZL2z84abvKzahbR
            d8iPPuMROHgnst+7pRm1RYflzf+3Hqp2WOS492n62eqwS8xjnhonPO6qVJkbmSms
            V5LsFBCo23E9DQwtByiR7YNemAPFeeVR4TAMv/R6GgnWOeqqLV8CAwEAAaApMCcG
            CSqGSIb3DQEJDjEaMBgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwDQYJKoZIhvcN
            AQELBQADggEBACQykUfVcAoA160JKhAtQ3H2VhNy0/LxZ22Oqx/XdVW/WNxuKr8C
            bR/HoqauckKHtF4dOkMuTDkFpSZkiHB1N6kNfeRetZZiavo6idUC5d9ml2B//+FV
            NCDeRIHGzihNu2GJUQk7lzWcBhzUBuFjS4Ic3dCQEgjb2mLN8LcU/coGd0LtAjt3
            U8Vy2U+HhsiHf3iwxwVlAZTDVgbS+hSEyAMHf1Xh9sLZw230C1RGd44TWqrkS3Dp
            y/cJGrUtTWx9DBiX6nhQfbLR/nmW7rXYYRodhzj+aVwYW6MfO5Bjr6AfI4e/pYTY
            G/9DhJMrIomYuhg9kwnwnNFGDUjw6eqW9zc=
            -----END CERTIFICATE REQUEST-----
            """
        ).encode("utf8"),
        subject_components=(
            ("O", "Example inc."),
            ("OU", "Example Dept"),
            ("CN", "bar.example.com"),
        ),
    )

    bad_signature = CSRFixture(  # `good` with the subject of `initial`
        pem=dedent(
            """\
            -----BEGIN CERTIFICATE REQUEST-----
            MIIBAjCBrQIBADBIMRUwEwYDVQQKDAxFeGFtcGxlIGluYy4xFTATBgNVBAsMDEV4
            YW1wbGUgRGVwdDEYMBYGA1UEAwwPZm9vLmV4YW1wbGUuY29tMFwwDQYJKoZIhvcN
            AQEBBQADSwAwSAJBAKk2sD6xi/gfO3TVnoGMhUmkPDD17/qYzEvDdw/kponLTdNF
            asGx1//giKSBqBpUFt+KTz3NofK9Pf2qWWDxyUECAwEAAaAAMA0GCSqGSIb3DQEB
            BQUAA0EAcsrzTdYBqlbq/JQaMSEoi64NmoxiC8GGzOaKlTxqRc7PKb+T1wN94PxJ
            faXw8kA8p0E6hmwFAE9QVkuTKvP/eg==
            -----END CERTIFICATE REQUEST-----
            """
        ).encode("utf8"),
    )

    truncated = CSRFixture(
        pem=dedent(
            """\
            -----BEGIN CERTIFICATE REQUEST-----
            MIIBAjCBrQIBADBIMRUwEwYDVQQKDAxFeGFtcGxlIGluYy4xFTATBgNVBAsMDEV4
            YW1wbGUgRGVwdDEYMBYGA1UEAwwPYmFyLmV4YW1wbGUuY29tMFwwDQYJKoZIhvcN
            AQEBBQADSwAwSAJBAKk2sD6xi/gfO3TVnoGMhUmkPDD17/qYzEvDdw/kponLTdNF
            asGx1//giKSBqBpUFt+KTz3NofK9Pf2qWWDxyUECAwEAAaAAMA0GCSqGSIb3DQEB
            """
        ).encode("utf8"),
    )

    trailing_content = CSRFixture(
        pem=dedent(
            """\
            -----BEGIN CERTIFICATE REQUEST-----
            MIIBAjCBrQIBADBIMRUwEwYDVQQKDAxFeGFtcGxlIGluYy4xFTATBgNVBAsMDEV4
            YW1wbGUgRGVwdDEYMBYGA1UEAwwPYmFyLmV4YW1wbGUuY29tMFwwDQYJKoZIhvcN
            AQEBBQADSwAwSAJBAKk2sD6xi/gfO3TVnoGMhUmkPDD17/qYzEvDdw/kponLTdNF
            asGx1//giKSBqBpUFt+KTz3NofK9Pf2qWWDxyUECAwEAAaAAMA0GCSqGSIb3DQEB
            BQUAA0EAcsrzTdYBqlbq/JQaMSEoi64NmoxiC8GGzOaKlTxqRc7PKb+T1wN94PxJ
            faXw8kA8p0E6hmwFAE9QVkuTKvP/eg==
            -----END CERTIFICATE REQUEST-----
            foo
            bar
            baz
            quux
            """
        ).encode("utf8"),
    )

    leading_content = CSRFixture(
        pem=dedent(
            """\
            foo
            bar
            baz
            quux
            -----BEGIN CERTIFICATE REQUEST-----
            MIIBAjCBrQIBADBIMRUwEwYDVQQKDAxFeGFtcGxlIGluYy4xFTATBgNVBAsMDEV4
            YW1wbGUgRGVwdDEYMBYGA1UEAwwPYmFyLmV4YW1wbGUuY29tMFwwDQYJKoZIhvcN
            AQEBBQADSwAwSAJBAKk2sD6xi/gfO3TVnoGMhUmkPDD17/qYzEvDdw/kponLTdNF
            asGx1//giKSBqBpUFt+KTz3NofK9Pf2qWWDxyUECAwEAAaAAMA0GCSqGSIb3DQEB
            BQUAA0EAcsrzTdYBqlbq/JQaMSEoi64NmoxiC8GGzOaKlTxqRc7PKb+T1wN94PxJ
            faXw8kA8p0E6hmwFAE9QVkuTKvP/eg==
            -----END CERTIFICATE REQUEST-----
            """
        ).encode("utf8"),
    )

    multi_request = CSRFixture(
        pem=dedent(
            """\
            -----BEGIN CERTIFICATE REQUEST-----
            MIIBAjCBrQIBADBIMRUwEwYDVQQKDAxFeGFtcGxlIGluYy4xFTATBgNVBAsMDEV4
            YW1wbGUgRGVwdDEYMBYGA1UEAwwPZm9vLmV4YW1wbGUuY29tMFwwDQYJKoZIhvcN
            AQEBBQADSwAwSAJBANBBe43zbCwPs1jRPPqgb6Otdqx9kg67Dgfoxh3Mly7b9JPp
            orKIs6zzoyMeLHLJYk+CwSHyeS1hc4zL+3A+k88CAwEAAaAAMA0GCSqGSIb3DQEB
            BQUAA0EALt6dIjlzG05KCfyiy2PJdAwcjC+mpHh3i4cJs50U+EnxBgX8QscOu382
            72uukmhYBG1Xd1LN4S5RL9pcQ9KLaA==
            -----END CERTIFICATE REQUEST-----
            -----BEGIN CERTIFICATE REQUEST-----
            MIIBAjCBrQIBADBIMRUwEwYDVQQKDAxFeGFtcGxlIGluYy4xFTATBgNVBAsMDEV4
            YW1wbGUgRGVwdDEYMBYGA1UEAwwPYmFyLmV4YW1wbGUuY29tMFwwDQYJKoZIhvcN
            AQEBBQADSwAwSAJBAKk2sD6xi/gfO3TVnoGMhUmkPDD17/qYzEvDdw/kponLTdNF
            asGx1//giKSBqBpUFt+KTz3NofK9Pf2qWWDxyUECAwEAAaAAMA0GCSqGSIb3DQEB
            BQUAA0EAcsrzTdYBqlbq/JQaMSEoi64NmoxiC8GGzOaKlTxqRc7PKb+T1wN94PxJ
            faXw8kA8p0E6hmwFAE9QVkuTKvP/eg==
            -----END CERTIFICATE REQUEST-----
            """
        ).encode("utf8"),
    )

    not_pem = CSRFixture(
        pem=dedent(
            """\
            Egg and Bacon
            Egg, Sausage and Bacon
            Egg and Spam
            Egg, Bacon and Spam
            Egg, Bacon, Sausage and Spam
            Spam, Bacon, Sausage and Spam
            Spam, Egg, Spam, Spam, Bacon and Spam
            Spam, Spam, Spam, Egg and Spam
            Spam, Spam, Spam, Spam, Spam, Spam, Baked Beans,
                Spam, Spam, Spam and Spam
            """
        ).encode("utf8"),
    )

    empty = CSRFixture(pem=b"")

    bad_sha = CSRFixture(good, sha256sum=not_pem.sha256sum)

    bad_subject = CSRFixture(
        orgunit="Example test dept.",
        commonname="baz.example.com",
        pem=dedent(
            """\
            -----BEGIN CERTIFICATE REQUEST-----
            MIIBCDCBswIBADBOMRUwEwYDVQQKDAxFeGFtcGxlIGluYy4xGzAZBgNVBAsMEkV4
            YW1wbGUgdGVzdCBkZXB0LjEYMBYGA1UEAwwPYmF6LmV4YW1wbGUuY29tMFwwDQYJ
            KoZIhvcNAQEBBQADSwAwSAJBAOQ+LeU8pbEg5/XeD+HLnGah4A96qDL4HtNsTW0N
            //DbwGchtE8h9LSs3ePXWDVHak87Jx8A+wq7DRUd/LDVP6cCAwEAAaAAMA0GCSqG
            SIb3DQEBBQUAA0EAhriivXQYFbdc8QrnDjwVCX8ZGXiGKQEC66LceWDdvOy+mDu8
            gi+L6IgnptU8VmEowAPp0veIH1MWJrnGdp7M0g==
            -----END CERTIFICATE REQUEST-----
        """
        ).encode("utf-8"),
        subject_components=(
            ("O", "Example inc."),
            ("OU", "Example test dept."),
            ("CN", "baz.example.com"),
        ),
    )

    large_body = CSRFixture(
        pem="".join(("foobar", "x" * views._MAXLEN)).encode("utf-8"),
    )
