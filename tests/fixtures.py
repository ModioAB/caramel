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

from textwrap import dedent
from hashlib import sha256
from operator import attrgetter

try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest

from datetime import datetime, timedelta
day = timedelta(days=1)
year = 365 * day                # close enough
now = datetime.now()

from caramel import (
    models,
    views,
    )


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
        attrs = [attr for attr in dir(self)
                 if not attr.startswith("_") and attr not in excludes]
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
    __relations = ("accessed", "certificates",)

    @property
    def _match_excluded_attrs_(self):
        return (super(CSRFixture, self)._match_excluded_attrs_ +
                self.__relations)

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
    def __call__(self, csr):
        # FIXME: adjust when models.Certificate gets a proper __init__
        cert = models.Certificate(csr, self.pem)
        for name, value in self._attrs.items():
            setattr(cert, name, value)
        cert.csr = csr
        return cert


class AccessLogFixture(AttributeCollection, SimilarityComparable):
    def __call__(self, csr):
        access = models.AccessLog(csr, self.addr)
        access.when = self.when
        return access


# "Correct" subject prefix for test data
subject_prefix = (('O', 'Example inc.'), ('OU', 'Example Dept'),)


class CertificateData(object):
    initial = CertificateFixture(
        not_before=now - 2 * year,
        not_after=now + 2 * year,
        pem=dedent("""\
            -----BEGIN CERTIFICATE-----
            MIIEVDCCAjygAwIBAgIBZTANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDDBtDYXJh
            bWVsIFNpZ25pbmcgQ2VydGlmaWNhdGUwHhcNMTQwODA4MTM0NDA0WhcNMTQxMDA4
            MTM0NDA0WjAaMRgwFgYDVQQDDA9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3
            DQEBAQUAA4IBDwAwggEKAoIBAQC+UOYhTExyWQL/mPzxvkd4xzju9Gcoxu5WZxxP
            +FjvsCKXkdMdzyTGYuaOulsRqyNmc8N73KJa9rlajIxdtR7duBwzX6Ddx2MmOLVL
            Q95X0jzdYR9iv6NX+bdYnoFUuzFt6N6Tf6OFS7IGiCeYqN7JTzTwlseJ7O4ozdsk
            vNlw7Cybb5RjqJQ/TRDSDWp1Fuq7FXanM+9Eaok0xqGty1TdMiEsCK8t7w3F1gd3
            bt48hld7cfe+OqdPxFLLtXv6wVM8EzcFYmwBGx7avXVS8aOsN6Oc3FZBfW0Fi0XD
            S6YO7WSzsRqciXolv/zPIvc1g6z5RkIPlgUaCtAdNBWkDG0hAgMBAAGjgZgwgZUw
            DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQU
            79OVse0vdmb3VW6T9P7haHDOrhEwTgYDVR0jBEcwRYAUt9UtYpijdgeh1fObZHE4
            EBJPROGhKqQoMCYxJDAiBgNVBAMMG0NhcmFtZWwgU2lnbmluZyBDZXJ0aWZpY2F0
            ZYIBADANBgkqhkiG9w0BAQsFAAOCAgEAN8oppVaZlklLmvD1OfG0jf7SwWa03x6L
            Ej7xh0EbCeTZXNCmJNjiPpYG57Lf7OlXit9u1aJUQ5VXpUDmv1njb0jnB3EJBWf/
            Y2KZbRYgXCpMUXxmfLrntULHAn/M3RLNi1ovwisiBqAU5/SZLcRq26Uwb8ygT0K7
            OA80JqjVzv53nKdUmDR0mopiWiU8c5BTi0R5+Q9vGov+DBcmrgatIHrtiXG8exGK
            m/DHZMAA93Vv/nh6GUe9uWI4mDhhLRSrdfkHoTPDqrFHIdH4OC+ljlPDRNhpkWAt
            FIzejEk5pqyqnAW4HHWM13vtOpddnXea+1y6PCX/9InAP5Tl1HMcq7BOgQa+EyPN
            NdzIRtdRnhtncMJUTCJpm2QEH09aPM3411tFpG3nZ6eTvo5f6oZS+epBVwNVqFXm
            xTbIEnBFnVBhQh2mXgJJsac2Oy8KGyBnVvGn6FKB6slrBjcIWKg+CDyiXMjwKhk5
            bjUvUdML4uWoGqdJfl+S+f+8m6S6F276p/uLI8Kb0NaE+z+LFRp2wrrC7DW65R+W
            eMdFWSu/IZZkoEaTrOeaqmLtQQt/4s66KKNOddftt+uLEMjce7foYQHo+qx9RI/1
            n4rH2rFn8rcQwSaRyE9NcOpirCur43MR42+LAfZq5s9j7CuQJTw6G0wvCHGqRIQ9
            X1qbQOxg6ig=
            -----END CERTIFICATE-----
            """).encode("utf8"),
        )

    expired = CertificateFixture(
        not_before=initial.not_before,
        not_after=now - 1 * day,
        pem=dedent("""\
            -----BEGIN CERTIFICATE-----
            MIIEVTCCAj2gAwIBAgIBaDANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDDBtDYXJh
            bWVsIFNpZ25pbmcgQ2VydGlmaWNhdGUwHhcNMTQwODA4MTM1OTUxWhcNMTQxMDA4
            MTM1OTUxWjAbMRkwFwYDVQQDDBBzcGFtLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG
            9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnrzJ2qNhyIiCZvikFvPr0iEfzf27kTfHN+13
            7bGuTAzmXFFrajz9K+leYcZR4sCPPRI8QjEUSYcngP1LKUrgzUSldjPrQGLsmx+8
            gLdi2JN1kPu6uMT97uB1RDKQpIMHGuV4mJKJku3sh6DJvQMjuMv8xOUXHtCw9jjc
            6CLI9zeEZfM1RXsmRVxLx8HuwlF8ZNRjPGn5lEGIxTORpF1Mef5eTnGIg2kxwj8F
            5aJP4ei9XS6gbYSFZekruT9Ivh41x4FYmx4bcGQfuIu+cG+XI3xGoNrm/IKMguMQ
            vwjBj2XnLHzskR5mz9YSLd9vi1nHl7b5u9GDtpmliNOvehaxjQIDAQABo4GYMIGV
            MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYE
            FH/tkDyXntmyru3UFyYTO6UTOwjuME4GA1UdIwRHMEWAFLfVLWKYo3YHodXzm2Rx
            OBAST0ThoSqkKDAmMSQwIgYDVQQDDBtDYXJhbWVsIFNpZ25pbmcgQ2VydGlmaWNh
            dGWCAQAwDQYJKoZIhvcNAQELBQADggIBAD4r7SEyD6A61ORVjHHpw+5nZuaIf3Xs
            nZakE5I+wm/ZsVmWO3iOjAKdL2HartlDqGAvX5/w/sEoOkrpr48R7Uolm4ojYD2B
            Etxb4p9PDHmgT9Sc8nE2hOh8FdIUiGVLRJOuCmZqgk+EBIwB0zJQjREXHVZaN4dS
            wNNQGz46Vd2b6e4iRCJdgfOd2tuJi/WtvQORJkJ+HeTwLcN9LYY6d1bgups970DP
            Ve3QzxowNaRdX4SNtTmWs2BqcpYJV/Bx+q5r5CxhuDs5Jyvfmh9K7ux8z8Rv9THm
            UPJSXahBKLIYI8BYotXB9vpHvgWd15Opa3g+MV1Ego7KDKvdirTKnIcvafAi47vo
            kpAussllmvGr3wjDrGLlvbyBbbg44MpTzZrWspAjm9t0XFwkDDZGjY9l1zzqolDa
            KXbDda3LApBjWOr2QxsiwuOcemeekyiYusx5O4NqWJhGRVluvLpo5FWvuGZfoTCG
            X9QYUVrbsvhMMZR0VQDkJ7zfqbA8HvZ72qRpkC3MkOKDo4Ve9PffRjK+bamZM38I
            rvKws1E0w1WI1cK8ypefZhF8BiC/KUFMBw3bQAUQqdubv4eN81IX0PjnpfH+7wwA
            7CRL6mRM5+q4ICfesXzUXpPYjgD2UexIjSJNoYjiu3aKpjwvrZ88t8hPR46Uac7E
            5yvm61Agw/Tg
            -----END CERTIFICATE-----
            """).encode("utf8"),
        )

    ca_cert = CertificateFixture(
        not_before=initial.not_before,
        not_after=initial.not_after,
        subject=(('C', 'SE'), ('ST', 'Östergötland'),
                 ('L', 'Norrköping'), ('O', 'Muppar AB'),
                 ('OU', 'Muppar Teknik'),
                 ('CN', 'Caramel Signing Certificate')),

        common_subject=(('C', 'SE'), ('ST', 'Östergötland'),
                        ('L', 'Norrköping'), ('O', 'Muppar AB')),

        pem=dedent("""\
            -----BEGIN CERTIFICATE-----
            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
            7eLmmg==
            -----END CERTIFICATE-----
            """).encode("utf8"),
        )
    # FIXME: add more certificates here, once we have something to test.


class AccessLogData(object):
    initial_1 = AccessLogFixture(
        when=CertificateData.initial.not_before + 30 * day,
        addr="127.0.0.1",       # XXX: bytestring or unicode string?
        )

    initial_2 = AccessLogFixture(
        when=now - 3 * day,
        addr="127.0.0.127",
        )


class CSRData(object):
    initial = CSRFixture(
        orgunit="Example Dept",
        commonname="foo.example.com",
        pem=dedent("""\
            -----BEGIN CERTIFICATE REQUEST-----
            MIICjTCCAXUCAQIwSDEVMBMGA1UECgwMRXhhbXBsZSBpbmMuMRUwEwYDVQQLDAxF
            eGFtcGxlIERlcHQxGDAWBgNVBAMMD2Zvby5leGFtcGxlLmNvbTCCASIwDQYJKoZI
            hvcNAQEBBQADggEPADCCAQoCggEBAL5Q5iFMTHJZAv+Y/PG+R3jHOO70ZyjG7lZn
            HE/4WO+wIpeR0x3PJMZi5o66WxGrI2Zzw3vcolr2uVqMjF21Ht24HDNfoN3HYyY4
            tUtD3lfSPN1hH2K/o1f5t1iegVS7MW3o3pN/o4VLsgaIJ5io3slPNPCWx4ns7ijN
            2yS82XDsLJtvlGOolD9NENINanUW6rsVdqcz70RqiTTGoa3LVN0yISwIry3vDcXW
            B3du3jyGV3tx9746p0/EUsu1e/rBUzwTNwVibAEbHtq9dVLxo6w3o5zcVkF9bQWL
            RcNLpg7tZLOxGpyJeiW//M8i9zWDrPlGQg+WBRoK0B00FaQMbSECAwEAAaAAMA0G
            CSqGSIb3DQEBCwUAA4IBAQBxkfl/Nq0y2u8Deq17OlB8WZfJnigEtFtMFstWNxNp
            Z3yxSFbaOYpB/+S0qOTjFbx1vQd8sSKTEqSgn2MkLhNsqtakWhejC+rrzVA02K6d
            J7uCylX8XVRJPjmt14E2LNLxGx1adV8St0tPrbzXMzr0ygpGaIITvd+ZzXr4CuGQ
            vao+T3EooEVQeFmWaoU6URUsqlp1itYzN1O+tvHv9pmCZ5UyTJlHQSc+cKJsUgE4
            O+jruZshnFL0KQybIokYGLLcb6NixdsCTSw+rfztuLUEEMP1ozNCgk8TX8mXWduM
            XIP49FHFe6IjLuj0ofRXiJPmS+4ToqRbNIBRoz7kSLov
            -----END CERTIFICATE REQUEST-----
            """).encode("utf8"),  # py3 dedent can't handle bytes
        subject_components=(
            ('O', 'Example inc.'),
            ('OU', 'Example Dept'),
            ('CN', 'foo.example.com'),
        ),
        accessed=[
            AccessLogData.initial_2,
            AccessLogData.initial_1,
        ],
        certificates=[
            CertificateData.initial,
        ],
        )

    with_expired_cert = CSRFixture(
        orgunit="Example Dept",
        commonname="spam.example.com",
        pem=dedent("""\
            -----BEGIN CERTIFICATE REQUEST-----
            MIICjjCCAXYCAQIwSTEVMBMGA1UECgwMRXhhbXBsZSBpbmMuMRUwEwYDVQQLDAxF
            eGFtcGxlIERlcHQxGTAXBgNVBAMMEHNwYW0uZXhhbXBsZS5jb20wggEiMA0GCSqG
            SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCevMnao2HIiIJm+KQW8+vSIR/N/buRN8c3
            7Xftsa5MDOZcUWtqPP0r6V5hxlHiwI89EjxCMRRJhyeA/UspSuDNRKV2M+tAYuyb
            H7yAt2LYk3WQ+7q4xP3u4HVEMpCkgwca5XiYkomS7eyHoMm9AyO4y/zE5Rce0LD2
            ONzoIsj3N4Rl8zVFeyZFXEvHwe7CUXxk1GM8afmUQYjFM5GkXUx5/l5OcYiDaTHC
            PwXlok/h6L1dLqBthIVl6Su5P0i+HjXHgVibHhtwZB+4i75wb5cjfEag2ub8goyC
            4xC/CMGPZecsfOyRHmbP1hIt32+LWceXtvm70YO2maWI0696FrGNAgMBAAGgADAN
            BgkqhkiG9w0BAQsFAAOCAQEAf5SnEDewYNy4bu1bwga2alawbr+BQpysl/h53/aJ
            woJakG3E3+jSyAQ6Bu/j+YY+hTMbNX/sOyWMexS6w6HryQ6i/xvFZqhgN5ap/I6M
            k7V13j1LyxcTtlD773ikWq7F/+H76FgTAoE4oUmNvptej/C5eW5A1N150vMeecY/
            0nHIV+eXaZTCbg7UKr1xmR3tdu3DNnFC/BfaVv+Ul7s974k4g53ejLCvnCjMGVS3
            oQN1HuxKCScUJ9Vtr0dnBLGAf62vAqv5yZYhl9Qnt5EJ9OtspWm0e8FwTjNmoA/z
            qnvUxskzM2ItxVV9oa9YDTid0GbJvF67QJQyVIO0Vz4uwg==
            -----END CERTIFICATE REQUEST-----
            """).encode("utf8"),  # py3 dedent can't handle bytes
        subject_components=(
            ('O', 'Example inc.'),
            ('OU', 'Example Dept'),
            ('CN', 'spam.example.com'),
        ),
        certificates=[
            CertificateData.expired,
        ],
        )

    good = CSRFixture(
        orgunit="Example Dept",
        commonname="bar.example.com",
        pem=dedent("""\
            -----BEGIN CERTIFICATE REQUEST-----
            MIICjTCCAXUCAQIwSDEVMBMGA1UECgwMRXhhbXBsZSBpbmMuMRUwEwYDVQQLDAxF
            eGFtcGxlIERlcHQxGDAWBgNVBAMMD2Jhci5leGFtcGxlLmNvbTCCASIwDQYJKoZI
            hvcNAQEBBQADggEPADCCAQoCggEBAN7fng4vFo0P0+K1L64rADgXBDrwsa39p3tV
            7GwY/LZ9crxUgwFKfVLM8rX4KAySiOXix8JF44jansXTOkcm8OjnOKVNIJX/5Pf3
            bRDSXcjodFIhPVzUynj8E5Z8rEB2ES9gwYDKIYVNnJa2nGmQVe7IgA5O7lNM6gse
            TqYlN3bmB9Dy/dY+ZVyts1p6aSOYMdAcJ7ojCco9HuYFav2hd7k2h4b4lCKvi7p2
            sx6DoKmnblmlvMlP9UdSq7wORkAUnMn5rlzdj5LnWsSB+JLBrQaSlsIfVeL0+5oB
            6zrZI5hJPQiaLcet0v6a7M7UkOyJKiGJVCKYnO122D4Cu4lB2d0CAwEAAaAAMA0G
            CSqGSIb3DQEBCwUAA4IBAQAGJwl7vUlDg2L3KgnsNA9A4rMKfFn5fzdf6Z0X3HSY
            Zvi8XKkVAKd7aRUSg6jcJbOm0HNmBR+5SWzXUU62KQWuUCwz+dCyCbcEO/frG0IB
            HdOs/L4AJgHlIaxwisCLh5VQpj5w0ahhzVfLGWcCK1nbqjUTLcEFhvZviUPUugAD
            f7QdWNDBuZTrwXGTLsnhC5XQfsk0maXcNji79ziK4sMm5TU2599JmuWL2NTbqaCQ
            MN1FxWzEy4yXgzW8uv+lX6yyTtkfrC7e3LFiAuoUlBeD5GmsVd30Xz5iGnuQv3d0
            fekjT5Np8XIS2ERJmx4CIjs5VpE1FMNOMoJ35kQpkQaQ
            -----END CERTIFICATE REQUEST-----
            """).encode("utf8"),
        subject_components=(
            ('O', 'Example inc.'),
            ('OU', 'Example Dept'),
            ('CN', 'bar.example.com'),
        ),
        )

    bad_signature = CSRFixture(  # `good` with the subject of `initial`
        pem=dedent("""\
            -----BEGIN CERTIFICATE REQUEST-----
            MIIBAjCBrQIBADBIMRUwEwYDVQQKDAxFeGFtcGxlIGluYy4xFTATBgNVBAsMDEV4
            YW1wbGUgRGVwdDEYMBYGA1UEAwwPZm9vLmV4YW1wbGUuY29tMFwwDQYJKoZIhvcN
            AQEBBQADSwAwSAJBAKk2sD6xi/gfO3TVnoGMhUmkPDD17/qYzEvDdw/kponLTdNF
            asGx1//giKSBqBpUFt+KTz3NofK9Pf2qWWDxyUECAwEAAaAAMA0GCSqGSIb3DQEB
            BQUAA0EAcsrzTdYBqlbq/JQaMSEoi64NmoxiC8GGzOaKlTxqRc7PKb+T1wN94PxJ
            faXw8kA8p0E6hmwFAE9QVkuTKvP/eg==
            -----END CERTIFICATE REQUEST-----
            """).encode("utf8"),
        )

    truncated = CSRFixture(
        pem=dedent("""\
            -----BEGIN CERTIFICATE REQUEST-----
            MIIBAjCBrQIBADBIMRUwEwYDVQQKDAxFeGFtcGxlIGluYy4xFTATBgNVBAsMDEV4
            YW1wbGUgRGVwdDEYMBYGA1UEAwwPYmFyLmV4YW1wbGUuY29tMFwwDQYJKoZIhvcN
            AQEBBQADSwAwSAJBAKk2sD6xi/gfO3TVnoGMhUmkPDD17/qYzEvDdw/kponLTdNF
            asGx1//giKSBqBpUFt+KTz3NofK9Pf2qWWDxyUECAwEAAaAAMA0GCSqGSIb3DQEB
            """).encode("utf8"),
        )

    trailing_content = CSRFixture(
        pem=dedent("""\
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
            """).encode("utf8"),
        )

    leading_content = CSRFixture(
        pem=dedent("""\
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
            """).encode("utf8"),
        )

    multi_request = CSRFixture(
        pem=dedent("""\
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
            """).encode("utf8"),
        )

    not_pem = CSRFixture(
        pem=dedent("""\
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
            """).encode("utf8"),
        )

    empty = CSRFixture(pem=b"")

    bad_sha = CSRFixture(good, sha256sum=not_pem.sha256sum)

    bad_subject = CSRFixture(
        orgunit="Example test dept.",
        commonname="baz.example.com",
        pem=dedent("""\
            -----BEGIN CERTIFICATE REQUEST-----
            MIIBCDCBswIBADBOMRUwEwYDVQQKDAxFeGFtcGxlIGluYy4xGzAZBgNVBAsMEkV4
            YW1wbGUgdGVzdCBkZXB0LjEYMBYGA1UEAwwPYmF6LmV4YW1wbGUuY29tMFwwDQYJ
            KoZIhvcNAQEBBQADSwAwSAJBAOQ+LeU8pbEg5/XeD+HLnGah4A96qDL4HtNsTW0N
            //DbwGchtE8h9LSs3ePXWDVHak87Jx8A+wq7DRUd/LDVP6cCAwEAAaAAMA0GCSqG
            SIb3DQEBBQUAA0EAhriivXQYFbdc8QrnDjwVCX8ZGXiGKQEC66LceWDdvOy+mDu8
            gi+L6IgnptU8VmEowAPp0veIH1MWJrnGdp7M0g==
            -----END CERTIFICATE REQUEST-----
        """).encode("utf-8"),
        subject_components=(
            ("O", "Example inc."),
            ("OU", "Example test dept."),
            ("CN", "baz.example.com"),
        ),
        )

    large_body = CSRFixture(
        pem="".join(("foobar", "x" * views._MAXLEN)).encode("utf-8"),
        )
