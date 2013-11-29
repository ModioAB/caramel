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
        cert = models.Certificate()
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
            FIXME: replace with appropriate text, once we've started
                   generating certificates.
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
            MIIBAjCBrQIBADBIMRUwEwYDVQQKDAxFeGFtcGxlIGluYy4xFTATBgNVBAsMDEV4
            YW1wbGUgRGVwdDEYMBYGA1UEAwwPZm9vLmV4YW1wbGUuY29tMFwwDQYJKoZIhvcN
            AQEBBQADSwAwSAJBANBBe43zbCwPs1jRPPqgb6Otdqx9kg67Dgfoxh3Mly7b9JPp
            orKIs6zzoyMeLHLJYk+CwSHyeS1hc4zL+3A+k88CAwEAAaAAMA0GCSqGSIb3DQEB
            BQUAA0EALt6dIjlzG05KCfyiy2PJdAwcjC+mpHh3i4cJs50U+EnxBgX8QscOu382
            72uukmhYBG1Xd1LN4S5RL9pcQ9KLaA==
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

    good = CSRFixture(
        orgunit="Example Dept",
        commonname="bar.example.com",
        pem=dedent("""\
            -----BEGIN CERTIFICATE REQUEST-----
            MIIBAjCBrQIBADBIMRUwEwYDVQQKDAxFeGFtcGxlIGluYy4xFTATBgNVBAsMDEV4
            YW1wbGUgRGVwdDEYMBYGA1UEAwwPYmFyLmV4YW1wbGUuY29tMFwwDQYJKoZIhvcN
            AQEBBQADSwAwSAJBAKk2sD6xi/gfO3TVnoGMhUmkPDD17/qYzEvDdw/kponLTdNF
            asGx1//giKSBqBpUFt+KTz3NofK9Pf2qWWDxyUECAwEAAaAAMA0GCSqGSIb3DQEB
            BQUAA0EAcsrzTdYBqlbq/JQaMSEoi64NmoxiC8GGzOaKlTxqRc7PKb+T1wN94PxJ
            faXw8kA8p0E6hmwFAE9QVkuTKvP/eg==
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
