from setuptools import setup, find_packages

requires = [
    "pyramid",
    "SQLAlchemy ~= 1.4.32",
    "transaction",
    "pyramid_tm",
    "zope.sqlalchemy >= 1.6",
    "waitress",
    "cryptography >= 38",
    "pyOpenSSL >= 22.0.0",
    "python-dateutil",
    # Transient dependency from pyramid->webob,
    # should be fixed in a later release of webob
    "legacy-cgi; python_version >= '3.13'"
]

deplinks = []

setup(
    name="caramel",
    version="1.9.6",
    python_requires=">=3.7",
    description="caramel",
    long_description="""
Caramel is a certificate management system that makes it easy to use client
certificates in web applications, mobile applications, embedded use and
other places. It solves the certificate signing and certificate
management headache, while attempting to be easy to deploy, maintain and
use in a secure manner.

Caramel makes it easier (it's never completely easy) to run your own
certificate authority and manage and maintain keys and signing periods.

Caramel focuses on reliably and continuously updating short-lived certificates
where clients (and embedded devices) continue to "phone home" and fetch
updated certificates.  This means that we do not have to provide OCSP and
CRL endpoints to handle compromised certificates, but only have to stop
updating the certificate. This also means that expired certificates
should be considered broken.
      """,
    classifiers=[
        "Programming Language :: Python",
        "Framework :: Pyramid",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
    ],
    author="D.S. Ljungmark",
    author_email="spider@modio.se",
    url="https://github.com/MyTemp/caramel",
    keywords="web wsgi bfg pylons pyramid certificates x509 ca cert ssl tls",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    test_suite="tests",
    install_requires=requires,
    dependency_links=deplinks,
    entry_points="""\
      [paste.app_factory]
      main = caramel:main
      [console_scripts]
      caramel_initialize_db = caramel.scripts.initializedb:main
      caramel_tool = caramel.scripts.tool:main
      caramel_ca = caramel.scripts.generate_ca:main
      caramel_autosign = caramel.scripts.autosign:main
      """,
)
