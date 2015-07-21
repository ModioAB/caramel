import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, "README.md")).read()
CHANGES = open(os.path.join(here, "CHANGES.txt")).read()

requires = [
    "pyramid",
    "SQLAlchemy",
    "transaction",
    "pyramid_tm",
    # "pyramid_debugtoolbar",
    "zope.sqlalchemy",
    "waitress",
    "cryptography>=0.5.dev1",
    "pyOpenSSL>=0.14",
    "flup<=1.0.4.dev",
    "python-dateutil",
    ]

try:
    import ipaddress
except ImportError:
    requires.append("ipaddr>=2")
del ipaddress

deplinks = [
    "http://hg.saddi.com/flup-py3.0/archive/cc23b715b120.tar.gz" +
    "#egg=flup-1.0.4.dev",
    ]

setup(name="caramel",
      version="1.2",
      description="caramel",
      long_description=README + "\n\n" + CHANGES,
      classifiers=[
          "Programming Language :: Python",
          "Framework :: Pyramid",
          "Topic :: Internet :: WWW/HTTP",
          "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
          ],
      author="D.S. Ljungmark",
      author_email="spider@modio.se",
      url="https://github.com/MyTemp/caramel",
      keywords="web wsgi bfg pylons pyramid certificates x509 ca cert",
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
      caramel_autorefresh = caramel.scripts.autorefresh:main
      caramel_dump_json = caramel.scripts.dump_json:main
      caramel_restore_json = caramel.scripts.restore_json:main
      """,
      )
