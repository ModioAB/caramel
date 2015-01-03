import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, "README.txt")).read()
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
    "pyOpenSSL>=0.15.dev",
    "flup<=1.0.4.dev",
    "python-dateutil",
    ]

deplinks = [
    "http://hg.saddi.com/flup-py3.0/archive/cc23b715b120.tar.gz" +
    "#egg=flup-1.0.4.dev",
    "https://github.com/MyTemp/pyopenssl/tarball/no-more-T61Strings" +
    "#egg=pyOpenSSL-0.15.dev"
    ]

setup(name="caramel",
      version="0.0",
      description="caramel",
      long_description=README + "\n\n" + CHANGES,
      classifiers=[
          "Programming Language :: Python",
          "Framework :: Pyramid",
          "Topic :: Internet :: WWW/HTTP",
          "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
          ],
      author="",
      author_email="",
      url="",
      keywords="web wsgi bfg pylons pyramid",
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
      """,
      )
