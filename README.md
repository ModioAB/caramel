Caramel README
==============

What is Caramel?
----------------

Caramel is a certificate management system that makes it easy to use
client certificates in web applications, mobile applications, embedded use
and other places. It solves the certificate signing and certificate
management headache, while attempting to be easy to deploy, maintain and
use in a secure manner.

Caramel makes it easier (it's never completely easy) to run your own
certificate authority and manage and maintain keys and signing periods.

Caramel focuses on reliably and continuously updating short-lived certificates
where clients (and embedded devices) continue to "phone home" and fetch
updated certificates.  This means that we do not have to provide OCSP and CRL
endpoints to handle compromised certificates, but only have to stop updating
the certificate. This also means that expired certificates should be
considered broken.


How does Caramel work?
----------------------

Caramel is a REST-ful web application that accepts certificate signing
requests (CSR) from anyone, stores them, and possibly returns a signed
certificate.

A client pushes its certificate signing request (CSR) to the public web
application. The web application validates the CSR, and stores it in a
database.

A backend (administration) web application talks to the same database
(preferably from inside an intranet or other secure place), and lets you
view signing requests, and sign them.

The certificates are signed with a *short* lifetime (3 days), and client
scripts are supposed to regularly contact the public web service and
download a freshly signed certificate. Root (Certificate Authority) keys
only live on the "administration" part, and should preferably be kept on a
non-public machine.


What should I take special care about?
--------------------------------------

*No* identity validation is performed by the application, this is left as
an exercise for the reader.

Your signing keys are stored on the administration machine.

If a client doesn't regularly download its public certificate, it will
time out and become "stale", thus preventing future connections.


Example usage
-------------

We install the administration interface and database on an internal
machine (intranet) and put the public application on our software update
service. We use the unique identifier for each client (its machine-ID or
mac-address) as the identifier, and manually match these when initially
signing requests.

Since the CSR doesn't change with time, it is re-signed every 15 days, and
in the client startup sequence, the client will download a refreshed
certificate from the caramel server.

Example implementation of a client (in shell-script, using OpenSSL) is
included. The example includes:

- Generating a key
- Generating a signing request
- Uploading a signing request
- Fetching a valid certificate
- Updating a valid certificate


Security trade-offs
-------------------

We have made a conscious decision to have signing keys living
(unencrypted, for now) on the administration server. This is a usability
trade-off in order to make it possible to smoothly use signing keys.

We set strict limits on what kinds of crypto, strings and other things are
allowed in a CSR.

We are doing our very best to **not** build crypto. OpenSSL is used
wherever possible, and we try to **not** implement our own algorithms for
fear of doing it wrongly.


Maintaining your certificates
-----------------------------

In a server environment with several certificates you usually end up
rotating/refreshing them in a cron job.
Included under scripts/ is a tool called `caramel-refresh.sh` that will parse a
config file, and automatically refresh all certificates matching. This requires
the original CSR and certificate to be in place. See `request-certificate` for a
tool to generate your own certificates.

`caramel-refresh` is intended to be run in a cron job on servers (or clients).
Please make sure you run the job as the correct user, so permissions aren't a
problem afterwards.


Getting Started
---------------
```
cd <directory containing this file>
$venv/bin/python setup.py develop
$venv/bin/caramel_initialize_db development.ini
$venv/bin/caramel_ca development.ini
$venv/bin/pserve development.ini
```

Running Tests
-------------
```
cd <directory containing this file>
$venv/bin/python setup.py develop
$venv/bin/python -m unittest discover
```


Running Tests with Nose
-----------------------

```
cd <directory containing this file>
$venv/bin/python setup.py develop
$venv/bin/pip install nose
nosetests
```


Installing the Commit Hook
--------------------------

We use commit-hooks to run test-cases in a clean virtualenv before each commit.
This is to ensure a certain level of quality and code standards, and to prevent
missing dependencies in setup.py. Running these tests at each commit can be
expensive as it involves going to the network and downloading every package
from scratch. This is not a concern for our development environment, but may be
a problem for others.


Install the hooks with the following commands:
```
cd <directory containing this file>
ln -rs pre-commit-checks .git/hooks/pre-commit
```

Please note the "-r" flag to ln, as it makes sure the relative link keeps the
correct path.

For the pre-commit hook to work, you need to have flake8 available. Either
install flake8 via:

`pip install flake8`

Or point git config hooks.flake8 to the flake8 executable:

`git config hooks.flake8 /path/to/flake8`


Dependencies needed from the operating system
---------------------------------------------

* libffi-devel (on RHEL/CentOS)
* openssl, openssl-devel
* gcc


Making sure you have VirtualEnv
-------------------------------

To use the commit hook you need virtualenv available.
If you do not have virtualenv in your path, please point to it with:

`git config hooks.virtualenv /path/to/virtualenv`

In order to run the python3 interpreter instead of the normal python2
interpreter, you should configure the hook as this:

`git config hooks.virtualenv /usr/bin/virtualenv -p /usr/bin/python3`


License
-------
We have chosen the GNU Affero GPL v3 license for the project. We see no need
for others to keep modification to this software a secret, and we welcome
outside providers. Just because the code is GPLv3, doesn't prevent you from
keeping your keys & certificates private.

For the organizations using this, there should be no additional gain to be
had from keeping the source code secret, and if you think there is any such
gain, please contact us.
