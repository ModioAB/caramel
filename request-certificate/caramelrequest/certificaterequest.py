#! /usr/bin/env python

import distutils.spawn
import hashlib
import logging
import os
import subprocess
import sys
import time
import tempfile
from xml.etree import ElementTree as ET

import requests

OPENSSL_CNF = b"""
# This definition stops the following lines choking if HOME isn't
# defined.
HOME            = .
RANDFILE        = $ENV::HOME/.rnd
####################################################################
[ req ]
default_bits        = 2048
default_md      = sha256
default_keyfile     = privkey.pem
distinguished_name  = req_distinguished_name
attributes      = req_attributes
x509_extensions = v3_req    # The extentions to add to the self signed cert
string_mask = utf8only

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment


[ req_distinguished_name ]
countryName         = Country Name (2 letter code)
countryName_default     = AU
countryName_min         = 2
countryName_max         = 2
stateOrProvinceName     = State or Province Name (full name)
stateOrProvinceName_default = Some-State
localityName            = Locality Name (eg, city)
0.organizationName      = Organization Name (eg, company)
0.organizationName_default  = Internet Widgits Pty Ltd
organizationalUnitName      = Organizational Unit Name (eg, section)
commonName          = Common Name (e.g. server FQDN or YOUR name)
commonName_max          = 64
emailAddress            = Email Address
emailAddress_max        = 64

[ req_attributes ]
challengePassword       = A challenge password
challengePassword_min       = 4
challengePassword_max       = 20
unstructuredName        = An optional company name
"""


class CertificateRequestException(Exception):
    pass


class CertificateRequest(object):
    def __init__(self, *, server, client_id):
        self.server = server
        self.client_id = client_id
        self.key_file_name = client_id + '.key'
        self.csr_file_name = client_id + '.csr'
        self.crt_temp_file_name = client_id + '.tmp'
        self.crt_file_name = client_id + '.crt'
        self.ca_cert_file_name = server + '.cacert'

    def perform(self):
        self.assert_openssl_available()
        self.assert_ca_cert_available()
        self.assert_ca_cert_verifies()
        subject = self.get_subject()
        self.ensure_valid_key_file()
        self.ensure_valid_csr_file(subject)
        self.request_cert_from_server()
        self.assert_temp_cert_verifies()
        self.rename_temp_cert()

    def assert_openssl_available(self):
        path = distutils.spawn.find_executable('openssl')
        if path is None:
            logging.error('Cannot find an openssl executable!')
            raise CertificateRequestException()

    def assert_ca_cert_available(self):
        if not os.path.isfile(self.ca_cert_file_name):
            logging.info('CA certificate file {} does not exist!'
                         .format(self.ca_cert_file_name))
            raise CertificateRequestException()

    def assert_ca_cert_verifies(self):
        result = call_silent('openssl', 'verify',
                             '-CAfile', self.ca_cert_file_name,
                             self.ca_cert_file_name)
        if 0 != result:
            logging.error('CA cert {} is not valid; bailing'
                          .format(self.ca_cert_file_name))
            raise CertificateRequestException()

    def assert_temp_cert_verifies(self):
        result = call_silent('openssl', 'verify',
                             '-CAfile', self.ca_cert_file_name,
                             self.crt_temp_file_name)
        if 0 != result:
            logging.error('Our new cert {} is not valid; bailing'
                          .format(self.crt_temp_file_name))
            raise CertificateRequestException()

    def rename_temp_cert(self):
        logging.info('Recieved certificate valid; moving it to {}'
                     .format(self.crt_file_name))
        os.rename(self.crt_temp_file_name,
                  self.crt_file_name)

    def get_subject(self):
        output = check_output_silent('openssl',
                                     'x509',
                                     '-subject',
                                     '-noout',
                                     '-in', self.ca_cert_file_name)
        _, value = decode_openssl_utf8(output).strip().split('subject= ', 1)
        prefix, original_cn = value.split('/CN=')
        if prefix == '/C=SE/OU=Caramel/L=Linköping/O=Modio AB/ST=Östergötland':
            prefix = '/C=SE/ST=Östergötland/L=Linköping/O=Modio AB/OU=Caramel'
        return '{}/CN={}'.format(prefix, self.client_id)

    def ensure_valid_key_file(self):
        have_key = False
        if not os.path.isfile(self.key_file_name):
            logging.info('Key file {} does not exist; generating it'
                         .format(self.key_file_name))
        elif 0 != call_silent('openssl',
                              'pkey',
                              '-noout',
                              '-in', self.key_file_name):
            logging.info('Key file {} is not valid; regenerating it'
                         .format(self.key_file_name))
        else:
            logging.info('Key file {} is valid; using it'
                         .format(self.key_file_name))
            have_key = True
        if not have_key:
            result = call_silent('openssl',
                                 'genrsa',
                                 '-out', self.key_file_name,
                                 '2048')
            if result != 0:
                logging.error('Failed to generate private key!')
                raise CertificateRequestException()

    def ensure_valid_csr_file(self, subject):
        have_csr = False
        if not os.path.isfile(self.csr_file_name):
            logging.info(('Certificate signing request file {} ' +
                          'does not exist; generating it')
                         .format(self.csr_file_name))
        elif 0 != call_silent('openssl',
                              'req',
                              '-noout',
                              '-verify',
                              '-in', self.csr_file_name,
                              '-key', self.key_file_name):
            logging.info(('Certificate signing request file {} ' +
                          'is not valid; regenerating it')
                         .format(self.csr_file_name))
        else:
            logging.info(('Certificate signing request file {} is valid; ' +
                          'using it').format(self.csr_file_name))
            have_csr = True
        if not have_csr:
            with tempfile.NamedTemporaryFile() as cnf:
                cnf.write(OPENSSL_CNF)
                cnf.flush()
                result = call_silent('openssl',
                                     'req',
                                     '-config', cnf.name,
                                     '-sha256',
                                     '-utf8',
                                     '-new',
                                     '-key', self.key_file_name,
                                     '-out', self.csr_file_name,
                                     '-subj', subject)
            if result != 0:
                logging.error('Failed to create certificate signing request!')
                raise CertificateRequestException()

    def request_cert_from_server(self):
        csr, csr_hash = self.get_csr_and_hash()
        url = 'https://{}/{}'.format(self.server, csr_hash)

        session = requests.Session()
        session.verify = self.ca_cert_file_name

        response = session.get(url)
        while True:
            if response.status_code == 404:
                logging.info('CSR not posted; posting it')
                response = session.post(url, csr)
            elif response.status_code == 202 or response.status_code == 304:
                logging.info('CSR not processed yet; waiting ...')
                try:
                    time.sleep(15)
                except KeyboardInterrupt:
                    break
                response = session.get(url)
            elif response.status_code == 200:
                logging.info('Recieved certificate; saving it to {}'
                             .format(self.crt_temp_file_name))
                with open(self.crt_temp_file_name, 'wb') as f:
                    f.write(response.content)
                break
            else:
                logging.error('Request failed: {}'
                              .format(parse(response)))
                response.raise_for_status()
                break

    def get_csr_and_hash(self):
        with open(self.csr_file_name, 'rb') as f:
            csr = f.read()
        return csr, hashlib.sha256(csr).hexdigest()


def printerr(text):
    sys.stderr.write(text + '\n')


def parse(response):
    try:
        result = response.json()
    except Exception:
        result = parse_html(response)
    return result


def parse_html(response):
    return ''.join((e.text or '') + (e.tail or '')
                   for e in ET.fromstring(response.text).iterfind('body//'))


def decode_openssl_utf8(text):
    return bytes(ord(x) for x in text.decode('unicode_escape')) \
        .decode('utf-8')


def call_silent(*args):
    return subprocess.call(args,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)


def check_output_silent(*args):
    return subprocess.check_output(args, stderr=subprocess.DEVNULL)


def main():
    logging.basicConfig(level=logging.INFO,
                        format='%(message)s')

    if (len(sys.argv) == 3):
        server = sys.argv[1]
        client_id = sys.argv[2]
    else:
        print('Usage: {} SERVER CLIENTID\n'.format(sys.argv[0]),
              file=sys.stderr)
        sys.exit(1)

    try:
        CertificateRequest(server=server, client_id=client_id).perform()
    except CertificateRequestException:
        sys.exit(1)


if __name__ == '__main__':
    main()
