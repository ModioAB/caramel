#! /usr/bin/env python3
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :

import certlib
import sys
from OpenSSL import crypto as _crypto

if __name__ == "__main__":
    with open('../modio_ca/modioCA.key', 'rt') as f:
        cakey = _crypto.load_privatekey(_crypto.FILETYPE_PEM, f.read())

    with open('../modio_ca/modioCA.cert', 'rt') as f:
        cacert = _crypto.load_certificate(_crypto.FILETYPE_PEM, f.read())

    name = sys.argv[1]
    serial = int(sys.argv[2])
    key, req = certlib.create_req(template={'CN': name})
    cert = certlib.sign_req(req, cacert, cakey, Type="server", serial=serial)
    certlib.write_out_files(key, req, cert, name)
