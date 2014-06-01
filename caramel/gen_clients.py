#! /usr/bin/env python3
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :

import certlib

if __name__ == "__main__":
    ca_name = "testCA"

    # Fixme: don't generate a new CA each time....
    cakey, req, cacert = certlib.create_ca()
    certlib.write_out_files(cakey, None, cacert, ca_name)

    name = "testClient"
    key, req = certlib.create_req(template={'CN': name})
    cert = certlib.sign_req(req, cacert, cakey, Type="client")
    certlib.write_out_files(key, req, cert, name)

    name = "testServer"
    key, req = certlib.create_req(template={'CN': name})
    cert = certlib.sign_req(req, cacert, cakey, Type="server")
    certlib.write_out_files(key, req, cert, name)

    name = "testBox"
    key, req = certlib.create_req(template={'CN': name})
    cert = certlib.sign_req(req, cacert, cakey, Type="client-server")
    certlib.write_out_files(key, req, cert, name)
