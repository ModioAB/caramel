#! /usr/bin/env python3
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
import certlib

if __name__ == "__main__":
    key, req, cert = certlib.create_ca()
    certlib .write_out_files(key, req, cert)
