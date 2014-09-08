#!/bin/env python

import argparse

from pyramid.paster import bootstrap
from sqlalchemy import create_engine
from dateutil.relativedelta import relativedelta
import caramel.models as models
import transaction
import datetime


def cmdline():
    parser = argparse.ArgumentParser()
    parser.add_argument("inifile")
    parser.add_argument("--sign", metavar="id",
                        help="Sign the CSR with this id")
    parser.add_argument("--reject", metavar="id",
                        help="Reject the CSR with this id")
    parser.add_argument("--long", help="Generate a long lived cert(1 year)",
                        action="store_true")
    parser.add_argument("--resign", help="Resign all certificates",
                        action="store_true")

    args = parser.parse_args()

    # Didn't find a way to do this with argparse, but I didn't look too hard.
    return args


def print_list():
    requests = models.CSR.valid()
    for csr in requests:
        if csr.certificates:
            cert = csr.certificates[0]
            not_after = str(cert.not_after)
        else:
            not_after = "----------"
        output = " ".join((str(csr.id), csr.commonname, csr.sha256sum,
                           not_after))
        # TODO: Add lifetime of latest (fetched?) cert for the key.
        print(output)


def main():
    args = cmdline()
    env = bootstrap(args.inifile)
    settings, closer = env['registry'].settings, env['closer']
    engine = create_engine(settings['sqlalchemy.url'])
    models.init_session(engine)

    if not args.sign and not args.resign and not args.reject:
        print_list()
        closer()
        exit()

    try:
        with open(settings['ca.cert'], 'rt') as f:
            ca_cert = f.read()

        with open(settings['ca.key'], 'rt') as f:
            ca_key = f.read()
    except KeyError:
        print("config file needs ca.cert and ca.key properly set")
        exit(1)

    if args.sign and args.resign:
        print("Only resign or sign, not both")
        exit(1)

    if args.reject and args.resign:
        print("Reject & resign? No. Just no.")
        exit(1)

    if args.sign and args.reject:
        print("Sign & Reject at once is a stupid thing")
        exit(1)

    if args.reject:
        with transaction.manager:
            CSR = models.CSR.query().get(args.reject)
            if not CSR:
                print("ID not found")
                exit(1)

            CSR.rejected = True
            CSR.save()

    if args.sign:
        now = datetime.datetime.now()
        if args.long:
            future = now + relativedelta(years=1)
        else:
            future = now + relativedelta(months=1)
        lifetime = future - now
        del now, future

        with transaction.manager:
            CSR = models.CSR.query().get(args.sign)
            if not CSR:
                print("ID not found")
                exit(1)

            cert = models.Certificate.sign(CSR, ca_key, ca_cert, lifetime)
            cert.save()

    if args.resign:
        with transaction.manager:
            try:
                csrlist = models.CSR.valid()
            except:
                print("no csrs found")
                exit(1)

            for csr in csrlist:
                if not csr.certificates:
                    continue
                last = csr.certificates[0]
                lifetime = last.not_after - last.not_before
                cert = models.Certificate.sign(csr, ca_key, ca_cert, lifetime)
                cert.save()
