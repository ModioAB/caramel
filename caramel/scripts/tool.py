#!/bin/env python

import argparse

from pyramid.paster import bootstrap
from pyramid.settings import asbool
from sqlalchemy import create_engine
from dateutil.relativedelta import relativedelta
import caramel.models as models
import transaction
import datetime
import sys


def cmdline():
    parser = argparse.ArgumentParser()
    parser.add_argument("inifile")
    parser.add_argument("--sign", metavar="id",
                        help="Sign the CSR with this id")
    parser.add_argument("--reject", metavar="id",
                        help="Reject the CSR with this id")
    parser.add_argument("--long", help="Generate a long lived cert(1 year)",
                        action="store_true")
    parser.add_argument("--refresh", help="Sign all certificates previously"
                        "signed certificates again.",
                        action="store_true")

    args = parser.parse_args()

    # Didn't find a way to do this with argparse, but I didn't look too hard.
    return args


def error_out(message):
    print(message)
    sys.exit(1)


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


def calc_lifetime(lifetime=relativedelta(hours=24)):
    now = datetime.datetime.now()
    future = now + lifetime
    return future - now


def csr_reject(number):
    with transaction.manager:
        CSR = models.CSR.query().get(number)
        if not CSR:
            error_out("ID not found")

        CSR.rejected = True
        CSR.save()


def csr_sign(number, ca_key, ca_cert, timedelta, backdate):
    with transaction.manager:
        CSR = models.CSR.query().get(number)
        if not CSR:
            error_out("ID not found")
        if CSR.rejected:
            error_out("Refusing to sign rejected ID")

        if CSR.certificates:
            today = datetime.datetime.now()
            cert = CSR.certificates[0]
            cur_lifetime = cert.not_after - cert.not_before
            # Cert hasn't expired, and currently has longer lifetime
            if (cert.not_after > today) and (cur_lifetime > timedelta):
                msg = ("Currently has a valid certificate with {} lifetime, "
                       "new certificate would have {} lifetime. \n"
                       "Clean out existing certificates before shortening "
                       "lifetime.\n"
                       "The old certificate is still out there.")
                error_out(msg.format(cur_lifetime, timedelta))

        cert = models.Certificate.sign(CSR, ca_key, ca_cert,
                                       timedelta, backdate)
        cert.save()


def csr_resign(ca_key, ca_cert, lifetime_short, lifetime_long, backdate):
    with transaction.manager:
        try:
            csrlist = models.CSR.valid()
        except:
            error_out("No CSR's found")

        for csr in csrlist:
            if not csr.certificates:
                continue
            last = csr.certificates[0]
            old_lifetime = last.not_after - last.not_before

            # XXX: In a backdated cert, this is almost always true.
            if old_lifetime >= lifetime_long:
                cert = models.Certificate.sign(csr, ca_key, ca_cert,
                                               lifetime_long, backdate)
            else:
                # Never backdate short-lived certs
                cert = models.Certificate.sign(csr, ca_key, ca_cert,
                                               lifetime_short, False)
            cert.save()


def main():
    args = cmdline()
    env = bootstrap(args.inifile)
    settings, closer = env['registry'].settings, env['closer']
    engine = create_engine(settings['sqlalchemy.url'])
    models.init_session(engine)
    settings_backdate = asbool(settings.get('backdate', False))

    _short = int(settings.get('lifetime.short', 48))
    _long = int(settings.get('lifetime.long', 7*24))
    life_short = calc_lifetime(relativedelta(hours=_short))
    life_long = calc_lifetime(relativedelta(hours=_long))
    del _short, _long

    if not args.sign and not args.refresh and not args.reject:
        print_list()
        closer()
        sys.exit(0)

    try:
        with open(settings['ca.cert'], 'rt') as f:
            ca_cert = f.read()

        with open(settings['ca.key'], 'rt') as f:
            ca_key = f.read()
    except KeyError:
        error_out("config file needs ca.cert and ca.key properly set")

    if args.sign and args.refresh:
        error_out("Only refresh or sign, not both")

    if args.reject and args.refresh:
        error_out("Reject doesn't go well with other arguments.")

    if args.reject and args.sign:
        error_out("Reject doesn't go well with other arguments.")

    if life_short > life_long:
        error_out("Short lived certs ({0}) shouldn't last longer "
                  "than long lived certs ({1})".format(life_short, life_long))

    if args.reject:
        csr_reject(args.reject)

    if args.sign:
        if args.long:
            csr_sign(args.sign, ca_key, ca_cert,
                     life_long, settings_backdate)
        else:
            # Never backdate short lived certs
            csr_sign(args.sign, ca_key, ca_cert, life_short, False)

    if args.refresh:
        csr_resign(ca_key, ca_cert, life_short, life_long, settings_backdate)
