#!/bin/env python3

import argparse

from pyramid.paster import bootstrap
from pyramid.settings import asbool
from sqlalchemy import create_engine
import caramel.models as models
import transaction
import datetime
import sys
import concurrent.futures


def cmdline():
    parser = argparse.ArgumentParser()
    parser.add_argument("inifile")
    parser.add_argument("--long", help="Generate a long lived cert(1 year)",
                        action="store_true")

    parser.add_argument("--list", help="List active requests, do nothing else",
                        action="store_true")

    exclusives = parser.add_mutually_exclusive_group()
    exclusives.add_argument("--sign", metavar="id", type=int,
                            help="Sign the CSR with this id")
    exclusives.add_argument("--reject", metavar="id", type=int,
                            help="Reject the CSR with this id")

    cleanout = parser.add_mutually_exclusive_group()
    cleanout.add_argument("--clean", metavar="id", type=int,
                          help="Remove all older certificates for this CSR")
    cleanout.add_argument("--wipe", metavar="id", type=int,
                          help="Wipe all certificates for this CSR")

    bulk = parser.add_mutually_exclusive_group()
    bulk.add_argument("--refresh", help="Sign all certificates previously "
                      "signed certificates again.", action="store_true")

    bulk.add_argument("--cleanall", help="Clean all older certificates.",
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


def csr_wipe(number):
    with transaction.manager:
        CSR = models.CSR.query().get(number)
        if not CSR:
            error_out("ID not found")
        CSR.certificates = []
        CSR.save()


def csr_clean(number):
    with transaction.manager:
        CSR = models.CSR.query().get(number)
        if not CSR:
            error_out("ID not found")
        certs = sorted(CSR.certificates, key=lambda cert: cert.id)
        CSR.certificates = [certs[-1]]
        CSR.save()


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
            today = datetime.datetime.utcnow()
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


def refresh(csr, ca_key, ca_cert, lifetime, backdate):
    print("Refreshing {} with lifetime: {}, backdate: {}"
          .format(csr, lifetime, backdate))

    with transaction.manager:
        cert = models.Certificate.sign(csr, ca_key, ca_cert,
                                       lifetime, backdate)
        cert.save()


def csr_resign(ca_key, ca_cert, lifetime_short, lifetime_long, backdate):
    csrlist = models.CSR.valid()
    lifetimes = models.CSR.most_recent_lifetime()
    now = datetime.datetime.utcnow()
    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        for csr in csrlist:
            if csr.id not in lifetimes:
                continue

            before, after = lifetimes[csr.id]
            lifetime = min(after - before, lifetime_long)
            half_life = lifetime / 2

            if now < after - half_life:
                continue

            if lifetime >= lifetime_long:
                new_lifetime = lifetime_long
                new_backdate = backdate
            else:
                new_lifetime = lifetime_short
                new_backdate = False

            promise = executor.submit(refresh,
                                      csr, ca_key, ca_cert,
                                      new_lifetime, new_backdate)
            futures.append(promise)
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception:
                print("Future failed")


def main():
    args = cmdline()
    env = bootstrap(args.inifile)

    settings, closer = env['registry'].settings, env['closer']
    engine = create_engine(settings['sqlalchemy.url'])
    models.init_session(engine)
    settings_backdate = asbool(settings.get('backdate', False))

    _short = int(settings.get('lifetime.short', 48))
    _long = int(settings.get('lifetime.long', 7*24))
    life_short = datetime.timedelta(hours=_short)
    life_long = datetime.timedelta(hours=_long)
    del _short, _long

    try:
        with open(settings['ca.cert'], 'rt') as f:
            ca_cert = f.read()

        with open(settings['ca.key'], 'rt') as f:
            ca_key = f.read()
    except KeyError:
        error_out("config file needs ca.cert and ca.key properly set")

    if life_short > life_long:
        error_out("Short lived certs ({0}) shouldn't last longer "
                  "than long lived certs ({1})".format(life_short, life_long))
    if args.list:
        print_list()
        closer()
        sys.exit(0)

    if args.reject:
        csr_reject(args.reject)

    if args.wipe:
        error_out("Not implemented yet")

    if args.clean:
        error_out("Not implemented yet")

    if args.cleanall:
        error_out("Not implemented yet")

    if args.sign:
        if args.long:
            csr_sign(args.sign, ca_key, ca_cert,
                     life_long, settings_backdate)
        else:
            # Never backdate short lived certs
            csr_sign(args.sign, ca_key, ca_cert, life_short, False)

    if args.refresh:
        csr_resign(ca_key, ca_cert, life_short, life_long, settings_backdate)
