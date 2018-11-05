#!/bin/env python3
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :

import argparse

from pyramid.paster import bootstrap
from pyramid.settings import asbool
from sqlalchemy import create_engine
from dateutil.relativedelta import relativedelta
import caramel.models as models
import transaction
import datetime
import sys
import concurrent.futures


def cmdline():
    parser = argparse.ArgumentParser()
    parser.add_argument("inifile")
    parser.add_argument(
        "--long",
        help="Generate a long lived cert(1 year)",
        action="store_true",
    )

    parser.add_argument(
        "--list",
        help="List active requests, do nothing else",
        action="store_true",
    )

    exclusives = parser.add_mutually_exclusive_group()
    exclusives.add_argument(
        "--sign", metavar="id", type=int, help="Sign the CSR with this id"
    )
    exclusives.add_argument(
        "--reject",
        metavar="id",
        type=int,
        help="Reject the CSR with this id",
    )

    cleanout = parser.add_mutually_exclusive_group()
    cleanout.add_argument(
        "--clean",
        metavar="id",
        type=int,
        help="Remove all older certificates for this CSR",
    )
    cleanout.add_argument(
        "--wipe",
        metavar="id",
        type=int,
        help="Wipe all certificates for this CSR",
    )

    bulk = parser.add_mutually_exclusive_group()
    bulk.add_argument(
        "--refresh",
        help="Sign all certificates that have a valid current signature.",
        action="store_true",
    )

    bulk.add_argument(
        "--cleanall",
        help="Clean all older certificates.",
        action="store_true",
    )

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
        output = " ".join(
            (str(csr.id), csr.commonname, csr.sha256sum, not_after)
        )
        # TODO: Add lifetime of latest (fetched?) cert for the key.
        print(output)


def calc_lifetime(lifetime=relativedelta(hours=24)):
    now = datetime.datetime.utcnow()
    future = now + lifetime
    return future - now


def csr_wipe(csr_id):
    with transaction.manager:
        CSR = models.CSR.query().get(csr_id)
        if not CSR:
            error_out("ID not found")
        CSR.certificates = []
        CSR.save()


def csr_clean(csr_id):
    with transaction.manager:
        CSR = models.CSR.query().get(csr_id)
        if not CSR:
            error_out("ID not found")
        certs = sorted(CSR.certificates, key=lambda cert: cert.not_after)
        CSR.certificates = certs[-1:]
        CSR.save()


def clean_all():
    csrlist = models.CSR.refreshable()
    for csr in csrlist:
        csr_clean(csr.id)


def csr_reject(csr_id):
    with transaction.manager:
        CSR = models.CSR.query().get(csr_id)
        if not CSR:
            error_out("ID not found")

        CSR.rejected = True
        CSR.save()


def csr_sign(csr_id, ca, timedelta, backdate):
    with transaction.manager:
        CSR = models.CSR.query().get(csr_id)
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
                msg = (
                    "Currently has a valid certificate with {} lifetime, "
                    "new certificate would have {} lifetime. \n"
                    "Clean out existing certificates before shortening "
                    "lifetime.\n"
                    "The old certificate is still out there."
                )
                error_out(msg.format(cur_lifetime, timedelta))

        cert = models.Certificate.sign(CSR, ca, timedelta, backdate)
        cert.save()


def refresh(csr, ca, lifetime_short, lifetime_long, backdate):
    last = csr.certificates[0]
    old_lifetime = last.not_after - last.not_before
    # XXX: In a backdated cert, this is almost always true.
    if old_lifetime >= lifetime_long:
        cert = models.Certificate.sign(csr, ca, lifetime_long, backdate)
    else:
        # Never backdate short-lived certs
        cert = models.Certificate.sign(csr, ca, lifetime_short, False)
    with transaction.manager:
        cert.save()


def csr_resign(ca, lifetime_short, lifetime_long, backdate):
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        try:
            csrlist = models.CSR.refreshable()
        except Exception:
            error_out("Not found or some other error")
        futures = (
            executor.submit(
                refresh, csr, ca, lifetime_short, lifetime_long, backdate
            )
            for csr in csrlist
        )
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception:
                print("Future failed")


def main():
    args = cmdline()
    env = bootstrap(args.inifile)
    settings, closer = env["registry"].settings, env["closer"]
    engine = create_engine(settings["sqlalchemy.url"])
    models.init_session(engine)
    settings_backdate = asbool(settings.get("backdate", False))

    _short = int(settings.get("lifetime.short", 48))
    _long = int(settings.get("lifetime.long", 7 * 24))
    life_short = calc_lifetime(relativedelta(hours=_short))
    life_long = calc_lifetime(relativedelta(hours=_long))
    del _short, _long

    try:
        certname = settings["ca.cert"]
        keyname = settings["ca.key"]
    except KeyError:
        error_out("config file needs ca.cert and ca.key properly set")
    ca = models.SigningCert.from_files(certname, keyname)

    if life_short > life_long:
        error_out(
            "Short lived certs ({0}) shouldn't last longer "
            "than long lived certs ({1})".format(life_short, life_long)
        )
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
        clean_all()

    if args.sign:
        if args.long:
            csr_sign(args.sign, ca, life_long, settings_backdate)
        else:
            # Never backdate short lived certs
            csr_sign(args.sign, ca, life_short, False)

    if args.refresh:
        csr_resign(ca, life_short, life_long, settings_backdate)
