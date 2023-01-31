#!/bin/env python3
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
"""Admin tool to sign/refresh certificates."""

import argparse
import concurrent.futures
import datetime
import logging
import sys

import transaction
from dateutil.relativedelta import relativedelta
from pyramid.settings import asbool
from sqlalchemy import create_engine

from caramel import config, models

LOG = logging.getLogger(name="caramel.tool")


def cmdline():
    """Parse commandline."""
    parser = argparse.ArgumentParser()

    config.add_inifile_argument(parser)
    config.add_db_url_argument(parser)
    config.add_ca_arguments(parser)
    config.add_backdate_argument(parser)
    config.add_lifetime_arguments(parser)

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


def error_out(message, exc=None):
    """Print error message and exit with failure code."""
    LOG.error(message)
    if exc is not None:
        LOG.error(str(exc))
    sys.exit(1)


def print_list():
    """Print a list of certificates."""
    valid_requests = models.CSR.list_csr_printable()

    def unsigned_last(csr):
        return (not csr[3], csr.id)

    valid_requests.sort(key=unsigned_last)

    for csr_id, csr_commonname, csr_sha256sum, not_after in valid_requests:
        not_after = "----------" if not_after is None else str(not_after)
        output = " ".join((str(csr_id), csr_commonname, csr_sha256sum, not_after))
        # TODO: Add lifetime of latest (fetched?) cert for the key.
        print(output)


def calc_lifetime(lifetime=relativedelta(hours=24)):
    """Calculate lifetime of certificate."""
    now = datetime.datetime.utcnow()
    future = now + lifetime
    return future - now


def csr_wipe(csr_id):
    """Wipe a certain csr."""
    with transaction.manager:
        csr = models.CSR.query().get(csr_id)
        if not csr:
            error_out("ID not found")
        csr.certificates = []
        csr.save()


def csr_clean(csr_id):
    """Clean out old certs."""
    with transaction.manager:
        csr = models.CSR.query().get(csr_id)
        if not csr:
            error_out("ID not found")
        certs = [csr.certificates.first()]
        csr.certificates = certs
        csr.save()


def clean_all():
    """Clean out all old requests."""
    csrlist = models.CSR.refreshable()
    for csr in csrlist:
        csr_clean(csr.id)


def csr_reject(csr_id):
    """Reject a request."""
    with transaction.manager:
        csr = models.CSR.query().get(csr_id)
        if not csr:
            error_out("ID not found")
        csr.rejected = True
        csr.save()


def csr_sign(csr_id, ca_cert, timedelta, backdate):
    """Sign a request with ca, valid for timedelta, or backdate as well."""
    with transaction.manager:
        csr = models.CSR.query().get(csr_id)
        if not csr:
            error_out("ID not found")
        if csr.rejected:
            error_out("Refusing to sign rejected ID")

        cert = csr.certificates.first()
        if cert:
            today = datetime.datetime.utcnow()
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

        cert = models.Certificate.sign(csr, ca_cert, timedelta, backdate)
        cert.save()


def refresh(csr, ca_cert, lifetime_short, lifetime_long, backdate):
    """Refresh a single csr."""
    last = csr.certificates.first()
    old_lifetime = last.not_after - last.not_before
    # In a backdated cert, this is almost always true.
    if old_lifetime >= lifetime_long:
        cert = models.Certificate.sign(csr, ca_cert, lifetime_long, backdate)
    else:
        # Never backdate short-lived certs
        cert = models.Certificate.sign(csr, ca_cert, lifetime_short, False)
    with transaction.manager:
        cert.save()


def csr_resign(ca_cert, lifetime_short, lifetime_long, backdate):
    """Re-sign all requests for lifetime."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        try:
            csrlist = models.CSR.refreshable()
        except Exception as exc:  # pylint:disable=broad-except
            error_out("Not found or some other error", exc=exc)
        futures = (
            executor.submit(
                refresh, csr, ca_cert, lifetime_short, lifetime_long, backdate
            )
            for csr in csrlist
        )
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as exc:  # pylint:disable=broad-except
                LOG.error("Future failed: %s", exc)


def main():
    """Entrypoint of application."""
    args = cmdline()
    logging.basicConfig(format="%(message)s", level=logging.WARNING)
    env = config.bootstrap(args.inifile, dburl=args.dburl)
    settings, closer = env["registry"].settings, env["closer"]
    db_url = config.get_db_url(args, settings)
    engine = create_engine(db_url)
    models.init_session(engine)
    settings_backdate = asbool(config.get_backdate(args, settings, default=False))

    _short = int(config.get_lifetime_short(args, settings, default=48))
    _long = int(config.get_lifetime_long(args, settings, default=7 * 24))
    life_short = calc_lifetime(relativedelta(hours=_short))
    life_long = calc_lifetime(relativedelta(hours=_long))
    del _short, _long

    try:
        ca_cert_path, ca_key_path = config.get_ca_cert_key_path(args, settings)
    except ValueError as error:
        error_out("Error reading ca data", exc=error)

    ca_cert = models.SigningCert.from_files(ca_cert_path, ca_key_path)

    if life_short > life_long:
        error_out(
            f"Short lived certs ({life_short}) shouldn't last longer "
            f"than long lived certs ({life_long})"
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
            csr_sign(args.sign, ca_cert, life_long, settings_backdate)
        else:
            # Never backdate short lived certs
            csr_sign(args.sign, ca_cert, life_short, False)

    if args.refresh:
        csr_resign(ca_cert, life_short, life_long, settings_backdate)
