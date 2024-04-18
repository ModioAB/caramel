#!/bin/env python3

"""The caramel auto-signer daemon.
This isn't necessary a _good_ idea, but it's part of examples of how
you can use caramel for application signups.

To work, you need to embed the root CA in your application (effectively pinning
it).
The client then generates a key (if none exists) and a CSR (based on the stored
CA). It pushes this to the caramel server, and goes into a spin-loop, waiting
for the key to get signed.

The autosigner then automatically signs the CSR.
The client gets it's certificate, and then connects to a second service (not
quite implemented here)  where the user adds contact information
(email/password) which ties an identity to the private key.

This can then be used to link multiple keys/applications to the same user, in a
safe & secure manner.

Autosigneer is implemented as it's own service, to make it obvious that you
shouldn't have your private key accessible by the web-application.
it."""

import argparse
import concurrent.futures
import datetime
import logging
import sys
import time
import uuid

import transaction
from sqlalchemy import create_engine

import caramel.models as models
from caramel import config
from caramel.config import (
    bootstrap,
    setup_logging,
)

logger = logging.getLogger(__name__)


def csr_sign(csr, ca, delta):
    """Signs a CSR and saves it in a transaction.
    Transaction so we won't have racing with the database.
    Also validates that it's a UUID for commonname."""

    # Could have been by us, or before
    if csr.rejected:
        return

    try:
        uuid.UUID(csr.commonname)
    except ValueError:
        # not a valid uuid. Just ignore
        return

    with transaction.manager:
        cert = models.Certificate.sign(csr, ca, delta)
        cert.save()
    return


def mainloop(delay, ca, delta):
    """Concurrent-enabled mainloop.
    Spins forever and signs all certificates that come in"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        while True:
            csrs = models.CSR.unsigned()
            futures = [executor.submit(csr_sign, csr, ca, delta) for csr in csrs]

            time.sleep(delay)
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception:
                    logger.exception("Future failed")


def cmdline():
    """Basically just parsing the arguments and returning them"""
    parser = argparse.ArgumentParser()

    config.add_inifile_argument(parser)
    config.add_db_url_argument(parser)
    config.add_verbosity_argument(parser)
    config.add_ca_arguments(parser)

    parser.add_argument("--delay", help="How long to sleep. (ms)")
    parser.add_argument("--valid", help="How many hours the certificate is valid for")

    args = parser.parse_args()
    return args


def error_out(message, closer):
    """Just log a message, and perform cleanup"""
    logger.error(message)
    closer()
    sys.exit(1)


def main():
    """Main, as called from the script instance by pyramid"""
    args = cmdline()
    config_path = args.inifile

    setup_logging(config_path)
    config.configure_log_level(args)

    env = bootstrap(config_path, dburl=args.dburl)
    settings, closer = env["registry"].settings, env["closer"]

    db_url = config.get_db_url(args, settings)
    engine = create_engine(db_url)

    models.init_session(engine)
    delay = int(settings.get("delay", 500)) / 1000
    valid = int(settings.get("valid", 3))
    delta = datetime.timedelta(days=0, hours=valid)
    del valid

    try:
        ca_cert_path, ca_key_path = config.get_ca_cert_key_path(args, settings)
    except ValueError as error:
        error_out(str(error), closer)
    ca = models.SigningCert.from_files(ca_cert_path, ca_key_path)
    mainloop(delay, ca, delta)


if __name__ == "__main__":
    logging.basicConfig()
