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
import transaction
import sys
import logging
import datetime
import time
import uuid
import concurrent.futures

from pyramid.paster import bootstrap
from sqlalchemy import create_engine

import caramel.models as models

logger = logging.getLogger(__name__)


def csr_sign(csr, key, cert, delta):
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
        cert = models.Certificate.sign(csr, key, cert, delta)
        logger.info("Signing: {0} valid for {1}".format(csr.commonname, delta))
        cert.save()
    return


def mainloop(delay, key, cert, delta):
    """Concurrent-enabled mainloop.
    Spins forever and signs all certificates that come in"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        while True:
            csrs = models.CSR.unsigned()
            futures = [executor.submit(csr_sign,
                                       csr,
                                       key, cert, delta)
                       for csr in csrs]

            time.sleep(delay)
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception:
                    logger.exception("Future failed")


def cmdline():
    """Basically just parsing the arguments and returning them"""
    parser = argparse.ArgumentParser()
    parser.add_argument("inifile")
    parser.add_argument("--delay", help="How long to sleep. (ms)")
    args = parser.parse_args()
    return args


def error_out(message, closer):
    """Just log a message, and perform cleanup"""
    logger.error(message)
    closer()
    sys.exit(1)


def log_strange_csrs():
    csrs = models.CSR.unsigned()
    for csr in csrs:
        if csr.rejected:
            logging.info("Skipping rejected csr: {}".format(csr.commonname))

        try:
            uuid.UUID(csr.commonname)
        except ValueError:
            logger.warn("Unsigned, Non-UUID CSR: {}".format(csr.commonname))


def main():
    """Main, as called from the script instance by pyramid"""
    args = cmdline()
    env = bootstrap(args.inifile)
    logging.config.fileConfig(args.inifile)
    logger.setLevel(logging.DEBUG)

    settings, closer = env['registry'].settings, env['closer']
    engine = create_engine(settings['sqlalchemy.url'])
    models.init_session(engine)
    delay = int(settings.get('delay', 500)) / 1000

    valid = int(settings.get('lifetime.short', 3))
    delta = datetime.timedelta(days=0, hours=valid)
    del valid

    try:
        with open(settings['ca.cert'], 'rt') as f:
            cert = f.read()
        with open(settings['ca.key'], 'rt') as f:
            key = f.read()
    except KeyError:
        error_out("config file lacks ca.cert or ca.key", closer)
    except OSError:
        error_out("Key or cert not found", closer)

    log_strange_csrs()
    mainloop(delay, key, cert, delta)
