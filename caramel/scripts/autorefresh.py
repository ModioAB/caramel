#!/bin/env python3

"""The caramel auto-refresh daemon.
Automatically refreshes certificates, needs access to private key for the CA.
May run concurrent with the autosign daemon.
"""

import sys
import time
import logging
import argparse
import datetime
import transaction
import concurrent.futures

from pyramid.paster import bootstrap
from pyramid.settings import asbool
from sqlalchemy import create_engine

import caramel.models as models

logger = logging.getLogger(__name__)


def csr_refresh(csr, before, after, settings):
    """ Refreshes a CSR if need be"""
    now = datetime.datetime.utcnow()
    if csr.rejected:
        return

    # backdating is ugly, cap it.
    lifetime = min(after - before, settings["long"])
    half_life = lifetime / 2

    if now < after - half_life:
        return

    ca_key = settings["ca_key"]
    ca_cert = settings["ca_cert"]

    if lifetime == settings["long"]:
        new_lifetime = settings["long"]
        backdate = settings["backdate"]
    else:
        backdate = False
        new_lifetime = settings["short"]

    with transaction.manager:
        logger.info("Refreshing {} with lifetime {}, backdate={}"
                    .format(csr, new_lifetime, backdate))

        cert = models.Certificate.sign(csr, ca_key, ca_cert,
                                       new_lifetime, backdate)
        cert.save()
    return


def mainloop(delay, settings):
    """Concurrent-enabled mainloop.
    Spins forever and signs all certificates that come in"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        while True:
            csrlist = models.CSR.valid()
            lifetimes = models.CSR.most_recent_lifetime()
            futures = []
            for csr in csrlist:
                if csr.id not in lifetimes:
                    continue
                before, after = lifetimes[csr.id]
                future = executor.submit(csr_refresh,
                                         csr, before, after, settings)
                futures.append(future)

            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception:
                    logger.exception("Future failed")
            time.sleep(delay)


def cmdline():
    """Basically just parsing the arguments and returning them"""
    parser = argparse.ArgumentParser()
    parser.add_argument("inifile")
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
    env = bootstrap(args.inifile)
    logger.setLevel(logging.DEBUG)
    logging.config.fileConfig(args.inifile)

    settings, closer = env['registry'].settings, env['closer']
    engine = create_engine(settings['sqlalchemy.url'])
    models.init_session(engine)

    backdate = asbool(settings.get('backdate', False))
    delay = int(settings.get('autorefresh.delay', 15)) * 60

    life_short = int(settings.get('lifetime.short', 3))
    life_short = datetime.timedelta(hours=life_short)

    life_long = int(settings.get('lifetime.long', 3))
    life_long = datetime.timedelta(hours=life_long)

    try:
        with open(settings['ca.cert'], 'rt') as f:
            cert = f.read()
        with open(settings['ca.key'], 'rt') as f:
            key = f.read()
    except KeyError:
        error_out("config file lacks ca.cert or ca.key", closer)
    except OSError:
        error_out("Key or cert not found", closer)

    settings = {
        "short": life_short,
        "long": life_long,
        "ca_cert": cert,
        "ca_key": key,
        "backdate": backdate,
    }
    mainloop(delay, settings)
