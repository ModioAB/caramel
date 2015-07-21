#!/bin/env python3

import sys
import json
import argparse

from datetime import datetime

import transaction
from pyramid.paster import bootstrap
from sqlalchemy import create_engine

from caramel import models


def cmdline():
    parser = argparse.ArgumentParser()
    parser.add_argument("inifile")
    args = parser.parse_args()
    return args


def logify(csr, x):
    log = models.AccessLog(csr, x["addr"])
    log.when = datetime.utcfromtimestamp(x["when"])
    return log


def main():
    args = cmdline()
    env = bootstrap(args.inifile)

    settings, closer = env["registry"].settings, env["closer"]
    engine = create_engine(settings["sqlalchemy.url"])
    models.init_session(engine)

    data = json.load(sys.stdin)
    print("Will restore {} requests".format(len(data)))

    with transaction.manager:
        for obj in data:
            sys.stdout.write(".")
            sys.stdout.flush()
            csr = models.CSR(obj["sha256sum"], obj["pem"])
            csr.rejected = obj["rejected"]
            csr.certificates = [models.Certificate(csr, pem)
                                for pem in obj["certificates"]]
            csr.accessed = [logify(csr, x) for x in reversed(obj["accessed"])]
            csr.save()
        print("\nTransaction finalizing.")
    closer()
    engine.dispose()
    sys.exit(0)
