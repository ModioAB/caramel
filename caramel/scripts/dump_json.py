#!/bin/env python3

import sys
import json
import argparse

from datetime import timezone

from pyramid.paster import bootstrap
from sqlalchemy import create_engine
from caramel import models


def cmdline():
    parser = argparse.ArgumentParser()
    parser.add_argument("inifile")
    args = parser.parse_args()
    return args


def stringy(something):
    try:
        return something.decode("ascii")
    except AttributeError:
        return something


def main():
    args = cmdline()
    env = bootstrap(args.inifile)

    settings, closer = env['registry'].settings, env['closer']
    engine = create_engine(settings['sqlalchemy.url'])
    models.init_session(engine)

    out = []
    for csr in models.CSR.all():
        obj = {
            "sha256sum": csr.sha256sum,
            "rejected": bool(csr.rejected),
            "pem": stringy(csr.pem),
            "certificates": [stringy(x.pem) for x in csr.certificates],
            "accessed": [
                {"when": x.when.replace(tzinfo=timezone.utc).timestamp(),
                 "addr": x.addr}
                for x in csr.accessed
            ],
        }
        out.append(obj)

    print(json.dumps(out, sort_keys=True, indent=2))
    closer()
    engine.dispose()
    sys.exit(0)
