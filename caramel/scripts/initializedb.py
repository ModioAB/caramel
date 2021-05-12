#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
import argparse

from sqlalchemy import engine_from_config

from pyramid.paster import (
    get_appsettings,
    setup_logging,
)

import caramel.config as config
from caramel.models import init_session


def cmdline():
    parser = argparse.ArgumentParser()
    config.add_inifile_argument(parser)
    args = parser.parse_args()
    return args


def main():
    args = cmdline()
    config_uri = args.inifile
    setup_logging(config_uri)
    settings = get_appsettings(config_uri)
    engine = engine_from_config(settings, "sqlalchemy.")
    init_session(engine, create=True)
