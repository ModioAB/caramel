#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
import argparse

from sqlalchemy import create_engine

import caramel.config as config
from caramel.config import (
    get_appsettings,
    setup_logging,
)
from caramel.models import init_session


def cmdline():
    parser = argparse.ArgumentParser()

    config.add_inifile_argument(parser)
    config.add_db_url_argument(parser)
    config.add_verbosity_argument(parser)

    args = parser.parse_args()
    return args


def main():
    args = cmdline()
    config_path = args.inifile
    settings = get_appsettings(config_path)

    setup_logging(config_path)
    config.configure_log_level(args)

    db_url = config.get_db_url(args, settings)
    engine = create_engine(db_url)
    init_session(engine, create=True)
