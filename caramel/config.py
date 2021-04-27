#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
import argparse
import os


def add_inifile_argument(parser, env=None):
    if env is None:
        env = os.environ
    default_ini = env.get("CARAMEL_INI")

    parser.add_argument(
        nargs="?",
        help="Path to a specific .ini-file to use as config",
        dest="inifile",
        default=default_ini,
        type=str,
        action=CheckInifilePathSet,
    )


class CheckInifilePathSet(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        inifile = getattr(namespace, self.dest, None)
        if inifile is None:
            raise ValueError(
                "ENVIRONMENT VARIABLE 'CARAMEL_INI' IS NOT SET\n"
                " - Set 'CARAMEL_INI' to the absolute path of the config or"
                " specify a path in the call like so:\n"
                "\t caramel_initializedb /path/to/config.ini [...]"
            )
