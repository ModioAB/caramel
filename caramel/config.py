#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
"""caramel.config is a helper library that standardizes and collects the logic
 in one place used by the caramel CLI tools/scripts"""

import argparse
import os


def add_inifile_argument(parser, env=None):
    """Adds an argument to the parser for the config-file, defaults to
    CARAMEL_INI in the environment"""
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


def add_db_url_argument(parser, env=None):
    """Adds an argument for the URL for the database to a given parser"""
    parser.add_argument(
        "--dburl",
        help="URL to the database to use",
        type=str,
    )


class CheckInifilePathSet(argparse.Action):
    """An arparse.Action to raise an error if no config file has been
    defined by the user or  in the environment"""

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


def _get_config_value(
    arguments: argparse.Namespace,
    variable,
    required=False,
    setting_name=None,
    settings=None,
    env=None,
):
    """Returns what value to use for a given config variable, prefer argument >
    env-variable > config-file"""
    result = None
    if setting_name is None:
        setting_name = variable
    if settings is not None:
        result = settings.get(setting_name, result)

    if env is None:
        env = os.environ
    env_var = "CARAMEL_" + variable.upper().replace("-", "_")
    result = env.get(env_var, result)

    arg_value = getattr(arguments, variable, result)
    result = arg_value if arg_value is not None else result

    if required and result is None:
        raise ValueError(
            f"No {variable} could be found as either an argument,"
            f" in the environment variable {env_var} or in the config file",
            variable,
            env_var,
        )
    return result


def get_db_url(arguments=None, settings=None, required=True):
    """Returns URL to use for database, prefer argument > env-variable >
    config-file"""
    return _get_config_value(
        arguments,
        variable="dburl",
        required=required,
        setting_name="sqlalchemy.url",
        settings=settings,
    )
