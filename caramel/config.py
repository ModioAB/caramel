#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
"""caramel.config is a helper library that standardizes and collects the logic
 in one place used by the caramel CLI tools/scripts"""

import argparse
import logging
import os

LOG_LEVEL = (
    logging.ERROR,
    logging.WARNING,
    logging.INFO,
    logging.DEBUG,
)


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


def add_verbosity_argument(parser):
    """Adds an argument for verbosity to a given parser, counting the amount of
    'v's and 'verbose' on the commandline"""
    parser.add_argument(
        "-v",
        "--verbose",
        help="Verbosity of root logger, increasing the more 'v's are added",
        action="count",
        default=0,
    )


def add_ca_arguments(parser):
    """Adds a ca-cert and ca-key argument to a given parser"""
    parser.add_argument(
        "--ca-cert",
        help="Path to CA certificate to use",
        type=str,
    )
    parser.add_argument(
        "--ca-key",
        help="Path to CA key to use",
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
    default=None,
    env=None,
):
    """Returns what value to use for a given config variable, prefer argument >
    env-variable > config-file, if a value cant be found and default is not
    None, default is returned"""
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

    if result is None:
        result = default

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


def get_log_level(argument_level, logger=None, env=None):
    """Calculates the highest verbosity(here inverted) from the argument,
    environment and root, capping it to between 0-3, returning the log level"""

    if env is None:
        env = os.environ
    env_level = int(env.get("CARAMEL_LOG_LEVEL", 0))

    if logger is None:
        logger = logging.getLogger()
    current_level = LOG_LEVEL.index(logger.level) if logger.level in LOG_LEVEL else 0

    verbosity = max(argument_level, env_level, current_level)
    verbosity = min(verbosity, len(LOG_LEVEL) - 1)
    log_level = LOG_LEVEL[verbosity]
    return log_level


def configure_log_level(arguments: argparse.Namespace, logger=None):
    """Sets the root loggers level to the highest verbosity from the argument,
    environment and config-file"""
    log_level = get_log_level(arguments.verbose)
    if logger is None:
        logger = logging.getLogger()
    logger.setLevel(log_level)


def get_ca_cert_key_path(arguments: argparse.Namespace, settings=None, required=True):
    """Returns the path to the ca-cert and ca-key to use"""
    ca_cert_path = _get_config_value(
        arguments,
        variable="ca-cert",
        required=required,
        setting_name="ca.cert",
        settings=settings,
    )
    ca_key_path = _get_config_value(
        arguments,
        variable="ca-key",
        required=required,
        setting_name="ca.key",
        settings=settings,
    )
    return ca_cert_path, ca_key_path
