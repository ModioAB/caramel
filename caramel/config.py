#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
"""caramel.config is a helper library that standardizes and collects the logic
in one place used by the caramel CLI tools/scripts"""

import argparse
import logging
import os
from logging.config import dictConfig

import pyramid.paster as paster
from pyramid.scripting import prepare

LOG_LEVEL = {
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}

DEFAULT_LOGGING_CONFIG = {
    "version": 1,
    "formatters": {
        "generic": {
            "format": "%(asctime)s %(levelname)-5.5s [%(name)s][%(threadName)s]"
            "%(message)s"
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
            "level": "NOTSET",
            "formatter": "generic",
        },
    },
    "loggers": {
        "": {  # root logger
            "handlers": ["console"],
            "level": "INFO",
        },
        "caramel": {
            "level": "DEBUG",
            "qualname": "caramel",
        },
        "sqlalchemy": {
            "level": "INFO",
            "qualname": "sqlalchemy.engine",
        },
    },
}

DEFAULT_APP_SETTINGS = {
    "csrf_trusted_origins": [],
    "debug_all": False,
    "debug_authorization": False,
    "debug_notfound": False,
    "debug_routematch": False,
    "debug_templates": False,
    "default_locale_name": "en",
    "prevent_cachebust": False,
    "prevent_http_cache": False,
    "pyramid.csrf_trusted_origins": [],
    "pyramid.debug_all": False,
    "pyramid.debug_authorization": False,
    "pyramid.debug_notfound": False,
    "pyramid.debug_routematch": False,
    "pyramid.debug_templates": False,
    "pyramid.default_locale_name": "en",
    "pyramid.prevent_cachebust": False,
    "pyramid.prevent_http_cache": False,
    "pyramid.reload_all": False,
    "pyramid.reload_assets": False,
    "pyramid.reload_resources": False,
    "pyramid.reload_templates": True,
    "reload_all": False,
    "reload_assets": False,
    "reload_resources": False,
    "reload_templates": True,
}


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
    )


def add_db_url_argument(parser):
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


def add_lifetime_arguments(parser):
    """Adds an argument for the short and long lifetime of certs"""
    parser.add_argument(
        "-l",
        "--life-short",
        help="Lifetime of short term certs",
        type=int,
    )
    parser.add_argument(
        "-s",
        "--life-long",
        help="Lifetime of long term certs",
        type=int,
    )


def add_backdate_argument(parser):
    """Adds an argument to enable backdating certs"""
    parser.add_argument(
        "-b",
        "--backdate",
        help="Use backdating, default is False",
        action="store_true",
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
    environment and root, capping it to between logging.DEBUG(10)-logging.ERROR(40),
    returning the log level"""

    if env is None:
        env = os.environ
    env_level_name = env.get("CARAMEL_LOG_LEVEL", "ERROR").upper()
    env_level = LOG_LEVEL[env_level_name]

    if logger is None:
        logger = logging.getLogger()
    current_level = logger.level

    argument_verbosity = logging.ERROR - argument_level * 10  # level steps are 10
    verbosity = min(argument_verbosity, env_level, current_level)
    log_level = (
        verbosity if logging.DEBUG <= verbosity <= logging.ERROR else logging.ERROR
    )
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
        variable="ca_cert",
        required=required,
        setting_name="ca.cert",
        settings=settings,
    )
    ca_key_path = _get_config_value(
        arguments,
        variable="ca_key",
        required=required,
        setting_name="ca.key",
        settings=settings,
    )
    return ca_cert_path, ca_key_path


def get_lifetime_short(
    arguments: argparse.Namespace, settings=None, required=False, default=None
):
    """Returns the default lifetime for certs in hours"""
    return _get_config_value(
        arguments,
        variable="life_short",
        required=required,
        setting_name="lifetime.short",
        settings=settings,
        default=default,
    )


def get_lifetime_long(
    arguments: argparse.Namespace, settings=None, required=False, default=None
):
    """Returns the long term certs lifetime in hours"""
    return _get_config_value(
        arguments,
        variable="life_long",
        required=required,
        setting_name="lifetime.long",
        settings=settings,
        default=default,
    )


def get_backdate(
    arguments: argparse.Namespace, settings=None, required=False, default=None
):
    """Returns the long term certs lifetime in hours"""
    return _get_config_value(
        arguments,
        variable="backdate",
        required=required,
        settings=settings,
        default=default,
    )


def setup_logging(config_path=None):
    """wrapper for pyramid.paster.sertup_logging using file at config.path, if
    no config_path is passed on use dictionary DEFAULT_LOGGING_CONFIG"""
    if config_path:
        paster.setup_logging(config_path)
    else:
        dictConfig(DEFAULT_LOGGING_CONFIG)


def bootstrap(config_path=None, dburl=None):
    """wrapper for pyramid.paster.bootstraper, if a config_path is not given
    then DEFAULT_APP_SETTINGS to bootstrap the app manually"""
    if dburl:
        os.environ["CARAMEL_DBURL"] = dburl
    if config_path:
        return paster.bootstrap(config_path)
    else:
        from caramel import main as get_app

        app = get_app({}, **DEFAULT_APP_SETTINGS)
        env = prepare()
        env["app"] = app
        return env


def get_appsettings(config_path):
    """wrapper for pyramid.paster.get_appsettings, if a config_path is not
    given then return DEFAULT_APP_SETTINGS"""
    if config_path:
        return paster.get_appsettings(config_path)
    else:
        return DEFAULT_APP_SETTINGS
