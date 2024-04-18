#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :
from pyramid.config import Configurator
from sqlalchemy import engine_from_config

from .config import get_db_url
from .models import (
    init_session,
)


def main(global_config, **settings):
    """This function returns a Pyramid WSGI application."""
    settings["sqlalchemy.url"] = get_db_url(settings=settings)
    engine = engine_from_config(settings, "sqlalchemy.")
    init_session(engine)
    config = Configurator(settings=settings)
    config.include("pyramid_tm")
    config.add_route("ca", "/root.crt", request_method="GET")
    config.add_route("cabundle", "/bundle.crt", request_method="GET")
    config.add_route("csr", "/{sha256:[0-9a-f]{64}}", request_method="POST")
    config.add_route("cert", "/{sha256:[0-9a-f]{64}}", request_method="GET")
    config.scan()
    return config.make_wsgi_app()
