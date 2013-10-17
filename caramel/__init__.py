#! /usr/bin/env python
# vim: expandtab shiftwidth=4 softtabstop=4 tabstop=17 filetype=python :

# Make things as three-ish as possible (requires python >= 2.6)
from __future__ import (unicode_literals, print_function,
                        absolute_import, division)
# Namespace cleanup
del unicode_literals, print_function, absolute_import, division

#
# ----- End header -----
#

from pyramid.config import Configurator
from sqlalchemy import engine_from_config

from .models import (
    init_session,
    )


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    engine = engine_from_config(settings, "sqlalchemy.")
    init_session(engine)
    config = Configurator(settings=settings)
    config.add_route("csr", "/{sha256:[0-9a-f]{64}}", request_method="POST")
    config.add_route("cert", "/{sha256:[0-9a-f]{64}}", request_method="GET")
    config.scan()
    return config.make_wsgi_app()
