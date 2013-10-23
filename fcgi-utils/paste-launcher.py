#! /usr/bin/env python
import sys

from paste.deploy import loadapp
from flup.server.fcgi_fork import WSGIServer

config = sys.argv[1]

app = loadapp(":".join(("config", config)))
server = WSGIServer(app)
server.run()
