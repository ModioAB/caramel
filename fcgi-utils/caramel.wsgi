from pyramid.paster import get_app, setup_logging
ini_path = '/THIS/IS/WHERE/I/KEEP/MY/config.ini'
setup_logging(ini_path)
application = get_app(ini_path, 'main')
