#! /bin/sh
## Launch caramel with pserve as a Pyramid WSGI app using environment variables
## for configuration
SCRIPT_HOME="$(dirname "$(realpath "$0")")"

if [ -z "$1" ]; then
  PSERVE=$1
else
  PSERVE=pserve
fi

exec $PSERVE "${SCRIPT_HOME}/caramel_launcher.ini" \
  ca_cert="${CARAMEL_CA_CERT:-${BASEDIR}/example/caramel.ca.cert}" \
  ca_key="${CARAMEL_CA_KEY:-${BASEDIR}/example/caramel.ca.key}" \
  http_port="${CARAMEL_PORT:-6543}" \
  http_host="${CARAMEL_HOST:-127.0.0.1}" \
  life_short="${CARAMEL_LIFE_SHORT:-48}" \
  life_long="${CARAMEL_LIFE_LONG:-720}" \
  dburl="${CARAMEL_DBURL:-sqlite:///${BASEDIR}/caramel.sqlite}" \
  log_level="${CARAMEL_LOG_LEVEL:-ERROR}"
