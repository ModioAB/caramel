#! /bin/bash
## This script are tasks to be done on the server after initial deployment.
## This includes setting up local environments and virtualenvs
## This should only be called from "deploy-caramel.sh"

set -e
## get the paths
: ${PIP_DOWNLOAD_CACHE:=$HOME/pip-downloads}
export PIP_DOWNLOAD_CACHE
HERE="$(dirname "$(readlink -f "$0")")"
PROJECT="$1"
REV="$2"
venv=/opt/venv/"$PROJECT-$REV"

# Create new VirtualEnv
scl enable python33 "virtualenv-3.3 $venv"
/sbin/restorecon -vR "$venv"

# Virtual env population & install
scl enable python33 "bash -c \
'source \"${venv}/bin/activate\";\
 cd \"${HERE}\"; python setup.py install;'"

/sbin/restorecon -vR "$venv"
echo "Setting permissions"
chmod -R go+rX "$HERE"
chmod -R go+rX "$venv"

# Permissions inside Virtual Env
chcon -t httpd_sys_content_t "${venv}/bin/activate"


## Set up venv inside web-root
cd "$HERE"/..
rm -f "$PROJECT"-venv

# create link if it doesn't exist
test -e "$PROJECT".ini || ln -s "$HERE"/production.ini "$PROJECT".ini

# Update the link if it exists
test -L "$PROJECT".ini && ln -sf "$HERE"/production.ini "$PROJECT".ini

ln -s "$venv" "$PROJECT"-venv
chcon -t httpd_sys_content_t "$PROJECT".ini
# Below only works for root, do it manually.
echo "As root: chcon -t httpd_sys_content_rw_t caramel.sqlite"
# You probably want to do something to kill all old instances of caramel here below.
