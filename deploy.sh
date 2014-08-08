#! /bin/bash
set -e
## get the paths
: ${PIP_DOWNLOAD_CACHE:=$HOME/pip-downloads}
HERE="$(dirname "$(readlink -f "$0")")"
PROJECT="$1"
REV="$2"
venv=/opt/venv/"$PROJECT-$REV"
export PIP_DOWNLOAD_CACHE

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
chcon -t httpd_sys_content_t ${venv}/bin/activate


## Set up venv inside web-root
cd "$HERE"/..
rm -f "$PROJECT".ini "$PROJECT"-venv
ln -s "$HERE"/production.ini "$PROJECT".ini
ln -s "$venv" "$PROJECT"-venv
chcon -t httpd_sys_content_t "$PROJECT".ini
chcon -t httpd_sys_content_rw_t caramel.sqlite

sudo /usr/local/bin/killcaramel
