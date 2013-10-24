#!/bin/bash

die () {
    echo >&2 "error:" "$@"
    exit 1
}

app="$(basename "$0" .sh)"
here="$(dirname "$0")"

venv_path="$(readlink -m "${here}/${app}-venv/")"
cfg_path="$(readlink -m "${here}/${app}.ini")"

venv="$(readlink -e "${venv_path}")" || die not found: "${venv_path}"
cfg="$(readlink -e "${cfg_path}")" || die not found: "${cfg_path}"

[ -r "${venv}/bin/activate" ] || \
    die "${venv}" does not appear to be a virtualenv

scl enable python33 "bash -c \
'source \"${venv}/bin/activate\"; ${here}/paste-launcher.py \"${cfg}\"'"
