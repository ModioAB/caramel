#!/bin/bash
## This is our example deployment for our own servers
## This is an example of how we deploy python code,
## more documentation about that will follow.

set -e
: ${PROJECT:=caramel}
: ${SERVER:=ca.example.com}

TMPDIR=$(mktemp -d /tmp/${PROJECT}.XXXXX)
trap "rm -rf $TMPDIR" EXIT
REV=$(git rev-parse --verify --short HEAD)
(git archive HEAD | tar -f - -xC "$TMPDIR")
rsync -vr "$TMPDIR/" "$SERVER:/srv/$SERVER/$PROJECT-$REV"
ssh -t "$SERVER" "/srv/$SERVER/$PROJECT-$REV/scripts/post-deploy.sh" "$PROJECT" "$REV"

## All done
echo "**** All worked.  Python has been restarted for the webserver"
