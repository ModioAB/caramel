#!/bin/bash
set -e
: ${PROJECT:=caramel}
: ${SERVER:=ca.modio.se}

LOCALPROJECT="$PROJECT"
TMPDIR=$(mktemp -d /tmp/${PROJECT}.XXXXX)
trap "rm -rf $TMPDIR" EXIT
REV=$(git rev-parse --verify --short HEAD)
(git archive HEAD | tar -f - -xC "$TMPDIR")
# (cd "$TMPDIR/$LOCALPROJECT"; python -m unittest discover) || exit
# Upload project first, shared lib later
rsync -vr "$TMPDIR/" "$SERVER:/srv/$SERVER/$PROJECT-$REV"
ssh -t "$SERVER" "/srv/$SERVER/$PROJECT-$REV/deploy.sh" "$PROJECT" "$REV"

## All done
echo "**** All worked.  Python has been restarted for the webserver"
