#!/bin/bash
set -euo pipefail
: ${CONFIG:=/etc/caramel-refresh.conf}
IFS=$'\n'

die () {
    echo >&2 $'Error: \n'"$@"
    exit 1
}

if [ "$#" -lt 1 ];
then
    cat << EOF
This is caramel-refresh!

The first argument to caramel-refresh shall be the CA server URI
The next argument to caramel-refresh can be CA server cert.

We read a config file called /etc/caramel-refresh.conf. (or from CONFIG
environment variable)

$CONFIG is structured as per the following:

One request per line. semicolon (;) separated fields.
Field 0: CSR filename
Field 1: CRT filename
Field 2: PEM filename (optional, for lighttpd and others)

The PEM filename will only be created if specified, and only if it
exists.

The PEM file will be concatenation of private key & cert, for Lighttpd
and other tools that need that.
Key is assumed to be named the same as csr, s/csr/key/.
EOF
    die "Please add correct arguments"
fi

CURL_OPTS="--silent --show-error --connect-timeout 30 --max-time 60 --tlsv1"
POST_URL="$1"

if [ "$#" -gt 1 ]
then
   CA_CERT=$2
   test -s "$CA_CERT" || die "$CA_CERT missing"
   CURL_OPTS="${CURL_OPTS} --cacert $CA_CERT"
fi

type -p curl > /dev/null || die "We need curl in PATH"
type -p sha256sum > /dev/null || die "We need sha256sum in PATH"
test -s "$CONFIG" || die "$CONFIG should point to .csr files to be refreshed"

TMPDIR=$(mktemp -d /tmp/caramel-refresh.XXXXXXXX)
trap "rm -rf $TMPDIR" EXIT

FAILED=""
renew() {
    if [ "$#" -lt 2 ]
    then
        die "Need at least two posts in the config file, separated by ;"
    fi

    CSR="$1"
    CRT="$2"
    PEM=""

    if [ "$#" -gt 3 ]
    then
        PEM="$3"
        KEY=${CSR/.csr/.key}
        test -s "$PEM" || die "$PEM: found in config but missing"
        test -s "$KEY" || die "$PEM: Found but $KEY missing"
    fi

    test -z $CSR && die "Each line in the config is: csr filename;cert filename;pem filename"
    test -s "$CSR" || die "$CSR: invalid file match in config"
    test -s "$CRT" || die "$CRT: needs to exist."

    # Expansion done below, otherwise you get fun time debugging.
    IFS=$'\n\ '
    echo "Processing: $CSR => $CRT"

    CSRSUM=$(sha256sum "$CSR" |cut -f1 -d" ")
    CERTOUT=$TMPDIR/$CSRSUM
    STATUS=$(curl ${CURL_OPTS} -w '%{http_code}' --url ${POST_URL}/${CSRSUM} -o $CERTOUT)
    if [ $STATUS -eq 200 ]
    then
        cat $CERTOUT > "$CRT"
        if [ ! -z "$PEM" ]
        then
            cat "$KEY" "$CRT" > $PEM
        fi
    else
        FAILED="${FAILED}${CSR} => HTTP Status: ${STATUS}"$'\n'
    fi
    rm -f $CERTOUT
}

IFS=$'\n'
for line in $(<$CONFIG)
do
    split=$(echo "$line" | tr ";" "\n")
    renew $split
done

test -z "$FAILED" || die "$FAILED"
echo "all done"
