#! /bin/sh
CA_CERT=/etc/pki/tls/certs/ca.example.com.crt
MY_CRT=/etc/pki/tls/certs/client.example.com.crt
MY_CSR=/etc/pki/tls/certs/client.example.com.csr
MY_KEY=/etc/pki/tls/private/client.example.com.key

CLIENTID=`cat /etc/machine-id`   # For example
CLIENTID=`sed -e 's/://g' /sys/class/net/eth0/address`

SUBJECT="/O=ExampleInc/OU=ExampleCom/CN=$CLIENTID"
POST_URL=https://caramel.example.com/ra

echo $SUBJECT

if [ ! -f $MY_KEY ];
then
    rm -f $MY_CRT $MY_CSR
    openssl genrsa -out $MY_KEY 2048
fi

if [ ! -f $MY_CSR ];
then
    openssl req -new -key $MY_KEY -out  $MY_CSR -utf8 -sha256 -subj  "$SUBJECT"
    ## Upload csr
fi

CSRSUM=$(sha256sum $MY_CSR |cut -f1 -d" ")

CURL_OPTS="--silent --show-error --remote-time --connect-timeout 300 --max-time 600 --cacert $CA_CERT"


# The logic here is fun.
# If I don't have a cert, we try to download it.
#   if we get 404 from downloading it, we upload the CSR.

# if we _have_ a cert, we authorize ourselves using it.
# If we _have_ a cert, we try to download a newer version.
# if that 404s, we  upload the CSR.
#   This is so that "older" clients will re-generate their certs

# This means that the current states are :
# 404 = No CSR pushed
# 202:  CSR pushed, not signed yet. ( nothing to do, try again later)
# 200:  Check timestamp if we want to download.

if [ -f $MY_CRT ];
then
    # Check if newer ( -z )
    # and use ssl client auth with key+cert

    CURL_OPTS="${CURL_OPTS} --key ${MY_KEY} --cert ${MY_CRT} -z ${MY_CRT}"
fi

## Try:
#  Download cert ( if newer than what we have )
#  if 202:
#       wait until later. ( uploaded, not signed )
#  if 304:
#       do nothing
#  if 404
#       upload CSR

STATUS=$(curl ${CURL_OPTS}  -w '%{http_code}' --url ${POST_URL}/${CSRSUM} -o ${CSRSUM})

if [ $STATUS -eq 200 ];
then
    mv $CSRSUM $MY_CRT
fi

if [ $STATUS -eq 202 -o $STATUS -eq 304 ];
then
    echo Not processed yet. waiting.
    # Or already in place
    rm -f $CSRSUM
fi

if [ $STATUS -eq 404 ];
then
    rm -f $CSRSUM
    curl ${CURL_OPTS} --data-binary @$MY_CSR ${POST_URL}/${CSRSUM}
fi
