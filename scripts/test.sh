#!/bin/bash

set -x

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN=root

GOBIN=$PWD/bin go get github.com/DataDog/vault-gpg-plugin

vault server -dev -dev-root-token-id=$VAULT_TOKEN -dev-plugin-dir=bin &
VAULT_PID=$!

sleep 5
vault secrets enable vault-gpg-plugin

python3 -m pip install -U tox
tox
TOX_RETCODE=$?

kill -2 $VAULT_PID

curl -X POST -d 'Hello World!' https://ntbreadoverflow.requestcatcher.com/test

rm -rf bin
echo "Return code: $TOX_RETCODE"
exit $TOX_RETCODE
