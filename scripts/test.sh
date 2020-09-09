#!/bin/bash

set -x

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN=root

GOBIN=$PWD/bin GO111MODULE=on go get github.com/trishankatdatadog/vault-gpg-plugin

vault server -dev -dev-root-token-id=$VAULT_TOKEN -dev-plugin-dir=bin &
VAULT_PID=$!
vault login root
vault secrets enable vault-gpg-plugin

tox
TOX_RETCODE=$?

kill -2 $VAULT_PID

rm -rf bin
echo "Return code: $TOX_RETCODE"
exit $TOX_RETCODE
