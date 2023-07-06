#!/bin/bash

# This script is intended to be run by go generate.

export SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

command-exists() {
    command -v "$@" >/dev/null 2>&1
}

set -ex

rm -rf static/dashboard

export VERSION=$(git describe --tags --always --dirty)
pushd $SCRIPT_DIR
if command-exists winpty ; then
    yarn install </dev/tty
    yarn build </dev/tty
else
    yarn install
    yarn build
fi
popd

cp -r $SCRIPT_DIR/dist/spa static/dashboard
