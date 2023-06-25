#!/bin/bash

# This script is intended to be run by go generate.

export SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

set -ex

rm -rf static/dashboard

pushd $SCRIPT_DIR
yarn
VERSION=$(git describe --tags --always --dirty) yarn build
popd

cp -r $SCRIPT_DIR/dist/spa static/dashboard
