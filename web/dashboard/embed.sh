#!/bin/bash -ex

export SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export VERSION=$(git describe --tags --always --dirty)

rm -rf static/dashboard

pushd $SCRIPT_DIR
yarn ; yarn build
popd

cp -r $SCRIPT_DIR/dist/spa static/dashboard
