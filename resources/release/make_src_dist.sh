#!/bin/bash
# Script to produce the source distribution package



if [ "$#" -lt 1 ]; then
    echo "This script produces a source distribution package"
    echo ""
    echo "      Usage: ./resources/release/make_srd_dist.sh <version>"
    echo "";
    exit 0
fi

VERSION=$1 # Full yubihsm-manager version, tex 2.1.0

set +e
set -x

tar --exclude .git        \
    --exclude .github     \
    --exclude .gitignore  \
    --exclude resources   \
    --transform="s/^\./yubihsm-manager-$VERSION/" -czf ../yubihsm-manager-$VERSION.tar.gz .


exitcode=$?
if [ "$exitcode" != "1" ] && [ "$exitcode" != "0" ]; then
    exit $exitcode
fi

set -e