#!/usr/bin/env bash
# Script to produce a MacOS installer (.pkg)

# asciidoctor -o $PKG_RESOURCES/license.html $MAC_DIR/license.adoc

if [ "$#" -ne 2 ]; then
    echo "This script is a guide to build a .pkg installer. Output installer will be found in the directory this script is running from."
    echo ""
    echo "      Usage: ./make_installer.sh <RELEASE_VERSION> <BINARIES DIRECTORY>"
    echo "";
    exit 0
fi

set -e -o pipefail

RELEASE_VERSION=$1
SRC_DIR=$2 #path to unsigned binaries structured /usr/local/...

echo "Release version: $RELEASE_VERSION"
echo "Binaries: $SRC_DIR"
echo "Working directory: $PWD"

read -p "Press Enter to continue"

MAC_DIR=$PWD
PKG_DIR=$MAC_DIR/pkg

mkdir -p $PKG_DIR/root $PKG_DIR/comp $PKG_DIR/resources
cp -av $SRC_DIR $PKG_DIR/root/

echo ""
echo "DO NOW: Update data inside distribution.xml if necessary"
read -p "Press Enter to continue"

echo ""
echo "===================== Make binaries executable ====================="

chmod 755 $PKG_DIR/root/usr/local/bin/yubihsm-manager

# ── Verify paths are correct (read-only, no modifications needed) ──
echo ""
echo "===================== Verify binary paths ====================="

echo "--- $PKG_DIR/root/usr/local/bin/yubihsm-manager ---"
otool -L $PKG_DIR/root/usr/local/bin/yubihsm-manager
otool -l $PKG_DIR/root/usr/local/bin/yubihsm-manager | grep LC_RPATH -A 3

echo ""
echo "===================== Sign binaries ====================="
read -p "DO NOW: Insert signing key then press Enter to continue"

codesign -f --timestamp --options runtime --sign 'Application' $PKG_DIR/root/usr/local/bin/yubihsm-manager

echo ""
echo "DO NOW: Remove signing key"
read -p "Press Enter to continue"

echo ""
echo "===================== Verify signature ====================="

codesign -dv --verbose=4 $PKG_DIR/root/usr/local/bin/yubihsm-manager

echo ""
echo "===================== Make installer ====================="
cd $MAC_DIR

mkdir -p $PKG_DIR/resources/English.lproj
asciidoctor -o $PKG_DIR/resources/English.lproj/license.html license.adoc

pkgbuild --root=$PKG_DIR/root --identifier "com.yubico.yubihsm-manager" $PKG_DIR/comp/yubihsm-manager.pkg
productbuild  --package-path $PKG_DIR/comp --distribution distribution.xml --resources $PKG_DIR/resources yubihsm-manager-$RELEASE_VERSION-mac-universal.pkg

read -p "DO NOW: Insert signing key then press Enter to continue"
productsign --sign 'Installer' yubihsm-manager-$RELEASE_VERSION-mac-universal.pkg yubihsm-manager-$RELEASE_VERSION-mac-universal-signed.pkg
echo ""
echo "DO NOW: Remove signing key"
read -p "Press Enter to continue"
echo ""
echo "ALL DONE!!"