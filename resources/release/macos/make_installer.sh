#!/usr/bin/env bash
# Script to produce a MacOS installer (.pkg)

# asciidoctor -o $PKG_RESOURCES/license.html $MAC_DIR/license.adoc

if [ "$#" -ne 4 ]; then
    echo "This script is a guide to build a .pkg installer. Output installer will be found in the directory this script is running from."
    echo ""
    echo "      Usage: ./make_installer.sh <LIBYUBIHSM SO VERSION> <LIBYUBIHSM VERSION> <RELEASE_VERSION> <BINARIES DIRECTORY>"
    echo "";
    exit 0
fi

set -e -o pipefail

LIBYUBIHSM_SO_VERSION=$1
LIBYUBIHSM_VERSION=$2
RELEASE_VERSION=$3
SRC_DIR=$4 #path to unsigned binaries structured /usr/local/...

echo "libyubihsm version: $LIBYUBIHSM_VERSION"
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
chmod 755 $PKG_DIR/root/usr/local/lib/*

# ── Verify paths are correct (read-only, no modifications needed) ──
echo ""
echo "===================== Verify binary paths ====================="

echo "--- $PKG_DIR/root/usr/local/bin/yubihsm-manager ---"
otool -L $PKG_DIR/root/usr/local/bin/yubihsm-manager
otool -l $PKG_DIR/root/usr/local/bin/yubihsm-manager | grep LC_RPATH -A 3

for f in $PKG_DIR/root/usr/local/lib/*.dylib; do
  echo "--- $f ---"
  otool -L "$f"
  echo ""
  read -p "Press Enter to continue"
done
read -p "If paths are correct, press Enter to continue"


echo ""
echo "===================== Sign binaries ====================="
read -p "DO NOW: Insert signing key then press Enter to continue"
for f in $PKG_DIR/root/usr/local/bin/yubihsm-manager $PKG_DIR/root/usr/local/lib/*.dylib; do
  echo "--- codesign $f ---"
  codesign -f --timestamp --options runtime --sign 'Application' $f
done

echo ""
echo "DO NOW: Remove signing key"
read -p "Press Enter to continue"

echo ""
echo "===================== Verify signature ====================="
for f in $PKG_DIR/root/usr/local/bin/yubihsm-manager $PKG_DIR/root/usr/local/lib/*.dylib; do
  echo "--- codesign $f ---"
  codesign -dv --verbose=4 $f
  read -p "Press Enter to continue"
done

echo ""
echo "===================== Fixing symbolic links ====================="
cd $PKG_DIR/root/usr/local/lib
ln -s libyubihsm.$LIBYUBIHSM_VERSION.dylib libyubihsm.$LIBYUBIHSM_SO_VERSION.dylib
ln -s libyubihsm.$LIBYUBIHSM_SO_VERSION.dylib libyubihsm.dylib
ln -s libyubihsm_http.$LIBYUBIHSM_VERSION.dylib libyubihsm_http.$LIBYUBIHSM_SO_VERSION.dylib
ln -s libyubihsm_http.$LIBYUBIHSM_SO_VERSION.dylib libyubihsm_http.dylib
ln -s libyubihsm_usb.$LIBYUBIHSM_VERSION.dylib libyubihsm_usb.$LIBYUBIHSM_SO_VERSION.dylib
ln -s libyubihsm_usb.$LIBYUBIHSM_SO_VERSION.dylib libyubihsm_usb.dylib

ls -l $PKG_DIR/root/usr/local/lib

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