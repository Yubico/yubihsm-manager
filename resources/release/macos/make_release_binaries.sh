#!/usr/bin/env bash
# Script to produce a MacOS release binaries

if [ "$#" -ne 4 ]; then
    echo "This script is a guide to build a .pkg installer. Output installer will be found in the directory this script is running from."
    echo ""
    echo "      Usage: ./make_release_binaries.sh <amd|arm> <RELEASE_VERSION> <LIBYUBIHSM_TAG> <SOURCE_DIRECTORY>"
    echo "";
    exit 0
fi

ARCH=$1 # amd or arm
RELEASE_VERSION=$2 # yubihsm-manager release version
LIBYUBIHSM_TAG=$3 # libyubihsm version tag to build static library from, e.g. 3.0.0
SOURCE_DIR=$4 #path to yubihsm-manager source code

echo "Architecture: $ARCH"
echo "Release version: $RELEASE_VERSION"
echo "libyubihsm version: $LIBYUBIHSM_TAG"
echo "Source directory: $SOURCE_DIR"

if [ "$ARCH" == "amd" ]; then
  export BREW_LIB="/usr/local/opt"
  #BREW_CELLAR="/usr/local/Cellar"
elif [ "$ARCH" == "arm" ]; then
  export BREW_LIB="/opt/homebrew/opt"
  #BREW_CELLAR="/opt/homebrew/Cellar"
else
  echo "Unknown architecture"
  exit
fi

WORKING_DIR=$PWD/temp_dir
mkdir -p "$WORKING_DIR"

# Install dependencies
brew update
brew install asciidoctor
brew reinstall openssl@3
OPENSSL_PREFIX=$(brew --prefix openssl@3)

export PATH=$PATH:~/.cargo/bin
if [[ ! -x $(command -v rustc) ]]; then
    curl -o rustup.sh https://sh.rustup.rs
    bash ./rustup.sh -y
fi

if [[ ! -x $(command -v asciidoctor) ]]; then
    export PATH=$PATH:/opt/brew/opt/bin
fi

cd "$WORKING_DIR"

# Build static libyubihsm
git clone --branch $LIBYUBIHSM_TAG https://github.com/Yubico/yubihsm-shell.git
#git clone https://github.com/Yubico/yubihsm-shell.git
cd yubihsm-shell
mkdir build; cd build
cmake -DRELEASE_BUILD=1 \
      -DBUILD_ONLY_LIB=ON \
      -DENABLE_STATIC=ON \
      -DENABLE_CERT_COMPRESS=OFF \
      -DLIBCRYPTO_LDFLAGS="$OPENSSL_PREFIX/lib/libcrypto.a" \
      -DLIBCRYPTO_INCLUDEDIR="$OPENSSL_PREFIX/include" \
      ..
make yubihsm_static
cd ..

# Build static curl
CURL_VERSION=8.11.1
curl -L https://curl.se/download/curl-${CURL_VERSION}.tar.gz | tar xz
cd curl-${CURL_VERSION}
./configure \
    --disable-shared --enable-static \
    --with-secure-transport \
    --without-libssh2 --without-brotli --without-libidn2 \
    --without-libpsl --without-nghttp2 \
    --without-zlib --without-zstd \
    --disable-ldap --disable-ldaps \
    --disable-manual --disable-docs \
    --prefix=$WORKING_DIR/curl-static
make -j$(sysctl -n hw.ncpu)
make install
cd ..

# Build static libusb
LIBUSB_VERSION=1.0.27
curl -L https://github.com/libusb/libusb/releases/download/v${LIBUSB_VERSION}/libusb-${LIBUSB_VERSION}.tar.bz2 | tar xj
cd libusb-${LIBUSB_VERSION}
./configure \
    --disable-shared --enable-static \
    --prefix=$WORKING_DIR/libusb-static
make -j$(sysctl -n hw.ncpu)
make install
cd ..

# Build yubihsm-manager
cd "$SOURCE_DIR"

CURL_LIB_DIR=$WORKING_DIR/curl-static/lib \
LIBUSB_LIB_DIR=$WORKING_DIR/libusb-static/lib \
YUBIHSM_STATIC=1 \
OPENSSL_STATIC=1 \
OPENSSL_DIR=$BREW_LIB/openssl@3 \
YUBIHSM_LIB_DIR=$WORKING_DIR/yubihsm-shell/build/lib \
cargo build --release

strip -u -r target/release/yubihsm-manager

rm -rf "$WORKING_DIR"