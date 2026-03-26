#!/bin/bash

TEST_DIR="test_data"
mkdir -p $TEST_DIR

# RSA 2048 private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $TEST_DIR/rsa2048_private.pem 2>/dev/null

# RSA 2048 public key
openssl pkey -in $TEST_DIR/rsa2048_private.pem -pubout -out $TEST_DIR/rsa2048_public.pem 2>/dev/null

# EC P256 private key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $TEST_DIR/ecp256_private.pem 2>/dev/null

# EC P256 public key
openssl pkey -in $TEST_DIR/ecp256_private.pem -pubout -out $TEST_DIR/ecp256_public.pem 2>/dev/null

# EC P384 public key (for negative tests)
mkdir $TEST_DIR/tmp
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out $TEST_DIR/tmp/ecp384_priv.pem 2>/dev/null
openssl pkey -in $TEST_DIR/tmp/ecp384_priv.pem -pubout -out $TEST_DIR/ecp384_public.pem 2>/dev/null
rm $TEST_DIR/tmp/ecp384_priv.pem
rmdir $TEST_DIR/tmp

# Self-signed X509 certificate (using the EC P256 key)
openssl req -new -x509 -key $TEST_DIR/ecp256_private.pem -out $TEST_DIR/x509_cert.pem -days 365 -subj "/CN=Test" 2>/dev/null

# SunPKCS11 combo file: private key + cert
cat $TEST_DIR/ecp256_private.pem $TEST_DIR/x509_cert.pem > $TEST_DIR/sunpkcs11_combo.pem

WD=$(pwd)
echo "Test data generated in $WD/$TEST_DIR"