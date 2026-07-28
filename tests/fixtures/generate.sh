#!/bin/bash
#
# Regenerate the golden and PKI test fixtures with OpenSSL.
#
# These fixtures are deliberately produced by an independent implementation. If
# `keystone-pki` and this script ever disagree about how to encode a certificate,
# a test fails rather than both sides being wrong in the same way.
#
# Every certificate has a pinned serial number and a pinned validity window, so
# the fixtures do not depend on the day they were generated and the golden
# signing artifacts stay stable. `GOLDEN_TIMESTAMP` in
# `tests/golden/create_session.rs` sits inside every window that is meant to be
# valid.
#
# The issuing CA private keys are removed at the end, mirroring the ephemeral CA
# the design specifies: nothing in the repository can mint a new certificate for
# an arbitrary key. Re-run this script to change the fixture set.
#
# Usage: tests/fixtures/generate.sh

set -euo pipefail

cd "$(dirname "$0")"

# The device key ID that appears in the URI SAN. Fixed, because IAM policies in
# the golden expectations condition on it.
KEY_ID="0f1e2d3c4b5a69788796a5b4c3d2e1f0"
SAN="urn:keystone:device:${KEY_ID}"

# Serials are chosen to exercise the decimal conversion in the `Credential=`
# field: large enough to need more than 32 bits, and not round in either base.
CA_SERIAL=20260101000000001
LEAF_SERIAL=88664422113355779
OTHER_CA_SERIAL=20260101000000002
OTHER_LEAF_SERIAL=17771177711777177

NOT_BEFORE=20260101000000Z
NOT_AFTER_CA=20360101000000Z
NOT_AFTER_LEAF=20310101000000Z
# An expired leaf, for the validity-window rejection test.
EXPIRED_NOT_BEFORE=20260101000000Z
EXPIRED_NOT_AFTER=20260201000000Z

cat > openssl.cnf <<EOF
[req]
distinguished_name = dn
prompt = no

[dn]
CN = keystone-golden-device

[ca_ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash

[leaf_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = URI:${SAN}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[leaf_ext_no_san]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

p256_key() {
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null
}

# The device key. This one stays: the golden tests sign with it, and the official
# AWS helper can load the same PKCS#8 file, which is what makes a differential
# comparison possible.
p256_key device-key.pem
# A second device key, for the "certificate names another key" rejection.
p256_key other-device-key.pem

p256_key ca-key.tmp
p256_key other-ca-key.tmp

self_signed_ca() {
    local key="$1" out="$2" cn="$3" serial="$4"
    openssl req -new -key "$key" -out "${out}.csr" -config openssl.cnf -subj "/CN=${cn}"
    openssl x509 -req -in "${out}.csr" -signkey "$key" -out "$out" \
        -extfile openssl.cnf -extensions ca_ext \
        -set_serial "$serial" -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER_CA" 2>/dev/null
    command rm -f "${out}.csr"
}

issue() {
    local ca="$1" ca_key="$2" device_key="$3" out="$4" cn="$5" serial="$6" \
        not_before="$7" not_after="$8" extension="$9"
    openssl req -new -key "$device_key" -out "${out}.csr" -config openssl.cnf -subj "/CN=${cn}"
    openssl x509 -req -in "${out}.csr" -CA "$ca" -CAkey "$ca_key" -out "$out" \
        -extfile openssl.cnf -extensions "$extension" \
        -set_serial "$serial" -not_before "$not_before" -not_after "$not_after" 2>/dev/null
    command rm -f "${out}.csr"
}

self_signed_ca ca-key.tmp ca.pem "Keystone Ephemeral CA 0f1e2d3c4b5a6978" "$CA_SERIAL"
self_signed_ca other-ca-key.tmp other-ca.pem "Keystone Ephemeral CA aaaabbbbccccdddd" "$OTHER_CA_SERIAL"

# The golden leaf: valid, correct SAN, matches device-key.pem.
issue ca.pem ca-key.tmp device-key.pem device.pem \
    keystone-golden-device "$LEAF_SERIAL" "$NOT_BEFORE" "$NOT_AFTER_LEAF" leaf_ext

# Expired: everything else correct.
issue ca.pem ca-key.tmp device-key.pem device-expired.pem \
    keystone-golden-device 88664422113355780 "$EXPIRED_NOT_BEFORE" "$EXPIRED_NOT_AFTER" leaf_ext

# No URI SAN: the certificate cannot identify a device.
issue ca.pem ca-key.tmp device-key.pem device-no-san.pem \
    keystone-golden-device 88664422113355781 "$NOT_BEFORE" "$NOT_AFTER_LEAF" leaf_ext_no_san

# The right SAN over the wrong key: signed by the trusted CA, so only the
# public-key comparison catches it.
issue ca.pem ca-key.tmp other-device-key.pem device-other-key.pem \
    keystone-golden-device 88664422113355782 "$NOT_BEFORE" "$NOT_AFTER_LEAF" leaf_ext

# The right key under a CA that is not the trust anchor.
issue other-ca.pem other-ca-key.tmp device-key.pem device-other-ca.pem \
    keystone-golden-device "$OTHER_LEAF_SERIAL" "$NOT_BEFORE" "$NOT_AFTER_LEAF" leaf_ext

# Cross-check with OpenSSL's own verifier before publishing the fixtures.
openssl verify -CAfile ca.pem device.pem >/dev/null
openssl verify -CAfile other-ca.pem device-other-ca.pem >/dev/null
if openssl verify -CAfile ca.pem device-other-ca.pem >/dev/null 2>&1; then
    echo "fixture error: a leaf from the other CA verified against ca.pem" >&2
    exit 1
fi

# The CA keys never survive generation. See the module comment.
command rm -f ca-key.tmp other-ca-key.tmp openssl.cnf

echo "fixtures regenerated:"
for pem in *.pem; do
    printf '  %-24s %s\n' "$pem" "$(openssl x509 -in "$pem" -noout -subject 2>/dev/null || echo 'private key')"
done
