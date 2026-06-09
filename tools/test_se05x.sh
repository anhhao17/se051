#!/bin/sh
# Smoke test for se05x_crypto_app on embedded target.
# Env vars EX_SSS_BOOT_SSS_PORT and EX_SSS_BOOT_SCP03_PATH are read by the app
# directly, so no --port flag is needed.
#
# Usage:
#   sh /customer/test_se05x.sh

APP=${APP:-/customer/se05x_crypto_app}
TESTDIR=/customer/test_xx

rm -rf "$TESTDIR"
mkdir -p "$TESTDIR"

pass=0
fail=0

ok() {
    echo "[PASS] $*"
    pass=$((pass + 1))
}

fail() {
    echo "[FAIL] $*"
    fail=$((fail + 1))
}

run() {
    label=$1; shift
    err=$("$APP" "$@" 2>&1 >/dev/null)
    if [ $? -eq 0 ]; then
        ok "$label"
    else
        fail "$label"
        echo "       >> $err"
    fi
}

echo "=== se05x_crypto_app smoke test ==="
echo "APP:    $APP"
echo "PORT:   $EX_SSS_BOOT_SSS_PORT"
echo "SCP03:  $EX_SSS_BOOT_SCP03_PATH"
echo "TMPDIR: $TESTDIR"
echo

echo "--- connectivity check ---"
if ! "$APP" se uid 2>&1; then
    echo "[ERROR] se uid failed above - fix SE connection before running tests"
    exit 1
fi
echo

run "rng 16"   rng 16
run "rng 32"   rng 32
run "rng 1"    rng 1

run "se uid"   se uid

run "rsa genkey"                   rsa genkey
run "rsa genkey --force (regen)"   rsa genkey --force
run "rsa genkey idempotent"        rsa genkey          # no --force: exits 0, no-op

run "rsa pub DER"   rsa pub --out "$TESTDIR/pub.der"
run "rsa pub PEM"   rsa pub --out "$TESTDIR/pub.pem" --pem

if grep -q "BEGIN PUBLIC KEY" "$TESTDIR/pub.pem" 2>/dev/null; then
    ok "rsa pub PEM header valid"
else
    fail "rsa pub PEM header missing"
fi

echo "test payload for signing" > "$TESTDIR/msg.txt"

run "rsa sign"       rsa sign   --in "$TESTDIR/msg.txt" --out "$TESTDIR/msg.sig"
run "rsa verify OK"  rsa verify --in "$TESTDIR/msg.txt" --sig "$TESTDIR/msg.sig"

echo "tampered content" > "$TESTDIR/msg_bad.txt"
if "$APP" rsa verify --in "$TESTDIR/msg_bad.txt" --sig "$TESTDIR/msg.sig" >/dev/null 2>&1; then
    fail "rsa verify should reject tampered message"
else
    ok "rsa verify rejects tampered message"
fi

echo "secret data 12345" > "$TESTDIR/plain.txt"

run "rsa encrypt"    rsa encrypt --in "$TESTDIR/plain.txt"      --out "$TESTDIR/cipher.bin"
run "rsa decrypt"    rsa decrypt --in "$TESTDIR/cipher.bin"     --out "$TESTDIR/plain_dec.txt"

if cmp -s "$TESTDIR/plain.txt" "$TESTDIR/plain_dec.txt" 2>/dev/null; then
    ok "rsa encrypt/decrypt round-trip"
else
    fail "rsa encrypt/decrypt round-trip mismatch"
fi

run "rsa csr" \
    rsa csr --subject "CN=device-test,O=TestCorp" --out "$TESTDIR/device.csr" 

if grep -q "BEGIN CERTIFICATE REQUEST" "$TESTDIR/device.csr" 2>/dev/null; then
    ok "rsa csr PEM header valid"
else
    fail "rsa csr PEM header missing"
fi

if [ -f "$TESTDIR/device.csr" ] && command -v openssl >/dev/null 2>&1; then
    openssl x509 -req -in "$TESTDIR/device.csr" \
        -signkey "$TESTDIR/pub.pem" \
        -out "$TESTDIR/leaf.pem" -days 1 2>/dev/null &&
    openssl x509 -in "$TESTDIR/leaf.pem" -outform DER \
        -out "$TESTDIR/leaf.der" 2>/dev/null || true

    if [ -f "$TESTDIR/leaf.der" ]; then
        run "rsa write-cert"              rsa write-cert     --in   "$TESTDIR/leaf.der"
        run "rsa write-cert idempotent"   rsa write-cert     --in   "$TESTDIR/leaf.der"
        run "rsa verify-binding"          rsa verify-binding --cert "$TESTDIR/leaf.der"
    else
        echo "[SKIP] write-cert/verify-binding: cert gen failed (no private key for self-sign)"
    fi
else
    echo "[SKIP] write-cert/verify-binding: openssl not available"
fi

MASTER=000102030405060708090a0b0c0d0e0f
echo "--- se rotate-scp03 --dry-run ---"
if "$APP" se rotate-scp03 --master-key "$MASTER" --dry-run; then
    ok "se rotate-scp03 --dry-run"
else
    fail "se rotate-scp03 --dry-run"
fi

echo
echo "=== Results: $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
