#!/bin/sh
# mimic_ca.sh - sign a device CSR with a local test CA (mimics a real CA).
#
#   $1  input CSR  (PEM, from `rsa csr`)
#   $2  output cert (PEM)
#
# Always writes BOTH the PEM ($2) and a DER alongside it (same name, .der), and
# prints md5sums so you can verify the file survived the copy to the device.
# `rsa write-cert` / `rsa verify-binding` want the .der.
#
# Usage (run on the host):
#   sh mimic_ca.sh device.csr device.cer
#     -> device.cer (PEM) + device.der (DER) + md5sums
#
# Env overrides: CA_DIR (default ./ca), DAYS (825), CN ("Test Device CA"), ORG.

set -e

CSR_IN=$1
CER_OUT=$2
if [ -z "$CSR_IN" ] || [ -z "$CER_OUT" ]; then
    echo "usage: $0 <input.csr> <output.cer>   (also writes <output>.der)" >&2
    exit 2
fi
if [ ! -f "$CSR_IN" ]; then
    echo "error: CSR not found: $CSR_IN" >&2
    exit 1
fi

CA_DIR=${CA_DIR:-./ca}
DAYS=${DAYS:-825}
CN=${CN:-Test Device CA}
ORG=${ORG:-TestCorp}

CA_KEY="$CA_DIR/ca.key"
CA_CRT="$CA_DIR/ca.crt"
CA_SRL="$CA_DIR/ca.srl"
DER_OUT="${CER_OUT%.*}.der"   # same base name, .der extension

mkdir -p "$CA_DIR"

# 1) Create the CA once, reuse it afterwards.
if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CRT" ]; then
    echo "[*] creating test CA in $CA_DIR"
    openssl genrsa -out "$CA_KEY" 4096 >/dev/null 2>&1
    openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
        -subj "/CN=$CN/O=$ORG" -out "$CA_CRT" >/dev/null 2>&1
else
    echo "[*] reusing CA in $CA_DIR"
fi

# 2) Verify the CSR's self-signature (proves the SE actually signed it).
if ! openssl req -in "$CSR_IN" -noout -verify >/dev/null 2>&1; then
    echo "error: CSR self-signature does not verify: $CSR_IN" >&2
    exit 1
fi

# 3) Leaf extensions: a TLS client-auth identity cert.
EXT=$(mktemp)
trap 'rm -f "$EXT"' EXIT
cat > "$EXT" <<'XEOF'
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
basicConstraints = critical, CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
XEOF

# Reuse the serial file after the first signing.
if [ -f "$CA_SRL" ]; then
    SERIAL="-CAserial $CA_SRL"
else
    SERIAL="-CAcreateserial"
fi

# 4) Sign -> PEM, then convert to DER.
openssl x509 -req -in "$CSR_IN" \
    -CA "$CA_CRT" -CAkey "$CA_KEY" $SERIAL \
    -days "$DAYS" -sha256 -extfile "$EXT" -out "$CER_OUT" >/dev/null 2>&1
openssl x509 -in "$CER_OUT" -outform DER -out "$DER_OUT"

# 5) Verify the chain.
openssl verify -CAfile "$CA_CRT" "$CER_OUT" >/dev/null

# 6) Report + checksums (compare these on the device after copying).
SUBJ=$(openssl x509 -in "$CER_OUT" -noout -subject | sed 's/^subject=//')
echo "[+] signed: $SUBJ"
echo "    PEM: $CER_OUT   (md5 $(md5sum "$CER_OUT" | cut -d' ' -f1))"
echo "    DER: $DER_OUT   (md5 $(md5sum "$DER_OUT" | cut -d' ' -f1))   <- use for write-cert/verify-binding"