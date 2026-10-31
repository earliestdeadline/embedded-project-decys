#!/usr/bin/env bash

set -euo pipefail

KEY="${1:-key.der}"
SIGNATURE="${2:-signature.bin}"
RAINBOW_TABLE="${3:-rainbow_table.txt}"
TRANSCRIPT="target_transcript.txt"

echo "-------------- Target 5: c&c password recovery --------------" | tee "$TRANSCRIPT"
echo "Key:           $KEY"           | tee -a "$TRANSCRIPT"
echo "Signature:     $SIGNATURE"     | tee -a "$TRANSCRIPT"
echo "Rainbow table: $RAINBOW_TABLE" | tee -a "$TRANSCRIPT"
echo | tee -a "$TRANSCRIPT"

for f in "$KEY" "$SIGNATURE" "$RAINBOW_TABLE"; do
    if [[ ! -s "$f" ]]; then
        echo "ERROR: $f is missing or empty. Check you're pointing at the real target-4 files." >&2
        exit 1
    fi
done

echo "-------------- Key structure (asn1parse) --------------" | tee -a "$TRANSCRIPT"
ASN1=$(openssl asn1parse -inform DER -in "$KEY" 2>&1)
echo "$ASN1" | tee -a "$TRANSCRIPT"
echo | tee -a "$TRANSCRIPT"

N_FIELDS=$(echo "$ASN1" | grep -c "prim: INTEGER")
if [[ "$N_FIELDS" -ge 9 ]]; then
    echo "-> $N_FIELDS INTEGER fields: this is a PRIVATE key (RSAPrivateKey)." \
        | tee -a "$TRANSCRIPT"
    KEY_IS_PRIVATE=1
elif [[ "$N_FIELDS" -eq 2 ]]; then
    echo "-> $N_FIELDS INTEGER fields: this is a PUBLIC key (RSAPublicKey)." \
        | tee -a "$TRANSCRIPT"
    KEY_IS_PRIVATE=0
else
    echo "-> $N_FIELDS INTEGER fields: unexpected structure, inspect manually." \
        | tee -a "$TRANSCRIPT"
    KEY_IS_PRIVATE=0
fi
echo | tee -a "$TRANSCRIPT"

if [[ "$KEY_IS_PRIVATE" -ne 1 ]]; then
    echo "ERROR: expected a private key for the decrypt step below." >&2
    exit 1
fi

echo "------------- Decrypting signature.bin with private key --------------" | tee -a "$TRANSCRIPT"

decrypt_with() {
    local padding_opt="$1"
    local outfile="$2"
    if [[ -n "$padding_opt" ]]; then
        openssl pkeyutl -decrypt -inkey "$KEY" -keyform DER \
            -in "$SIGNATURE" -pkeyopt "$padding_opt" -out "$outfile" 2>>"$TRANSCRIPT"
    else
        openssl pkeyutl -decrypt -inkey "$KEY" -keyform DER \
            -in "$SIGNATURE" -out "$outfile" 2>>"$TRANSCRIPT"
    fi
}

DECRYPTED=""
if decrypt_with "" decrypted.bin; then
    echo "(used: PKCS#1 v1.5 padding — default)" | tee -a "$TRANSCRIPT"
    DECRYPTED="decrypted.bin"
elif decrypt_with "rsa_padding_mode:oaep" decrypted.bin; then
    echo "(used: OAEP padding)" | tee -a "$TRANSCRIPT"
    DECRYPTED="decrypted.bin"
elif decrypt_with "rsa_padding_mode:none" decrypted.bin; then
    echo "(used: no padding — raw, inspect manually)" | tee -a "$TRANSCRIPT"
    DECRYPTED="decrypted.bin"
else
    echo "ERROR: all decrypt attempts failed (PKCS#1v1.5, OAEP, raw)." >&2
    echo "key.der/signature.bin may be mismatched or from the wrong board." >&2
    exit 1
fi

echo | tee -a "$TRANSCRIPT"
echo "------------- Decrypted plaintext ------------" | tee -a "$TRANSCRIPT"
cat "$DECRYPTED" | tee -a "$TRANSCRIPT"
echo | tee -a "$TRANSCRIPT"

# --- Pull the MD5 out of the JSON {"hash": "<md5>"} ---
HASH_HEX=$(grep -o '"hash"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]\{32\}"' "$DECRYPTED" \
    | grep -o '[0-9a-fA-F]\{32\}' || true)

if [[ -z "$HASH_HEX" ]]; then
    echo "WARNING: couldn't auto-extract a 32-hex-char hash from the JSON." \
         "Inspect $DECRYPTED manually." | tee -a "$TRANSCRIPT"
    exit 1
fi

echo "$HASH_HEX" > recovered_hash.txt
echo "Recovered MD5: $HASH_HEX" | tee -a "$TRANSCRIPT"
echo | tee -a "$TRANSCRIPT"

echo "------------ Table lookup ------------" | tee -a "$TRANSCRIPT"
MATCH_LINE=$(awk -v h="$HASH_HEX" 'tolower($2) == tolower(h) { print; found=1 } END { if (!found) exit 1 }' "$RAINBOW_TABLE") || MATCH_LINE=""

if [[ -n "$MATCH_LINE" ]]; then
    FOUND=$(awk '{print $1}' <<< "$MATCH_LINE")
    echo "MATCH FOUND in rainbow table: $MATCH_LINE" | tee -a "$TRANSCRIPT"
    echo "c&c password = $FOUND" | tee -a "$TRANSCRIPT"
else
    echo "No match for hash $HASH_HEX in $RAINBOW_TABLE." | tee -a "$TRANSCRIPT"
    exit 1
fi