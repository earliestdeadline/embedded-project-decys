#!/usr/bin/env bash
set -euo pipefail

KEY="${1:-key.der}"
SIGNATURE="${2:-signature.bin}"
RAINBOW_TABLE="${3:-rainbow_table.txt}"
TRANSCRIPT="target_transcript.txt"

for f in "$KEY" "$SIGNATURE" "$RAINBOW_TABLE"; do
    [[ -s "$f" ]] || { echo "ERROR: $f is missing or empty." >&2; exit 1; }
done

{
    echo "-------------- Target 5: c&c password recovery --------------"
    echo "Key: $KEY | Signature: $SIGNATURE | Rainbow table: $RAINBOW_TABLE"
    echo

    echo "-------------- Decrypting signature with private key --------------"
    openssl pkeyutl -decrypt -inkey "$KEY" -keyform DER -in "$SIGNATURE" -out decrypted.bin
    cat decrypted.bin
    echo
} | tee "$TRANSCRIPT"

HASH_HEX=$(grep -o '"hash"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]\{32\}"' decrypted.bin \
    | grep -o '[0-9a-fA-F]\{32\}')
echo "$HASH_HEX" > recovered_hash.txt
echo "Recovered MD5: $HASH_HEX" | tee -a "$TRANSCRIPT"

MATCH_LINE=$(awk -v h="$HASH_HEX" 'tolower($2)==tolower(h){print; exit}' "$RAINBOW_TABLE")
echo "$MATCH_LINE" | tee -a "$TRANSCRIPT"
echo "c&c password = $(awk '{print $1}' <<< "$MATCH_LINE")" | tee -a "$TRANSCRIPT"
