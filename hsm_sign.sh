#!/bin/bash

# load config variables
source ./config.sh

# validate required arguments
if [[ -z "$LABEL" ]]; then
    echo "Error: label is required"
    exit 1
fi

if [[ -z "$USER_PIN" ]]; then
    echo "Error: userpin is required"
    exit 1
fi

# extract key ID for the given label
echo "[*] Extracting key ID for label '$LABEL'"
KEY_ID=$(pkcs11-tool --module "$MODULE" --login --pin "$USER_PIN" --list-objects --type pubkey --verbose | awk -v label="$LABEL" '
    /Public Key Object/ { in_block = 0 }
    $1 == "label:" && $2 == label { in_block = 1 }
    in_block && $1 == "ID:" { print $2; exit 0 }
')

# sign the message
echo "[*] Signing message"
pkcs11-tool \
    --module "$MODULE" \
    --login --pin "$USER_PIN" \
    --sign --mechanism "ECDSA" \
    --type privkey \
    --input-file ./output/"$MESSAGE_FILE" \
    --output-file ./output/"$SIGNATURE_FILE" \
    --id "$KEY_ID"
