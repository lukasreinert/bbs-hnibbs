#!/bin/bash

# load config variables
source ./config.sh

# parse flags and arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kuc)
            if [[ -n "$2" && "$2" =~ ^[1-9][0-9]*$ ]]; then
                KUC="$2"
                shift 2
            else
                echo "Error: --kuc requires a positive integer (e.g., 30)"
                exit 1
            fi
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# validate required arguments
if [[ -z "$LABEL" ]]; then
    echo "Error: label is required"
    exit 1
fi

if [[ -z "$CURVE" ]]; then
    echo "Error: curve is required"
    exit 1
fi

if [[ -z "$USER_PIN" ]]; then
    echo "Error: userpin is required"
    exit 1
fi

# generate RSA2048KUC keypair
if $DO_GEN; then
    echo "[*] Generating keypair"
    $SCSH_PATH/scsh-bbs-hnibbs/ec.sh "$LABEL" "$CURVE" "$KUC" "$USER_PIN"
fi

# export public key
echo "[*] Exporting public key"
mkdir -p ./output
pkcs11-tool \
    --module "$MODULE" \
    --login --pin "$USER_PIN" \
    --read-object \
    --label "$LABEL" \
    --type pubkey > ./output/"$LABEL".der

# convert public key to PEM
echo "[*] Converting public key to PEM"
openssl ec -pubin -inform DER -in ./output/"$LABEL".der -out ./output/"$LABEL".pem