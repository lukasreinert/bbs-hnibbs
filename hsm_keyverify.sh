#!/bin/bash

# load config variables
source ./config.sh

echo "[*] Generating keypair"
$SCSH_PATH/scsh-bbs-hnibbs/keyverify.sh
