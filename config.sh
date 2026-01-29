# Label of the key
LABEL="BBS-HNIBBS"

# Used elliptic curve
CURVE="secp256r1"

# Key-use-counter (0 to disable)
KUC="30"

# User PIN of the SmartCard-HSM
USER_PIN="123456"

# Path (absolute or relative from this repository) to the SCSH folder containing the Smart Card Shell "scsh3"
SCSH_PATH="../../scsh-3.18.61/"

# Path (absolute) to the opensc-pkcs11.so module
MODULE="/usr/lib/opensc-pkcs11.so"

# Name of the binary message file
MESSAGE_FILE="message.bin"

# Name of the binary signature file
SIGNATURE_FILE="signature.bin"