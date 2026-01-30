# BBS#-HNIBBS

**BBS#-HNIBBS** is a Python prototype implementation for my bachelor thesis [Hardware-Assisted Batching for (Non-Interactive) Anonymous Tokens](https://lukasreinert.de/bachelor_thesis.pdf), designed to interact with a `SmartCard-HSM`.

This project was developed on **Arch Linux** (Kernel `6.18.6-arch1-1`) with **Python 3.14.2**.  
It was tested using the **SmartCard-HSM 4K USB-Token**.

---

## Requirements

- Python 3.14+
- pip
- SmartCard-HSM 4K USB-Token (or compatible HSM)
- `opensc` and `pcsclite` for smart card communication
- Smart Card Shell (SCSH) version 3.18.61 or newer

---

## Setup

1. **Install Python dependencies**

    ```bash
    pip install -r requirements.txt
    ```

2. **Install system packages and start the PC/SC daemon**

    ```bash
    sudo pacman -S pcsclite opensc
    sudo systemctl enable --now pcscd
    ```

3. **Download Smart Card Shell (SCSH)**

    Download SCSH from [https://www.openscdp.org/scsh3/download.html](https://www.openscdp.org/scsh3/download.html).  
    Development was done with version `3.18.61`.

4. **Copy repository scripts into SCSH folder**

    Copy the folder `scsh-bbs-hnibbs/` from this repository into the SCSH installation folder that contains the Smart Card Shell executable `scsh3`.

---

## Configuration

Edit the `config.sh` file and set the following variables:

```bash
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
```

---

## Attribution

The scripts `scsh-bbs-hnibbs/ec.js` and `scsh-bbs-hnibbs/keyverify.js`
are based on example SmartCard-HSM scripts by CardContact Software
& System Consulting (Andreas Schwier, [www.cardcontact.de](https://www.cardcontact.de)). All code
here is adapted or written by the author.
