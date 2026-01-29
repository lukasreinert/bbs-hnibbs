import subprocess
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from general.dataclasses import *
from general.proofs import *
from utils.bbs_hnibbs_utils import *


def userKeyGen(pp: PublicParamsEC, N: int) -> tuple[PubKey, float]:
    """
    User: Generate a keypair.
    """
    start_user_keygen = time.time()
    
    curve = pp.curve
    subprocess.run(
        ["bash", "hsm_keygen.sh", "--kuc", str(N)],
        capture_output=True,
        text=True,
        check=True
    )

    with open("./output/BBS-HNIBBS.pem", "rb") as f:
        pub_pem = f.read()

    pub_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())

    pub_numbers = pub_key.public_numbers()
    x = pub_numbers.x
    y = pub_numbers.y

    pk = PubKey(Point(curve.curve, x, y))
    
    dur_user_keygen = time.time() - start_user_keygen

    return pk, dur_user_keygen