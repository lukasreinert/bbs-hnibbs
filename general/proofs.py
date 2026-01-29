import hashlib
import subprocess
import time
from ecdsa import VerifyingKey
from general.dataclasses import *
from utils.bbs_hnibbs_utils import *


def key_verify(user_pubkey: PubKey, N: int) -> float:
    """
    Issuer: Verify the user's key-pair using the secure hardware's manufacturer-controlled attestation trust chain
    """
    start = time.time()
    res = subprocess.run(
        ["bash", "hsm_keyverify.sh"],
        capture_output=True,
        text=True,
        check=True
    )
    
    if not "Certificate chain and attestation request verified!" in res.stdout:
        raise ValueError("Key verification failed")

    end = time.time() - start
    return end

def proof_I_prove(pp: PublicParamsEC, issuer_keypair: Keypair) -> tuple[IProof, float]:
    """
    Issuer: Compute proof_I.
    """
    start = time.time()
    order = pp.order
    gt = pp.gt

    skI = issuer_keypair.sk
    pkIb = issuer_keypair.pubkey.pkb
    
    r = rand_scalar(order)
    com = gt * r
    comb = point_to_bytes(com)

    h = pp.prehash.copy()
    h.update(pkIb)
    h.update(comb)
    digest = int.from_bytes(h.digest(), "big")
    
    c = digest % order
    rho = (r + c * skI) % order
    proof_I = IProof(c, rho)

    end = time.time() - start
    
    return proof_I, end

def proof_I_verify(pp: PublicParamsEC, issuer_pubkey: PubKey, proof_I: IProof) -> float:
    """
    User: Verify proof_I.
    """
    start = time.time()
    order = pp.order
    gt = pp.gt

    pkI = issuer_pubkey.pk
    pkIb = issuer_pubkey.pkb
    c = proof_I.c
    rho = proof_I.rho

    com_check = gt * rho + pkI * (-c % order)
    com_checkb = point_to_bytes(com_check)

    h = pp.prehash.copy()
    h.update(pkIb)
    h.update(com_checkb)
    
    digest = int.from_bytes(h.digest(), "big")
    c_check = digest % order

    if c != c_check:
        raise ValueError("Invalid proof of knowledge: IProof")

    end = time.time() - start
    return end

def proof_dleq_prove(pp: PublicParamsEC, A: Point, B: Point, issuer_keypair: Keypair, context: bytes = b"") -> tuple[DLEQProof, float]:
    """
    Issuer: Compute proof_DLEQ.
    """
    start = time.time()
    order = pp.order
    gt = pp.gt
    gtb = pp.gtb

    skI = issuer_keypair.sk
    pkIb = issuer_keypair.pubkey.pkb
    
    r = rand_scalar(order)
    com1 = gt * r
    com2 = A * r
    
    Ab = point_to_bytes(A)
    Bb = point_to_bytes(B)
    com1b = point_to_bytes(com1)
    com2b = point_to_bytes(com2)

    h = pp.prehash.copy()
    h.update(Ab)
    h.update(Bb)
    h.update(gtb)
    h.update(pkIb)
    h.update(com1b)
    h.update(com2b)
    h.update(context)
    digest = int.from_bytes(h.digest(), "big")
    
    c = digest % order
    rho = (r + c * skI) % order
    proof_dleq = DLEQProof(c, rho)

    end = time.time() - start
    
    return proof_dleq, end

def proof_dleq_verify(pp: PublicParamsEC, A: Point, B: Point, issuer_pubkey: PubKey, proof_dleq: DLEQProof, context: bytes = b"") -> float:
    """
    User: Verify proof_DLEQ.
    """
    start = time.time()
    order = pp.order
    gt = pp.gt
    gtb = pp.gtb

    pkI = issuer_pubkey.pk
    pkIb = issuer_pubkey.pkb
    c = proof_dleq.c
    rho = proof_dleq.rho

    com1_check = gt * rho + pkI * (-c % order)
    com2_check = A * rho + B * (-c % order)
    
    Ab = point_to_bytes(A)
    Bb = point_to_bytes(B)
    com1_checkb = point_to_bytes(com1_check)
    com2_checkb = point_to_bytes(com2_check)

    h = pp.prehash.copy()
    h.update(Ab)
    h.update(Bb)
    h.update(gtb)
    h.update(pkIb)
    h.update(com1_checkb)
    h.update(com2_checkb)
    h.update(context)
    
    digest = int.from_bytes(h.digest(), "big")
    c_check = digest % order

    if c != c_check:
        raise ValueError("Invalid proof of knowledge: DLEQProof")

    end = time.time() - start
    return end

def proof_hb_prove(pp: PublicParamsEC, mu: bytes, r: int, user_pubkey_blind: PubKey, context: bytes = b"") -> tuple[HBProof, float]:
    """
    User: Compute proof_hb.
    """
    start = time.time()
    order = pp.order

    pk_blindb = user_pubkey_blind.pkb

    # Compute M = r^(-1) * H(mu || context || pk_blind)
    h = hashlib.sha256()
    h.update(mu + context)
    h.update(pk_blindb)
    digest = int.from_bytes(h.digest(), "big")
    M = pow(r, -1, order) * digest % order
    Mb = M.to_bytes(32, byteorder="big")
    with open("output/message.bin", "wb") as f:
        f.write(Mb)

    # Sign M
    subprocess.run(
        ["bash", "hsm_sign.sh"],
        capture_output=True,
        text=True,
        check=True
    )

    # Read and blind signature
    with open("output/signature.bin", "rb") as f:
        sig_raw = f.read()

    xb = sig_raw[:32]
    rhob = sig_raw[32:]
    rho = int.from_bytes(rhob, "big") % order
    
    x = int.from_bytes(xb, "big") % order
    rho_blind = (rho * r) % order
    proof_hb = HBProof(x, rho_blind)

    end = time.time() - start
    
    return proof_hb, end

def proof_hb_verify(pp: PublicParamsEC, user_pubkey_blind: PubKey, proof_hb: HBProof, mu: bytes, context: bytes = b"") -> float:
    """
    Issuer: Verify proof_hb.
    """
    start = time.time()
    curve = pp.curve
    order = pp.order

    pk_blind = user_pubkey_blind.pk
    pk_blindb = user_pubkey_blind.pkb

    # Compute M' = H(mu || context || pk_blind)
    h = hashlib.sha256()
    h.update(mu + context)
    h.update(pk_blindb)
    digest = int.from_bytes(h.digest(), "big")

    M = digest % order
    Mb = M.to_bytes(32, byteorder="big")

    sig_blind = proof_hb.x.to_bytes(32, byteorder="big") + proof_hb.rho_blind.to_bytes(32, byteorder="big")

    vk = VerifyingKey.from_public_point(pk_blind, curve=curve)
    try:
        vk.verify_digest(sig_blind, Mb)
    except Exception:
        raise ValueError("Invalid proof of knowledge: HBProof")

    end = time.time() - start
    return end

def proof_validity_prove(pp: PublicParamsEC, A_blinded: Point, B_blinded: Point, D: Point, user_pubkey_blind: PubKey, e: int, r1: int, r2: int, r3: int, r: int, context: bytes = b"") -> tuple[ValidityProof, float]:
    """
    User: Compute proof_validity.
    """
    start = time.time()
    order = pp.order
    
    pk_blind = user_pubkey_blind.pk
    pk_blindb = user_pubkey_blind.pkb
    
    alpha = rand_scalar(order)
    beta = rand_scalar(order)
    gamma = rand_scalar(order)
    delta = rand_scalar(order)

    com1 = A_blinded * alpha + D * beta
    com2 = D * gamma + pk_blind * delta
    
    A_blindedb = point_to_bytes(A_blinded)
    B_blindedb = point_to_bytes(B_blinded)
    Db = point_to_bytes(D)
    com1b = point_to_bytes(com1)
    com2b = point_to_bytes(com2)

    h = pp.prehash.copy()
    h.update(A_blindedb)
    h.update(B_blindedb)
    h.update(Db)
    h.update(pk_blindb)
    h.update(com1b)
    h.update(com2b)
    h.update(context)
    
    digest = int.from_bytes(h.digest(), "big")
    c = digest % order

    rho1 = (alpha - c * e) % order
    rho2 = (beta + c * r1) % order
    rho3 = (gamma + c * r3) % order
    r_tilde = -pow(r, -1, order) % order
    rho4 = (delta + c * r_tilde) % order

    proof_validity = ValidityProof(c, rho1, rho2, rho3, rho4)

    end = time.time() - start

    return proof_validity, end

def proof_validity_verify(pp: PublicParamsEC, A_blind: Point, B_blind: Point, D: Point, user_pubkey_blind: PubKey, proof_validity: ValidityProof, context: bytes = b"") -> float:
    """
    Issuer: Verify proof_validity.
    """
    start = time.time()
    order = pp.order
    g0 = pp.g0

    pk_blind = user_pubkey_blind.pk
    pk_blindb = user_pubkey_blind.pkb

    c = proof_validity.c
    rho1 = proof_validity.rho1
    rho2 = proof_validity.rho2
    rho3 = proof_validity.rho3
    rho4 = proof_validity.rho4

    com_check1 = A_blind * rho1 + D * rho2 + B_blind * (-c % order)
    com_check2 = D * rho3 + pk_blind * rho4 + g0 * (-c % order)

    Ab = point_to_bytes(A_blind)
    Bb = point_to_bytes(B_blind)
    Db = point_to_bytes(D)
    com_check1b = point_to_bytes(com_check1)
    com_check2b = point_to_bytes(com_check2)

    h = pp.prehash.copy()
    h.update(Ab)
    h.update(Bb)
    h.update(Db)
    h.update(pk_blindb)
    h.update(com_check1b)
    h.update(com_check2b)
    h.update(context)
    
    digest = int.from_bytes(h.digest(), "big")
    c_check = digest % order

    if c != c_check:
        raise ValueError("Invalid proof of knowledge: ValidityProof")

    end = time.time() - start
    return end
