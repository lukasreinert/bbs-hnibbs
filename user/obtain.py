from general.proofs import *
from general.dataclasses import *

def obtain(pp: PublicParamsEC, user_pubkey: PubKey, A: Point, e: int, mu: bytes) -> tuple[PubKey, HBProof, Point, Point, Point, ValidityProof, float, float, float, float, float]:
    """
    User: Generate a signature on message mu.
    """
    start_obt = time.time()
    
    order = pp.order
    g0 = pp.g0

    pk = user_pubkey.pk

    # Blind pubkey
    start_pk_blind = time.time()
    r = rand_scalar(order)
    pk_blind = PubKey(pk * r)
    dur_pk_blind = time.time() - start_pk_blind

    # Randomize pre-signature
    start_sigma_blind = time.time()
    r1 = rand_scalar(order)
    r2 = rand_scalar(order)
    r3 = pow(r2, -1, order)

    A_blinded = A * (r1 * r2 % order)

    C = g0 + pk
    D = C * r2

    B_blinded = A_blinded * (-e % order) + D * r1
    
    dur_sigma_blind = time.time() - start_sigma_blind

    proof_hb, dur_proof_hb_gen = proof_hb_prove(pp, mu, r, pk_blind)
    proof_validity, dur_proof_validity_gen = proof_validity_prove(pp, A_blinded, B_blinded, D, pk_blind, e, r1, r2, r3, r)
    dur_obt = time.time() - start_obt

    return pk_blind, proof_hb, A_blinded, B_blinded, D, proof_validity, dur_pk_blind, dur_sigma_blind, dur_obt, dur_proof_hb_gen, dur_proof_validity_gen