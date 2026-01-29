from general.dataclasses import *
from general.proofs import *


def issue(pp: PublicParamsEC, issuer_keypair: Keypair, user_pubkey: PubKey) -> tuple[Point, Point, int, DLEQProof, float, float]:
    """
    Issuer: Issue a BBS#-HNIBBS pre-signature.
    """
    start_iss = time.time()
    
    order = pp.order
    g0 = pp.g0
    
    skI = issuer_keypair.sk
    pk = user_pubkey.pk

    e = rand_scalar(order)
    C = g0 + pk
    exp = pow((skI + e) % order, -1, order)
    
    A = C * exp
    B = C + A * (-e % order)

    proof_dleq, dur_proof_dleq_gen = proof_dleq_prove(pp, A, B, issuer_keypair)

    dur_iss = time.time() - start_iss

    return A, B, e, proof_dleq, dur_iss, dur_proof_dleq_gen