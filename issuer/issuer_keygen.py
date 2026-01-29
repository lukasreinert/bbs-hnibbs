import time
from general.dataclasses import *
from general.proofs import *
from utils.bbs_hnibbs_utils import *


def issKeyGen(pp: PublicParamsEC) -> tuple[Keypair, IProof, float, float]:
    """
    Issuer: Generate a keypair with a ZKPK proof_I.
    """
    start_iss_keygen = time.time()
    
    order = pp.order
    gt = pp.gt
    
    skI = rand_scalar(order)
    pkI = gt * skI
    keypair = Keypair(skI, PubKey(pkI))
    
    proof_I, dur_proof_I_gen = proof_I_prove(pp, keypair)
    
    dur_iss_keygen = time.time() - start_iss_keygen

    return keypair, proof_I, dur_iss_keygen, dur_proof_I_gen