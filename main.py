import os
import statistics
import time
from collections import defaultdict
from general.setup import *
from issuer.issue import *
from issuer.issuer_keygen import *
from user.obtain import *
from user.user_keygen import *


if __name__ == "__main__":
    ITERATIONS = 1000
    durations = defaultdict(list)

    for i in range(ITERATIONS):
        print(f"Iteration {i+1}")
        start_total = time.time()
        
        # Definitions
        N = 30
        user = User()
        issuer = Issuer()

        # Setup
        pp, dur_setup = setup()
        durations["setup"].append(dur_setup)

        # Issuer: Key generation
        issuer.keypair, issuer.proof_I, dur_iss_keygen, dur_proof_I_gen = issKeyGen(pp)
        durations["iss_keygen"].append(dur_iss_keygen)
        durations["proof_I_gen"].append(dur_proof_I_gen)

        # User: Verify proof_I
        dur_proof_I_ver = proof_I_verify(pp, issuer.keypair.pubkey, issuer.proof_I)
        durations["proof_I_ver"].append(dur_proof_I_ver)
        
        # User: Key generation
        user.pubkey, dur_user_keygen = userKeyGen(pp, N)
        durations["user_keygen"].append(dur_user_keygen)

        # Issuer: Verify user's key-pair
        dur_key_ver = key_verify(user.pubkey, N)
        durations["key_ver"].append(dur_key_ver)

        # Issuer: Issue pre-signature
        A, B, e, proof_dleq, dur_iss, dur_proof_dleq_gen = issue(pp, issuer.keypair, user.pubkey)
        durations["iss"].append(dur_iss)
        durations["proof_dleq_gen"].append(dur_proof_dleq_gen)

        # User: Verify proof_dleq
        dur_proof_dleq_ver = proof_dleq_verify(pp, A, B, issuer.keypair.pubkey, proof_dleq)
        durations["proof_dleq_ver"].append(dur_proof_dleq_ver)

        # User: Obtain signature
        mu = os.urandom(256)
        pk_blind, proof_hb, A_blind, B_blind, D, proof_validity, dur_pk_blind, dur_sigma_blind, dur_obt, dur_proof_hb_gen, dur_proof_validity_gen = obtain(pp, user.pubkey, A, e, mu)
        durations["pk_blind"].append(dur_pk_blind)
        durations["sigma_blind"].append(dur_sigma_blind)
        durations["obt"].append(dur_obt)
        durations["proof_hb_gen"].append(dur_proof_hb_gen)
        durations["proof_validity_gen"].append(dur_proof_validity_gen)
        
        # Issuer: Verify signature
        dur_proof_hb_ver = proof_hb_verify(pp, pk_blind, proof_hb, mu)    
        durations["proof_hb_ver"].append(dur_proof_hb_ver)
        
        dur_proof_validity_ver = proof_validity_verify(pp, A_blind, B_blind, D, pk_blind, proof_validity)
        durations["proof_validity_ver"].append(dur_proof_validity_ver)

        start_val_ver = time.time()
        if B_blind != A_blind * issuer.keypair.sk:
            raise ValueError("Invalid equality")
        dur_val_ver = time.time() - start_val_ver
        durations["val_ver"].append(dur_val_ver)
        
        dur_total = time.time() - start_total
        durations["total"].append(dur_total)

    print(f"Average and std (ms) over {ITERATIONS} runs:")
    for step, values in durations.items():
        avg_ms = statistics.mean(values) * 1000
        std_ms = statistics.stdev(values) * 1000
        print(f"{step}: avg {avg_ms:.3f} ms, std {std_ms:.3f} ms")