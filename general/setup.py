import hashlib
import time
from ecdsa.curves import NIST256p
from general.proofs import *
from utils.bbs_hnibbs_utils import *


def setup() -> tuple[PublicParamsEC, float]:
    """
    Generate EC-based public parameters.
    """
    start_setup = time.time()
    
    curve = NIST256p
    curve_name = "NIST256p"
    curve_nameb = curve_name.encode()
    G = curve.generator.to_affine()
    Gb = point_to_bytes(G)
    order = NIST256p.order
    orderb = order.to_bytes(32, "big")
    p = curve.curve.p()
    pb = p.to_bytes(32, "big")
    
    # Pick generators
    g = G
    gb = point_to_bytes(g)
    gt = G * rand_scalar(order)
    gtb = point_to_bytes(gt)
    g0 = G * rand_scalar(order)
    g0b = point_to_bytes(g0)
    H = G * rand_scalar(order)
    Hb = point_to_bytes(H)
    F = G * rand_scalar(order)
    Fb = point_to_bytes(F)

    # Initialize prehash to a SHA-256 hash
    prehash = hashlib.sha256()
    for gen in [curve_nameb, Gb, orderb, pb, gb, gtb, g0b, Hb, Fb]:
        prehash.update(gen)

    pp = PublicParamsEC(curve, G, order, p, g, gb, gt, gtb, g0, g0b, H, Hb, F, Fb, prehash)
    
    dur_setup = time.time() - start_setup
    
    return pp, dur_setup