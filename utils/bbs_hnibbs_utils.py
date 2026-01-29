import secrets
from ecdsa.ellipticcurve import Point

def rand_scalar(curve_order: int) -> int:
    """
    Get a random scalar in [1, order-1].
    """
    return secrets.randbelow(curve_order - 1) + 1

def point_to_bytes(P: Point) -> bytes:
    """
    Convert Point to bytes.
    """
    xb = int(P.x()).to_bytes(32, "big")
    yb = int(P.y()).to_bytes(32, "big")
    return b"\x04" + xb + yb