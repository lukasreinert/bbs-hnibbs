from dataclasses import dataclass
from ecdsa.curves import Curve
from ecdsa.ellipticcurve import Point
from typing import Any, Optional
from utils.bbs_hnibbs_utils import point_to_bytes


@dataclass
class PublicParamsEC:
    curve: Curve
    G: Point
    order: int
    p: int
    g: Point
    gb: bytes
    gt: Point
    gtb: bytes
    g0: Point
    g0b: bytes
    H: Point
    Hb: bytes
    F: Point
    Fb: bytes
    prehash: Any

@dataclass
class PubKey:
    pk: Point
    pkb: Optional[bytes] = None

    def __post_init__(self):
        self.pkb = point_to_bytes(self.pk)

@dataclass
class Keypair:
    sk: int
    pubkey: PubKey

@dataclass
class IProof:
    c: int
    rho: int

@dataclass
class UProof:
    c: int
    rho: int

@dataclass
class DLEQProof:
    c: int
    rho: int

@dataclass
class HBProof:
    x: int
    rho_blind: int

@dataclass
class ValidityProof:
    c: int
    rho1: int
    rho2: int
    rho3: int
    rho4: int

@dataclass
class Issuer:
    keypair: Optional[Keypair] = None
    proof_I: Optional[IProof] = None

@dataclass
class User:
    pubkey: Optional[PubKey] = None
    