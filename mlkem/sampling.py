"""SampleNTT and SamplePolyCBD per FIPS 203 §4.2.2 (Algorithms 7–8)."""

from .bytes_bits import bytes_to_bits
from .hashes import XOF
from .params import N, Q


def sample_ntt(seed: bytes):
    """Algorithm 7: rejection sampling from a SHAKE-128 stream.

    `seed` is the XOF input (e.g. ρ ‖ i ‖ j in K-PKE.KeyGen / Encrypt).
    Returns a polynomial in NTT representation with all coefficients in [0, q).
    """
    xof = XOF(seed)
    a = [0] * N
    j = 0
    while j < N:
        chunk = xof.read(3)
        b0, b1, b2 = chunk[0], chunk[1], chunk[2]
        d1 = b0 + 256 * (b1 & 0x0F)
        d2 = (b1 >> 4) + 16 * b2
        if d1 < Q:
            a[j] = d1
            j += 1
        if d2 < Q and j < N:
            a[j] = d2
            j += 1
    return a


def sample_poly_cbd(eta: int, B: bytes):
    """Algorithm 8: centered binomial distribution sampler with parameter η."""
    if eta not in (2, 3):
        raise ValueError("eta must be 2 or 3 for ML-KEM")
    if len(B) != 64 * eta:
        raise ValueError(f"B must be {64 * eta} bytes for eta={eta}")
    bits = bytes_to_bits(B)
    f = [0] * N
    for i in range(N):
        x = 0
        y = 0
        for j in range(eta):
            x += bits[2 * i * eta + j]
            y += bits[2 * i * eta + eta + j]
        f[i] = (x - y) % Q
    return f
