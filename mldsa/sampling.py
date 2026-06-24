"""FIPS 204 §7.2–§7.3 sampling utilities (Algorithms 14, 15, 29–34)."""

from common.bytes_bits import bytes_to_bits

from .conversions import integer_to_bytes
from .encoding import bit_unpack
from .hashes import H, XOF128, XOF256
from .params import BITLEN_GAMMA_1, ETA, GAMMA_1, K, L, LAMBDA, N, Q, TAU


def _coeff_from_three_bytes(b0, b1, b2):
    """Algorithm 14."""
    if b2 > 127:
        b2 -= 128
    z = (b2 << 16) | (b1 << 8) | b0
    return z if z < Q else None


def _coeff_from_half_byte(b):
    """Algorithm 15, specialized for ML-DSA-65 (η = 4)."""
    if ETA == 4:
        return 4 - b if b < 9 else None
    if ETA == 2:
        return 2 - (b % 5) if b < 15 else None
    raise ValueError(f"unsupported η = {ETA}")


def rej_ntt_poly(rho: bytes):
    """Algorithm 30. Input: 34-byte seed. Output: NTT-domain polynomial."""
    if len(rho) != 34:
        raise ValueError("rej_ntt_poly seed must be 34 bytes")
    xof = XOF128(rho)
    out = [0] * N
    j = 0
    while j < N:
        chunk = xof.read(3)
        c = _coeff_from_three_bytes(chunk[0], chunk[1], chunk[2])
        if c is not None:
            out[j] = c
            j += 1
    return out


def rej_bounded_poly(rho: bytes):
    """Algorithm 31. Input: 66-byte seed. Output: η-bounded polynomial."""
    if len(rho) != 66:
        raise ValueError("rej_bounded_poly seed must be 66 bytes")
    xof = XOF256(rho)
    out = [0] * N
    j = 0
    while j < N:
        z = xof.read(1)[0]
        z0 = _coeff_from_half_byte(z & 0x0F)
        z1 = _coeff_from_half_byte(z >> 4)
        if z0 is not None:
            out[j] = z0 % Q
            j += 1
        if z1 is not None and j < N:
            out[j] = z1 % Q
            j += 1
    return out


def expand_a(rho: bytes):
    """Algorithm 32. Returns matrix Â ∈ T_q^{k×l} sampled from ρ ∈ B^32."""
    if len(rho) != 32:
        raise ValueError("expand_a seed must be 32 bytes")
    A = [[None] * L for _ in range(K)]
    for r in range(K):
        for s in range(L):
            A[r][s] = rej_ntt_poly(rho + integer_to_bytes(s, 1) + integer_to_bytes(r, 1))
    return A


def expand_s(rho: bytes):
    """Algorithm 33. Returns (s1 ∈ R_q^l, s2 ∈ R_q^k) sampled from ρ ∈ B^64."""
    if len(rho) != 64:
        raise ValueError("expand_s seed must be 64 bytes")
    s1 = [rej_bounded_poly(rho + integer_to_bytes(r, 2)) for r in range(L)]
    s2 = [rej_bounded_poly(rho + integer_to_bytes(L + r, 2)) for r in range(K)]
    return s1, s2


def expand_mask(rho: bytes, mu: int):
    """Algorithm 34. Returns y ∈ R_q^l with coefficients in (-γ1, γ1]."""
    if len(rho) != 64:
        raise ValueError("expand_mask seed must be 64 bytes")
    c = BITLEN_GAMMA_1                       # bitlen(2γ1 - 1) = 20 for ML-DSA-65
    bytes_per = 32 * c
    y = []
    for r in range(L):
        v = H(rho + integer_to_bytes(mu + r, 2), bytes_per)
        y.append(bit_unpack(v, GAMMA_1 - 1, GAMMA_1))
    return y


def sample_in_ball(rho: bytes):
    """Algorithm 29. Output: sparse polynomial with τ nonzero coeffs in {−1, 1}."""
    if len(rho) != LAMBDA // 4:
        raise ValueError(f"sample_in_ball seed must be {LAMBDA // 4} bytes")
    xof = XOF256(rho)
    h_bits = bytes_to_bits(xof.read(8))
    c = [0] * N
    for i in range(N - TAU, N):
        while True:
            j = xof.read(1)[0]
            if j <= i:
                break
        c[i] = c[j]
        c[j] = 1 if h_bits[i + TAU - N] == 0 else (Q - 1)  # ±1 in [0, q)
    return c
