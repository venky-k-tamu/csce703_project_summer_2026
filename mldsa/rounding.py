"""FIPS 204 §7.4 rounding and hint utilities (Algorithms 35–40)."""

from .params import D, GAMMA_2, Q


def _mod_pm(r, alpha):
    """Centered modular reduction: result in (-α/2, α/2] when α even,
    or (-(α-1)/2, (α-1)/2] when α odd. ML-DSA always uses even α here."""
    r %= alpha
    if r > alpha // 2:
        r -= alpha
    return r


def power2round(r):
    """Algorithm 35. r ≡ r1·2^D + r0 (mod q), r0 ∈ (-2^(D-1), 2^(D-1)]."""
    r %= Q
    r0 = _mod_pm(r, 1 << D)
    r1 = (r - r0) >> D
    return r1, r0


def decompose(r):
    """Algorithm 36. r ≡ r1·(2γ2) + r0 (mod q), r0 ∈ (-γ2, γ2].

    Wraparound: when (r - r0) == q - 1, set r1 = 0 and r0 := r0 - 1
    so r1 stays in [0, (q-1)/(2γ2)).
    """
    r %= Q
    r0 = _mod_pm(r, 2 * GAMMA_2)
    if r - r0 == Q - 1:
        return 0, r0 - 1
    return (r - r0) // (2 * GAMMA_2), r0


def high_bits(r):
    """Algorithm 37."""
    return decompose(r)[0]


def low_bits(r):
    """Algorithm 38."""
    return decompose(r)[1]


def make_hint(z, r):
    """Algorithm 39. Returns 1 if HighBits(r) ≠ HighBits(r+z), else 0."""
    return int(high_bits(r) != high_bits((r + z) % Q))


def use_hint(h, r):
    """Algorithm 40. Reconstructs HighBits(r+z) from r and a 1-bit hint."""
    m = (Q - 1) // (2 * GAMMA_2)
    r1, r0 = decompose(r)
    if h == 1:
        if r0 > 0:
            return (r1 + 1) % m
        return (r1 - 1) % m
    return r1
