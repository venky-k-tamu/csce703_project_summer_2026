"""Number-theoretic transform per FIPS 204 §7.5 (Algorithms 41/42).

ζ = 1753 is a primitive 512-th root of unity mod q = 8380417, so X²⁵⁶ + 1
factors into 256 *linear* factors over ℤ_q. Therefore:
- the NTT goes from R_q to ℤ_q²⁵⁶,
- pointwise multiplication is literally element-wise,
- the inverse multiplies by 256⁻¹ = 8347681.
"""

from .params import N, Q

_ZETA = 1753
_INV_N = pow(N, -1, Q)  # 8347681


def _bit_rev_8(i: int) -> int:
    r = 0
    for _ in range(8):
        r = (r << 1) | (i & 1)
        i >>= 1
    return r


# ZETAS[k] = ζ^{BitRev_8(k)} mod q, k = 0..255 (FIPS 204 Appendix B).
ZETAS = tuple(pow(_ZETA, _bit_rev_8(k), Q) for k in range(256))


def ntt(w):
    """Algorithm 41."""
    if len(w) != N:
        raise ValueError(f"polynomial must have {N} coefficients")
    wh = [v % Q for v in w]
    m = 0
    length = 128
    while length >= 1:
        for start in range(0, N, 2 * length):
            m += 1
            zeta = ZETAS[m]
            for j in range(start, start + length):
                t = (zeta * wh[j + length]) % Q
                wh[j + length] = (wh[j] - t) % Q
                wh[j] = (wh[j] + t) % Q
        length //= 2
    return wh


def intt(wh):
    """Algorithm 42."""
    if len(wh) != N:
        raise ValueError(f"polynomial must have {N} coefficients")
    w = [v % Q for v in wh]
    m = 256
    length = 1
    while length < N:
        for start in range(0, N, 2 * length):
            m -= 1
            zeta = (-ZETAS[m]) % Q
            for j in range(start, start + length):
                t = w[j]
                w[j] = (t + w[j + length]) % Q
                w[j + length] = (zeta * (t - w[j + length])) % Q
        length *= 2
    return [(_INV_N * v) % Q for v in w]


def multiply_ntts(a_hat, b_hat):
    """Pointwise product in T_q — element-wise because the NTT is fully diagonal."""
    if len(a_hat) != N or len(b_hat) != N:
        raise ValueError(f"polynomials must have {N} coefficients")
    return [(a * b) % Q for a, b in zip(a_hat, b_hat)]
