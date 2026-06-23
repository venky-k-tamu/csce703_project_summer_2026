"""Number-theoretic transform per FIPS 203 §4.3 (Algorithms 9–12).

The NTT maps ℤ_q[X]/(X^256 + 1) onto ∏_{i=0..127} ℤ_q[X]/(X^2 − ζ^{2·BitRev_7(i)+1}),
i.e. 128 quadratic factors, since 17 is a primitive 256-th root of unity mod 3329.
"""

from .params import N, Q

_ZETA = 17


def _bit_rev_7(i: int) -> int:
    r = 0
    for _ in range(7):
        r = (r << 1) | (i & 1)
        i >>= 1
    return r


# ZETAS[k] = ζ^{BitRev_7(k)} mod q for k = 0..127 (FIPS 203 Appendix A).
ZETAS = tuple(pow(_ZETA, _bit_rev_7(k), Q) for k in range(128))

# GAMMAS[i] = ζ^{2·BitRev_7(i)+1} mod q for i = 0..127, used by BaseCaseMultiply.
GAMMAS = tuple(pow(_ZETA, 2 * _bit_rev_7(i) + 1, Q) for i in range(128))

# N^{-1} mod q for N=128 (the half-length used in the NTT). 128 · 3303 ≡ 1 (mod 3329).
_INV128 = pow(128, -1, Q)


def ntt(f):
    """Algorithm 9: forward NTT, in-place style on a copy."""
    if len(f) != N:
        raise ValueError(f"polynomial must have {N} coefficients")
    fh = [v % Q for v in f]
    k = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * fh[j + length]) % Q
                fh[j + length] = (fh[j] - t) % Q
                fh[j] = (fh[j] + t) % Q
        length //= 2
    return fh


def intt(fh):
    """Algorithm 10: inverse NTT."""
    if len(fh) != N:
        raise ValueError(f"polynomial must have {N} coefficients")
    f = [v % Q for v in fh]
    k = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = (zeta * (f[j + length] - t)) % Q
        length *= 2
    return [(v * _INV128) % Q for v in f]


def base_case_multiply(a0, a1, b0, b1, gamma):
    """Algorithm 11: multiplication in ℤ_q[X]/(X^2 − γ)."""
    c0 = (a0 * b0 + a1 * b1 * gamma) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1


def multiply_ntts(fh, gh):
    """Algorithm 12: pointwise multiplication of two NTT-domain polynomials."""
    if len(fh) != N or len(gh) != N:
        raise ValueError(f"polynomials must have {N} coefficients")
    h = [0] * N
    for i in range(128):
        h[2 * i], h[2 * i + 1] = base_case_multiply(
            fh[2 * i], fh[2 * i + 1], gh[2 * i], gh[2 * i + 1], GAMMAS[i]
        )
    return h
