"""FIPS 204 §7.1–§7.3 bit-packing and high-level encoders (Algorithms 16–28).

All "polynomial" arguments are length-N lists of integers. "Vector"
arguments are lists of K (or L) polynomials.
"""

from common.bytes_bits import bits_to_bytes, bytes_to_bits

from .conversions import bits_to_integer, integer_to_bits
from .params import (
    BITLEN_2_ETA,
    BITLEN_GAMMA_1,
    BITLEN_T0,
    BITLEN_T1,
    BITLEN_W1,
    D,
    DK_SIZE,
    EK_SIZE,
    ETA,
    GAMMA_1,
    K,
    L,
    LAMBDA,
    N,
    OMEGA,
    Q,
    SIG_SIZE,
)


def _to_signed(coef):
    """Map either a signed integer or a mod-q value in [0, q) into the
    centered representative in (-q/2, q/2]."""
    sc = coef % Q
    if sc > Q // 2:
        sc -= Q
    return sc


# -- low-level polynomial bit-packers ------------------------------------------------


def simple_bit_pack(w, b):
    """Algorithm 16. Pack polynomial coefficients in [0, b] into 32·bitlen(b) bytes."""
    width = b.bit_length()
    bits = []
    for coef in w:
        if not 0 <= coef <= b:
            raise ValueError(f"simple_bit_pack: coef {coef} out of [0, {b}]")
        bits.extend(integer_to_bits(coef, width))
    return bits_to_bytes(bits)


def simple_bit_unpack(v, b):
    """Algorithm 18. Inverse of simple_bit_pack."""
    width = b.bit_length()
    if len(v) != 32 * width:
        raise ValueError(f"simple_bit_unpack: bad length {len(v)} for b={b}")
    bits = bytes_to_bits(v)
    return [bits_to_integer(bits[i * width : (i + 1) * width], width) for i in range(N)]


def bit_pack(w, a, b):
    """Algorithm 17. Pack coefficients in [-a, b] into 32·bitlen(a+b) bytes.

    Accepts either signed integers or mod-q values in [0, q); both are
    canonicalized via _to_signed.
    """
    width = (a + b).bit_length()
    bits = []
    for coef in w:
        sc = _to_signed(coef)
        if not -a <= sc <= b:
            raise ValueError(f"bit_pack: coef {sc} (from {coef}) out of [-{a}, {b}]")
        bits.extend(integer_to_bits(b - sc, width))
    return bits_to_bytes(bits)


def bit_unpack(v, a, b):
    """Algorithm 19. Inverse of bit_pack."""
    width = (a + b).bit_length()
    if len(v) != 32 * width:
        raise ValueError(f"bit_unpack: bad length {len(v)}")
    bits = bytes_to_bits(v)
    return [b - bits_to_integer(bits[i * width : (i + 1) * width], width) for i in range(N)]


# -- hint vector packer / unpacker ---------------------------------------------------


def hint_bit_pack(h):
    """Algorithm 20. Encode hint vector h ∈ {0,1}^(k×N), ‖h‖₁ ≤ ω, into ω+k bytes."""
    if len(h) != K:
        raise ValueError(f"hint_bit_pack: expected {K} polynomials, got {len(h)}")
    y = bytearray(OMEGA + K)
    idx = 0
    for i in range(K):
        for j in range(N):
            if h[i][j] != 0:
                if idx >= OMEGA:
                    raise ValueError("hint_bit_pack: ‖h‖₁ exceeds ω")
                y[idx] = j
                idx += 1
        y[OMEGA + i] = idx
    return bytes(y)


def hint_bit_unpack(y):
    """Algorithm 21. Decode the hint vector, returning None on malformed input."""
    if len(y) != OMEGA + K:
        return None
    h = [[0] * N for _ in range(K)]
    idx = 0
    for i in range(K):
        end = y[OMEGA + i]
        # Cumulative count must be non-decreasing and within [idx, ω].
        if end < idx or end > OMEGA:
            return None
        first_index = idx
        while idx < end:
            # Positions within a single polynomial must be strictly increasing.
            if idx > first_index and y[idx - 1] >= y[idx]:
                return None
            h[i][y[idx]] = 1
            idx += 1
    # All trailing slots (indices in [idx, OMEGA)) must be zero.
    for k in range(idx, OMEGA):
        if y[k] != 0:
            return None
    return h


# -- high-level encoders -------------------------------------------------------------


def _bytes_of_poly_count_simple(b):
    return 32 * b.bit_length()


def pk_encode(rho, t1):
    """Algorithm 22. pk = ρ ‖ SimpleBitPack(t1[i], 2^bitlen_t1 − 1)."""
    if len(rho) != 32:
        raise ValueError("pk_encode: ρ must be 32 bytes")
    if len(t1) != K:
        raise ValueError(f"pk_encode: expected {K} polys")
    pk = bytes(rho)
    bound = (1 << BITLEN_T1) - 1
    for i in range(K):
        pk += simple_bit_pack(t1[i], bound)
    if len(pk) != EK_SIZE:
        raise AssertionError(f"pk_encode produced {len(pk)} bytes (want {EK_SIZE})")
    return pk


def pk_decode(pk):
    """Algorithm 23."""
    if len(pk) != EK_SIZE:
        raise ValueError(f"pk_decode: pk must be {EK_SIZE} bytes")
    rho = pk[:32]
    bound = (1 << BITLEN_T1) - 1
    bytes_per_poly = _bytes_of_poly_count_simple(bound)
    t1 = []
    for i in range(K):
        start = 32 + i * bytes_per_poly
        t1.append(simple_bit_unpack(pk[start : start + bytes_per_poly], bound))
    return rho, t1


def sk_encode(rho, K_seed, tr, s1, s2, t0):
    """Algorithm 24. sk = ρ ‖ K ‖ tr ‖ pack(s1) ‖ pack(s2) ‖ pack(t0)."""
    if len(rho) != 32 or len(K_seed) != 32 or len(tr) != 64:
        raise ValueError("sk_encode: wrong size for ρ / K / tr")
    if len(s1) != L or len(s2) != K or len(t0) != K:
        raise ValueError("sk_encode: vector length mismatch")
    sk = bytes(rho) + bytes(K_seed) + bytes(tr)
    for poly in s1:
        sk += bit_pack(poly, ETA, ETA)
    for poly in s2:
        sk += bit_pack(poly, ETA, ETA)
    pow2 = 1 << (D - 1)
    for poly in t0:
        sk += bit_pack(poly, pow2 - 1, pow2)
    if len(sk) != DK_SIZE:
        raise AssertionError(f"sk_encode produced {len(sk)} bytes (want {DK_SIZE})")
    return sk


def sk_decode(sk):
    """Algorithm 25."""
    if len(sk) != DK_SIZE:
        raise ValueError(f"sk_decode: sk must be {DK_SIZE} bytes")
    cursor = 0
    rho = sk[cursor : cursor + 32]; cursor += 32
    K_seed = sk[cursor : cursor + 32]; cursor += 32
    tr = sk[cursor : cursor + 64]; cursor += 64
    s_bytes = 32 * BITLEN_2_ETA
    s1 = []
    for _ in range(L):
        s1.append(bit_unpack(sk[cursor : cursor + s_bytes], ETA, ETA))
        cursor += s_bytes
    s2 = []
    for _ in range(K):
        s2.append(bit_unpack(sk[cursor : cursor + s_bytes], ETA, ETA))
        cursor += s_bytes
    t0_bytes = 32 * BITLEN_T0
    pow2 = 1 << (D - 1)
    t0 = []
    for _ in range(K):
        t0.append(bit_unpack(sk[cursor : cursor + t0_bytes], pow2 - 1, pow2))
        cursor += t0_bytes
    assert cursor == DK_SIZE
    return rho, K_seed, tr, s1, s2, t0


def sig_encode(c_tilde, z, h):
    """Algorithm 26. sig = c_tilde ‖ pack(z) ‖ HintBitPack(h)."""
    if len(c_tilde) != LAMBDA // 4:
        raise ValueError(f"sig_encode: c_tilde must be {LAMBDA // 4} bytes")
    if len(z) != L:
        raise ValueError(f"sig_encode: expected {L} z-polys")
    sig = bytes(c_tilde)
    for poly in z:
        sig += bit_pack(poly, GAMMA_1 - 1, GAMMA_1)
    sig += hint_bit_pack(h)
    if len(sig) != SIG_SIZE:
        raise AssertionError(f"sig_encode produced {len(sig)} bytes (want {SIG_SIZE})")
    return sig


def sig_decode(sig):
    """Algorithm 27. Returns (c_tilde, z, h) or (c_tilde, z, None) on bad hint."""
    if len(sig) != SIG_SIZE:
        raise ValueError(f"sig_decode: sig must be {SIG_SIZE} bytes")
    cursor = 0
    c_tilde = sig[cursor : cursor + LAMBDA // 4]; cursor += LAMBDA // 4
    z_bytes = 32 * BITLEN_GAMMA_1
    z = []
    for _ in range(L):
        z.append(bit_unpack(sig[cursor : cursor + z_bytes], GAMMA_1 - 1, GAMMA_1))
        cursor += z_bytes
    h = hint_bit_unpack(sig[cursor : cursor + OMEGA + K])
    return c_tilde, z, h


def w1_encode(w1):
    """Algorithm 28. SimpleBitPack each w1[i] at bit-width bitlen((q-1)/(2γ2) - 1)."""
    if len(w1) != K:
        raise ValueError(f"w1_encode: expected {K} polys")
    bound = (1 << BITLEN_W1) - 1
    out = b""
    for poly in w1:
        out += simple_bit_pack(poly, bound)
    return out
