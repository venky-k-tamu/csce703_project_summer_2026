"""ML-DSA internal + public KeyGen / Sign / Verify per FIPS 204 §5–§6.

Public API:
- keygen()                              → (pk, sk)
- sign(sk, M, ctx=b"", deterministic=False)
- verify(pk, M, sig, ctx=b"")
- hash_sign(sk, M, ctx=b"", *, hash_alg="SHA2-512", deterministic=False)
- hash_verify(pk, M, sig, ctx=b"", *, hash_alg="SHA2-512")

Internal API (underscore-prefixed) is exposed for KAT replay.
"""

import hashlib
import secrets

from .conversions import integer_to_bytes
from .encoding import (
    pk_decode,
    pk_encode,
    sig_decode,
    sig_encode,
    sk_decode,
    sk_encode,
    w1_encode,
)
from .hashes import H
from .ntt import intt, multiply_ntts, ntt
from .params import (
    BETA,
    D,
    GAMMA_1,
    GAMMA_2,
    K,
    L,
    LAMBDA,
    N,
    OMEGA,
    Q,
)
from .rounding import (
    high_bits,
    low_bits,
    make_hint,
    power2round,
    use_hint,
)
from .sampling import expand_a, expand_mask, expand_s, sample_in_ball


# ----- small helpers ---------------------------------------------------------


def _vec_add(u, v):
    return [[(a + b) % Q for a, b in zip(p, q)] for p, q in zip(u, v)]


def _vec_sub(u, v):
    return [[(a - b) % Q for a, b in zip(p, q)] for p, q in zip(u, v)]


def _vec_neg(v):
    return [[(-a) % Q for a in p] for p in v]


def _vec_ntt(vec):
    return [ntt(p) for p in vec]


def _vec_intt(vec):
    return [intt(p) for p in vec]


def _matvec_ntt(A_hat, v_hat):
    """K×L matrix · L-vector → K-vector in the NTT domain."""
    out = []
    for i in range(K):
        acc = [0] * N
        for j in range(L):
            prod = multiply_ntts(A_hat[i][j], v_hat[j])
            acc = [(a + b) % Q for a, b in zip(acc, prod)]
        out.append(acc)
    return out


def _scalvec_ntt(c_hat, v_hat):
    return [multiply_ntts(c_hat, p) for p in v_hat]


def _power2round_vec(t):
    t1 = [[0] * N for _ in range(K)]
    t0 = [[0] * N for _ in range(K)]
    for i in range(K):
        for j in range(N):
            t1[i][j], t0[i][j] = power2round(t[i][j])
    return t1, t0


def _high_bits_vec(w):
    return [[high_bits(c) for c in p] for p in w]


def _low_bits_vec(w):
    return [[low_bits(c) for c in p] for p in w]


def _make_hint_vec(z_vec, r_vec):
    return [[make_hint(z, r) for z, r in zip(zp, rp)] for zp, rp in zip(z_vec, r_vec)]


def _use_hint_vec(h_vec, r_vec):
    return [[use_hint(h, r) for h, r in zip(hp, rp)] for hp, rp in zip(h_vec, r_vec)]


def _hint_weight(h):
    return sum(c for p in h for c in p)


def _inf_norm_poly(poly):
    """Centered ℓ∞ norm. Accepts coefficients in either signed or mod-q form;
    each is canonicalized to (-q/2, q/2] before taking the absolute value."""
    out = 0
    for c in poly:
        sc = c % Q
        if sc > Q // 2:
            sc -= Q
        if -sc > out:
            out = -sc
        if sc > out:
            out = sc
    return out


def _inf_norm_vec(vec):
    return max(_inf_norm_poly(p) for p in vec)


def _scale_vec(vec, scalar):
    return [[(scalar * c) % Q for c in p] for p in vec]


# ----- core algorithms -------------------------------------------------------


def _keygen_internal(xi: bytes):
    """Algorithm 6. Returns (pk, sk)."""
    if len(xi) != 32:
        raise ValueError("ξ must be 32 bytes")

    seed_material = H(xi + integer_to_bytes(K, 1) + integer_to_bytes(L, 1), 128)
    rho = seed_material[:32]
    rho_prime = seed_material[32:96]
    K_seed = seed_material[96:128]

    A_hat = expand_a(rho)
    s1, s2 = expand_s(rho_prime)

    s1_hat = _vec_ntt(s1)
    t = _vec_add(_vec_intt(_matvec_ntt(A_hat, s1_hat)), s2)
    t1, t0 = _power2round_vec(t)

    pk = pk_encode(rho, t1)
    tr = H(pk, 64)
    sk = sk_encode(rho, K_seed, tr, s1, s2, t0)
    return pk, sk


def _sign_internal(sk: bytes, M_prime: bytes, rnd: bytes) -> bytes:
    """Algorithm 7. Deterministic when rnd = b'\\x00' * 32."""
    if len(rnd) != 32:
        raise ValueError("rnd must be 32 bytes")

    rho, K_seed, tr, s1, s2, t0 = sk_decode(sk)

    s1_hat = _vec_ntt(s1)
    s2_hat = _vec_ntt(s2)
    t0_hat = _vec_ntt(t0)
    A_hat = expand_a(rho)

    mu = H(bytes(tr) + bytes(M_prime), 64)
    rho_prime = H(bytes(K_seed) + bytes(rnd) + mu, 64)

    kappa = 0
    while True:
        if kappa > 1000 * L:
            raise RuntimeError("ML-DSA Sign rejection loop exceeded sane bound")

        y = expand_mask(rho_prime, kappa)
        w = _vec_intt(_matvec_ntt(A_hat, _vec_ntt(y)))
        w1 = _high_bits_vec(w)

        c_tilde = H(mu + w1_encode(w1), LAMBDA // 4)
        c = sample_in_ball(c_tilde)
        c_hat = ntt(c)

        cs1 = _vec_intt(_scalvec_ntt(c_hat, s1_hat))
        cs2 = _vec_intt(_scalvec_ntt(c_hat, s2_hat))

        z = _vec_add(y, cs1)
        r_low = _low_bits_vec(_vec_sub(w, cs2))

        if _inf_norm_vec(z) >= GAMMA_1 - BETA:
            kappa += L
            continue
        if _inf_norm_vec(r_low) >= GAMMA_2 - BETA:
            kappa += L
            continue

        ct0 = _vec_intt(_scalvec_ntt(c_hat, t0_hat))
        if _inf_norm_vec(ct0) >= GAMMA_2:
            kappa += L
            continue

        neg_ct0 = _vec_neg(ct0)
        r_for_hint = _vec_add(_vec_sub(w, cs2), ct0)
        h = _make_hint_vec(neg_ct0, r_for_hint)
        if _hint_weight(h) > OMEGA:
            kappa += L
            continue

        return sig_encode(c_tilde, z, h)


def _verify_internal(pk: bytes, M_prime: bytes, sig: bytes) -> bool:
    """Algorithm 8."""
    try:
        rho, t1 = pk_decode(pk)
        c_tilde, z, h = sig_decode(sig)
    except ValueError:
        return False
    if h is None:
        return False

    # Norm check on z; sigDecode returned z in centered (signed) form.
    z_mod = [[c % Q for c in p] for p in z]
    if _inf_norm_vec(z_mod) >= GAMMA_1 - BETA:
        return False

    A_hat = expand_a(rho)
    tr = H(pk, 64)
    mu = H(bytes(tr) + bytes(M_prime), 64)
    c = sample_in_ball(c_tilde)
    c_hat = ntt(c)
    z_hat = _vec_ntt(z_mod)
    t1_scaled = _scale_vec(t1, 1 << D)
    t1_hat = _vec_ntt(t1_scaled)

    Az_minus_ct1 = _vec_sub(
        _matvec_ntt(A_hat, z_hat),
        _scalvec_ntt(c_hat, t1_hat),
    )
    w_approx = _vec_intt(Az_minus_ct1)
    w1_prime = _use_hint_vec(h, w_approx)

    c_tilde_prime = H(mu + w1_encode(w1_prime), LAMBDA // 4)
    return c_tilde == c_tilde_prime


# ----- public API (FIPS 204 §5, Algorithms 1–5) -----------------------------


# DER-encoded OIDs for each pre-hash function permitted by FIPS 204 §5.4.
# Each value is the full ASN.1 OID encoding (tag 0x06, length, content).
# Names match the ACVP-style identifiers used in NIST test vectors.
_PREHASH_FUNCTIONS = {
    "SHA2-224":     (bytes.fromhex("0609608648016503040204"), lambda m: hashlib.new("sha224", m).digest()),
    "SHA2-256":     (bytes.fromhex("0609608648016503040201"), lambda m: hashlib.sha256(m).digest()),
    "SHA2-384":     (bytes.fromhex("0609608648016503040202"), lambda m: hashlib.sha384(m).digest()),
    "SHA2-512":     (bytes.fromhex("0609608648016503040203"), lambda m: hashlib.sha512(m).digest()),
    "SHA2-512/224": (bytes.fromhex("0609608648016503040205"), lambda m: hashlib.new("sha512_224", m).digest()),
    "SHA2-512/256": (bytes.fromhex("0609608648016503040206"), lambda m: hashlib.new("sha512_256", m).digest()),
    "SHA3-224":     (bytes.fromhex("0609608648016503040207"), lambda m: hashlib.sha3_224(m).digest()),
    "SHA3-256":     (bytes.fromhex("0609608648016503040208"), lambda m: hashlib.sha3_256(m).digest()),
    "SHA3-384":     (bytes.fromhex("0609608648016503040209"), lambda m: hashlib.sha3_384(m).digest()),
    "SHA3-512":     (bytes.fromhex("060960864801650304020A"), lambda m: hashlib.sha3_512(m).digest()),
    "SHAKE-128":    (bytes.fromhex("060960864801650304020B"), lambda m: hashlib.shake_128(m).digest(32)),
    "SHAKE-256":    (bytes.fromhex("060960864801650304020C"), lambda m: hashlib.shake_256(m).digest(64)),
}


def _format_M_prime(M: bytes, ctx: bytes, prehash_oid: bytes | None) -> bytes:
    """Build the M' string for either ML-DSA (prehash_oid=None) or HashML-DSA."""
    if len(ctx) > 255:
        raise ValueError("ctx must be at most 255 bytes")
    domain_separator = 1 if prehash_oid is not None else 0
    head = integer_to_bytes(domain_separator, 1) + integer_to_bytes(len(ctx), 1) + bytes(ctx)
    if prehash_oid is None:
        return head + bytes(M)
    return head + prehash_oid + bytes(M)


def keygen():
    """Algorithm 1: ML-DSA.KeyGen."""
    return _keygen_internal(secrets.token_bytes(32))


def sign(sk: bytes, M: bytes, ctx: bytes = b"", *, deterministic: bool = False) -> bytes:
    """Algorithm 2: ML-DSA.Sign."""
    M_prime = _format_M_prime(M, ctx, prehash_oid=None)
    rnd = b"\x00" * 32 if deterministic else secrets.token_bytes(32)
    return _sign_internal(sk, M_prime, rnd)


def verify(pk: bytes, M: bytes, sig: bytes, ctx: bytes = b"") -> bool:
    """Algorithm 3: ML-DSA.Verify."""
    if len(ctx) > 255:
        return False
    M_prime = _format_M_prime(M, ctx, prehash_oid=None)
    return _verify_internal(pk, M_prime, sig)


def _resolve_prehash(name: str):
    try:
        return _PREHASH_FUNCTIONS[name]
    except KeyError:
        raise ValueError(f"unsupported pre-hash function {name!r}") from None


def hash_sign(
    sk: bytes,
    M: bytes,
    ctx: bytes = b"",
    *,
    hash_alg: str = "SHA2-512",
    deterministic: bool = False,
) -> bytes:
    """Algorithm 4: HashML-DSA.Sign."""
    oid, prehash = _resolve_prehash(hash_alg)
    M_prime = _format_M_prime(prehash(M), ctx, prehash_oid=oid)
    rnd = b"\x00" * 32 if deterministic else secrets.token_bytes(32)
    return _sign_internal(sk, M_prime, rnd)


def hash_verify(
    pk: bytes,
    M: bytes,
    sig: bytes,
    ctx: bytes = b"",
    *,
    hash_alg: str = "SHA2-512",
) -> bool:
    """Algorithm 5: HashML-DSA.Verify."""
    if len(ctx) > 255:
        return False
    try:
        oid, prehash = _resolve_prehash(hash_alg)
    except ValueError:
        return False
    M_prime = _format_M_prime(prehash(M), ctx, prehash_oid=oid)
    return _verify_internal(pk, M_prime, sig)
