"""ML-DSA internal KeyGen / Sign / Verify per FIPS 204 §6 (Algorithms 6–8)."""

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
    """Centered ℓ∞ norm: max |signed(c)| for c ∈ [0, q)."""
    return max(min(c, Q - c) for c in poly)


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
