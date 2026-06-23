"""K-PKE: the IND-CPA-secure public-key encryption underlying ML-KEM.

Implements FIPS 203 §5 (Algorithms 13–15).
"""

from .hashes import G, prf
from .ntt import intt, multiply_ntts, ntt
from .params import (
    CT_SIZE,
    DK_PKE_SIZE,
    DU,
    DV,
    EK_PKE_SIZE,
    ETA_1,
    ETA_2,
    K,
    N,
    Q,
)
from .sampling import sample_ntt, sample_poly_cbd
from .serialize import byte_decode, byte_encode, compress, decompress


def _poly_add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def _poly_sub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


def _vec_add(u, v):
    return [_poly_add(a, b) for a, b in zip(u, v)]


def _vec_ntt(vec):
    return [ntt(p) for p in vec]


def _vec_intt(vec):
    return [intt(p) for p in vec]


def _matvec_ntt(A_hat, vec_hat):
    """A_hat · vec_hat in the NTT domain (matrix-vector product over R̂_q)."""
    out = []
    for i in range(len(A_hat)):
        acc = [0] * N
        for j in range(len(vec_hat)):
            acc = _poly_add(acc, multiply_ntts(A_hat[i][j], vec_hat[j]))
        out.append(acc)
    return out


def _vec_inner_ntt(u_hat, v_hat):
    """⟨u_hat, v_hat⟩ in the NTT domain (returns a single polynomial)."""
    acc = [0] * N
    for a, b in zip(u_hat, v_hat):
        acc = _poly_add(acc, multiply_ntts(a, b))
    return acc


def _vec_byte_encode(d, vec):
    return b"".join(byte_encode(d, p) for p in vec)


def _vec_byte_decode(d, k, data):
    sz = 32 * d
    return [byte_decode(d, data[i * sz : (i + 1) * sz]) for i in range(k)]


def _vec_compress(d, vec):
    return [compress(d, p) for p in vec]


def _vec_decompress(d, vec):
    return [decompress(d, p) for p in vec]


def _sample_matrix(rho):
    """Generate Â ∈ (R̂_q)^{k×k}. Spec: Â[i,j] = SampleNTT(ρ ‖ j ‖ i)."""
    A_hat = [[None] * K for _ in range(K)]
    for i in range(K):
        for j in range(K):
            A_hat[i][j] = sample_ntt(rho + bytes([j, i]))
    return A_hat


def kpke_keygen(d_seed: bytes):
    """Algorithm 13: K-PKE.KeyGen."""
    if len(d_seed) != 32:
        raise ValueError("seed d must be 32 bytes")
    rho, sigma = G(d_seed + bytes([K]))

    A_hat = _sample_matrix(rho)

    n_ctr = 0
    s = []
    for _ in range(K):
        s.append(sample_poly_cbd(ETA_1, prf(ETA_1, sigma, bytes([n_ctr]))))
        n_ctr += 1
    e = []
    for _ in range(K):
        e.append(sample_poly_cbd(ETA_1, prf(ETA_1, sigma, bytes([n_ctr]))))
        n_ctr += 1

    s_hat = _vec_ntt(s)
    e_hat = _vec_ntt(e)
    t_hat = _vec_add(_matvec_ntt(A_hat, s_hat), e_hat)

    ek_pke = _vec_byte_encode(12, t_hat) + rho
    dk_pke = _vec_byte_encode(12, s_hat)
    assert len(ek_pke) == EK_PKE_SIZE
    assert len(dk_pke) == DK_PKE_SIZE
    return ek_pke, dk_pke


def kpke_encrypt(ek_pke: bytes, m: bytes, r: bytes) -> bytes:
    """Algorithm 14: K-PKE.Encrypt."""
    if len(ek_pke) != EK_PKE_SIZE:
        raise ValueError(f"ek_pke must be {EK_PKE_SIZE} bytes")
    if len(m) != 32:
        raise ValueError("m must be 32 bytes")
    if len(r) != 32:
        raise ValueError("r must be 32 bytes")

    t_hat = _vec_byte_decode(12, K, ek_pke[: 384 * K])
    rho = ek_pke[384 * K : 384 * K + 32]

    A_hat = _sample_matrix(rho)
    A_hat_T = [[A_hat[j][i] for j in range(K)] for i in range(K)]

    n_ctr = 0
    y = []
    for _ in range(K):
        y.append(sample_poly_cbd(ETA_1, prf(ETA_1, r, bytes([n_ctr]))))
        n_ctr += 1
    e1 = []
    for _ in range(K):
        e1.append(sample_poly_cbd(ETA_2, prf(ETA_2, r, bytes([n_ctr]))))
        n_ctr += 1
    e2 = sample_poly_cbd(ETA_2, prf(ETA_2, r, bytes([n_ctr])))

    y_hat = _vec_ntt(y)
    u = _vec_add(_vec_intt(_matvec_ntt(A_hat_T, y_hat)), e1)

    mu = decompress(1, byte_decode(1, m))
    v_inner = intt(_vec_inner_ntt(t_hat, y_hat))
    v = _poly_add(_poly_add(v_inner, e2), mu)

    c1 = _vec_byte_encode(DU, _vec_compress(DU, u))
    c2 = byte_encode(DV, compress(DV, v))
    ct = c1 + c2
    assert len(ct) == CT_SIZE
    return ct


def kpke_decrypt(dk_pke: bytes, c: bytes) -> bytes:
    """Algorithm 15: K-PKE.Decrypt."""
    if len(dk_pke) != DK_PKE_SIZE:
        raise ValueError(f"dk_pke must be {DK_PKE_SIZE} bytes")
    if len(c) != CT_SIZE:
        raise ValueError(f"c must be {CT_SIZE} bytes")

    split = 32 * DU * K
    c1 = c[:split]
    c2 = c[split:]

    u_prime = _vec_decompress(DU, _vec_byte_decode(DU, K, c1))
    v_prime = decompress(DV, byte_decode(DV, c2))
    s_hat = _vec_byte_decode(12, K, dk_pke)

    w = _poly_sub(v_prime, intt(_vec_inner_ntt(s_hat, _vec_ntt(u_prime))))
    return byte_encode(1, compress(1, w))
