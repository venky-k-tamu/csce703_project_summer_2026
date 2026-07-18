"""FIPS 204 Table 1 parameter values for the three ML-DSA parameter sets.

Only ML-DSA-65 (mldsa/params.py) ships as a real, NIST-ACVP-KAT-verified
implementation in this repo -- see CLAUDE.md. ML-DSA-44 and ML-DSA-87
exist here purely for benchmarking: derive_constants() reproduces
mldsa/params.py's derivation formulas so the *same* unmodified algorithm
code can be run against each set's (k, l, eta, tau, lambda, gamma1,
gamma2, omega) via monkeypatch + reload -- see param_loader.py.

n = 256, q = 8380417, and d = 13 are fixed across every ML-DSA parameter set.
"""

N = 256
Q = 8380417
D = 13

# name -> (k, l, eta, tau, lam, gamma1_exp, gamma2_div, omega), FIPS 204 Table 1.
# gamma1 = 2^gamma1_exp; gamma2 = (q-1) / gamma2_div.
RAW_PARAMS = {
    "ML-DSA-44": dict(k=4, l=4, eta=2, tau=39, lam=128, gamma1_exp=17, gamma2_div=88, omega=80),
    "ML-DSA-65": dict(k=6, l=5, eta=4, tau=49, lam=192, gamma1_exp=19, gamma2_div=32, omega=55),
    "ML-DSA-87": dict(k=8, l=7, eta=2, tau=60, lam=256, gamma1_exp=19, gamma2_div=32, omega=75),
}


def derive_constants(k, l, eta, tau, lam, gamma1_exp, gamma2_div, omega):
    """Reproduce mldsa/params.py's derivations for an arbitrary parameter tuple."""
    gamma1 = 1 << gamma1_exp
    gamma2 = (Q - 1) // gamma2_div
    beta = tau * eta

    bitlen_t1 = (Q - 1).bit_length() - D          # 10, constant (q, d shared)
    bitlen_2_eta = (2 * eta).bit_length()          # 3 for eta=2, 4 for eta=4
    bitlen_t0 = D                                   # 13, constant
    bitlen_gamma1 = (2 * gamma1 - 1).bit_length()  # gamma1_exp + 1
    bitlen_w1 = ((Q - 1) // (2 * gamma2) - 1).bit_length()

    ek_size = 32 + 32 * bitlen_t1 * k
    dk_size = (
        32                                  # rho
        + 32                                # K seed
        + 64                                # tr
        + 32 * bitlen_2_eta * l             # s1 packed
        + 32 * bitlen_2_eta * k             # s2 packed
        + 32 * bitlen_t0 * k                # t0 packed
    )
    sig_size = lam // 4 + 32 * bitlen_gamma1 * l + omega + k

    return {
        "N": N,
        "Q": Q,
        "D": D,
        "TAU": tau,
        "LAMBDA": lam,
        "GAMMA_1": gamma1,
        "GAMMA_2": gamma2,
        "K": k,
        "L": l,
        "ETA": eta,
        "BETA": beta,
        "OMEGA": omega,
        "BITLEN_T1": bitlen_t1,
        "BITLEN_2_ETA": bitlen_2_eta,
        "BITLEN_T0": bitlen_t0,
        "BITLEN_GAMMA_1": bitlen_gamma1,
        "BITLEN_W1": bitlen_w1,
        "EK_SIZE": ek_size,
        "DK_SIZE": dk_size,
        "SIG_SIZE": sig_size,
    }
