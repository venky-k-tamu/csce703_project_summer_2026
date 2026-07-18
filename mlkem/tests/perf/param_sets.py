"""FIPS 203 Table 2 parameter values for the three ML-KEM parameter sets.

Only ML-KEM-768 (mlkem/params.py) ships as a real, NIST-ACVP-KAT-verified
implementation in this repo -- see CLAUDE.md. ML-KEM-512 and ML-KEM-1024
exist here purely for benchmarking: derive_constants() reproduces
mlkem/params.py's derivation formulas so the *same* unmodified algorithm
code can be run against each set's (k, eta1, eta2, du, dv) via
monkeypatch + reload -- see param_loader.py.

n = 256 and q = 3329 are fixed across every ML-KEM parameter set.
"""

N = 256
Q = 3329

# name -> (k, eta1, eta2, du, dv), FIPS 203 Table 2.
RAW_PARAMS = {
    "ML-KEM-512":  dict(k=2, eta1=3, eta2=2, du=10, dv=4),
    "ML-KEM-768":  dict(k=3, eta1=2, eta2=2, du=10, dv=4),
    "ML-KEM-1024": dict(k=4, eta1=2, eta2=2, du=11, dv=5),
}


def derive_constants(k, eta1, eta2, du, dv):
    """Reproduce mlkem/params.py's derivations for an arbitrary (k, eta1, eta2, du, dv)."""
    ek_pke_size = 384 * k + 32
    dk_pke_size = 384 * k
    ct_size = 32 * (du * k + dv)

    return {
        "N": N,
        "Q": Q,
        "K": k,
        "ETA_1": eta1,
        "ETA_2": eta2,
        "DU": du,
        "DV": dv,
        "EK_PKE_SIZE": ek_pke_size,
        "DK_PKE_SIZE": dk_pke_size,
        "CT_SIZE": ct_size,
        "EK_SIZE": ek_pke_size,
        "DK_SIZE": 768 * k + 96,
        "SS_SIZE": 32,
    }
