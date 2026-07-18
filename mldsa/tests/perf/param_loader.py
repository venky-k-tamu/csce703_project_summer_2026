"""Load the mldsa package bound to a benchmark-only parameter set.

Only ML-DSA-65 (mldsa/params.py) is the real, NIST-ACVP-KAT-verified
implementation shipped in this repo. `load()` monkeypatches
mldsa.params' constants to a different FIPS 204 parameter set and
reloads the dependency stack in order (ntt -> rounding -> sampling ->
encoding -> mldsa -> mldsa package) so every module's
`from .params import X` re-binds to the patched values -- the *same*
algorithm code then runs unmodified against the new parameters.
(mldsa.conversions and mldsa.hashes have no params dependency and are
not reloaded.)

Correctness for non-65 sets is checked here only by a sign/verify
round trip, not by NIST ACVP vectors -- none exist for them in this repo.

Because reload() mutates process-global module state, call load() at
most once per process. bench_param_sets.py runs each parameter set in
its own subprocess (via _param_worker.py) for exactly this reason.
"""

import importlib

from . import param_sets


def load(name: str):
    """Monkeypatch + reload mldsa for parameter set `name`.

    Returns (constants, api) where `constants` is the derived parameter
    dict and `api` is a dict of keygen/sign/verify/hash_sign/hash_verify
    bound to the patched implementation.
    """
    if name not in param_sets.RAW_PARAMS:
        raise ValueError(f"unknown parameter set {name!r}, expected one of {list(param_sets.RAW_PARAMS)}")
    constants = param_sets.derive_constants(**param_sets.RAW_PARAMS[name])

    import mldsa  # noqa: F401  (first import: executes the whole stack with default 65 constants)
    import mldsa.encoding as encoding_mod
    import mldsa.mldsa as mldsa_mod
    import mldsa.ntt as ntt_mod
    import mldsa.params as params_mod
    import mldsa.rounding as rounding_mod
    import mldsa.sampling as sampling_mod

    for key, value in constants.items():
        setattr(params_mod, key, value)

    importlib.reload(ntt_mod)
    importlib.reload(rounding_mod)
    importlib.reload(sampling_mod)
    importlib.reload(encoding_mod)
    importlib.reload(mldsa_mod)
    importlib.reload(mldsa)

    api = {
        "keygen": mldsa.keygen,
        "sign": mldsa.sign,
        "verify": mldsa.verify,
        "hash_sign": mldsa.hash_sign,
        "hash_verify": mldsa.hash_verify,
    }

    pk, sk = api["keygen"]()
    msg = b"param-set self-test"
    sig = api["sign"](sk, msg, deterministic=True)
    if not api["verify"](pk, msg, sig):
        raise RuntimeError(f"self-test round trip failed for parameter set {name!r}")

    return constants, api
