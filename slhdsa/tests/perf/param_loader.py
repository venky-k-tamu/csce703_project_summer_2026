"""Load the slhdsa package bound to a benchmark-only parameter set.

Only SLH-DSA-SHAKE-128s (slhdsa/params.py) is the real, NIST-ACVP-KAT
-verified implementation shipped in this repo. `load()` monkeypatches
slhdsa.params' constants to a different FIPS 205 SHAKE parameter set's
(n, h, d, a, k) and reloads the dependency stack in order (hashes ->
wots -> xmss -> fors -> ht -> slhdsa.slhdsa -> slhdsa) so every module's
`from .params import X` / `from .hashes import Y` style imports re-bind
to the patched values -- the *same* algorithm code then runs unmodified
against the new parameters.

Correctness for non-128s sets is checked here only by a sign/verify
self-test (round trip), not by NIST ACVP vectors -- none exist for them
in this repo (see slhdsa/tests/vectors/README.md).

Because reload() mutates process-global module state, call load() at
most once per process. bench_param_sets.py runs each parameter set in
its own subprocess (via _param_worker.py) for exactly this reason.
"""

import importlib

from . import param_sets


def load(name: str):
    """Monkeypatch + reload slhdsa for parameter set `name`.

    Returns (constants, api) where `constants` is the derived parameter
    dict and `api` is a dict of keygen/sign/verify/hash_sign/hash_verify
    bound to the patched implementation.
    """
    if name not in param_sets.RAW_PARAMS:
        raise ValueError(f"unknown parameter set {name!r}, expected one of {list(param_sets.RAW_PARAMS)}")
    constants = param_sets.derive_constants(**param_sets.RAW_PARAMS[name])

    import slhdsa  # noqa: F401  (first import: executes the whole stack with default 128s constants)
    import slhdsa.fors as fors_mod
    import slhdsa.ht as ht_mod
    import slhdsa.hashes as hashes_mod
    import slhdsa.params as params_mod
    import slhdsa.slhdsa as slhdsa_mod
    import slhdsa.wots as wots_mod
    import slhdsa.xmss as xmss_mod

    for key, value in constants.items():
        setattr(params_mod, key, value)

    # Dependency order matters: each reload re-executes `from .params import X`
    # (or `from .hashes import Y`, etc.), which re-binds to whatever the
    # already-reloaded upstream module currently holds.
    importlib.reload(hashes_mod)
    importlib.reload(wots_mod)
    importlib.reload(xmss_mod)
    importlib.reload(fors_mod)
    importlib.reload(ht_mod)
    importlib.reload(slhdsa_mod)
    importlib.reload(slhdsa)

    api = {
        "keygen": slhdsa.keygen,
        "sign": slhdsa.sign,
        "verify": slhdsa.verify,
        "hash_sign": slhdsa.hash_sign,
        "hash_verify": slhdsa.hash_verify,
    }

    pk, sk = api["keygen"]()
    msg = b"param-set self-test"
    sig = api["sign"](msg, sk, randomize=False)
    if not api["verify"](msg, sig, pk):
        raise RuntimeError(f"self-test round trip failed for parameter set {name!r}")

    return constants, api
