"""Load the mlkem package bound to a benchmark-only parameter set.

Only ML-KEM-768 (mlkem/params.py) is the real, NIST-ACVP-KAT-verified
implementation shipped in this repo. `load()` monkeypatches
mlkem.params' constants to a different FIPS 203 parameter set's
(k, eta1, eta2, du, dv) and reloads the dependency stack in order
(ntt -> sampling -> serialize -> kpke -> mlkem -> mlkem package) so
every module's `from .params import X` re-binds to the patched values --
the *same* algorithm code then runs unmodified against the new
parameters. (mlkem.hashes has no params dependency and is not reloaded.)

Correctness for non-768 sets is checked here only by an encaps/decaps
round trip, not by NIST ACVP vectors -- none exist for them in this repo.

Because reload() mutates process-global module state, call load() at
most once per process. bench_param_sets.py runs each parameter set in
its own subprocess (via _param_worker.py) for exactly this reason.
"""

import importlib

from . import param_sets


def load(name: str):
    """Monkeypatch + reload mlkem for parameter set `name`.

    Returns (constants, api) where `constants` is the derived parameter
    dict and `api` is a dict of keygen/encaps/decaps bound to the
    patched implementation.
    """
    if name not in param_sets.RAW_PARAMS:
        raise ValueError(f"unknown parameter set {name!r}, expected one of {list(param_sets.RAW_PARAMS)}")
    constants = param_sets.derive_constants(**param_sets.RAW_PARAMS[name])

    import mlkem  # noqa: F401  (first import: executes the whole stack with default 768 constants)
    import mlkem.kpke as kpke_mod
    import mlkem.mlkem as mlkem_mod
    import mlkem.ntt as ntt_mod
    import mlkem.params as params_mod
    import mlkem.sampling as sampling_mod
    import mlkem.serialize as serialize_mod

    for key, value in constants.items():
        setattr(params_mod, key, value)

    importlib.reload(ntt_mod)
    importlib.reload(sampling_mod)
    importlib.reload(serialize_mod)
    importlib.reload(kpke_mod)
    importlib.reload(mlkem_mod)
    importlib.reload(mlkem)

    api = {
        "keygen": mlkem.keygen,
        "encaps": mlkem.encaps,
        "decaps": mlkem.decaps,
    }

    ek, dk = api["keygen"]()
    ss, ct = api["encaps"](ek)
    ss2 = api["decaps"](dk, ct)
    if ss != ss2:
        raise RuntimeError(f"self-test round trip failed for parameter set {name!r}")

    return constants, api
