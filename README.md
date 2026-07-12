# CSCE 703 — NIST PQC Reference Implementations

From-scratch, spec-faithful Python reference implementations of three NIST
post-quantum cryptography standards:

| Package  | Standard | Scheme | Purpose |
|----------|----------|--------|---------|
| `mlkem/`  | [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | **ML-KEM-768**          | Key encapsulation (KEM) |
| `mldsa/`  | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | **ML-DSA-65**           | Digital signatures (lattice) |
| `slhdsa/` | [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) | **SLH-DSA-SHAKE-128s**  | Digital signatures (hash-based) |

The code prioritizes **spec fidelity over performance**: every module maps to
a specific FIPS section and references the corresponding algorithm numbers in
its docstrings, so it can be audited against the standard line by line.

> ⚠️ **Not for production use.** This is an educational reference
> implementation. It is deliberately *not* constant-time and applies no
> side-channel or performance hardening. Do not use it to protect real data.

## Status

All three algorithms are complete and verified against the official
[NIST ACVP](https://github.com/usnistgov/ACVP-Server) known-answer test (KAT)
vectors plus in-house unit and property tests.

| Scheme                | NIST ACVP KATs | In-house | Total |
|-----------------------|:--------------:|:--------:|:-----:|
| ML-KEM-768            | 80             | 73       | 153   |
| ML-DSA-65             | 115            | 119      | 234   |
| SLH-DSA-SHAKE-128s    | 76             | 105      | 181   |
| **Total**             | **271**        | **297**  | **568** |

### NIST ACVP known-answer tests

Official [ACVP](https://github.com/usnistgov/ACVP-Server) prompt/expected
vector pairs live under each package's `tests/vectors/` and are replayed by
`test_<scheme>_kat.py`. Coverage by scheme:

- **ML-KEM-768 (80 cases):** `keyGen`, `encapsulation`, `decapsulation`, plus
  the `encapsulationKeyCheck` and `decapsulationKeyCheck` input-validation
  suites (FIPS 203 §7).
- **ML-DSA-65 (115 cases):** `keyGen`, and `sigGen`/`sigVer` for both
  pure ML-DSA and HashML-DSA, exercising deterministic and hedged signing.
- **SLH-DSA-SHAKE-128s (76 cases):** `keyGen`, and `sigGen`/`sigVer` for both
  pure SLH-DSA and HashSLH-DSA, deterministic and hedged. Vectors are filtered
  to the implemented SHAKE / "s" / external interface (see
  `slhdsa/tests/vectors/README.md`).

### In-house tests

Unit tests pin each internal layer to its FIPS pseudocode, and
[Hypothesis](https://hypothesis.readthedocs.io/) property tests check
end-to-end invariants (e.g. encaps/decaps agreement, sign→verify round-trips)
over randomized inputs. Coverage by scheme:

- **ML-KEM-768:** `bytes_bits`, `hashes` (H/J/G/PRF/XOF), `ntt`, `sampling`,
  `serialize` (ByteEncode/Decode, Compress/Decompress), `kpke`, and property
  tests.
- **ML-DSA-65:** `conversions`, `encoding` (BitPack/HintBitPack), `rounding`
  (Power2Round/Decompose/MakeHint), `ntt`, `sampling`, `hashes`, the public
  `api`, and property tests.
- **SLH-DSA-SHAKE-128s:** `address` (ADRS layout), `hashes`, `params`, and the
  `wots` → `xmss` → `ht`/`fors` component stack, plus the public `api` and
  property tests.

## Requirements

- **Python 3.10+** (uses PEP 604 `X | Y` typing and `pow(x, -1, m)` modular
  inverse). No third-party runtime dependencies — only the standard library.
- Dev tools (`pytest`, `hypothesis`) are declared under the `dev` extra.

## Install

```bash
python3 -m pip install -e ".[dev]"    # editable install + test tools
```

## Running the tests

From the repo root (`pyproject.toml` sets `testpaths`):

```bash
python3 -m pytest                     # full suite (all three schemes)
python3 -m pytest mlkem/tests/        # ML-KEM only
python3 -m pytest mldsa/tests/        # ML-DSA only
python3 -m pytest slhdsa/tests/       # SLH-DSA only
python3 -m pytest -k "kat and keygen" # by keyword
```

> **Note:** SLH-DSA-SHAKE-128s is the small-signature / slow-signing variant —
> each signature performs hundreds of thousands of SHAKE256 calls, so the
> `slhdsa/` sigGen/sigVer KATs take minutes. Scope to a package or file (or
> raise your timeout) when iterating; the full run can exceed a 2-minute limit.

## Usage

Each package exposes a small public API mirroring the FIPS external interface.
Keys and signatures are `bytes`.

### ML-KEM-768 — key encapsulation

```python
import mlkem

ek, dk = mlkem.keygen()        # (encapsulation key, decapsulation key)
K, c   = mlkem.encaps(ek)      # (shared secret, ciphertext) — sender side
K2     = mlkem.decaps(dk, c)   # shared secret — receiver side
assert K == K2
```

### ML-DSA-65 — signatures

```python
import mldsa

pk, sk = mldsa.keygen()                      # (public key, secret key)
sig    = mldsa.sign(sk, b"message", ctx=b"") # hedged by default
assert mldsa.verify(pk, b"message", sig, ctx=b"")

# Deterministic signing, and the pre-hash (HashML-DSA) interface:
sig_d  = mldsa.sign(sk, b"message", deterministic=True)
sig_h  = mldsa.hash_sign(sk, b"message", hash_alg="SHA2-512")
assert mldsa.hash_verify(pk, b"message", sig_h, hash_alg="SHA2-512")
```

### SLH-DSA-SHAKE-128s — signatures

Note the message-first argument order (`sign(m, sk)`), which differs from
ML-DSA's `sign(sk, M)`.

```python
import slhdsa

pk, sk = slhdsa.keygen()                       # (public key, secret key)
sig    = slhdsa.sign(b"message", sk, ctx=b"")  # hedged by default
assert slhdsa.verify(b"message", sig, pk, ctx=b"")

# Deterministic signing, and the pre-hash (HashSLH-DSA) interface:
sig_d  = slhdsa.sign(b"message", sk, randomize=False)
sig_h  = slhdsa.hash_sign(b"message", sk, hash_alg="SHA2-512")
assert slhdsa.hash_verify(b"message", sig_h, pk, hash_alg="SHA2-512")
```

## Repository layout

```
common/        # primitives proven-shared across standards (BitsToBytes/BytesToBits)
mlkem/         # FIPS 203 ML-KEM-768   — lattice/NTT-based KEM
mldsa/         # FIPS 204 ML-DSA-65    — lattice/NTT-based signatures
slhdsa/        # FIPS 205 SLH-DSA-SHAKE-128s — hash-based signatures (Merkle/XMSS/FORS)
hardware/      # SystemVerilog Keccak-f[1600] / SHAKE accelerator (shared PQC core)
visualization/ # interactive webpages: SLH-DSA (slh-dsa.html) and ML-KEM (mlkem.html)
docs/          # PLAN.md (authoritative plan) + PROMPTS.md (design-decision log)
```

Each algorithm package's modules form a bottom-up dependency stack where every
layer only uses those below it, and tests live in-package under
`<pkg>/tests/`. See [`CLAUDE.md`](CLAUDE.md) for the per-package module-to-FIPS
mapping, ring/NTT details, and implementation gotchas; see
[`docs/PLAN.md`](docs/PLAN.md) for the authoritative project plan.

## Companion artifacts

Two directories accompany the Python reference implementations:

- **`hardware/`** — a from-scratch SystemVerilog **Keccak-f[1600] / SHAKE /
  SHA3** accelerator, the one primitive every scheme depends on. The core
  (`keccak_round`, `keccak_f1600`, `keccak_sponge`, `shake_xof`) is functional
  and passes a self-checking Icarus smoke test against Python `hashlib` golden
  vectors (`make smoke`). See [`hardware/README.md`](hardware/README.md).
- **`visualization/`** — self-contained interactive webpages (no build step,
  no dependencies; open directly in a browser). `slh-dsa.html` walks through the
  SLH-DSA-SHAKE-128s building blocks (WOTS+, XMSS, FORS, hypertree);
  `mlkem.html` walks through ML-KEM (the module-LWE key equation, NTT, sampling,
  compression, and the encaps/decaps flow). Both support all parameter sets via
  a selector.

## Scope & non-goals

- **Only** ML-KEM-768, ML-DSA-65, and SLH-DSA-SHAKE-128s parameter sets are
  implemented — not the other sizes.
- For SLH-DSA, only the **SHAKE**, **"s"** (small), **external** interface is
  provided: no SHA-2 instantiations, no "f" (fast) variant, and no internal
  signature interface.
- No constant-time behavior and no performance optimizations — explicit
  non-goals per `docs/PLAN.md`.

## License / attribution

CSCE 703 course project, Texas A&M University (Summer 2026). Test vectors are
derived from the public NIST ACVP test suite.
