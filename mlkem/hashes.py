"""Hash and XOF wrappers per FIPS 203 §4.1."""

import hashlib


def H(s: bytes) -> bytes:
    return hashlib.sha3_256(s).digest()


def J(s: bytes) -> bytes:
    return hashlib.shake_256(s).digest(32)


def G(c: bytes) -> tuple[bytes, bytes]:
    h = hashlib.sha3_512(c).digest()
    return h[:32], h[32:]


def prf(eta: int, s: bytes, b: bytes) -> bytes:
    if len(s) != 32:
        raise ValueError("PRF expects a 32-byte seed s")
    if len(b) != 1:
        raise ValueError("PRF expects a 1-byte counter b")
    return hashlib.shake_256(s + b).digest(64 * eta)


class XOF:
    """Incremental SHAKE-128 stream used by SampleNTT.

    hashlib.shake_128 has no streaming squeeze API, so we re-digest a
    growing prefix on demand. Each digest call returns the same byte prefix
    as a longer one, so reads are consistent across resizes.
    """

    _INITIAL = 504  # 3 * 168, one SHAKE-128 block worth of triples

    def __init__(self, seed: bytes) -> None:
        self._seed = seed
        self._pos = 0
        self._buf = hashlib.shake_128(seed).digest(self._INITIAL)

    def read(self, n: int) -> bytes:
        if self._pos + n > len(self._buf):
            new_len = max(len(self._buf) * 2, self._pos + n)
            self._buf = hashlib.shake_128(self._seed).digest(new_len)
        out = self._buf[self._pos : self._pos + n]
        self._pos += n
        return out
