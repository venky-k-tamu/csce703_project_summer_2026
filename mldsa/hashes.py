"""SHAKE wrappers per FIPS 204 §4.1, plus incremental XOFs for samplers.

FIPS 204 uses SHAKE-128 (G/XOF) for ExpandA / RejNTTPoly and SHAKE-256 (H)
for everything else.
"""

import hashlib


def H(data: bytes, length: int) -> bytes:
    return hashlib.shake_256(data).digest(length)


def G(data: bytes, length: int) -> bytes:
    return hashlib.shake_128(data).digest(length)


class _Stream:
    """Re-digesting XOF stream — hashlib SHAKE has no streaming squeeze."""

    _shake = None
    _INITIAL = 504

    def __init__(self, seed: bytes) -> None:
        self._seed = seed
        self._pos = 0
        self._buf = self._shake(seed).digest(self._INITIAL)

    def read(self, n: int) -> bytes:
        if self._pos + n > len(self._buf):
            new_len = max(len(self._buf) * 2, self._pos + n)
            self._buf = self._shake(self._seed).digest(new_len)
        out = self._buf[self._pos : self._pos + n]
        self._pos += n
        return out


class XOF128(_Stream):
    _shake = staticmethod(hashlib.shake_128)


class XOF256(_Stream):
    _shake = staticmethod(hashlib.shake_256)
