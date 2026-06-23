"""ByteEncode/ByteDecode (Alg 5/6) and Compress/Decompress from FIPS 203 §4.2.1."""

from .bytes_bits import bits_to_bytes, bytes_to_bits
from .params import N, Q


def byte_encode(d, f):
    if not 1 <= d <= 12:
        raise ValueError("d must be in 1..12")
    if len(f) != N:
        raise ValueError(f"f must have {N} coefficients")
    m = (1 << d) if d < 12 else Q
    bits = [0] * (N * d)
    for i in range(N):
        a = f[i] % m
        for j in range(d):
            bits[i * d + j] = a & 1
            a >>= 1
    return bits_to_bytes(bits)


def byte_decode(d, b):
    if not 1 <= d <= 12:
        raise ValueError("d must be in 1..12")
    if len(b) != 32 * d:
        raise ValueError(f"b must have {32 * d} bytes for d={d}")
    m = (1 << d) if d < 12 else Q
    bits = bytes_to_bits(b)
    f = [0] * N
    for i in range(N):
        v = 0
        for j in range(d):
            v |= bits[i * d + j] << j
        f[i] = v % m
    return f


def _compress_scalar(d, x):
    # round(2^d * x / q) mod 2^d, ties to nearest integer rounded up.
    return (((x % Q) << (d + 1)) + Q) // (2 * Q) & ((1 << d) - 1)


def _decompress_scalar(d, y):
    # round(q * y / 2^d), ties rounded up.
    return ((Q * (y & ((1 << d) - 1))) * 2 + (1 << d)) >> (d + 1)


def compress(d, x):
    if isinstance(x, int):
        return _compress_scalar(d, x)
    return [_compress_scalar(d, v) for v in x]


def decompress(d, y):
    if isinstance(y, int):
        return _decompress_scalar(d, y)
    return [_decompress_scalar(d, v) for v in y]
