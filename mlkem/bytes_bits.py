"""Algorithms 3 and 4 of FIPS 203 §4.2.1: bit/byte conversions."""


def bits_to_bytes(bits):
    if len(bits) % 8 != 0:
        raise ValueError("bit array length must be a multiple of 8")
    out = bytearray(len(bits) // 8)
    for i, bit in enumerate(bits):
        out[i // 8] |= (bit & 1) << (i % 8)
    return bytes(out)


def bytes_to_bits(data):
    bits = [0] * (8 * len(data))
    for i, byte in enumerate(data):
        for j in range(8):
            bits[8 * i + j] = (byte >> j) & 1
    return bits
