"""BitsToBytes / BytesToBits — identical in FIPS 203 §4.2.1 (Alg 3/4)
and FIPS 204 §4.2 (Alg 12/13). Shared by both packages.
"""


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
