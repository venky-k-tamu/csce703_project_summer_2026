"""FIPS 204 §4.2 integer / bit / byte conversions (Algorithms 9–11)."""


def integer_to_bits(x, alpha):
    """Algorithm 9. x ∈ [0, 2^α) → bit list of length α (LSB first)."""
    out = [0] * alpha
    for i in range(alpha):
        out[i] = x & 1
        x >>= 1
    return out


def bits_to_integer(y, alpha):
    """Algorithm 10. Bit list (LSB first) → integer in [0, 2^α)."""
    if len(y) < alpha:
        raise ValueError("bit list too short")
    x = 0
    for i in range(alpha):
        x |= (y[i] & 1) << i
    return x


def integer_to_bytes(x, alpha):
    """Algorithm 11. Little-endian byte encoding of x ∈ [0, 256^α)."""
    out = bytearray(alpha)
    for i in range(alpha):
        out[i] = x & 0xFF
        x >>= 8
    return bytes(out)
