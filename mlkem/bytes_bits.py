"""Re-exports the shared bit/byte conversions for the FIPS 203 module structure.

The actual implementation lives in `common.bytes_bits` because FIPS 204
specifies the same algorithms.
"""

from common.bytes_bits import bits_to_bytes, bytes_to_bits

__all__ = ["bits_to_bytes", "bytes_to_bits"]
