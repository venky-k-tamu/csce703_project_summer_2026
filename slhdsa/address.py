"""ADRS (address) structure for SLH-DSA per FIPS 205 §4.

ADRS is a 32-byte bytearray with the following layout:

  [0:4]   layer_address  (big-endian uint32)
  [4:16]  tree_address   (12 bytes: 4 bytes padding + 8-byte big-endian uint64)
  [16:20] type           (big-endian uint32)
  [20:32] type-specific  (12 bytes)

Type-specific fields by type:
  WOTS_HASH / WOTS_PRF:  [20:24] key_pair  [24:28] chain  [28:32] hash
  WOTS_PK  / FORS_ROOTS: [20:24] key_pair  [24:32] (zeros)
  TREE:                  [20:24] (zeros)    [24:28] tree_height  [28:32] tree_index
  FORS_TREE / FORS_PRF:  [20:24] key_pair  [24:28] tree_height  [28:32] tree_index
"""

# ADRS type constants (FIPS 205 §4)
WOTS_HASH  = 0
WOTS_PK    = 1
TREE       = 2
FORS_TREE  = 3
FORS_ROOTS = 4
WOTS_PRF   = 5
FORS_PRF   = 6


def new_adrs() -> bytearray:
    return bytearray(32)


def copy_adrs(adrs: bytearray) -> bytearray:
    return bytearray(adrs)


# ---- Layer ---------------------------------------------------------------

def set_layer_address(adrs: bytearray, layer: int) -> None:
    adrs[0:4] = layer.to_bytes(4, "big")


def get_layer_address(adrs: bytearray) -> int:
    return int.from_bytes(adrs[0:4], "big")


# ---- Tree ----------------------------------------------------------------

def set_tree_address(adrs: bytearray, tree: int) -> None:
    adrs[4:8] = b"\x00" * 4               # 4-byte padding (spec §4)
    adrs[8:16] = tree.to_bytes(8, "big")  # 8-byte tree index


def get_tree_address(adrs: bytearray) -> int:
    return int.from_bytes(adrs[8:16], "big")


# ---- Type ----------------------------------------------------------------

def set_type_and_clear(adrs: bytearray, t: int) -> None:
    """Set the type field and zero out the 12 type-specific bytes."""
    adrs[16:20] = t.to_bytes(4, "big")
    adrs[20:32] = b"\x00" * 12


def get_type(adrs: bytearray) -> int:
    return int.from_bytes(adrs[16:20], "big")


# ---- Type-specific fields ------------------------------------------------

def set_key_pair_address(adrs: bytearray, kp: int) -> None:
    adrs[20:24] = kp.to_bytes(4, "big")


def get_key_pair_address(adrs: bytearray) -> int:
    return int.from_bytes(adrs[20:24], "big")


def set_chain_address(adrs: bytearray, c: int) -> None:
    adrs[24:28] = c.to_bytes(4, "big")


def set_hash_address(adrs: bytearray, h: int) -> None:
    adrs[28:32] = h.to_bytes(4, "big")


def set_tree_height(adrs: bytearray, height: int) -> None:
    adrs[24:28] = height.to_bytes(4, "big")


def get_tree_height(adrs: bytearray) -> int:
    return int.from_bytes(adrs[24:28], "big")


def set_tree_index(adrs: bytearray, idx: int) -> None:
    adrs[28:32] = idx.to_bytes(4, "big")


def get_tree_index(adrs: bytearray) -> int:
    return int.from_bytes(adrs[28:32], "big")
