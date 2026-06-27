"""SLH-DSA-SHAKE-128s parameters per FIPS 205 §11.1 (Table 1)."""

# Security parameter (bytes)
N = 16

# Hypertree
H = 63       # total height
D = 7        # number of layers
HP = H // D  # h' = 9: XMSS tree height per layer

# FORS
A = 12       # log2 of FORS tree size (leaves per tree)
K = 14       # number of FORS trees

# WOTS+
LG_W = 4             # log2 of Winternitz parameter
W = 1 << LG_W        # w = 16
LEN1 = 8 * N // LG_W  # ceil(8n / lg_w) = 32
# len2 = floor(log2(len1*(w-1)) / lg_w) + 1
#      = floor(log2(480) / 4) + 1 = floor(8.9/4) + 1 = 2 + 1 = 3
LEN2 = (LEN1 * (W - 1)).bit_length() // LG_W + 1  # 3
LEN = LEN1 + LEN2    # 35

# Message digest (bytes), FIPS 205 Table 1
M_BYTES = 30

# Key sizes (bytes)
PK_SIZE = 2 * N   # PK.seed || PK.root  (32)
SK_SIZE = 4 * N   # SK.seed || SK.prf || PK.seed || PK.root  (64)

# Signature size (bytes):
#   R              = n = 16
#   FORS sig       = k * (a+1) * n = 14 * 13 * 16 = 2912
#   HT sig         = (h + d*len) * n = (63 + 7*35) * 16 = 308 * 16 = 4928
SIG_SIZE = N + K * (A + 1) * N + (H + D * LEN) * N  # 7856

# Digest split offsets (bytes within the m-byte digest)
_KA_BYTES = (K * A + 7) // 8              # ceil(ka/8) = 21
_IDX_TREE_BYTES = (H - HP + 7) // 8      # ceil((h-h')/8) = ceil(54/8) = 7
_IDX_LEAF_BYTES = (HP + 7) // 8          # ceil(h'/8) = ceil(9/8) = 2

MD_END = _KA_BYTES                        # 21
TREE_END = _KA_BYTES + _IDX_TREE_BYTES   # 28
LEAF_END = TREE_END + _IDX_LEAF_BYTES    # 30 (= M_BYTES)

# Masks for extracting tree/leaf indices from their byte fields
IDX_TREE_MASK = (1 << (H - HP)) - 1      # 54-bit mask
IDX_LEAF_MASK = (1 << HP) - 1            # 9-bit mask
