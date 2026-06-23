"""ML-DSA-65 parameters per FIPS 204 §4 / Appendix C."""

N = 256
Q = 8380417  # = 2^23 - 2^13 + 1
D = 13

TAU = 49
LAMBDA = 192
GAMMA_1 = 1 << 19            # 524288
GAMMA_2 = (Q - 1) // 32      # 261888

K = 6
L = 5
ETA = 4
BETA = TAU * ETA             # 196
OMEGA = 55

# Bit widths used by the encoders / bit-packers.
BITLEN_T1 = 10               # bitlen(q - 1) - d  = 23 - 13
BITLEN_2_ETA = 4             # bitlen(2η) = bitlen(8)
BITLEN_T0 = D                # 13; t0 coeffs lie in (-2^(d-1), 2^(d-1)]
BITLEN_GAMMA_1 = 20          # bitlen(2γ1 - 1)
BITLEN_W1 = 4                # bitlen((q-1)/(2γ2) - 1) = bitlen(15)

# Encoded sizes (bytes), see FIPS 204 Table 1.
EK_SIZE = 32 + 32 * BITLEN_T1 * K                 # 1952
DK_SIZE = (
    32                                            # ρ
    + 32                                          # K (secret seed)
    + 64                                          # tr
    + 32 * BITLEN_2_ETA * L                       # s1 packed   (640)
    + 32 * BITLEN_2_ETA * K                       # s2 packed   (768)
    + 32 * BITLEN_T0 * K                          # t0 packed   (2496)
)                                                 # = 4032
SIG_SIZE = (
    LAMBDA // 4                                   # c_tilde     (48)
    + 32 * BITLEN_GAMMA_1 * L                     # z packed    (3200)
    + OMEGA + K                                   # hint packed (61)
)                                                 # = 3309
