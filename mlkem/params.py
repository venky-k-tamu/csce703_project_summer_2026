"""ML-KEM-768 parameters per FIPS 203 §8."""

N = 256
Q = 3329

K = 3
ETA_1 = 2
ETA_2 = 2
DU = 10
DV = 4

EK_PKE_SIZE = 384 * K + 32
DK_PKE_SIZE = 384 * K
CT_SIZE = 32 * (DU * K + DV)

EK_SIZE = EK_PKE_SIZE
DK_SIZE = 768 * K + 96
SS_SIZE = 32
