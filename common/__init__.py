"""Primitives shared between mlkem and mldsa.

Only code that is *literally identical* between FIPS 203 and FIPS 204
belongs here. Different rings (q = 3329 vs 8380417), different zetas,
and different sampling distributions mean that NTT, sampling, and most
encoding logic must stay per-algorithm.
"""
