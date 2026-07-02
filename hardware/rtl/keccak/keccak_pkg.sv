// keccak_pkg.sv — shared types, constants, and mode config for the Keccak core.
//
// FIPS 202 (SHA-3 / SHAKE). Constant tables below are transcribed from the
// standard; VERIFY against FIPS 202 Table 1 (round constants) and the rho
// offsets (§3.2.2 / Table 2) before trusting synthesis — they are the first
// suspects if a permutation KAT fails.
//
// State: A[x][y] is a 64-bit lane, x,y in 0..4. Bit (x,y,z) per §3.1.2.
// Byte <-> lane conversion is little-endian per FIPS 202 §B.1.

package keccak_pkg;

  // ---- basic types -------------------------------------------------------
  typedef logic [63:0] lane_t;
  typedef lane_t       state_t [0:4][0:4];   // A[x][y]

  localparam int NUM_ROUNDS = 24;            // for width w=64: 12 + 2*log2(w)

  // ---- round constants RC[0..23] (FIPS 202 Table 1) ----------------------
  // Function rather than an unpacked-array param, for simulator portability
  // (Icarus rejects unpacked array params; commercial tools accept both).
  function automatic lane_t rc(input int unsigned r);
    case (r)
       0: rc = 64'h0000000000000001;  1: rc = 64'h0000000000008082;
       2: rc = 64'h800000000000808A;  3: rc = 64'h8000000080008000;
       4: rc = 64'h000000000000808B;  5: rc = 64'h0000000080000001;
       6: rc = 64'h8000000080008081;  7: rc = 64'h8000000000008009;
       8: rc = 64'h000000000000008A;  9: rc = 64'h0000000000000088;
      10: rc = 64'h0000000080008009; 11: rc = 64'h000000008000000A;
      12: rc = 64'h000000008000808B; 13: rc = 64'h800000000000008B;
      14: rc = 64'h8000000000008089; 15: rc = 64'h8000000000008003;
      16: rc = 64'h8000000000008002; 17: rc = 64'h8000000000000080;
      18: rc = 64'h000000000000800A; 19: rc = 64'h800000008000000A;
      20: rc = 64'h8000000080008081; 21: rc = 64'h8000000000008080;
      22: rc = 64'h0000000080000001; 23: rc = 64'h8000000080008008;
      default: rc = 64'h0;
    endcase
  endfunction

  // ---- rho rotation offsets r[x][y] (FIPS 202 §3.2.2 / Table 2) -----------
  // Left-rotation amount (mod 64) for lane A[x][y].
  function automatic int unsigned rho(input int unsigned x, input int unsigned y);
    int unsigned t [0:24];
    t = '{  0, 36,  3, 41, 18,    // x=0, y=0..4
            1, 44, 10, 45,  2,    // x=1
           62,  6, 43, 15, 61,    // x=2
           28, 55, 25, 21, 56,    // x=3
           27, 20, 39,  8, 14 };  // x=4
    rho = t[x*5 + y];
  endfunction

  // ---- sponge mode configuration (FIPS 202 §6) ---------------------------
  typedef enum logic [1:0] {
    MODE_SHAKE128 = 2'd0,   // rate 168 B, domain 0x1F, XOF
    MODE_SHAKE256 = 2'd1,   // rate 136 B, domain 0x1F, XOF
    MODE_SHA3_256 = 2'd2,   // rate 136 B, domain 0x06, 32 B
    MODE_SHA3_512 = 2'd3    // rate  72 B, domain 0x06, 64 B
  } keccak_mode_e;

  // Rate in bytes per mode. (1600 - 2*security)/8.
  function automatic int unsigned rate_bytes(keccak_mode_e m);
    case (m)
      MODE_SHAKE128: rate_bytes = 168;
      MODE_SHAKE256: rate_bytes = 136;
      MODE_SHA3_256: rate_bytes = 136;
      MODE_SHA3_512: rate_bytes = 72;
      default:       rate_bytes = 136;
    endcase
  endfunction

  // Domain-separation / padding-start byte (pre-`pad10*1`).
  function automatic logic [7:0] domain_byte(keccak_mode_e m);
    case (m)
      MODE_SHAKE128, MODE_SHAKE256: domain_byte = 8'h1F;  // XOFs
      default:                      domain_byte = 8'h06;  // SHA3 fixed
    endcase
  endfunction

endpackage : keccak_pkg
