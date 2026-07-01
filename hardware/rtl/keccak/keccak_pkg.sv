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
  localparam lane_t RC [0:NUM_ROUNDS-1] = '{
    64'h0000000000000001, 64'h0000000000008082,
    64'h800000000000808A, 64'h8000000080008000,
    64'h000000000000808B, 64'h0000000080000001,
    64'h8000000080008081, 64'h8000000000008009,
    64'h000000000000008A, 64'h0000000000000088,
    64'h0000000080008009, 64'h000000008000000A,
    64'h000000008000808B, 64'h800000000000008B,
    64'h8000000000008089, 64'h8000000000008003,
    64'h8000000000008002, 64'h8000000000000080,
    64'h000000000000800A, 64'h800000008000000A,
    64'h8000000080008081, 64'h8000000000008080,
    64'h0000000080000001, 64'h8000000080008008
  };

  // ---- rho rotation offsets r[x][y] (FIPS 202 §3.2.2 / Table 2) -----------
  // Indexed [x][y]; each is a left-rotation amount mod 64.
  localparam int unsigned RHO [0:4][0:4] = '{
    '{  0, 36,  3, 41, 18 },   // x=0, y=0..4
    '{  1, 44, 10, 45,  2 },   // x=1
    '{ 62,  6, 43, 15, 61 },   // x=2
    '{ 28, 55, 25, 21, 56 },   // x=3
    '{ 27, 20, 39,  8, 14 }    // x=4
  };

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
