// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// Written with AI assistance: GitHub Copilot CLI, model claude-opus-5.5.

// Supervisor Domains (Smsd), from RISC-V Supervisor Domains Access
// Protection v0.9 (below, "the text"; a reference N:L is line L of the
// text's chapter N at its tag v0.9): the fields of the mmpt CSR, the memory
// protection table (MPT) modes that it selects, and the configuration.
//
// Where the text leaves a behaviour open, the behaviour is a configuration
// option, and its default is the reading given with it.

enum mpt_mode = {MPT_Bare, MPT_Smmpt34, MPT_Smmpt43, MPT_Smmpt52, MPT_Smmpt64}

// SDIDLEN, the number of implemented SDID bits, from 0 to SDIDMAX, which is
// 6 (3:66-72).
let smsd_sdidlen : range(0, 6) = config extensions.Smsd.sdid_len

// The MPT modes that mmpt.MODE accepts, since "Implementations are not
// required to support all defined MODE settings" (3:113): Smmpt34 when XLEN
// is 32, and the others when it is 64.
let smsd_supports_smmpt34 : bool = config extensions.Smsd.modes.Smmpt34
let smsd_supports_smmpt43 : bool = config extensions.Smsd.modes.Smmpt43
let smsd_supports_smmpt52 : bool = config extensions.Smsd.modes.Smmpt52
let smsd_supports_smmpt64 : bool = config extensions.Smsd.modes.Smmpt64

// A write of an unsupported MODE "is not ignored. Instead, the fields of mmpt
// are WARL in the normal way" (3:113-116). Default: MODE keeps its value, and
// SDID and PPN take the values written.
enum SmsdUnsupportedModeWrite = {
  Smsd_KeepMode, // MODE keeps its value; SDID and PPN are written
  Smsd_ModeBare, // MODE becomes Bare; SDID and PPN are written as for Bare
  Smsd_ZeroAll,  // all of mmpt becomes zero
}
let smsd_unsupported_mode_write : SmsdUnsupportedModeWrite = config extensions.Smsd.unsupported_mode_write

// Whether SDID is writable while MODE is Bare. The text no longer has SDID
// zero under Bare, and its procedure for finding SDIDLEN names no mode
// (3:66-71). Default: writable.
let smsd_bare_sdid_writable : bool = config extensions.Smsd.bare_sdid_writable

// Under Bare, "The field PPN must be set to zeros" (3:84-87, 3:99-102).
// Default: a rule for software, so PPN keeps the value written. True makes
// PPN read as zero under Bare.
let smsd_bare_ppn_zero : bool = config extensions.Smsd.bare_ppn_zero

// The exception that MFENCE.PA and MINVAL.PA raise in VS-mode and VU-mode.
// They are "only valid in M-mode" (3:155, 3:230), so they are not
// HS-qualified, and the privileged architecture then raises an
// illegal-instruction exception, not a virtual-instruction one (the
// default).
enum SmsdFenceVirtualException = {
  Smsd_Fence_Illegal,
  Smsd_Fence_Virtual,
}
let smsd_fence_exception_in_vs_vu : SmsdFenceVirtualException = config extensions.Smsd.fence_exception_in_vs_vu

// The fields of mmpt, for either XLEN.
struct mmpt_fields = {
  mode : bits(4),
  sdid : bits(6),
  ppn  : bits(44),
}

// mmpt's layout (3:39-64). When MXLEN=32: MODE 31:30, SDID 27:22, and PPN
// 21:0. When MXLEN=64: MODE 63:60, SDID 57:52, and PPN 43:0. Its other bits
// are 0 (NZR), and read as zero (3:72-75).
function mmpt_unpack(v : xlenbits) -> mmpt_fields =
  match xlen {
    32 => struct { mode = zero_extend(v[31 .. 30]), sdid = v[27 .. 22], ppn = zero_extend(v[21 .. 0]) },
    64 => struct { mode = v[63 .. 60], sdid = v[57 .. 52], ppn = v[43 .. 0] },
    _  => internal_error(__FILE__, __LINE__, "unsupported xlen"),
  }

function mmpt_pack(f : mmpt_fields) -> xlenbits =
  match xlen {
    32 => f.mode[1 .. 0] @ 0b00 @ f.sdid @ f.ppn[21 .. 0],
    64 => f.mode @ 0b00 @ f.sdid @ 0x00 @ f.ppn,
    _  => internal_error(__FILE__, __LINE__, "unsupported xlen"),
  }

// The mode that an encoding of MODE selects, if the hart supports it
// (3:77-111). Reserved and custom encodings select none.
function mpt_mode_of_bits(m : bits(4)) -> option(mpt_mode) =
  match (xlen, m) {
    (_, 0b0000)  => Some(MPT_Bare),
    (32, 0b0001) => if smsd_supports_smmpt34 then Some(MPT_Smmpt34) else None(),
    (64, 0b0001) => if smsd_supports_smmpt43 then Some(MPT_Smmpt43) else None(),
    (64, 0b0010) => if smsd_supports_smmpt52 then Some(MPT_Smmpt52) else None(),
    (64, 0b0011) => if smsd_supports_smmpt64 then Some(MPT_Smmpt64) else None(),
    _            => None(),
  }
