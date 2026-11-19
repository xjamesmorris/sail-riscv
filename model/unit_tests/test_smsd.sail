// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// Written with AI assistance: GitHub Copilot CLI, model claude-opus-5.5.

// Unit tests of Supervisor Domains (Smsd): mmpt's legalization
// (extensions/Smsd/smsd_regs.sail), on values made up for each case, under
// the default configuration's options.

private function selects(o : option(mpt_mode), m : mpt_mode) -> bool =
  match o { Some(n) => n == m, None() => false }

$[test]
function test_smsd_mmpt_legalize() -> unit = {
  match xlen {
    64 => {
      // MODE's encodings: 4 to 13 are reserved, and 14 and 15 custom.
      assert(selects(mpt_mode_of_bits(0b0000), MPT_Bare));
      assert(selects(mpt_mode_of_bits(0b0001), MPT_Smmpt43));
      assert(selects(mpt_mode_of_bits(0b0011), MPT_Smmpt64));
      assert(not(selects(mpt_mode_of_bits(0b0100), MPT_Bare)));
      // The NZR bits, 59:58 and 51:44, read as zero.
      assert(legalize_mmpt(zeros(), 0x1D5FF00000080000) == 0x1150000000080000);
      // Under Smmpt64, bits 2:0 of PPN read as zero.
      assert(legalize_mmpt(zeros(), 0x3000000000123457) == 0x3000000000123450);
      // An unsupported MODE: MODE keeps its value, and SDID and PPN are
      // written. From Bare, with all ones, SDID's six bits and PPN as written.
      assert(legalize_mmpt(0x1150000000080000, 0x52A0000000001000) == 0x12A0000000001000);
      assert(legalize_mmpt(zeros(), ones()) == 0x03F00FFFFFFFFFFF);
    },
    _ => (),
  }
}
