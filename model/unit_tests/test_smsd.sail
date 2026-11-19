// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// Written with AI assistance: GitHub Copilot CLI, model claude-opus-5.5.

// Unit tests of Supervisor Domains (Smsd): mmpt's legalization
// (extensions/Smsd/smsd_regs.sail) and the MPT lookup's steps
// (extensions/Smsd/smsd_mpt_types.sail), on values made up for each case,
// under the default configuration's options.

private function is_fault(s : mpt_step) -> bool =
  match s { MPT_Fault() => true, _ => false }

private function is_table(s : mpt_step, a : bits(64)) -> bool =
  match s { MPT_Table(t) => t == a, _ => false }

private function is_leaf(s : mpt_step, xwr : bits(3)) -> bool =
  match s { MPT_Leaf(x) => x == xwr, _ => false }

private function selects(o : option(mpt_mode), m : mpt_mode) -> bool =
  match o { Some(n) => n == m, None() => false }

// A non-NAPOT leaf MPTE whose XWR[j] is xwr.
private function with_tuple(mpte : bits(64), j : range(0, 15), xwr : bits(3)) -> bits(64) =
  mpte | (zero_extend(xwr) << (8 + 3 * j))

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

$[test]
function test_smsd_mpt_geometry() -> unit = {
  assert(mpt_levels(MPT_Smmpt34) == 2);
  assert(mpt_levels(MPT_Smmpt43) == 3);
  assert(mpt_levels(MPT_Smmpt52) == 4);
  assert(mpt_levels(MPT_Smmpt64) == 5);
  assert(mpt_mpte_size(MPT_Smmpt34) == 4);
  assert(mpt_mpte_size(MPT_Smmpt64) == 8);

  // Smmpt34: pn[0] is bits 24..15 and pn[1] bits 33..25.
  assert(mpt_pn(MPT_Smmpt34, 0, 0x0000000001FF8000) == 1023);
  assert(mpt_pn(MPT_Smmpt34, 1, 0x00000003FE000000) == 511);
  assert(mpt_pn(MPT_Smmpt34, 0, 0x0000000002000000) == 0);
  // Smmpt43: pn[0] is bits 24..16, pn[2] bits 42..34.
  assert(mpt_pn(MPT_Smmpt43, 0, 0x0000000000050000) == 5);
  assert(mpt_pn(MPT_Smmpt43, 2, 0x0000001C00000000) == 7);
  // Smmpt64: pn[4] is bits 63..52.
  assert(mpt_pn(MPT_Smmpt64, 4, 0xFFF0000000000000) == 4095);

  assert(mpt_pa_in_range(MPT_Smmpt43, 0x0000040000000000));
  assert(not(mpt_pa_in_range(MPT_Smmpt43, 0x0000080000000000)));
  assert(mpt_pa_in_range(MPT_Smmpt52, 0x0008000000000000));
  assert(not(mpt_pa_in_range(MPT_Smmpt52, 0x0010000000000000)));
  assert(mpt_pa_in_range(MPT_Smmpt64, 0xFFFFFFFFFFFFFFFF));

  // The MPTE for pn[0] = 3 at level 0 of an Smmpt43 table at 0x1000, and for
  // pn[1] = 2 at level 1 of an Smmpt34 table at 0x2000.
  assert(mpt_mpte_addr(MPT_Smmpt43, 0, 0x0000000000001000, 0x0000000000030000) == 0x0000000000001018);
  assert(mpt_mpte_addr(MPT_Smmpt34, 1, 0x0000000000002000, 0x0000000004000000) == 0x0000000000002008);

  // A NAPOT range: 4 MiB in Smmpt34 at level 0, and 2 MiB and 1 GiB in the
  // other modes at levels 0 and 1.
  assert(mpt_napot_range_log2(MPT_Smmpt34, 0) == 22);
  assert(mpt_napot_range_log2(MPT_Smmpt43, 0) == 21);
  assert(mpt_napot_range_log2(MPT_Smmpt52, 1) == 30);
}

$[test]
function test_smsd_mpt_tuple_index() -> unit = {
  // At level 0, the most significant bits of the range offset: the page.
  assert(mpt_tuple_index(MPT_Smmpt43, 0, 0x000000000000B123) == 11);
  assert(mpt_tuple_index(MPT_Smmpt34, 0, 0x0000000000005123) == 5);
  // Above level 0, the most significant bits of pn[i - 1].
  assert(mpt_tuple_index(MPT_Smmpt43, 1, 0x0000000001400000) == 10);
  assert(mpt_tuple_index(MPT_Smmpt43, 2, 0x0000000300000000) == 12);
  assert(mpt_tuple_index(MPT_Smmpt34, 1, 0x0000000001800000) == 6);
}

$[test]
function test_smsd_mpt_step_non_leaf() -> unit = {
  let pa : bits(64) = zeros();
  // V=0.
  assert(is_fault(mpt_step_of(MPT_Smmpt43, 2, 0x0000000020000002, pa)));
  // A pointer to the table at 0x80000000, above level 0 only.
  assert(is_table(mpt_step_of(MPT_Smmpt43, 2, 0x0000000020000001, pa), 0x0000000080000000));
  assert(is_fault(mpt_step_of(MPT_Smmpt43, 0, 0x0000000020000001, pa)));
  // L=0 with N=1, and a reserved bit above PPN.
  assert(is_fault(mpt_step_of(MPT_Smmpt43, 2, 0x0000000020000005, pa)));
  assert(is_fault(mpt_step_of(MPT_Smmpt43, 2, 0x0040000020000001, pa)));
  // Smmpt34's 22-bit PPN.
  assert(is_table(mpt_step_of(MPT_Smmpt34, 1, 0x00000000FFFFFC01, pa), 0x00000003FFFFF000));
}

$[test]
function test_smsd_mpt_step_leaf() -> unit = {
  let page3 : bits(64) = 0x0000000000003000;
  let page2 : bits(64) = 0x0000000000002000;
  // V=1 with L=1: a non-NAPOT leaf MPTE, with XWR[3] read-only.
  let leaf = with_tuple(0x0000000000000003, 3, 0b001);
  // The tuple that the range offset selects.
  assert(is_leaf(mpt_step_of(MPT_Smmpt43, 0, leaf, page3), 0b001));
  assert(is_leaf(mpt_step_of(MPT_Smmpt43, 0, leaf, page2), 0b000));
  // A reserved encoding in any tuple, selected or not (the default), and a
  // reserved bit.
  assert(is_fault(mpt_step_of(MPT_Smmpt43, 0, with_tuple(leaf, 5, 0b010), page3)));
  assert(is_fault(mpt_step_of(MPT_Smmpt43, 0, with_tuple(leaf, 5, 0b110), page3)));
  assert(is_fault(mpt_step_of(MPT_Smmpt43, 0, leaf | 0x0100000000000000, page3)));
  assert(is_fault(mpt_step_of(MPT_Smmpt43, 0, leaf | 0x0000000000000008, page3)));

  // NAPOT leaves: G=4 in the RV64 modes, G=6 in Smmpt34. Bit 11 of an RV64
  // NAPOT leaf is reserved (the default).
  let napot : bits(64) = 0x0000000000004507; // G=4, XWR=101, N=L=V=1
  assert(is_leaf(mpt_step_of(MPT_Smmpt43, 1, napot, page3), 0b101));
  assert(is_fault(mpt_step_of(MPT_Smmpt43, 1, 0x0000000000003507, page3)));
  assert(is_fault(mpt_step_of(MPT_Smmpt43, 1, napot | 0x0000000000000800, page3)));
  assert(is_fault(mpt_step_of(MPT_Smmpt43, 1, 0x0000000000004607, page3)));
  assert(is_fault(mpt_step_of(MPT_Smmpt43, 1, napot | 0x0000000000010000, page3)));
  assert(is_leaf(mpt_step_of(MPT_Smmpt34, 0, 0x0000000000006307, page3), 0b011));
  assert(is_fault(mpt_step_of(MPT_Smmpt34, 0, 0x0000000000004307, page3)));
}

$[test]
function test_smsd_mpt_allows() -> unit = {
  // Read-only.
  assert(mpt_allows(0b001, Load(Data)));
  assert(mpt_allows(0b001, Load(PageTableEntry)));
  assert(not(mpt_allows(0b001, Store(Data))));
  assert(not(mpt_allows(0b001, Atomic(AMOADD, false, false, Data, Data))));
  assert(not(mpt_allows(0b001, InstructionFetch())));
  // Read-write.
  assert(mpt_allows(0b011, Store(Data)));
  assert(mpt_allows(0b011, Atomic(AMOADD, false, false, Data, Data)));
  assert(mpt_allows(0b011, Store(PageTableEntry)));
  assert(mpt_allows(0b011, CacheAccess(CB_zero())));
  // Execute-only: MXR does not make it readable.
  assert(mpt_allows(0b100, InstructionFetch()));
  assert(not(mpt_allows(0b100, Load(Data))));
  // HLVX needs execute and read (the default).
  assert(mpt_allows(0b101, LoadExecute(Data)));
  assert(not(mpt_allows(0b100, LoadExecute(Data))));
  assert(not(mpt_allows(0b001, LoadExecute(Data))));
  // Shadow-stack accesses need read and write.
  assert(not(mpt_allows(0b001, Load(ShadowStack))));
  assert(mpt_allows(0b011, Load(ShadowStack)));
  // No access.
  assert(not(mpt_allows(0b000, Load(Data))));
  assert(not(mpt_allows(0b000, CacheAccess(CB_prefetch(PREFETCH_R)))));
}
