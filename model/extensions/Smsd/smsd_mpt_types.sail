// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// Written with AI assistance: GitHub Copilot CLI, model claude-opus-5.5.

// The memory protection table (MPT) of Supervisor Domains (Smsd), the
// text's chapter 4 (see smsd_types.sail): the geometry of each mode, and the
// steps of the "MPT access type permissions lookup process" (4:185-233) as
// pure functions. The walk that reads MPTEs is in smsd_mpt.sail.
//
// Physical addresses and MPTEs are 64-bit values here: an RV32 physical
// address (34 bits) and an Smmpt34 MPTE (32 bits) are zero-extended.

// Options for behaviours that the text leaves open (see smsd_types.sail).

// Step 3 of the lookup raises an access fault "if any bits or encodings that
// are reserved for future standard use are set within mpte" (4:199-202).
// Default: that covers every XWR tuple of a leaf MPTE, whether or not the
// access selects it. False checks only the tuple that the access selects.
let smsd_reserved_xwr_any_tuple : bool = config extensions.Smsd.reserved_xwr_any_tuple

// Bit 11 of an RV64 NAPOT leaf MPTE, drawn "0" (4:336) where Smmpt34's is
// "Reserved" (4:91). Default: reserved, so that step 3 faults when it is set.
let smsd_napot_bit11_reserved : bool = config extensions.Smsd.napot_bit11_reserved

// What an HLVX needs in the MPT. "The MXR mechanisms or the use of HLVX
// instruction cannot be used to affect or override the interpretation of
// permissions encoded in memory-protection-table entries" (4:224-226), so
// an execute-only page refuses an HLVX either way. Default: execute and
// read, the answer given to the text's issue 202. Smsd_HLVX_Read: read.
enum SmsdHlvxPermission = {
  Smsd_HLVX_ExecuteAndRead,
  Smsd_HLVX_Read,
}
let smsd_hlvx_permission : SmsdHlvxPermission = config extensions.Smsd.hlvx_permission

// Where an MPT access fault is taken. Each step of the lookup that refuses an
// access raises "an access-fault exception corresponding to the original
// access type" (4:194-222), which medeleg and hedeleg may delegate as any
// other, while the text's introduction says that "An MPT access violation is
// always reported as a trap to the M-mode RDSM" (its lines 138-139).
// Default: as any other access fault.
enum SmsdMptFaultTarget = {
  Smsd_MPT_Fault_Delegable, // medeleg and hedeleg apply
  Smsd_MPT_Fault_Machine,   // always taken in M-mode
}
let smsd_mpt_fault_target : SmsdMptFaultTarget = config extensions.Smsd.mpt_fault_target

// What applies when the MPTEs of a NAPOT range differ. "All leaf MPTEs at that
// level of this NAPOT memory protection range have the same value for L, N,
// XWR and V bits" (4:131-132) binds software, and the text expects that a
// range "may be cached as a single cache entry" (4:138-142). Default: false,
// so each access uses the MPTE that its walk reads. True keeps the last NAPOT
// range that a walk found as one entry, whose XWR then applies to each page
// of the range until mmpt is written or a fence is executed.
let smsd_napot_range_cache : bool = config extensions.Smsd.napot_range_cache

// LEVELS: the number of levels of the table.
function mpt_levels(mode : mpt_mode) -> range(0, 5) =
  match mode {
    MPT_Bare    => 0,
    MPT_Smmpt34 => 2,
    MPT_Smmpt43 => 3,
    MPT_Smmpt52 => 4,
    MPT_Smmpt64 => 5,
  }

// MPTESIZE: the size of an MPTE in bytes.
function mpt_mpte_size(mode : mpt_mode) -> {4, 8} =
  match mode {
    MPT_Smmpt34 => 4,
    _           => 8,
  }

// NUMPGINRANGE: the number of range-offset bits that select the XWR tuple of
// a non-NAPOT leaf MPTE, which has eight tuples in Smmpt34 and sixteen in the
// other modes.
function mpt_numpginrange(mode : mpt_mode) -> {3, 4} =
  match mode {
    MPT_Smmpt34 => 3,
    _           => 4,
  }

// The lowest bit of pa.pn[i]. Smmpt34 has a 15-bit range offset, then pn[0]
// of 10 bits and pn[1] of 9. The other modes have a 16-bit range offset,
// then pn[0] to pn[3] of 9 bits each, and in Smmpt64 pn[4] of 12.
function mpt_pn_lsb(mode : mpt_mode, i : range(0, 4)) -> range(15, 52) =
  match mode {
    MPT_Smmpt34 => if i == 0 then 15 else 25,
    _           => 16 + 9 * i,
  }

// pa.pn[i].
function mpt_pn(mode : mpt_mode, i : range(0, 4), pa : bits(64)) -> range(0, 4095) = {
  let field = (pa >> mpt_pn_lsb(mode, i))[11 .. 0];
  match (mode, i) {
    (MPT_Smmpt34, 0) => unsigned(field[9 .. 0]),
    (MPT_Smmpt64, 4) => unsigned(field),
    (_, _)           => unsigned(field[8 .. 0]),
  }
}

// Smmpt43 and Smmpt52 raise an access fault for a physical address with any
// bit set above their 43 and 52 bits.
function mpt_pa_in_range(mode : mpt_mode, pa : bits(64)) -> bool =
  match mode {
    MPT_Smmpt43 => pa[63 .. 43] == zeros(),
    MPT_Smmpt52 => pa[63 .. 52] == zeros(),
    _           => true,
  }

// Step 2: the address of the MPTE for pa at level i, in the table at a.
function mpt_mpte_addr(mode : mpt_mode, i : range(0, 4), a : bits(64), pa : bits(64)) -> bits(64) = {
  let offset : range(0, 32760) = mpt_pn(mode, i, pa) * mpt_mpte_size(mode);
  a + to_bits(offset)
}

// The reserved bits of an MPTE, by its kind, which raise an access fault when
// set (step 3). For a non-leaf MPTE they include N, bit 2, so that L=0 with
// N=1 is among them. Bit 11 of an RV64 NAPOT leaf is an option (see
// smsd_types.sail).
function mpt_reserved_mask(mode : mpt_mode, leaf : bool, napot : bool) -> bits(64) =
  match (mode, leaf, napot) {
    (MPT_Smmpt34, false, _)    => 0x00000000000003FC, // 9..2
    (MPT_Smmpt34, true, false) => 0x00000000000000F8, // 7..3
    (MPT_Smmpt34, true, true)  => 0x00000000FFFF08F8, // 31..16, 11, 7..3
    (_, false, _)              => 0xFFC00000000003FC, // 63..54, 9..2
    (_, true, false)           => 0xFF000000000000F8, // 63..56, 7..3
    (_, true, true)            =>
      if smsd_napot_bit11_reserved
      then 0xFFFFFFFFFFFF08F8 // 63..16, 11, 7..3
      else 0xFFFFFFFFFFFF00F8, // 63..16, 7..3
  }

// The encodings 010 and 110 of an XWR tuple, write without read, are
// "Reserved for future use" (4:159-172).
function mpt_xwr_reserved(xwr : bits(3)) -> bool = xwr[1] == 0b1 & xwr[0] == 0b0

// XWR[j] of a non-NAPOT leaf MPTE.
function mpt_leaf_xwr(mpte : bits(64), j : range(0, 15)) -> bits(3) =
  (mpte >> (8 + 3 * j))[2 .. 0]

// Step 5: the index pi of the XWR tuple that applies to pa, for a non-NAPOT
// leaf found at level i: the NUMPGINRANGE most significant bits of
// pa.pn[i - 1], or for i = 0 of the range offset. Those are the bits just
// below pa.pn[i].
function mpt_tuple_index(mode : mpt_mode, i : range(0, 4), pa : bits(64)) -> range(0, 15) = {
  let n = mpt_numpginrange(mode);
  let bits_below = pa >> (mpt_pn_lsb(mode, i) - n);
  if n == 3 then unsigned(bits_below[2 .. 0]) else unsigned(bits_below[3 .. 0])
}

// The one encoding of G that each mode does not reserve: G=6 (128 MPTEs) in
// Smmpt34, and G=4 (32 MPTEs) in the other modes.
function mpt_napot_g(mode : mpt_mode) -> bits(4) =
  match mode {
    MPT_Smmpt34 => 0b0110,
    _           => 0b0100,
  }

// The log2 of the size in bytes of a NAPOT range found at level i: 2^(G+1)
// MPTEs (4:130-131), each covering the bits below pa.pn[i]. So a range of
// 4 MiB in Smmpt34 at level 0 (4:144-145), and of 2 MiB and 1 GiB in the
// other modes at levels 0 and 1 (4:353-354).
function mpt_napot_range_log2(mode : mpt_mode, i : range(0, 4)) -> range(20, 59) =
  match mode {
    MPT_Smmpt34 => mpt_pn_lsb(mode, i) + 7,
    _           => mpt_pn_lsb(mode, i) + 5,
  }

union mpt_step = {
  MPT_Table : bits(64), // a non-leaf MPTE: the address of the next table
  MPT_Leaf  : bits(3),  // a leaf MPTE: the XWR that applies
  MPT_Fault : unit,     // stop, and raise an access fault
}

// Steps 3 to 6, for the MPTE read for pa at level i.
function mpt_step_of(mode : mpt_mode, i : range(0, 4), mpte : bits(64), pa : bits(64)) -> mpt_step = {
  let valid = mpte[0] == 0b1;
  let leaf = mpte[1] == 0b1;
  let napot = mpte[2] == 0b1;
  if not(valid) | (mpte & mpt_reserved_mask(mode, leaf, napot)) != zeros() then return MPT_Fault();
  if not(leaf) then {
    // Step 4: a pointer to the next level, unless this is the last.
    if i == 0 then return MPT_Fault();
    let ppn : bits(44) = match mode {
      MPT_Smmpt34 => zero_extend(mpte[31 .. 10]),
      _           => mpte[53 .. 10],
    };
    return MPT_Table(zero_extend(ppn @ zeros(12)))
  };
  if napot then {
    // Step 6, and step 3's reserved encodings.
    let xwr = mpte[10 .. 8];
    if mpt_xwr_reserved(xwr) | mpte[15 .. 12] != mpt_napot_g(mode)
    then MPT_Fault()
    else MPT_Leaf(xwr)
  } else {
    // Step 3's reserved encodings, then step 5.
    let xwr = mpt_leaf_xwr(mpte, mpt_tuple_index(mode, i, pa));
    if mpt_xwr_reserved(xwr) then return MPT_Fault();
    if smsd_reserved_xwr_any_tuple then {
      let tuples : {8, 16} = if mpt_numpginrange(mode) == 3 then 8 else 16;
      foreach (j from 0 to (tuples - 1)) {
        if mpt_xwr_reserved(mpt_leaf_xwr(mpte, j)) then return MPT_Fault()
      }
    };
    MPT_Leaf(xwr)
  }
}

// Step 7: whether XWR allows the access. "Access type permissions --
// readable, writable, or executable -- are checked by MPT the same as for
// VS-stage and G-stage translation"; a read or a write of a page table is
// checked as an implicit load or store (4:174-180). As for PMP, an AMO needs
// read and write permission. A shadow-stack access needs read and write
// (4:228-229). MXR has no effect (4:224-226), and HLVX needs what the
// configuration says (see smsd_hlvx_permission).
function mpt_allows(xwr : bits(3), access : MemoryAccessType(mem_payload)) -> bool = {
  let r = xwr[0] == 0b1;
  let w = xwr[1] == 0b1;
  let x = xwr[2] == 0b1;
  match access {
    Load(ShadowStack)                         => r & w,
    Store(ShadowStack)                        => r & w,
    Atomic(_, _, _, ShadowStack, ShadowStack) => r & w,
    Load(_)                                   => r,
    Store(_)                                  => w,
    LoadReserved(_, _, _)                     => r,
    StoreConditional(_, _, _)                 => w,
    Atomic(_, _, _, _, _)                     => r & w,
    LoadExecute(_)                            => match smsd_hlvx_permission {
      Smsd_HLVX_ExecuteAndRead => x & r,
      Smsd_HLVX_Read           => r,
    },
    InstructionFetch()                        => x,
    CacheAccess(CB_zero())                    => w,
    CacheAccess(CB_manage(_))                 => r | w,
    CacheAccess(CB_prefetch(p))               => match p {
      PREFETCH_I => x,
      PREFETCH_R => r,
      PREFETCH_W => w,
    },
  }
}
