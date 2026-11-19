// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// Written with AI assistance: GitHub Copilot CLI, model claude-opus-5.5.

// The memory protection table (MPT) walk of Supervisor Domains (Smsd), the
// text's chapter 4 (see smsd_types.sail). While mmpt.MODE is not Bare, an
// access made with an effective privilege below M-mode is allowed only if
// the MPTE for its physical address allows it. That covers implicit
// accesses: a read or a write of a VS-stage or a G-stage page table is
// checked as a load or a store, and its fault is reported for the original
// access type (4:174-180), as the page-table walker reports a PMP fault.
// The steps of the lookup are in smsd_mpt_types.sail.
//
// The model keeps no MPT cache, unless the configuration keeps a NAPOT range
// as one entry (smsd_napot_range_cache): otherwise each access walks the
// table as it is in memory.

// Step 1: the physical address of the root table.
private function mpt_root() -> bits(64) = zero_extend(mmpt_unpack(mmpt).ppn @ zeros(12))

// Step 2's read of an MPTE: an implicit M-mode access, checked by PMP
// (4:231-233), and by the PMAs as a read of a page-table entry. None() if a
// check fails, or if the MPTE is not in main memory. The model supports only
// little-endian accesses (mstatus.MBE = 0).
private function mpte_read(addr : bits(64), size : {4, 8}) -> option(bits(64)) = {
  let paddr = Physaddr(trunc(addr));
  match pmpCheck(paddr, size, Load(PageTableEntry), Machine) {
    Some(_) => return None(),
    None()  => (),
  };
  match matching_pma_region(pma_regions, paddr, size) {
    None() => None(),
    Some(struct { attributes, _ }) =>
      if attributes.supports_pte_read & not(within_mmio_readable(paddr, size)) then {
        let (value, _) = read_ram(Read_plain, Load(PageTableEntry), paddr, size, false);
        Some(zero_extend(value))
      } else None(),
  }
}

// Keeps the NAPOT range that holds pa, found at level i, as one entry with
// its XWR (smsd_napot_range_cache).
private function mpt_keep_range(mode : mpt_mode, i : range(0, 4), pa : bits(64), xwr : bits(3)) -> unit = {
  let mask : bits(64) = ones(64) << mpt_napot_range_log2(mode, i);
  mpt_range_valid = true;
  mpt_range_base = pa & mask;
  mpt_range_mask = mask;
  mpt_range_xwr = xwr;
}

// Steps 1 to 7: whether the MPT allows the access in the page of pa.
private function mpt_allows_page(mode : mpt_mode, pa : bits(64), access : MemoryAccessType(mem_payload)) -> bool = {
  if not(mpt_pa_in_range(mode, pa)) then return false;
  // A NAPOT range kept as one entry gives each of its pages its XWR.
  if smsd_napot_range_cache & mpt_range_valid & (pa & mpt_range_mask) == mpt_range_base
  then return mpt_allows(mpt_range_xwr, access);
  let levels = mpt_levels(mode);
  assert(levels >= 2, "the MPT walk needs a mode other than Bare");
  var a : bits(64) = mpt_root();
  foreach (i from (levels - 1) downto 0) {
    match mpte_read(mpt_mpte_addr(mode, i, a, pa), mpt_mpte_size(mode)) {
      None()     => return false,
      Some(mpte) => match mpt_step_of(mode, i, mpte, pa) {
        MPT_Table(next) => a = next,
        MPT_Leaf(xwr)   => {
          // N=1: a NAPOT leaf.
          if smsd_napot_range_cache & mpte[2] == 0b1 then mpt_keep_range(mode, i, pa, xwr);
          return mpt_allows(xwr, access)
        },
        MPT_Fault()     => return false,
      },
    }
  };
  // Not reached: at level 0, mpt_step_of takes a non-leaf MPTE as a fault.
  false
}

// Whether the MPT has refused one of the current instruction's accesses. A
// refusal ends the instruction's accesses: the instruction raises the access
// fault, or a prefetch or a fault-only-first load does not. So an access
// fault that the instruction raises after a refusal is the MPT's.
register mpt_refused : bool = false

// Before each instruction (ext_pre_step_hook calls it).
function smsd_pre_step() -> unit = {
  mpt_refused = false
}

// Whether the MPT allows an access of width bytes at paddr, made with the
// effective privilege priv: None() if it does, or if it does not apply, and
// otherwise an access fault for the access type. mmpt is active unless the
// effective privilege is M (3:125-126), and the access must be allowed in
// each page that it touches.
function mpt_access_check forall 'n, 0 < 'n <= max_mem_access . (
  paddr  : physaddr,
  width  : int('n),
  access : MemoryAccessType(mem_payload),
  priv   : Privilege,
) -> option(ExceptionType) = {
  if priv == Machine | not(currentlyEnabled(Ext_Smsd)) then return None();
  let mode : mpt_mode = match mpt_mode_of_bits(mmpt_unpack(mmpt).mode) {
    Some(m) => m,
    None()  => internal_error(__FILE__, __LINE__, "mmpt holds an unsupported MODE"),
  };
  if mode == MPT_Bare then return None();
  let first : bits(64) = zero_extend(bits_of(paddr));
  let last = first + to_bits(width - 1);
  let allowed = mpt_allows_page(mode, first, access)
    & (last[63 .. 12] == first[63 .. 12] | mpt_allows_page(mode, last, access));
  if allowed then return None();
  mpt_refused = true;
  Some(accessFaultFromAccessType(access))
}

// The memory path's check (see mptCheck in sys/mem.sail).
function mptCheck(paddr, width, access, priv) = mpt_access_check(paddr, width, access, priv)

// Whether exception e is an MPT access fault that the configuration has taken
// in M-mode, whatever medeleg and hedeleg say (smsd_mpt_fault_target).
function mpt_fault_in_machine(e : ExceptionType) -> bool =
  smsd_mpt_fault_target == Smsd_MPT_Fault_Machine & mpt_refused & (match e {
    E_Fetch_Access_Fault() => true,
    E_Load_Access_Fault()  => true,
    E_SAMO_Access_Fault()  => true,
    _                      => false,
  })
