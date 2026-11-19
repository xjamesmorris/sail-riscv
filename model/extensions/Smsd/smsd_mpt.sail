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
// The model keeps no MPT cache: each access walks the table as it is in
// memory.

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

// Steps 1 to 7: whether the MPT allows the access in the page of pa.
private function mpt_allows_page(mode : mpt_mode, pa : bits(64), access : MemoryAccessType(mem_payload)) -> bool = {
  if not(mpt_pa_in_range(mode, pa)) then return false;
  let levels = mpt_levels(mode);
  assert(levels >= 2, "the MPT walk needs a mode other than Bare");
  var a : bits(64) = mpt_root();
  foreach (i from (levels - 1) downto 0) {
    match mpte_read(mpt_mpte_addr(mode, i, a, pa), mpt_mpte_size(mode)) {
      None()     => return false,
      Some(mpte) => match mpt_step_of(mode, i, mpte, pa) {
        MPT_Table(next) => a = next,
        MPT_Leaf(xwr)   => return mpt_allows(xwr, access),
        MPT_Fault()     => return false,
      },
    }
  };
  // Not reached: at level 0, mpt_step_of takes a non-leaf MPTE as a fault.
  false
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
  if allowed then None() else Some(accessFaultFromAccessType(access))
}
