// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// Written with AI assistance: GitHub Copilot CLI, model claude-opus-5.5.

// The CSRs of Supervisor Domains (Smsd): mmpt and msdcfg (the text's
// chapter 3; see smsd_types.sail).

function clause currentlyEnabled(Ext_Smsd) = hartSupports(Ext_Smsd) & currentlyEnabled(Ext_Zicsr)

// mmpt (3:28-134). The text gives it no reset value; the model resets it to
// Bare.
register mmpt : xlenbits = zeros()

// The fields that mmpt holds after a write of sdid and ppn, with MODE set to
// mode, an encoding of the supported mode m.
private function mmpt_fields_for(m : mpt_mode, mode : bits(4), sdid : bits(6), ppn : bits(44)) -> mmpt_fields = {
  // "if SDIDLEN > 0, SDID[SDIDLEN-1:0] is writable" (3:70-71); its other bits
  // read as zero.
  let sdid_mask : bits(6) = ~(ones(6) << smsd_sdidlen);
  let sdid : bits(6) = if m == MPT_Bare & not(smsd_bare_sdid_writable) then zeros() else sdid & sdid_mask;
  let ppn : bits(44) = match m {
    MPT_Bare    => if smsd_bare_ppn_zero then zeros() else ppn,
    // "In this mode, bits 2:0 of mmpt.PPN always read as zero" (3:121-123).
    MPT_Smmpt64 => [ppn with 2 .. 0 = 0b000],
    _           => ppn,
  };
  struct { mode = mode, sdid = sdid, ppn = ppn }
}

function legalize_mmpt(old : xlenbits, value : xlenbits) -> xlenbits = {
  let o = mmpt_unpack(old);
  let v = mmpt_unpack(value);
  let f : mmpt_fields = match mpt_mode_of_bits(v.mode) {
    Some(m) => mmpt_fields_for(m, v.mode, v.sdid, v.ppn),
    // An unsupported MODE (3:113-116).
    None() => match smsd_unsupported_mode_write {
      Smsd_KeepMode => match mpt_mode_of_bits(o.mode) {
        Some(m) => mmpt_fields_for(m, o.mode, v.sdid, v.ppn),
        None()  => internal_error(__FILE__, __LINE__, "mmpt holds an unsupported MODE"),
      },
      Smsd_ModeBare => mmpt_fields_for(MPT_Bare, zeros(), v.sdid, v.ppn),
      Smsd_ZeroAll  => struct { mode = zeros(), sdid = zeros(), ppn = zeros() },
    },
  };
  mmpt_pack(f)
}

// The SDID augments the ASIDs and VMIDs of SFENCE.VMA and its kin, to form
// the identifiers that cached translations are tagged with (3:232-247). The
// model's TLB does not record the SDID, so the model flushes it whenever
// mmpt is written, and on MFENCE.PA and MINVAL.PA, whose orderings cover the
// page-table walks that the MPT checks.
function smsd_flush_translations() -> unit = {
  flush_TLB(None(), None(), None(), S_Stage);
  flush_TLB(None(), None(), None(), VS_Stage);
  flush_TLB(None(), None(), None(), G_Stage);
}

mapping clause csr_name_map = 0x382 <-> "mmpt"

function clause is_CSR_accessible(0x382, _, _) = currentlyEnabled(Ext_Smsd)

function clause read_CSR(0x382) = mmpt

function clause write_CSR(0x382, value) = {
  mmpt = legalize_mmpt(mmpt, value);
  smsd_flush_translations();
  Ok(mmpt)
}

// msdcfg (3:249-284). Its fields belong to Smsdia and Smsdqosid, which the
// model does not implement, and "if no optional extensions are implemented,
// this CSR becomes read-only zero" (3:262-266). When MXLEN=64, bits 63:32,
// which the text does not draw, read as zero too.
mapping clause csr_name_map = 0x74E <-> "msdcfg"

function clause is_CSR_accessible(0x74E, _, _) = currentlyEnabled(Ext_Smsd)

function clause read_CSR(0x74E) = zeros()

function clause write_CSR(0x74E, _) = Ok(zeros())
