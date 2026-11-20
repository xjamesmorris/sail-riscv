// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// Written with AI assistance: GitHub Copilot CLI, model claude-opus-5.5.

// Supervisor Domain Quality-of-Service Identifiers (Smsdqosid), from RISC-V
// Supervisor Domains Access Protection v0.9 (below, "the text"; a reference
// N:L is line L of the text's chapter N at its tag v0.9): mnrmcfg, and the
// SSRM, SSMM, SRL, and SML fields of msdcfg, with which M-mode limits the
// RCID and MCID values that a supervisor domain may write to srmcfg
// (9:117-221). The identifiers that accompany requests made below M-mode
// are computed here too; the model has no shared resource controllers, so
// only the unit tests use them.
//
// Where the text leaves a behaviour open, the behaviour is a configuration
// option, and its default is the reading given with it.

// Which writes of srmcfg the ranges constrain. The text has them "constrain
// only the values that may be written to and held in srmcfg.RCID and
// srmcfg.MCID" (9:189-190). The answer given to the text's issue 295 has
// them constrain only the values that a supervisor domain writes, leaving
// srmcfg's legal values as they are. Default: that answer.
enum SmsdqosidRangeScope = {
  Smsdqosid_SD_Writes,  // the writes made below M-mode
  Smsdqosid_All_Writes, // every write, M-mode's included
  Smsdqosid_Held,       // every write; and a write of msdcfg leaves no ID
                        // held in srmcfg outside its new range
}
let smsdqosid_range_scope : SmsdqosidRangeScope = config extensions.Smsdqosid.range_scope

// What a constrained write leaves in an ID field of srmcfg when the value
// written is outside the field's range. The text does not say. Default: the
// field keeps its value, since that value "may" not be written.
enum SmsdqosidOutOfRange = {
  Smsdqosid_Keep,  // the field keeps its value
  Smsdqosid_Clamp, // the field takes the largest value in its range
}
let smsdqosid_out_of_range : SmsdqosidOutOfRange = config extensions.Smsdqosid.out_of_range_write

// The number of implemented bits of mnrmcfg.QRID. The text makes mnrmcfg
// WARL (9:131-135) and gives QRID no width. Its RCID and MCID have RCIDLEN
// and MCIDLEN bits, as srmcfg's do, as the answer given to the text's issue
// 296 has it.
let smsdqosid_qrid_len : range(0, 4) = config extensions.Smsdqosid.qrid_length

function clause currentlyEnabled(Ext_Smsdqosid) =
  hartSupports(Ext_Smsdqosid) & currentlyEnabled(Ext_Smsd) & currentlyEnabled(Ext_Ssqosid)

// mnrmcfg's layout (9:137-162), as mrmcfg's: RCID in bits 11:0, MCID in
// bits 27:16, and QRID in bits 31:28. Its other bits are WPRI, which the
// model makes read-only zero.
bitfield Mnrmcfg : xlenbits = {
  QRID : 31 .. 28,
  MCID : 27 .. 16,
  RCID : 11 .. 0
}

function legalize_mnrmcfg(value : xlenbits) -> Mnrmcfg = {
  let v = Mk_Mnrmcfg(value);
  [Mk_Mnrmcfg(zeros()) with
    QRID = v[QRID] & ~(ones(4) << smsdqosid_qrid_len),
    MCID = v[MCID] & ~(ones(12) << mcidlen),
    RCID = v[RCID] & ~(ones(12) << rcidlen)
  ]
}

// The text gives mnrmcfg no reset value; the model resets it to zero.
register mnrmcfg : Mnrmcfg = Mk_Mnrmcfg(zeros())

mapping clause csr_name_map = 0x781 <-> "mnrmcfg"

function clause is_CSR_accessible(0x781, _, _) = currentlyEnabled(Ext_Smsdqosid)

function clause read_CSR(0x781) = mnrmcfg.bits

function clause write_CSR(0x781, value) = {
  mnrmcfg = legalize_mnrmcfg(value);
  Ok(mnrmcfg.bits)
}

// msdcfg's fields (9:164-188). SRL and SML are WARL, with legal values from
// 0 to RCIDLEN and to MCIDLEN (9:167-175); while SSRM or SSMM is 1, SRL or
// SML must also be less than RCIDLEN or MCIDLEN (9:180-181, 9:186-187).
// The text does not say what a write of a larger value leaves: the model
// takes the largest legal value. SSRM and SSMM are independent (the answer
// given to the text's issue 283).
function smsdqosid_msdcfg_fields(v : Msdcfg) -> Msdcfg = {
  let srl_max : range(0, 12) = if v[SSRM] == 0b1 then rcidlen - 1 else rcidlen;
  let sml_max : range(0, 12) = if v[SSMM] == 0b1 then mcidlen - 1 else mcidlen;
  [Mk_Msdcfg(zeros()) with
    SML  = if unsigned(v[SML]) > sml_max then to_bits(4, sml_max) else v[SML],
    SRL  = if unsigned(v[SRL]) > srl_max then to_bits(4, srl_max) else v[SRL],
    SSMM = v[SSMM],
    SSRM = v[SSRM]
  ]
}

// The largest value that a constrained write may leave in an ID field of
// srmcfg (9:177-188): with mode 0, 2^SL - 1; with mode 1, 2^LEN - 2^SL - 1.
// LEN is RCIDLEN or MCIDLEN, mode is SSRM or SSMM, and SL is SRL or SML,
// which msdcfg keeps below LEN while mode is 1.
function smsdqosid_id_max(len : range(0, 12), mode : bits(1), sl : bits(4)) -> bits(12) = {
  let one : bits(12) = zero_extend(0b1);
  let low : bits(12) = ~(ones(12) << unsigned(sl));
  if mode == 0b0 then low else ~(ones(12) << len) - (one << unsigned(sl))
}

// What a constrained write leaves in an ID field: the value written, if it
// is in range, and otherwise what smsdqosid_out_of_range says.
private function smsdqosid_id(old : bits(12), written : bits(12), max : bits(12)) -> bits(12) =
  if written <=_u max then written
  else match smsdqosid_out_of_range {
    Smsdqosid_Keep  => old,
    Smsdqosid_Clamp => max,
  }

// A write of srmcfg: o is its value before, and n the value that Ssqosid's
// legalization gives the write. The ranges constrain the writes that
// smsdqosid_range_scope names.
function smsdqosid_constrain_srmcfg(o : Srmcfg, n : Srmcfg) -> Srmcfg = {
  let constrained = currentlyEnabled(Ext_Smsdqosid)
    & (cur_privilege != Machine | smsdqosid_range_scope != Smsdqosid_SD_Writes);
  if not(constrained) then return n;
  [n with
    RCID = smsdqosid_id(o[RCID], n[RCID], smsdqosid_id_max(rcidlen, msdcfg[SSRM], msdcfg[SRL])),
    MCID = smsdqosid_id(o[MCID], n[MCID], smsdqosid_id_max(mcidlen, msdcfg[SSMM], msdcfg[SML]))
  ]
}

// A write of msdcfg (see smsd_regs.sail). Under Smsdqosid_Held, an ID held in
// srmcfg that falls outside its new range becomes zero, the one value in
// every range.
function msdcfg_write(value) = {
  if not(currentlyEnabled(Ext_Smsdqosid)) then return Mk_Msdcfg(zeros());
  let n = smsdqosid_msdcfg_fields(Mk_Msdcfg(value));
  if smsdqosid_range_scope == Smsdqosid_Held then {
    if srmcfg[RCID] >_u smsdqosid_id_max(rcidlen, n[SSRM], n[SRL]) then srmcfg[RCID] = zeros();
    if srmcfg[MCID] >_u smsdqosid_id_max(mcidlen, n[SSMM], n[SML]) then srmcfg[MCID] = zeros();
  };
  n
}

// The RCID or MCID that accompanies a request made below M-mode
// (9:196-214): with mode (SSRM or SSMM) 0, the bits of base (mnrmcfg's)
// above its SL least-significant bits, and those of id (srmcfg's) below
// them; with mode 1, id.
function smsdqosid_request_id(mode : bits(1), sl : bits(4), base : bits(12), id : bits(12)) -> bits(12) = {
  let low : bits(12) = ~(ones(12) << unsigned(sl));
  if mode == 0b0 then (base & ~(low)) | (id & low) else id
}

// The QRID, RCID, and MCID that accompany each request made below M-mode
// (9:216-221).
function smsdqosid_request_ids() -> (bits(4), bits(12), bits(12)) =
  (mnrmcfg[QRID],
   smsdqosid_request_id(msdcfg[SSRM], msdcfg[SRL], mnrmcfg[RCID], srmcfg[RCID]),
   smsdqosid_request_id(msdcfg[SSMM], msdcfg[SML], mnrmcfg[MCID], srmcfg[MCID]))
