// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// Written with AI assistance: GitHub Copilot CLI, model claude-opus-5.5.

// Machine-Mode Quality-of-Service Identifiers (Smqosid), from RISC-V
// Supervisor Domains Access Protection v0.9 (below, "the text"; a reference
// N:L is line L of the text's chapter N at its tag v0.9): mrmcfg, which
// holds the QoS identifiers that accompany requests made with an effective
// privilege of M (9:53-88). The model has no shared resource controllers,
// so the identifiers have no other effect.

// The number of implemented bits of each field of mrmcfg. The fields are
// WARL (9:60-63), and the text gives them no widths: the model implements
// the least-significant bits of each first, as Ssqosid does for srmcfg.
let smqosid_rcid_len : range(0, 12) = config extensions.Smqosid.rcid_length
let smqosid_mcid_len : range(0, 12) = config extensions.Smqosid.mcid_length
let smqosid_qrid_len : range(0, 4) = config extensions.Smqosid.qrid_length

// mrmcfg's layout (9:90-115): RCID in bits 11:0, MCID in bits 27:16, and
// QRID in bits 31:28. Its other bits are WPRI, which the model makes
// read-only zero.
bitfield Mrmcfg : xlenbits = {
  QRID : 31 .. 28,
  MCID : 27 .. 16,
  RCID : 11 .. 0
}

function clause currentlyEnabled(Ext_Smqosid) = hartSupports(Ext_Smqosid) & currentlyEnabled(Ext_Zicsr)

function legalize_mrmcfg(value : xlenbits) -> Mrmcfg = {
  let v = Mk_Mrmcfg(value);
  [Mk_Mrmcfg(zeros()) with
    QRID = v[QRID] & ~(ones(4) << smqosid_qrid_len),
    MCID = v[MCID] & ~(ones(12) << smqosid_mcid_len),
    RCID = v[RCID] & ~(ones(12) << smqosid_rcid_len)
  ]
}

// The text suggests a reset value of 0 for RCID and QRID (9:74-80); the
// model resets MCID to 0 as well.
register mrmcfg : Mrmcfg = Mk_Mrmcfg(zeros())

mapping clause csr_name_map = 0x381 <-> "mrmcfg"

function clause is_CSR_accessible(0x381, _, _) = currentlyEnabled(Ext_Smqosid)

function clause read_CSR(0x381) = mrmcfg.bits

function clause write_CSR(0x381, value) = {
  mrmcfg = legalize_mrmcfg(value);
  Ok(mrmcfg.bits)
}
