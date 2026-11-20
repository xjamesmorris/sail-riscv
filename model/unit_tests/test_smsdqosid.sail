// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// Written with AI assistance: GitHub Copilot CLI, model claude-opus-5.5.

// Unit tests of Machine-Mode and Supervisor Domain QoS Identifiers
// (Smqosid, Smsdqosid; extensions/Smqosid/smqosid.sail and
// extensions/Smsdqosid/smsdqosid.sail): their registers' legalization,
// under the default configuration's widths (RCID and MCID 12 bits, QRID 4
// bits), and the ranges and identifiers of chapter 9 of RISC-V Supervisor
// Domains Access Protection v0.9, with the example that it gives.

$[test]
function test_smqosid_mrmcfg() -> unit = {
  // RCID 11:0, MCID 27:16, and QRID 31:28; the WPRI bits read as zero.
  assert(legalize_mrmcfg(ones()).bits == zero_extend(0xFFFF0FFF));
  assert(legalize_mrmcfg(zero_extend(0x00005000)).bits == zeros());
}

$[test]
function test_smsdqosid_mnrmcfg() -> unit = {
  assert(legalize_mnrmcfg(ones()).bits == zero_extend(0xFFFF0FFF));
  assert(legalize_mnrmcfg(zero_extend(0x00005000)).bits == zeros());
}

$[test]
function test_smsdqosid_msdcfg_fields() -> unit = {
  // With RCIDLEN and MCIDLEN 12: SRL and SML above 12 become 12, or 11 while
  // SSRM or SSMM is 1; the other bits, SIDN's included, read as zero.
  assert(smsdqosid_msdcfg_fields(Mk_Msdcfg(ones())).bits == zero_extend(0xBBC00000));
  assert(smsdqosid_msdcfg_fields(Mk_Msdcfg(zero_extend(0xFF000000))).bits == zero_extend(0xCC000000));
  assert(smsdqosid_msdcfg_fields(Mk_Msdcfg(zero_extend(0x35C0003F))).bits == zero_extend(0x35C00000));
  // SSRM and SSMM are independent.
  assert(smsdqosid_msdcfg_fields(Mk_Msdcfg(zero_extend(0xCC400000))).bits == zero_extend(0xCB400000));
}

$[test]
function test_smsdqosid_ranges() -> unit = {
  // The text's example, with RCIDLEN 5 and SRL 3: RCID 0 to 23 with SSRM 1,
  // and 0 to 7 with SSRM 0 (9:224-239).
  assert(smsdqosid_id_max(5, 0b1, 0x3) == 0x017);
  assert(smsdqosid_id_max(5, 0b0, 0x3) == 0x007);
  assert(smsdqosid_id_max(12, 0b0, 0xC) == 0xFFF);
  assert(smsdqosid_id_max(12, 0b1, 0x0) == 0xFFE);
  assert(smsdqosid_id_max(1, 0b1, 0x0) == 0x000);
}

$[test]
function test_smsdqosid_request_ids() -> unit = {
  // The text's example: with mnrmcfg.RCID 24, SRL 3, and SSRM 0, srmcfg.RCID
  // 0 to 7 gives 24 to 31; with SSRM 1, srmcfg.RCID itself (9:224-239).
  assert(smsdqosid_request_id(0b0, 0x3, 0x018, 0x000) == 0x018);
  assert(smsdqosid_request_id(0b0, 0x3, 0x018, 0x007) == 0x01F);
  assert(smsdqosid_request_id(0b1, 0x3, 0x018, 0x017) == 0x017);
}
