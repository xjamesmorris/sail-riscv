// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// Written with AI assistance: GitHub Copilot CLI, model claude-opus-5.5.

// MFENCE.PA and MINVAL.PA of Supervisor Domains (Smsd), the text's
// 3:136-230. The text names their funct7 values without giving them; these
// are those of riscv/riscv-opcodes pull request 389 (rv_smsdid). Each is
// valid only in M-mode, where the model flushes its translations (see
// smsd_flush_translations). The model keeps no MPT cache, and ignores the
// operands, as the text allows (3:182-186).

private function smsd_fence_in_virtual_mode() -> ExecutionResult =
  match smsd_fence_exception_in_vs_vu {
    Smsd_Fence_Illegal => Illegal_Instruction(),
    Smsd_Fence_Virtual => Virtual_Instruction(),
  }

private function smsd_fence() -> ExecutionResult =
  match cur_privilege {
    Machine           => { smsd_flush_translations(); RETIRE_SUCCESS },
    VirtualSupervisor => smsd_fence_in_virtual_mode(),
    VirtualUser       => smsd_fence_in_virtual_mode(),
    _                 => Illegal_Instruction(),
  }

union clause instruction = MFENCE_PA : (regidx, regidx)

mapping clause encdec = MFENCE_PA(rs1, rs2)
  <-> 0b0011001 @ encdec_reg(rs2) @ encdec_reg(rs1) @ 0b000 @ 0b00000 @ 0b1110011
  when currentlyEnabled(Ext_Smsd)

function clause execute MFENCE_PA(_, _) = smsd_fence()

mapping clause assembly = MFENCE_PA(rs1, rs2)
  <-> "mfence.pa" ^ spc() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

// The text no longer makes MINVAL.PA depend on Svinval, although only
// SFENCE.W.INVAL and SFENCE.INVAL.IR order it (3:208-217).
union clause instruction = MINVAL_PA : (regidx, regidx)

mapping clause encdec = MINVAL_PA(rs1, rs2)
  <-> 0b0011011 @ encdec_reg(rs2) @ encdec_reg(rs1) @ 0b000 @ 0b00000 @ 0b1110011
  when currentlyEnabled(Ext_Smsd)

function clause execute MINVAL_PA(_, _) = smsd_fence()

mapping clause assembly = MINVAL_PA(rs1, rs2)
  <-> "minval.pa" ^ spc() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)
