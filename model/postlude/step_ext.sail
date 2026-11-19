// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// The default implementation of hooks for the step() and main() functions.

function ext_fetch_hook(f : FetchResult) -> FetchResult = f

// Supervisor Domains (Smsd) clears its record of MPT refusals before each
// instruction (see smsd_pre_step).
function ext_pre_step_hook()  -> unit = smsd_pre_step()
function ext_post_step_hook() -> unit = ()

function ext_reset() -> unit = ()
