// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

module kmac_cov_bind;
  bind kmac kmac_cov_if kmac_cov_if (
    .sw_cmd_process (reg2msgfifo_process),
    .keccak_st      (u_sha3.u_keccak.keccak_st),
    .msgfifo_depth  (msgfifo_depth),
    .msgfifo_full   (msgfifo_full),
    .msgfifo_empty  (msgfifo_empty)
  );

  bind kmac cip_mubi_cov_if #(.Width(4)) kmac_sha3_done_mubi_cov_if (
    .rst_ni (rst_ni),
    .mubi   (sha3_done)
  );

  bind kmac cip_mubi_cov_if #(.Width(4)) kmac_sha3_absorb_mubi_cov_if (
    .rst_ni (rst_ni),
    .mubi   (sha3_absorbed)
  );

  bind kmac sha3pad_assert_if #(.EnMasking(u_sha3.u_pad.EnMasking)) sha3pad_assert_cov_if (
    .clk_i (clk_i),
    .rst_ni (rst_ni),
    .process_i (u_sha3.u_pad.process_i),
    .keccak_complete_i (u_sha3.u_pad.keccak_complete_i),
    .keccak_run_o (u_sha3.u_pad.keccak_run_o),
    .lc_escalate_en_i (u_sha3.u_pad.lc_escalate_en_i)
  );

endmodule
