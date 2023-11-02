// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// AES top-level wrapper

module ascon (
  input                     clk_i,
  input                     rst_ni,

  // Bus Interface
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o
);

  import ascon_reg_pkg::*;

  ascon_reg2hw_t reg2hw;
  ascon_hw2reg_t hw2reg;

  ascon_reg_top u_reg (
    .clk_i,
    .rst_ni,
    .tl_i,
    .tl_o,
    .reg2hw,
    .hw2reg
  );

  aes_core aes_core (
    .clk_i,
    .rst_ni,
    .reg2hw,
    .hw2reg
  );

endmodule