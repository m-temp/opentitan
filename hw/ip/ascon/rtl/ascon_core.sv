// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// AES core implementation

module ascon_core (
  input                            clk_i,
  input                            rst_ni,

  // Bus Interface
  input  ascon_reg_pkg::aes_reg2hw_t reg2hw,
  output ascon_reg_pkg::aes_hw2reg_t hw2reg
);

  import ascon_reg_pkg::*;
  import ascon_pkg::*;

  // Types

  // Signals
  logic [31:0] data_in[4];
  logic  [3:0] data_in_new_d, data_in_new_q;
  logic        data_in_new;
  logic        data_in_load;

  logic [31:0] key_in[4];
  logic  [3:0] key_in_new_d, key_in_new_q;
  logic        key_in_new;
  logic        key_in_load;

  logic        force_data_overwrite;
  logic        manual_start_trigger;
  logic        mode;
  logic        start;
  logic        flavor;

  logic [63:0]  state_init[5];
  logic [63:0]  state_d[5];
  logic [63:0]  state_q[5];

  logic [31:0] data_out_d[4];
  logic [31:0] data_out_q[4];
  logic        data_out_we;
  logic  [3:0] data_out_read_d, data_out_read_q;
  logic        data_out_read;

  // Unused signals
  logic [31:0] unused_data_out_q[4];

  // Inputs
  assign key_in[0] = reg2hw.key0.q;
  assign key_in[1] = reg2hw.key1.q;
  assign key_in[2] = reg2hw.key2.q;
  assign key_in[3] = reg2hw.key3.q;

  assign data_in[0] = reg2hw.data_in0.q;
  assign data_in[1] = reg2hw.data_in1.q;
  assign data_in[2] = reg2hw.data_in2.q;
  assign data_in[3] = reg2hw.data_in3.q;

  assign nonce_in[0] = reg2hw.nonce_in0.q;
  assign nonce_in[1] = reg2hw.nonce_in1.q;
  assign nonce_in[2] = reg2hw.nonce_in2.q;
  assign nonce_in[3] = reg2hw.nonce_in3.q;

  assign force_data_overwrite = reg2hw.ctrl.force_data_overwrite.q;
  assign manual_start_trigger = reg2hw.ctrl.manual_start_trigger.q;
  assign mode                 = reg2hw.ctrl.mode.q;
  assign flavor               = reg2hw.ctrl.flavor.q;
  assign start                = reg2hw.trigger.q;


  // Unused inputs # FIXME
  // data_out is actually hwo, but we need hrw for hwre
  assign unused_data_out_q[0] = reg2hw.data_out0.q;
  assign unused_data_out_q[1] = reg2hw.data_out1.q;
  assign unused_data_out_q[2] = reg2hw.data_out2.q;
  assign unused_data_out_q[3] = reg2hw.data_out3.q;

  // Core modules

  assign state_init[0] = IV_128;
  assign state_init[1] = {key[0], key[1]};
  assign state_init[2] = {key[2], key[3]};
  assign state_init[3] = {nonce_in[0], nonce_in[1]};
  assign state_init[3] = {nonce_in[2], nonce_in[3]};

  // State registers
  assign state_d = key_in_load ? state_init : state_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin : reg_state
    if (!rst_ni) begin
      state_q <= '{default: '0};
    end else begin
      state_q <= state_d;
    end
  end

  // Detect new key, new input, output read
  // Edge detectors are cleared by the FSM
  assign key_init_new_d = key_in_load ? '0 : key_init_new_q |
      {reg2hw.key3.qe, reg2hw.key2.qe, reg2hw.key1.qe, reg2hw.key0.qe};
  assign key_init_new = &key_init_new_d;

  assign data_in_new_d = data_in_load ? '0 : data_in_new_q |
      {reg2hw.data_in3.qe, reg2hw.data_in2.qe, reg2hw.data_in1.qe, reg2hw.data_in0.qe};
  assign data_in_new = &data_in_new_d;

  assign data_out_read_d = data_out_we ? '0 : data_out_read_q |
      {reg2hw.data_out3.re, reg2hw.data_out2.re, reg2hw.data_out1.re, reg2hw.data_out0.re};
  assign data_out_read = &data_out_read_d;

  always_ff @(posedge clk_i or negedge rst_ni) begin : reg_edge_detection
    if (!rst_ni) begin
      key_init_new_q  <= '0;
      data_in_new_q   <= '0;
      data_out_read_q <= '0;
    end else begin
      key_init_new_q  <= key_init_new_d;
      data_in_new_q   <= data_in_new_d;
      data_out_read_q <= data_out_read_d;
    end
  end

  // Control FSM
  assign key_in_load = 1'b0
  assign data_in_load = 1'b0;
  assign data_out_we  = 1'b0;

  // placeholders
  logic     unused_force_data_overwrite;
  logic     unused_manual_start_trigger;
  logic     unused_flavor;
  logic     unused_mode;
  logic     unused_start;
  assign unused_force_data_overwrite = force_data_overwrite;
  assign unused_manual_start_trigger = manual_start_trigger;
  assign unused_flavor               = flavor;
  assign unused_mode                 = mode;
  assign unused_start                = start;
  logic unused_data_in_new;
  logic unused_key_init_new;
  logic unused_data_out_read;
  assign unused_data_in_new   = data_in_new;
  assign unused_key_init_new  = key_init_new;
  assign unused_data_out_read = data_out_read;
  logic [63:0] unused_data_in[4];
  assign unused_data_in[0] = data_in[0];
  assign unused_data_in[1] = data_in[1];
  assign unused_data_in[2] = data_in[2];
  assign unused_data_in[3] = data_in[3];


  // Output registers
  data_out_d[0] = state_q[0][63:32];
  data_out_d[1] = state_q[0][31:0];
  data_out_d[2] = state_q[1][63:32];
  data_out_d[3] = state_q[1][31:0];

  always_ff @(posedge clk_i or negedge rst_ni) begin : reg_data_out
    if (!rst_ni) begin
      data_out_q <= '{default: '0};
    end else if (data_out_we) begin
      data_out_q <= data_out_d;
    end
  end

  // Outputs
  assign hw2reg.data_out0.d = data_out_q[0];
  assign hw2reg.data_out1.d = data_out_q[1];
  assign hw2reg.data_out2.d = data_out_q[2];
  assign hw2reg.data_out3.d = data_out_q[3];

  assign hw2reg.trigger.d   = 1'b0;
  assign hw2reg.trigger.de  = 1'b1;

  assign hw2reg.status.idle.d   = 1'b0;
  assign hw2reg.status.idle.de  = 1'b1;
  assign hw2reg.status.stall.d  = 1'b0;
  assign hw2reg.status.stall.de = 1'b1;

  // clear once all output regs have been read
  assign hw2reg.status.output_valid.d  = data_out_we;
  assign hw2reg.status.output_valid.de = data_out_we | data_out_read;

  // clear once all input regs have been written
  assign hw2reg.status.input_ready.d   = ~data_in_new;
  assign hw2reg.status.input_ready.de  =  data_in_new | data_in_load;

endmodule