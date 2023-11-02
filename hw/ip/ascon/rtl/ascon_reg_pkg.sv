// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// Register Package auto-generated by `reggen` containing data structure

package ascon_reg_pkg;

  // Address widths within the block
  parameter int BlockAw = 6;

  ////////////////////////////
  // Typedefs for registers //
  ////////////////////////////

  typedef struct packed {
    logic [31:0] q;
    logic        qe;
  } ascon_reg2hw_key_mreg_t;

  typedef struct packed {
    logic [31:0] q;
    logic        qe;
  } ascon_reg2hw_data_in_mreg_t;

  typedef struct packed {
    logic [31:0] q;
    logic        re;
  } ascon_reg2hw_data_out_mreg_t;

  typedef struct packed {
    struct packed {
      logic        q;
    } mode;
    struct packed {
      logic        q;
    } flavor;
    struct packed {
      logic        q;
    } manual_start_trigger;
    struct packed {
      logic        q;
    } force_data_overwrite;
  } ascon_reg2hw_ctrl_reg_t;

  typedef struct packed {
    logic        q;
  } ascon_reg2hw_trigger_reg_t;

  typedef struct packed {
    logic [31:0] d;
  } ascon_hw2reg_data_out_mreg_t;

  typedef struct packed {
    logic        d;
    logic        de;
  } ascon_hw2reg_trigger_reg_t;

  typedef struct packed {
    struct packed {
      logic        d;
      logic        de;
    } idle;
    struct packed {
      logic        d;
      logic        de;
    } stall;
    struct packed {
      logic        d;
      logic        de;
    } output_valid;
    struct packed {
      logic        d;
      logic        de;
    } input_ready;
  } ascon_hw2reg_status_reg_t;

  // Register -> HW type
  typedef struct packed {
    ascon_reg2hw_key_mreg_t [3:0] key; // [400:269]
    ascon_reg2hw_data_in_mreg_t [3:0] data_in; // [268:137]
    ascon_reg2hw_data_out_mreg_t [3:0] data_out; // [136:5]
    ascon_reg2hw_ctrl_reg_t ctrl; // [4:1]
    ascon_reg2hw_trigger_reg_t trigger; // [0:0]
  } ascon_reg2hw_t;

  // HW -> register type
  typedef struct packed {
    ascon_hw2reg_data_out_mreg_t [3:0] data_out; // [137:10]
    ascon_hw2reg_trigger_reg_t trigger; // [9:8]
    ascon_hw2reg_status_reg_t status; // [7:0]
  } ascon_hw2reg_t;

  // Register offsets
  parameter logic [BlockAw-1:0] ASCON_KEY_0_OFFSET = 6'h 0;
  parameter logic [BlockAw-1:0] ASCON_KEY_1_OFFSET = 6'h 4;
  parameter logic [BlockAw-1:0] ASCON_KEY_2_OFFSET = 6'h 8;
  parameter logic [BlockAw-1:0] ASCON_KEY_3_OFFSET = 6'h c;
  parameter logic [BlockAw-1:0] ASCON_DATA_IN_0_OFFSET = 6'h 10;
  parameter logic [BlockAw-1:0] ASCON_DATA_IN_1_OFFSET = 6'h 14;
  parameter logic [BlockAw-1:0] ASCON_DATA_IN_2_OFFSET = 6'h 18;
  parameter logic [BlockAw-1:0] ASCON_DATA_IN_3_OFFSET = 6'h 1c;
  parameter logic [BlockAw-1:0] ASCON_DATA_OUT_0_OFFSET = 6'h 20;
  parameter logic [BlockAw-1:0] ASCON_DATA_OUT_1_OFFSET = 6'h 24;
  parameter logic [BlockAw-1:0] ASCON_DATA_OUT_2_OFFSET = 6'h 28;
  parameter logic [BlockAw-1:0] ASCON_DATA_OUT_3_OFFSET = 6'h 2c;
  parameter logic [BlockAw-1:0] ASCON_CTRL_OFFSET = 6'h 30;
  parameter logic [BlockAw-1:0] ASCON_TRIGGER_OFFSET = 6'h 34;
  parameter logic [BlockAw-1:0] ASCON_STATUS_OFFSET = 6'h 38;

  // Reset values for hwext registers and their fields
  parameter logic [31:0] ASCON_DATA_OUT_0_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_DATA_OUT_1_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_DATA_OUT_2_RESVAL = 32'h 0;
  parameter logic [31:0] ASCON_DATA_OUT_3_RESVAL = 32'h 0;

  // Register index
  typedef enum int {
    ASCON_KEY_0,
    ASCON_KEY_1,
    ASCON_KEY_2,
    ASCON_KEY_3,
    ASCON_DATA_IN_0,
    ASCON_DATA_IN_1,
    ASCON_DATA_IN_2,
    ASCON_DATA_IN_3,
    ASCON_DATA_OUT_0,
    ASCON_DATA_OUT_1,
    ASCON_DATA_OUT_2,
    ASCON_DATA_OUT_3,
    ASCON_CTRL,
    ASCON_TRIGGER,
    ASCON_STATUS
  } ascon_id_e;

  // Register width information to check illegal writes
  parameter logic [3:0] ASCON_PERMIT [15] = '{
    4'b 1111, // index[ 0] ASCON_KEY_0
    4'b 1111, // index[ 1] ASCON_KEY_1
    4'b 1111, // index[ 2] ASCON_KEY_2
    4'b 1111, // index[ 3] ASCON_KEY_3
    4'b 1111, // index[ 4] ASCON_DATA_IN_0
    4'b 1111, // index[ 5] ASCON_DATA_IN_1
    4'b 1111, // index[ 6] ASCON_DATA_IN_2
    4'b 1111, // index[ 7] ASCON_DATA_IN_3
    4'b 1111, // index[ 8] ASCON_DATA_OUT_0
    4'b 1111, // index[ 9] ASCON_DATA_OUT_1
    4'b 1111, // index[10] ASCON_DATA_OUT_2
    4'b 1111, // index[11] ASCON_DATA_OUT_3
    4'b 0001, // index[12] ASCON_CTRL
    4'b 0001, // index[13] ASCON_TRIGGER
    4'b 0001  // index[14] ASCON_STATUS
  };

endpackage
