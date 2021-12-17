// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "aes_tlul_interface.h"

#define SEQ 2

#if (SEQ == 2)
#include "aes_tlul_sequence_modes.h"
#elif (SEQ == 1)
#include "aes_tlul_sequence_1.h"
#else  // SEQ == 0
#include "aes_tlul_sequence_0.h"
#endif

AESTLULInterface::AESTLULInterface(Vaes_sim *rtl) : rtl_(rtl) {
  rtl_->tl_i[0] = 0;
  rtl_->tl_i[1] = 0;
  rtl_->tl_i[2] = 0;
  rtl_->tl_i[3] = 0;
  tl_i_.a_valid = false;
  tl_i_.a_opcode = 0;
  tl_i_.a_size = 0;
  tl_i_.a_address = 0;
  tl_i_.a_mask = 0;
  tl_i_.a_data = 0;
  tl_i_.d_ready = false;
  tl_o_.d_valid = false;
  tl_o_.d_opcode = 0;
  tl_o_.d_param = 0;
  tl_o_.d_size = 0;
  tl_o_.d_source = 0;
  tl_o_.d_sink = 0;
  tl_o_.d_data = 0;
  tl_o_.d_user = 0;
  tl_o_.d_error = 0;
  tl_o_.a_ready = false;
  got_handshake_a_ = false;
  got_handshake_d_ = false;
  num_transactions_ = -1;
  num_responses_ = 0;

#if (SEQ == 2)
  aes_tlul_sequence_modes_gen_all();
#endif
}

void AESTLULInterface::HandleInterface() {
  bool interface_ready;
  bool got_exp_resp;

  MonitorSignals();
  got_exp_resp = CheckResp();
  interface_ready = CheckReady();

  // prepare interface for transaction only if the interface is ready
  // repeat previous transaction if we did not get the expected response
  if (interface_ready) {
    GetTransaction(got_exp_resp);
  }

  DriveSignals();

  return;
}

int AESTLULInterface::GetNumTransactions() { return num_transactions_; }

int AESTLULInterface::GetNumResponses() { return num_responses_; }

bool AESTLULInterface::StatusDone() {
  bool done = false;

  if ((num_responses_ >= num_responses_max) &&
      (num_transactions_ >= num_transactions_max)) {
    done = true;
  }

  return done;
}

void AESTLULInterface::GetTransaction(bool get_next) {
  if (get_next) {
    num_transactions_++;
  }
  if (num_transactions_ < num_transactions_max) {
    tl_i_ = tl_i_transactions[num_transactions_];
  } else {
    tl_i_ = {false, 0, 0, 0, 0, 0, 0, 0, 0, false};
  }

  return;
}

bool AESTLULInterface::CheckReady() {
  bool ready = false;

  // check for handshakes
  if (tl_i_.a_valid && tl_o_.a_ready) {
    got_handshake_a_ = true;
  }
  if (tl_i_.d_ready && tl_o_.d_valid) {
    got_handshake_d_ = true;
  }

  // deassert valid/ready
  if (got_handshake_a_) {
    tl_i_.a_valid = false;
  }
  if (got_handshake_d_) {
    tl_i_.d_ready = false;
  }

  // we cannot drive the next transaction unless
  // - we completed both handshakes
  // - or were not driving before
  // both cases are given if a_valid == d_valid == false
  if (!tl_i_.a_valid && !tl_i_.d_ready) {
    got_handshake_a_ = false;
    got_handshake_d_ = false;
    ready = true;
  }

  return ready;
}

bool AESTLULInterface::CheckResp() {
  bool match = false;
  EXP_RESP exp_resp = tl_o_exp_resp[num_responses_];

  // do not check if not waiting for a response
  if (!tl_i_.d_ready) {
    match = true;
  }
  // only do the check during a data handshake
  else if (tl_i_.d_ready && tl_o_.d_valid) {
    // non-read operations are not checked
    if (tl_i_.a_opcode != 4) {
      match = true;
    }
    // do the actual check
    else if ((exp_resp.mask & tl_o_.d_data) ==
             (exp_resp.mask & exp_resp.exp_resp)) {
      match = true;
      num_responses_++;
    }
  }

  return match;
}

void AESTLULInterface::MonitorSignals() {
  // tl_o bits:
  // d_valid   - 1   - [65]      - [2][1]
  // d_opcode  - 3   - [64:62]   - [1][31:30] - [2][0]
  // d_param   - 3   - [61:59]   - [1][29:27]
  // d_size    - 2   - [58:57]   - [1][26:25]
  // d_source  - 8   - [56:49]   - [1][24:17]
  // d_sink    - 1   - [48]      - [1][16]
  // d_data    - 32  - [47:16]   - [0][31:16] - [1][15:0]
  // d_user    - 14  - [15:2]    - [0][15:2]
  // d_error   - 1   - [1]       - [0][1]
  // a_ready   - 1   - [0]       - [0][0]

  // just montior handshakes, error and resp data
  tl_o_.d_valid = (rtl_->tl_o[2] & 0x2) >> 1;
  tl_o_.d_data =
      ((rtl_->tl_o[1] & 0xFFFF) << 16) | ((rtl_->tl_o[0] >> 16) & 0xFFFF);
  tl_o_.d_error = (rtl_->tl_o[0] & 0x2) >> 1;
  tl_o_.a_ready = rtl_->tl_o[0] & 0x1;

  return;
}

static uint64_t BitwiseXOR(uint64_t in) {
  uint64_t out = 0;
  for (int i = 0; i < 64; i++) {
    out ^= (in >> i) & 0x1;
  }

  return out;
}

void AESTLULInterface::DriveSignals() {
  // clear
  rtl_->tl_i[3] = 0;
  rtl_->tl_i[2] = 0;
  rtl_->tl_i[1] = 0;
  rtl_->tl_i[0] = 0;

  // tl_i bits:
  // a_valid   - 1   - [108]     - [3][12]
  // a_opcode  - 3   - [107:105] - [3][11:9]
  // a_param   - 3   - [104:102] - [3][8:6]
  // a_size    - 2   - [101:100] - [3][5:4]
  // a_source  - 8   - [99:92]   - [2][31:28] - [3][3:0]
  // a_address - 32  - [91:60]   - [1][31:28] - [2][27:0]
  // a_mask    - 4   - [59:56]   - [1][27:24]
  // a_data    - 32  - [55:24]   - [0][31:24] - [1][23:0]
  // a_user    - 23  - [23:1]    - [0][23:1]
  // d_ready   - 1   - [0]       - [0][0]

  // a_user.instr_type = False (Data)
  uint8_t tl_type = 0x5;

  // generate cmd integrity data, see also
  // - hw/ip/tlul/rtl/tlul_pkg.sv
  // - hw/ip/tlul/rtl/tlul_cmd_intg_chk.sv
  // - hw/ip/prim/rtl/prim_secded_inv_64_57_enc.sv
  // - hw/ip/prim/rtl/prim_secded_inv_39_32_enc.sv

  // cmd and data integrity checking
  // prepare
  uint64_t cmd_payload = 0;
  cmd_payload |= tl_i_.a_mask & 0xF;
  cmd_payload |= (tl_i_.a_opcode & 0x7) << 4;
  cmd_payload |= (tl_i_.a_address & 0xFFFFFFFF) << 7;
  cmd_payload |= ((uint64_t)tl_type & 0xF) << 39;

  // generate
  uint64_t cmd_intg = cmd_payload;
  cmd_intg |= ((BitwiseXOR(cmd_intg & 0x0103FFF800007FFF) & 0x1) ^ 0x0) << 57;
  cmd_intg |= ((BitwiseXOR(cmd_intg & 0x017C1FF801FF801F) & 0x1) ^ 0x1) << 58;
  cmd_intg |= ((BitwiseXOR(cmd_intg & 0x01BDE1F87E0781E1) & 0x1) ^ 0x0) << 59;
  cmd_intg |= ((BitwiseXOR(cmd_intg & 0x01DEEE3B8E388E22) & 0x1) ^ 0x1) << 60;
  cmd_intg |= ((BitwiseXOR(cmd_intg & 0x01EF76CDB2C93244) & 0x1) ^ 0x0) << 61;
  cmd_intg |= ((BitwiseXOR(cmd_intg & 0x01F7BB56D5525488) & 0x1) ^ 0x1) << 62;
  cmd_intg |= ((BitwiseXOR(cmd_intg & 0x01FBDDA769A46910) & 0x1) ^ 0x0) << 63;

  // prepare
  uint32_t data_payload = tl_i_.a_data;

  // generate
  uint64_t data_intg = (uint64_t)data_payload;
  data_intg |= ((BitwiseXOR(data_intg & 0x012606BD25) & 0x1) ^ 0x0) << 32;
  data_intg |= ((BitwiseXOR(data_intg & 0x02DEBA8050) & 0x1) ^ 0x1) << 33;
  data_intg |= ((BitwiseXOR(data_intg & 0x04413D89AA) & 0x1) ^ 0x0) << 34;
  data_intg |= ((BitwiseXOR(data_intg & 0x0831234ED1) & 0x1) ^ 0x1) << 35;
  data_intg |= ((BitwiseXOR(data_intg & 0x10C2C1323B) & 0x1) ^ 0x0) << 36;
  data_intg |= ((BitwiseXOR(data_intg & 0x202DCC624C) & 0x1) ^ 0x1) << 37;
  data_intg |= ((BitwiseXOR(data_intg & 0x4098505586) & 0x1) ^ 0x0) << 38;

  // set required bits
  rtl_->tl_i[3] |= (tl_i_.a_valid & 0x1) << 12;
  rtl_->tl_i[3] |= (tl_i_.a_opcode & 0x7) << 9;
  // param = 0
  rtl_->tl_i[3] |= (tl_i_.a_size & 0x3) << 4;
  // source = 0
  rtl_->tl_i[2] |= (tl_i_.a_address & 0xFFFFFFF0) >> 4;
  rtl_->tl_i[1] |= (tl_i_.a_address & 0x0000000F) << 28;
  rtl_->tl_i[1] |= (tl_i_.a_mask & 0xF) << 24;
  rtl_->tl_i[1] |= (tl_i_.a_data & 0xFFFFFF00) >> 8;
  rtl_->tl_i[0] |= (tl_i_.a_data & 0x000000FF) << 24;
  // a_user = 0
  // a_user.data_intg
  rtl_->tl_i[0] |= ((data_intg >> 32) & 0x7F) << 1;
  // a_user.cmd_intg
  rtl_->tl_i[0] |= ((cmd_intg  >> 57) & 0x7F) << (7 + 1);
  // a_user.tl_type
  rtl_->tl_i[0] |= tl_type << (7 + 7 + 1);
  rtl_->tl_i[0] |= (tl_i_.d_ready & 0x1);

  return;
}
