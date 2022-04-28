// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_HW_IP_AES_PRE_DV_AES_TB_CPP_AES_TLUL_SEQUENCE_DOC_H_
#define OPENTITAN_HW_IP_AES_PRE_DV_AES_TB_CPP_AES_TLUL_SEQUENCE_DOC_H_

#include "aes_tlul_sequence_common.h"
#include "crypto.h"

// This is a simple example to demonstrate one decryption and one encryption of one block in AES-128-ECB.
// This example is hihglighy annotated and contains information from various sources.
// It is intended as a starting point for creating individual sequences.



// PART I: What is sent to the AES-IP over the TLUL-BUS:
// a) as a SystemVerilog struct and  b) as Verilator cpp-struct

// a) SystemVerilog representation
// typedef struct packed { 
// logic                         a_valid;   ==> true => we want to send
// tl_a_op_e                     a_opcode;  ==> 0 => put full data, 1 => put partial data, 4 => get
// logic                  [2:0]  a_param;   ==> 0 => unused in OT!
// logic  [top_pkg::TL_SZW-1:0]  a_size;    ==> request 2^a_size: 0 => 1byte, 1 => 16b, 2 => 32b, 3 =>64b
// logic  [top_pkg::TL_AIW-1:0]  a_source;  ==> 0 => unused here!
// logic   [top_pkg::TL_AW-1:0]  a_address; ==> register address + offset
// logic  [top_pkg::TL_DBW-1:0]  a_mask;    ==> write strobe, one bit per byte indicating which lanes of data are valid for this request
// logic   [top_pkg::TL_DW-1:0]  a_data;    ==> data we want to send 32bytes
// tl_a_user_t                   a_user;    ==> 0 => unused
// logic                         d_ready;   ==> true => we accept data
// } tl_h2d_t;

// b) Verilator cpp representation. We only use a subset of the possible values here.
// struct TLI {
//  public:
//   bool a_valid;        ==> true
//   uint8_t a_opcode;    ==> 0/4 (put full data / receive data)
//   uint8_t a_param;     ==> 0   (unused)
//   uint8_t a_size;      ==> 2   (2^2=4 bytes = 32 bit)
//   uint8_t a_source;    ==> 0   (ignored)
//   uint32_t a_address;  ==> #define + offset ==> (for AES-128) we have 4*32bit regs to form one 128bit block. 
//   uint8_t a_mask;      ==> 0xF (complete 32 bits)  - set to 0xF for 32 bit read
//   uint32_t a_data;     ==> our data                - set to 0x0 for read
//   uint32_t a_user;     ==> 0   (ignored)
//   bool d_ready;        ==> true
// };


// In both cases we need to configure the bus (a_valid, a_opcode, d_ready) and send our data (a_data, a_mask, a_address)
// For register-table (values for a_data, and a_address) see https://docs.opentitan.org/hw/ip/aes/doc/#register-table

static const int num_transactions_max = 1+2+16+10+2+7+ 6;                   // Total number of transactions in this sequence
static const TLI tl_i_transactions[num_transactions_max] = {
    {true, 4, 0, 2, 0, AES_STATUS, 0xF, 0x0, 0, true},                      // read status
    // AES-128
    {true, 0, 0, 2, 0, AES_CONFIG, 0xF,                                     // write AES_CONFIG, set lowest 8 bits
     (0x0 << AES_CTRL_MANUAL_OPERATION_OFFSET) |                            // start automatic, do not oveerwrite output
         (0x1 << AES_CTRL_KEY_LEN_OFFSET) |                                 // AES-128 (1), [AES-192 (2), AES-256 (4)]
         (kCryptoAesEcb << AES_CTRL_MODE_OFFSET) | 0x2,                     // ECB + DEC(2) [Enc(1)]
     0, true},  // ctrl - decrypt, 128-bit
    {true, 0, 0, 2, 0, AES_CONFIG, 0xF,                                     // we are using shaddow config
     (0x0 << AES_CTRL_MANUAL_OPERATION_OFFSET) |                            // write everything twice
         (0x1 << AES_CTRL_KEY_LEN_OFFSET) |                                 // with same parameters
         (kCryptoAesEcb << AES_CTRL_MODE_OFFSET) | 0x2,
     0, true},  // ctrl - decrypt, 128-bit
    {true, 0, 0, 2, 0, AES_KEY_SHARE0_0 + 0x00, 0xF, 0x03020100, 0, true},  // write key0
    {true, 0, 0, 2, 0, AES_KEY_SHARE0_0 + 0x04, 0xF, 0x07060504, 0, true},  // write key1
    {true, 0, 0, 2, 0, AES_KEY_SHARE0_0 + 0x08, 0xF, 0x0B0A0908, 0, true},  // write key2
    {true, 0, 0, 2, 0, AES_KEY_SHARE0_0 + 0x0C, 0xF, 0x0F0E0D0C, 0, true},  // write key3
    {true, 0, 0, 2, 0, AES_KEY_SHARE0_0 + 0x10, 0xF, 0x13121110, 0, true},  // all key regs must be written...
    {true, 0, 0, 2, 0, AES_KEY_SHARE0_0 + 0x14, 0xF, 0x17161514, 0, true},  // ...even if unused in AES-128...
    {true, 0, 0, 2, 0, AES_KEY_SHARE0_0 + 0x18, 0xF, 0x1B1A1918, 0, true},  // ...even if unused in AES-192...
    {true, 0, 0, 2, 0, AES_KEY_SHARE0_0 + 0x1c, 0xF, 0x1F1E1D1C, 0, true},  // ...write "random" values

    {true, 0, 0, 2, 0, AES_KEY_SHARE1_0 + 0x00, 0xF, 0x0, 0, true},         // all key shares must be written - even if there's no masking
    {true, 0, 0, 2, 0, AES_KEY_SHARE1_0 + 0x04, 0xF, 0x0, 0, true},         // we do not have any masked key shares - so XOR 0
    {true, 0, 0, 2, 0, AES_KEY_SHARE1_0 + 0x08, 0xF, 0x0, 0, true},         // we do not have any masked key shares - so XOR 0
    {true, 0, 0, 2, 0, AES_KEY_SHARE1_0 + 0x0C, 0xF, 0x0, 0, true},         // we do not have any masked key shares - so XOR 0
    {true, 0, 0, 2, 0, AES_KEY_SHARE1_0 + 0x10, 0xF, 0x0, 0, true},         // all key shares must be written...
    {true, 0, 0, 2, 0, AES_KEY_SHARE1_0 + 0x14, 0xF, 0x0, 0, true},         // ...even if unused in AES-128...
    {true, 0, 0, 2, 0, AES_KEY_SHARE1_0 + 0x18, 0xF, 0x0, 0, true},         // ...even if unused in AES-192...
    {true, 0, 0, 2, 0, AES_KEY_SHARE1_0 + 0x1c, 0xF, 0x0, 0, true},         // ...so write zeros to be XORed

    {true, 0, 0, 2, 0, AES_DATA_IN_0 + 0x0, 0xF, 0x33221100, 0, true},      // write data0
    {true, 0, 0, 2, 0, AES_DATA_IN_0 + 0x4, 0xF, 0x77665544, 0, true},      // write data1
    {true, 0, 0, 2, 0, AES_DATA_IN_0 + 0x8, 0xF, 0xBBAA9988, 0, true},      // write data2
    {true, 0, 0, 2, 0, AES_DATA_IN_0 + 0xC, 0xF, 0xFFEEDDCC, 0, true},      // write data3 => one AES-Block has been sent

    {true, 4, 0, 2, 0, AES_STATUS, 0xF, 0x0, 0, true},                      // read status
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x0, 0xF, 0x0, 0, true},            // read data0
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x4, 0xF, 0x0, 0, true},            // read data1
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x8, 0xF, 0x0, 0, true},            // read data2
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0xC, 0xF, 0x0, 0, true},            // read data3 ==> one AES Block has been read => we can start over
    {true, 4, 0, 2, 0, AES_STATUS, 0xF, 0x0, 0, true},                      // read status

    {true, 0, 0, 2, 0, AES_CONFIG, 0xF,                                     // write AES_CONFIG, set lowest 8 bits
     (0x1 << AES_CTRL_MANUAL_OPERATION_OFFSET) | // !!THIS IS DEFFERENT!!   // DO NOT start automatic, but oveerwrite output
         (0x1 << AES_CTRL_KEY_LEN_OFFSET) |                                 // AES-128 (1), [AES-192 (2), AES-256 (4)]
         (kCryptoAesEcb << AES_CTRL_MODE_OFFSET) | 0x1,                     // ECB + ENC(1) [DEC(2)]
     0, true},  // ctrl - encrypt, 128-bit
    {true, 0, 0, 2, 0, AES_CONFIG, 0xF,                                     // we are using shaddow config
     (0x1 << AES_CTRL_MANUAL_OPERATION_OFFSET) |                            // write everything twice
         (0x1 << AES_CTRL_KEY_LEN_OFFSET) |                                 // with same parameters
         (kCryptoAesEcb << AES_CTRL_MODE_OFFSET) | 0x1,
     0, true},  // ctrl - encrypt, 128-bit
    {true, 0, 0, 2, 0, AES_TRIGGER, 0xF, 0x1, 0, true},                     // set start, as we are not in automatic mode!
    {true, 4, 0, 2, 0, AES_STATUS, 0xF, 0x0, 0, true},                      // read status
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x0, 0xF, 0x0, 0, true},            // only read - we are using the previous data!
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x4, 0xF, 0x0, 0, true},            // only read - we are using the previous data!
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x8, 0xF, 0x0, 0, true},            // only read - we are using the previous data!
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0xC, 0xF, 0x0, 0, true},            // only read - we are using the previous data!
    {true, 4, 0, 2, 0, AES_STATUS, 0xF, 0x0, 0, true},                      // read status

    
    // Clear
    {true, 0, 0, 2, 0, AES_TRIGGER, 0xF, 0x1E, 0, true},                    // clear (normally 0xE should be sufficient)
    {true, 4, 0, 2, 0, AES_STATUS, 0xF, 0x0, 0, true},                      // read status
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x0, 0xF, 0x0, 0, true},            // do one final reading of the AES-regs...
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x4, 0xF, 0x0, 0, true},            // ...hould now be cleared...
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x8, 0xF, 0x0, 0, true},            // ...with random values...
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0xC, 0xF, 0x0, 0, true},            // ...this is done by the AES-IP
};

// PART II: What the AES-IP returns over the TLUL-BUS:
// a) as a SystemVerilog struct, b) as Verilator cpp-struct, and c) as simplified cpp-struct

// a) SystemVerilog representation.
// typedef struct packed {
// logic                         d_valid;
// tl_d_op_e                     d_opcode;
// logic                  [2:0]  d_param;
// logic  [top_pkg::TL_SZW-1:0]  d_size;  
// logic  [top_pkg::TL_AIW-1:0]  d_source;
// logic  [top_pkg::TL_DIW-1:0]  d_sink;
// logic   [top_pkg::TL_DW-1:0]  d_data;    ==> we only care about that
// tl_d_user_t                   d_user;
// logic                         d_error;
// logic                         a_ready;
// } tl_d2h_t;

// b) Verilator cpp representation. We only use a subset of the possible values here.
// struct TLO {
//  public:
//   bool d_valid;
//   uint8_t d_opcode;
//   uint8_t d_param;
//   uint8_t d_size;
//   uint8_t d_source;
//   uint8_t d_sink;
//   uint32_t d_data;                       ==> we only care about that
//   uint32_t d_user;
//   bool d_error;
//   bool a_ready;
// };

// c) simplified ccp struct
// As we only care about the data values in this TB, we can use a much more simpler structure:
// exp_resp represents the data. mask is used to mask partial data, we are not interessted in.

// struct EXP_RESP {
//  public:
//   uint32_t mask;      ==> 32 bit mask ANDed wit exp_resp => if set to 0 don't care
//   uint32_t exp_resp;  ==> 32 bit of data that are expected on TLO.d_data
// };

// The respons depends on the data sent to AES.
// This means, if some of the status reads in Part I are changed, the response here must be adjusted

static const int num_responses_max = 1 + 12 + 5;      // Total number of transactions in this sequence
static const EXP_RESP tl_o_exp_resp[num_responses_max] = {
    {1 << AES_STATUS_IDLE_OFFSET,
     1 << AES_STATUS_IDLE_OFFSET},                    // we should be idle
    {1 << AES_STATUS_OUTPUT_VALID_OFFSET,
     1 << AES_STATUS_OUTPUT_VALID_OFFSET},            // AES has valid output
    {0x0, 0x0},                                       // we read the output of the first encryption,
    {0x0, 0x0},                                       // but we don't care about its actual value
    {0x0, 0x0},                                       // because we check that on the fly with the model checker
    {0x0, 0x0},                                       // change to actual values if you do care
    {1 << AES_STATUS_OUTPUT_VALID_OFFSET,
     0},                                              // now there shouldn't be a valid output any longer

    {1 << AES_STATUS_OUTPUT_VALID_OFFSET,
     1 << AES_STATUS_OUTPUT_VALID_OFFSET},            // we've started a new encryption, thus there should be valid output
    {CHECK_DATA_OUT ? 0xFFFFFFFF : 0x0, 0xD8E0C469},  // if CHECK_DATA_OUT is 1 we also care about its value
    {CHECK_DATA_OUT ? 0xFFFFFFFF : 0x0, 0x30047B6A},  // The actual value depends on the key and the input
    {CHECK_DATA_OUT ? 0xFFFFFFFF : 0x0, 0x80B7CDD8},  // and must be precalculated
    {CHECK_DATA_OUT ? 0xFFFFFFFF : 0x0, 0x5AC5B470},  // eg. use the python script or a crypto implementation
    {1 << AES_STATUS_OUTPUT_VALID_OFFSET,
     0},                                              // now we've read every thing. output shouldn't be valid anymore

    
    {1 << AES_STATUS_IDLE_OFFSET,
     1 << AES_STATUS_IDLE_OFFSET},                    // status shows idle
    {0x0, 0x0},                                       // data_out0 should be cleared to random value
    {0x0, 0x0},                                       // data_out1 should be cleared to random value
    {0x0, 0x0},                                       // data_out2 should be cleared to random value
    {0x0, 0x0},                                       // data_out3 should be cleared to random value
};

#endif  // OPENTITAN_HW_IP_AES_PRE_DV_AES_TB_CPP_AES_TLUL_SEQUENCE_DOC_H_
