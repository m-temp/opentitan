#!/usr/bin/env python3
# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0


def verilator_req_header(runs, key):
    # we need to adjust the endianness
    key0 =bytes(key[3::-1]).hex()
    key1 =bytes(key[7:3:-1]).hex()
    key2 =bytes(key[11:7:-1]).hex()
    key3 =bytes(key[15:11:-1]).hex()

    return (
   "static const int num_transactions_max = 1+2+16 +"+str(runs)+"*(4+1+4+1) + 6;           // init, set+mode+key, data-loop, clear\n" +
   '''
static const TLI tl_i_transactions[num_transactions_max] = {
    {true, 4, 0, 2, 0, AES_STATUS, 0xF, 0x0, 0, true},                      // read status
    // AES-128
    {true, 0, 0, 2, 0, AES_CONFIG, 0xF,                                     // write AES_CONFIG, set lowest 8 bits
     (0x0 << AES_CTRL_MANUAL_OPERATION_OFFSET) |                            // start automatic, do not oveerwrite output
         (0x1 << AES_CTRL_KEY_LEN_OFFSET) |                                 // AES-128 (1), [AES-192 (2), AES-256 (4)]
         (kCryptoAesEcb << AES_CTRL_MODE_OFFSET) | 0x1,                     // ECB + ENC
     0, true},  // ctrl - decrypt, 128-bit
    {true, 0, 0, 2, 0, AES_CONFIG, 0xF,                                     // we are using shaddow config
     (0x0 << AES_CTRL_MANUAL_OPERATION_OFFSET) |                            // write everything twice
         (0x1 << AES_CTRL_KEY_LEN_OFFSET) |                                 // with same parameters
         (kCryptoAesEcb << AES_CTRL_MODE_OFFSET) | 0x1,
     0, true},  // ctrl - decrypt, 128-bit
    {true, 0, 0, 2, 0, AES_KEY_SHARE0_0 + 0x00, 0xF, 0x'''+key0+''', 0, true},  // write key0
    {true, 0, 0, 2, 0, AES_KEY_SHARE0_0 + 0x04, 0xF, 0x'''+key1+''', 0, true},  // write key1
    {true, 0, 0, 2, 0, AES_KEY_SHARE0_0 + 0x08, 0xF, 0x'''+key2+''', 0, true},  // write key2
    {true, 0, 0, 2, 0, AES_KEY_SHARE0_0 + 0x0C, 0xF, 0x'''+key3+''', 0, true},  // write key3
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
''')

def verilator_req_data(request):

    # we need to adjust the endianness
    in0 =bytes(request[3::-1]).hex()
    in1 =bytes(request[7:3:-1]).hex()
    in2 =bytes(request[11:7:-1]).hex()
    in3 =bytes(request[15:11:-1]).hex()

    intext = '''
    {true, 0, 0, 2, 0, AES_DATA_IN_0 + 0x0, 0xF, 0x'''+in0+''', 0, true},      // write data0
    {true, 0, 0, 2, 0, AES_DATA_IN_0 + 0x4, 0xF, 0x'''+in1+''', 0, true},      // write data1
    {true, 0, 0, 2, 0, AES_DATA_IN_0 + 0x8, 0xF, 0x'''+in2+''', 0, true},      // write data2
    {true, 0, 0, 2, 0, AES_DATA_IN_0 + 0xC, 0xF, 0x'''+in3+''', 0, true},      // write data3 ==> one AES Block has been sent => we can start over

    {true, 4, 0, 2, 0, AES_STATUS, 0xF, 0x0, 0, true},                      // read status
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x0, 0xF, 0x0, 0, true},            // read data0
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x4, 0xF, 0x0, 0, true},            // read data1
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x8, 0xF, 0x0, 0, true},            // read data2
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0xC, 0xF, 0x0, 0, true},            // read data3 ==> one AES Block has been read => we can start over
    {true, 4, 0, 2, 0, AES_STATUS, 0xF, 0x0, 0, true},                      // read status
    '''

    return intext

verilator_req_footer = '''
    // Clear
    {true, 0, 0, 2, 0, AES_TRIGGER, 0xF, 0x1E, 0, true},                    // clear (normally 0xE should be sufficient)
    {true, 4, 0, 2, 0, AES_STATUS, 0xF, 0x0, 0, true},                      // read status
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x0, 0xF, 0x0, 0, true},            // do one final reading of the AES-regs
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x4, 0xF, 0x0, 0, true},            // should now be cleared
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0x8, 0xF, 0x0, 0, true},            // with random values
    {true, 4, 0, 2, 0, AES_DATA_OUT_0 + 0xC, 0xF, 0x0, 0, true},            // this is done by the AES-IP
};
'''

def verilator_res_header(runs):
   return (
   "static const int num_responses_max = 1 + "+str(runs)+"*6 + 5;    // init, data-loop, clear\n" +
   '''
static const EXP_RESP tl_o_exp_resp[num_responses_max] = {
    {1 << AES_STATUS_IDLE_OFFSET,
     1 << AES_STATUS_IDLE_OFFSET},                    // we should be idle
''')

def verilator_res_data(response,prefix=""):

    # we need to adjust the endianness
    out0 =bytes(response[3::-1]).hex()
    out1 =bytes(response[7:3:-1]).hex()
    out2 =bytes(response[11:7:-1]).hex()
    out3 =bytes(response[15:11:-1]).hex()
   
    outtext = '''
    {1 << AES_STATUS_OUTPUT_VALID_OFFSET,
     1 << AES_STATUS_OUTPUT_VALID_OFFSET},            // we've started a new encryption, thus there should be valid output
    {CHECK_DATA_OUT ? 0xFFFFFFFF : 0x0, 0x'''+out0+'''},  // read data0
    {CHECK_DATA_OUT ? 0xFFFFFFFF : 0x0, 0x'''+out1+'''},  // read data1
    {CHECK_DATA_OUT ? 0xFFFFFFFF : 0x0, 0x'''+out2+'''},  // read data2
    {CHECK_DATA_OUT ? 0xFFFFFFFF : 0x0, 0x'''+out3+'''},  // read data3
    {1 << AES_STATUS_OUTPUT_VALID_OFFSET,
     0},                                              // now we've read every thing. output shouldn't be valid anymore
    '''

    return outtext

verilator_res_footer = '''
    {1 << AES_STATUS_IDLE_OFFSET,
     1 << AES_STATUS_IDLE_OFFSET},                    // status shows idle
    {0x0, 0x0},                                       // data_out0 should be cleared to random value
    {0x0, 0x0},                                       // data_out1 should be cleared to random value
    {0x0, 0x0},                                       // data_out2 should be cleared to random value
    {0x0, 0x0},                                       // data_out3 should be cleared to random value
};
'''


verilator_header = '''
// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// This file is autogenerated! Do not change!

#ifndef OPENTITAN_HW_IP_AES_PRE_DV_AES_TB_CPP_AES_TLUL_SEQUENCE_AUTO_H_
#define OPENTITAN_HW_IP_AES_PRE_DV_AES_TB_CPP_AES_TLUL_SEQUENCE_AUTO_H_

#include "aes_tlul_sequence_common.h"
#include "crypto.h"
'''

verilator_footer = '''
#endif  // OPENTITAN_HW_IP_AES_PRE_DV_AES_TB_CPP_AES_TLUL_SEQUENCE_AUTO_H_
'''

def create_sequence(plaintext, ciphertext, key, runs=1, file = "sequence_auto.h"):
    with open(file, 'w') as f:
        f.write(verilator_header)

        f.write(verilator_req_header(runs, key))
        for i in range(runs):
            f.write(verilator_req_data(plaintext[i]))
        f.write(verilator_req_footer)

        f.write(verilator_res_header(runs))
        for i in range(runs):
            f.write(verilator_res_data(ciphertext[i]))
        f.write(verilator_res_footer)

        f.write(verilator_footer)


if __name__ == "__main__":

    sequence_file= "../cpp/aes_tlul_sequence_auto.h"

    number_of_encryptions = 1
    ineff_ciphertexts = [[92, 234, 191, 5, 228, 156, 66, 56, 57, 244, 168, 162, 91, 46, 14, 252]]
    ineff_plaintexts = [[225, 245, 50, 91, 220, 63, 92, 99, 75, 233, 128, 60, 196, 100, 148, 200]]
    known_key=[43, 126,  21,  22,  40, 174, 210, 166, 171, 247,  21, 136,   9, 207,  79,  60]
    
    create_sequence(ineff_plaintexts, ineff_ciphertexts, known_key, number_of_encryptions, sequence_file)
