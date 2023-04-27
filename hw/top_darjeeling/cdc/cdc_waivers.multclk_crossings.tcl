# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# Verix CDC waiver file

# Multiple clocks on PAD are muxed in or out as designed. These waivers are included in other waivers such as cdc_waivers.w_masync, cdc_waivers.w_data, etc.
# tpm csb is a muxed connection. PAD input (mio_pad[38]) is recognized in JTAG_TCK domain and transferred to SPI clock domain.
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "-") && (MultiClockDomains == "JTAG_TCK::SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_sck_csb_edge.g_sync.u_sync.u_sync_1.gen_generic.u_impl_generic.q_o[0]") && (SampleTxSignal == "u_padring.gen_mio_pads[38].u_mio_pad.gen_generic.u_impl_generic.in_o") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_in_buf.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "-") && (MultiClockDomains == "JTAG_TCK::SPI_DEV_OUT_CLK,SPI_DEV_PASSTHRU_OUT_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_spi_tpm.u_rdfifo.sync_wptr.u_sync_1.gen_generic.u_impl_generic.q_o[0]") && (SampleTxSignal == "u_padring.gen_mio_pads[38].u_mio_pad.gen_generic.u_impl_generic.in_o") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_out_buf.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
# Signals from SPI clock domain are transferred to PAD outputs in IO_DIV4_CLK domain.
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "u_padring.gen_dio_pads[19].u_dio_pad.gen_generic.u_impl_generic.in_o") && (MultiClockDomains == "SPI_DEV_CLK,SPI_DEV_PASSTHRU_CLK::IO_DIV4_CLK") && (SampleRxSignal == "top_darjeeling.u_pinmux_aon.dio_out_retreg_q[14]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_passthrough.u_pt_sck_cg.gen_generic.u_impl_generic.en_latch") && (ToClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
# Signals from IO_DIV4_CLK and SPI clock domains are transferred to regs in IO_DIV4_CLK domain.
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_spi_device.u_sram_clk_sel.gen_generic.u_impl_generic.clk_o") && (MultiClockDomains == "IO_DIV4_CLK,SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK::IO_DIV4_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_reg.u_reg_if.rdata_q[2]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_fwmode.u_tx_fifo.fifo_wptr_q[0]") && (ToClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o")} -status {Waived}  -comment {Reviewed : a normal CDC path handled properly}
# Signals from IO_DIV2/4_CLK and SPI clock domains are transferred to regs in SPI clk domain.
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_spi_device.u_sram_clk_sel.gen_generic.u_impl_generic.clk_o") && (MultiClockDomains == "IO_DIV4_CLK,SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK::SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_fwmode.u_rx_fifo.sync_rptr.u_sync_1.gen_generic.u_impl_generic.q_o[0]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_fwmode.u_rx_fifo.fifo_rptr_gray_q[0]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_in_buf.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_spi_device.u_sram_clk_scan.gen_generic.u_impl_generic.clk_o") && (MultiClockDomains == "IO_DIV2_CLK,IO_DIV4_CLK,SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK::IO_DIV4_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_reg.u_reg_if.rdata_q[2]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_fwmode.u_tx_fifo.fifo_wptr_q[0]") && (ToClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o")} -status {Waived}  -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_spi_device.u_sram_clk_scan.gen_generic.u_impl_generic.clk_o") && (MultiClockDomains == "IO_DIV2_CLK,IO_DIV4_CLK,SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK::SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_fwmode.u_rx_fifo.sync_rptr.u_sync_1.gen_generic.u_impl_generic.q_o[0]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_fwmode.u_rx_fifo.fifo_rptr_gray_q[0]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_in_buf.clk_o")} -status {Waived}  -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "SPI_DEV_CLK") && (MultiClockDomains == "SPI_DEV_CLK,SPI_DEV_PASSTHRU_CLK::IO_DIV4_CLK") && (SampleRxSignal == "top_darjeeling.u_pinmux_aon.dio_out_retreg_q[14]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_passthrough.u_pt_sck_cg.gen_generic.u_impl_generic.en_latch") && (ToClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o")} -status {Waived}  -comment {Reviewed : a normal CDC path handled properly}
# Signals from JTAG_TCK clock domains are transferred to regs in SPI clk domain.
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "-") && (MultiClockDomains == "JTAG_TCK::SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_sck_csb_edge.g_sync.u_sync.u_sync_1.gen_generic.u_impl_generic.q_o[0]") && (SampleTxSignal == "IOR3") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_in_buf.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "-") && (MultiClockDomains == "JTAG_TCK::SPI_DEV_OUT_CLK,SPI_DEV_PASSTHRU_OUT_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_spi_tpm.u_rdfifo.sync_wptr.u_sync_1.gen_generic.u_impl_generic.q_o[0]") && (SampleTxSignal == "IOR3") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_out_buf.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
# Signals from IO_DIV2/4_CLK clock domains are transferred to regs in SPI clk domain.
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o") && (MultiClockDomains == "IO_DIV4_CLK::SPI_DEV_CLK,SPI_DEV_PASSTHRU_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_clk_spi_in_mux.gen_generic.u_impl_generic.clk_o") && (SampleTxSignal == "u_ast.dft_scan_md_o[3]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_in_mux.gen_generic.u_impl_generic.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o") && (MultiClockDomains == "IO_DIV4_CLK::SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_csb_edge_spiclk.g_sync.u_sync.u_sync_1.gen_generic.u_impl_generic.q_o[0]") && (SampleTxSignal == "u_ast.dft_scan_md_o[3]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_in_buf.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o") && (MultiClockDomains == "IO_DIV4_CLK::SPI_DEV_OUT_CLK,SPI_DEV_PASSTHRU_OUT_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_p2s.cnt[0]") && (SampleTxSignal == "u_ast.dft_scan_md_o[3]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_out_buf.clk_o")} -status {Waived}  -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o") && (MultiClockDomains == "IO_DIV4_CLK::SPI_CSB_CLK,SPI_DEV_PASSTHRU_CSB_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_spid_status.u_stage_to_commit.gen_generic.u_impl_generic.q_o[0]") && (SampleTxSignal == "u_ast.dft_scan_md_o[3]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_csb_buf.clk_o")} -status {Waived}  -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o") && (MultiClockDomains == "IO_DIV4_CLK::IO_DIV4_CLK,JTAG_TCK") && (SampleRxSignal == "top_darjeeling.u_lc_ctrl.u_dmi_jtag.i_dmi_jtag_tap.jtag_ir_shift_q[0]") && (SampleTxSignal == "u_ast.dft_scan_md_o[3]") && (ToClockSignal == "top_darjeeling.u_lc_ctrl.u_prim_clock_mux2.gen_generic.u_impl_generic.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o") && (MultiClockDomains == "IO_DIV4_CLK::IO_DIV4_CLK,SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_sram_clk_scan.gen_generic.u_impl_generic.clk_o") && (SampleTxSignal == "u_ast.dft_scan_md_o[3]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_sram_clk_scan.gen_generic.u_impl_generic.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o") && (MultiClockDomains == "IO_DIV4_CLK::IO_DIV2_CLK,IO_DIV4_CLK,SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_sram_clk_cg.gen_generic.u_impl_generic.clk_o") && (SampleTxSignal == "u_ast.dft_scan_md_o[3]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_sram_clk_cg.gen_generic.u_impl_generic.clk_o")} -status {Waived}  -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div2_div.clk_o") && (MultiClockDomains == "IO_DIV2_CLK::SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_fwmode.u_rx_fifo.sync_rptr.u_sync_1.gen_generic.u_impl_generic.q_o[0]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_fwmode.u_rx_fifo.fifo_rptr_gray_q[0]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_in_buf.clk_o")} -status {Waived}  -comment {Reviewed : a normal CDC path handled properly}
# Signals from SPI clock domains are transferred to regs in IO_DIV4_CLK domain.
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "SPI_DEV_CLK") && (MultiClockDomains == "SPI_DEV_CLK,SPI_DEV_PASSTHRU_CLK::IO_DIV4_CLK") && (SampleRxSignal == "top_darjeeling.u_pinmux_aon.dio_out_retreg_q[14]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_passthrough.u_pt_sck_cg.gen_generic.u_impl_generic.en_latch") && (ToClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o")} -status {Waived}  -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_in_buf.clk_o") && (MultiClockDomains == "SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK::IO_DIV4_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_reg.u_reg_if.rdata_q[2]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_fwmode.u_tx_fifo.fifo_wptr_q[0]") && (ToClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_spi_device.u_clk_csb_buf.clk_o") && (MultiClockDomains == "SPI_CSB_CLK,SPI_DEV_PASSTHRU_CSB_CLK::IO_DIV4_CLK") && (SampleRxSignal == "top_darjeeling.u_pinmux_aon.dio_oe_retreg_q[2]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_spid_status.u_stage_to_commit.gen_generic.u_impl_generic.q_o[0]") && (ToClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_out_buf.clk_o") && (MultiClockDomains == "SPI_DEV_OUT_CLK,SPI_DEV_PASSTHRU_OUT_CLK::IO_DIV4_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_txf_underflow.prim_flop_2sync.u_sync_1.gen_generic.u_impl_generic.q_o[0]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_txf_underflow.src_level") && (ToClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o")} -status {Waived}  -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_in_buf.clk_o") && (MultiClockDomains == "SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK::IO_DIV2_CLK,IO_DIV4_CLK,SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_memory_2p.b_rvalid_sram_q") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_s2p.data_q[0]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_sram_clk_scan.gen_generic.u_impl_generic.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
# Signals from SPI clock domains are transferred to regs in SPI clock domain.
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "SPI_DEV_CLK") && (MultiClockDomains == "SPI_DEV_CLK,SPI_DEV_PASSTHRU_CLK::IO_DIV4_CLK") && (SampleRxSignal == "top_darjeeling.u_pinmux_aon.dio_out_retreg_q[14]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_passthrough.u_pt_sck_cg.gen_generic.u_impl_generic.en_latch") && (ToClockSignal == "top_darjeeling.u_clkmgr_aon.u_no_scan_io_div4_div.clk_o")} -status {Waived}  -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_out_buf.clk_o") && (MultiClockDomains == "SPI_DEV_OUT_CLK,SPI_DEV_PASSTHRU_OUT_CLK::SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_spid_status.byte_sel_q[0]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_p2s.cnt[0]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_in_buf.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_out_buf.clk_o") && (MultiClockDomains == "SPI_DEV_OUT_CLK,SPI_DEV_PASSTHRU_OUT_CLK::IO_DIV2_CLK,IO_DIV4_CLK,SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_fwmode.u_tx_fifo.sync_rptr.u_sync_1.gen_generic.u_impl_generic.q_o[0]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_fwmode.u_tx_fifo.fifo_rptr_gray_q[0]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_sram_clk_scan.gen_generic.u_impl_generic.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_spi_device.u_clk_csb_buf.clk_o") && (MultiClockDomains == "SPI_CSB_CLK,SPI_DEV_PASSTHRU_CSB_CLK::SPI_DEV_OUT_CLK,SPI_DEV_PASSTHRU_OUT_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_spid_status.outclk_p2s_byte_o[0]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_spid_status.u_stage_to_commit.gen_generic.u_impl_generic.q_o[0]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_out_buf.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
set_rule_status -rule {MULTCLK_CROSSINGS} -expression {(ClockDomains == "") && (FromClockSignal == "top_darjeeling.u_spi_device.u_clk_spi_in_buf.clk_o") && (MultiClockDomains == "SPI_DEV_IN_CLK,SPI_DEV_PASSTHRU_IN_CLK::SPI_CSB_CLK,SPI_DEV_PASSTHRU_CSB_CLK") && (SampleRxSignal == "top_darjeeling.u_spi_device.u_spid_status.u_stage_to_commit.gen_generic.u_impl_generic.q_o[0]") && (SampleTxSignal == "top_darjeeling.u_spi_device.u_spid_status.sck_status_staged[0]") && (ToClockSignal == "top_darjeeling.u_spi_device.u_clk_csb_buf.clk_o")} -status {Waived} -comment {Reviewed : a normal CDC path handled properly}
