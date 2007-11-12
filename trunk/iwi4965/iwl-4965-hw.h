/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2005 - 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU Geeral Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called LICENSE.GPL.
 *
 * Contact Information:
 * James P. Ketrenos <ipw2100-admin@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2005 - 2007 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

#ifndef __iwl_4965_hw_h__
#define __iwl_4965_hw_h__

#define IWL_RX_BUF_SIZE (4 * 1024)
#define IWL_MAX_BSM_SIZE BSM_SRAM_SIZE
#define IWL_MAX_INST_SIZE (96 * 1024)
#define IWL_MAX_DATA_SIZE (40 * 1024)

/********************* START TXPOWER *****************************************/
enum {
	HT_IE_EXT_CHANNEL_NONE = 0,
	HT_IE_EXT_CHANNEL_ABOVE,
	HT_IE_EXT_CHANNEL_INVALID,
	HT_IE_EXT_CHANNEL_BELOW,
	HT_IE_EXT_CHANNEL_MAX
};

enum {
	CALIB_CH_GROUP_1 = 0,
	CALIB_CH_GROUP_2 = 1,
	CALIB_CH_GROUP_3 = 2,
	CALIB_CH_GROUP_4 = 3,
	CALIB_CH_GROUP_5 = 4,
	CALIB_CH_GROUP_MAX
};

#define POWER_TABLE_NUM_HT_OFDM_ENTRIES           (32)

/* Temperature calibration offset is 3% 0C in Kelvin */
#define TEMPERATURE_CALIB_KELVIN_OFFSET 8
#define TEMPERATURE_CALIB_A_VAL 259

#define IWL_TX_POWER_TEMPERATURE_MIN  (263)
#define IWL_TX_POWER_TEMPERATURE_MAX  (410)

#define IWL_TX_POWER_TEMPERATURE_OUT_OF_RANGE(t) \
	(((t) < IWL_TX_POWER_TEMPERATURE_MIN) || \
	 ((t) > IWL_TX_POWER_TEMPERATURE_MAX))

#define IWL_TX_POWER_ILLEGAL_TEMPERATURE (300)

#define IWL_TX_POWER_TEMPERATURE_DIFFERENCE (2)

#define IWL_TX_POWER_MIMO_REGULATORY_COMPENSATION (6)

#define IWL_TX_POWER_TARGET_POWER_MIN       (0)	/* 0 dBm = 1 milliwatt */
#define IWL_TX_POWER_TARGET_POWER_MAX      (16)	/* 16 dBm */

/* timeout equivalent to 3 minutes */
#define IWL_TX_POWER_TIMELIMIT_NOCALIB 1800000000

#define IWL_TX_POWER_CCK_COMPENSATION (9)

#define MIN_TX_GAIN_INDEX		(0)
#define MIN_TX_GAIN_INDEX_52GHZ_EXT	(-9)
#define MAX_TX_GAIN_INDEX_52GHZ		(98)
#define MIN_TX_GAIN_52GHZ		(98)
#define MAX_TX_GAIN_INDEX_24GHZ		(98)
#define MIN_TX_GAIN_24GHZ		(98)
#define MAX_TX_GAIN			(0)
#define MAX_TX_GAIN_52GHZ_EXT		(-9)

#define IWL_TX_POWER_DEFAULT_REGULATORY_24   (34)
#define IWL_TX_POWER_DEFAULT_REGULATORY_52   (34)
#define IWL_TX_POWER_REGULATORY_MIN          (0)
#define IWL_TX_POWER_REGULATORY_MAX          (34)
#define IWL_TX_POWER_DEFAULT_SATURATION_24   (38)
#define IWL_TX_POWER_DEFAULT_SATURATION_52   (38)
#define IWL_TX_POWER_SATURATION_MIN          (20)
#define IWL_TX_POWER_SATURATION_MAX          (50)

/* dv *0.4 = dt; so that 5 degrees temperature diff equals
 * 12.5 in voltage diff */
#define IWL_TX_TEMPERATURE_UPDATE_LIMIT 9

#define IWL_INVALID_CHANNEL                 (0xffffffff)
#define IWL_TX_POWER_REGITRY_BIT            (2)

#define MIN_IWL_TX_POWER_CALIB_DUR          (100)
#define IWL_CCK_FROM_OFDM_POWER_DIFF        (-5)
#define IWL_CCK_FROM_OFDM_INDEX_DIFF (9)

/* Number of entries in the gain table */
#define POWER_GAIN_NUM_ENTRIES 78
#define TX_POW_MAX_SESSION_NUM 5
/*  timeout equivalent to 3 minutes */
#define TX_IWL_TIMELIMIT_NOCALIB 1800000000

/* Kedron TX_CALIB_STATES */
#define IWL_TX_CALIB_STATE_SEND_TX        0x00000001
#define IWL_TX_CALIB_WAIT_TX_RESPONSE     0x00000002
#define IWL_TX_CALIB_ENABLED              0x00000004
#define IWL_TX_CALIB_XVT_ON               0x00000008
#define IWL_TX_CALIB_TEMPERATURE_CORRECT  0x00000010
#define IWL_TX_CALIB_WORKING_WITH_XVT     0x00000020
#define IWL_TX_CALIB_XVT_PERIODICAL       0x00000040

#define NUM_IWL_TX_CALIB_SETTINS 5	/* Number of tx correction groups */

#define IWL_MIN_POWER_IN_VP_TABLE 1	/* 0.5dBm multiplied by 2 */
#define IWL_MAX_POWER_IN_VP_TABLE 40	/* 20dBm - multiplied by 2 (because
					 * entries are for each 0.5dBm) */
#define IWL_STEP_IN_VP_TABLE 1	/* 0.5dB - multiplied by 2 */
#define IWL_NUM_POINTS_IN_VPTABLE \
	(1 + IWL_MAX_POWER_IN_VP_TABLE - IWL_MIN_POWER_IN_VP_TABLE)

#define MIN_TX_GAIN_INDEX         (0)
#define MAX_TX_GAIN_INDEX_52GHZ   (98)
#define MIN_TX_GAIN_52GHZ         (98)
#define MAX_TX_GAIN_INDEX_24GHZ   (98)
#define MIN_TX_GAIN_24GHZ         (98)
#define MAX_TX_GAIN               (0)

/* First and last channels of all groups */
#define CALIB_IWL_TX_ATTEN_GR1_FCH 34
#define CALIB_IWL_TX_ATTEN_GR1_LCH 43
#define CALIB_IWL_TX_ATTEN_GR2_FCH 44
#define CALIB_IWL_TX_ATTEN_GR2_LCH 70
#define CALIB_IWL_TX_ATTEN_GR3_FCH 71
#define CALIB_IWL_TX_ATTEN_GR3_LCH 124
#define CALIB_IWL_TX_ATTEN_GR4_FCH 125
#define CALIB_IWL_TX_ATTEN_GR4_LCH 200
#define CALIB_IWL_TX_ATTEN_GR5_FCH 1
#define CALIB_IWL_TX_ATTEN_GR5_LCH 20

struct tx_power_dual_stream {
	__le16 ramon_tx_gain;
	__le16 dsp_predis_atten;
} __attribute__ ((packed));

union tx_power_dual_stream_u {
	struct tx_power_dual_stream s;
	__le32 dw;
} __attribute__ ((packed));

struct iwl_tx_power_db {
	union tx_power_dual_stream_u
	 ht_ofdm_power[POWER_TABLE_NUM_HT_OFDM_ENTRIES];
	union tx_power_dual_stream_u legacy_cck_power;

} __attribute__ ((packed));

struct iwl_tx_power_table_cmd {
	u8 band;
	u8 channel_normal_width;
	__le16 channel;
	struct iwl_tx_power_db tx_power;
} __attribute__ ((packed));

/********************* END TXPOWER *****************************************/

/* HT flags */
#define RXON_FLG_CONTROL_CHANNEL_LOCATION_MSK	0x400000
#define RXON_FLG_CONTROL_CHANNEL_LOC_LOW_MSK	0x000000
#define RXON_FLG_CONTROL_CHANNEL_LOC_HIGH_MSK	0x400000

#define RXON_FLG_HT_OPERATING_MODE_POS		(23)
/*yshevet - bug fix */
#define RXON_FLG_HT_PROT_MSK			0x800000
#define RXON_FLG_FAT_PROT_MSK			0x1000000

#define RXON_FLG_CHANNEL_MODE_POS		(25)
#define RXON_FLG_CHANNEL_MODE_MSK		0x06000000
#define RXON_FLG_CHANNEL_MODE_LEGACY_MSK	0x00000000
#define RXON_FLG_CHANNEL_MODE_PURE_40_MSK	0x02000000
#define RXON_FLG_CHANNEL_MODE_MIXED_MSK		0x04000000

#define RXON_RX_CHAIN_DRIVER_FORCE_MSK		(0x1<<0)
#define RXON_RX_CHAIN_VALID_MSK			(0x7<<1)
#define RXON_RX_CHAIN_VALID_POS			(1)
#define RXON_RX_CHAIN_FORCE_SEL_MSK		(0x7<<4)
#define RXON_RX_CHAIN_FORCE_SEL_POS		(4)
#define RXON_RX_CHAIN_FORCE_MIMO_SEL_MSK	(0x7<<7)
#define RXON_RX_CHAIN_FORCE_MIMO_SEL_POS	(7)
#define RXON_RX_CHAIN_CNT_MSK			(0x3<<10)
#define RXON_RX_CHAIN_CNT_POS			(10)
#define RXON_RX_CHAIN_MIMO_CNT_MSK		(0x3<<12)
#define RXON_RX_CHAIN_MIMO_CNT_POS		(12)
#define RXON_RX_CHAIN_MIMO_FORCE_MSK		(0x1<<14)
#define RXON_RX_CHAIN_MIMO_FORCE_POS		(14)


#define MCS_DUP_6M_PLCP 0x20

/* OFDM HT rate masks */
/* ***************************************** */
#define R_MCS_6M_MSK 0x1
#define R_MCS_12M_MSK 0x2
#define R_MCS_18M_MSK 0x4
#define R_MCS_24M_MSK 0x8
#define R_MCS_36M_MSK 0x10
#define R_MCS_48M_MSK 0x20
#define R_MCS_54M_MSK 0x40
#define R_MCS_60M_MSK 0x80
#define R_MCS_12M_DUAL_MSK 0x100
#define R_MCS_24M_DUAL_MSK 0x200
#define R_MCS_36M_DUAL_MSK 0x400
#define R_MCS_48M_DUAL_MSK 0x800

#define is_legacy(tbl) (((tbl) == LQ_G) || ((tbl) == LQ_A))
#define is_siso(tbl) (((tbl) == LQ_SISO))
#define is_mimo(tbl) (((tbl) == LQ_MIMO))
#define is_Ht(tbl) (is_siso(tbl) || is_mimo(tbl))
#define is_a_band(tbl) (((tbl) == LQ_A))
#define is_g_and(tbl) (((tbl) == LQ_G))

/*RS_NEW_API: only TLC_RTS remains and moved to bit 0 */
#define  LINK_QUAL_FLAGS_SET_STA_TLC_RTS_MSK	(1<<0)

#define  LINK_QUAL_AC_NUM AC_NUM
#define  LINK_QUAL_MAX_RETRY_NUM 16

#define  LINK_QUAL_ANT_A_MSK (1<<0)
#define  LINK_QUAL_ANT_B_MSK (1<<1)
#define  LINK_QUAL_ANT_MSK   (LINK_QUAL_ANT_A_MSK|LINK_QUAL_ANT_B_MSK)

struct iwl_link_qual_general_params {
	u8 flags;
	u8 mimo_delimiter;
	u8 single_stream_ant_msk;
	u8 dual_stream_ant_msk;
	u8 start_rate_index[LINK_QUAL_AC_NUM];
} __attribute__ ((packed));

struct iwl_link_qual_agg_params {
	__le16 agg_time_limit;
	u8 agg_dis_start_th;
	u8 agg_frame_cnt_limit;
	__le32 reserved;
} __attribute__ ((packed));

struct iwl_link_quality_cmd {
	u8 sta_id;
	u8 reserved1;
	__le16 control;
	struct iwl_link_qual_general_params general_params;
	struct iwl_link_qual_agg_params agg_params;
	struct iwl_rate rate_scale_table[LINK_QUAL_MAX_RETRY_NUM];
	__le32 reserved2;
} __attribute__ ((packed));

#define STA_FLG_PWR_SAVE_MSK                0x100

/* Flow Handler Definitions */

/**********************/
/*     Addresses      */
/**********************/

#define FH_MEM_LOWER_BOUND                   (0x1000)
#define FH_MEM_UPPER_BOUND                   (0x1EF0)

#define IWL_FH_REGS_LOWER_BOUND		     (0x1000)
#define IWL_FH_REGS_UPPER_BOUND		     (0x2000)

/* TFDB  Area - TFDs buffer table */
#define FH_MEM_TFDB_LOWER_BOUND              (FH_MEM_LOWER_BOUND + 0x000)
#define FH_MEM_TFDB_UPPER_BOUND              (FH_MEM_LOWER_BOUND + 0x900)
/* channels 0 - 8 */
#define FH_MEM_TFDB_CHNL_BUF0(x) (FH_MEM_TFDB_LOWER_BOUND + (x) * 0x100)
#define FH_MEM_TFDB_CHNL_BUF1(x) (FH_MEM_TFDB_LOWER_BOUND + 0x80 + (x) * 0x100)

/* TFDIB Area - TFD Immediate Buffer */
#define FH_MEM_TFDIB_LOWER_BOUND	     (FH_MEM_LOWER_BOUND + 0x900)
#define FH_MEM_TFDIB_UPPER_BOUND	     (FH_MEM_LOWER_BOUND + 0x958)
/* channels 0 - 10 */
#define FH_MEM_TFDIB_CHNL(x)     (FH_MEM_TFDIB_LOWER_BOUND + (x) * 0x8)

/* TFDIB registers used in Service Mode */
#define FH_MEM_TFDIB_CHNL9_REG0		     (FH_MEM_TFDIB_CHNL(9))
#define FH_MEM_TFDIB_CHNL9_REG1		     (FH_MEM_TFDIB_CHNL(9) + 4)
#define FH_MEM_TFDIB_CHNL10_REG0	     (FH_MEM_TFDIB_CHNL(10))
#define FH_MEM_TFDIB_CHNL10_REG1	     (FH_MEM_TFDIB_CHNL(10) + 4)

/* Tx service channels */
#define FH_MEM_TFDIB_DRAM_ADDR_LSB_MASK	     (0xFFFFFFFF)
#define FH_MEM_TFDIB_DRAM_ADDR_MSB_MASK	     (0xF00000000)
#define FH_MEM_TFDIB_TB_LENGTH_MASK	     (0x0001FFFF)	/* bits 16:0 */

#define FH_MEM_TFDIB_DRAM_ADDR_LSB_BITSHIFT  (0)
#define FH_MEM_TFDIB_DRAM_ADDR_MSB_BITSHIFT  (32)
#define FH_MEM_TFDIB_TB_LENGTH_BITSHIFT	     (0)

#define FH_MEM_TFDIB_REG0_ADDR_MASK	     (0xFFFFFFFF)
#define FH_MEM_TFDIB_REG1_ADDR_MASK	     (0xF0000000)
#define FH_MEM_TFDIB_REG1_LENGTH_MASK	     (0x0001FFFF)

#define FH_MEM_TFDIB_REG0_ADDR_BITSHIFT	     (0)
#define FH_MEM_TFDIB_REG1_ADDR_BITSHIFT	     (28)
#define FH_MEM_TFDIB_REG1_LENGTH_BITSHIFT    (0)

/* TRB Area - Transmit Request Buffers */
#define FH_MEM_TRB_LOWER_BOUND		     (FH_MEM_LOWER_BOUND + 0x0958)
#define FH_MEM_TRB_UPPER_BOUND		     (FH_MEM_LOWER_BOUND + 0x0980)
/* channels 0 - 8 */
#define FH_MEM_TRB_CHNL(x)	   (FH_MEM_TRB_LOWER_BOUND + (x) * 0x4)

#define IWL_FH_KW_MEM_ADDR_REG		     (FH_MEM_LOWER_BOUND + 0x97C)
/* STAGB Area - Scheduler TAG Buffer */
#define FH_MEM_STAGB_LOWER_BOUND	     (FH_MEM_LOWER_BOUND + 0x980)
#define FH_MEM_STAGB_UPPER_BOUND	     (FH_MEM_LOWER_BOUND + 0x9D0)
/* channels 0 - 8 */
#define FH_MEM_STAGB_0(x)     (FH_MEM_STAGB_LOWER_BOUND + (x) * 0x8)
#define FH_MEM_STAGB_1(x)     (FH_MEM_STAGB_LOWER_BOUND + 0x4 + (x) * 0x8)

/* Tx service channels */
#define FH_MEM_SRAM_ADDR_9	     (FH_MEM_STAGB_LOWER_BOUND + 0x048)
#define FH_MEM_SRAM_ADDR_10	     (FH_MEM_STAGB_LOWER_BOUND + 0x04C)

#define FH_MEM_STAGB_SRAM_ADDR_MASK	     (0x00FFFFFF)

/* CBBC Area - Circular buffers base address cache pointers table */
#define FH_MEM_CBBC_LOWER_BOUND              (FH_MEM_LOWER_BOUND + 0x9D0)
#define FH_MEM_CBBC_UPPER_BOUND              (FH_MEM_LOWER_BOUND + 0xA10)
/* queues 0 - 15 */
#define FH_MEM_CBBC_QUEUE(x)  (FH_MEM_CBBC_LOWER_BOUND + (x) * 0x4)

/* TAGR Area - TAG reconstruct table */
#define FH_MEM_TAGR_LOWER_BOUND              (FH_MEM_LOWER_BOUND + 0xA10)
#define FH_MEM_TAGR_UPPER_BOUND              (FH_MEM_LOWER_BOUND + 0xA70)

/* TDBGR Area - Tx Debug Registers */
#define FH_MEM_TDBGR_LOWER_BOUND             (FH_MEM_LOWER_BOUND + 0x0A70)
#define FH_MEM_TDBGR_UPPER_BOUND             (FH_MEM_LOWER_BOUND + 0x0B20)
/* channels 0 - 10 */
#define FH_MEM_TDBGR_CHNL(x)      (FH_MEM_TDBGR_LOWER_BOUND + (x) * 0x10)

#define FH_MEM_TDBGR_CHNL_REG_0(x)	     (FH_MEM_TDBGR_CHNL(x))
#define FH_MEM_TDBGR_CHNL_REG_1(x)	     (FH_MEM_TDBGR_CHNL_REG_0(x) + 0x4)

#define FH_MEM_TDBGR_CHNL_BYTES_TO_FIFO_MASK		(0x000FFFFF)
#define FH_MEM_TDBGR_CHNL_BYTES_TO_FIFO_BITSHIFT	(0)

/* RDBUF Area */
#define FH_MEM_RDBUF_LOWER_BOUND             (FH_MEM_LOWER_BOUND + 0xB80)
#define FH_MEM_RDBUF_UPPER_BOUND             (FH_MEM_LOWER_BOUND + 0xBC0)
#define FH_MEM_RDBUF_CHNL0		     (FH_MEM_RDBUF_LOWER_BOUND)

/* RSCSR Area */
#define FH_MEM_RSCSR_LOWER_BOUND	(FH_MEM_LOWER_BOUND + 0xBC0)
#define FH_MEM_RSCSR_UPPER_BOUND	(FH_MEM_LOWER_BOUND + 0xC00)
#define FH_MEM_RSCSR_CHNL0		(FH_MEM_RSCSR_LOWER_BOUND)
#define FH_MEM_RSCSR_CHNL1		(FH_MEM_RSCSR_LOWER_BOUND + 0x020)

/* RSCSR registers used in Normal mode*/
#define FH_RSCSR_CHNL0_STTS_WPTR_REG		(FH_MEM_RSCSR_CHNL0)
#define FH_RSCSR_CHNL0_RBDCB_BASE_REG		(FH_MEM_RSCSR_CHNL0 + 0x004)
#define FH_RSCSR_CHNL0_RBDCB_WPTR_REG		(FH_MEM_RSCSR_CHNL0 + 0x008)
#define FH_RSCSR_CHNL0_RBDCB_RPTR_REG		(FH_MEM_RSCSR_CHNL0 + 0x00c)

#define FH_RSCSR_FRAME_SIZE_MASK	(0x00003FFF)	/* bits 0-13 */
/* RSCSR registers used in Service mode*/
#define FH_RSCSR_CHNL1_RB_WPTR_REG		(FH_MEM_RSCSR_CHNL1)
#define FH_RSCSR_CHNL1_RB_WPTR_OFFSET_REG	(FH_MEM_RSCSR_CHNL1 + 0x004)
#define FH_RSCSR_CHNL1_RB_CHUNK_NUM_REG		(FH_MEM_RSCSR_CHNL1 + 0x008)
#define FH_RSCSR_CHNL1_SRAM_ADDR_REG		(FH_MEM_RSCSR_CHNL1 + 0x00C)

/* RCSR Area - Registers address map */
#define FH_MEM_RCSR_LOWER_BOUND      (FH_MEM_LOWER_BOUND + 0xC00)
#define FH_MEM_RCSR_UPPER_BOUND      (FH_MEM_LOWER_BOUND + 0xCC0)
#define FH_MEM_RCSR_CHNL0            (FH_MEM_RCSR_LOWER_BOUND)
#define FH_MEM_RCSR_CHNL1            (FH_MEM_RCSR_LOWER_BOUND + 0x020)

#define FH_MEM_RCSR_CHNL0_CONFIG_REG	(FH_MEM_RCSR_CHNL0)
#define FH_MEM_RCSR_CHNL0_CREDIT_REG	(FH_MEM_RCSR_CHNL0 + 0x004)
#define FH_MEM_RCSR_CHNL0_RBD_STTS_REG	(FH_MEM_RCSR_CHNL0 + 0x008)
#define FH_MEM_RCSR_CHNL0_RB_STTS_REG	(FH_MEM_RCSR_CHNL0 + 0x00C)
#define FH_MEM_RCSR_CHNL0_RXPD_STTS_REG	(FH_MEM_RCSR_CHNL0 + 0x010)

#define FH_MEM_RCSR_CHNL0_RBD_STTS_FRAME_RB_CNT_MASK (0x7FFFFFF0) /* bits4:30 */

/* RCSR registers used in Service mode*/
#define FH_MEM_RCSR_CHNL1_CONFIG_REG		(FH_MEM_RCSR_CHNL1)
#define FH_MEM_RCSR_CHNL1_RB_STTS_REG         	(FH_MEM_RCSR_CHNL1 + 0x00C)
#define FH_MEM_RCSR_CHNL1_RX_PD_STTS_REG       	(FH_MEM_RCSR_CHNL1 + 0x010)

/* RSSR Area - Rx shared ctrl & status registers */
#define FH_MEM_RSSR_LOWER_BOUND                	(FH_MEM_LOWER_BOUND + 0xC40)
#define FH_MEM_RSSR_UPPER_BOUND               	(FH_MEM_LOWER_BOUND + 0xD00)
#define FH_MEM_RSSR_SHARED_CTRL_REG           	(FH_MEM_RSSR_LOWER_BOUND)
#define FH_MEM_RSSR_RX_STATUS_REG	(FH_MEM_RSSR_LOWER_BOUND + 0x004)
#define FH_MEM_RSSR_RX_ENABLE_ERR_IRQ2DRV  (FH_MEM_RSSR_LOWER_BOUND + 0x008)

/* TCSR */
#define IWL_FH_TCSR_LOWER_BOUND  (IWL_FH_REGS_LOWER_BOUND + 0xD00)
#define IWL_FH_TCSR_UPPER_BOUND  (IWL_FH_REGS_LOWER_BOUND + 0xE60)

#define IWL_FH_TCSR_CHNL_NUM                            (7)
#define IWL_FH_TCSR_CHNL_TX_CONFIG_REG(_chnl) \
	(IWL_FH_TCSR_LOWER_BOUND + 0x20 * _chnl)
#define IWL_FH_TCSR_CHNL_TX_CREDIT_REG(_chnl) \
	  (IWL_FH_TCSR_LOWER_BOUND + 0x20 * _chnl + 0x4)
#define IWL_FH_TCSR_CHNL_TX_BUF_STS_REG(_chnl) \
	 (IWL_FH_TCSR_LOWER_BOUND + 0x20 * _chnl + 0x8)

/* TSSR Area - Tx shared status registers */
/* TSSR */
#define IWL_FH_TSSR_LOWER_BOUND		(IWL_FH_REGS_LOWER_BOUND + 0xEA0)
#define IWL_FH_TSSR_UPPER_BOUND		(IWL_FH_REGS_LOWER_BOUND + 0xEC0)

#define IWL_FH_TSSR_TX_MSG_CONFIG_REG	(IWL_FH_TSSR_LOWER_BOUND + 0x008)
#define IWL_FH_TSSR_TX_STATUS_REG	(IWL_FH_TSSR_LOWER_BOUND + 0x010)

#define IWL_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TXPD_ON	(0xFF000000)
#define IWL_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_TXPD_ON	(0x00FF0000)

#define IWL_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_64B	(0x00000000)
#define IWL_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_128B	(0x00000400)
#define IWL_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_256B	(0x00000800)
#define IWL_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_512B	(0x00000C00)

#define IWL_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TFD_ON	(0x00000100)
#define IWL_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_CBB_ON	(0x00000080)

#define IWL_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RSP_WAIT_TH	(0x00000020)
#define IWL_FH_TSSR_TX_MSG_CONFIG_REG_VAL_RSP_WAIT_TH		(0x00000005)

#define IWL_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_chnl)	\
	((1 << (_chnl)) << 24)
#define IWL_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_chnl) \
	((1 << (_chnl)) << 16)

#define IWL_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(_chnl) \
	(IWL_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_chnl) | \
	IWL_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_chnl))

/* SRVC */
#define IWL_FH_SRVC_LOWER_BOUND          (IWL_FH_REGS_LOWER_BOUND + 0x9C8)
#define IWL_FH_SRVC_UPPER_BOUND          (IWL_FH_REGS_LOWER_BOUND + 0x9D0)

#define IWL_FH_SRVC_CHNL_SRAM_ADDR_REG(_chnl) \
	  (IWL_FH_SRVC_LOWER_BOUND + (_chnl - 9) * 0x4)

/* TFDIB */
#define IWL_FH_TFDIB_LOWER_BOUND         (IWL_FH_REGS_LOWER_BOUND + 0x900)
#define IWL_FH_TFDIB_UPPER_BOUND         (IWL_FH_REGS_LOWER_BOUND + 0x958)

#define IWL_FH_TFDIB_CTRL0_REG(_chnl)    \
	(IWL_FH_TFDIB_LOWER_BOUND + 0x8 * _chnl)
#define IWL_FH_TFDIB_CTRL1_REG(_chnl)    \
	(IWL_FH_TFDIB_LOWER_BOUND + 0x8 * _chnl + 0x4)

#define IWL_FH_SRVC_CHNL                                (9)
#define IWL_FH_TFDIB_CTRL1_REG_POS_MSB                  (28)

/* Debug Monitor Area */
#define FH_MEM_DM_LOWER_BOUND            (FH_MEM_LOWER_BOUND + 0xEE0)
#define FH_MEM_DM_UPPER_BOUND            (FH_MEM_LOWER_BOUND + 0xEF0)
#define FH_MEM_DM_CONTROL_MASK_REG       (FH_MEM_DM_LOWER_BOUND)
#define FH_MEM_DM_CONTROL_START_REG      (FH_MEM_DM_LOWER_BOUND + 0x004)
#define FH_MEM_DM_CONTROL_STATUS_REG     (FH_MEM_DM_LOWER_BOUND + 0x008)
#define FH_MEM_DM_MONITOR_REG            (FH_MEM_DM_LOWER_BOUND + 0x00C)

#define FH_TB1_ADDR_LOW_MASK	(0xFFFFFFFF)	/* bits 31:0 */
#define FH_TB1_ADDR_HIGH_MASK	(0xF00000000)	/* bits 35:32 */
#define FH_TB2_ADDR_LOW_MASK	(0x0000FFFF)	/* bits 15:0 */
#define FH_TB2_ADDR_HIGH_MASK	(0xFFFFF0000)	/* bits 35:16 */

#define FH_TB1_ADDR_LOW_BITSHIFT	(0)
#define FH_TB1_ADDR_HIGH_BITSHIFT	(32)
#define FH_TB2_ADDR_LOW_BITSHIFT	(0)
#define FH_TB2_ADDR_HIGH_BITSHIFT	(16)

#define FH_TB1_LENGTH_MASK         (0x00000FFF)	/* bits 11:0 */
#define FH_TB2_LENGTH_MASK         (0x00000FFF)	/* bits 11:0 */

/* number of FH channels including 2 service mode */
#define NUM_OF_FH_CHANNELS (10)

/* ctrl field bitology */
#define FH_TFD_CTRL_PADDING_MASK     (0xC0000000)	/* bits 31:30 */
#define FH_TFD_CTRL_NUMTB_MASK       (0x1F000000)	/* bits 28:24 */

#define FH_TFD_CTRL_PADDING_BITSHIFT                (30)
#define FH_TFD_CTRL_NUMTB_BITSHIFT                  (24)

#define FH_TFD_GET_NUM_TBS(ctrl) \
	((ctrl & FH_TFD_CTRL_NUMTB_MASK) >> FH_TFD_CTRL_NUMTB_BITSHIFT)
#define FH_TFD_GET_PADDING(ctrl) \
	((ctrl & FH_TFD_CTRL_PADDING_MASK) >> FH_TFD_CTRL_PADDING_BITSHIFT)

/* TCSR: tx_config register values */
#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_TXF              (0x00000000)
#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_DRIVER           (0x00000001)
#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_ARC              (0x00000002)

#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE_VAL    (0x00000000)
#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL     (0x00000008)

#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_NOINT           (0x00000000)
#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_ENDTFD          (0x00100000)
#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_IFTFD           (0x00200000)

#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_NOINT            (0x00000000)
#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_ENDTFD           (0x00400000)
#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_IFTFD            (0x00800000)

#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE            (0x00000000)
#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE_EOF        (0x40000000)
#define IWL_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE           (0x80000000)

#define IWL_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_EMPTY          (0x00000000)
#define IWL_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_WAIT           (0x00002000)
#define IWL_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID          (0x00000003)

#define IWL_FH_TCSR_CHNL_TX_BUF_STS_REG_BIT_TFDB_WPTR           (0x00000001)

#define IWL_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_NUM              (20)
#define IWL_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_IDX              (12)

/* CBB table */
#define FH_CBB_ADDR_MASK	0x0FFFFFFF	/* bits 27:0 */
#define FH_CBB_ADDR_BIT_SHIFT		(8)

/* RCSR:  channel 0 rx_config register defines */
#define FH_RCSR_CHNL0_RX_CONFIG_DMA_CHNL_EN_MASK  (0xC0000000) /* bits 30-31 */
#define FH_RCSR_CHNL0_RX_CONFIG_RBDBC_SIZE_MASK   (0x00F00000) /* bits 20-23 */
#define FH_RCSR_CHNL0_RX_CONFIG_RB_SIZE_MASK	  (0x00030000) /* bits 16-17 */
#define FH_RCSR_CHNL0_RX_CONFIG_SINGLE_FRAME_MASK (0x00008000) /* bit 15 */
#define FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_MASK     (0x00001000) /* bit 12 */
#define FH_RCSR_CHNL0_RX_CONFIG_RB_TIMEOUT_MASK   (0x00000FF0) /* bit 4-11 */

#define FH_RCSR_RX_CONFIG_RBDCB_SIZE_BITSHIFT       (20)
#define FH_RCSR_RX_CONFIG_RB_SIZE_BITSHIFT			(16)

#define FH_RCSR_GET_RDBC_SIZE(reg) \
	 ((reg & FH_RCSR_RX_CONFIG_RDBC_SIZE_MASK) >> \
	  FH_RCSR_RX_CONFIG_RDBC_SIZE_BITSHIFT)

/* RCSR:  channel 1 rx_config register defines */
#define FH_RCSR_CHNL1_RX_CONFIG_DMA_CHNL_EN_MASK  (0xC0000000) /* bits 30-31 */
#define FH_RCSR_CHNL1_RX_CONFIG_IRQ_DEST_MASK	  (0x00003000) /* bits 12-13 */

/* RCSR: rx_config register values */
#define FH_RCSR_RX_CONFIG_CHNL_EN_PAUSE_VAL         (0x00000000)
#define FH_RCSR_RX_CONFIG_CHNL_EN_PAUSE_EOF_VAL     (0x40000000)
#define FH_RCSR_RX_CONFIG_CHNL_EN_ENABLE_VAL        (0x80000000)
#define FH_RCSR_RX_CONFIG_SINGLE_FRAME_MODE	    (0x00008000)

#define FH_RCSR_RX_CONFIG_RDRBD_DISABLE_VAL         (0x00000000)
#define FH_RCSR_RX_CONFIG_RDRBD_ENABLE_VAL          (0x20000000)

#define IWL_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_4K    (0x00000000)

/* RCSR channel 0 config register values */
#define FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_NO_INT_VAL       (0x00000000)
#define FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_INT_HOST_VAL     (0x00001000)

/* RCSR channel 1 config register values */
#define FH_RCSR_CHNL1_RX_CONFIG_IRQ_DEST_NO_INT_VAL       (0x00000000)
#define FH_RCSR_CHNL1_RX_CONFIG_IRQ_DEST_INT_HOST_VAL     (0x00001000)
#define FH_RCSR_CHNL1_RX_CONFIG_IRQ_DEST_INT_RTC_VAL      (0x00002000)
#define FH_RCSR_CHNL1_RX_CONFIG_IRQ_DEST_INT_HOST_RTC_VAL (0x00003000)

/* RCSR: rb status register defines */
#define FH_RCSR_RB_BYTE_TO_SEND_MASK		(0x0001FFFF)	/* bits 0-16 */

/* RSCSR: defs used in normal mode */
#define FH_RSCSR_CHNL0_RBDCB_WPTR_MASK		(0x00000FFF)	/* bits 0-11 */

/* RSCSR: defs used in service mode */
#define FH_RSCSR_CHNL1_SRAM_ADDR_MASK		(0x00FFFFFF)	/* bits 0-23 */
#define FH_RSCSR_CHNL1_RB_WPTR_MASK		(0x0FFFFFFF)	/* bits 0-27 */
#define FH_RSCSR_CHNL1_RB_WPTR_OFFSET_MASK	(0x000000FF)	/* bits 0-7 */

/* RSSR: RX Enable Error IRQ to Driver register defines */
#define FH_MEM_RSSR_RX_ENABLE_ERR_IRQ2DRV_NO_RBD (0x00400000)	/* bit 22 */

#define FH_DRAM2SRAM_DRAM_ADDR_HIGH_MASK	(0xFFFFFFF00)	/* bits 8-35 */
#define FH_DRAM2SRAM_DRAM_ADDR_LOW_MASK		(0x000000FF)	/* bits 0-7 */

#define FH_DRAM2SRAM_DRAM_ADDR_HIGH_BITSHIFT	(8)	/* bits 8-35 */

/* RX DRAM status regs definitions  */
#define FH_RX_RB_NUM_MASK			(0x00000FFF)	/* bits 0-11 */
#define FH_RX_FRAME_NUM_MASK			(0x0FFF0000) /* bits 16-27 */

#define FH_RX_RB_NUM_BITSHIFT			(0)
#define FH_RX_FRAME_NUM_BITSHIFT		(16)

#define SCD_WIN_SIZE				64
#define SCD_FRAME_LIMIT				10

/* memory mapped registers */
#define SCD_START_OFFSET		0xa02c00

#define SCD_SRAM_BASE_ADDR           (SCD_START_OFFSET + 0x0)
#define SCD_EMPTY_BITS               (SCD_START_OFFSET + 0x4)
#define SCD_DRAM_BASE_ADDR           (SCD_START_OFFSET + 0x10)
#define SCD_AIT                      (SCD_START_OFFSET + 0x18)
#define SCD_TXFACT                   (SCD_START_OFFSET + 0x1c)
#define SCD_QUEUE_WRPTR(x)           (SCD_START_OFFSET + 0x24 + (x) * 4)
#define SCD_QUEUE_RDPTR(x)           (SCD_START_OFFSET + 0x64 + (x) * 4)
#define SCD_SETQUEUENUM              (SCD_START_OFFSET + 0xa4)
#define SCD_SET_TXSTAT_TXED          (SCD_START_OFFSET + 0xa8)
#define SCD_SET_TXSTAT_DONE          (SCD_START_OFFSET + 0xac)
#define SCD_SET_TXSTAT_NOT_SCHD      (SCD_START_OFFSET + 0xb0)
#define SCD_DECREASE_CREDIT          (SCD_START_OFFSET + 0xb4)
#define SCD_DECREASE_SCREDIT         (SCD_START_OFFSET + 0xb8)
#define SCD_LOAD_CREDIT              (SCD_START_OFFSET + 0xbc)
#define SCD_LOAD_SCREDIT             (SCD_START_OFFSET + 0xc0)
#define SCD_BAR                      (SCD_START_OFFSET + 0xc4)
#define SCD_BAR_DW0                  (SCD_START_OFFSET + 0xc8)
#define SCD_BAR_DW1                  (SCD_START_OFFSET + 0xcc)
#define SCD_QUEUECHAIN_SEL           (SCD_START_OFFSET + 0xd0)
#define SCD_QUERY_REQ                (SCD_START_OFFSET + 0xd8)
#define SCD_QUERY_RES                (SCD_START_OFFSET + 0xdc)
#define SCD_PENDING_FRAMES           (SCD_START_OFFSET + 0xe0)
#define SCD_INTERRUPT_MASK           (SCD_START_OFFSET + 0xe4)
#define SCD_INTERRUPT_THRESHOLD      (SCD_START_OFFSET + 0xe8)
#define SCD_QUERY_MIN_FRAME_SIZE     (SCD_START_OFFSET + 0x100)
#define SCD_QUEUE_STATUS_BITS(x)     (SCD_START_OFFSET + 0x104 + (x) * 4)

/* SRAM structures */
#define SCD_CONTEXT_DATA_OFFSET			0x380
#define SCD_TX_STTS_BITMAP_OFFSET		0x400
#define SCD_TRANSLATE_TBL_OFFSET		0x500
#define SCD_CONTEXT_QUEUE_OFFSET(x)	(SCD_CONTEXT_DATA_OFFSET + ((x) * 8))
#define SCD_TRANSLATE_TBL_OFFSET_QUEUE(x) \
	((SCD_TRANSLATE_TBL_OFFSET + ((x) * 2)) & 0xfffffffc)

#define SCD_TXFACT_REG_TXFIFO_MASK(lo, hi) \
       ((1<<(hi))|((1<<(hi))-(1<<(lo))))


#define SCD_MODE_REG_BIT_SEARCH_MODE		(1<<0)
#define SCD_MODE_REG_BIT_SBYP_MODE		(1<<1)

#define SCD_TXFIFO_POS_TID			(0)
#define SCD_TXFIFO_POS_RA			(4)
#define SCD_QUEUE_STTS_REG_POS_ACTIVE		(0)
#define SCD_QUEUE_STTS_REG_POS_TXF		(1)
#define SCD_QUEUE_STTS_REG_POS_WSL		(5)
#define SCD_QUEUE_STTS_REG_POS_SCD_ACK		(8)
#define SCD_QUEUE_STTS_REG_POS_SCD_ACT_EN	(10)
#define SCD_QUEUE_STTS_REG_MSK			(0x0007FC00)

#define SCD_QUEUE_RA_TID_MAP_RATID_MSK		(0x01FF)

#define SCD_QUEUE_CTX_REG1_WIN_SIZE_POS		(0)
#define SCD_QUEUE_CTX_REG1_WIN_SIZE_MSK		(0x0000007F)
#define SCD_QUEUE_CTX_REG1_CREDIT_POS		(8)
#define SCD_QUEUE_CTX_REG1_CREDIT_MSK		(0x00FFFF00)
#define SCD_QUEUE_CTX_REG1_SUPER_CREDIT_POS	(24)
#define SCD_QUEUE_CTX_REG1_SUPER_CREDIT_MSK	(0xFF000000)
#define SCD_QUEUE_CTX_REG2_FRAME_LIMIT_POS	(16)
#define SCD_QUEUE_CTX_REG2_FRAME_LIMIT_MSK	(0x007F0000)

#define CSR_HW_IF_CONFIG_REG_BIT_KEDRON_R	(0x00000010)
#define CSR_HW_IF_CONFIG_REG_MSK_BOARD_VER	(0x00000C00)
#define CSR_HW_IF_CONFIG_REG_BIT_MAC_SI		(0x00000100)
#define CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI	(0x00000200)


 /*IWL4965-END */

#define IWL4965_BROADCAST_ID    (31)

#define RX_RES_PHY_CNT 14

#define STATISTICS_FLG_CLEAR                      (0x1)
#define STATISTICS_FLG_DISABLE_NOTIFICATION       (0x2)

#define STATISTICS_REPLY_FLG_CLEAR                (0x1)
#define STATISTICS_REPLY_FLG_BAND_24G_MSK         (0x2)
#define STATISTICS_REPLY_FLG_TGJ_NARROW_BAND_MSK  (0x4)
#define STATISTICS_REPLY_FLG_FAT_MODE_MSK         (0x8)
#define RX_PHY_FLAGS_ANTENNAE_OFFSET		(4)
#define RX_PHY_FLAGS_ANTENNAE_MASK		(0x70)

struct iwl4965_rx_phy_res {
	u8 non_cfg_phy_cnt;     /* non configurable DSP phy data byte count */
	u8 cfg_phy_cnt;		/* configurable DSP phy data byte count */
	u8 stat_id;		/* configurable DSP phy data set ID */
	u8 reserved1;
	__le64 timestamp;	/* TSF at on air rise */
	__le32 beacon_time_stamp; /* beacon at on-air rise */
	__le16 phy_flags;	/* general phy flags: band, modulation, ... */
	__le16 channel;		/* channel number */
	__le16 non_cfg_phy[RX_RES_PHY_CNT];	/* upto 14 phy entries */
	__le32 reserved2;
	struct iwl_rate rate;	/* rate in ucode internal format */
	__le16 byte_count;		/* frame's byte-count */
	__le16 reserved3;
} __attribute__ ((packed));

struct iwl4965_rx_mpdu_res_start {
	__le16 byte_count;
	__le16 reserved;
} __attribute__ ((packed));

#if 0

union iwl_dram_scratch_union {
	struct iwl_dram_scratch s;
	__le32 dw;
};

struct iwl4965_beacon_notify {
	struct iwl_tx_resp beacon_notify_hdr;	/*15:4 */
	__le32 low_tsf;		/*19:16 */
	__le32 high_tsf;		/*23:20 */
	__le32 ibss_mgr_status;	/*27:24 */
} __attribute__ ((packed));

struct iwl4965_tx_beacon_cmd {
	struct iwl_tx_cmd tx;	/*byte 55:4 */
	__le16 tim_idx;		/*byte 57:56 */
	u8 tim_size;		/*byte 58 */
	u8 reserved1;		/*byte 59 */
	struct ieee80211_hdr frame[0];
	/* Beacon Frame */
} __attribute__ ((packed));

struct iwl4965_powertable_cmd {
	__le16 flags;
	u8 keep_alive_seconds;
	u8 debug_flags;
	__le32 rx_data_timeout;
	__le32 tx_data_timeout;
	__le32 sleep_interval[PMC_TCMD_SLEEP_INTRVL_TABLE_SIZE];
	__le32 keep_alive_beacons;
} __attribute__ ((packed));

#define IWL_NUM_OF_STATIONS  ( 32 )
#define BYTE_CNT_AREA_OFFSET            0

enum HT_STATUS {
	BA_STATUS_FAILURE = 0,
	BA_STATUS_INITIATOR_DELBA,
	BA_STATUS_RECIPIENT_DELBA,
	BA_STATUS_RENEW_ADDBA_REQUEST,
	BA_STATUS_ACTIVE,
};
#endif

#define IWL_AGC_DB_MASK 	(0x3f80)	/* MASK(7,13) */
#define IWL_AGC_DB_POS		(7)
/* Fixed (non-configurable) rx data from phy */
struct iwl4965_rx_non_cfg_phy {
	__le16 ant_selection;	/* ant A bit 4, ant B bit 5, ant C bit 6 */
	__le16 agc_info;	/* agc code 0:6, agc dB 7:13, reserved 14:15 */
	u8 rssi_info[6];	/* we use even entries, 0/2/4 for A/B/C rssi */
	u8 pad[0];
} __attribute__ ((packed));

struct iwl_tfd_frame_data {
	__le32 tb1_addr;

	__le32 val1;
	/* __le32 ptb1_32_35:4; */
#define IWL_tb1_addr_hi_POS 0
#define IWL_tb1_addr_hi_LEN 4
#define IWL_tb1_addr_hi_SYM val1
	/* __le32 tb_len1:12; */
#define IWL_tb1_len_POS 4
#define IWL_tb1_len_LEN 12
#define IWL_tb1_len_SYM val1
	/* __le32 ptb2_0_15:16; */
#define IWL_tb2_addr_lo16_POS 16
#define IWL_tb2_addr_lo16_LEN 16
#define IWL_tb2_addr_lo16_SYM val1

	__le32 val2;
	/* __le32 ptb2_16_35:20; */
#define IWL_tb2_addr_hi20_POS 0
#define IWL_tb2_addr_hi20_LEN 20
#define IWL_tb2_addr_hi20_SYM val2
	/* __le32 tb_len2:12; */
#define IWL_tb2_len_POS 20
#define IWL_tb2_len_LEN 12
#define IWL_tb2_len_SYM val2
} __attribute__ ((packed));

struct iwl_tfd_frame {
	__le32 val0;
	/* __le32 rsvd1:24; */
	/* __le32 num_tbs:5; */
#define IWL_num_tbs_POS 24
#define IWL_num_tbs_LEN 5
#define IWL_num_tbs_SYM val0
	/* __le32 rsvd2:1; */
	/* __le32 padding:2; */
	struct iwl_tfd_frame_data pa[10];
	__le32 reserved;
} __attribute__ ((packed));

#define IWL4965_MAX_WIN_SIZE              64
#define IWL4965_QUEUE_SIZE               256
#define IWL4965_NUM_FIFOS                  7
#define IWL4965_NUM_QUEUES                16

struct iwl4965_queue_byte_cnt_entry {
	__le16 val;
	/* __le16 byte_cnt:12; */
#define IWL_byte_cnt_POS 0
#define IWL_byte_cnt_LEN 12
#define IWL_byte_cnt_SYM val
	/* __le16 rsvd:4; */
} __attribute__ ((packed));

struct iwl4965_sched_queue_byte_cnt_tbl {
	struct iwl4965_queue_byte_cnt_entry tfd_offset[IWL4965_QUEUE_SIZE +
						       IWL4965_MAX_WIN_SIZE];
	u8 dont_care[1024 -
		     (IWL4965_QUEUE_SIZE + IWL4965_MAX_WIN_SIZE) *
		     sizeof(__le16)];
} __attribute__ ((packed));

/* Base physical address of iwl_shared is provided to SCD_DRAM_BASE_ADDR
 * and &iwl_shared.val0 is provided to FH_RSCSR_CHNL0_STTS_WPTR_REG */
struct iwl_shared {
	struct iwl4965_sched_queue_byte_cnt_tbl
	 queues_byte_cnt_tbls[IWL4965_NUM_QUEUES];
	__le32 val0;

	/* __le32 rb_closed_stts_rb_num:12; */
#define IWL_rb_closed_stts_rb_num_POS 0
#define IWL_rb_closed_stts_rb_num_LEN 12
#define IWL_rb_closed_stts_rb_num_SYM val0
	/* __le32 rsrv1:4; */
	/* __le32 rb_closed_stts_rx_frame_num:12; */
#define IWL_rb_closed_stts_rx_frame_num_POS 16
#define IWL_rb_closed_stts_rx_frame_num_LEN 12
#define IWL_rb_closed_stts_rx_frame_num_SYM val0
	/* __le32 rsrv2:4; */

	__le32 val1;
	/* __le32 frame_finished_stts_rb_num:12; */
#define IWL_frame_finished_stts_rb_num_POS 0
#define IWL_frame_finished_stts_rb_num_LEN 12
#define IWL_frame_finished_stts_rb_num_SYM val1
	/* __le32 rsrv3:4; */
	/* __le32 frame_finished_stts_rx_frame_num:12; */
#define IWL_frame_finished_stts_rx_frame_num_POS 16
#define IWL_frame_finished_stts_rx_frame_num_LEN 12
#define IWL_frame_finished_stts_rx_frame_num_SYM val1
	/* __le32 rsrv4:4; */

	__le32 padding1;  /* so that allocation will be aligned to 16B */
	__le32 padding2;
} __attribute__ ((packed));

#endif /* __iwl_4965_hw_h__ */
