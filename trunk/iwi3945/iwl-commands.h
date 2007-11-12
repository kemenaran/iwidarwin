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

#ifndef __iwl_commands_h__
#define __iwl_commands_h__
#include "defines.h"

enum {
	REPLY_ALIVE = 0x1,
	REPLY_ERROR = 0x2,

	/* RXON state commands */
	REPLY_RXON = 0x10,
	REPLY_RXON_ASSOC = 0x11,
	REPLY_QOS_PARAM = 0x13,
	REPLY_RXON_TIMING = 0x14,

	/* Multi-Station support */
	REPLY_ADD_STA = 0x18,
#if IWL == 3945
	REPLY_REMOVE_STA = 0x19,
	REPLY_REMOVE_ALL_STA = 0x1a,
#endif

	/* RX, TX */
#if IWL == 3945
	REPLY_3945_RX = 0x1b,
#endif

	REPLY_TX = 0x1c,

	/* timers commands */
	REPLY_BCON = 0x27,

#if IWL == 4965
	REPLY_SHUTDOWN = 0x40,
#endif

	/* MISC commands */
	REPLY_RATE_SCALE = 0x47,
	REPLY_LEDS_CMD = 0x48,
	REPLY_TX_LINK_QUALITY_CMD = 0x4e,

	/* 802.11h related */
	RADAR_NOTIFICATION = 0x70,
	REPLY_QUIET_CMD = 0x71,
	REPLY_CHANNEL_SWITCH = 0x72,
	CHANNEL_SWITCH_NOTIFICATION = 0x73,
	REPLY_SPECTRUM_MEASUREMENT_CMD = 0x74,
	SPECTRUM_MEASURE_NOTIFICATION = 0x75,

	/* Power Management *** */
	POWER_TABLE_CMD = 0x77,
	PM_SLEEP_NOTIFICATION = 0x7A,
	PM_DEBUG_STATISTIC_NOTIFIC = 0x7B,

	/* Scan commands and notifications */
	REPLY_SCAN_CMD = 0x80,
	REPLY_SCAN_ABORT_CMD = 0x81,

	SCAN_START_NOTIFICATION = 0x82,
	SCAN_RESULTS_NOTIFICATION = 0x83,
	SCAN_COMPLETE_NOTIFICATION = 0x84,

	/* IBSS/AP commands */
	BEACON_NOTIFICATION = 0x90,
	REPLY_TX_BEACON = 0x91,
	WHO_IS_AWAKE_NOTIFICATION = 0x94,

	QUIET_NOTIFICATION = 0x96,
	REPLY_TX_PWR_TABLE_CMD = 0x97,
	MEASURE_ABORT_NOTIFICATION = 0x99,

	REPLY_CALIBRATION_TUNE = 0x9a,

	/* BT config command */
	REPLY_BT_CONFIG = 0x9b,
	REPLY_STATISTICS_CMD = 0x9c,
	STATISTICS_NOTIFICATION = 0x9d,

	/* RF-KILL commands and notifications *** */
	REPLY_CARD_STATE_CMD = 0xa0,
	CARD_STATE_NOTIFICATION = 0xa1,

	/* Missed beacons notification */
	MISSED_BEACONS_NOTIFICATION = 0xa2,
	MISSED_BEACONS_NOTIFICATION_TH_CMD = 0xa3,

#if IWL == 4965
	REPLY_CT_KILL_CONFIG_CMD = 0xa4,
	SENSITIVITY_CMD = 0xa8,
	REPLY_PHY_CALIBRATION_CMD = 0xb0,
	REPLY_4965_RX = 0xc3,
	REPLY_RX_PHY_CMD = 0xc0,
	REPLY_RX_MPDU_CMD = 0xc1,
	REPLY_COMPRESSED_BA = 0xc5,
#endif
	REPLY_MAX = 0xff
};

/*
 * Tx Command & Response:
 */

/* Tx flags */
enum {
	TX_CMD_FLG_RTS_MSK = (1 << 1),
	TX_CMD_FLG_CTS_MSK = (1 << 2),
	TX_CMD_FLG_ACK_MSK = (1 << 3),
	TX_CMD_FLG_STA_RATE_MSK = (1 << 4),
	TX_CMD_FLG_IMM_BA_RSP_MASK = (1 << 6),
	TX_CMD_FLG_FULL_TXOP_PROT_MSK = (1 << 7),
	TX_CMD_FLG_ANT_SEL_MSK = 0xf00,
	TX_CMD_FLG_ANT_A_MSK = (1 << 8),
	TX_CMD_FLG_ANT_B_MSK = (1 << 9),

	/* ucode ignores BT priority for this frame */
	TX_CMD_FLG_BT_DIS_MSK = (1 << 12),

	/* ucode overrides sequence control */
	TX_CMD_FLG_SEQ_CTL_MSK = (1 << 13),

	/* signal that this frame is non-last MPDU */
	TX_CMD_FLG_MORE_FRAG_MSK = (1 << 14),

	/* calculate TSF in outgoing frame */
	TX_CMD_FLG_TSF_MSK = (1 << 16),

	/* activate TX calibration. */
	TX_CMD_FLG_CALIB_MSK = (1 << 17),

	/* signals that 2 bytes pad was inserted
	 * after the MAC header */
	TX_CMD_FLG_MH_PAD_MSK = (1 << 20),

	/* HCCA-AP - disable duration overwriting. */
	TX_CMD_FLG_DUR_MSK = (1 << 25),
};

/*
 * TX command security control
 */
#define TX_CMD_SEC_CCM               0x2
#define TX_CMD_SEC_TKIP              0x3

/*
 * TX command Frame life time
 */

#if IWL == 3945
struct iwl_rate {
	union {
		struct {
			u8 rate;
			u8 flags;
		} s;
		__le16 rate_n_flags;
	};
} __attribute__ ((packed));
#elif IWL == 4965
struct iwl_rate {
	union {
		struct {
			u8 rate;
			u8 flags;
			__le16 ext_flags;
		} s;
		__le32 rate_n_flags;
	};
} __attribute__ ((packed));
#endif

struct iwl_dram_scratch {
	u8 try_cnt;
	u8 bt_kill_cnt;
	__le16 reserved;
} __attribute__ ((packed));

struct iwl_tx_cmd {
	__le16 len;
	__le16 next_frame_len;
	__le32 tx_flags;
#if IWL == 3945
	u8 rate;
	u8 sta_id;
	u8 tid_tspec;
#elif IWL == 4965
	struct iwl_dram_scratch scratch;
	struct iwl_rate rate;
	u8 sta_id;
#endif
	u8 sec_ctl;
#if IWL == 4965
	u8 initial_rate_index;
	u8 reserved;
#endif
	u8 key[16];
#if IWL == 3945
	union {
		u8 byte[8];
		__le16 word[4];
		__le32 dw[2];
	} tkip_mic;
	__le32 next_frame_info;
#elif IWL == 4965
	__le16 next_frame_flags;
	__le16 reserved2;
#endif
	union {
		__le32 life_time;
		__le32 attempt;
	} stop_time;
#if IWL == 3945
	u8 supp_rates[2];
#elif IWL == 4965
	__le32 dram_lsb_ptr;
	u8 dram_msb_ptr;
#endif
	u8 rts_retry_limit;	/*byte 50 */
	u8 data_retry_limit;	/*byte 51 */
#if IWL == 4965
	u8 tid_tspec;
#endif
	union {
		__le16 pm_frame_timeout;
		__le16 attempt_duration;
	} timeout;
	__le16 driver_txop;
	u8 payload[0];
	struct ieee80211_hdr hdr[0];
} __attribute__ ((packed));

/*
 * TX command response status
 */
enum {
	TX_STATUS_SUCCESS = 0x01,
	TX_STATUS_DIRECT_DONE = 0x02,
	TX_STATUS_FAIL_SHORT_LIMIT = 0x82,
	TX_STATUS_FAIL_LONG_LIMIT = 0x83,
	TX_STATUS_FAIL_FIFO_UNDERRUN = 0x84,
	TX_STATUS_FAIL_MGMNT_ABORT = 0x85,
	TX_STATUS_FAIL_NEXT_FRAG = 0x86,
	TX_STATUS_FAIL_LIFE_EXPIRE = 0x87,
	TX_STATUS_FAIL_DEST_PS = 0x88,
	TX_STATUS_FAIL_ABORTED = 0x89,
	TX_STATUS_FAIL_BT_RETRY = 0x8a,
	TX_STATUS_FAIL_STA_INVALID = 0x8b,
	TX_STATUS_FAIL_FRAG_DROPPED = 0x8c,
	TX_STATUS_FAIL_TID_DISABLE = 0x8d,
	TX_STATUS_FAIL_FRAME_FLUSHED = 0x8e,
	TX_STATUS_FAIL_INSUFFICIENT_CF_POLL = 0x8f,
	TX_STATUS_FAIL_TX_LOCKED = 0x90,
	TX_STATUS_FAIL_NO_BEACON_ON_RADAR = 0x91,
};

enum {
	TX_PACKET_MODE_REGULAR = 0x0000,
	TX_PACKET_MODE_BURST_PART = 0x00100,
	TX_PACKET_MODE_BURST_FIRST = 0x0200,
};

enum {
	TX_POWER_PA_NOT_ACTIVE = 0x0,
};

enum {
	TX_STATUS_MSK = 0x000000ff,	/* bits 0:7 */
	TX_STATUS_DELAY_MSK = 0x00000040,
	TX_STATUS_ABORT_MSK = 0x00000080,
	TX_PACKET_MODE_MSK = 0x0000ff00,	/* bits 8:15 */
	TX_FIFO_NUMBER_MSK = 0x00070000,	/* bits 16:18 */
	TX_RESERVED = 0x00780000,	/* bits 19:22 */
	TX_POWER_PA_DETECT_MSK = 0x7f800000,	/* bits 23:30 */
	TX_ABORT_REQUIRED_MSK = 0x80000000,	/* bits 31:31 */
};

/* *******************************
 * TX aggregation state
 ******************************* */

enum {
	AGG_TX_STATE_TRANSMITTED = 0x00,
	AGG_TX_STATE_UNDERRUN_MSK = 0x01,
	AGG_TX_STATE_BT_PRIO_MSK = 0x02,
	AGG_TX_STATE_FEW_BYTES_MSK = 0x04,
	AGG_TX_STATE_ABORT_MSK = 0x08,
	AGG_TX_STATE_LAST_SENT_TTL_MSK = 0x10,
	AGG_TX_STATE_LAST_SENT_TRY_CNT_MSK = 0x20,
	AGG_TX_STATE_LAST_SENT_BT_KILL_MSK = 0x40,
	AGG_TX_STATE_SCD_QUERY_MSK = 0x80,
	AGG_TX_STATE_TEST_BAD_CRC32_MSK = 0x100,
	AGG_TX_STATE_RESPONSE_MSK = 0x1ff,
	AGG_TX_STATE_DUMP_TX_MSK = 0x200,
	AGG_TX_STATE_DELAY_TX_MSK = 0x400
};

#define AGG_TX_STATE_LAST_SENT_MSK \
(AGG_TX_STATE_LAST_SENT_TTL_MSK | \
 AGG_TX_STATE_LAST_SENT_TRY_CNT_MSK | \
 AGG_TX_STATE_LAST_SENT_BT_KILL_MSK)

#define AGG_TX_STATE_TRY_CNT_POS 12
#define AGG_TX_STATE_TRY_CNT_MSK 0xf000

#define AGG_TX_STATE_SEQ_NUM_POS 16
#define AGG_TX_STATE_SEQ_NUM_MSK 0xffff0000

struct iwl_tx_resp {
#if IWL == 4965
	u8 frame_count;		/* 1 no aggregation, >1 aggregation */
	u8 bt_kill_count;
#endif
	u8 failure_rts;
	u8 failure_frame;
#if IWL == 3945
	u8 bt_kill_count;
	u8 rate;
	__le32 wireless_media_time;
#elif IWL == 4965
	struct iwl_rate rate;
	__le16 wireless_media_time;
	__le16 reserved;
	__le32 pa_power1;
	__le32 pa_power2;
#endif
	__le32 status;	/* TX status (for aggregation status of 1st frame) */
} __attribute__ ((packed));

/* TX command response is sent after *all* transmission attempts.
 *
 * NOTES:
 *
 * TX_STATUS_FAIL_NEXT_FRAG
 *
 * If the fragment flag in the MAC header for the frame being transmitted
 * is set and there is insufficient time to transmit the next frame, the
 * TX status will be returned with 'TX_STATUS_FAIL_NEXT_FRAG'.
 *
 * TX_STATUS_FIFO_UNDERRUN
 *
 * Indicates the host did not provide bytes to the FIFO fast enough while
 * a TX was in progress.
 *
 * TX_STATUS_FAIL_MGMNT_ABORT
 *
 * This status is only possible if the ABORT ON MGMT RX parameter was
 * set to true with the TX command.
 *
 * If the MSB of the status parameter is set then an abort sequence is
 * required.  This sequence consists of the host activating the TX Abort
 * control line, and then waiting for the TX Abort command response.  This
 * indicates that a the device is no longer in a transmit state, and that the
 * command FIFO has been cleared.  The host must then deactivate the TX Abort
 * control line.  Receiving is still allowed in this case.
 */

struct iwl_tx_power {
	u8 tx_gain;		/* gain for analog radio */
	u8 dsp_atten;		/* gain for DSP */
} __attribute__ ((packed));

struct iwl_scan_channel {
	u8 type;
	/* type is defined as:
	 * 0:0 active (0 - passive)
	 * 1:4 SSID direct
	 *     If 1 is set then corresponding SSID IE is transmitted in probe
	 * 5:6 reserved
	 * 7:7 Narrow
	 */
	u8 channel;
	struct iwl_tx_power tpc;
	__le16 active_dwell;
	__le16 passive_dwell;
} __attribute__ ((packed));

struct iwl_ssid_ie {
	u8 id;
	u8 len;
	u8 ssid[32];
} __attribute__ ((packed));

#define PROBE_OPTION_MAX        0x4
#define TX_CMD_FLG_SEQ_CTL_MSK  0x2000
#define TX_CMD_LIFE_TIME_INFINITE       0xFFFFFFFF
#define IWL_GOOD_CRC_TH             (1)

#define IWL_MAX_SCAN_SIZE 1024
struct iwl_scan_cmd {
	__le16 len;
	u8 reserved0;
	u8 channel_count;
	__le16 quiet_time;     /* dwell only this long on quiet chnl
				* (active scan) */
	__le16 quiet_plcp_th;  /* quiet chnl is < this # pkts (typ. 1) */
	__le16 good_CRC_th;    /* passive -> active promotion threshold */
#if IWL == 3945
	__le16 reserved1;
#elif IWL == 4965
	__le16 rx_chain;
#endif
	__le32 max_out_time;   /* max usec to be out of associated (service)
				* chnl */
	__le32 suspend_time;   /* pause scan this long when returning to svc
				* chnl.
				* 3945 -- 31:24 # beacons, 19:0 additional usec,
				* 4965 -- 31:22 # beacons, 21:0 additional usec.
				*/
	__le32 flags;
	__le32 filter_flags;

	struct iwl_tx_cmd tx_cmd;
	struct iwl_ssid_ie direct_scan[PROBE_OPTION_MAX];

	u8 data[0];
	/*
	 * The channels start after the probe request payload and are of type:
	 *
	 * struct iwl_scan_channel channels[0];
	 *
	 * NOTE:  Only one band of channels can be scanned per pass.  You
	 * can not mix 2.4GHz channels and 5.2GHz channels and must
	 * request a scan multiple times (not concurrently)
	 *
	 */
} __attribute__ ((packed));

/*
 * RXON-ASSOCIATED Command & Response
 */
struct iwl_rxon_assoc_cmd {
	__le32 flags;
	__le32 filter_flags;
	u8 ofdm_basic_rates;
	u8 cck_basic_rates;
#if IWL == 4965
	u8 ofdm_ht_single_stream_basic_rates;
	u8 ofdm_ht_dual_stream_basic_rates;
	__le16 rx_chain_select_flags;
#endif
	__le16 reserved;
} __attribute__ ((packed));

/*
 * RXON Command & Response
 */
struct iwl_rxon_cmd {
	u8 node_addr[6];
	__le16 reserved1;
	u8 bssid_addr[6];
	__le16 reserved2;
	u8 wlap_bssid_addr[6];
	__le16 reserved3;
	u8 dev_type;
	u8 air_propagation;
#if IWL == 3945
	__le16 reserved4;
#elif IWL == 4965
	__le16 rx_chain;
#endif
	u8 ofdm_basic_rates;
	u8 cck_basic_rates;
	__le16 assoc_id;
	__le32 flags;
	__le32 filter_flags;
	__le16 channel;
#if IWL == 3945
	__le16 reserved5;
#elif IWL == 4965
	u8 ofdm_ht_single_stream_basic_rates;
	u8 ofdm_ht_dual_stream_basic_rates;
#endif
} __attribute__ ((packed));

struct iwl_compressed_ba_resp {
	__le32 sta_addr_lo32;
	__le16 sta_addr_hi16;
	__le16 reserved;
	u8 sta_id;
	u8 tid;
	__le16 ba_seq_ctl;
	__le32 ba_bitmap0;
	__le32 ba_bitmap1;
	__le16 scd_flow;
	__le16 scd_ssn;
} __attribute__ ((packed));

#define PHY_CALIBRATE_DIFF_GAIN_CMD (7)
#define HD_TABLE_SIZE  (11)

struct iwl_sensitivity_cmd {
	__le16 control;
	__le16 table[HD_TABLE_SIZE];
} __attribute__ ((packed));

struct iwl_calibration_cmd {
	u8 opCode;
	u8 flags;
	__le16 reserved;
	s8 diff_gain_a;
	s8 diff_gain_b;
	s8 diff_gain_c;
	u8 reserved1;
} __attribute__ ((packed));

struct iwl_missed_beacon_notif {
	__le32 consequtive_missed_beacons;
	__le32 total_missed_becons;
	__le32 num_expected_beacons;
	__le32 num_recvd_beacons;
} __attribute__ ((packed));

struct iwl_ct_kill_config {
	u32   reserved;
	u32   critical_temperature_M;
	u32   critical_temperature_R;
}  __attribute__ ((packed));
/*
 * Add/Modify Station Command & Response
 */
struct iwl_keyinfo {
	__le16 key_flags;
	u8 tkip_rx_tsc_byte2;	/* TSC[2] for key mix ph1 detection */
	u8 reserved1;
	__le16 tkip_rx_ttak[5];	/* 10-byte unicast TKIP TTAK */
	__le16 reserved2;
	u8 key[16];		/* 16-byte unicast decryption key */
} __attribute__ ((packed));

struct sta_id_modify {
	u8 addr[ETH_ALEN];
	__le16 reserved1;
	u8 sta_id;
	u8 modify_mask;
	__le16 reserved2;
} __attribute__ ((packed));

struct iwl_addsta_cmd {
	u8 mode;
	u8 reserved[3];
	struct sta_id_modify sta;
	struct iwl_keyinfo key;
	__le32 station_flags;
	__le32 station_flags_msk;
	__le16 tid_disable_tx;
	union {
		struct {
			u8 rate;
			u8 flags;
		} s;
		__le16 rate_n_flags;
	} tx_rate;
	u8 add_immediate_ba_tid;
	u8 remove_immediate_ba_tid;
	__le16 add_immediate_ba_start_seq;
#if IWL == 4965
	__le32 reserved1;
#endif
} __attribute__ ((packed));

struct iwl_add_sta_resp {
	u8 status;
} __attribute__ ((packed));

#define ADD_STA_SUCCESS_MSK              0x1

/**
 * struct iwl_powertable_cmd - Power Table Command & Response
 * @flags: See below:
 *
 * PM allow:
 *   bit 0 - '0' Driver not allow power management
 *           '1' Driver allow PM (use rest of parameters)
 * uCode send sleep notifications:
 *   bit 1 - '0' Don't send sleep notification
 *           '1' send sleep notification (SEND_PM_NOTIFICATION)
 * Sleep over DTIM
 *   bit 2 - '0' PM have to walk up every DTIM
 *           '1' PM could sleep over DTIM till listen Interval.
 * PCI power managed
 *   bit 3 - '0' (PCI_LINK_CTRL & 0x1)
 *           '1' !(PCI_LINK_CTRL & 0x1)
 * Force sleep Modes
 *   bit 31/30- '00' use both mac/xtal sleeps
 *              '01' force Mac sleep
 *              '10' force xtal sleep
 *              '11' Illegal set
 *
 * NOTE: if sleep_interval[SLEEP_INTRVL_TABLE_SIZE-1] > DTIM period then
 * ucode assume sleep over DTIM is allowed and we don't need to wakeup
 * for every DTIM.
 */
#define IWL_POWER_TABLE_SIZE 5
#define IWL_POWER_VEC_SIZE 5

#if IWL == 3945

#define IWL_POWER_DRIVER_ALLOW_SLEEP_MSK	cpu_to_le32(1<<0)
#define IWL_POWER_SLEEP_OVER_DTIM_MSK		cpu_to_le32(1<<2)
#define IWL_POWER_PCI_PM_MSK			cpu_to_le32(1<<3)
struct iwl_powertable_cmd {
	__le32 flags;
	__le32 rx_data_timeout;
	__le32 tx_data_timeout;
	__le32 sleep_interval[IWL_POWER_VEC_SIZE];
} __attribute__((packed));

#elif IWL == 4965

#define IWL_POWER_DRIVER_ALLOW_SLEEP_MSK	__constant_cpu_to_le16(1<<0)
#define IWL_POWER_SLEEP_OVER_DTIM_MSK		__constant_cpu_to_le16(1<<2)
#define IWL_POWER_PCI_PM_MSK			__constant_cpu_to_le16(1<<3)

struct iwl_powertable_cmd {
	__le16 flags;
	u8 keep_alive_seconds;
	u8 debug_flags;
	__le32 rx_data_timeout;
	__le32 tx_data_timeout;
	__le32 sleep_interval[IWL_POWER_VEC_SIZE];
	__le32 keep_alive_beacons;
} __attribute__ ((packed));
#endif


struct iwl_rate_scaling_info {
	union {
		struct {
			u8 tx_rate;
			u8 flags;
		} s;
		__le16 rate_n_flags;
	};
	u8 try_cnt;
	u8 next_rate_index;
} __attribute__ ((packed));

/**
 * struct iwl_rate_scaling_cmd - Rate Scaling Command & Response
 *
 * NOTE: The table of rates passed to the uCode via the
 * RATE_SCALE command sets up the corresponding order of
 * rates used for all related commands, including rate
 * masks, etc.
 *
 * For example, if you set 9MB (PLCP 0x0f) as the first
 * rate in the rate table, the bit mask for that rate
 * when passed through ofdm_basic_rates on the REPLY_RXON
 * command would be bit 0 (1<<0)
 */
struct iwl_rate_scaling_cmd {
	u8 table_id;
	u8 reserved[3];
	struct iwl_rate_scaling_info table[IWL_MAX_RATES];
} __attribute__ ((packed));

#endif				/* __iwl_commands_h__ */
