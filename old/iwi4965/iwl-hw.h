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
 *****************************************************************************/

#ifndef	__iwlwifi_hw_h__
#define __iwlwifi_hw_h__
#include "defines.h"

/*
 * This file defines hardware / uCode API constants, enums,
 * and inline functions.
 *
 * For common usage code where the implementation can be the same
 * with the exception of a different value going into a constant
 * those constants are defined in this file.
 *
 * NOTE:  DO NOT PUT IMPLEMENTATION SPECIFIC DECLRATIONS HERE
 *
 * The iwl-*hw.h (and files they include) files should remain OS driver
 * implementation independent, declaring only the hardware/uCode API
 *
 */

/* uCode queue management definitions */
#define IWL_CMD_QUEUE_NUM       4
#define IWL_CMD_FIFO_NUM        4
#define IWL_BACK_QUEUE_FIRST_ID 7

#define IWL_CCK_RATES 4
#define IWL_OFDM_RATES 8

#if IWL == 3945
#define IWL_HT_RATES 0
#elif IWL == 4965
#define IWL_HT_RATES 16
#endif

#define IWL_MAX_RATES  (IWL_CCK_RATES+IWL_OFDM_RATES+IWL_HT_RATES)

/*
 *  Time constants
 */
#define SHORT_SLOT_TIME 9
#define LONG_SLOT_TIME 20
#define OFDM_SYMBOL_TIME 4

/* RSSI to dBm */
#if IWL == 3945
#define IWL_RSSI_OFFSET	95
#elif IWL == 4965
#define IWL_RSSI_OFFSET	44
#endif

#include "iwl-eeprom.h"
#include "iwl-commands.h"

union tsf {
	u8 byte[8];
	__le16 word[4];
	__le32 dw[2];
};

/*
 * Alive Command & Response
 */

#define UCODE_VALID_OK      (0x1)
#define INITIALIZE_SUBTYPE    (9)

struct iwl_alive_resp {
	u8 ucode_minor;
	u8 ucode_major;
	__le16 reserved1;
	u8 sw_rev[8];
	u8 ver_type;
	u8 ver_subtype;
	__le16 reserved2;
	__le32 log_event_table_ptr;
	__le32 error_event_table_ptr;
	__le32 timestamp;
	__le32 is_valid;
} __attribute__ ((packed));

struct iwl_init_alive_resp {
	u8 ucode_minor;
	u8 ucode_major;
	__le16 reserved1;
	u8 sw_rev[8];
	u8 ver_type;
	u8 ver_subtype;
	__le16 reserved2;
	__le32 log_event_table_ptr;
	__le32 error_event_table_ptr;
	__le32 timestamp;
	__le32 is_valid;

#if IWL == 4965
	/* calibration values from "initialize" uCode */
	__le32 voltage;		/* signed */
	__le32 therm_r1[2];	/* signed 1st for normal, 2nd for FAT channel */
	__le32 therm_r2[2];	/* signed */
	__le32 therm_r3[2];	/* signed */
	__le32 therm_r4[2];	/* signed */
	__le32 tx_atten[5][2];	/* signed MIMO gain comp, 5 freq groups,
				 * 2 Tx chains */
#endif
} __attribute__ ((packed));

/*
 * Error Command & Response
 */

struct iwl_error_resp {
	__le32 error_type;
	u8 cmd_id;
	u8 reserved1;
	__le16 bad_cmd_seq_num;
#if IWL == 3945
	__le16 reserved2;
#endif
	__le32 error_info;
	union tsf timestamp;
} __attribute__ ((packed));

#define PCI_LINK_CTRL      0x0F0

/*
 * Rx config defines & structure
 */
/* rx_config device types  */
enum {
	RXON_DEV_TYPE_AP = 1,
	RXON_DEV_TYPE_ESS = 3,
	RXON_DEV_TYPE_IBSS = 4,
	RXON_DEV_TYPE_SNIFFER = 6,
};

/* rx_config flags */
enum {
	/* band & modulation selection */
	RXON_FLG_BAND_24G_MSK = (1 << 0),
	RXON_FLG_CCK_MSK = (1 << 1),
	/* auto detection enable */
	RXON_FLG_AUTO_DETECT_MSK = (1 << 2),
	/* TGg protection when tx */
	RXON_FLG_TGG_PROTECT_MSK = (1 << 3),
	/* cck short slot & preamble */
	RXON_FLG_SHORT_SLOT_MSK = (1 << 4),
	RXON_FLG_SHORT_PREAMBLE_MSK = (1 << 5),
	/* antenna selection */
	RXON_FLG_DIS_DIV_MSK = (1 << 7),
	RXON_FLG_ANT_SEL_MSK = 0x0f00,
	RXON_FLG_ANT_A_MSK = (1 << 8),
	RXON_FLG_ANT_B_MSK = (1 << 9),
	/* radar detection enable */
	RXON_FLG_RADAR_DETECT_MSK = (1 << 12),
	RXON_FLG_TGJ_NARROW_BAND_MSK = (1 << 13),
	/* rx response to host with 8-byte TSF
	 * (according to ON_AIR deassertion) */
	RXON_FLG_TSF2HOST_MSK = (1 << 15)
};

/* rx_config filter flags */
enum {
	/* accept all data frames */
	RXON_FILTER_PROMISC_MSK = (1 << 0),
	/* pass control & management to host */
	RXON_FILTER_CTL2HOST_MSK = (1 << 1),
	/* accept multi-cast */
	RXON_FILTER_ACCEPT_GRP_MSK = (1 << 2),
	/* don't decrypt uni-cast frames */
	RXON_FILTER_DIS_DECRYPT_MSK = (1 << 3),
	/* don't decrypt multi-cast frames */
	RXON_FILTER_DIS_GRP_DECRYPT_MSK = (1 << 4),
	/* STA is associated */
	RXON_FILTER_ASSOC_MSK = (1 << 5),
	/* transfer to host non bssid beacons in associated state */
	RXON_FILTER_BCON_AWARE_MSK = (1 << 6)
};

/*
 * RXON-Timings Command & Response
 */
struct iwl_rxon_time_cmd {
	union tsf timestamp;
	__le16 beacon_interval;
	__le16 atim_window;
	__le32 beacon_init_val;
	__le16 listen_interval;
	__le16 reserved;
} __attribute__ ((packed));

/*
 * beacon QOS parameters Command & Response
 */
struct iwl_ac_qos {
	__le16 cw_min;
	__le16 cw_max;
	u8 aifsn;
	u8 reserved1;
	__le16 edca_txop;
} __attribute__ ((packed));

/* QoS flags defines */
#define MH_QOS_TXOP_TYPE_MSK 0x10
#define QOS_PARAM_FLG_UPDATE_EDCA_MSK 0x1
#define QOS_PARAM_FLG_TGN_MSK 0x2
#define QOS_PARAM_FLG_TXOP_TYPE_MSK MH_QOS_TXOP_TYPE_MSK

/*
 *  TXFIFO Queue number defines
 */
/* number of Access categories (AC) (EDCA), queues 0..3 */
#define AC_NUM                4
/* total number of queues */
#define QUEUE_NUM             7
/* command queue number */

struct iwl_qosparam_cmd {
	__le32 qos_flags;
	struct iwl_ac_qos ac[AC_NUM];
} __attribute__ ((packed));

/*
 * Multi station support
 */
#if IWL == 3945
enum {
	IWL_AP_ID = 0,
	IWL_MULTICAST_ID,
	IWL_STA_ID,
	IWL_BROADCAST_ID = 24,
	IWL_STATION_COUNT = 25,
	IWL_INVALID_STATION
};
#elif IWL == 4965
enum {
	IWL_AP_ID = 0,
	IWL_MULTICAST_ID,
	IWL_STA_ID,
	IWL_BROADCAST_ID = 31,
	IWL_STATION_COUNT = 32,
	IWL_INVALID_STATION
};
#endif

#define STA_CONTROL_MODIFY_MSK             0x01

/* key flags */
enum {
	STA_KEY_FLG_ENCRYPT_MSK = 0x7,
	STA_KEY_FLG_NO_ENC = 0x0,
	STA_KEY_FLG_WEP = 0x1,
	STA_KEY_FLG_CCMP = 0x2,
	STA_KEY_FLG_TKIP = 0x3,

	STA_KEY_FLG_KEYID_POS = 8,
	STA_KEY_FLG_INVALID = 0x0800,
};

/* modify flags  */
enum {
	STA_MODIFY_KEY_MASK = 0x01,
	STA_MODIFY_TID_DISABLE_TX = 0x02,
	STA_MODIFY_TX_RATE_MSK = 0x04
};

/*
 * Antenna masks:
 * bit14:15 01 B inactive, A active
 *          10 B active, A inactive
 *          11 Both active
 */
#define RATE_MCS_ANT_A_POS 14
#define RATE_MCS_ANT_B_POS 15
#define RATE_MCS_ANT_A_MSK 0x4000
#define RATE_MCS_ANT_B_MSK 0x8000
#define RATE_MCS_ANT_AB_MSK 0xc000

/*
 * WEP/CKIP group key command
 */
struct iwl_key {
	u8 index;
	u8 reserved[3];
	__le32 size;
	u8 key[16];
} __attribute__ ((packed));

struct iwl_key_cmd {
	u8 count;
	u8 decrypt_type;
	u8 reserved[2];
	struct iwl_key key[4];
} __attribute__ ((packed));

struct iwl_rx_frame_stats {
	u8 phy_count;
	u8 id;
	u8 rssi;
	u8 agc;
	__le16 sig_avg;
	__le16 noise_diff;
	u8 payload[0];
} __attribute__ ((packed));

struct iwl_rx_frame_hdr {
	__le16 channel;
	__le16 phy_flags;
	u8 reserved1;
	u8 rate;
	__le16 len;
	u8 payload[0];
} __attribute__ ((packed));

enum {
	RX_RES_STATUS_NO_CRC32_ERROR = (1 << 0),
	RX_RES_STATUS_NO_RXE_OVERFLOW = (1 << 1),
};

enum {
	RX_RES_PHY_FLAGS_BAND_24_MSK = (1 << 0),
	RX_RES_PHY_FLAGS_MOD_CCK_MSK = (1 << 1),
	RX_RES_PHY_FLAGS_SHORT_PREAMBLE_MSK = (1 << 2),
	RX_RES_PHY_FLAGS_NARROW_BAND_MSK = (1 << 3),
	RX_RES_PHY_FLAGS_ANTENNA_MSK = 0xf0,

	RX_RES_STATUS_SEC_TYPE_MSK = (0x7 << 8),
	RX_RES_STATUS_SEC_TYPE_NONE = (STA_KEY_FLG_NO_ENC << 8),
	RX_RES_STATUS_SEC_TYPE_WEP = (STA_KEY_FLG_WEP << 8),
	RX_RES_STATUS_SEC_TYPE_TKIP = (STA_KEY_FLG_TKIP << 8),
	RX_RES_STATUS_SEC_TYPE_CCMP = (STA_KEY_FLG_CCMP << 8),

	RX_RES_STATUS_DECRYPT_TYPE_MSK = (0x3 << 11),
	RX_RES_STATUS_NOT_DECRYPT = (0x0 << 11),
	RX_RES_STATUS_DECRYPT_OK = (0x3 << 11),
	RX_RES_STATUS_BAD_ICV_MIC = (0x1 << 11),
	RX_RES_STATUS_BAD_KEY_TTAK = (0x2 << 11),
};

struct iwl_rx_frame_end {
	__le32 status;
	__le64 timestamp;
	__le32 beacon_timestamp;
} __attribute__ ((packed));

/* NOTE:  DO NOT dereference from casts to this structure
 * It is provided only for calculating minimum data set size.
 * The actual offsets of the hdr and end are dynamic based on
 * stats.phy_count */
struct iwl_rx_frame {
	struct iwl_rx_frame_stats stats;
	struct iwl_rx_frame_hdr hdr;
	struct iwl_rx_frame_end end;
} __attribute__ ((packed));

/*
 * Tx Power Table Command
 */
struct iwl_power_per_rate {
	u8 rate;		/* plcp */
	struct iwl_tx_power tpc;
	u8 reserved;
} __attribute__ ((packed));

struct iwl_txpowertable_cmd {
	u8 band;
	u8 reserved;
	__le16 channel;
	struct iwl_power_per_rate power[IWL_MAX_RATES];
} __attribute__ ((packed));

/*
 * Scan Request Commands , Responses  & Notifications
 */

/* Can abort will notify by complete notification with abort status. */
#define CAN_ABORT_STATUS        0x1

struct iwl_scanreq_notification {
	__le32 status;
} __attribute__ ((packed));

struct iwl_scanstart_notification {
	__le32 tsf_low;
	__le32 tsf_high;
	__le32 beacon_timer;
	u8 channel;
	u8 band;
	u8 reserved[2];
	__le32 status;
} __attribute__ ((packed));

#define  SCAN_OWNER_STATUS 0x1;
#define  MEASURE_OWNER_STATUS 0x2;

#define NUMBER_OF_STATISTICS 1	/* first __le32 is good CRC */
struct iwl_scanresults_notification {
	u8 channel;
	u8 band;
	u8 reserved[2];
	__le32 tsf_low;
	__le32 tsf_high;
	__le32 statistics[NUMBER_OF_STATISTICS];
} __attribute__ ((packed));

struct iwl_scancomplete_notification {
	u8 scanned_channels;
	u8 status;
	u8 reserved;
	u8 last_channel;
	__le32 tsf_low;
	__le32 tsf_high;
} __attribute__ ((packed));

/* complete notification statuses */
#define ABORT_STATUS            0x2

/*
 * LEDs Command & Response
 */
struct iwl_led_cmd {
	__le32 interval;
	u8 id;
	u8 off;
	u8 on;
	u8 reserved;
} __attribute__ ((packed));

/*
 * card_state Command and Notification
 */

#define CARD_STATE_CMD_DISABLE 0x00
#define CARD_STATE_CMD_ENABLE 0x01

struct iwl_card_state_notif {
	__le32 flags;
} __attribute__ ((packed));

#define HW_CARD_DISABLED   0x01
#define SW_CARD_DISABLED   0x02
#define RF_CARD_DISABLED   0x04
#define RXON_CARD_DISABLED 0x10

/*
 * Tx Beacon Command & Response
 */
struct iwl_beacon_notif {
	struct iwl_tx_resp beacon_notify_hdr;
	__le32 low_tsf;
	__le32 high_tsf;
	__le32 ibss_mgr_status;
} __attribute__ ((packed));

struct iwl_tx_beacon_cmd {
	struct iwl_tx_cmd tx;
	__le16 tim_idx;
	u8 tim_size;
	u8 reserved1;
	struct ieee80211_hdr frame[0];	/* beacon frame */
} __attribute__ ((packed));

/*
 * Spectrum Management
 */
#define MEASUREMENT_FILTER_FLAG (RXON_FILTER_PROMISC_MSK         | \
				 RXON_FILTER_CTL2HOST_MSK        | \
				 RXON_FILTER_ACCEPT_GRP_MSK      | \
				 RXON_FILTER_DIS_DECRYPT_MSK     | \
				 RXON_FILTER_DIS_GRP_DECRYPT_MSK | \
				 RXON_FILTER_ASSOC_MSK           | \
				 RXON_FILTER_BCON_AWARE_MSK)

struct iwl_measure_channel {
	__le32 duration;	/* measurement duration in extended beacon
				 * format */
	u8 channel;		/* channel to measure */
	u8 type;		/* see enum iwl_measure_type */
	__le16 reserved;
} __attribute__ ((packed));

struct iwl_spectrum_cmd {
	__le16 len;		/* number of bytes starting from token */
	u8 token;		/* token id */
	u8 id;			/* measurement id -- 0 or 1 */
	u8 origin;		/* 0 = TGh, 1 = other, 2 = TGk */
	u8 periodic;		/* 1 = periodic */
	__le16 path_loss_timeout;
	__le32 start_time;	/* start time in extended beacon format */
	__le32 reserved2;
	__le32 flags;		/* rxon flags */
	__le32 filter_flags;	/* rxon filter flags */
	__le16 channel_count;	/* minimum 1, maximum 10 */
	__le16 reserved3;
	struct iwl_measure_channel channels[10];
} __attribute__ ((packed));

struct iwl_spectrum_resp {
	u8 token;
	u8 id;			/* id of the prior command replaced, or 0xff */
	__le16 status;		/* 0 - command will be handled
				 * 1 - cannot handle (conflicts with another
				 *     measurement) */
} __attribute__ ((packed));

enum iwl_measurement_state {
	IWL_MEASUREMENT_START = 0,
	IWL_MEASUREMENT_STOP = 1,
};

enum iwl_measurement_status {
	IWL_MEASUREMENT_OK = 0,
	IWL_MEASUREMENT_CONCURRENT = 1,
	IWL_MEASUREMENT_CSA_CONFLICT = 2,
	IWL_MEASUREMENT_TGH_CONFLICT = 3,
	/* 4-5 reserved */
	IWL_MEASUREMENT_STOPPED = 6,
	IWL_MEASUREMENT_TIMEOUT = 7,
	IWL_MEASUREMENT_PERIODIC_FAILED = 8,
};

#define NUM_ELEMENTS_IN_HISTOGRAM 8

struct iwl_measurement_histogram {
	__le32 ofdm[NUM_ELEMENTS_IN_HISTOGRAM];	/* in 0.8usec counts */
	__le32 cck[NUM_ELEMENTS_IN_HISTOGRAM];	/* in 1usec counts */
} __attribute__ ((packed));

/* clear channel availability counters */
struct iwl_measurement_cca_counters {
	__le32 ofdm;
	__le32 cck;
} __attribute__ ((packed));

enum iwl_measure_type {
	IWL_MEASURE_BASIC = (1 << 0),
	IWL_MEASURE_CHANNEL_LOAD = (1 << 1),
	IWL_MEASURE_HISTOGRAM_RPI = (1 << 2),
	IWL_MEASURE_HISTOGRAM_NOISE = (1 << 3),
	IWL_MEASURE_FRAME = (1 << 4),
	/* bits 5:6 are reserved */
	IWL_MEASURE_IDLE = (1 << 7),
};

struct iwl_spectrum_notification {
	u8 id;			/* measurement id -- 0 or 1 */
	u8 token;
	u8 channel_index;	/* index in measurement channel list */
	u8 state;		/* 0 - start, 1 - stop */
	__le32 start_time;	/* lower 32-bits of TSF */
	u8 band;		/* 0 - 5.2GHz, 1 - 2.4GHz */
	u8 channel;
	u8 type;		/* see enum iwl_measurement_type */
	u8 reserved1;
	/* NOTE:  cca_ofdm, cca_cck, basic_type, and histogram are only only
	 * valid if applicable for measurement type requested. */
	__le32 cca_ofdm;	/* cca fraction time in 40Mhz clock periods */
	__le32 cca_cck;		/* cca fraction time in 44Mhz clock periods */
	__le32 cca_time;	/* channel load time in usecs */
	u8 basic_type;		/* 0 - bss, 1 - ofdm preamble, 2 -
				 * unidentified */
	u8 reserved2[3];
	struct iwl_measurement_histogram histogram;
	__le32 stop_time;	/* lower 32-bits of TSF */
	__le32 status;		/* see iwl_measurement_status */
} __attribute__ ((packed));

struct iwl_csa_notification {
	__le16 band;
	__le16 channel;
	__le32 status;		/* 0 - OK, 1 - fail */
} __attribute__ ((packed));

struct iwl_sleep_notification {
	u8 pm_sleep_mode;
	u8 pm_wakeup_src;
	__le16 reserved;
	__le32 sleep_time;
	__le32 tsf_low;
	__le32 bcon_timer;
} __attribute__ ((packed));

enum {
	IWL_PM_NO_SLEEP = 0,
	IWL_PM_SLP_MAC = 1,
	IWL_PM_SLP_FULL_MAC_UNASSOCIATE = 2,
	IWL_PM_SLP_FULL_MAC_CARD_STATE = 3,
	IWL_PM_SLP_PHY = 4,
	IWL_PM_SLP_REPENT = 5,
	IWL_PM_WAKEUP_BY_TIMER = 6,
	IWL_PM_WAKEUP_BY_DRIVER = 7,
	IWL_PM_WAKEUP_BY_RFKILL = 8,
	/* 3 reserved */
	IWL_PM_NUM_OF_MODES = 12,
};

struct iwl_bt_cmd {
	u8 flags;
	u8 lead_time;
	u8 max_kill;
	u8 reserved;
	__le32 kill_ack_mask;
	__le32 kill_cts_mask;
} __attribute__ ((packed));

struct rx_phy_statistics {
	__le32 ina_cnt;		/* number of INA signal assertions (enter RX) */
	__le32 fina_cnt;	/* number of FINA signal assertions
				 * (false_alarm = INA - FINA) */
	__le32 plcp_err;	/* number of bad PLCP header detections
				 * (PLCP_good = FINA - PLCP_bad) */
	__le32 crc32_err;	/* number of CRC32 error detections */
	__le32 overrun_err;	/* number of Overrun detections (this is due
				 * to RXE sync overrun) */
	__le32 early_overrun_err;	/* number of times RX is aborted at the
					 * start because rxfifo is full behind
					 * threshold */
	__le32 crc32_good;	/* number of frames with good CRC */
	__le32 false_alarm_cnt;	/* number of times false alarm was
				 * detected (i.e. INA w/o FINA) */
	__le32 fina_sync_err_cnt;	/* number of times sync problem between
					 * HW & SW FINA counter was found */
	__le32 sfd_timeout;	/* number of times got SFD timeout
				 * (i.e. got FINA w/o rx_frame) */
	__le32 fina_timeout;	/* number of times got FINA timeout (i.e. got
				 * INA w/o FINA, w/o false alarm) */
	__le32 unresponded_rts;	/* un-responded RTS, due to NAV not zero */
	__le32 rxe_frame_limit_overrun;	/* RXE got frame limit overrun */
	__le32 sent_ack_cnt;	/* ACK TX count */
	__le32 sent_cts_cnt;	/* CTS TX count */
} __attribute__ ((packed));

struct rx_non_phy_statistics {
	__le32 bogus_cts;	/* CTS received when not expecting CTS */
	__le32 bogus_ack;	/* ACK received when not expecting ACK */
	__le32 non_bssid_frames;/* number of frames with BSSID that doesn't
				 * belong to the STA BSSID */
	__le32 filtered_frames;	/* count frames that were dumped in the
				 * filtering process */
} __attribute__ ((packed));

struct rx_statistics {
	struct rx_phy_statistics ofdm;
	struct rx_phy_statistics cck;
	struct rx_non_phy_statistics general;
} __attribute__ ((packed));

struct tx_non_phy_statistics {
	__le32 preamble_cnt;	/* number of times preamble was asserted */
	__le32 rx_detected_cnt;	/* number of times TX was delayed to RX
				 * detected */
	__le32 bt_prio_defer_cnt;/* number of times TX was deferred due to
				  * BT priority */
	__le32 bt_prio_kill_cnt;/* number of times TX was killed due to BT
				 * priority */
	__le32 few_bytes_cnt;	/* number of times TX was delayed due to not
				 * enough bytes in TXFIFO */
	__le32 cts_timeout;	/* timeout when waiting for CTS */
	__le32 ack_timeout;	/* timeout when waiting for ACK */
	__le32 expected_ack_cnt;/* number of data frames that need ack or
				 * rts that need cts */
	__le32 actual_ack_cnt;	/* number of expected ack or cts that were
				 * actually received */
} __attribute__ ((packed));

struct tx_statistics {
	struct tx_non_phy_statistics general;
} __attribute__ ((packed));

struct debug_statistics {
	__le32 cont_burst_chk_cnt;/* number of times continuation or
				   * fragmentation or bursting was checked */
	__le32 cont_burst_cnt;	/* number of times continuation,
				 * fragmentation, or bursting was successful */
	__le32 reserved[4];
} __attribute__ ((packed));

#define IWL_TEMP_CONVERT 260

struct general_statistics {
	__le32 temperature;
	struct debug_statistics debug;
	__le32 usec_sleep;   /* < usecs NIC was asleep. Running counter. */
	__le32 slots_out;    /* < slots NIC was out of serving channel */
	__le32 slots_idle;   /* < slots NIC was idle */
} __attribute__ ((packed));

struct statistics {
	__le32 flags;
	struct rx_statistics rx_statistics;
	struct tx_statistics tx_statistics;
	struct general_statistics general_statistics;
} __attribute__ ((packed));

/* if ucode missed CONSECUTIVE_MISSED_BCONS_TH beacons in a row,
 * then this notification will be sent. */
#define CONSECUTIVE_MISSED_BCONS_TH 20

/* register and values */
/* base */
#define CSR_BASE    (0x0)
#define HBUS_BASE   (0x400)
#define FH_BASE     (0x800)

#define HBUS_TARG_MBX_C         (HBUS_BASE+0x030)

/*=== CSR (control and status registers) ===*/

#define CSR_SW_VER              (CSR_BASE+0x000)
#define CSR_HW_IF_CONFIG_REG    (CSR_BASE+0x000) /* hardware interface config */
#define CSR_INT_COALESCING      (CSR_BASE+0x004) /* accum ints, 32-usec units */
#define CSR_INT                 (CSR_BASE+0x008) /* host interrupt status/ack */
#define CSR_INT_MASK            (CSR_BASE+0x00c) /* host interrupt enable */
#define CSR_FH_INT_STATUS       (CSR_BASE+0x010) /* busmaster int status/ack*/
#define CSR_GPIO_IN             (CSR_BASE+0x018) /* read external chip pins */
#define CSR_RESET               (CSR_BASE+0x020) /* busmaster enable, NMI, etc*/
#define CSR_GP_CNTRL            (CSR_BASE+0x024)
/* 0x028 - reserved */
#define CSR_EEPROM_REG          (CSR_BASE+0x02c)
#define CSR_EEPROM_GP           (CSR_BASE+0x030)
#define   CSR_EEPROM_GP_VALID_MSK	0x00000007
#define   CSR_EEPROM_GP_BAD_SIGNATURE	0x00000000
#if IWL == 3945
#define   CSR_EEPROM_GP_OWNER		0x00000180
#endif
#define CSR_UCODE_DRV_GP1       (CSR_BASE+0x054)
#define CSR_UCODE_DRV_GP1_SET   (CSR_BASE+0x058)
#define CSR_UCODE_DRV_GP1_CLR   (CSR_BASE+0x05c)
#define CSR_UCODE_DRV_GP2       (CSR_BASE+0x060)
#define CSR_GIO_CHICKEN_BITS    (CSR_BASE+0x100)
#define CSR_ANA_PLL_CFG         (CSR_BASE+0x20c)
#define CSR_HW_REV_WA_REG	(CSR_BASE+0x22C)

/* BSM (Bootstrap State Machine) */
#define BSM_BASE                     (CSR_BASE + 0x3400)

#define BSM_WR_CTRL_REG              (BSM_BASE + 0x000) /* ctl and status */
#define BSM_WR_MEM_SRC_REG           (BSM_BASE + 0x004) /* source in BSM mem */
#define BSM_WR_MEM_DST_REG           (BSM_BASE + 0x008) /* dest in SRAM mem */
#define BSM_WR_DWCOUNT_REG           (BSM_BASE + 0x00C) /* bytes */
#define BSM_WR_STATUS_REG            (BSM_BASE + 0x010) /* bit 0:  1 == done */

/* pointers and size regs for bootstrap load and data SRAM save */
#define BSM_DRAM_INST_PTR_REG        (BSM_BASE + 0x090)
#define BSM_DRAM_INST_BYTECOUNT_REG  (BSM_BASE + 0x094)
#define BSM_DRAM_DATA_PTR_REG        (BSM_BASE + 0x098)
#define BSM_DRAM_DATA_BYTECOUNT_REG  (BSM_BASE + 0x09C)

/* BSM special memory, stays powered during power-save sleeps */
#define BSM_SRAM_LOWER_BOUND         (CSR_BASE + 0x3800)
#define BSM_SRAM_SIZE			(1024)

/* DBG MON */

/* SCD */
#define SCD_BASE                        (CSR_BASE + 0x2E00)

#define SCD_MODE_REG                    (SCD_BASE + 0x000)
#define SCD_ARASTAT_REG                 (SCD_BASE + 0x004)
#define SCD_TXFACT_REG                  (SCD_BASE + 0x010)
#define SCD_TXF4MF_REG                  (SCD_BASE + 0x014)
#define SCD_TXF5MF_REG                  (SCD_BASE + 0x020)
#define SCD_SBYP_MODE_1_REG             (SCD_BASE + 0x02C)
#define SCD_SBYP_MODE_2_REG             (SCD_BASE + 0x030)

/*=== HBUS (Host-side bus) ===*/

#define HBUS_TARG_MEM_RADDR     (HBUS_BASE+0x00c)
#define HBUS_TARG_MEM_WADDR     (HBUS_BASE+0x010)
#define HBUS_TARG_MEM_WDAT      (HBUS_BASE+0x018)
#define HBUS_TARG_MEM_RDAT      (HBUS_BASE+0x01c)
#define HBUS_TARG_PRPH_WADDR    (HBUS_BASE+0x044)
#define HBUS_TARG_PRPH_RADDR    (HBUS_BASE+0x048)
#define HBUS_TARG_PRPH_WDAT     (HBUS_BASE+0x04c)
#define HBUS_TARG_PRPH_RDAT     (HBUS_BASE+0x050)
#define HBUS_TARG_WRPTR         (HBUS_BASE+0x060)
/*=== FH (data Flow handler) ===*/

#define FH_CBCC_TABLE           (FH_BASE+0x140)
#define FH_TFDB_TABLE           (FH_BASE+0x180)
#define FH_RCSR_TABLE           (FH_BASE+0x400)
#define FH_RSSR_TABLE           (FH_BASE+0x4c0)
#define FH_TCSR_TABLE           (FH_BASE+0x500)
#define FH_TSSR_TABLE           (FH_BASE+0x680)

/* TFDB (Transmit Frame Buffer Descriptor) */
#define FH_TFDB(_channel, buf) \
	(FH_TFDB_TABLE+((_channel)*2+(buf))*0x28)
#define ALM_FH_TFDB_CHNL_BUF_CTRL_REG(_channel) \
	(FH_TFDB_TABLE + 0x50 * _channel)
/* CBCC _channel is [0,2] */
#define FH_CBCC(_channel)           (FH_CBCC_TABLE+(_channel)*0x8)
#define FH_CBCC_CTRL(_channel)      (FH_CBCC(_channel)+0x00)
#define FH_CBCC_BASE(_channel)      (FH_CBCC(_channel)+0x04)

/* RCSR _channel is [0,2] */
#define FH_RCSR(_channel)           (FH_RCSR_TABLE+(_channel)*0x40)
#define FH_RCSR_CONFIG(_channel)    (FH_RCSR(_channel)+0x00)
#define FH_RCSR_RBD_BASE(_channel)  (FH_RCSR(_channel)+0x04)
#define FH_RCSR_WPTR(_channel)      (FH_RCSR(_channel)+0x20)
#define FH_RCSR_RPTR_ADDR(_channel) (FH_RCSR(_channel)+0x24)

#if IWL == 3945
#define FH_RSCSR_CHNL0_WPTR        (FH_RCSR_WPTR(0))
#elif IWL == 4965
#define FH_RSCSR_CHNL0_WPTR        (FH_RSCSR_CHNL0_RBDCB_WPTR_REG)
#endif

/* RSSR */
#define FH_RSSR_CTRL            (FH_RSSR_TABLE+0x000)
#define FH_RSSR_STATUS          (FH_RSSR_TABLE+0x004)
/* TCSR */
#define FH_TCSR(_channel)           (FH_TCSR_TABLE+(_channel)*0x20)
#define FH_TCSR_CONFIG(_channel)    (FH_TCSR(_channel)+0x00)
#define FH_TCSR_CREDIT(_channel)    (FH_TCSR(_channel)+0x04)
#define FH_TCSR_BUFF_STTS(_channel) (FH_TCSR(_channel)+0x08)
/* TSSR */
#define FH_TSSR_CBB_BASE        (FH_TSSR_TABLE+0x000)
#define FH_TSSR_MSG_CONFIG      (FH_TSSR_TABLE+0x008)
#define FH_TSSR_TX_STATUS       (FH_TSSR_TABLE+0x010)
/* 18 - reserved */

/* card static random access memory (SRAM) for processor data and instructs */
#define RTC_INST_LOWER_BOUND                        (0x00000)
#define ALM_RTC_INST_UPPER_BOUND                    (0x14000)

#define RTC_DATA_LOWER_BOUND                                (0x800000)
#define ALM_RTC_DATA_UPPER_BOUND                            (0x808000)

#define ALM_RTC_INST_SIZE (ALM_RTC_INST_UPPER_BOUND - RTC_INST_LOWER_BOUND)
#define ALM_RTC_DATA_SIZE (ALM_RTC_DATA_UPPER_BOUND - RTC_DATA_LOWER_BOUND)

#define VALID_RTC_DATA_ADDR(addr)               \
    ( ((addr) >= RTC_DATA_LOWER_BOUND) && ((addr) < ALM_RTC_DATA_UPPER_BOUND) )


/* HW I/F configuration */
#define CSR_HW_IF_CONFIG_REG_BIT_ALMAGOR_MB         (0x00000100)
#define CSR_HW_IF_CONFIG_REG_BIT_ALMAGOR_MM         (0x00000200)
#define CSR_HW_IF_CONFIG_REG_BIT_SKU_MRC            (0x00000400)
#define CSR_HW_IF_CONFIG_REG_BIT_BOARD_TYPE         (0x00000800)
#define CSR_HW_IF_CONFIG_REG_BITS_SILICON_TYPE_A    (0x00000000)
#define CSR_HW_IF_CONFIG_REG_BITS_SILICON_TYPE_B    (0x00001000)

#define CSR_UCODE_DRV_GP1_BIT_MAC_SLEEP             (0x00000001)
#define CSR_UCODE_SW_BIT_RFKILL                     (0x00000002)
#define CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED           (0x00000004)
#define CSR_UCODE_DRV_GP1_REG_BIT_CT_KILL_EXIT      (0x00000008)

#define CSR_GPIO_IN_BIT_AUX_POWER                   (0x00000200)
#define CSR_GPIO_IN_VAL_VAUX_PWR_SRC                (0x00000000)
#define CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX  (0x00800000)
#define CSR_GIO_CHICKEN_BITS_REG_BIT_DIS_L0S_EXIT_TIMER  (0x20000000)
#define CSR_GPIO_IN_VAL_VMAIN_PWR_SRC               CSR_GPIO_IN_BIT_AUX_POWER

#define PCI_CFG_PMC_PME_FROM_D3COLD_SUPPORT         (0x80000000)


/* interrupt flags in INTA, set by uCode or hardware (e.g. dma),
 * acknowledged (reset) by host writing "1" to flagged bits. */
#define BIT_INT_FH_RX        (1<<31) /* Rx DMA, cmd responses, FH_INT[17:16] */
#define BIT_INT_ERR          (1<<29) /* DMA hardware error FH_INT[31] */
#define BIT_INT_FH_TX        (1<<27) /* Tx DMA FH_INT[1:0] */
#define BIT_INT_MAC_CLK_ACTV (1<<26) /* NIC controller's clock toggled on/off */
#define BIT_INT_SWERROR      (1<<25) /* uCode error */
#define BIT_INT_RF_KILL      (1<<7)  /* HW RFKILL switch GP_CNTRL[27] toggled */
#define BIT_INT_CT_KILL      (1<<6)  /* Critical temp (chip too hot) rfkill */
#define BIT_INT_SW_RX        (1<<3)  /* Rx, command responses, 3945 */
#define BIT_INT_WAKEUP       (1<<1)  /* NIC controller waking up (pwr mgmt) */
#define BIT_INT_ALIVE        (1<<0)  /* uCode interrupts once it initializes */

#define CSR_INI_SET_MASK      ( BIT_INT_FH_RX   |  \
				BIT_INT_ERR     |  \
				BIT_INT_FH_TX   |  \
				BIT_INT_SWERROR |  \
				BIT_INT_RF_KILL |  \
				BIT_INT_SW_RX   |  \
				BIT_INT_WAKEUP  |  \
				BIT_INT_ALIVE )

/* interrupt flags in FH (flow handler) (PCI busmaster DMA) */
#define BIT_FH_INT_ERR       (1<<31) /* Error */
#define BIT_FH_INT_HI_PRIOR  (1<<30) /* High priority Rx, bypass coalescing */
#define BIT_FH_INT_RX_CHNL2  (1<<18) /* Rx channel 2 (3945 only) */
#define BIT_FH_INT_RX_CHNL1  (1<<17) /* Rx channel 1 */
#define BIT_FH_INT_RX_CHNL0  (1<<16) /* Rx channel 0 */
#define BIT_FH_INT_TX_CHNL6  (1<<6)  /* Tx channel 6 (3945 only) */
#define BIT_FH_INT_TX_CHNL1  (1<<1)  /* Tx channel 1 */
#define BIT_FH_INT_TX_CHNL0  (1<<0)  /* Tx channel 0 */

#define FH_INT_RX_MASK        ( BIT_FH_INT_HI_PRIOR |  \
				BIT_FH_INT_RX_CHNL2 |  \
				BIT_FH_INT_RX_CHNL1 |  \
				BIT_FH_INT_RX_CHNL0 )

#define FH_INT_TX_MASK        ( BIT_FH_INT_TX_CHNL6 |  \
				BIT_FH_INT_TX_CHNL1 |  \
				BIT_FH_INT_TX_CHNL0 )

/* RESET */
#define CSR_RESET_REG_FLAG_NEVO_RESET                (0x00000001)
#define CSR_RESET_REG_FLAG_FORCE_NMI                 (0x00000002)
#define CSR_RESET_REG_FLAG_SW_RESET                  (0x00000080)
#define CSR_RESET_REG_FLAG_MASTER_DISABLED           (0x00000100)
#define CSR_RESET_REG_FLAG_STOP_MASTER               (0x00000200)

/* GP (general purpose) CONTROL */
#define CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY        (0x00000001)
#define CSR_GP_CNTRL_REG_FLAG_INIT_DONE              (0x00000004)
#define CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ         (0x00000008)
#define CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP         (0x00000010)

#define CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN          (0x00000001)

#define CSR_GP_CNTRL_REG_MSK_POWER_SAVE_TYPE        (0x07000000)
#define CSR_GP_CNTRL_REG_FLAG_MAC_POWER_SAVE         (0x04000000)
#define CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW          (0x08000000)

/* APMG (power management) constants */
#define APMG_CLK_CTRL_REG                        (0x003000)
#define ALM_APMG_CLK_EN                          (0x003004)
#define ALM_APMG_CLK_DIS                         (0x003008)
#define ALM_APMG_PS_CTL                          (0x00300c)
#define ALM_APMG_PCIDEV_STT                      (0x003010)
#define ALM_APMG_RFKILL				 (0x003014)
#define ALM_APMG_LARC_INT                        (0x00301c)
#define ALM_APMG_LARC_INT_MSK                    (0x003020)

#define APMG_CLK_REG_VAL_DMA_CLK_RQT                (0x00000200)
#define APMG_CLK_REG_VAL_BSM_CLK_RQT                (0x00000800)

#define APMG_PS_CTRL_REG_VAL_ALM_R_RESET_REQ        (0x04000000)

#define APMG_DEV_STATE_REG_VAL_L1_ACTIVE_DISABLE    (0x00000800)

#define APMG_PS_CTRL_REG_MSK_POWER_SRC              (0x03000000)
#define APMG_PS_CTRL_REG_VAL_POWER_SRC_VMAIN        (0x00000000)
#define APMG_PS_CTRL_REG_VAL_POWER_SRC_VAUX         (0x01000000)

/* BSM (bootstrap state machine) */
#define BSM_WR_CTRL_REG_BIT_START     (0x80000000) /* start boot load now */
#define BSM_WR_CTRL_REG_BIT_START_EN  (0x40000000) /* enable boot after pwrup*/

/* DBM */

#define ALM_FH_SRVC_CHNL                            (6)

#define ALM_FH_RCSR_RX_CONFIG_REG_POS_RBDC_SIZE     (20)
#define ALM_FH_RCSR_RX_CONFIG_REG_POS_IRQ_RBTH      (4)

#define ALM_FH_RCSR_RX_CONFIG_REG_BIT_WR_STTS_EN    (0x08000000)

#define ALM_FH_RCSR_RX_CONFIG_REG_VAL_DMA_CHNL_EN_ENABLE        (0x80000000)

#define ALM_FH_RCSR_RX_CONFIG_REG_VAL_RDRBD_EN_ENABLE           (0x20000000)

#define ALM_FH_RCSR_RX_CONFIG_REG_VAL_MAX_FRAG_SIZE_128         (0x01000000)

#define ALM_FH_RCSR_RX_CONFIG_REG_VAL_IRQ_DEST_INT_HOST         (0x00001000)

#define ALM_FH_RCSR_RX_CONFIG_REG_VAL_MSG_MODE_FH               (0x00000000)

#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_TXF              (0x00000000)
#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_DRIVER           (0x00000001)

#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE_VAL    (0x00000000)
#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL     (0x00000008)

#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_IFTFD           (0x00200000)

#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_NOINT            (0x00000000)

#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE            (0x00000000)
#define ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE           (0x80000000)

#define ALM_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID          (0x00004000)

#define ALM_FH_TCSR_CHNL_TX_BUF_STS_REG_BIT_TFDB_WPTR           (0x00000001)

#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TXPD_ON      (0xFF000000)
#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_TXPD_ON      (0x00FF0000)

#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_128B    (0x00000400)

#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TFD_ON       (0x00000100)
#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_CBB_ON       (0x00000080)

#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RSP_WAIT_TH     (0x00000020)
#define ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_RSP_WAIT_TH           (0x00000005)

#define ALM_TB_MAX_BYTES_COUNT      (0xFFF0)

#define ALM_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_channel) \
	((1LU << _channel) << 24)
#define ALM_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_channel) \
	((1LU << _channel) << 16)

#define ALM_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(_channel) \
	(ALM_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_channel) | \
	 ALM_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_channel))
#define PCI_CFG_REV_ID_BIT_BASIC_SKU                (0x40)	/* bit 6    */
#define PCI_CFG_REV_ID_BIT_RTP                      (0x80)	/* bit 7    */

#define HBUS_TARG_MBX_C_REG_BIT_CMD_BLOCKED         (0x00000004)

#define TFD_QUEUE_MIN           0
#define TFD_QUEUE_MAX           6
#define TFD_QUEUE_SIZE_MAX      (256)

/* spectrum and channel data structures */
#define IWL_NUM_SCAN_RATES         (2)

#define IWL_SCAN_FLAG_24GHZ  (1<<0)
#define IWL_SCAN_FLAG_52GHZ  (1<<1)
#define IWL_SCAN_FLAG_ACTIVE (1<<2)
#define IWL_SCAN_FLAG_DIRECT (1<<3)

#define IWL_MAX_CMD_SIZE 1024

/* LEDs mode */

#define IWL_DEFAULT_TX_RETRY  15
#define IWL_MAX_TX_RETRY      16

/*********************************************/

#define RFD_SIZE                              4
#define NUM_TFD_CHUNKS                        4

#define RX_QUEUE_SIZE                         256
#define RX_QUEUE_SIZE_LOG                     8

/*
 * TX Queue Flag Definitions
 */

/* abort attempt if mgmt frame is rx'd */

/* require CTS */

/* use short preamble */
#define DCT_FLAG_LONG_PREAMBLE             0x00
#define DCT_FLAG_SHORT_PREAMBLE            0x04

/* RTS/CTS first */

/* don't calculate duration field */

/* even if MAC WEP set (allows pre-encrypt) */
#define IWL_
/* overwrite TSF field */

/* ACK rx is expected to follow */
#define DCT_FLAG_ACK_REQD                  0x80

#define IWL_MB_DISASSOCIATE_THRESHOLD_DEFAULT           24
#define IWL_MB_ROAMING_THRESHOLD_DEFAULT                8
#define IWL_REAL_RATE_RX_PACKET_THRESHOLD               300

/* QoS  definitions */

#define CW_MIN_OFDM          15
#define CW_MAX_OFDM          1023
#define CW_MIN_CCK           31
#define CW_MAX_CCK           1023

#define QOS_TX0_CW_MIN_OFDM      CW_MIN_OFDM
#define QOS_TX1_CW_MIN_OFDM      CW_MIN_OFDM
#define QOS_TX2_CW_MIN_OFDM      ( (CW_MIN_OFDM + 1) / 2 - 1 )
#define QOS_TX3_CW_MIN_OFDM      ( (CW_MIN_OFDM + 1) / 4 - 1 )

#define QOS_TX0_CW_MIN_CCK       CW_MIN_CCK
#define QOS_TX1_CW_MIN_CCK       CW_MIN_CCK
#define QOS_TX2_CW_MIN_CCK       ( (CW_MIN_CCK + 1) / 2 - 1 )
#define QOS_TX3_CW_MIN_CCK       ( (CW_MIN_CCK + 1) / 4 - 1 )

#define QOS_TX0_CW_MAX_OFDM      CW_MAX_OFDM
#define QOS_TX1_CW_MAX_OFDM      CW_MAX_OFDM
#define QOS_TX2_CW_MAX_OFDM      CW_MIN_OFDM
#define QOS_TX3_CW_MAX_OFDM      ( (CW_MIN_OFDM + 1) / 2 - 1 )

#define QOS_TX0_CW_MAX_CCK       CW_MAX_CCK
#define QOS_TX1_CW_MAX_CCK       CW_MAX_CCK
#define QOS_TX2_CW_MAX_CCK       CW_MIN_CCK
#define QOS_TX3_CW_MAX_CCK       ( (CW_MIN_CCK + 1) / 2 - 1 )

#define QOS_TX0_AIFS            (3)
#define QOS_TX1_AIFS            (7)
#define QOS_TX2_AIFS            (2)
#define QOS_TX3_AIFS            (2)

#define QOS_TX0_ACM             0
#define QOS_TX1_ACM             0
#define QOS_TX2_ACM             0
#define QOS_TX3_ACM             0

#define QOS_TX0_TXOP_LIMIT_CCK          0
#define QOS_TX1_TXOP_LIMIT_CCK          0
#define QOS_TX2_TXOP_LIMIT_CCK          6016
#define QOS_TX3_TXOP_LIMIT_CCK          3264

#define QOS_TX0_TXOP_LIMIT_OFDM      0
#define QOS_TX1_TXOP_LIMIT_OFDM      0
#define QOS_TX2_TXOP_LIMIT_OFDM      3008
#define QOS_TX3_TXOP_LIMIT_OFDM      1504

#define DEF_TX0_CW_MIN_OFDM      CW_MIN_OFDM
#define DEF_TX1_CW_MIN_OFDM      CW_MIN_OFDM
#define DEF_TX2_CW_MIN_OFDM      CW_MIN_OFDM
#define DEF_TX3_CW_MIN_OFDM      CW_MIN_OFDM

#define DEF_TX0_CW_MIN_CCK       CW_MIN_CCK
#define DEF_TX1_CW_MIN_CCK       CW_MIN_CCK
#define DEF_TX2_CW_MIN_CCK       CW_MIN_CCK
#define DEF_TX3_CW_MIN_CCK       CW_MIN_CCK

#define DEF_TX0_CW_MAX_OFDM      CW_MAX_OFDM
#define DEF_TX1_CW_MAX_OFDM      CW_MAX_OFDM
#define DEF_TX2_CW_MAX_OFDM      CW_MAX_OFDM
#define DEF_TX3_CW_MAX_OFDM      CW_MAX_OFDM

#define DEF_TX0_CW_MAX_CCK       CW_MAX_CCK
#define DEF_TX1_CW_MAX_CCK       CW_MAX_CCK
#define DEF_TX2_CW_MAX_CCK       CW_MAX_CCK
#define DEF_TX3_CW_MAX_CCK       CW_MAX_CCK

#define DEF_TX0_AIFS            (2)
#define DEF_TX1_AIFS            (2)
#define DEF_TX2_AIFS            (2)
#define DEF_TX3_AIFS            (2)

#define DEF_TX0_ACM             0
#define DEF_TX1_ACM             0
#define DEF_TX2_ACM             0
#define DEF_TX3_ACM             0

#define DEF_TX0_TXOP_LIMIT_CCK        0
#define DEF_TX1_TXOP_LIMIT_CCK        0
#define DEF_TX2_TXOP_LIMIT_CCK        0
#define DEF_TX3_TXOP_LIMIT_CCK        0

#define DEF_TX0_TXOP_LIMIT_OFDM       0
#define DEF_TX1_TXOP_LIMIT_OFDM       0
#define DEF_TX2_TXOP_LIMIT_OFDM       0
#define DEF_TX3_TXOP_LIMIT_OFDM       0

#define QOS_QOS_SETS                  3
#define QOS_PARAM_SET_ACTIVE          0
#define QOS_PARAM_SET_DEF_CCK         1
#define QOS_PARAM_SET_DEF_OFDM        2

#define CTRL_QOS_NO_ACK               (0x0020)
#define DCT_FLAG_EXT_QOS_ENABLED      (0x10)

#define IWL_TX_QUEUE_AC0        0
#define IWL_TX_QUEUE_AC1        1
#define IWL_TX_QUEUE_AC2        2
#define IWL_TX_QUEUE_AC3        3
#define IWL_TX_QUEUE_HCCA_1     5
#define IWL_TX_QUEUE_HCCA_2     6

#define U32_PAD(n)                     ((4-(n%4))%4)

#define AC_BE_TID_MASK 0x9	/* TID 0 and 3 */
#define AC_BK_TID_MASK 0x6	/* TID 1 and 2 */

/*
 * Generic queue structure
 *
 * Contains common data for Rx and Tx queues
 */
#define TFD_CTL_COUNT_SET(n)       (n<<24)
#define TFD_CTL_COUNT_GET(ctl)     ((ctl>>24) & 7)
#define TFD_CTL_PAD_SET(n)         (n<<28)
#define TFD_CTL_PAD_GET(ctl)       (ctl>>28)

#define TFD_TX_CMD_SLOTS 64
#define TFD_CMD_SLOTS 32

#define TFD_MAX_PAYLOAD_SIZE (sizeof(struct iwl_cmd) - \
			      sizeof(struct iwl_cmd_meta))

/*
 * RX related structures and functions
 */
#define RX_FREE_BUFFERS 64
#if IWL == 4965
#define RX_LOW_WATERMARK 25
#else
#define RX_LOW_WATERMARK 8
#endif

#define SUP_RATE_11A_MAX_NUM_CHANNELS  8
#define SUP_RATE_11B_MAX_NUM_CHANNELS  4
#define SUP_RATE_11G_MAX_NUM_CHANNELS  12

#define IWL_CMD_FAILED_MSK 0x40

struct iwl_cmd_header {
	u8 cmd;
	u8 flags;
	/* We have 15 LSB to use as we please (MSB indicates
	 * a frame Rx'd from the HW).  We encode the following
	 * information into the sequence field:
	 *
	 *  0:7    index in fifo
	 *  8:13   fifo selection
	 * 14:14   bit indicating if this packet references the 'extra'
	 *         storage at the end of the memory queue
	 * 15:15   (Rx indication)
	 *
	 */
	__le16 sequence;

	/* command data follows immediately */
	u8 data[0];
} __attribute__ ((packed));

/* Used for passing to driver number of successes and failures per rate */
struct rate_histogram {
	union {
		__le32 a[SUP_RATE_11A_MAX_NUM_CHANNELS];
		__le32 b[SUP_RATE_11B_MAX_NUM_CHANNELS];
		__le32 g[SUP_RATE_11G_MAX_NUM_CHANNELS];
	} success;
	union {
		__le32 a[SUP_RATE_11A_MAX_NUM_CHANNELS];
		__le32 b[SUP_RATE_11B_MAX_NUM_CHANNELS];
		__le32 g[SUP_RATE_11G_MAX_NUM_CHANNELS];
	} failed;
} __attribute__ ((packed));

/* statistics command response */

struct statistics_rx_phy {
	__le32 ina_cnt;
	__le32 fina_cnt;
	__le32 plcp_err;
	__le32 crc32_err;
	__le32 overrun_err;
	__le32 early_overrun_err;
	__le32 crc32_good;
	__le32 false_alarm_cnt;
	__le32 fina_sync_err_cnt;
	__le32 sfd_timeout;
	__le32 fina_timeout;
	__le32 unresponded_rts;
	__le32 rxe_frame_limit_overrun;
	__le32 sent_ack_cnt;
	__le32 sent_cts_cnt;
#if IWL == 4965
	__le32 sent_ba_rsp_cnt;
	__le32 dsp_self_kill;
	__le32 mh_format_err;
	__le32 re_acq_main_rssi_sum;
	__le32 reserved3;
#endif
} __attribute__ ((packed));

#if IWL == 4965
struct statistics_rx_ht_phy {
	__le32 plcp_err;
	__le32 overrun_err;
	__le32 early_overrun_err;
	__le32 crc32_good;
	__le32 crc32_err;
	__le32 mh_format_err;
	__le32 agg_crc32_good;
	__le32 agg_mpdu_cnt;
	__le32 agg_cnt;
	__le32 reserved2;
} __attribute__ ((packed));
#endif

struct statistics_rx_non_phy {
	__le32 bogus_cts;	/* CTS received when not expecting CTS */
	__le32 bogus_ack;	/* ACK received when not expecting ACK */
	__le32 non_bssid_frames;	/* number of frames with BSSID that
					 * doesn't belong to the STA BSSID */
	__le32 filtered_frames;	/* count frames that were dumped in the
				 * filtering process */
	__le32 non_channel_beacons;	/* beacons with our bss id but not on
					 * our serving channel */
#if IWL == 4965
	__le32 channel_beacons;	/* beacons with our bss id and in our
				 * serving channel */
	__le32 num_missed_bcon;	/* number of missed beacons */
	__le32 adc_rx_saturation_time;	/* count in 0.8us units the time the
					 * ADC was in saturation */
	__le32 ina_detection_search_time;/* total time (in 0.8us) searched
					  * for INA */
	__le32 beacon_silence_rssi_a;	/* RSSI silence after beacon frame */
	__le32 beacon_silence_rssi_b;	/* RSSI silence after beacon frame */
	__le32 beacon_silence_rssi_c;	/* RSSI silence after beacon frame */
	__le32 interference_data_flag;	/* flag for interference data
					 * availability. 1 when data is
					 * available. */
	__le32 channel_load;	/* counts RX Enable time */
	__le32 dsp_false_alarms;	/* DSP false alarm (both OFDM
					 * and CCK) counter */
	__le32 beacon_rssi_a;
	__le32 beacon_rssi_b;
	__le32 beacon_rssi_c;
	__le32 beacon_energy_a;
	__le32 beacon_energy_b;
	__le32 beacon_energy_c;
#endif
} __attribute__ ((packed));

struct statistics_rx {
	struct statistics_rx_phy ofdm;
	struct statistics_rx_phy cck;
	struct statistics_rx_non_phy general;
#if IWL == 4965
	struct statistics_rx_ht_phy ofdm_ht;
#endif
} __attribute__ ((packed));

#if IWL == 4965
struct statistics_tx_non_phy_agg {
	__le32 ba_timeout;
	__le32 ba_reschedule_frames;
	__le32 scd_query_agg_frame_cnt;
	__le32 scd_query_no_agg;
	__le32 scd_query_agg;
	__le32 scd_query_mismatch;
	__le32 frame_not_ready;
	__le32 underrun;
	__le32 bt_prio_kill;
	__le32 rx_ba_rsp_cnt;
	__le32 reserved2;
	__le32 reserved3;
} __attribute__ ((packed));
#endif

struct statistics_tx {
	__le32 preamble_cnt;
	__le32 rx_detected_cnt;
	__le32 bt_prio_defer_cnt;
	__le32 bt_prio_kill_cnt;
	__le32 few_bytes_cnt;
	__le32 cts_timeout;
	__le32 ack_timeout;
	__le32 expected_ack_cnt;
	__le32 actual_ack_cnt;
#if IWL == 4965
	__le32 dump_msdu_cnt;
	__le32 burst_abort_next_frame_mismatch_cnt;
	__le32 burst_abort_missing_next_frame_cnt;
	__le32 cts_timeout_collision;
	__le32 ack_or_ba_timeout_collision;
	struct statistics_tx_non_phy_agg agg;
#endif
} __attribute__ ((packed));

struct statistics_dbg {
	__le32 burst_check;
	__le32 burst_count;
	__le32 reserved[4];
} __attribute__ ((packed));

struct statistics_div {
	__le32 tx_on_a;
	__le32 tx_on_b;
	__le32 exec_time;
	__le32 probe_time;
#if IWL == 4965
	__le32 reserved1;
	__le32 reserved2;
#endif
} __attribute__ ((packed));

struct statistics_general {
	__le32 temperature;
#if IWL == 4965
	__le32 temperature_m;
#endif
	struct statistics_dbg dbg;
	__le32 sleep_time;
	__le32 slots_out;
	__le32 slots_idle;
	__le32 ttl_timestamp;
	struct statistics_div div;
#if IWL == 4965
	__le32 rx_enable_counter;
	__le32 reserved1;
	__le32 reserved2;
	__le32 reserved3;
#endif
} __attribute__ ((packed));

struct iwl_notif_statistics {
	__le32 flag;
	struct statistics_rx rx;
	struct statistics_tx tx;
	struct statistics_general general;
} __attribute__ ((packed));

struct iwl_rx_packet {
	__le32 len;
	struct iwl_cmd_header hdr;
	union {
		struct iwl_alive_resp alive_frame;
		struct iwl_rx_frame rx_frame;
		struct iwl_tx_resp tx_resp;
		struct iwl_spectrum_notification spectrum_notif;
		struct iwl_csa_notification csa_notif;
		struct iwl_error_resp err_resp;
		struct iwl_card_state_notif card_state_notif;
		struct iwl_beacon_notif beacon_status;
		struct iwl_add_sta_resp add_sta;
		struct iwl_sleep_notification sleep_notif;
		struct iwl_spectrum_resp spectrum;
		struct iwl_notif_statistics stats;
#if IWL == 4965
		struct iwl_compressed_ba_resp compressed_ba;
		struct iwl_missed_beacon_notif missed_beacon;
#endif
		__le32 status;
		u8 raw[0];
	} u;
} __attribute__ ((packed));

#define IWL_RX_FRAME_SIZE        (4 + sizeof(struct iwl_rx_frame))

struct iwl_multicast_addr {
	u8 num_of_multicast_addresses;
	u8 reserved[3];
	u8 mac1[6];
	u8 mac2[6];
	u8 mac3[6];
	u8 mac4[6];
} __attribute__ ((packed));

struct iwl_tgi_tx_key {
	u8 key_id;
	u8 security_type;
	u8 station_index;
	u8 flags;
	u8 key[16];
	__le32 tx_counter[2];
} __attribute__ ((packed));

struct iwl_associate {
	u8 channel;
	u8 auth; /* & 0xf0 = auth_type, & 0xf0 = auth_key*/
	u8 assoc_type;
	u8 reserved;
	__le16 policy_support;
	u8 preamble_length;
	u8 ieee_mode;
	u8 bssid[ETH_ALEN];
	__le32 assoc_tsf_msw;
	__le32 assoc_tsf_lsw;
	__le16 capability;
	__le16 listen_interval;
	__le16 beacon_interval;
	u8 dest[ETH_ALEN];
	__le16 atim_window;
	u8 smr;
	u8 reserved1;
	__le16 reserved2;
	__le16 assoc_id;
	u8 erp_value;
} __attribute__ ((packed));

#define IWL_SUPPORTED_RATES_IE_LEN         8

struct iwl_supported_rates {
	u8 ieee_mode;
	u8 num_rates;
	u8 purpose;
	u8 reserved;
	u8 supported_rates[IWL_MAX_RATES];
} __attribute__ ((packed));

struct iwl_channel_tx_power {
	u8 channel_number;
	s8 tx_power;
} __attribute__ ((packed));

#if IWL == 3945
#include "iwl-3945-hw.h"
#elif IWL == 4965
#include "iwl-4965-hw.h"
#endif

#endif				/* __iwlwifi_hw_h__ */
