/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2005 - 2006 Intel Corporation. All rights reserved.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU Geeral Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
  USA

  The full GNU General Public License is included in this distribution
  in the file called LICENSE.GPL.

  Contact Information:
  James P. Ketrenos <ipw2100-admin@linux.intel.com>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

  BSD LICENSE

  Copyright(c) 2005 - 2006 Intel Corporation. All rights reserved.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/
#ifndef __ipw3945_daemon_h__
#define __ipw3945_daemon_h__

/* driver <-> daemon command and response structure */

#define IPW_DAEMON_VERSION 7

/* Protol change history
 *
 * Changes in protocol v7
 *   * Changed REINIT to an explicit UNINIT and INIT sequence
 *   * Added DAEMON_SYNC_{SUSPEND,RESUME} for the driver to
 *     notify the daemon when it is going into suspend/resume.
 *
 * Changes in protocol v6
 *   * Added TEMPERATURE and EEPROM read commands
 *   * Added STATE command for set daemon state
 *   * Changed DAEMON_SYNC_* enumeration
 *
 * Changes in protocol v5
 *   * Added DAEMON_POLL_INTERVAL as the maximum time
 *     in ms for the driver to block in the sysfs show
 *     operation.  If no commands are available in that
 *   * Renamed all IPW_ defines to DAEMON_
 *     time period, it needs to return -ETIMEDOUT.
 *   * Removed DAEMON_SYNC_ASSOCIATE and added beacon_interval
 *     to DAEMON_RX_CONFIG.
 *
 * Changes in protocol v4
 *   * Added DAEMON_SYNC_TX_STATUS for sending Tx measurement
 *     status to the daemon.
 *
 * Changes in protocol v3
 *   * Added synchronous command notification via DAEMON_CMD_DONE
 *
 */

/*
 * Driver / Daemon State Machine
 *
 * As a result of the requirements that the device must operate within
 * operating parameters known to be in compliance, the daemon enforces
 * its view of the hardware state machine.  If the daemon does not think
 * the hardware is calibrated, for example, it won't allow scanning or
 * rx config to be configured.
 *
 * The typical flow of events is as follows:
 * 1.  Driver loads
 * 2.  Daemon loads
 * 3.  Daemon finds driver sysfs entry (exiting if not present)
 * 4.  Daemon requests the driver perform a UNINIT sequence via
 *     DAEMON_SET_STATE with the state DAEMON_DRIVER_STATE_UNINIT
 *     At this point, the daemon's view of the hardware is uninitializing
 * 5.  Driver takes down hardware (if it is configured).
 *     At completion of the takedown, or if not needed, the driver sends the
 *     DAEMON_SYNC:DAEMON_SYNC_UNINIT to the daemon.
 * 6.  Daemon requests the driver perform an INIT sequence via
 *     DAEMON_SET_STATE with the state DAEMON_DRIVER_STATE_INIT
 *     At this point, the daemon's view of the hardware is initializing
 * 7.  Driver brings up the hardware.  At completion of the bring up,
 *     the driver sends the DAEMON_SYNC:DAEMON_SYNC_INIT to the daemon.
 * 8.  Driver sends DAEMON_SYNC command with the state set to DAEMON_SYNC_INIT
 *     At this point, the daemon's view of the hardware is initialized, but
 *     not calibrated.
 * 9.  Daemon calibrates the hardware
 *     At this point, the daemon's view of the hardware is calibrated -- all
 *     operations now function (scan, rx_config, etc.)
 * 10. Daemon sends DAEMON_SET_STATE with DAEMON_DRIVER_STATE_CALIBRATED
 *
 * In the event that the driver detects a microcode or hardware error, the
 * following will occur:
 * 1.  Driver sends DAEMON_SYNC command with the state set to DAEMON_SYNC_UNINIT
 * 2.  Upon receipt of the DAEMON_SYNC_UNINIT command, the state machine
 *     transitions back to step #6 above
 *
 * If the regulatory daemon is terminated and restarted, the steps begin above
 * with step #2.
 *
 * Between step #4 and step #9, the daemon will ignore all commands sent from
 * the driver to the daemon.  This allows any pending operations to flush
 * out of the queues and for the driver and daemon to synchronize back to the
 * DAEMON_SYNC_INIT state.
 *
 */

/* command and reponse enumeration */
enum {
	DAEMON_ERROR = 0x01,	/* driver <-  daemon */
	DAEMON_REGULATORY_INFO = 0x02,	/* driver <-  daemon */
	DAEMON_FRAME_TX = 0x03,	/* driver <-  daemon */
	DAEMON_FRAME_RX = 0x04,	/* daemon  -> daemon */
	DAEMON_CMD_DONE = 0x05,	/* driver <-  daemon */
	DAEMON_SYNC = 0x06,	/* driver  -> daemon */
	DAEMON_SCAN_REQUEST = 0x7,	/* driver  -> daemon */
	DAEMON_RX_CONFIG = 0x8,	/* driver  -> daemon */
	DAEMON_READ_TIMEOUT = 0x9,	/* driver  -> daemon */
	DAEMON_REQUEST_INFO = 0x10,	/* driver <-  daemon */
	DAEMON_SET_STATE = 0x11,	/* driver <-  daemon */
};

/* command flags */
enum {
	DAEMON_FLAG_WANT_RESULT = (1 << 0),
	DAEMON_FLAG_HUGE = (1 << 1),
	DAEMON_FLAG_NIC_CMD = (1 << 2),
};

/* request info type */
enum {
	DAEMON_REQUEST_TEMPERATURE = 1,
	DAEMON_REQUEST_EEPROM = 2,
};

/* state of driver per daemon request
 *
 * NOTE:
 *   The driver needs to transition into these states when the
 *   daemon indicates it is required. */
enum {
	/* When the daemon requests the state to transition to the UNINIT
	 * within the driver, the driver should take down the hardware.
	 * Upon completing the take down process, the driver should
	 * send the DAEMON_SYNC:DAEMON_SYNC_UNINIT command back to the
	 * driver even if the hardware was already down. */
	DAEMON_DRIVER_STATE_UNINIT,

	/* When the daemon requests the state to transition to the INIT
	 * within the driver, the driver should take down the hardware.
	 * Upon completing the take down process, the driver should
	 * send the DAEMON_SYNC:DAEMON_SYNC_INIT command back to the
	 * driver even if the driver was already up. */
	DAEMON_DRIVER_STATE_INIT,

	/* When the daemon indicates CALIBRATED to the driver,
	 * it is an indication that the rx_config command will
	 * be able to proceed.  The driver can begin scanning,
	 * etc. */
	DAEMON_DRIVER_STATE_CALIBRATED,
};

/* Period in ms for the sysfs read operation to block waiting for
 * a command to appear. Currently set to 60s. */
#define DAEMON_POLL_INTERVAL 60000

#define DAEMON_BUF_SIZE 3000

struct daemon_cmd_hdr {
	u8 cmd;
	u8 flags;
	u8 token;
	u8 reserved1;
	u16 version;
	u16 data_len;
	u8 data[0];
} __attribute__ ((packed));

struct daemon_cmd {
	struct daemon_cmd_hdr hdr;
	u8 data[DAEMON_BUF_SIZE];
} __attribute__ ((packed));

/*  driver <- daemon error response */
struct daemon_error {
	u8 cmd_requested;
	u8 reserved1;
	u16 reserved2;
	s32 return_code;
} __attribute__ ((packed));

/*  driver <- daemon synchronous command done */
struct daemon_cmd_done {
	u8 cmd_requested;
	u8 reserved1;
	u16 reserved2;
	s32 return_code;
} __attribute__ ((packed));

/*  driver <- daemon regulatory information
 *
 * The following is sent from the daemon to the driver
 * to inform the driver of current channel capabilities and
 * restrictions.
 *
 * Immediately after INIT is provided from the driver the
 * daemon will send the full channel map.
 *
 * After a channel has been selected via rx_config, the
 * daemon will send periodic updates when the channel limits
 * change for a specific channel.
 *
 * NOTE:  The txpower field represents the current configured
 * power as directed by either the user (sent to the daemon
 * through the DAEMON_SYNC::DAEMON_SYNC_TXPOWER_LIMIT command)
 * or as specified through the currently associated access
 * point.  The max_txpower is the highest the channel is
 * allowed to transmit.
 *
 */
enum {
	DAEMON_A_BAND = (1 << 0),	/* 0 - 2.4Ghz, 1 - 5.2Ghz */
	DAEMON_IBSS_ALLOWED = (1 << 1),
	DAEMON_ACTIVE_ALLOWED = (1 << 2),
	DAEMON_RADAR_DETECT = (1 << 3),
};
struct daemon_channel_info {
	u8 channel;
	u8 flags;
	s8 txpower;
	s8 max_txpower;
};
struct daemon_regulatory_info {
	u16 count;		/* Number of channels provided */
	struct daemon_channel_info channel_info[0];
} __attribute__ ((packed));

/* driver <- daemon information request */
struct daemon_request_info {
	u8 request;
} __attribute__ ((packed));

/* driver <- daemon set state */
struct daemon_set_state {
	u8 state;
} __attribute__ ((packed));

/* driver -> daemon scan request */
#define DAEMON_MIN_24GHZ_CHANNEL 1
#define DAEMON_MAX_24GHZ_CHANNEL 14
#define DAEMON_MIN_52GHZ_CHANNEL 34
#define DAEMON_MAX_52GHZ_CHANNEL 165

#define DAEMON_SCAN_FLAG_24GHZ  (1<<0)
#define DAEMON_SCAN_FLAG_52GHZ  (1<<1)
#define DAEMON_SCAN_FLAG_ACTIVE (1<<2)
#define DAEMON_SCAN_FLAG_DIRECT (1<<3)

#define DAEMON_MAX_CMD_SIZE 1024

enum {
	DAEMON_TXRATE_1 = 0xa,
	DAEMON_TXRATE_2 = 0x14,
	DAEMON_TXRATE_5_5 = 0x37,
	DAEMON_TXRATE_6 = 0xd,
	DAEMON_TXRATE_9 = 0xf,
	DAEMON_TXRATE_11 = 0x6e,
	DAEMON_TXRATE_12 = 0x5,
	DAEMON_TXRATE_18 = 0x7,
	DAEMON_TXRATE_24 = 0x9,
	DAEMON_TXRATE_36 = 0xb,
	DAEMON_TXRATE_48 = 0x1,
	DAEMON_TXRATE_54 = 0x3,
};

struct daemon_scan_channel {
	u8 channel;
	u8 request_active;
	u16 active_dwell;
	u16 passive_dwell;
} __attribute__ ((packed));

struct daemon_ssid_ie {
	u8 id;
	u8 len;
	u8 ssid[32];
} __attribute__ ((packed));

struct daemon_rx_config {
	u8 dev_type;
	u16 channel;
	u32 flags;
	u32 filter_flags;
	u8 ofdm_basic_rates;
	u8 cck_basic_rates;
	u8 node_addr[6];
	u8 bssid_addr[6];
	u16 assoc_id;
	u16 beacon_interval;
} __attribute__ ((packed));

#define DAEMON_MAX_SCAN_SIZE 1024
struct daemon_scan_request {
	u8 flags;		/* 0 - 2.4Ghz, 1 - 5.2Ghz */
	u8 channel_count;
	u16 probe_request_len;
	u16 quiet_time;		/* dwell only this long on quiet chnl (active scan) */
	u16 quiet_plcp_th;	/* quiet chnl is < this # pkts (typ. 1) */
	u32 suspend_time;	/* pause scan this long when returning to svc chnl */
	u32 max_out_time;	/* max msec to be out of associated (service) chnl */
	u8 probe_request_rate;	/* rate to send probe request */
	u32 filter_flags;
	u32 rxon_flags;
	struct daemon_ssid_ie direct_scan;
	u8 data[0];
	/*
	   The channels start after the probe request payload and are of type:

	   struct daemon_scan_channel channels[0];

	   NOTE:  Only one band of channels can be scanned per pass.  You
	   can not mix 2.4Ghz channels and 5.2Ghz channels and must
	   request a scan multiple times (not concurrently)

	 */
} __attribute__ ((packed));

/* driver -> daemon 11h frame */
struct daemon_80211_frame {
	u8 channel;
	u8 reserved1;
	u16 rssi;
	u16 reserved2;
	u64 tsf;
	u32 beacon_time;
	u16 frame_len;
	u8 frame[0];
} __attribute__ ((packed));

struct daemon_sync_txpower_limit {
	u8 channel;
	s8 power;
} __attribute__ ((packed));

enum {
	DAEMON_SYNC_UNINIT = 0,
	DAEMON_SYNC_INIT,
	DAEMON_SYNC_SCAN_COMPLETE,
	DAEMON_SYNC_TXPOWER_LIMIT,
	DAEMON_SYNC_MEASURE_REPORT,
	DAEMON_SYNC_TX_STATUS,
	DAEMON_SYNC_SUSPEND,
	DAEMON_SYNC_RESUME,
};

/* driver  -> daemon */
struct daemon_sync_cmd {
	u16 state;
	u16 len;
	u8 data[0];
} __attribute__ ((packed));

#endif
