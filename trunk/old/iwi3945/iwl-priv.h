/******************************************************************************
 *
 * Copyright(c) 2003 - 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110, USA
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *
 * Contact Information:
 * James P. Ketrenos <ipw2100-admin@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 *****************************************************************************/

#ifndef __iwl_priv_h__
#define __iwl_priv_h__
#include "defines.h"
//#include <linux/workqueue.h>

#ifdef CONFIG_IWLWIFI_SPECTRUM_MEASUREMENT

enum {
	MEASUREMENT_READY = (1 << 0),
	MEASUREMENT_ACTIVE = (1 << 1),
};

#endif

struct iwl_priv {

	struct ieee80211_hw *hw;
	struct ieee80211_channel *ieee_channels;
	struct ieee80211_rate *ieee_rates;

	struct list_head free_frames;
	int frames_count;

	u8 phymode;
	int alloc_rxb_skb;

	void (*rx_handlers[REPLY_MAX])(struct iwl_priv * priv,
				       struct iwl_rx_mem_buffer * rxb);

	const struct ieee80211_hw_mode *modes;

#ifdef CONFIG_IWLWIFI_SPECTRUM_MEASUREMENT
	struct iwl_spectrum_notification measure_report;
	u8 measurement_status;
#endif

	struct iwl_channel_info *channel_info;	
	u8 channel_count;	

	const struct iwl_clip_group clip_groups[5];

	s32 temperature;	
	s32 last_temperature;

	unsigned long last_scan_jiffies;
	unsigned long scan_start;
	unsigned long scan_pass_start;
	unsigned long scan_start_tsf;
	int scan_bands;
	int one_direct_scan;
	u8 direct_ssid_len;
	u8 direct_ssid[IW_ESSID_MAX_SIZE];
	struct iwl_scan_cmd *scan;
	u8 only_active_channel;

	void* lock;
	void* mutex;

	//struct pci_dev *pci_dev;

	void* hw_base;
	unsigned long hw_len;

	struct fw_image_desc ucode_code;	
	struct fw_image_desc ucode_data;	
	struct fw_image_desc ucode_data_backup;	
	struct fw_image_desc ucode_init;	
	struct fw_image_desc ucode_init_data;	
	struct fw_image_desc ucode_boot;	


	struct iwl_rxon_time_cmd rxon_timing;


	const struct iwl_rxon_cmd active_rxon;
	struct iwl_rxon_cmd staging_rxon;

	int error_recovering;
	struct iwl_rxon_cmd recovery_rxon;

	// 1st responses from initialize and runtime uCode images.
	// 4965's initialize alive response contains some calibration data. 
	struct iwl_init_alive_resp card_alive_init;
	struct iwl_alive_resp card_alive;

#ifdef LED
	struct iwl_activity_blink activity;
	unsigned long led_packets;
	int led_state;
#endif

	u16 active_rate;
	u16 active_rate_basic;

	u8 call_post_assoc_from_beacon;
	u8 assoc_station_added;
#if IWL == 4965
	u8 use_ant_b_for_management_frame;	// Tx antenna selection 
	// HT variables 
	u8 is_dup;
	u8 is_ht_enabled;
	u8 channel_width;	// 0=20MHZ, 1=40MHZ 
	u8 current_channel_width;
	u8 valid_antenna;	// Bit mask of antennas actually connected 
#ifdef CONFIG_IWLWIFI_SENSITIVITY
	struct iwl_sensitivity_data sensitivity_data;
	struct iwl_chain_noise_data chain_noise_data;
	u8 start_calib;
	__le16 sensitivity_tbl[HD_TABLE_SIZE];
#endif 

#ifdef CONFIG_IWLWIFI_HT
	struct sta_ht_info current_assoc_ht;
#endif
	u8 active_rate_ht[2];
	u8 last_phy_res[100];

	// Rate scaling data 
	struct iwl_lq_mngr lq_mngr;
#endif

	// Rate scaling data 
	s8 data_retry_limit;
	u8 retry_rate;

	void* wait_command_queue;

	int activity_timer_active;

	//Rx and Tx DMA processing queues 
	struct iwl_rx_queue rxq;
	struct iwl_tx_queue txq[IWL_MAX_NUM_QUEUES];
#if IWL == 4965
	struct iwl_kw kw;	// keep warm address 
	u32 scd_base_addr;	// scheduler sram base address 
#endif

	u32 status;
	u32 config;

	int quality;
	int last_rx_rssi;
	int last_rx_noise;
	int last_rx_snr;

	struct iwl_power_mgr power_data;

	struct iwl_notif_statistics statistics;
	unsigned long last_statistics_time;

	// context information 
	u8 essid[IW_ESSID_MAX_SIZE];
	u8 essid_len;
	u16 rates_mask;

	u32 power_mode;
	u32 antenna;
	u8 bssid[ETH_ALEN];
	u16 rts_threshold;
	u8 mac_addr[ETH_ALEN];

	//station table variables 
	void* sta_lock;
	u8 num_stations;
	struct iwl_station_entry stations[IWL_STATION_COUNT];

	// Indication if ieee80211_ops->open has been called 
	int is_open;

	u8 mac80211_registered;
	int is_abg;

	u32 notif_missed_beacons;

	// Rx'd packet timing information
	u32 last_beacon_time;
	u64 last_tsf;

	// Duplicate packet detection
	u16 last_seq_num;
	u16 last_frag_num;
	unsigned long last_packet_time;
	struct list_head ibss_mac_hash[IWL_IBSS_MAC_HASH_SIZE];

	struct iwl_eeprom eeprom;

	int iw_mode;

	mbuf_t ibss_beacon;

	// Last Rx'd beacon timestamp 
	u32 timestamp0;
	u32 timestamp1;
	u16 beacon_int;
	struct iwl_driver_hw_info hw_setting;
	int interface_id;

	// Current association information needed to configure the
	//hardware 
	u16 assoc_id;
	u16 assoc_capability;
	u8 ps_mode;

	void* workqueue;

	void* up;
	void* restart;
	void* calibrated_work;
	void* scan_completed;
	void* rx_replenish;
	void* rf_kill;
	void* abort_scan;
	void* update_link_led;
	void* auth_work;
	void* report_work;
	void* request_scan;

	void* irq_tasklet;

	void* init_alive_start;
	void* alive_start;
	void* activity_timer;
	void* thermal_periodic;
	void* gather_stats;
	void* scan_check;
	void* post_associate;

#define IWL_DEFAULT_TX_POWER 0x0F
	s8 user_txpower_limit;
	s8 max_channel_txpower_limit;
	u32 cck_power_index_compensation;

#ifdef CONFIG_PM
	u32 pm_state[16];
#endif

	// debugging info 
	u32 framecnt_to_us;



#if IWL == 4965
	void* txpower_work;
#ifdef CONFIG_IWLWIFI_SENSITIVITY
	void* sensitivity_work;
#endif
	void* statistics_work;
	struct timer_list statistics_periodic;

#ifdef CONFIG_IWLWIFI_HT_AGG
	void* agg_work;
#endif

#endif // 4965

};				/*iwl_priv */

#endif /* __iwl_priv_h__ */
