/******************************************************************************
 *
 * Copyright(c) 2003 - 2007 Intel Corporation. All rights reserved.
 *
 * Portions of this file are derived from the ipw3945 project, as well
 * as portions of the ieee80211 subsystem header files.
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

#ifndef __iwlwifi_h__
#define __iwlwifi_h__
#include "defines.h"

//#include <linux/pci.h> /* for struct pci_device_id */
//#include <net/ieee80211_radiotap.h>

struct iwl_priv;

/* Hardware specific file defines the PCI IDs table for that hardware module */
extern struct pci_device_id iwl_hw_card_ids[];

#if IWL == 3945
#define DRV_NAME	"iwl3945"
#elif IWL == 4965
#define DRV_NAME        "iwl4965"
#endif

#include "iwl-hw.h"

/*
 * Driver implementation data structures, constants, inline
 * functions
 *
 * NOTE:  DO NOT PUT HARDWARE/UCODE SPECIFIC DECLRATIONS HERE
 *
 * Hardware specific declrations go into iwl-*hw.h
 *
 */

#include "iwl-debug.h"


/* Module parameters accessible from iwl-*.c */
extern int param_disable_hw_scan;
extern int param_debug;
extern int param_mode;
extern int param_disable;
extern int param_antenna;
extern int param_hwcrypto;
extern int param_qos_enable;

enum iwl_antenna {
	IWL_ANTENNA_DIVERSITY,
	IWL_ANTENNA_MAIN,
	IWL_ANTENNA_AUX
};

/*
 * RTS threshold here is total size [2347] minus 4 FCS bytes
 * Per spec:
 *   a value of 0 means RTS on all data/management packets
 *   a value > max MSDU size means no RTS
 * else RTS for data/management frames where MPDU is larger
 *   than RTS value.
 */
#define DEFAULT_RTS_THRESHOLD     2347U
#define MIN_RTS_THRESHOLD         0U
#define MAX_RTS_THRESHOLD         2347U
#define MAX_MSDU_SIZE		  2304U
#define MAX_MPDU_SIZE		  2346U
#define DEFAULT_BEACON_INTERVAL   100U
#define	DEFAULT_SHORT_RETRY_LIMIT 7U
#define	DEFAULT_LONG_RETRY_LIMIT  4U

struct iwl_rx_mem_buffer {
	dma_addr_t dma_addr;
	mbuf_t skb;
	struct list_head list;
};

struct iwl_rt_rx_hdr {
	struct ieee80211_radiotap_header rt_hdr;
	__le64 rt_tsf;		/* TSF */
	u8 rt_flags;		/* radiotap packet flags */
	u8 rt_rate;		/* rate in 500kb/s */
	__le16 rt_channel;	/* channel in mHz */
	__le16 rt_chbitmask;	/* channel bitfield */
	s8 rt_dbmsignal;	/* signal in dBm, kluged to signed */
	s8 rt_dbmnoise;
	u8 rt_antenna;		/* antenna number */
	u8 payload[0];		/* payload... */
} __attribute__ ((packed));

struct iwl_rt_tx_hdr {
	struct ieee80211_radiotap_header rt_hdr;
	u8 rt_rate;		/* rate in 500kb/s */
	__le16 rt_channel;	/* channel in mHz */
	__le16 rt_chbitmask;	/* channel bitfield */
	s8 rt_dbmsignal;	/* signal in dBm, kluged to signed */
	u8 rt_antenna;		/* antenna number */
	u8 payload[0];		/* payload... */
} __attribute__ ((packed));

/*
 * Generic queue structure
 *
 * Contains common data for Rx and Tx queues
 */
struct iwl_queue {
	int n_bd;              /* number of BDs in this queue */
	int first_empty;       /* 1-st empty entry (index) host_w*/
	int last_used;         /* last used entry (index) host_r*/
	dma_addr_t dma_addr;   /* physical addr for BD's */
	int n_window;	       /* safe queue window */
	u32 id;
	u32 element_size;
	int low_mark;	       /* low watermark, resume queue if free
				* space more than this */
	int high_mark;         /* high watermark, stop queue if free
				* space less than this */
} __attribute__ ((packed));

#define MAX_NUM_OF_TBS          (20)

struct iwl_tx_info {
	struct ieee80211_tx_status status;
	mbuf_t skb[MAX_NUM_OF_TBS];
};

/**
 * struct iwl_tx_queue - Tx Queue for DMA
 * @need_update: need to update read/write index
 * @shed_retry: queue is HT AGG enabled
 *
 * Queue consists of circular buffer of BD's and required locking structures.
 */
struct iwl_tx_queue {
	struct iwl_queue q;
	struct iwl_tfd_frame *bd;
	struct iwl_cmd *cmd;
	dma_addr_t dma_addr_cmd;
	struct iwl_tx_info *txb;
	int need_update;
	int sched_retry;
	int active;
};

#include "iwl-channel.h"

#if IWL == 3945
#include "iwl-3945-rs.h"
#else
#include "iwl-4965-rs.h"
#endif

#define IWL_TX_QUEUE_AC0	0
#define IWL_TX_QUEUE_AC1	1
#define IWL_TX_QUEUE_AC2	2
#define IWL_TX_QUEUE_AC3	3
#define IWL_TX_QUEUE_HCCA_1	5
#define IWL_TX_QUEUE_HCCA_2	6
#define IWL_TX_QUEUE_NONE	7
#define IWL_MAX_NUM_QUEUES   16

/* Power management (not Tx power) structures */

struct iwl_power_vec_entry {
	struct iwl_powertable_cmd cmd;
	u8 no_dtim;
};
#define IWL_POWER_RANGE_0  (0)
#define IWL_POWER_RANGE_1  (1)

#define IWL_POWER_MODE_CAM	0x00	/* Continuously Aware Mode, always on */
#define IWL_POWER_INDEX_3	0x03
#define IWL_POWER_INDEX_5	0x05
#define IWL_POWER_AC		0x06
#define IWL_POWER_BATTERY	0x07
#define IWL_POWER_LIMIT		0x07
#define IWL_POWER_MASK		0x0F
#define IWL_POWER_ENABLED	0x10
#define IWL_POWER_LEVEL(x)	((x) & IWL_POWER_MASK)

struct iwl_power_mgr {
	void* lock;
	struct iwl_power_vec_entry pwr_range_0[IWL_POWER_AC];
	struct iwl_power_vec_entry pwr_range_1[IWL_POWER_AC];
	u8 active_index;
	u32 dtim_val;
};

#define IEEE80211_DATA_LEN              2304
#define IEEE80211_4ADDR_LEN             30
#define IEEE80211_HLEN                  (IEEE80211_4ADDR_LEN)
#define IEEE80211_FRAME_LEN             (IEEE80211_DATA_LEN + IEEE80211_HLEN)

struct iwl_frame {
	union {
		struct ieee80211_hdr frame;
		struct iwl_tx_beacon_cmd beacon;
		u8 raw[IEEE80211_FRAME_LEN];
		u8 cmd[360];
	} u;
	struct list_head list;
};

#define SEQ_TO_QUEUE(x)  ((x >> 8) & 0xbf)
#define QUEUE_TO_SEQ(x)  ((x & 0xbf) << 8)
#define SEQ_TO_INDEX(x) (x & 0xff)
#define INDEX_TO_SEQ(x) (x & 0xff)
#define SEQ_HUGE_FRAME  (0x4000)
#define SEQ_RX_FRAME    (0x8000)
#define SEQ_TO_SN(seq) (((seq) & IEEE80211_SCTL_SEQ) >> 4)
#define SN_TO_SEQ(ssn) (((ssn) << 4 ) & IEEE80211_SCTL_SEQ)

enum {
	/* CMD_SIZE_NORMAL = 0, */
	CMD_SIZE_HUGE = (1 << 0),
	/* CMD_SYNC = 0, */
	CMD_ASYNC = (1 << 1),
	/* CMD_NO_SKB = 0, */
	CMD_WANT_SKB = (1 << 2),
	/* CMD_LOCK = 0, */
	CMD_NO_LOCK = (1 << 4),
};

struct iwl_cmd;
struct iwl_priv;

#define CMD_VAR_MAGIC 0xA987

struct iwl_cmd_meta {
	struct iwl_cmd_meta *source;
	union {
		mbuf_t skb;
		int (*callback)(struct iwl_priv * priv,
				struct iwl_cmd * cmd, mbuf_t  skb);
	} __attribute__ ((packed)) u;

	u16 len;

	/* The CMD_SIZE_HUGE flag bit indicates that the command
	 * structure is stored at the end of the shared queue memory. */
	u8 flags;

	u8 token;
	u16 magic;
} __attribute__ ((packed));

struct iwl_cmd {
	struct iwl_cmd_meta meta;
	struct iwl_cmd_header hdr;
	union {
		struct iwl_addsta_cmd addsta;
		struct iwl_led_cmd led;
		u32 flags;
		u8 val8;
		u16 val16;
		u32 val32;
		struct iwl_bt_cmd bt;
		struct iwl_rxon_time_cmd rxon_time;
		struct iwl_powertable_cmd powertable;
		struct iwl_qosparam_cmd qosparam;
		struct iwl_tx_cmd tx;
		struct iwl_key_cmd key;
		struct iwl_tx_beacon_cmd tx_beacon;
		struct iwl_rxon_assoc_cmd rxon_assoc;
		struct iwl_rate_scaling_cmd rate_scale;
		u8 *indirect;
		u8 payload[360];
	} __attribute__ ((packed)) cmd;
} __attribute__ ((packed));

struct iwl_host_cmd {
	u8 id;
	u16 len;
	struct iwl_cmd_meta meta;
	const void *data;
};

#define TFD_MAX_PAYLOAD_SIZE (sizeof(struct iwl_cmd) - \
			      sizeof(struct iwl_cmd_meta))

/*
 * RX related structures and functions
 */

#if IWL == 3945
#define RX_SPACE_HIGH_MARK	52
#else
#define RX_SPACE_HIGH_MARK	210
#endif

#define SUP_RATE_11A_MAX_NUM_CHANNELS  8
#define SUP_RATE_11B_MAX_NUM_CHANNELS  4
#define SUP_RATE_11G_MAX_NUM_CHANNELS  12

/**
 * struct iwl_rx_queue - Rx queue
 * @processed: Internal index to last handled Rx packet
 * @read: Shared index to newest available Rx buffer
 * @write: Shared index to oldest written Rx packet
 * @free_count: Number of pre-allocated buffers in rx_free
 * @rx_free: list of free SKBs for use
 * @rx_used: List of Rx buffers with no SKB
 * @need_update: flag to indicate we need to update read/write index
 *
 * NOTE:  rx_free and rx_used are used as a FIFO for iwl_rx_mem_buffers
 */
struct iwl_rx_queue {
	__le32 *bd;
	dma_addr_t dma_addr;
	struct iwl_rx_mem_buffer pool[RX_QUEUE_SIZE + RX_FREE_BUFFERS];
	struct iwl_rx_mem_buffer *queue[RX_QUEUE_SIZE];
	u32 processed;
	u32 read;
	u32 write;
	u32 free_count;
	struct list_head rx_free;
	struct list_head rx_used;
	int need_update;
	void* lock;
};

#define IWL_SUPPORTED_RATES_IE_LEN         8

#define SCAN_INTERVAL 100

#define MAX_A_CHANNELS  252
#define MIN_A_CHANNELS  7

#define MAX_B_CHANNELS  14
#define MIN_B_CHANNELS  1

#define STATUS_HCMD_ACTIVE      (1<<0)	/* host command in progress */

#define STATUS_INT_ENABLED      (1<<1)
#define STATUS_RF_KILL_HW       (1<<2)
#define STATUS_RF_KILL_SW       (1<<3)
#define STATUS_RF_KILL_MASK     (STATUS_RF_KILL_HW | STATUS_RF_KILL_SW)

#define STATUS_INIT             (1<<4)
#define STATUS_ALIVE            (1<<5)
#define STATUS_READY            (1<<6)
#define STATUS_TEMPERATURE      (1<<7)
#define STATUS_GEO_CONFIGURED   (1<<8)
#define STATUS_EXIT_PENDING     (1<<9)
#define STATUS_IN_SUSPEND       (1<<10)
#define STATUS_STATISTICS       (1<<11)

#define STATUS_AUTH             (1<<13)

#define STATUS_DISASSOCIATING   (1<<15)

#define STATUS_ROAMING           (1<<16)
#define STATUS_SCANNING          (1<<17)
#define STATUS_SCAN_ABORTING     (1<<19)
#define STATUS_SCAN_PENDING      (1<<20)
#define STATUS_SCAN_HW           (1<<21)

#define STATUS_POWER_PMI        (1<<24)
#define STATUS_RESTRICTED       (1<<26)
#define STATUS_FW_ERROR         (1<<27)

#define STATUS_TX_MEASURE       (1<<28)

/*todoG need to support adding adhoc station MAX_STATION should be 25 */
#define IWL_INVALID_STATION     (0xff)

#define MAX_TID_COUNT        9

#define IWL_INVALID_RATE     0xFF
#define IWL_INVALID_VALUE    -1
struct iwl_tid_data {
	u16 seq_number;
#ifdef CONFIG_IWLWIFI_HT_AGG
	s8 txq_id;
	u8 ht_agg_active;
#endif				/* CONFIG_IWLWIFI_HT_AGG */
};

struct iwl_hw_key {
	ieee80211_key_alg alg;
	int keylen;
	u8 key[32];
};

union iwl_ht_rate_supp {
	u16 rates;
	struct {
		u8 siso_rate;
		u8 mimo_rate;
	};
};

#ifdef CONFIG_IWLWIFI_HT
#define CFG_HT_RX_AMPDU_FACTOR_DEF  (0x3)
#define HT_IE_MAX_AMSDU_SIZE_4K     (0)
#define CFG_HT_MPDU_DENSITY_2USEC   (0x5)
#define CFG_HT_MPDU_DENSITY_DEF CFG_HT_MPDU_DENSITY_2USEC

struct sta_ht_info {
	u8 is_ht;
	u16 rx_mimo_ps_mode;
	u16 tx_mimo_ps_mode;
	u8 max_amsdu_size;
	u8 ampdu_factor;
	u8 mpdu_density;
	u8 control_chan;
	u8 operating_mode;
	u8 supported_chan_width;
	u8 extension_chan_offset;
	u8 is_green_field;
	u8 sgf;
	u8 supp_rates[16];
	u8 tx_chan_width;
	u8 chan_width_cap;
};
#endif				/*CONFIG_IWLWIFI_HT */

#define STA_PS_STATUS_WAKE             0
#define STA_PS_STATUS_SLEEP            1

struct iwl_station_entry {
	struct iwl_addsta_cmd sta;
	struct iwl_tid_data tid[MAX_TID_COUNT];
	union {
		struct {
			u8 rate;
			u8 flags;
		} s;
		u16 rate_n_flags;
	} current_rate;
	u8 used;
	u8 ps_status;
	struct iwl_hw_key keyinfo;
};

/* one for each uCode image (inst/data, boot/init/runtime) */
struct fw_image_desc {
	void *v_addr;		/* access by driver */
	dma_addr_t p_addr;	/* access by card's busmaster DMA */
	u32 len;		/* bytes */
};

/* uCode file layout */
struct iwl_ucode {
	__le32 ver;		/* major/minor/subminor */
	__le32 inst_size;		/* bytes of runtime instructions */
	__le32 data_size;		/* bytes of runtime data */
	__le32 init_size;		/* bytes of initialization instructions */
	__le32 init_data_size;	/* bytes of initialization data */
	__le32 boot_size;		/* bytes of bootstrap instructions */
	u8 data[0];		/* data in same order as "size" elements */
};

#define IWL_IBSS_MAC_HASH_SIZE 31

struct iwl_ibss_seq {
	u8 mac[ETH_ALEN];
	u16 seq_num;
	u16 frag_num;
	unsigned long packet_time;
	struct list_head list;
};

struct iwl_driver_hw_info {
	u16 max_queue_number;
	u16 ac_queue_count;
	u32 rx_buffer_size;
	u16 tx_cmd_len;
	u16 max_rxq_size;
	u16 max_rxq_log;
	u32 cck_flag;
	struct iwl_shared *shared_virt;
	dma_addr_t shared_phys;
};


#define STA_FLG_RTS_MIMO_PROT_POS	(17)
#define STA_FLG_RTS_MIMO_PROT_MSK	(1 << STA_FLG_RTS_MIMO_PROT_POS)
#define STA_FLG_AGG_MPDU_8US_POS	(18)
#define STA_FLG_AGG_MPDU_8US_MSK	(1 << STA_FLG_AGG_MPDU_8US_POS)
#define STA_FLG_MAX_AGG_SIZE_POS	(19)
#define STA_FLG_MAX_AGG_SIZE_MSK	(3 << STA_FLG_MAX_AGG_SIZE_POS)
#define STA_FLG_FAT_EN_POS		(21)
#define STA_FLG_FAT_EN_MSK		(1 << STA_FLG_FAT_EN_POS)
#define STA_FLG_MIMO_DIS_POS		(22)
#define STA_FLG_MIMO_DIS_MSK		(1 << STA_FLG_MIMO_DIS_POS)
#define STA_FLG_AGG_MPDU_DENSITY_POS	(23)
#define STA_FLG_AGG_MPDU_DENSITY_MSK	(7 << STA_FLG_AGG_MPDU_DENSITY_POS)
#define HT_SHORT_GI_20MHZ_ONLY          (1 << 0)
#define HT_SHORT_GI_40MHZ_ONLY          (1 << 1)

#include "iwl-4965.h"
#include "iwl-3945.h"
#include "iwl-priv.h"

/* Requires full declaration of iwl_priv before including */
#include "iwl-io.h"

#define IWL_RX_HDR(x) ((struct iwl_rx_frame_hdr *)(\
		       x->u.rx_frame.stats.payload + \
		       x->u.rx_frame.stats.phy_count))
#define IWL_RX_END(x) ((struct iwl_rx_frame_end *)(\
		       IWL_RX_HDR(x)->payload + \
		       le16_to_cpu(IWL_RX_HDR(x)->len)))
#define IWL_RX_STATS(x) (&x->u.rx_frame.stats)
#define IWL_RX_DATA(x) (IWL_RX_HDR(x)->payload)


/******************************************************************************
 *
 * Functions implemented in base.c which are forward declared here
 * for use by iwl-*.c
 *
 *****************************************************************************/
 extern void ieee80211_tx_status(struct ieee80211_hw *hw, mbuf_t skb,
			 struct ieee80211_tx_status *status);
struct iwl_addsta_cmd;
extern int iwl_send_add_station(struct iwl_priv *priv,
				struct iwl_addsta_cmd *sta, u8 flags);
extern const char *iwl_get_tx_fail_reason(u32 status);
extern u8 iwl_add_station(struct iwl_priv *priv, const u8 * bssid,
			  int is_ap, u8 flags);
extern int iwl_is_network_packet(struct iwl_priv *priv,
				 struct ieee80211_hdr *header);
extern int iwl_power_init_handle(struct iwl_priv *priv);
extern int iwl_eeprom_init(struct iwl_priv *priv);
#ifdef CONFIG_IWLWIFI_DEBUG
extern void iwl_report_frame(struct iwl_priv *priv,
			     struct iwl_rx_packet *pkt,
			     struct ieee80211_hdr *header, int group100);
/*#else
static inline void iwl_report_frame(struct iwl_priv *priv,
				    struct iwl_rx_packet *pkt,
				    struct ieee80211_hdr *header,
				    int group100) {}*/
#endif
extern int iwl_tx_queue_update_write_ptr(struct iwl_priv *priv,
					 struct iwl_tx_queue *txq);
extern void iwl_handle_data_packet_monitor(struct iwl_priv *priv,
					   struct iwl_rx_mem_buffer *rxb,
					   void *data, short len,
					   struct ieee80211_rx_status *stats,
					   u16 phy_flags);
extern int is_duplicate_packet(struct iwl_priv *priv, struct ieee80211_hdr
			       *header);
extern void iwl_rx_queue_free(struct iwl_priv *priv, struct iwl_rx_queue *rxq);
extern int iwl_rx_queue_alloc(struct iwl_priv *priv);
extern void iwl_rx_queue_reset(struct iwl_priv *priv,
			       struct iwl_rx_queue *rxq);
extern int iwl_calc_db_from_ratio(int sig_ratio);
extern int iwl_calc_sig_qual(int rssi_dbm, int noise_dbm);
extern int iwl_tx_queue_init(struct iwl_priv *priv,
			     struct iwl_tx_queue *txq, int count, u32 id);
extern int iwl_rx_queue_restock(struct iwl_priv *priv);
extern void iwl_rx_replenish(void *data, u8 do_lock);
extern void iwl_tx_queue_free(struct iwl_priv *priv, struct iwl_tx_queue *txq);
extern int iwl_send_cmd_pdu(struct iwl_priv *priv, u8 id, u16 len,
			    const void *data);
extern int iwl_send_cmd(struct iwl_priv *priv, struct iwl_host_cmd *cmd);
extern int iwl_fill_beacon_frame(struct iwl_priv *priv,
				 struct ieee80211_hdr *hdr, const u8 * dest,
				 int left);
extern int iwl_rx_queue_update_write_ptr(struct iwl_priv *priv,
					 struct iwl_rx_queue *q);
extern int iwl_send_statistics_request(struct iwl_priv *priv);
extern void iwl_set_decrypted_flag(struct iwl_priv *priv, mbuf_t skb,
				   u32 decrypt_res,
				   struct ieee80211_rx_status *stats);

extern const u8 BROADCAST_ADDR[ETH_ALEN];

/*
 * Currently used by ipw-3945-rs... look at restructuring so that it doesn't
 * call this... todo... fix that.
*/
extern u8 iwl_sync_station(struct iwl_priv *priv, int sta_id,
			   u16 tx_rate, u8 flags);

static inline int iwl_is_associated(struct iwl_priv *priv)
{
	return (priv->active_rxon.filter_flags & RXON_FILTER_ASSOC_MSK) ?
		1 : 0;
}
extern void iwl_down(struct iwl_priv *priv);
extern int iwl_up(struct iwl_priv *priv);
extern void iwl_isr(struct iwl_priv *priv);
extern void iwl_resume(struct iwl_priv *priv);
extern void iwl_cancel_deferred_work(struct iwl_priv *priv);


/******************************************************************************
 *
 * Functions implemented in iwl-*.c which are forward declared here
 * for use by base.c
 *
 * NOTE:  The implementation of these functions are hardware specific
 * which is why they are in the hardware specific files (vs. base.c)
 *
 * Naming convention --
 * iwl_         <-- Its part of iwlwifi (should be changed to iwl_)
 * iwl_hw_      <-- Hardware specific (implemented in iwl-XXXX.c by all HW)
 * iwlXXXX_     <-- Hardware specific (implemented in iwl-XXXX.c for XXXX)
 * iwl_bg_      <-- Called from work queue context
 * d_           <-- mac80211 callback
 *
 ****************************************************************************/
extern void iwl_hw_rx_handler_setup(struct iwl_priv *priv);
extern void iwl_hw_setup_deferred_work(struct iwl_priv *priv);
extern void iwl_hw_cancel_deferred_work(struct iwl_priv *priv);
extern int iwl_hw_rxq_stop(struct iwl_priv *priv);
extern int iwl_hw_set_hw_setting(struct iwl_priv *priv);
extern int iwl_hw_nic_init(struct iwl_priv *priv);
extern void iwl_hw_card_show_info(struct iwl_priv *priv);
extern int iwl_hw_nic_stop_master(struct iwl_priv *priv);
extern void iwl_hw_txq_ctx_free(struct iwl_priv *priv);
extern void iwl_hw_txq_ctx_stop(struct iwl_priv *priv);
extern int iwl_hw_nic_reset(struct iwl_priv *priv);
extern int iwl_hw_tx_queue_attach_buffer_to_tfd(
	struct iwl_priv *priv, void *tfd, dma_addr_t addr, u16 len);
extern int iwl_hw_tx_queue_free_tfd(struct iwl_priv *priv,
				    struct iwl_tx_queue *txq);
extern int iwl_hw_get_temperature(struct iwl_priv *priv);
extern int iwl_tx_queue_free_tfd(struct iwl_priv *priv,
				 struct iwl_tx_queue *txq);
extern int iwl_hw_tx_queue_init(struct iwl_priv *priv,
				struct iwl_tx_queue *txq);
extern int iwl_hw_get_beacon_cmd(struct iwl_priv *priv,
				 struct iwl_frame *frame, u16 rate);
extern int iwl_hw_get_rx_read(struct iwl_priv *priv);
extern void iwl_hw_build_tx_cmd_rate(struct iwl_priv *priv,
				     struct iwl_cmd *cmd,
				     struct ieee80211_tx_control *ctrl,
				     struct ieee80211_hdr *hdr,
				     int sta_id, int tx_id);
extern int iwl_hw_reg_send_txpower(struct iwl_priv *priv);
extern int iwl_hw_reg_set_txpower(struct iwl_priv *priv, s8 power);
extern void iwl_hw_rx_statistics(struct iwl_priv *priv,
				 struct iwl_rx_mem_buffer *rxb);
extern void iwl_disable_events(struct iwl_priv *priv);
extern int iwl4965_get_temperature(const struct iwl_priv *priv);

/**
 * iwl_hw_find_station - Find station id for a given BSSID
 * @bssid: MAC address of station ID to find
 *
 * NOTE:  This should not be hardware specific but the code has
 * not yet been merged into a single common layer for managing the
 * station tables.
 */
extern u8 iwl_hw_find_station(struct iwl_priv *priv, const u8 * bssid);


#endif
