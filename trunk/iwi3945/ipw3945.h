#ifndef __ipw3945_h__
#define __ipw3945_h__

#include "defines.h"

#define DRV_NAME	"ipw3945"
#define LINUX_VERSION_CODE 0
#define KERNEL_VERSION 0
#define KERN_ERR
typedef signed int	s32;


//#include "ipw3945_daemon.h"

/* Kernel compatibility defines */
#ifndef IRQ_NONE
typedef void irqreturn_t;
#define IRQ_NONE
#define IRQ_HANDLED
#endif

/* Debug and printf string expansion helpers for printing bitfields */
#define BIT_FMT8 "%c%c%c%c-%c%c%c%c"
#define BIT_FMT16 BIT_FMT8 ":" BIT_FMT8
#define BIT_FMT32 BIT_FMT16 " " BIT_FMT16

#define BITC(x,y) (((x>>y)&1)?'1':'0')
#define BIT_ARG8(x) \
BITC(x,7),BITC(x,6),BITC(x,5),BITC(x,4),\
BITC(x,3),BITC(x,2),BITC(x,1),BITC(x,0)

#define BIT_ARG16(x) \
BITC(x,15),BITC(x,14),BITC(x,13),BITC(x,12),\
BITC(x,11),BITC(x,10),BITC(x,9),BITC(x,8),\
BIT_ARG8(x)

#define BIT_ARG32(x) \
BITC(x,31),BITC(x,30),BITC(x,29),BITC(x,28),\
BITC(x,27),BITC(x,26),BITC(x,25),BITC(x,24),\
BITC(x,23),BITC(x,22),BITC(x,21),BITC(x,20),\
BITC(x,19),BITC(x,18),BITC(x,17),BITC(x,16),\
BIT_ARG16(x)

#ifdef CONFIG_IPW3945_DEBUG
#define IPW_DEBUG(level, fmt, args...) \
do { if (ipw_debug_level & (level)) \
  printk(KERN_ERR DRV_NAME": %c %s " fmt, \
         in_interrupt() ? 'I' : 'U', __FUNCTION__ , ## args); } while (0)
#else
#define IPW_DEBUG(level, fmt, args...) do {} while (0)
#endif				/* CONFIG_IPW3945_DEBUG */

/*
 * To use the debug system;
 *
 * If you are defining a new debug classification, simply add it to the #define
 * list here in the form of:
 *
 * #define IPW_DL_xxxx VALUE
 *
 * shifting value to the left one bit from the previous entry.  xxxx should be
 * the name of the classification (for example, WEP)
 *
 * You then need to either add a IPW_xxxx_DEBUG() macro definition for your
 * classification, or use IPW_DEBUG(IPW_DL_xxxx, ...) whenever you want
 * to send output to that classification.
 *
 * To add your debug level to the list of levels seen when you perform
 *
 * % cat /proc/net/ipw/debug_level
 *
 * you simply need to add your entry to the ipw_debug_levels array.
 *
 * If you do not see debug_level in /proc/net/ipw then you do not have
 * CONFIG_IPW3945_DEBUG defined in your kernel configuration
 *
 */

#define IPW_DL_INFO          (1<<2)
#define IPW_DL_WX            (1<<3)
#define IPW_DL_HOST_COMMAND  (1<<5)
#define IPW_DL_STATE         (1<<6)

#define IPW_DL_RADIO         (1<<7)
#define IPW_DL_POWER         (1<<8)

#define IPW_DL_NOTIF         (1<<10)
#define IPW_DL_SCAN          (1<<11)
#define IPW_DL_ASSOC         (1<<12)
#define IPW_DL_DROP          (1<<13)

#define IPW_DL_DAEMON        (1<<15)

#define IPW_DL_FW            (1<<16)
#define IPW_DL_RF_KILL       (1<<17)
#define IPW_DL_FW_ERRORS     (1<<18)

#define IPW_DL_LED           (1<<19)

#define IPW_DL_RATE          (1<<20)

#define IPW_DL_FRAG          (1<<21)
#define IPW_DL_WEP           (1<<22)
#define IPW_DL_TX            (1<<23)
#define IPW_DL_RX            (1<<24)
#define IPW_DL_ISR           (1<<25)
#define IPW_DL_IO            (1<<27)
#define IPW_DL_11H           (1<<28)

#define IPW_DL_STATS         (1<<29)
#define IPW_DL_MERGE         (1<<30)
#define IPW_DL_QOS           (1<<31)

#define IPW_ERROR(f, a...) printk(KERN_ERR DRV_NAME ": " f, ## a)
#define IPW_WARNING(f, a...) printk(KERN_ERR DRV_NAME ": " f, ## a)
#define IPW_DEBUG_INFO(f, a...)    IPW_DEBUG(IPW_DL_INFO, f, ## a)

#define IPW_DEBUG_WX(f, a...)     IPW_DEBUG(IPW_DL_WX, f, ## a)
#define IPW_DEBUG_SCAN(f, a...)   IPW_DEBUG(IPW_DL_SCAN, f, ## a)
#define IPW_DEBUG_RX(f, a...)     IPW_DEBUG(IPW_DL_RX, f, ## a)
#define IPW_DEBUG_TX(f, a...)     IPW_DEBUG(IPW_DL_TX, f, ## a)
#define IPW_DEBUG_ISR(f, a...)    IPW_DEBUG(IPW_DL_ISR, f, ## a)
#define IPW_DEBUG_DAEMON(f, a...) IPW_DEBUG(IPW_DL_DAEMON, f, ## a)
#define IPW_DEBUG_LED(f, a...) IPW_DEBUG(IPW_DL_LED, f, ## a)
#define IPW_DEBUG_WEP(f, a...)    IPW_DEBUG(IPW_DL_WEP, f, ## a)
#define IPW_DEBUG_HC(f, a...) IPW_DEBUG(IPW_DL_HOST_COMMAND, f, ## a)
#define IPW_DEBUG_FRAG(f, a...) IPW_DEBUG(IPW_DL_FRAG, f, ## a)
#define IPW_DEBUG_FW(f, a...) IPW_DEBUG(IPW_DL_FW, f, ## a)
#define IPW_DEBUG_RF_KILL(f, a...) IPW_DEBUG(IPW_DL_RF_KILL, f, ## a)
#define IPW_DEBUG_DROP(f, a...) IPW_DEBUG(IPW_DL_DROP, f, ## a)
#define IPW_DEBUG_IO(f, a...) IPW_DEBUG(IPW_DL_IO, f, ## a)
#define IPW_DEBUG_RATE(f, a...) IPW_DEBUG(IPW_DL_RATE, f, ## a)
#define IPW_DEBUG_NOTIF(f, a...) IPW_DEBUG(IPW_DL_NOTIF, f, ## a)
#define IPW_DEBUG_ASSOC(f, a...) IPW_DEBUG(IPW_DL_ASSOC | IPW_DL_INFO, f, ## a)
#define IPW_DEBUG_STATS(f, a...) IPW_DEBUG(IPW_DL_STATS, f, ## a)
#define IPW_DEBUG_MERGE(f, a...) IPW_DEBUG(IPW_DL_MERGE, f, ## a)
#define IPW_DEBUG_QOS(f, a...)   IPW_DEBUG(IPW_DL_QOS, f, ## a)
#define IPW_DEBUG_RADIO(f, a...)  IPW_DEBUG(IPW_DL_RADIO, f, ## a)
#define IPW_DEBUG_POWER(f, a...)  IPW_DEBUG(IPW_DL_POWER, f, ## a)
#define IPW_DEBUG_11H(f, a...)  IPW_DEBUG(IPW_DL_11H, f, ## a)

/* Amount of time after sending an association request to wait before we send
 * the next request frame. */
#define IPW_ASSOC_STATE_TIMEOUT 100

/* Number of association sequence request frames to send before we bail */
#define IPW_MAX_ASSOC_RETRY 7

/* microcode and hardware interface definitions */

/*
 *  Time constants
 */
#define SHORT_SLOT_TIME 9
#define LONG_SLOT_TIME 20

#define OFDM_SYMBOL_TIME 4

/*
 * Driver API command-id
 */
#define REPLY_ALIVE    0x1
#define REPLY_ERROR    0x2

/* RXON state commands */
#define REPLY_RX_ON_ASSOC  0x11
#define REPLY_QOS_PARAM    0x13
#define REPLY_RX_ON_TIMING 0x14

/* Multi-Station support */
#define REPLY_ADD_STA       0x18

/* RX, TX */
#define REPLY_RX        0x1b
#define REPLY_TX        0x1c

/* MISC commands */
#define REPLY_DAEMON_1  0x22
#define REPLY_DAEMON_2   0x23
#define REPLY_DAEMON_3   0x24
#define REPLY_DAEMON_4   0x80
#define REPLY_RATE_SCALE  0x47
#define REPLY_LEDS_CMD    0x48

/* timers commands */
#define REPLY_BCON   0x27	//  off

/* measurements ****/
#define RADAR_NOTIFICATION              0x70
#define CHANNEL_SWITCH_NOTIFICATION     0x73

#define SPECTRUM_MEASURE_NOTIFICATION   0x75

/* Power Management ****/
#define POWER_TABLE_CMD                 0x77
#define PM_SLEEP_NOTIFICATION           0x7A
#define PM_DEBUG_STATISTIC_NOTIFIC      0x7B

/* Scan commands and notifications ****/
#define REPLY_SCAN_ABORT_CMD        0x81
#define SCAN_REQUEST_NOTIFICATION   0x80
#define SCAN_START_NOTIFICATION     0x82
#define SCAN_RESULTS_NOTIFICATION   0x83
#define SCAN_COMPLETE_NOTIFICATION  0x84

/* IBSS/AP commands ****/
#define BEACON_NOTIFICATION             0x90
#define REPLY_TX_BEACON                 0x91
#define WHO_IS_AWAKE_NOTIFICATION       0x94

#define QUIET_NOTIFICATION              0x96
#define MEASURE_ABORT_NOTIFICATION      0x99

//bt config command
#define REPLY_BT_CONFIG                 0x9b
#define REPLY_STATISTICS_CMD            0x9c
#define STATISTICS_NOTIFICATION         0x9d
/* RF-KILL commands and notifications ****/
#define REPLY_CARD_STATE_CMD            0xa0
#define CARD_STATE_NOTIFICATION         0xa1

/* Missed beacons notification ****/
#define MISSED_BEACONS_NOTIFICATION     0xa2
#define MISSED_BEACONS_NOTIFICATION_TH_CMD 0xa3

union tsf {
	u8 byte[8];		//7:0
	u16 word[4];		//7:6,5:4,3:2,1:0
	u32 dw[2];		//7:4,3:0
};

/*
 * Alive Command & Response
 */

#define UCODE_VALID_OK      (0x1)

struct ipw_alive_resp {
	u8 ucode_minor;
	u8 ucode_major;
	u16 reserved1;
	u8 sw_rev[8];
	u8 ver_type;
	u8 ver_subtype;
	u16 reserved2;
	u32 log_event_table_ptr;
	u32 error_event_table_ptr;
	u32 timestamp;
	u32 is_valid;
} __attribute__ ((packed));

/*
 * Error Command & Response
 */

struct ipw_error_resp {
	u32 enumErrorType;	//7:4
	u8 currentCmdID;	//8
	u8 reserved;		//9
	u16 erroneousCmdSeqNum;	//11:10
	u32 errorService;	//15:12
	union tsf timestamp;	//all TSF  //23:16
} __attribute__ ((packed));

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
 * RXON-ASSOCIATED Command & Response
 */
struct ipw_rxon_assoc_cmd {
	u32 flags;		// 7:4
	u32 filter_flags;	// 11:8
	u8 ofdm_basic_rates;	// 12
	u8 cck_basic_rates;	// 13
	u16 reserved;		// 15:14
} __attribute__ ((packed));

/*
 * RXON-Timings Command & Response
 */
struct ipw_rxon_time_cmd {
	union tsf timestamp;	// all TSF  //11:4
	u16 beaconInterval;	//13:12
	u16 atimWindow;		//15:14
	u32 beaconTimerInitVal;	//19:16
	u16 listenInterval;	//21:20
	u16 reserved;		//23:22
} __attribute__ ((packed));

/*
 * beacon QOS parameters Command & Response
 */
struct ipw_ac_qos {
	u16 dot11CWmin;		// 9+(8*(N-1)):8+(8*(N-1))
	u16 dot11CWmax;		// 11+(8*(N-1)):10+(8*(N-1))
	u8 dot11AIFSN;		// 12+(8*(N-1))
	u8 reserved1;		// 13+(8*(N-1))
	u16 edca_txop;		// 15+(8*(N-1)):14+(8*(N-1))
} __attribute__ ((packed));

/*
 *  TXFIFO Queue number defines
 */
/* number of Access catergories (AC) (EDCA), queues 0..3 */
#define AC_NUM                4
/* total number of queues */
#define QUEUE_NUM             7
/* command queue number */
#define CMD_QUEUE_NUM         4

struct ipw_qosparam_cmd {
	u32 qos_flags;		// 7:4
	struct ipw_ac_qos ac[AC_NUM];	// 39:8
} __attribute__ ((packed));

/*
 * Multi station support
 */
#define NUM_OF_STATIONS 25
#define AP_ID           0
#define MULTICAST_ID    1
#define STA_ID          2
#define BROADCAST_ID    24

#define STA_CONTROL_MODIFY_MSK             0x01

/*
 * Add/Modify Station Command & Response
 */
struct ipw_keyinfo {
	u16 key_flags;
	u8 tkip_rx_tsc_byte2;	//byte  2 TSC[2] for key mix ph1 detection
	u8 reserved1;		//byte  3
	u16 tkip_rx_ttak[5];	//byte 13:4 10-byte unicast TKIP TTAK
	u16 reserved2;		//byte 15:14
	u8 key[16];		//byte 32:16 16-byte unicast decryption key
} __attribute__ ((packed));

struct sta_id_modify {
	u8 MACAddr[ETH_ALEN];
	u16 reserved1;
	u8 staID;
	u8 modify_mask;
	u16 reserved2;
} __attribute__ ((packed));

struct ipw_addsta_cmd {
	u8 ctrlAddModify;	// byte  4
	u8 reserved[3];		// bytes 7:5
	struct sta_id_modify sta;	// bytes 19:8
	struct ipw_keyinfo key;	//byte 51:20
	u32 station_flags;	//bytes 55:52
	u32 station_flags_msk;	//bytes 59:56
	u16 tid_disable_tx;	//bytes 61:60
	u8 tx_rate;		//byte 62
	u8 reserved_1;		//byte 63
	u8 add_immediate_ba_tid;	//byte 64
	u8 remove_immediate_ba_tid;	//byte 65
	u16 add_immediate_ba_start_seq;	//byte 67:66
} __attribute__ ((packed));

struct ipw_add_sta_resp {
	u8 status;
} __attribute__ ((packed));

#define ADD_STA_SUCCESS_MSK              0x1

/*
 * WEP/CKIP group key command
 */
struct ipw_key {
	u8 index;
	u8 reserved[3];
	u32 size;
	u8 key[16];
} __attribute__ ((packed));

struct ipw_key_cmd {
	u8 count;
	u8 decrypt_type;
	u8 reserved[2];
	struct ipw_key key[4];
} __attribute__ ((packed));

struct ipw_rx_frame_stats {
	u8 mib_count;
	u8 id;
	u8 rssi;
	u8 agc;
	u16 sig_avg;
	u16 noise_diff;
	u8 payload[0];
} __attribute__ ((packed));

struct ipw_rx_frame_hdr {
	u16 channel;		//5:4
	u16 phy_flags;		//7:6
	u8 reserved1;		//macHeaderLength;          //8
	u8 rate;		//9
	u16 len;		//17:16
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
};

struct ipw_rx_frame_end {
	u32 status;		//3+(N+20):0+(N+20)
	u64 timestamp;		//11+(N+20):4+(N+20)
	u32 beaconTimeStamp;
} __attribute__ ((packed));

/* NOTE:  DO NOT dereference from casts to this structure
 * It is provided only for calculating minimum data set size.
 * The actual offsets of the hdr and end are dynamic based on
 * stats.mib_count */
struct ipw_rx_frame {
	struct ipw_rx_frame_stats stats;
	struct ipw_rx_frame_hdr hdr;
	struct ipw_rx_frame_end end;
} __attribute__ ((packed));

/*
 * Tx Command & Response
 */

/* Tx flags */
enum {
	TX_CMD_FLG_RTS_MSK = (1 << 1),
	TX_CMD_FLG_CTS_MSK = (1 << 2),
	TX_CMD_FLG_ACK_MSK = (1 << 3),
	TX_CMD_FLG_FULL_TXOP_PROT_MSK = (1 << 7),
	TX_CMD_FLG_ANT_SEL_MSK = 0xf00,
	TX_CMD_FLG_ANT_A_MSK = (1 << 8),
	TX_CMD_FLG_ANT_B_MSK = (1 << 9),

	/* ucode ignores BT priority for this frame */
	TX_CMD_FLG_BT_DIS_MSK = (1 << 12),

	/* ucode overides sequence control */
	TX_CMD_FLG_SEQ_CTL_MSK = (1 << 13),

	/* signal that this frame is non-last MPDU */
	TX_CMD_FLG_MORE_FRAG_MSK = (1 << 14),

	/* calculate TSF in outgoing frame */
	TX_CMD_FLG_TSF_MSK = (1 << 16),

	/* activate TX calibration. */
	TX_CMD_FLG_CALIB_MSK = (1 << 17),

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

#define MAX_REAL_TX_QUEUE_NUM 5

/* the number of bytes in tx_cmd_s should be 32-bit aligned as to allow
 * fast block transfer */

/*
 * Tx Command & Response:
 */

struct ipw_tx_cmd {
	u16 len;		//byte 5:411500
	u16 next_frame_len;	//byte 7:6
	u32 tx_flags;		//byte 11:8
	u8 rate;		//byte 12
	u8 sta_id;		//byte 13
	u8 tid_tspec;		//byte 14
	u8 sec_ctl;
//      u8 key_index:2,reserved:2,key_size:1,key_type:3;
	u8 key[16];
	union {
		u8 byte[8];	//7:0
		u16 word[4];	//7:6,5:4,3:2,1:0
		u32 dw[2];	//7:4,3:0
	} tkip_mic;		/* byte 39:32 */
	u32 next_frame_info;	//byte 43:40
	union {
		u32 life_time;
		u32 attemp_stop_time;
	} u;
	u8 supp_rates[2];	//byte 49:48
	u8 rts_retry_limit;	//byte 50
	u8 data_retry_limit;	//byte 51
	union {
		u16 pm_frame_timeout;
		u16 attemp_duration;
	} u2;
	u16 driver_txop;	//byte 55:54
	u8 payload[0];
	struct ieee80211_hdr hdr[0];
} __attribute__ ((packed));

/*
 * TX command response status
 */
struct ipw_tx_resp {
	u8 failure_rts;
	u8 failure_frame;
	u8 bt_kill_count;	//6
	u8 rate;		//7
	u32 wireless_media_time;	//11:8
	u32 status;		//15:12
} __attribute__ ((packed));

/*
 * Scan Request Commands , Responses  & Notifications
 */

/* Can abort will notify by complete notification with abort status. */
#define CAN_ABORT_STATUS        0x1

struct ipw_scanreq_notification {
	u32 status;
} __attribute__ ((packed));

struct ipw_scanstart_notification {
	u32 tsf_low;
	u32 tsf_high;
	u32 beacon_timer;
	u8 channel;
	u8 band;
	u8 reserved[2];
	u32 status;
} __attribute__ ((packed));

#define  SCAN_OWNER_STATUS 0x1;
#define  MEASURE_OWNER_STATUS 0x2;

#define NUMBER_OF_STATISTICS 1	// first DW is good CRC
struct ipw_scanresults_notification {
	u8 channel;
	u8 band;
	u8 reserved[2];
	u32 tsf_low;
	u32 tsf_high;
	u32 statistics[NUMBER_OF_STATISTICS];	//TBD
} __attribute__ ((packed));

struct ipw_scancomplete_notification {
	u8 scanned_channels;
	u8 status;
	u8 reserved;
	u8 last_channel;
	u32 tsf_low;
	u32 tsf_high;
} __attribute__ ((packed));

//complete notification statuses
#define ABORT_STATUS            0x2	// Abort status for scan finish notification

// **************************************************
// * Rate Scaling Command & Response
// **************************************************

// *****************************************
// * ofdm & cck rate codes
// *****************************************
#define R_6M 0xd
#define R_9M 0xf
#define R_12M 0x5
#define R_18M 0x7
#define R_24M 0x9
#define R_36M 0xb
#define R_48M 0x1
#define R_54M 0x3

#define R_1M 0xa
#define R_2M 0x14
#define R_5_5M 0x37
#define R_11M 0x6e

// OFDM rates mask values
#define RATE_SCALE_6M_INDEX  0
#define RATE_SCALE_9M_INDEX  1
#define RATE_SCALE_12M_INDEX 2
#define RATE_SCALE_18M_INDEX 3
#define RATE_SCALE_24M_INDEX 4
#define RATE_SCALE_36M_INDEX 5
#define RATE_SCALE_48M_INDEX 6
#define RATE_SCALE_54M_INDEX 7

// CCK rate mask values
#define RATE_SCALE_1M_INDEX   8
#define RATE_SCALE_2M_INDEX   9
#define RATE_SCALE_5_5M_INDEX 10
#define RATE_SCALE_11M_INDEX  11

/*  OFDM rates mask values */
enum {
	R_6M_MSK = (1 << 0),
	R_9M_MSK = (1 << 1),
	R_12M_MSK = (1 << 2),
	R_18M_MSK = (1 << 3),
	R_24M_MSK = (1 << 4),
	R_36M_MSK = (1 << 5),
	R_48M_MSK = (1 << 6),
	R_54M_MSK = (1 << 7),
};

/* CCK rate mask values */
enum {
	R_1M_MSK = (1 << 0),
	R_2M_MSK = (1 << 1),
	R_5_5M_MSK = (1 << 2),
	R_11M_MSK = (1 << 3),
};

#define CCK_RATES  4
#define NUM_RATES  12

struct rate_scaling_info {
	u8 tx_rate;
	u8 flags;
	u8 try_cnt;
	u8 next_rate_index;
} __attribute__ ((packed));

struct RateScalingCmdSpecifics {
	u8 table_id;
	u8 reserved[3];
	struct rate_scaling_info rate_scale_table[NUM_RATES];
} __attribute__ ((packed));

/*
 * LEDs Command & Response
 */
struct ipw_led_cmd {
	u32 interval;		// 4
	u8 id;			// 8
	u8 off;			// 9
	u8 on;			//10
	u8 reserved;		// 11
} __attribute__ ((packed));

/*
 * card_state Command and Notification
 */

#define CARD_STATE_CMD_DISABLE 0x00
#define CARD_STATE_CMD_ENABLE 0x01

struct ipw_card_state_notif {
	u32 flags;
} __attribute__ ((packed));

#define HW_CARD_DISABLED 0x01
#define SW_CARD_DISABLED 0x02

// **************************************************
// * TxBeacon Command & Response
// **************************************************

// Command Notification and Response Headers are Covered by the

// Beacon Notification
struct BeaconNtfSpecifics {
	struct ipw_tx_resp bconNotifHdr;	//15:4
	u32 lowTSF;		//19:16
	u32 highTSF;		//23:20
	u32 ibssMgrStatus;	//27:24
} __attribute__ ((packed));

// TxBeacon Command
struct ipw_tx_beacon_cmd {
	struct ipw_tx_cmd tx;;	//byte 55:4
	u16 tim_idx;		//byte 57:56
	u8 tim_size;		//byte 58
	u8 reserved1;		//byte 59
	struct ieee80211_hdr frame[0];
	// Beacon Frame
} __attribute__ ((packed));

// TxBeacon response

/* Passed to regulatory daemon for parsing */
struct ipw_spectrum_notification {
	u16 reserved1;
	u8 reserved2;
	u8 state;		/* 0 - start, 1 - stop */
	u8 reserved3[96];
} __attribute__ ((packed));

struct ipw_csa_notification {
	u16 band;
	u16 channel;
	u32 status;		// 0 - OK, 1 - fail
} __attribute__ ((packed));

/*
 * Power Table Command & Response
 *
 * FLAGS
 *   PM allow:
 *   bit 0 - '0' Driver not allow power management
 *           '1' Driver allow PM (use rest of parameters)
 *   uCode send sleep notifications:
 *   bit 1 - '0' Don't send sleep notification
 *           '1' send sleep notification (SEND_PM_NOTIFICATION)
 *   Sleep over DTIM
 *   bit 2 - '0' PM have to walk up every DTIM
 *           '1' PM could sleep over DTIM till listen Interval.
 *   force sleep Modes
 *    bit 31/30- '00' use both mac/xtal sleeps
 *               '01' force Mac sleep
 *               '10' force xtal sleep
 *               '11' Illegal set
 * NOTE: if SleepInterval[SLEEP_INTRVL_TABLE_SIZE-1] > DTIM period then
 * ucode assume sleep over DTIM is allowed and we don't need to wakeup
 * for every DTIM.
 */
#define PMC_TCMD_SLEEP_INTRVL_TABLE_SIZE          5

#define PMC_TCMD_FLAG_DRIVER_ALLOW_SLEEP_MSK      0x1
#define PMC_TCMD_FLAG_SLEEP_OVER_DTIM_MSK         0x4

struct ipw_powertable_cmd {
	u32 flags;
	u32 RxDataTimeout;
	u32 TxDataTimeout;
	u32 SleepInterval[PMC_TCMD_SLEEP_INTRVL_TABLE_SIZE];
} __attribute__ ((packed));

struct ipw_sleep_notification {
	u8 pm_sleep_mode;
	u8 pm_wakeup_src;
	u16 reserved;
	u32 sleep_time;
	u32 tsf_low;
	u32 bcon_timer;
} __attribute__ ((packed));

enum {
	IPW_PM_NO_SLEEP = 0,
	IPW_PM_SLP_MAC = 1,
	IPW_PM_SLP_FULL_MAC_UNASSOCIATE = 2,
	IPW_PM_SLP_FULL_MAC_CARD_STATE = 3,
	IPW_PM_SLP_PHY = 4,
	IPW_PM_SLP_REPENT = 5,
	IPW_PM_WAKEUP_BY_TIMER = 6,
	IPW_PM_WAKEUP_BY_DRIVER = 7,
	IPW_PM_WAKEUP_BY_RFKILL = 8,
	/* 3 reserved */
	IPW_PM_NUM_OF_MODES = 12,
};

struct ipw_bt_cmd {
	u8 flags;
	u8 leadTime;
	u8 maxKill;
	u8 reserved;
	u32 killAckMask;
	u32 killCTSMask;
} __attribute__ ((packed));

struct rx_phy_statistics {
	u32 ina_cnt;		/* number of INA signal assertions (enter RX) */
	u32 fina_cnt;		/* number of FINA signal assertions
				 * (false_alarm = INA - FINA) */
	u32 plcp_err;		/* number of bad PLCP header detections
				 * (PLCP_good = FINA - PLCP_bad) */
	u32 crc32_err;		/* number of CRC32 error detections */
	u32 overrun_err;	/* number of Overrun detections (this is due
				 * to RXE sync overrun) */
	u32 early_overrun_err;	/* number of times RX is aborted at the
				 * begining because rxfifo is full behind
				 * threshold */
	u32 crc32_good;		/* number of frames with good CRC */
	u32 false_alarm_cnt;	/* number of times false alarm was
				 * detected (i.e. INA w/o FINA) */
	u32 fina_sync_err_cnt;	/* number of times sync problem between
				 * HW & SW FINA counter was found */
	u32 sfd_timeout;	/* number of times got SFD timeout
				 * (i.e. got FINA w/o rx_frame) */
	u32 fina_timeout;	/* number of times got FINA timeout (i.e. got
				 * INA w/o FINA, w/o false alarm) */
	u32 unresponded_rts;	/* un-responded RTS, due to NAV not zero */
	u32 rxe_frame_limit_overrun;	/* RXE got frame limit overrun */
	u32 sent_ack_cnt;	/* ACK TX count */
	u32 sent_cts_cnt;	/* CTS TX count */
} __attribute__ ((packed));

struct rx_non_phy_statistics {
	u32 bogus_cts;		/* CTS received when not expecting CTS */
	u32 bogus_ack;		/* ACK received when not expecting ACK */
	u32 non_bssid_frames;	/* number of frames with BSSID that doesn't
				 * belong to the STA BSSID */
	u32 filtered_frames;	/* count frames that were dumped in the
				 * filtering process */
} __attribute__ ((packed));

struct rx_statistics {
	struct rx_phy_statistics ofdm;
	struct rx_phy_statistics cck;
	struct rx_non_phy_statistics general;
} __attribute__ ((packed));

struct tx_non_phy_statistics {
	u32 preamble_cnt;	/* number of times preamble was asserted */
	u32 rx_detected_cnt;	/* number of times TX was delayed to RX
				 * detected */
	u32 bt_prio_defer_cnt;	/* number of times TX was deferred due to
				 * BT priority */
	u32 bt_prio_kill_cnt;	/* number of times TX was killed due to BT
				 * priority */
	u32 few_bytes_cnt;	/* number of times TX was delayed due to not
				 * enough bytes in TXFIFO */
	u32 cts_timeout;	/* timeout when waiting for CTS */
	u32 ack_timeout;	/* timeout when waiting for ACK */
	u32 expected_ack_cnt;	/* number of data frames that need ack or
				 * rts that need cts */
	u32 actual_ack_cnt;	/* number of expected ack or cts that were
				 * actually received */
} __attribute__ ((packed));

struct tx_statistics {
	struct tx_non_phy_statistics general;
} __attribute__ ((packed));

struct debug_statistics {
	u32 cont_burst_chk_cnt;	/* number of times continuation or
				 * fragmentation or bursting was checked */
	u32 cont_burst_cnt;	/* number of times continuation or fragmentation
				 * or bursting was successfull */
	u32 reserved[4];
} __attribute__ ((packed));

struct general_statistics {
	u32 temperature;
	struct debug_statistics debug;
	u32 usec_sleep;	  /**< usecs NIC was asleep. Running counter. */
	u32 slots_out;	   /**< slots NIC was out of serving channel */
	u32 slots_idle;	   /**< slots NIC was idle */
} __attribute__ ((packed));

// This struct is used as a reference for the driver.
// uCode is using global variables that are defined in
struct statistics {
	u32 flags;
	struct rx_statistics rx_statistics;
	struct tx_statistics tx_statistics;
	struct general_statistics general_statistics;
} __attribute__ ((packed));

/*********************************************************************
* These defines are for DRIVER use.
* The defines specify the none acomulative entries in the statistics
* If you add a none accomulative statistic entry you shuld add a
* define and contact the drivers team for updating the parsing.
*********************************************************************/
#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field) ((u32)&(((type *)0)->field))
#endif

/********************************************************************
* End of driver use statistics defines.
********************************************************************/

//if ucode consecutively missed  beacons above CONSEQUTIVE_MISSED_BCONS_TH
//then this notification will be sent.
#define CONSEQUTIVE_MISSED_BCONS_TH 20

/* 3945ABG register and values */
/* base */
#define CSR_BASE    (0x0)
#define HBUS_BASE   (0x400)
#define FH_BASE     (0x800)

/*=== CSR ===*/

#define CSR_HW_IF_CONFIG_REG    (CSR_BASE+0x000)
#define CSR_INT                 (CSR_BASE+0x008)
#define CSR_INT_MASK            (CSR_BASE+0x00c)
#define CSR_FH_INT_STATUS       (CSR_BASE+0x010)
#define CSR_GPIO_IN             (CSR_BASE+0x018)
#define CSR_RESET               (CSR_BASE+0x020)
#define CSR_GP_CNTRL            (CSR_BASE+0x024)
/* 0x028 - reserved */
#define CSR_EEPROM_REG          (CSR_BASE+0x02c)
#define CSR_EEPROM_GP           (CSR_BASE+0x030)
#define CSR_UCODE_DRV_GP1       (CSR_BASE+0x054)
#define CSR_UCODE_DRV_GP1_SET   (CSR_BASE+0x058)
#define CSR_UCODE_DRV_GP1_CLR   (CSR_BASE+0x05c)
#define CSR_UCODE_DRV_GP2       (CSR_BASE+0x060)
#define CSR_GIO_CHICKEN_BITS    (CSR_BASE+0x100)
#define CSR_ANA_PLL_CFG         (CSR_BASE+0x20c)

/* BSM */
#define BSM_BASE                        (CSR_BASE + 0x3400)

#define BSM_WR_CTRL_REG                 (BSM_BASE + 0x000)
#define BSM_WR_MEM_SRC_REG              (BSM_BASE + 0x004)
#define BSM_WR_MEM_DST_REG              (BSM_BASE + 0x008)
#define BSM_WR_DWCOUNT_REG              (BSM_BASE + 0x00C)

#define BSM_DRAM_INST_PTR_REG           (BSM_BASE + 0x090)
#define BSM_DRAM_INST_BYTECOUNT_REG     (BSM_BASE + 0x094)
#define BSM_DRAM_DATA_PTR_REG           (BSM_BASE + 0x098)
#define BSM_DRAM_DATA_BYTECOUNT_REG     (BSM_BASE + 0x09C)

#define BSM_SRAM_LOWER_BOUND            (CSR_BASE + 0x3800)

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

/*=== HBUS ===*/

#define HBUS_TARG_MEM_RADDR     (HBUS_BASE+0x00c)
#define HBUS_TARG_MEM_WADDR     (HBUS_BASE+0x010)
#define HBUS_TARG_MEM_RDAT      (HBUS_BASE+0x01c)
#define HBUS_TARG_PRPH_WADDR    (HBUS_BASE+0x044)
#define HBUS_TARG_PRPH_RADDR    (HBUS_BASE+0x048)
#define HBUS_TARG_PRPH_WDAT     (HBUS_BASE+0x04c)
#define HBUS_TARG_PRPH_RDAT     (HBUS_BASE+0x050)
#define HBUS_TARG_WRPTR         (HBUS_BASE+0x060)
/*=== FH ===*/

#define FH_CBCC_TABLE           (FH_BASE+0x140)
#define FH_TFDB_TABLE           (FH_BASE+0x180)
#define FH_RCSR_TABLE           (FH_BASE+0x400)
#define FH_RSSR_TABLE           (FH_BASE+0x4c0)
#define FH_TCSR_TABLE           (FH_BASE+0x500)
#define FH_TSSR_TABLE           (FH_BASE+0x680)

/* TFDB */
#define FH_TFDB(_channel,buf)                    (FH_TFDB_TABLE+((_channel)*2+(buf))*0x28)
#define ALM_FH_TFDB_CHNL_BUF_CTRL_REG(_channel)  (FH_TFDB_TABLE + 0x50 * _channel)
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

/*        card memory */
#define RTC_INST_LOWER_BOUND                                (0x00000)
#define ALM_RTC_INST_UPPER_BOUND                            (0x14000)

#define RTC_DATA_LOWER_BOUND                                (0x800000)
#define ALM_RTC_DATA_UPPER_BOUND                            (0x808000)

#define ALM_RTC_INST_SIZE           (ALM_RTC_INST_UPPER_BOUND - RTC_INST_LOWER_BOUND)
#define ALM_RTC_DATA_SIZE           (ALM_RTC_DATA_UPPER_BOUND - RTC_DATA_LOWER_BOUND)

#define VALID_RTC_DATA_ADDR(addr)               \
    ( ((addr) >= RTC_DATA_LOWER_BOUND) && ((addr) < ALM_RTC_DATA_UPPER_BOUND) )

/*=== Periphery ===*/

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

#define CSR_GPIO_IN_BIT_AUX_POWER                   (0x00000200)
#define CSR_GPIO_IN_VAL_VAUX_PWR_SRC                (0x00000000)
#define CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX  (0x00800000)
#define CSR_GPIO_IN_VAL_VMAIN_PWR_SRC               CSR_GPIO_IN_BIT_AUX_POWER

#define PCI_CFG_PMC_PME_FROM_D3COLD_SUPPORT         (0x80000000)
/*   interrupt flags */
#define BIT_INT_RX           (1<<31)
#define BIT_INT_SWERROR      (1<<25)
#define BIT_INT_ERR          (1<<29)
#define BIT_INT_TX           (1<<27)
#define BIT_INT_WAKEUP       (1<< 1)
#define BIT_INT_ALIVE        (1<<0)

#define CSR_INI_SET_MASK      ( BIT_INT_RX      |  \
                                BIT_INT_SWERROR |  \
                                BIT_INT_ERR     |  \
                                BIT_INT_TX      |  \
                                BIT_INT_ALIVE   |  \
                                BIT_INT_WAKEUP )

/* RESET */
#define CSR_RESET_REG_FLAG_NEVO_RESET                (0x00000001)
#define CSR_RESET_REG_FLAG_FORCE_NMI                 (0x00000002)
#define CSR_RESET_REG_FLAG_SW_RESET                  (0x00000080)
#define CSR_RESET_REG_FLAG_MASTER_DISABLED           (0x00000100)
#define CSR_RESET_REG_FLAG_STOP_MASTER               (0x00000200)

/* GP CONTROL */
#define CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY        (0x00000001)
#define CSR_GP_CNTRL_REG_FLAG_INIT_DONE              (0x00000004)
#define CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ         (0x00000008)
#define CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP         (0x00000010)

#define CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN          (0x00000001)

#define CSR_GP_CNTRL_REG_MSK_POWER_SAVE_TYPE        (0x07000000)
#define CSR_GP_CNTRL_REG_FLAG_MAC_POWER_SAVE         (0x04000000)

/* APMG constants */
#define APMG_CLK_CTRL_REG                        (0x003000)
#define ALM_APMG_CLK_EN                          (0x003004)
#define ALM_APMG_CLK_DIS                         (0x003008)
#define ALM_APMG_PS_CTL                          (0x00300c)
#define ALM_APMG_PCIDEV_STT                      (0x003010)
#define ALM_APMG_LARC_INT                        (0x00301c)
#define ALM_APMG_LARC_INT_MSK                    (0x003020)

#define APMG_CLK_REG_VAL_DMA_CLK_RQT                (0x00000200)
#define APMG_CLK_REG_VAL_BSM_CLK_RQT                (0x00000800)

#define APMG_PS_CTRL_REG_VAL_ALM_R_RESET_REQ        (0x04000000)

#define APMG_DEV_STATE_REG_VAL_L1_ACTIVE_DISABLE    (0x00000800)

#define APMG_PS_CTRL_REG_MSK_POWER_SRC              (0x03000000)
#define APMG_PS_CTRL_REG_VAL_POWER_SRC_VMAIN        (0x00000000)
#define APMG_PS_CTRL_REG_VAL_POWER_SRC_VAUX         (0x01000000)
/* BSM */
#define BSM_WR_CTRL_REG_BIT_START_EN                (0x40000000)

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

#define ALM_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_channel)         ((1LU << _channel) << 24)
#define ALM_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_channel)        ((1LU << _channel) << 16)

#define ALM_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(_channel)          (ALM_FH_TSSR_TX_STATUS_REG_BIT_BUFS_EMPTY(_channel) | \
                                                                 ALM_FH_TSSR_TX_STATUS_REG_BIT_NO_PEND_REQ(_channel))
#define PCI_CFG_REV_ID_BIT_BASIC_SKU                (0x40)	/* bit 6    */
#define PCI_CFG_REV_ID_BIT_RTP                      (0x80)	/* bit 7    */

#define TFD_QUEUE_MIN           0
#define TFD_QUEUE_MAX           6
#define TFD_QUEUE_SIZE_MAX      (256)

/* Eeprom */

#define MSB                             1
#define LSB                             0
#define WORD_TO_BYTE(_word)             ((_word) * sizeof(u16))

#define EEPROM_ADDR(_wordoffset,_byteoffset)    \
    ( WORD_TO_BYTE(_wordoffset) + (_byteoffset) )

/* EEPROM access by BYTE */

/* General */
#define EEPROM_MAC_ADDRESS                  (EEPROM_ADDR(0x15,LSB))	/* 6  bytes */

#define EEPROM_BOARD_REVISION               (EEPROM_ADDR(0x35,LSB))	/* 2  bytes */
#define EEPROM_BOARD_PBA_NUMBER             (EEPROM_ADDR(0x3B,MSB))	/* 9  bytes */
#define EEPROM_SKU_CAP                      (EEPROM_ADDR(0x45,LSB))	/* 1  bytes */
#define EEPROM_LEDS_MODE                    (EEPROM_ADDR(0x45,MSB))	/* 1  bytes */
#define EEPROM_ALMGOR_M_VERSION             (EEPROM_ADDR(0x4A,LSB))	/* 1  bytes */
#define EEPROM_ANTENNA_SWITCH_TYPE          (EEPROM_ADDR(0x4A,MSB))	/* 1  bytes */

/* LED definitions */
#define EEPROM_LEDS_TIME_INTERVAL           (EEPROM_ADDR(0x48,LSB))	/* 2  bytes */
#define EEPROM_LEDS_ON_TIME                 (EEPROM_ADDR(0x49,MSB))	/* 1  bytes */
#define EEPROM_LEDS_OFF_TIME                (EEPROM_ADDR(0x49,LSB))	/* 1  bytes */

/* EEPROM field values */

/* EEPROM field lengths */
#define EEPROM_BOARD_PBA_NUMBER_LENTGH                  11

/* SKU Capabilities */
#define EEPROM_SKU_CAP_SW_RF_KILL_ENABLE                (1 << 0)
#define EEPROM_SKU_CAP_HW_RF_KILL_ENABLE                (1 << 1)
#define EEPROM_SKU_CAP_OP_MODE_MRC                      (1 << 7)

/* LEDs mode */

#define IPW_DEFAULT_TX_RETRY  15
#define IPW_MAX_TX_RETRY      16

/*********************************************/

/* Authentication  and Association States */
enum ipw_auth_sequence {
	AUTH_INIT = 0,
	AUTH_TRANSACTION_1,	/* STA send AUTH request */
	AUTH_TRANSACTION_2,	/* shared: AP responds */
	AUTH_TRANSACTION_3,	/* shared: STA sends encrypted text */
	AUTH_TRANSACTION_4,	/* shared: AP sends success or failure */
	AUTH_SUCCESS,
};

#define IPW_POWER_MODE_CAM           0x00	//(always on)
#define IPW_POWER_INDEX_3            0x03
#define IPW_POWER_INDEX_5            0x05
#define IPW_POWER_AC                 0x06
#define IPW_POWER_BATTERY            0x07
#define IPW_POWER_LIMIT              0x07
#define IPW_POWER_MASK               0x0F
#define IPW_POWER_ENABLED            0x10
#define IPW_POWER_LEVEL(x)           ((x) & IPW_POWER_MASK)

#define RFD_SIZE                              4
#define NUM_TFD_CHUNKS                        4

#define RX_QUEUE_SIZE                        64
#define RX_QUEUE_SIZE_LOG                     6

#define IPW_A_MODE                         0
#define IPW_B_MODE                         1
#define IPW_G_MODE                         2

/*
 * TX Queue Flag Definitions
 */

/* abort attempt if mgmt frame is rx'd */

/* require CTS */

/* use short preamble */
#define DCT_FLAG_LONG_PREAMBLE             0x00
#define DCT_FLAG_SHORT_PREAMBLE            0x04

/* RTS/CTS first */

/* dont calculate duration field */

/* even if MAC WEP set (allows pre-encrypt) */
#define IPW_
/* overwrite TSF field */

/* ACK rx is expected to follow */
#define DCT_FLAG_ACK_REQD                  0x80

#define IPW_MB_DISASSOCIATE_THRESHOLD_DEFAULT           24
#define IPW_MB_ROAMING_THRESHOLD_DEFAULT                8
#define IPW_REAL_RATE_RX_PACKET_THRESHOLD               300

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

#define IPW_TX_QUEUE_1        1
#define IPW_TX_QUEUE_2        2
#define IPW_TX_QUEUE_3        3
#define IPW_TX_QUEUE_4        4

#define EEPROM_IMAGE_SIZE              (0x200 * sizeof(u16))
#define U32_PAD(n)                     ((4-(n%4))%4)

#define AC_BE_TID_MASK 0x9	//TID 0 and 3
#define AC_BK_TID_MASK 0x6	//TID 1 and 2

/* QoS sturctures */
struct ipw_qos_info {
	int qos_enable;
	struct ieee80211_qos_parameters *def_qos_parm_OFDM;
	struct ieee80211_qos_parameters *def_qos_parm_CCK;
	u32 burst_duration_CCK;
	u32 burst_duration_OFDM;
	u16 qos_no_ack_mask;
	int burst_enable;
};

/**************************************************************/
/**
 * Generic queue structure
 *
 * Contains common data for Rx and Tx queues
 */
struct ipw_queue {
	int n_bd;		       /**< number of BDs in this queue */
	int first_empty;	       /**< 1-st empty entry (index) */
	int last_used;		       /**< last used entry (index) */
	dma_addr_t dma_addr;		/**< physical addr for BD's */
	int n_window;
	u32 id;
	int low_mark;		       /**< low watermark, resume queue if free space more than this */
	int high_mark;		       /**< high watermark, stop queue if free space less than this */
} __attribute__ ((packed));

#define TFD_CTL_COUNT_SET(n)       (n<<24)
#define TFD_CTL_COUNT_GET(ctl)     ((ctl>>24) & 7)
#define TFD_CTL_PAD_SET(n)         (n<<28)
#define TFD_CTL_PAD_GET(ctl)       (ctl>>28)

struct tfd_frame_data {
	u32 addr;
	u32 len;
} __attribute__ ((packed));

struct tfd_frame {
	u32 control_flags;
	struct tfd_frame_data pa[4];
	u8 reserved[28];
} __attribute__ ((packed));

#define SEQ_TO_FIFO(x)  ((x >> 8) & 0xbf)
#define FIFO_TO_SEQ(x)  ((x & 0xbf) << 8)
#define SEQ_TO_INDEX(x) (x & 0xff)
#define INDEX_TO_SEQ(x) (x & 0xff)
#define SEQ_HUGE_FRAME  (0x4000)
#define SEQ_RX_FRAME    (0x8000)

enum {
	/* CMD_SIZE_NORMAL = 0, */
	CMD_SIZE_HUGE = (1 << 0),
	/* CMD_DIRECT = 0, */
	CMD_INDIRECT = (1 << 1),
	/* CMD_SYNC = 0, */
	CMD_ASYNC = (1 << 2),
	/* CMD_NO_SKB = 0, */
	CMD_WANT_SKB = (1 << 3),
	/* CMD_LOCK = 0, */
	CMD_NO_LOCK = (1 << 4),
	CMD_DAEMON = (1 << 5),
};
#define CMD_DAEMON_MASK (CMD_SIZE_HUGE)

struct ipw_cmd;
struct ipw_priv;

typedef int (*IPW_CALLBACK_FUNC) (struct ipw_priv * priv,
				  struct ipw_cmd * cmd, mbuf_t * skb);
#define TFD_TX_CMD_SLOTS 64
#define TFD_CMD_SLOTS 32

struct ipw_cmd_meta {
	union {
		struct ipw_cmd_meta *source;
		mbuf_t *skb;
		IPW_CALLBACK_FUNC callback;
	} __attribute__ ((packed)) u;

	u16 len;

	/* The CMD_SIZE_HUGE flag bit indicates that the command
	 * structure is stored at the end of the shared queue memory. */
	u8 flags;

	u8 token;
} __attribute__ ((packed));

struct ipw_cmd_header {
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
	u16 sequence;
} __attribute__ ((packed));

struct ipw_host_cmd {
	u8 id;
	u16 len;
	struct ipw_cmd_meta meta;
	void *data;
};

struct ipw_cmd {
	struct ipw_cmd_meta meta;
	struct ipw_cmd_header hdr;
	union {
		struct ipw_addsta_cmd addsta;
		struct ipw_led_cmd led;
		u32 flags;
		u8 val8;
		u16 val16;
		u32 val32;
		struct ipw_bt_cmd bt;
		struct ipw_rxon_time_cmd rx_on_time;
		struct ipw_powertable_cmd powertable;
		struct ipw_qosparam_cmd qosparam;
		struct ipw_tx_cmd tx;
		struct ipw_key_cmd key;
		struct ipw_tx_beacon_cmd tx_beacon;
		struct ipw_rxon_assoc_cmd rxon_assoc;
		struct RateScalingCmdSpecifics rate_scale;
		u8 *indirect;
		u8 payload[360];
	} __attribute__ ((packed)) cmd;
} __attribute__ ((packed));

#define TFD_MAX_PAYLOAD_SIZE (sizeof(struct ipw_cmd) - \
                              sizeof(struct ipw_cmd_meta))

/**
 * Tx Queue for DMA. Queue consists of circular buffer of
 * BD's and required locking structures.
 */
struct ipw_tx_queue {
	struct ipw_queue q;
	struct tfd_frame *bd;
	struct ipw_cmd *cmd;
	dma_addr_t dma_addr_cmd;
	struct ieee80211_txb **txb;
	int need_update;	/* flag to indicate we need to update read/write index */
};

/*
 * RX related structures and functions
 */
#define RX_FREE_BUFFERS 64
#define RX_LOW_WATERMARK 8

#define SUP_RATE_11A_MAX_NUM_CHANNELS  8
#define SUP_RATE_11B_MAX_NUM_CHANNELS  4
#define SUP_RATE_11G_MAX_NUM_CHANNELS  12

// Used for passing to driver number of successes and failures per rate
struct rate_histogram {
	union {
		u32 a[SUP_RATE_11A_MAX_NUM_CHANNELS];
		u32 b[SUP_RATE_11B_MAX_NUM_CHANNELS];
		u32 g[SUP_RATE_11G_MAX_NUM_CHANNELS];
	} success;
	union {
		u32 a[SUP_RATE_11A_MAX_NUM_CHANNELS];
		u32 b[SUP_RATE_11B_MAX_NUM_CHANNELS];
		u32 g[SUP_RATE_11G_MAX_NUM_CHANNELS];
	} failed;
} __attribute__ ((packed));

/* statistics command response */

struct statistics_rx_phy {
	u32 ina_cnt;
	u32 fina_cnt;
	u32 plcp_err;
	u32 crc32_err;
	u32 overrun_err;
	u32 early_overrun_err;
	u32 crc32_good;
	u32 false_alarm_cnt;
	u32 fina_sync_err_cnt;
	u32 sfd_timeout;
	u32 fina_timeout;
	u32 unresponded_rts;
	u32 rxe_frame_limit_overrun;
	u32 sent_ack_cnt;
	u32 sent_cts_cnt;
} __attribute__ ((packed));

struct statistics_rx {
	struct statistics_rx_phy ofdm;
	struct statistics_rx_phy cck;
	u32 bogus_cts;
	u32 bogus_ack;
	u32 non_bssid_frames;
	u32 filtered_frames;
	u32 non_channel_beacons;
} __attribute__ ((packed));

struct statistics_tx {
	u32 preamble_cnt;
	u32 rx_detected_cnt;
	u32 bt_prio_defer_cnt;
	u32 bt_prio_kill_cnt;
	u32 few_bytes_cnt;
	u32 cts_timeout;
	u32 ack_timeout;
	u32 expected_ack_cnt;
	u32 actual_ack_cnt;
} __attribute__ ((packed));

struct statistics_dbg {
	u32 burst_check;
	u32 burst_count;
	u32 reserved[4];
} __attribute__ ((packed));

struct statistics_div {
	u32 tx_on_a;
	u32 tx_on_b;
	u32 exec_time;
	u32 probe_time;
} __attribute__ ((packed));

struct statistics_general {
	u32 temperature;
	struct statistics_dbg dbg;
	u32 sleep_time;
	u32 slots_out;
	u32 slots_idle;
	u32 ttl_timestamp;
	struct statistics_div div;
} __attribute__ ((packed));

struct ipw_notif_statistics {
	u32 flag;
	struct statistics_rx rx;
	struct statistics_tx tx;
	struct statistics_general general;
} __attribute__ ((packed));

struct ipw_rx_packet {
	u32 len;
	struct ipw_cmd_header hdr;
	union {
		struct ipw_alive_resp alive_frame;
		struct ipw_rx_frame rx_frame;
		struct ipw_tx_resp tx_resp;
		struct ipw_spectrum_notification spectrum_notif;
		struct ipw_csa_notification csa_notif;
		struct ipw_error_resp err_resp;
		struct ipw_card_state_notif card_state_notif;
		struct ipw_notif_statistics stats;
		struct BeaconNtfSpecifics beacon_status;
		struct ipw_add_sta_resp add_sta;
		struct ipw_sleep_notification sleep_notif;
		u32 status;
		u8 raw[0];
	} u;
} __attribute__ ((packed));

#define IPW_RX_FRAME_SIZE        (4 + sizeof(struct ipw_rx_frame))

struct ipw_rx_mem_buffer {
	dma_addr_t dma_addr;
	struct m_buff *skb;
	struct list_head list;
};				/* Not transferred over network, so not  __attribute__ ((packed)) */

struct ipw_rx_queue {
	void *bd;
	dma_addr_t dma_addr;
	struct ipw_rx_mem_buffer pool[RX_QUEUE_SIZE + RX_FREE_BUFFERS];
	struct ipw_rx_mem_buffer *queue[RX_QUEUE_SIZE];
	u32 processed;		/* Internal index to last handled Rx packet */
	u32 read;		/* Shared index to newest available Rx buffer */
	u32 write;		/* Shared index to oldest written Rx packet */
	u32 free_count;		/* Number of pre-allocated buffers in rx_free */
	/* Each of these lists is used as a FIFO for ipw_rx_mem_buffers */
	struct list_head rx_free;	/* Own an SKBs */
	struct list_head rx_used;	/* No SKB allocated */
	int need_update;	/* flag to indicate we need to update read/write index */
	spinlock_t lock;
};				/* Not transferred over network, so not  __attribute__ ((packed)) */

struct ipw_multicast_addr {
	u8 num_of_multicast_addresses;
	u8 reserved[3];
	u8 mac1[6];
	u8 mac2[6];
	u8 mac3[6];
	u8 mac4[6];
} __attribute__ ((packed));

struct ipw_tgi_tx_key {
	u8 key_id;
	u8 security_type;
	u8 station_index;
	u8 flags;
	u8 key[16];
	u32 tx_counter[2];
} __attribute__ ((packed));

struct ipw_associate {
	u8 channel;
	u8 auth_type:4, auth_key:4;
	u8 assoc_type;
	u8 reserved;
	u16 policy_support;
	u8 preamble_length;
	u8 ieee_mode;
	u8 bssid[ETH_ALEN];
	u32 assoc_tsf_msw;
	u32 assoc_tsf_lsw;
	u16 capability;
	u16 listen_interval;
	u16 beacon_interval;
	u8 dest[ETH_ALEN];
	u16 atim_window;
	u8 smr;
	u8 reserved1;
	u16 reserved2;
	u16 assoc_id;
	u8 erp_value;
} __attribute__ ((packed));

#define IPW_SUPPORTED_RATES_IE_LEN         8
#define IPW_MAX_RATES                     12

struct ipw_supported_rates {
	u8 ieee_mode;
	u8 num_rates;
	u8 purpose;
	u8 reserved;
	u8 supported_rates[IPW_MAX_RATES];
} __attribute__ ((packed));

struct ipw_channel_tx_power {
	u8 channel_number;
	s8 tx_power;
} __attribute__ ((packed));

#define SCAN_INTERVAL 100

#define MAX_A_CHANNELS  252
#define MIN_A_CHANNELS  7

#define MAX_B_CHANNELS  14
#define MIN_B_CHANNELS  1

#define STATUS_HCMD_ACTIVE      (1<<0)	/**< host command in progress */

#define STATUS_INT_ENABLED      (1<<1)
#define STATUS_RF_KILL_HW       (1<<2)
#define STATUS_RF_KILL_SW       (1<<3)
#define STATUS_RF_KILL_MASK     (STATUS_RF_KILL_HW | STATUS_RF_KILL_SW)

#define STATUS_INIT             (1<<4)
#define STATUS_ALIVE            (1<<5)
#define STATUS_READY            (1<<6)
#define STATUS_CALIBRATE        (1<<7)
#define STATUS_GEO_CONFIGURED   (1<<8)
#define STATUS_EXIT_PENDING     (1<<9)
#define STATUS_IN_SUSPEND       (1<<10)

#define STATUS_ASSOCIATING      (1<<12)
#define STATUS_AUTH             (1<<13)
#define STATUS_ASSOCIATED       (1<<14)
#define STATUS_DISASSOCIATING   (1<<15)

#define STATUS_ROAMING           (1<<16)
#define STATUS_SCANNING          (1<<17)
#define STATUS_SCAN_ABORTING     (1<<19)
#define STATUS_SCAN_PENDING      (1<<20)
#define STATUS_SCAN_HW           (1<<21)

#define STATUS_DCMD_ACTIVE      (1<<23)	/* Sync. daemon cmd active */

#define STATUS_POWER_PMI        (1<<24)
#define STATUS_RESTRICTED       (1<<26)
#define STATUS_FW_ERROR         (1<<27)

#define STATUS_TX_MEASURE       (1<<28)

#define STATUS_SECURITY_UPDATED (1<<31)	/* Security sync needed */

#define CFG_STATIC_CHANNEL      (1<<0)	/* Restrict assoc. to single channel */
#define CFG_STATIC_ESSID        (1<<1)	/* Restrict assoc. to single SSID */
#define CFG_STATIC_BSSID        (1<<2)	/* Restrict assoc. to single BSSID */
#define CFG_CUSTOM_MAC          (1<<3)
#define CFG_PREAMBLE_LONG       (1<<4)
#define CFG_ADHOC_PERSIST       (1<<5)
#define CFG_ASSOCIATE           (1<<6)
#define CFG_FIXED_RATE          (1<<7)
#define CFG_ADHOC_CREATE        (1<<8)
#define CFG_NO_LED              (1<<9)
#define CFG_BACKGROUND_SCAN     (1<<10)
#define CFG_TXPOWER_LIMIT       (1<<11)
#define CFG_NO_ROAMING          (1<<12)

#define CAP_SHARED_KEY          (1<<0)	/* Off = OPEN */
#define CAP_PRIVACY_ON          (1<<1)	/* Off = No privacy */
#define CAP_RF_HW_KILL          (1<<2)	/* Off = no HW rf kill support */
#define CAP_RF_SW_KILL          (1<<3)	/* Off = no HW rf kill support */

//todoG need to support adding adhoc station MAX_STATION should be 25
#define IPW_INVALID_STATION     (0xff)

#define MAX_TID_COUNT           6

struct ipw_tid_data {
	u16 seq_number;
};

struct ipw_station_entry {
	struct ipw_addsta_cmd sta;
	struct ipw_tid_data tid[MAX_TID_COUNT];
	u8 current_rate;
	u8 used;
};

struct ipw_rate_info {
	u8 rate_plcp;
	u8 rate_ieee;
	s32 rate_scale_index;
	u32 bps;		/* Bits per symbol, only OFDM */
	u32 dur_ack;
	u32 dur_rts;
	u32 dur_cts;
	u32 dur_back;
};

#define AVG_ENTRIES 8
struct average {
	long entries[AVG_ENTRIES];
	long sum;
	u8 pos;
	u8 init;
};

#define IPW_LED_ACTIVITY                (1<<0)
#define IPW_LED_LINK                    (1<<1)

struct ipw_led {
	u8 time_on;		/* ON time in interval units - 0 == OFF */
	u8 time_off;		/* OFF time in interval units - 0 == always ON if
				 * time_on != 0 */
};

struct ipw_led_info {
	u32 interval;		/* uSec length of "interval" */
	struct ipw_led activity;
	struct ipw_led link;
	struct ipw_led tech;
};

struct ipw_shared_t {
	volatile u32 tx_base_ptr[8];
	volatile u32 rx_read_ptr[3];
};

struct fw_image_desc {
	void *v_addr;
	dma_addr_t p_addr;
	u32 len;
	u32 actual_len;
};

struct ipw_tpt_entry {
	s32 min_rssi;
	u32 no_protection_tpt;
	u32 cts_rts_tpt;
	u32 cts_to_self_tpt;
	s32 rate_scale_index;
};

struct ipw_rate_scale_data {
	u64 data;
	s32 success_counter;
	s32 success_ratio;
	s32 counter;
	s32 average_tpt;
	unsigned long stamp;
};

struct ipw_rate_scale_mgr {
	spinlock_t lock;
	struct ipw_rate_scale_data window[NUM_RATES];
	s32 max_window_size;
	struct RateScalingCmdSpecifics scale_rate_cmd;
	s32 *expected_tpt;
	u8 *next_higher_rate;
	u8 *next_lower_rate;
	unsigned long stamp;
	unsigned long stamp_last;
	u32 flush_time;
	u32 tx_packets;
};

#define IPW_IBSS_MAC_HASH_SIZE 31

struct ipw_ibss_seq {
	u8 mac[ETH_ALEN];
	u16 seq_num;
	u16 frag_num;
	unsigned long packet_time;
	struct list_head list;
};

struct ipw_daemon_cmd_list {
	struct list_head list;
	mbuf_t *skb_resp;
	struct daemon_cmd_hdr cmd;	/* Must be last */
};

/* Power management (not Tx power) structures */

struct ipw_power_vec_entry {
	struct ipw_powertable_cmd cmd;
	u8 no_dtim;
};
#define IPW_POWER_RANGE_0  (0)
#define IPW_POWER_RANGE_1  (1)

struct ipw_power_mgr {
	//spinlock_t lock;
	struct ipw_power_vec_entry pwr_range_0[IPW_POWER_AC];
	struct ipw_power_vec_entry pwr_range_1[IPW_POWER_AC];
	u8 active_index;
	u32 dtim_val;
};

/* The LED interval is expressed in uSec and is the time
 * unit by which all other LED command are represented
 *
 * A value of '1000' for makes each unit 1ms.
 */

#define IPW_LED_INTERVAL 1000

#define DEFAULT_POWER_SAVE_ON       LED_SOLID_ON
#define DEFAULT_POWER_SAVE_OFF      0
#define DEFAULT_POWER_SAVE_INTERVAL 1000

struct ipw_activity_blink {
	u16 throughput;		/* threshold in Mbs */
	u8 off;			/* OFF time in interval units - 0 == always ON if
				 * time_on != 0 */
	u8 on;			/* ON time in interval units - 0 == OFF */
};

enum {
	IPW_LED_LINK_UNINIT = 0,
	IPW_LED_LINK_RADIOOFF,
	IPW_LED_LINK_UNASSOCIATED,
	IPW_LED_LINK_SCANNING,
	IPW_LED_LINK_ASSOCIATED,
	IPW_LED_LINK_ROAMING,
};

struct ipw_link_blink {
	u16 interval;		/* Number of interval units per second */
	u8 off;			/* OFF time in interval units - 0 == always ON if
				 * time_on != 0 */
	u8 on;			/* ON time in interval units - 0 == OFF */
};

struct ipw_frame {
	int len;
	union {
		struct ieee80211_hdr frame;
		u8 raw[IEEE80211_FRAME_LEN];
		u8 cmd[360];
	} u;
	struct list_head list;
};

#ifdef CONFIG_IPW3945_PROMISCUOUS
enum ipw_prom_filter {
	IPW_PROM_CTL_HEADER_ONLY = (1 << 0),
	IPW_PROM_MGMT_HEADER_ONLY = (1 << 1),
	IPW_PROM_DATA_HEADER_ONLY = (1 << 2),
	IPW_PROM_ALL_HEADER_ONLY = 0xf,	/* bits 0..3 */
	IPW_PROM_NO_TX = (1 << 4),
	IPW_PROM_NO_RX = (1 << 5),
	IPW_PROM_NO_CTL = (1 << 6),
	IPW_PROM_NO_MGMT = (1 << 7),
	IPW_PROM_NO_DATA = (1 << 8),
};

struct ipw_priv;
struct ipw_prom_priv {
	struct ipw_priv *priv;
	struct ieee80211_device *ieee;
	enum ipw_prom_filter filter;
	int tx_packets;
	int rx_packets;
};
#endif

#if defined(CONFIG_IPW3945_PROMISCUOUS) || defined(CONFIG_IEEE80211_RADIOTAP)
/* Magic struct that slots into the radiotap header -- no reason
 * to build this manually element by element, we can write it much
 * more efficiently than we can parse it. ORDER MATTERS HERE
 *
 * When sent to us via the simulated Rx interface in sysfs, the entire
 * structure is provided regardless of any bits unset.
 */
struct ipw_rt_hdr {
	struct ieee80211_radiotap_header rt_hdr;
	u64 rt_tsf;		/* TSF */
	u8 rt_flags;		/* radiotap packet flags */
	u8 rt_rate;		/* rate in 500kb/s */
	u16 rt_channel;		/* channel in mhz */
	u16 rt_chbitmask;	/* channel bitfield */
	s8 rt_dbmsignal;	/* signal in dbM, kluged to signed */
	s8 rt_dbmnoise;
	u8 rt_antenna;		/* antenna number */
	u8 payload[0];		/* payload... */
} __attribute__ ((packed));
#endif

/* The following macros are neccessary to retain compatibility
 * around the workqueue chenges happened in kernels >= 2.6.20:
 * - INIT_WORK changed to take 2 arguments and let the work function
 *   get its own data through the container_of macro
 * - delayed works have been split from normal works to save some
 *   memory usage in struct work_struct
 */
#define IPW_INIT_WORK				INIT_WORK
#define IPW_INIT_DELAYED_WORK			INIT_DELAYED_WORK
#define IPW_DELAYED_DATA(_ptr, _type, _m)	container_of(_ptr, _type, _m.work)
typedef struct delayed_work delayed_work_t;


struct ipw_priv {
	/* ieee device used by generic ieee processing code */
	struct ieee80211_device *ieee;

	//struct iw_public_data wireless_data;

	/* temporary frame storage list */
	struct list_head free_frames;
	int frames_count;

	/* spectrum measurement report caching */
	struct ipw_spectrum_notification measure_report;

	/* driver <-> daemon command, response, and communication queue */
	spinlock_t daemon_lock;
	wait_queue_head_t wait_daemon_out_queue;
	struct list_head daemon_in_list;
	struct list_head daemon_out_list;
	struct list_head daemon_free_list;
	/* return code for synchronous driver -> daemon commands */
	s32 daemon_cmd_rc;
	/* daemon driven work queue */
	//delayed_work_t daemon_cmd_work;
	//struct workqueue_struct *daemonqueue;
	//struct work_struct daemon_tx_status_sync;
	//wait_queue_head_t wait_daemon_cmd_done;
	/* daemon cmd queue flushing indicator */
	u16 daemon_tx_sequence;
	u8 daemon_tx_rate;
	u32 daemon_tx_status;
	unsigned long daemon_last_status;
	int daemon_flushing;

	/* Scan related variables */
	u8 scan_flags;
	unsigned long last_scan_jiffies;
	unsigned long scan_start;
	unsigned long scan_pass_start;
	unsigned long scan_start_tsf;
	int scan_passes;
	int scan_bands_remaining;
	int scan_bands;
#if WIRELESS_EXT > 17
	int one_direct_scan;
	u8 direct_ssid_len;
	u8 direct_ssid[IW_ESSID_MAX_SIZE];
#endif

	/* spinlock */
	spinlock_t lock;
	//struct mutex mutex;

	/* basic pci-network driver stuff */
	struct pci_dev *pci_dev;
	struct net_device *net_dev;

#ifdef CONFIG_IPW3945_PROMISCUOUS
	/* Promiscuous mode */
	struct ipw_prom_priv *prom_priv;
	struct net_device *prom_net_dev;
#endif

	/* pci hardware address support */
	void __iomem *hw_base;
	unsigned long hw_len;

	struct fw_image_desc ucode_code;
	struct fw_image_desc ucode_data;
	struct ipw_shared_t *shared_virt;
	dma_addr_t shared_phys;
	struct ipw_rxon_time_cmd rxon_timing;
	//struct daemon_rx_config rxon;
	struct ipw_alive_resp card_alive;

	/* LED related variables */
	struct ipw_activity_blink activity;
	unsigned long led_packets;
	int led_state;

	u32 rates_mask;
	u16 active_rate;
	u16 active_rate_basic;

	/* Rate scaling data */
	struct ipw_rate_scale_mgr rate_scale_mgr;
	s8 data_retry_limit;
	u8 retry_rate;

	wait_queue_head_t wait_command_queue;

	struct timer_list roaming_wdt;
	struct timer_list disassociate_wdt;

	int activity_timer_active;

	/* Cached microcode data */
	const struct firmware *ucode_raw;

	/* Rx and Tx DMA processing queues */
	struct ipw_rx_queue *rxq;
	struct ipw_tx_queue txq[6];
	u32 status;
	u32 config;
	u32 capability;

	u32 port_type;
	u32 missed_beacon_threshold;
	u32 roaming_threshold;

	struct ipw_power_mgr power_data;

	enum ipw_auth_sequence auth_state;

	struct ipw_frame *assoc_sequence_frame;
	struct ipw_associate assoc_request;
	struct ieee80211_network *assoc_network;
	int association_retries;

	struct ipw_notif_statistics statistics;

	/* context information */
	u8 essid[IW_ESSID_MAX_SIZE];
	u8 essid_len;
	u8 nick[IW_ESSID_MAX_SIZE];

	u8 channel;
	u32 power_mode;
	u32 antenna;
	u8 bssid[ETH_ALEN];
	u16 rts_threshold;
	u8 mac_addr[ETH_ALEN];
	u8 num_stations;
	struct ipw_station_entry stations[NUM_OF_STATIONS];
	u8 netdev_registered;
	int is_abg;

	u32 notif_missed_beacons;

	/* Wireless statistics */
	unsigned long last_rx_jiffies;
	u32 last_beacon_time;
	u64 last_tsf;
	u8 last_rx_rssi;
	u16 last_noise;
	struct average average_missed_beacons;
	struct average average_rssi;
	struct average average_noise;

	/* Statistics and counters normalized with each association */
	u32 last_missed_beacons;
	u32 last_tx_packets;
	u32 last_rx_packets;
	u32 last_tx_failures;
	u32 last_rx_err;
	u32 last_rate;

	u32 missed_adhoc_beacons;
	u32 missed_beacons;
	unsigned long rx_packets;
	unsigned long tx_packets;
	unsigned long long rx_bytes;
	unsigned long long tx_bytes;
	u32 quality;

	/* Duplicate packet detection */
	u16 last_seq_num;
	u16 last_frag_num;
	unsigned long last_packet_time;
	struct list_head ibss_mac_hash[IPW_IBSS_MAC_HASH_SIZE];

	/* eeprom */
	u8 eeprom[EEPROM_IMAGE_SIZE];	/* 1024 bytes of eeprom */

	struct iw_statistics wstats;

	/* Driver and iwconfig driven work queue */
	/*struct workqueue_struct *workqueue;

	struct work_struct adhoc_check;
	struct work_struct calibrated_work;
	struct work_struct associate;
	struct work_struct disassociate;
	struct work_struct rx_replenish;
	struct work_struct abort_scan;
	struct work_struct roam;
	struct work_struct link_up;
	struct work_struct update_link_led;
	struct work_struct link_down;
	struct work_struct auth_work;
	struct work_struct merge_networks;
	struct work_struct post_associate;

	delayed_work_t up;
	delayed_work_t down;
	delayed_work_t activity_timer;
	delayed_work_t assoc_state_retry;
	delayed_work_t request_scan;
	delayed_work_t gather_stats;
	delayed_work_t scan_check;
	delayed_work_t rf_kill;
	delayed_work_t rate_scale_flush;
	delayed_work_t resume_work;
	delayed_work_t alive_start;

	/* 802.11h  */
	//delayed_work_t report_work;

	//struct tasklet_struct irq_tasklet;*/

#define IPW_DEFAULT_TX_POWER 0x0F
	s8 user_txpower_limit;
	s8 actual_txpower_limit;
	s8 max_channel_txpower_limit;

#ifdef CONFIG_PM
	u32 pm_state[16];
#endif

	/* Used to pass the current INTA value from ISR to Tasklet */
	u32 isr_inta;

#ifdef CONFIG_IPW3945_QOS
	/* QoS */
	struct ipw_qos_info qos_data;
	struct work_struct qos_activate;
	/*********************************/
#endif

	/* debugging info */
	u32 framecnt_to_us;
};				/*ipw_priv */

/* debug macros */

/*
* Register bit definitions
*/

/* NIC type as found in the one byte EEPROM_NIC_TYPE  offset*/

/* Defines a single bit in a by bit number (0-31) */

/* Interrupts masks */
#define IPW_RX_BUF_SIZE 3000
enum {
	IPW_FW_ERROR_OK = 0,
	IPW_FW_ERROR_FAIL,
	IPW_FW_ERROR_MEMORY_UNDERFLOW,
	IPW_FW_ERROR_MEMORY_OVERFLOW,
	IPW_FW_ERROR_BAD_PARAM,
	IPW_FW_ERROR_BAD_CHECKSUM,
	IPW_FW_ERROR_NMI_INTERRUPT,
	IPW_FW_ERROR_BAD_DATABASE,
	IPW_FW_ERROR_ALLOC_FAIL,
	IPW_FW_ERROR_DMA_UNDERRUN,
	IPW_FW_ERROR_DMA_STATUS,
	IPW_FW_ERROR_DINO_ERROR,
	IPW_FW_ERROR_EEPROM_ERROR,
	IPW_FW_ERROR_SYSASSERT,
	IPW_FW_ERROR_FATAL_ERROR
};

#define AUTH_OPEN       0
#define AUTH_SHARED_KEY 1

#define HC_ASSOCIATE      0
#define HC_REASSOCIATE    1
#define HC_DISASSOCIATE   2
#define HC_IBSS_START     3
#define HC_DISASSOC_QUIET 5

#define HC_QOS_SUPPORT_ASSOC  0x01

#define IPW_RATE_CAPABILITIES 1
#define IPW_RATE_CONNECT      0

/*
 * Rate values and masks
 */
#define IPW_TX_RATE_1MB  0x0A
#define IPW_TX_RATE_2MB  0x14
#define IPW_TX_RATE_5MB  0x37
#define IPW_TX_RATE_6MB  0x0D
#define IPW_TX_RATE_9MB  0x0F
#define IPW_TX_RATE_11MB 0x6E
#define IPW_TX_RATE_12MB 0x05
#define IPW_TX_RATE_18MB 0x07
#define IPW_TX_RATE_24MB 0x09
#define IPW_TX_RATE_36MB 0x0B
#define IPW_TX_RATE_48MB 0x01
#define IPW_TX_RATE_54MB 0x03

#define IPW_ORD_TABLE_0_MASK              0x0000F000
#define IPW_ORD_TABLE_1_MASK              0x0000F100
#define IPW_ORD_TABLE_2_MASK              0x0000F200
#define IPW_ORD_TABLE_3_MASK              0x0000F300
#define IPW_ORD_TABLE_4_MASK              0x0000F400
#define IPW_ORD_TABLE_5_MASK              0x0000F500
#define IPW_ORD_TABLE_6_MASK              0x0000F600
#define IPW_ORD_TABLE_7_MASK              0x0000F700

/*
 * Table 0 Entries (all entries are 32 bits)
 */
enum {
	IPW_ORD_STAT_TX_CURR_RATE = IPW_ORD_TABLE_0_MASK + 1,
	IPW_ORD_STAT_FRAG_TRESHOLD,
	IPW_ORD_STAT_RTS_THRESHOLD,
	IPW_ORD_STAT_TX_HOST_REQUESTS,
	IPW_ORD_STAT_TX_HOST_COMPLETE,
	IPW_ORD_STAT_TX_DIR_DATA,
	IPW_ORD_STAT_TX_DIR_DATA_B_1,
	IPW_ORD_STAT_TX_DIR_DATA_B_2,
	IPW_ORD_STAT_TX_DIR_DATA_B_5_5,
	IPW_ORD_STAT_TX_DIR_DATA_B_11,
	/* Hole */

	IPW_ORD_STAT_TX_DIR_DATA_G_1 = IPW_ORD_TABLE_0_MASK + 19,
	IPW_ORD_STAT_TX_DIR_DATA_G_2,
	IPW_ORD_STAT_TX_DIR_DATA_G_5_5,
	IPW_ORD_STAT_TX_DIR_DATA_G_6,
	IPW_ORD_STAT_TX_DIR_DATA_G_9,
	IPW_ORD_STAT_TX_DIR_DATA_G_11,
	IPW_ORD_STAT_TX_DIR_DATA_G_12,
	IPW_ORD_STAT_TX_DIR_DATA_G_18,
	IPW_ORD_STAT_TX_DIR_DATA_G_24,
	IPW_ORD_STAT_TX_DIR_DATA_G_36,
	IPW_ORD_STAT_TX_DIR_DATA_G_48,
	IPW_ORD_STAT_TX_DIR_DATA_G_54,
	IPW_ORD_STAT_TX_NON_DIR_DATA,
	IPW_ORD_STAT_TX_NON_DIR_DATA_B_1,
	IPW_ORD_STAT_TX_NON_DIR_DATA_B_2,
	IPW_ORD_STAT_TX_NON_DIR_DATA_B_5_5,
	IPW_ORD_STAT_TX_NON_DIR_DATA_B_11,
	/* Hole */

	IPW_ORD_STAT_TX_NON_DIR_DATA_G_1 = IPW_ORD_TABLE_0_MASK + 44,
	IPW_ORD_STAT_TX_NON_DIR_DATA_G_2,
	IPW_ORD_STAT_TX_NON_DIR_DATA_G_5_5,
	IPW_ORD_STAT_TX_NON_DIR_DATA_G_6,
	IPW_ORD_STAT_TX_NON_DIR_DATA_G_9,
	IPW_ORD_STAT_TX_NON_DIR_DATA_G_11,
	IPW_ORD_STAT_TX_NON_DIR_DATA_G_12,
	IPW_ORD_STAT_TX_NON_DIR_DATA_G_18,
	IPW_ORD_STAT_TX_NON_DIR_DATA_G_24,
	IPW_ORD_STAT_TX_NON_DIR_DATA_G_36,
	IPW_ORD_STAT_TX_NON_DIR_DATA_G_48,
	IPW_ORD_STAT_TX_NON_DIR_DATA_G_54,
	IPW_ORD_STAT_TX_RETRY,
	IPW_ORD_STAT_TX_FAILURE,
	IPW_ORD_STAT_RX_ERR_CRC,
	IPW_ORD_STAT_RX_ERR_ICV,
	IPW_ORD_STAT_RX_NO_BUFFER,
	IPW_ORD_STAT_FULL_SCANS,
	IPW_ORD_STAT_PARTIAL_SCANS,
	IPW_ORD_STAT_TGH_ABORTED_SCANS,
	IPW_ORD_STAT_TX_TOTAL_BYTES,
	IPW_ORD_STAT_CURR_RSSI_RAW,
	IPW_ORD_STAT_RX_BEACON,
	IPW_ORD_STAT_MISSED_BEACONS,
	IPW_ORD_TABLE_0_LAST
};

/* Table 1 Entries
 */
enum {
	IPW_ORD_TABLE_1_LAST = IPW_ORD_TABLE_1_MASK | 1,
};

/*
 * Table 2 Entries
 *
 * FW_VERSION:    16 byte string
 * FW_DATE:       16 byte string (only 14 bytes used)
 * UCODE_VERSION: 4 byte version code
 * UCODE_DATE:    5 bytes code code
 * ADAPTER_MAC:   6 byte MAC address
 * RTC:           4 byte clock
 */
enum {
	IPW_ORD_STAT_FW_VERSION = IPW_ORD_TABLE_2_MASK | 1,
	IPW_ORD_STAT_FW_DATE,
	IPW_ORD_STAT_UCODE_VERSION,
	IPW_ORD_STAT_UCODE_DATE,
	IPW_ORD_STAT_ADAPTER_MAC,
	IPW_ORD_STAT_RTC,
	IPW_ORD_TABLE_2_LAST
};

/* Table 3 */
enum {
	IPW_ORD_STAT_TX_PACKET = IPW_ORD_TABLE_3_MASK | 0,
	IPW_ORD_STAT_TX_PACKET_FAILURE,
	IPW_ORD_STAT_TX_PACKET_SUCCESS,
	IPW_ORD_STAT_TX_PACKET_ABORTED,
	IPW_ORD_TABLE_3_LAST
};

/* Table 4 */
enum {
	IPW_ORD_TABLE_4_LAST = IPW_ORD_TABLE_4_MASK
};

/* Table 5 */
enum {
	IPW_ORD_STAT_AVAILABLE_AP_COUNT = IPW_ORD_TABLE_5_MASK,
	IPW_ORD_STAT_AP_ASSNS,
	IPW_ORD_STAT_ROAM,
	IPW_ORD_STAT_ROAM_CAUSE_MISSED_BEACONS,
	IPW_ORD_STAT_ROAM_CAUSE_UNASSOC,
	IPW_ORD_STAT_ROAM_CAUSE_RSSI,
	IPW_ORD_STAT_ROAM_CAUSE_LINK_QUALITY,
	IPW_ORD_STAT_ROAM_CAUSE_AP_LOAD_BALANCE,
	IPW_ORD_STAT_ROAM_CAUSE_AP_NO_TX,
	IPW_ORD_STAT_LINK_UP,
	IPW_ORD_STAT_LINK_DOWN,
	IPW_ORD_ANTENNA_DIVERSITY,
	IPW_ORD_CURR_FREQ,
	IPW_ORD_TABLE_5_LAST
};

/* Table 6 */
enum {
	IPW_ORD_COUNTRY_CODE = IPW_ORD_TABLE_6_MASK,
	IPW_ORD_CURR_BSSID,
	IPW_ORD_CURR_SSID,
	IPW_ORD_TABLE_6_LAST
};

/* Table 7 */
enum {
	IPW_ORD_STAT_PERCENT_MISSED_BEACONS = IPW_ORD_TABLE_7_MASK,
	IPW_ORD_STAT_PERCENT_TX_RETRIES,
	IPW_ORD_STAT_PERCENT_LINK_QUALITY,
	IPW_ORD_STAT_CURR_RSSI_DBM,
	IPW_ORD_TABLE_7_LAST
};

struct ipw_fixed_rate {
	u16 tx_rates;
	u16 reserved;
} __attribute__ ((packed));

#define IPW_MIN_RSSI_VAL                 -100
#define IPW_MAX_RSSI_VAL                    0
#define IPW_RSSI_OFFSET                    95
#define IPW_RATE_SCALE_FLUSH          (3*HZ/10)	//300 milli
#define IPW_RATE_SCALE_WIN_FLUSH      (HZ/2)	//500 milli
#define IPW_RATE_SCALE_HIGH_TH          11520
#define IPW_RATE_SCALE_MIN_FAILURE_TH       8
#define IPW_RATE_SCALE_MIN_SUCCESS_TH       8
#define IPW_RATE_SCALE_DECREASE_TH       1920

#if LINUX_VERSION_CODE < KERNEL_VERSION
static inline void *kzalloc(size_t size, unsigned __nocast flags)
{
	void *ret = kmalloc(size, flags);
	if (ret)
		memset(ret, 0, size);
	return ret;
}
#endif

static inline unsigned compare_ether_addr(const u8 * _a, const u8 * _b)
{
	const u16 *a = (const u16 *)_a;
	const u16 *b = (const u16 *)_b;

	if(ETH_ALEN != 6) return -1;
	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
}

#endif				/* __ipw3945_h__ */
