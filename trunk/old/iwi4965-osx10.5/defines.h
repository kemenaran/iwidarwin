#ifndef __DEFINES_H__
#define __DEFINES_H__


#define IM_HERE_NOW() printf("%s @ %s:%d\n", __FUNCTION__, __FILE__, __LINE__)
#define CONFIG_IWL4965_DEBUG 1

#define DUMP_PREFIX_OFFSET 0
#define DUMP_PREFIX_ADDRESS 1

#define NUM_RX_DATA_QUEUES 17
#define NUM_TX_DATA_QUEUES 6
#define MAX_STA_COUNT 2007
#define STA_HASH_SIZE 256
#define STA_HASH(sta) (sta[5])
#define IEEE80211_MAX_SSID_LEN 32
#define MAX_JIFFY_OFFSET ((~0UL >> 1)-1)
#define PCI_DMA_TODEVICE 0x2 // aka kIODirectionIn. defined in IOMemoryDescriptor
#define PCI_DMA_FROMDEVICE 0x1 // aka kIODirectionOut. defined in IOMemoryDescriptor
#define PCI_REVISION_ID  0x08 //kIOPCIConfigRevisionID
#define GFP_KERNEL 0
#define GFP_ATOMIC 0
#define __GFP_NOWARN 0
#define RX_FLAG_MMIC_ERROR       0x1
#define RX_FLAG_DECRYPTED	0x2
#define RX_FLAG_RADIOTAP        (1<<2)
#define IRQF_SHARED 0
#define IEEE80211_HW_NO_PROBE_FILTERING 0
#define DMA_32BIT_MASK 0
#define S_IRUSR 0

/* miscellaneous IEEE 802.11 constants */
#define IEEE80211_MAX_FRAG_THRESHOLD	2346
#define IEEE80211_MAX_RTS_THRESHOLD	2347
#define IEEE80211_MAX_AID		2007
#define IEEE80211_MAX_TIM_LEN		251
#define IEEE80211_MAX_DATA_LEN		2304
#define RATE_CONTROL_NUM_DOWN 20
#define RATE_CONTROL_NUM_UP   15


#define __builtin_expect(x, expected_value) (x)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x) __builtin_expect(!!(x), 1)




/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({          \
const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
(type *)( (char *)__mptr - offsetof(type,member) );})


/* Force a compilation error if condition is true */
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define ETH_ALEN 6
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BUG() do { \
printk("BUG: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __FUNCTION__); \
printk("BUG!"); \
} while (0)
#define BUG_ON(condition) do { if (unlikely((condition)!=0)) BUG(); } while(0)

//#include <i386/locks.h>
#include <IOKit/pccard/k_compat.h>
#undef add_timer
#undef del_timer
#undef mod_timer	
#include <IOKit/IOLocks.h>

//#include <IOKit/network/IOPacketQueue.h>
//includes for fifnet functions
//extern "C" {
#include <net/if_var.h>
#include <sys/vm.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/dlil.h>
#include <net/bpf.h>
#include <netinet/if_ether.h>
#include <netinet/in_arp.h>
#include <sys/sockio.h>
#include <sys/malloc.h>
#include <sys/queue.h>
//}

typedef IOPhysicalAddress dma_addr_t;
#define cpu_to_le16(x) le16_to_cpu(x)
#define cpu_to_le32(x) le32_to_cpu(x)
#define __constant_cpu_to_le32(x) cpu_to_le32(x)
#define __constant_cpu_to_le16(x) cpu_to_le16(x)
#define le64_to_cpu(x) OSSwapLittleToHostInt64(x)
#define cpu_to_le64(x) OSSwapHostToLittleInt64(x)

struct timer_list2 {
        unsigned long expires;
        void (*function)(unsigned long);
        unsigned long data;
		int vv;
		int on;
};

//#include "iwi4965.h"
#include "net/compat.h"
#include "net/ieee80211.h"
#include "net/ieee80211_radiotap.h"



struct sk_buff {

	struct sk_buff          *next;
	struct sk_buff          *prev;
	int pkt_type;
//    void *data;
//    unsigned int len;
    mbuf_t mac_data;
    
    /*
     * This is the control buffer. It is free to use for every
     * layer. Please put your private variables there. If you
     * want to keep them across layers you have to do a skb_clone()
     * first. This is owned by whoever has the skb queued ATM.
     */
    // (We keep this on OS X because it's a handy scratch space.)
    char            cb[48];
    
    void *intf; // A pointer to an IO80211Controller.
};



#define __must_check

/*
struct p_dev {
    void *kobj; // Device of type IOPCIDevice.
}; */

struct kobject {
    void *ptr;
};

struct device {
    struct kobject kobj; // Device of type IOPCIDevice.
    void *driver_data;
};

struct pci_dev {
    unsigned long device;
    unsigned long subsystem_device;
    struct device dev;
    unsigned int irq;
	u32 saved_config_space[16];
};


struct mutex {
    lck_grp_attr_t *slock_grp_attr;
    lck_grp_t *slock_grp;
    lck_attr_t *slock_attr;
    lck_mtx_t *mlock;
};


struct tasklet_struct {
    int padding;
	void (*func)(unsigned long);
	unsigned long data;
};

//struct delayed_work;

//struct net_device;


typedef enum {
    SET_KEY, DISABLE_KEY, REMOVE_ALL_KEYS,
} set_key_cmd;


enum ieee80211_link_state_t {
    IEEE80211_LINK_STATE_XOFF = 0,
    IEEE80211_LINK_STATE_PENDING,
};


//struct ieee80211_hw;

#define KERN_WARNING "warning "
#define KERN_ERR "error "
#define KERN_CRIT "critical "


// Bit manipulation, rewritten to use mach routines
#define test_bit(x, y) isset(y, x)
#define clear_bit(x, y) clrbit(y, x)

//#define spin_lock_irqsave(lock, fl) //lck_spin_lock((lock)->slock+flags-flags)
//#define spin_unlock_irqrestore(lock, fl) //lck_spin_unlock(((lock)->slock)+flags-flags)
#undef MSEC_PER_SEC		
#undef USEC_PER_SEC		
#undef NSEC_PER_SEC		
#undef NSEC_PER_USEC		

#define MSEC_PER_SEC		1000L
#define USEC_PER_SEC		1000000L
#define NSEC_PER_SEC		1000000000L
#define NSEC_PER_USEC		1000L

static inline unsigned int
__div(unsigned long long n, unsigned int base)
{
	return n / base;
}
#undef jiffies
#define jiffies		\
({		\
	uint64_t m,f;		\
	clock_get_uptime(&m);		\
	absolutetime_to_nanoseconds(m,&f);		\
	((f * HZ) / 1000000000);		\
})

static inline unsigned long usecs_to_jiffies(const unsigned int u)
 {
         //if (u > jiffies_to_usecs(MAX_JIFFY_OFFSET))
           //      return MAX_JIFFY_OFFSET;
 #if HZ <= USEC_PER_SEC && !(USEC_PER_SEC % HZ)
         return (u + (USEC_PER_SEC / HZ) - 1) / (USEC_PER_SEC / HZ);
 #elif HZ > USEC_PER_SEC && !(HZ % USEC_PER_SEC)
         return u * (HZ / USEC_PER_SEC);
 #else
         return (u * HZ + USEC_PER_SEC - 1) / USEC_PER_SEC;
 #endif
 }

static inline void jiffies_to_timespec(unsigned long jiffiess, struct timespec *value)
{
	uint64_t nsec = (uint64_t)jiffies * NSEC_PER_SEC;//TICK_NSEC;
	//value->tv_sec = div_long_long_rem(nsec, NSEC_PER_SEC, &value->tv_nsec);
	// this is wrong
	value->tv_nsec = nsec;
	value->tv_sec = __div(nsec, NSEC_PER_SEC);
}

static inline unsigned int jiffies_to_msecs(const unsigned long j)
{
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
	return (MSEC_PER_SEC / HZ) * j;
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
	return (j + (HZ / MSEC_PER_SEC) - 1)/(HZ / MSEC_PER_SEC);
#else
	return (j * MSEC_PER_SEC) / HZ;
#endif
}

static inline unsigned long msecs_to_jiffies(const unsigned int m)
{
         //if (m > jiffies_to_msecs(MAX_JIFFY_OFFSET)) return MAX_JIFFY_OFFSET;
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
         return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
         return m * (HZ / MSEC_PER_SEC);
#else
         return (m * HZ + MSEC_PER_SEC - 1) / MSEC_PER_SEC;
#endif
}

#define time_after(a,b)	((long)(b) - (long)(a) < 0)

//struct sta_local;
//struct ieee80211_tx_control;
//struct ieee80211_tx_stored_packet;

struct ieee80211_frame_info {
	__be32 version;
	__be32 length;
	__be64 mactime;
	__be64 hosttime;
	__be32 phytype;
	__be32 channel;
	__be32 datarate;
	__be32 antenna;
	__be32 priority;
	__be32 ssi_type;
	__be32 ssi_signal;
	__be32 ssi_noise;
	__be32 preamble;
	__be32 encoding;

	/* Note: this structure is otherwise identical to capture format used
	 * in linux-wlan-ng, but this additional field is used to provide meta
	 * data about the frame to hostapd. This was the easiest method for
	 * providing this information, but this might change in the future. */
	__be32 msg_type;
} __attribute__ ((packed));





struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);



struct work_struct {
    void* data;
#define WORK_STRUCT_PENDING 0       /* T if work item pending execution */
#define WORK_STRUCT_NOAUTOREL 1     /* F if work item automatically released on 
exec */
#define WORK_STRUCT_FLAG_MASK (3UL)
#define WORK_STRUCT_WQ_DATA_MASK (~WORK_STRUCT_FLAG_MASK)
    struct list_head entry;
    work_func_t func;
	int number;
};


struct delayed_work {
    struct work_struct work;
    struct timer_list2 timer;
};



struct workqueue_struct {
    char data[4];
	thread_call_t tlink[256];
};



struct ieee80211_tx_control {
	int tx_rate; /* Transmit rate, given as the hw specific value for the
		      * rate (from struct ieee80211_rate) */
	int rts_cts_rate; /* Transmit rate for RTS/CTS frame, given as the hw
			   * specific value for the rate (from
			   * struct ieee80211_rate) */

#define IEEE80211_TXCTL_REQ_TX_STATUS	(1<<0)/* request TX status callback for
						* this frame */
#define IEEE80211_TXCTL_DO_NOT_ENCRYPT	(1<<1) /* send this frame without
						* encryption; e.g., for EAPOL
						* frames */
#define IEEE80211_TXCTL_USE_RTS_CTS	(1<<2) /* use RTS-CTS before sending
						* frame */
#define IEEE80211_TXCTL_USE_CTS_PROTECT	(1<<3) /* use CTS protection for the
						* frame (e.g., for combined
						* 802.11g / 802.11b networks) */
#define IEEE80211_TXCTL_NO_ACK		(1<<4) /* tell the low level not to
						* wait for an ack */
#define IEEE80211_TXCTL_RATE_CTRL_PROBE	(1<<5)
#define IEEE80211_TXCTL_CLEAR_DST_MASK	(1<<6)
#define IEEE80211_TXCTL_REQUEUE		(1<<7)
#define IEEE80211_TXCTL_FIRST_FRAGMENT	(1<<8) /* this is a first fragment of
						* the frame */
#define IEEE80211_TXCTL_TKIP_NEW_PHASE1_KEY (1<<9)
#define IEEE80211_TXCTL_HT_MPDU_AGG	(1<<10) /* MPDU aggregation */
	u32 flags;			       /* tx control flags defined
						* above */
	u8 retry_limit;		/* 1 = only first attempt, 2 = one retry, .. */
	u8 power_level;		/* per-packet transmit power level, in dBm */
	u8 antenna_sel_tx; 	/* 0 = default/diversity, 1 = Ant0, 2 = Ant1 */
	s8 key_idx;		/* -1 = do not encrypt, >= 0 keyidx from
				 * hw->set_key() */
	u8 icv_len;		/* length of the ICV/MIC field in octets */
	u8 iv_len;		/* length of the IV field in octets */
	u8 tkip_key[16];	/* generated phase2/phase1 key for hw TKIP */
	u8 queue;		/* hardware queue to use for this frame;
				 * 0 = highest, hw->queues-1 = lowest */
	u8 sw_retry_attempt;	/* number of times hw has tried to
				 * transmit frame (not incl. hw retries) */

	struct ieee80211_rate *rate;		/* internal 80211.o rate */
	struct ieee80211_rate *rts_rate;	/* internal 80211.o rate
						 * for RTS/CTS */
	int alt_retry_rate; /* retry rate for the last retries, given as the
			     * hw specific value for the rate (from
			     * struct ieee80211_rate). To be used to limit
			     * packet dropping when probing higher rates, if hw
			     * supports multiple retry rates. -1 = not used */
	int type;	/* internal */
	int ifindex;	/* internal */
};

struct ieee80211_tx_status {
    /* copied ieee80211_tx_control structure */
    struct ieee80211_tx_control control;
    
#define IEEE80211_TX_STATUS_TX_FILTERED (1<<0)
#define IEEE80211_TX_STATUS_ACK     (1<<1) /* whether the TX frame was ACKed */
    u32 flags;      /* tx staus flags defined above */
    
    int ack_signal; /* measured signal strength of the ACK frame */
    int excessive_retries;
    int retry_count;
    
    int queue_length;      /* information about TX queue */
    int queue_number;
};


struct ieee80211_tx_stored_packet {
	struct ieee80211_tx_control control;
	struct sk_buff *skb;
	int num_extra_frag;
	struct sk_buff **extra_frag;
	int last_frag_rateidx;
	int last_frag_hwrate;
	struct ieee80211_rate *last_frag_rate;
	unsigned int last_frag_rate_ctrl_probe:1;
};

#define IEEE80211_TX_OK		0
#define IEEE80211_TX_AGAIN	1
#define IEEE80211_TX_FRAG_AGAIN	2



struct ieee80211_passive_scan {
	unsigned int in_scan:1; /* this must be cleared before calling
     * netif_oper(WAKEUP) */
	unsigned int our_mode_only:1; /* only scan our physical mode a/b/g/etc
     */
	int interval; /* time in seconds between scans */
	int time; /* time in microseconds to scan for */
	int channel; /* channel to be scanned */
	int tries;
    
	struct ieee80211_hw_mode *mode;
	int chan_idx;
    
	int freq;
	int rx_packets;
	int rx_beacon;
	int txrx_count;
    
	struct timer_list2 timer;
    
	struct sk_buff *skb; /* skb to transmit before changing channels,
     * maybe null for none */
	struct ieee80211_tx_control tx_control;
    
	unsigned int num_scans;
};
typedef enum {
	TXRX_CONTINUE, TXRX_DROP, TXRX_QUEUED
} ieee80211_txrx_result;


struct ieee80211_txrx_data {
	struct sk_buff *skb;
	struct net_device *dev;
	struct ieee80211_local *local;
	struct ieee80211_sub_if_data *sdata;
	struct sta_info *sta;
	u16 fc, ethertype;
	struct ieee80211_key *key;
	unsigned int fragmented:1; /* whether the MSDU was fragmented */
	union {
		struct {
			struct ieee80211_tx_control *control;
			unsigned int unicast:1;
			unsigned int ps_buffered:1;
			unsigned int short_preamble:1;
			unsigned int probe_last_frag:1;
			struct ieee80211_hw_mode *mode;
			struct ieee80211_rate *rate;
			/* use this rate (if set) for last fragment; rate can
			 * be set to lower rate for the first fragments, e.g.,
			 * when using CTS protection with IEEE 802.11g. */
			struct ieee80211_rate *last_frag_rate;
			int last_frag_hwrate;
			int mgmt_interface;

			/* Extra fragments (in addition to the first fragment
			 * in skb) */
			int num_extra_frag;
			struct sk_buff **extra_frag;
		} tx;
		struct {
			struct ieee80211_rx_status *status;
			int sent_ps_buffered;
			int queue;
			int load;
			u16 qos_control;
			unsigned int in_scan:1;
			/* frame is destined to interface currently processed
			 * (including multicast frames) */
			unsigned int ra_match:1;
			unsigned int is_agg_frame:1;
		} rx;
	} u;
};

typedef ieee80211_txrx_result (*ieee80211_tx_handler)(struct ieee80211_txrx_data *tx);
typedef ieee80211_txrx_result (*ieee80211_rx_handler)(struct ieee80211_txrx_data *rx);

//SKB
struct sk_buff_head {
         /* These two members must be first. */
         struct sk_buff  *next;
         struct sk_buff  *prev;
 
         __u32           qlen;
         spinlock_t      lock;
};

struct ieee80211_local {
	/* embed the driver visible part.
	 * don't cast (use the static inlines below), but we keep
	 * it first anyway so they become a no-op */
	struct ieee80211_hw hw;
    
	const struct ieee80211_ops *ops;
    
	/* List of registered struct ieee80211_hw_mode */
	struct list_head modes_list;
    
	struct net_device *mdev; /* wmaster# - "master" 802.11 device */
	struct net_device *apdev; /* wlan#ap - management frames (hostapd) */
	int open_count;
	int monitors;
	struct iw_statistics wstats;
	u8 wstats_flags;
    int tx_headroom; /* required headroom for hardware/radiotap */
	
	enum {
		IEEE80211_DEV_UNINITIALIZED = 0,
		IEEE80211_DEV_REGISTERED,
		IEEE80211_DEV_UNREGISTERED,
	} reg_state;
	
	/* Tasklet and skb queue to process calls from IRQ mode. All frames
	 * added to skb_queue will be processed, but frames in
	 * skb_queue_unreliable may be dropped if the total length of these
	 * queues increases over the limit. */
	 struct tasklet_struct tasklet;
	 struct tasklet_struct tx_pending_tasklet;
	 
#define IEEE80211_IRQSAFE_QUEUE_LIMIT 128
	struct sk_buff_head skb_queue;
	struct sk_buff_head skb_queue_unreliable;
	enum {
		ieee80211_rx_msg = 1,
		ieee80211_tx_status_msg = 2
	} ieee80211_msg_enum;
    
	/* Station data structures */
//	struct kset sta_kset;
	spinlock_t sta_lock; /* mutex for STA data structures */
	int num_sta; /* number of stations in sta_list */
	struct list_head sta_list;
	struct list_head deleted_sta_list;
	struct sta_info *sta_hash[STA_HASH_SIZE];
	struct timer_list2 sta_cleanup;
    
	unsigned long state[NUM_TX_DATA_QUEUES];
	struct ieee80211_tx_stored_packet pending_packet[NUM_TX_DATA_QUEUES];
    
	int mc_count;	/* total count of multicast entries in all interfaces */
	int iff_allmultis, iff_promiscs;
    /* number of interfaces with corresponding IFF_ flags */
    
	/* Current rate table. This is a pointer to hw->modes structure. */
	struct ieee80211_rate *curr_rates;
	int num_curr_rates;
    
	struct rate_control_ref *rate_ctrl;
    
	int next_mode; /* MODE_IEEE80211*
     * The mode preference for next channel change. This is
     * used to select .11g vs. .11b channels (or 4.9 GHz vs.
     * .11a) when the channel number is not unique. */
    
	/* Supported and basic rate filters for different modes. These are
	 * pointers to -1 terminated lists and rates in 100 kbps units. */
	int *supp_rates[NUM_IEEE80211_MODES];
	int *basic_rates[NUM_IEEE80211_MODES];
    
	int rts_threshold;
	int cts_protect_erp_frames;
	int fragmentation_threshold;
	int short_retry_limit; /* dot11ShortRetryLimit */
	int long_retry_limit; /* dot11LongRetryLimit */
	int short_preamble; /* use short preamble with IEEE 802.11b */
    
	struct crypto_blkcipher *wep_tx_tfm;
	struct crypto_blkcipher *wep_rx_tfm;
	u32 wep_iv;
	int key_tx_rx_threshold; /* number of times any key can be used in TX
     * or RX before generating a rekey
     * notification; 0 = notification disabled. */
    
	int bridge_packets; /* bridge packets between associated stations and
     * deliver multicast frames both back to wireless
     * media and to the local net stack */
    
	struct ieee80211_passive_scan scan;
    
    
	ieee80211_rx_handler *rx_pre_handlers;
	ieee80211_rx_handler *rx_handlers;
	ieee80211_tx_handler *tx_handlers;
    
	spinlock_t sub_if_lock; /* mutex for STA data structures */
	struct list_head sub_if_list;
	int sta_scanning;
	int scan_channel_idx;
	//enum { SCAN_SET_CHANNEL, SCAN_SEND_PROBE } 
	int scan_state;
	unsigned long last_scan_completed;
	struct delayed_work scan_work;
	struct net_device *scan_dev;
	struct ieee80211_channel *oper_channel, *scan_channel;
	struct ieee80211_hw_mode *oper_hw_mode, *scan_hw_mode;
	u8 scan_ssid[IEEE80211_MAX_SSID_LEN];
	size_t scan_ssid_len;
	struct list_head sta_bss_list;
	struct ieee80211_sta_bss *sta_bss_hash[STA_HASH_SIZE];
	spinlock_t sta_bss_lock;
#define IEEE80211_SCAN_MATCH_SSID BIT(0)
#define IEEE80211_SCAN_WPA_ONLY BIT(1)
#define IEEE80211_SCAN_EXTRA_INFO BIT(2)
	int scan_flags;
    
#ifdef CONFIG_HOSTAPD_WPA_TESTING
	u32 wpa_trigger;
#endif /* CONFIG_HOSTAPD_WPA_TESTING */
	/* SNMP counters */
	/* dot11CountersTable */
	u32 dot11TransmittedFragmentCount;
	u32 dot11MulticastTransmittedFrameCount;
	u32 dot11FailedCount;
	u32 dot11RetryCount;
	u32 dot11MultipleRetryCount;
	u32 dot11FrameDuplicateCount;
	u32 dot11ReceivedFragmentCount;
	u32 dot11MulticastReceivedFrameCount;
	u32 dot11TransmittedFrameCount;
	u32 dot11WEPUndecryptableCount;
    
#ifdef CONFIG_MAC80211_LEDS
	int tx_led_counter, rx_led_counter;
	struct led_trigger *tx_led, *rx_led;
	char tx_led_name[32], rx_led_name[32];
#endif
    
	u32 channel_use;
	u32 channel_use_raw;
	u32 stat_time;
	struct timer_list2 stat_timer;
    
	struct work_struct sta_proc_add;
    
	enum {
		STA_ANTENNA_SEL_AUTO = 0,
		STA_ANTENNA_SEL_SW_CTRL = 1,
		STA_ANTENNA_SEL_SW_CTRL_DEBUG = 2
	} sta_antenna_sel;
    
	int rate_ctrl_num_up, rate_ctrl_num_down;
    
#ifdef CONFIG_MAC80211_DEBUG_COUNTERS
	/* TX/RX handler statistics */
	unsigned int tx_handlers_drop;
	unsigned int tx_handlers_queued;
	unsigned int tx_handlers_drop_unencrypted;
	unsigned int tx_handlers_drop_fragment;
	unsigned int tx_handlers_drop_wep;
	unsigned int tx_handlers_drop_not_assoc;
	unsigned int tx_handlers_drop_unauth_port;
	unsigned int rx_handlers_drop;
	unsigned int rx_handlers_queued;
	unsigned int rx_handlers_drop_nullfunc;
	unsigned int rx_handlers_drop_defrag;
	unsigned int rx_handlers_drop_short;
	unsigned int rx_handlers_drop_passive_scan;
	unsigned int tx_expand_skb_head;
	unsigned int tx_expand_skb_head_cloned;
	unsigned int rx_expand_skb_head;
	unsigned int rx_expand_skb_head2;
	unsigned int rx_handlers_fragments;
	unsigned int tx_status_drop;
	unsigned int wme_rx_queue[NUM_RX_DATA_QUEUES];
	unsigned int wme_tx_queue[NUM_RX_DATA_QUEUES];
#define I802_DEBUG_INC(c) (c)++
#else /* CONFIG_MAC80211_DEBUG_COUNTERS */
#define I802_DEBUG_INC(c) do { } while (0)
#endif /* CONFIG_MAC80211_DEBUG_COUNTERS */
    
    
	int default_wep_only; /* only default WEP keys are used with this
     * interface; this is used to decide when hwaccel
     * can be used with default keys */
	int total_ps_buffered; /* total number of all buffered unicast and
     * multicast packets for power saving stations
     */
	int allow_broadcast_always; /* whether to allow TX of broadcast frames
     * even when there are no associated STAs
     */
    
	int wifi_wme_noack_test;
	unsigned int wmm_acm; /* bit field of ACM bits (BIT(802.1D tag)) */
    
	unsigned int enabled_modes; /* bitfield of allowed modes;
     * (1 << MODE_*) */
	unsigned int hw_modes; /* bitfield of supported hardware modes;
     * (1 << MODE_*) */
    
	int user_space_mlme;
};







/* Parsed Information Elements */
struct ieee802_11_elems {
	/* pointers to IEs */
	u8 *ssid;
	u8 *supp_rates;
	u8 *fh_params;
	u8 *ds_params;
	u8 *cf_params;
	u8 *tim;
	u8 *ibss_params;
	u8 *challenge;
	u8 *wpa;
	u8 *rsn;
	u8 *erp_info;
	u8 *ext_supp_rates;
	u8 *wmm_info;
	u8 *wmm_param;

	/* length of them, respectively */
	u8 ssid_len;
	u8 supp_rates_len;
	u8 fh_params_len;
	u8 ds_params_len;
	u8 cf_params_len;
	u8 tim_len;
	u8 ibss_params_len;
	u8 challenge_len;
	u8 wpa_len;
	u8 rsn_len;
	u8 erp_info_len;
	u8 ext_supp_rates_len;
	u8 wmm_info_len;
	u8 wmm_param_len;
};

struct ieee80211_sta_bss {
	struct list_head list;
	struct ieee80211_sta_bss *hnext;
	atomic_t users;

	u8 bssid[ETH_ALEN];
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	size_t ssid_len;
	u16 capability; /* host byte order */
	int hw_mode;
	int channel;
	int freq;
	int rssi, signal, noise;
	u8 *wpa_ie;
	size_t wpa_ie_len;
	u8 *rsn_ie;
	size_t rsn_ie_len;
	u8 *wmm_ie;
	size_t wmm_ie_len;
#define IEEE80211_MAX_SUPP_RATES 32
	u8 supp_rates[IEEE80211_MAX_SUPP_RATES];
	size_t supp_rates_len;
	int beacon_int;
	u64 timestamp;

	int probe_resp;
	unsigned long last_update;

	/* during assocation, we save an ERP value from a probe response so
	 * that we can feed ERP info to the driver when handling the
	 * association completes. these fields probably won't be up-to-date
	 * otherwise, you probably don't want to use them. */
	int has_erp_value;
	u8 erp_value;
};


struct kref {
         atomic_t refcount;
          void (*release)(struct kref *kref);
  };
 
 struct dentry;
 
struct sta_info {
	struct kref kref;
	struct list_head list;
	struct sta_info *hnext; /* next entry in hash table list */

	struct ieee80211_local *local;

	u8 addr[ETH_ALEN];
	u16 aid; /* STA's unique AID (1..2007), 0 = not yet assigned */
	u32 flags; /* WLAN_STA_ */

	struct sk_buff_head ps_tx_buf; /* buffer of TX frames for station in
					* power saving state */
	int pspoll; /* whether STA has send a PS Poll frame */
	struct sk_buff_head tx_filtered; /* buffer of TX frames that were
					  * already given to low-level driver,
					  * but were filtered */
	int clear_dst_mask;

	unsigned long rx_packets, tx_packets; /* number of RX/TX MSDUs */
	unsigned long rx_bytes, tx_bytes;
	unsigned long tx_retry_failed, tx_retry_count;
	unsigned long tx_filtered_count;

	unsigned int wep_weak_iv_count; /* number of RX frames with weak IV */

	unsigned long last_rx;
	u32 supp_rates; /* bitmap of supported rates in local->curr_rates */
	int txrate; /* index in local->curr_rates */
	int last_txrate; /* last rate used to send a frame to this STA */
	int last_nonerp_idx;

	struct net_device *dev; /* which net device is this station associated
				 * to */

	struct ieee80211_key *key;

	u32 tx_num_consecutive_failures;
	u32 tx_num_mpdu_ok;
	u32 tx_num_mpdu_fail;

	struct rate_control_ref *rate_ctrl;
	void *rate_ctrl_priv;

	/* last received seq/frag number from this STA (per RX queue) */
	__le16 last_seq_ctrl[NUM_RX_DATA_QUEUES];
	unsigned long num_duplicates; /* number of duplicate frames received
				       * from this STA */
	unsigned long tx_fragments; /* number of transmitted MPDUs */
	unsigned long rx_fragments; /* number of received MPDUs */
	unsigned long rx_dropped; /* number of dropped MPDUs from this STA */

	int last_rssi; /* RSSI of last received frame from this STA */
	int last_signal; /* signal of last received frame from this STA */
	int last_noise; /* noise of last received frame from this STA */
	int last_ack_rssi[3]; /* RSSI of last received ACKs from this STA */
	unsigned long last_ack;
	int channel_use;
	int channel_use_raw;

	u8 antenna_sel_tx;
	u8 antenna_sel_rx;


	int key_idx_compression; /* key table index for compression and TX
				  * filtering; used only if sta->key is not
				  * set */

#ifdef CONFIG_MAC80211_DEBUGFS
	int debugfs_registered;
#endif
	int assoc_ap; /* whether this is an AP that we are
		       * associated with as a client */

#ifdef CONFIG_MAC80211_DEBUG_COUNTERS
	unsigned int wme_rx_queue[NUM_RX_DATA_QUEUES];
	unsigned int wme_tx_queue[NUM_RX_DATA_QUEUES];
#endif /* CONFIG_MAC80211_DEBUG_COUNTERS */

	int vlan_id;

	u16 listen_interval;

#ifdef CONFIG_MAC80211_DEBUGFS
	struct sta_info_debugfsdentries {
		struct dentry *dir;
		struct dentry *flags;
		struct dentry *num_ps_buf_frames;
		struct dentry *last_ack_rssi;
		struct dentry *last_ack_ms;
		struct dentry *inactive_ms;
		struct dentry *last_seq_ctrl;
#ifdef CONFIG_MAC80211_DEBUG_COUNTERS
		struct dentry *wme_rx_queue;
		struct dentry *wme_tx_queue;
#endif
	} debugfs;
#endif
};




struct rate_control_extra {
    /* values from rate_control_get_rate() to the caller: */
	struct ieee80211_rate *probe; /* probe with this rate, or NULL for no
				       * probing */
	struct ieee80211_rate *nonerp;

	/* parameters from the caller to rate_control_get_rate(): */
	struct ieee80211_hw_mode *mode;
	int mgmt_data; /* this is data frame that is used for management
			* (e.g., IEEE 802.1X EAPOL) */
	u16 ethertype;
};


struct rate_control_ops {
    struct module *module;
    const char *name;
    void (*tx_status)(void *priv, struct net_device *dev,
                      struct sk_buff *skb,
                      struct ieee80211_tx_status *status);
    struct ieee80211_rate *(*get_rate)(void *priv, struct net_device *dev,
                                       struct sk_buff *skb,
                                       struct rate_control_extra *extra);
    void (*rate_init)(void *priv, void *priv_sta,
                      struct ieee80211_local *local, struct sta_info *sta);
    void (*clear)(void *priv);
    
    void *(*alloc)(struct ieee80211_local *local);
    void (*free)(void *priv);
    void *(*alloc_sta)(void *priv, gfp_t gfp);
    void (*free_sta)(void *priv, void *priv_sta);
    
    int (*add_attrs)(void *priv, struct kobject *kobj);
    void (*remove_attrs)(void *priv, struct kobject *kobj);
    int (*add_sta_attrs)(void *priv, void *priv_sta,
                         struct kobject *kobj);
    void (*remove_sta_attrs)(void *priv, void *priv_sta,
                             struct kobject *kobj);
};


struct rate_control_ref {
    struct rate_control_ops *ops;
    void *priv;
    struct kref kref;
};



/* Receive status. The low-level driver should provide this information
 * (the subset supported by hardware) to the 802.11 code with each received
 * frame. */
struct ieee80211_rx_status {
    u64 mactime;
    int freq; /* receive frequency in Mhz */
    int channel;
    int phymode;
    int ssi;
    int signal; /* used as qual in statistics reporting */
    int noise;
    int antenna;
    int rate;
    int flag;
};


typedef enum { ALG_NONE, ALG_WEP, ALG_TKIP, ALG_CCMP, ALG_NULL } ieee80211_key_alg;
struct ieee80211_key_conf {
    
	int hw_key_idx;			/* filled + used by low-level driver */
	ieee80211_key_alg alg;
	int keylen;
    
#define IEEE80211_KEY_FORCE_SW_ENCRYPT (1<<0) /* to be cleared by low-level
driver */
#define IEEE80211_KEY_DEFAULT_TX_KEY   (1<<1) /* This key is the new default TX
key (used only for broadcast
keys). */
#define IEEE80211_KEY_DEFAULT_WEP_ONLY (1<<2) /* static WEP is the only
configured security policy;
this allows some low-level
drivers to determine when
hwaccel can be used */
	u32 flags; /* key configuration flags defined above */
    
	s8 keyidx;			/* WEP key index */
	u8 key[0];
};





/**
 * PCI_DEVICE - macro used to describe a specific pci device
 * @vend: the 16 bit PCI Vendor ID
 * @dev: the 16 bit PCI Device ID
 *
 * This macro is used to create a struct pci_device_id that matches a
 * specific device.  The subvendor and subdevice fields will be set to
 * PCI_ANY_ID.
 */
#define PCI_DEVICE(vend,dev) \
.vendor = (vend), .device = (dev), \
.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID

#define PCI_ANY_ID (~0)
#define PCI_VENDOR_ID_INTEL		0x8086

struct pci_device_id {
    __u32 vendor, device;       /* Vendor and device ID or PCI_ANY_ID*/
    __u32 subvendor, subdevice; /* Subsystem ID's or PCI_ANY_ID */
    __u32 classtype, class_mask;    /* (class,subclass,prog-if) triplet */
    void *driver_data; /* Data private to the driver */
};

#define MODULE_VERSION(x) 
#define MODULE_LICENSE(x)


#define ATOMIC_INIT(i)	{ (i) }
#define set_bit(x, y) setbit(y, x)

#define atomic_xchg(v, new) (xchg(&((v)->counter), new))
#define xchg(ptr,v) ((__typeof__(*(ptr)))__xchg((unsigned long)(v),(ptr),sizeof(*(ptr))))
struct __xchg_dummy { unsigned long a[100]; };
#define __xg(x) ((struct __xchg_dummy *)(x))
static inline unsigned long __xchg(unsigned long x, volatile void * ptr, int size)
{
    switch (size) {
        case 1:
            __asm__ __volatile__("xchgb %b0,%1"
                                 :"=q" (x)
                                 :"m" (*__xg(ptr)), "0" (x)
                                 :"memory");
            break;
        case 2:
            __asm__ __volatile__("xchgw %w0,%1"
                                 :"=r" (x)
                                 :"m" (*__xg(ptr)), "0" (x)
                                 :"memory");
            break;
        case 4:
            __asm__ __volatile__("xchgl %0,%1"
                                 :"=r" (x)
                                 :"m" (*__xg(ptr)), "0" (x)
                                 :"memory");
            break;
    }
    return x;
}

/**
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 * 
 * Atomically sets the value of @v to @i.
 */
#define atomic_set(v,i)     (((v)->counter) = (i))







/********** include/linux/list.h **********/
/*
 * These are non-NULL pointers that will result in page faults
 * under normal circumstances, used to verify that nobody uses
 * non-initialized list entries.
 */
#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

/**
 * list_entry - get the struct for this entry
 * @ptr:    the &struct list_head pointer.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) \
container_of(ptr, type, member)

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
    next->prev = prev;
    prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->next = (struct list_head *)LIST_POISON1;
    entry->prev = (struct list_head *)LIST_POISON2;
}


/**
 * __list_for_each  -   iterate over a list
 * @pos:    the &struct list_head to use as a loop cursor.
 * @head:   the head for your list.
 *
 * This variant differs from list_for_each() in that it's the
 * simplest possible list iteration code, no prefetching is done.
 * Use this for code that knows the list to be very short (empty
 * or 1 entry) most of the time.
 */
#define __list_for_each(pos, head) \
for (pos = (head)->next; pos != (head); pos = pos->next)


/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:    the &struct list_head to use as a loop cursor.
 * @n:      another &struct list_head to use as temporary storage
 * @head:   the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
for (pos = (head)->next, n = pos->next; pos != (head); \
pos = n, n = pos->next)






typedef int irqreturn_t;
#define IRQ_NONE    (0)
#define IRQ_HANDLED (1)
#define IRQ_RETVAL(x)   ((x) != 0)
typedef irqreturn_t (*irq_handler_t)(int, void *);




/**
 * struct ieee80211_if_init_conf - initial configuration of an interface
 *
 * @if_id: internal interface ID. This number has no particular meaning to
 *  drivers and the only allowed usage is to pass it to
 *  ieee80211_beacon_get() and ieee80211_get_buffered_bc() functions.
 *  This field is not valid for monitor interfaces
 *  (interfaces of %IEEE80211_IF_TYPE_MNTR type).
 * @type: one of &enum ieee80211_if_types constants. Determines the type of
 *  added/removed interface.
 * @mac_addr: pointer to MAC address of the interface. This pointer is valid
 *  until the interface is removed (i.e. it cannot be used after
 *  remove_interface() callback was called for this interface).
 *
 * This structure is used in add_interface() and remove_interface()
 * callbacks of &struct ieee80211_hw.
 */
struct ieee80211_if_init_conf {
    int if_id;
    int type;
    void *mac_addr;
};





/**
 * struct ieee80211_if_conf - configuration of an interface
 *
 * @type: type of the interface. This is always the same as was specified in
 *  &struct ieee80211_if_init_conf. The type of an interface never changes
 *  during the life of the interface; this field is present only for
 *  convenience.
 * @bssid: BSSID of the network we are associated to/creating.
 * @ssid: used (together with @ssid_len) by drivers for hardware that
 *  generate beacons independently. The pointer is valid only during the
 *  config_interface() call, so copy the value somewhere if you need
 *  it.
 * @ssid_len: length of the @ssid field.
 * @generic_elem: used (together with @generic_elem_len) by drivers for
 *  hardware that generate beacons independently. The pointer is valid
 *  only during the config_interface() call, so copy the value somewhere
 *  if you need it.
 * @generic_elem_len: length of the generic element.
 * @beacon: beacon template. Valid only if @host_gen_beacon_template in
 *  &struct ieee80211_hw is set. The driver is responsible of freeing
 *  the sk_buff.
 * @beacon_control: tx_control for the beacon template, this field is only
 *  valid when the @beacon field was set.
 *
 * This structure is passed to the config_interface() callback of
 * &struct ieee80211_hw.
 */
struct ieee80211_if_conf {
    int type;
    u8 *bssid;
    u8 *ssid;
    size_t ssid_len;
    u8 *generic_elem;
    size_t generic_elem_len;
    struct sk_buff *beacon;
    struct ieee80211_tx_control *beacon_control;
};





#define NUM_TX_DATA_QUEUES 6

struct ieee80211_tx_queue_stats_data {
    unsigned int len; /* num packets in queue */
    unsigned int limit; /* queue len (soft) limit */
    unsigned int count; /* total num frames sent */
};

struct ieee80211_tx_queue_stats {
    struct ieee80211_tx_queue_stats_data data[NUM_TX_DATA_QUEUES];
};




/* Indirect stringification.  Doing two levels allows the parameter to be a
 * macro itself.  For example, compile with -DFOO=bar, __stringify(FOO)
 * converts to "bar".
 */

#define __stringify_1(x)    #x
#define __stringify(x)      __stringify_1(x)

#define THIS_MODULE "me"
#define __ATTR(_name,_mode,_show,_store) { \
.attr = {.name = __stringify(_name), .mode = _mode, .owner = THIS_MODULE }, \
.show   = _show,                    \
.store  = _store,                   \
}


#define DEVICE_ATTR(_name,_mode,_show,_store) \
struct device_attribute dev_attr_##_name = __ATTR(_name,_mode,_show,_store)
#define S_IWUSR 0
#define S_IRUGO 0



struct attribute {
    const char      * name;
    char       * owner;
    mode_t          mode;
};
struct attribute_group {
    const char      * name;
    struct attribute    ** attrs;
};

/* interface for exporting device attributes */
struct device_attribute {
    struct attribute    attr;
    ssize_t (*show)(struct device *dev, struct device_attribute *attr,
                    char *buf);
    ssize_t (*store)(struct device *dev, struct device_attribute *attr,
                     const char *buf, size_t count);
};




struct ieee80211_scan_conf {
    int scan_channel;     /* IEEE 802.11 channel number to do passive scan
     * on */
    int scan_freq;  /* new freq in MHz to switch to for passive scan
     */
    int scan_channel_val; /* hw specific value for the channel */
    int scan_phymode;     /* MODE_IEEE80211A, .. */
    unsigned char scan_power_level;
    unsigned char scan_antenna_max;
    
    
    int running_channel; /* IEEE 802.11 channel number we operate on
     * normally */
    int running_freq;    /* freq in MHz we're operating on normally */
    int running_channel_val; /* hw specific value for the channel */
    int running_phymode;
    unsigned char running_power_level;
    unsigned char running_antenna_max;
    
    int scan_time;       /* time a scan will take in us */
    int tries;
    
    struct sk_buff *skb; /* skb to transmit before changing channels, maybe
     * NULL for none */
    struct ieee80211_tx_control *tx_control;
    
};



struct ieee80211_low_level_stats {
    unsigned int dot11ACKFailureCount;
    unsigned int dot11RTSFailureCount;
    unsigned int dot11FCSErrorCount;
    unsigned int dot11RTSSuccessCount;
};

struct ieee80211_tx_queue_params {
    int aifs; /* 0 .. 255; -1 = use default */
    int cw_min; /* 2^n-1: 1, 3, 7, .. , 1023; 0 = use default */
    int cw_max; /* 2^n-1: 1, 3, 7, .. , 1023; 0 = use default */
    int burst_time; /* maximum burst time in 0.1 ms (i.e., 10 = 1 ms);
     * 0 = disabled */
};




/* Configuration block used by the low-level driver to tell the 802.11 code
 * about supported hardware features and to pass function pointers to callback
 * functions. */
struct ieee80211_ops {
    /* Handler that 802.11 module calls for each transmitted frame.
     * skb contains the buffer starting from the IEEE 802.11 header.
     * The low-level driver should send the frame out based on
     * configuration in the TX control data. */
    int (*tx)(struct ieee80211_hw *hw, struct sk_buff *skb,
              struct ieee80211_tx_control *control);
    
    /* Handler for performing hardware reset. */
    int (*reset)(struct ieee80211_hw *hw);
    
    /* Handler that is called when any netdevice attached to the hardware
     * device is set UP for the first time. This can be used, e.g., to
     * enable interrupts and beacon sending. */
    int (*open)(struct ieee80211_hw *hw);
    
    /* Handler that is called when the last netdevice attached to the
     * hardware device is set DOWN. This can be used, e.g., to disable
     * interrupts and beacon sending. */
    int (*stop)(struct ieee80211_hw *hw);
    
    /* Handler for asking a driver if a new interface can be added (or,
     * more exactly, set UP). If the handler returns zero, the interface
     * is added. Driver should perform any initialization it needs prior
     * to returning zero. By returning non-zero addition of the interface
     * is inhibited. Unless monitor_during_oper is set, it is guaranteed
     * that monitor interfaces and normal interfaces are mutually
     * exclusive. The open() handler is called after add_interface()
     * if this is the first device added. At least one of the open()
     * open() and add_interface() callbacks has to be assigned. If
     * add_interface() is NULL, one STA interface is permitted only. */
    int (*add_interface)(struct ieee80211_hw *hw,
                         struct ieee80211_if_init_conf *conf);
    
    /* Notify a driver that an interface is going down. The stop() handler
     * is called prior to this if this is a last interface. */
    void (*remove_interface)(struct ieee80211_hw *hw,
                             struct ieee80211_if_init_conf *conf);
    
    /* Handler for configuration requests. IEEE 802.11 code calls this
     * function to change hardware configuration, e.g., channel. */
    int (*config)(struct ieee80211_hw *hw, struct ieee80211_conf *conf);
    
    /* Handler for configuration requests related to interfaces (e.g.
     * BSSID). */
    int (*config_interface)(struct ieee80211_hw *hw,
                            int if_id, struct ieee80211_if_conf *conf);
    
    /* ieee80211 drivers do not have access to the &struct net_device
     * that is (are) connected with their device. Hence (and because
     * we need to combine the multicast lists and flags for multiple
     * virtual interfaces), they cannot assign set_multicast_list.
     * The parameters here replace dev->flags and dev->mc_count,
     * dev->mc_list is replaced by calling ieee80211_get_mc_list_item. */
    void (*set_multicast_list)(struct ieee80211_hw *hw,
                               unsigned short flags, int mc_count);
    
    /* Set TIM bit handler. If the hardware/firmware takes care of beacon
     * generation, IEEE 802.11 code uses this function to tell the
     * low-level to set (or clear if set==0) TIM bit for the given aid. If
     * host system is used to generate beacons, this handler is not used
     * and low-level driver should set it to NULL. */
    int (*set_tim)(struct ieee80211_hw *hw, int aid, int set);
    
    /* Set encryption key. IEEE 802.11 module calls this function to set
     * encryption keys. addr is ff:ff:ff:ff:ff:ff for default keys and
     * station hwaddr for individual keys. aid of the station is given
     * to help low-level driver in selecting which key->hw_key_idx to use
     * for this key. TX control data will use the hw_key_idx selected by
     * the low-level driver. */
    int (*set_key)(struct ieee80211_hw *hw, set_key_cmd cmd,
                   u8 *addr, struct ieee80211_key_conf *key, int aid);
    
    /* Set TX key index for default/broadcast keys. This is needed in cases
     * where wlan card is doing full WEP/TKIP encapsulation (wep_include_iv
     * is not set), in other cases, this function pointer can be set to
     * NULL since the IEEE 802. 11 module takes care of selecting the key
     * index for each TX frame. */
    int (*set_key_idx)(struct ieee80211_hw *hw, int idx);
    
    /* Enable/disable IEEE 802.1X. This item requests wlan card to pass
     * unencrypted EAPOL-Key frames even when encryption is configured.
     * If the wlan card does not require such a configuration, this
     * function pointer can be set to NULL. */
    int (*set_ieee8021x)(struct ieee80211_hw *hw, int use_ieee8021x);
    
    /* Set port authorization state (IEEE 802.1X PAE) to be authorized
     * (authorized=1) or unauthorized (authorized=0). This function can be
     * used if the wlan hardware or low-level driver implements PAE.
     * 80211.o module will anyway filter frames based on authorization
     * state, so this function pointer can be NULL if low-level driver does
     * not require event notification about port state changes. */
    int (*set_port_auth)(struct ieee80211_hw *hw, u8 *addr,
                         int authorized);
    
    /* Ask the hardware to do a passive scan on a new channel. The hardware
     * will do what ever is required to nicely leave the current channel
     * including transmit any CTS packets, etc. */
    int (*passive_scan)(struct ieee80211_hw *hw, int state,
                        struct ieee80211_scan_conf *conf);
    
    /* Ask the hardware to service the scan request, no need to start
     * the scan state machine in stack. */
    int (*hw_scan)(struct ieee80211_hw *hw, u8 *ssid, size_t len);
    
    /* return low-level statistics */
    int (*get_stats)(struct ieee80211_hw *hw,
                     struct ieee80211_low_level_stats *stats);
    
    /* Enable/disable test modes; mode = IEEE80211_TEST_* */
    int (*test_mode)(struct ieee80211_hw *hw, int mode);
    
    /* Configuration of test parameters */
    int (*test_param)(struct ieee80211_hw *hw, int param, int value);
    
    /* For devices that generate their own beacons and probe response
     * or association responses this updates the state of privacy_invoked
     * returns 0 for success or an error number */
    int (*set_privacy_invoked)(struct ieee80211_hw *hw,
                               int privacy_invoked);
    
    /* For devices that have internal sequence counters, allow 802.11
     * code to access the current value of a counter */
    int (*get_sequence_counter)(struct ieee80211_hw *hw,
                                u8* addr, u8 keyidx, u8 txrx,
                                u32* iv32, u16* iv16);
    
    /* Configuration of RTS threshold (if device needs it) */
    int (*set_rts_threshold)(struct ieee80211_hw *hw, u32 value);
    
    /* Configuration of fragmentation threshold.
     * Assign this if the device does fragmentation by itself,
     * if this method is assigned then the stack will not do
     * fragmentation. */
    int (*set_frag_threshold)(struct ieee80211_hw *hw, u32 value);
    
    /* Configuration of retry limits (if device needs it) */
    int (*set_retry_limit)(struct ieee80211_hw *hw,
                           u32 short_retry, u32 long_retr);
    
    /* Number of STAs in STA table notification (NULL = disabled) */
    void (*sta_table_notification)(struct ieee80211_hw *hw,
                                   int num_sta);
    
    /* Configure TX queue parameters (EDCF (aifs, cw_min, cw_max),
     * bursting) for a hardware TX queue.
     * queue = IEEE80211_TX_QUEUE_*. */
    int (*conf_tx)(struct ieee80211_hw *hw, int queue,
                   const struct ieee80211_tx_queue_params *params);
    
    /* Get statistics of the current TX queue status. This is used to get
     * number of currently queued packets (queue length), maximum queue
     * size (limit), and total number of packets sent using each TX queue
     * (count). This information is used for WMM to find out which TX
     * queues have room for more packets and by hostapd to provide
     * statistics about the current queueing state to external programs. */
    int (*get_tx_stats)(struct ieee80211_hw *hw,
                        struct ieee80211_tx_queue_stats *stats);
    
    /* Get the current TSF timer value from firmware/hardware. Currently,
     * this is only used for IBSS mode debugging and, as such, is not a
     * required function. */
    u64 (*get_tsf)(struct ieee80211_hw *hw);
    
    /* Reset the TSF timer and allow firmware/hardware to synchronize with
     * other STAs in the IBSS. This is only used in IBSS mode. This
     * function is optional if the firmware/hardware takes full care of
     * TSF synchronization. */
    void (*reset_tsf)(struct ieee80211_hw *hw);
    
    /* Setup beacon data for IBSS beacons. Unlike access point (Master),
     * IBSS uses a fixed beacon frame which is configured using this
     * function. This handler is required only for IBSS mode. */
    int (*beacon_update)(struct ieee80211_hw *hw,
                         struct sk_buff *skb,
                         struct ieee80211_tx_control *control);
    
    /* Determine whether the last IBSS beacon was sent by us. This is
     * needed only for IBSS mode and the result of this function is used to
     * determine whether to reply to Probe Requests. */
    int (*tx_last_beacon)(struct ieee80211_hw *hw);
};



struct firmware {
	size_t size;
	//u8 data[0];
	u8 *data;
};




extern struct pci_device_id iwl4965_hw_card_ids[];
#define __devexit_p(x) x
#define module_param_named(w, x, y, z)
#define MODULE_PARM_DESC(x, y)
#define MODULE_DEVICE_TABLE(x, y)

struct device_driver;

struct pci_driver {
    struct list_head node;
    char *name;
    const struct pci_device_id *id_table;   /* must be non-NULL for probe to be called */
    int  (*probe)  (struct pci_dev *dev, const struct pci_device_id *id);   /* New device inserted */
    void (*remove) (struct pci_dev *dev);   /* Device removed (NULL if not a hot-plug capable driver) */
    int  (*suspend) (struct pci_dev *dev, void *state);  /* Device suspended */
    int  (*suspend_late) (struct pci_dev *dev, void *state);
    int  (*resume_early) (struct pci_dev *dev);
    int  (*resume) (struct pci_dev *dev);                   /* Device woken up */
    int  (*enable_wake) (struct pci_dev *dev, void *state, int enable);   /* Enable wake event */
    void (*shutdown) (struct pci_dev *dev);
    
//    struct pci_error_handlers *err_handler;
//    struct device_driver    driver;
//    struct pci_dynids dynids;
    
    int multithread_probe;
};




static struct ieee80211_hw * my_hw;

static inline struct ieee80211_local *hw_to_local(struct ieee80211_hw *hw)
{
    return container_of(hw, struct ieee80211_local, hw);
}

static inline struct ieee80211_local *wdev_priv(void *x)
{
	return hw_to_local(my_hw);
}

struct ieee80211_fragment_entry {
		unsigned long first_frag_time;
		unsigned int seq;
		unsigned int rx_queue;
		unsigned int last_frag;
		unsigned int extra_len;
		struct sk_buff_head skb_list;
		int ccmp; /* Whether fragments were encrypted with CCMP */
		u8 last_pn[6]; /* PN of the last fragment if CCMP was used */
};

struct sta_ts_data {
	enum {
		TS_STATUS_UNUSED	= 0,
		TS_STATUS_ACTIVE	= 1,
		TS_STATUS_INACTIVE	= 2,
		TS_STATUS_THROTTLING	= 3,
	} status;
	u8 dialog_token;
	u8 up;
	u32 admitted_time_usec;
	u32 used_time_usec;
};

#define IEEE80211_MAX_AID 2007
struct ieee80211_if_sta {
	enum ieee80211_state state;
	struct timer_list2 timer;
	struct work_struct work;
	struct timer_list2 admit_timer; /* Recompute EDCA admitted time */
	u8 bssid[ETH_ALEN], prev_bssid[ETH_ALEN];
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	size_t ssid_len;
	u16 aid;
	u16 ap_capab, capab;
	u8 *extra_ie; /* to be added to the end of AssocReq */
	size_t extra_ie_len;
	u8 nick[IW_ESSID_MAX_SIZE];

	/* The last AssocReq/Resp IEs */
	u8 *assocreq_ies, *assocresp_ies;
	size_t assocreq_ies_len, assocresp_ies_len;

	int auth_tries, assoc_tries;

	unsigned int ssid_set:1;
	unsigned int bssid_set:1;
	unsigned int prev_bssid_set:1;
	unsigned int authenticated:1;
	unsigned int associated:1;
	unsigned int probereq_poll:1;
	unsigned int create_ibss:1;
	unsigned int mixed_cell:1;
	unsigned int wmm_enabled:1;
	unsigned int ht_enabled:1;
	unsigned int auto_ssid_sel:1;
	unsigned int auto_bssid_sel:1;
	unsigned int auto_channel_sel:1;
#define IEEE80211_STA_REQ_SCAN 0
#define IEEE80211_STA_REQ_AUTH 1
#define IEEE80211_STA_REQ_RUN  2
	unsigned long request;
	struct sk_buff_head skb_queue;

	int key_mgmt;
	unsigned long last_probe;

#define IEEE80211_AUTH_ALG_OPEN BIT(0)
#define IEEE80211_AUTH_ALG_SHARED_KEY BIT(1)
#define IEEE80211_AUTH_ALG_LEAP BIT(2)
	unsigned int auth_algs; /* bitfield of allowed auth algs */
	int auth_alg; /* currently used IEEE 802.11 authentication algorithm */
	int auth_transaction;

	unsigned long ibss_join_req;
	struct sk_buff *probe_resp; /* ProbeResp template for IBSS */
	u32 supp_rates_bits;

	u32 last_rate; /* last tx data rate value. management and multi cast frame
			* wont be used. */

	int wmm_last_param_set;

	u32 dot11EDCAAveragingPeriod;
	u32 MPDUExchangeTime;
#define STA_TSID_NUM   16
#define STA_TSDIR_NUM  2
	/* EDCA: 0~7, HCCA: 8~15 */
	struct sta_ts_data ts_data[STA_TSID_NUM][STA_TSDIR_NUM];
#ifdef CONFIG_MAC80211_DEBUGFS
	struct ieee80211_elem_tspec tspec;
	u8 dls_mac[ETH_ALEN];
#endif
	struct ieee80211_channel *switch_channel;
};

struct ieee80211_if_ap {
	u8 *beacon_head, *beacon_tail;
	int beacon_head_len, beacon_tail_len;

	u8 ssid[IEEE80211_MAX_SSID_LEN];
	size_t ssid_len;
	u8 *generic_elem;
	size_t generic_elem_len;

	/* yes, this looks ugly, but guarantees that we can later use
	 * bitmap_empty :)
	 * NB: don't ever use set_bit, use bss_tim_set/bss_tim_clear! */
	u8 tim[sizeof(unsigned long) * (IEEE80211_MAX_AID + 1)];//BITS_TO_LONGS
	atomic_t num_sta_ps; /* number of stations in PS mode */
	struct sk_buff_head ps_bc_buf;
	int dtim_period, dtim_count;
	int force_unicast_rateidx; /* forced TX rateidx for unicast frames */
	int max_ratectrl_rateidx; /* max TX rateidx for rate control */
	int num_beacons; /* number of TXed beacon frames for this BSS */
};

struct ieee80211_if_wds {
	u8 remote_addr[ETH_ALEN];
	struct sta_info *sta;
};

struct ieee80211_if_vlan {
	u8 id;
};


#define IEEE80211_FRAGMENT_MAX 4
struct ieee80211_sub_if_data {
	struct list_head list;
	unsigned int type;

	void* wdev;

	struct net_device *dev;
	struct ieee80211_local *local;

	int mc_count;
	unsigned int allmulti:1;
	unsigned int promisc:1;
	unsigned int use_protection:1; /* CTS protect ERP frames */

	struct net_device_stats stats;
	int drop_unencrypted;
	int eapol; /* 0 = process EAPOL frames as normal data frames,
		    * 1 = send EAPOL frames through wlan#ap to hostapd
		    *     (default) */
	int ieee802_1x; /* IEEE 802.1X PAE - drop packet to/from unauthorized
			 * port */

	u16 sequence;

	/* Fragment table for host-based reassembly */
	struct ieee80211_fragment_entry	fragments[IEEE80211_FRAGMENT_MAX];
	unsigned int fragment_next;

#define NUM_DEFAULT_KEYS 4
	struct ieee80211_key *keys[NUM_DEFAULT_KEYS];
	struct ieee80211_key *default_key;

	struct ieee80211_if_ap *bss; /* BSS that this device belongs to */

	union {
		struct ieee80211_if_ap ap;
		struct ieee80211_if_wds wds;
		struct ieee80211_if_vlan vlan;
		struct ieee80211_if_sta sta;
	} u;
	int channel_use;
	int channel_use_raw;

#ifdef CONFIG_MAC80211_DEBUGFS
	struct dentry *debugfsdir;
	union {
		struct {
			struct dentry *channel_use;
			struct dentry *drop_unencrypted;
			struct dentry *eapol;
			struct dentry *ieee8021_x;
			struct dentry *state;
			struct dentry *bssid;
			struct dentry *prev_bssid;
			struct dentry *ssid_len;
			struct dentry *aid;
			struct dentry *ap_capab;
			struct dentry *capab;
			struct dentry *extra_ie_len;
			struct dentry *auth_tries;
			struct dentry *assoc_tries;
			struct dentry *auth_algs;
			struct dentry *auth_alg;
			struct dentry *auth_transaction;
			struct dentry *flags;
			struct dentry *qos_dir;
			struct {
				struct dentry *addts_11e;
				struct dentry *addts_wmm;
				struct dentry *delts_11e;
				struct dentry *delts_wmm;
				struct dentry *dls_mac;
				struct dentry *dls_op;
			} qos;
			struct dentry *tsinfo_dir;
			struct {
				struct dentry *tsid;
				struct dentry *direction;
				struct dentry *up;
			} tsinfo;
			struct dentry *tspec_dir;
			struct {
				struct dentry *nominal_msdu_size;
				struct dentry *max_msdu_size;
				struct dentry *min_service_interval;
				struct dentry *max_service_interval;
				struct dentry *inactivity_interval;
				struct dentry *suspension_interval;
				struct dentry *service_start_time;
				struct dentry *min_data_rate;
				struct dentry *mean_data_rate;
				struct dentry *peak_data_rate;
				struct dentry *burst_size;
				struct dentry *delay_bound;
				struct dentry *min_phy_rate;
				struct dentry *surplus_band_allow;
				struct dentry *medium_time;
			} tspec;
		} sta;
		struct {
			struct dentry *channel_use;
			struct dentry *drop_unencrypted;
			struct dentry *eapol;
			struct dentry *ieee8021_x;
			struct dentry *num_sta_ps;
			struct dentry *dtim_period;
			struct dentry *dtim_count;
			struct dentry *num_beacons;
			struct dentry *force_unicast_rateidx;
			struct dentry *max_ratectrl_rateidx;
			struct dentry *num_buffered_multicast;
			struct dentry *beacon_head_len;
			struct dentry *beacon_tail_len;
		} ap;
		struct {
			struct dentry *channel_use;
			struct dentry *drop_unencrypted;
			struct dentry *eapol;
			struct dentry *ieee8021_x;
			struct dentry *peer;
		} wds;
		struct {
			struct dentry *channel_use;
			struct dentry *drop_unencrypted;
			struct dentry *eapol;
			struct dentry *ieee8021_x;
			struct dentry *vlan_id;
		} vlan;
		struct {
			struct dentry *mode;
		} monitor;
		struct dentry *default_key;
	} debugfs;
#endif
};

#define INIT_DELAYED_WORK(_work, _func, _number)             \
do {                            \
INIT_WORK(&(_work)->work, (_func), _number);     \
} while (0)

#define INIT_WORK(_work, _func,p_number)                 \
do {                            \
PREPARE_WORK((_work), (_func));         \
(_work)->number=p_number;\
} while (0)

#define PREPARE_WORK(_work, _func)              \
do {                            \
(_work)->func = (_func);            \
} while (0)



# define do_div(n,base) ({                  \
uint32_t __base = (base);               \
uint32_t __rem;                     \
__rem = ((uint64_t)(n)) % __base;           \
(n) = ((uint64_t)(n)) / __base;             \
__rem;                          \
})


#define abs(x) ({               \
int __x = (x);          \
(__x < 0) ? -__x : __x;     \
})



#define net_ratelimit() 0


// This magic allows us to call init() and exit(), despite them being declared static
#define module_init(func) int (*init_routine)(void) = func
#define module_exit(func) void (*exit_routine)(void) = func
#define module_associated(func) int (*is_associated)(struct iwl4965_priv *priv) = func
#define module_mac_tx(func) int (*mac_tx)(struct ieee80211_hw *, struct sk_buff *,struct ieee80211_tx_control *) = func
//for up and down the card
#define module_down(func) void (*iwl_down)(struct iwl4965_priv *)=func
#define module_up(func) void (*iwl_up)(struct iwl4965_priv *)=func
#define module_scan(func) void (*iwl_scan)(struct iwl4965_priv *)=func
#define module_iwlready(func) int (*iwlready)(struct iwl4965_priv *)=func




// If we could figure out how to get this to work, we could run nigh-unmodified
// vesions of the Linux code.
// #define skb->data   mbuf_data(skb->mac_data)
// #define skb->len    mbuf_len(skb->mac_data)



/**
 * wait_event_interruptible_timeout - sleep until a condition gets true or a timeout elapses
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function returns 0 if the @timeout elapsed, -ERESTARTSYS if it
 * was interrupted by a signal, and the remaining jiffies otherwise
 * if the condition evaluated to true before the timeout elapsed.
 */
#define wait_event_interruptible_timeout(wq, condition, timeout)    \
({                                      \
long __ret = timeout;                 \
while(!(condition)) {                   \
    IOSleep(1);                    \
    __ret--;                            \
    if(ret==0)                          \
        break;                          \
}                                       \
__ret;                                  \
})



// Fix up brokenness from k_compat.h
#undef readl
#undef writel
#define readl(addr) OSReadLittleInt32(addr, 0)
#define writel(value, addr) OSWriteLittleInt32(addr, 0, value)
//#define IOPCCardAddTimer(x) q
#define DEBUG(level,...) IOLog(__VA_ARGS__)
#undef add_timer
#undef del_timer
#undef mod_timer	
#define BIT(x) (1UL << (x))



#define cpu_to_be64(x) OSSwapHostToBigInt64(x)
#define cpu_to_be32(x) OSSwapHostToBigInt32(x)

enum ieee80211_phytype {
	ieee80211_phytype_fhss_dot11_97  = 1,
	ieee80211_phytype_dsss_dot11_97  = 2,
	ieee80211_phytype_irbaseband     = 3,
	ieee80211_phytype_dsss_dot11_b   = 4,
	ieee80211_phytype_pbcc_dot11_b   = 5,
	ieee80211_phytype_ofdm_dot11_g   = 6,
	ieee80211_phytype_pbcc_dot11_g   = 7,
	ieee80211_phytype_ofdm_dot11_a   = 8,
	ieee80211_phytype_dsss_dot11_turbog = 255,
	ieee80211_phytype_dsss_dot11_turbo = 256,
};


enum ieee80211_ssi_type {
	ieee80211_ssi_none = 0,
	ieee80211_ssi_norm = 1, /* normalized, 0-1000 */
	ieee80211_ssi_dbm = 2,
	ieee80211_ssi_raw = 3, /* raw SSI */
};

#define IEEE80211_FI_VERSION 0x80211001

#define HW_KEY_IDX_INVALID -1

/*#undef wait_queue
typedef struct __wait_queue_head wait_queue_head_t;
#undef init_waitqueue_head
static inline void init_waitqueue_head(wait_queue_head_t *q)
{
		spin_lock_init(&q->lock);
		INIT_LIST_HEAD(&q->task_list);
}
*/

 #define PACKET_HOST             0               /* To us                */
  #define PACKET_BROADCAST        1               /* To all               */
  #define PACKET_MULTICAST        2               /* To group             */
  #define PACKET_OTHERHOST        3               /* To someone else      */
  #define PACKET_OUTGOING         4               /* Outgoing of any type */
  /* These ones are invisible by user level */
  #define PACKET_LOOPBACK         5               /* MC/BRD frame looped back */
  #define PACKET_FASTROUTE        6               /* Fastrouted frame     */
 
 #define CHAN_UTIL_RATE_LCM 95040
 #define WLAN_STA_PS BIT(2)
 
 #define IEEE80211_HW_DEFAULT_REG_DOMAIN_CONFIGURED (1<<11)

/* Stored in sk_buff->cb */
struct ieee80211_tx_packet_data {
	int ifindex;
	unsigned long jiffiess;
	unsigned int req_tx_status:1;
	unsigned int do_not_encrypt:1;
	unsigned int requeue:1;
	unsigned int mgmt_iface:1;
	unsigned int queue:4;
	unsigned int ht_queue:1;
};

struct ieee80211_msg_key_notification {
	int tx_rx_count;
	char ifname[IFNAMSIZ];
	u8 addr[ETH_ALEN]; /* ff:ff:ff:ff:ff:ff for broadcast keys */
};

#define NUM_RX_DATA_QUEUES 17

struct ieee80211_key {
	struct kref kref;

	int hw_key_idx; /* filled and used by low-level driver */
	ieee80211_key_alg alg;
	union {
		struct {
			/* last used TSC */
			u32 iv32;
			u16 iv16;
			u16 p1k[5];
			int tx_initialized;

			/* last received RSC */
			u32 iv32_rx[NUM_RX_DATA_QUEUES];
			u16 iv16_rx[NUM_RX_DATA_QUEUES];
			u16 p1k_rx[NUM_RX_DATA_QUEUES][5];
			int rx_initialized[NUM_RX_DATA_QUEUES];
		} tkip;
		struct {
			u8 tx_pn[6];
			u8 rx_pn[NUM_RX_DATA_QUEUES][6];
			struct crypto_cipher *tfm;
			u32 replays; /* dot11RSNAStatsCCMPReplays */
			/* scratch buffers for virt_to_page() (crypto API) */
#ifndef AES_BLOCK_LEN
#define AES_BLOCK_LEN 16
#endif
			u8 tx_crypto_buf[6 * AES_BLOCK_LEN];
			u8 rx_crypto_buf[6 * AES_BLOCK_LEN];
		} ccmp;
	} u;
	int tx_rx_count; /* number of times this key has been used */
	int keylen;

	/* if the low level driver can provide hardware acceleration it should
	 * clear this flag */
	unsigned int force_sw_encrypt:1;
	unsigned int default_tx_key:1; /* This key is the new default TX key
					* (used only for broadcast keys). */
	s8 keyidx; /* WEP key index */

#ifdef CONFIG_MAC80211_DEBUGFS
	struct {
		struct dentry *stalink;
		struct dentry *dir;
		struct dentry *keylen;
		struct dentry *force_sw_encrypt;
		struct dentry *keyidx;
		struct dentry *hw_key_idx;
		struct dentry *tx_rx_count;
		struct dentry *algorithm;
		struct dentry *tx_spec;
		struct dentry *rx_spec;
		struct dentry *replays;
		struct dentry *key;
	} debugfs;
#endif

	u8 key[0];
};

#define IEEE80211_AUTH_TIMEOUT (HZ / 5)
#define IEEE80211_AUTH_MAX_TRIES 3
#define IEEE80211_ASSOC_TIMEOUT (HZ / 5)
#define IEEE80211_ASSOC_MAX_TRIES 3
#define IEEE80211_MONITORING_INTERVAL (2 * HZ)
#define IEEE80211_PROBE_INTERVAL (60 * HZ)
#define IEEE80211_RETRY_AUTH_INTERVAL (1 * HZ)
#define IEEE80211_SCAN_INTERVAL (2 * HZ)
#define IEEE80211_SCAN_INTERVAL_SLOW (15 * HZ)
#define IEEE80211_IBSS_JOIN_TIMEOUT (20 * HZ)

#define IEEE80211_PROBE_DELAY (HZ / 33)
#define IEEE80211_CHANNEL_TIME (HZ / 33)
#define IEEE80211_PASSIVE_CHANNEL_TIME (HZ / 5)
#define IEEE80211_SCAN_RESULT_EXPIRE (10 * HZ)
#define IEEE80211_IBSS_MERGE_INTERVAL (30 * HZ)
#define IEEE80211_IBSS_INACTIVITY_LIMIT (60 * HZ)

#define IEEE80211_IBSS_MAX_STA_ENTRIES 128


#define IEEE80211_FC(type, stype) cpu_to_le16(type | stype)

#define ERP_INFO_USE_PROTECTION BIT(1)

enum {
	IEEE80211_KEY_MGMT_NONE = 0,
	IEEE80211_KEY_MGMT_IEEE8021X = 1,
	IEEE80211_KEY_MGMT_WPA_PSK = 2,
	IEEE80211_KEY_MGMT_WPA_EAP = 3,
};

/* Stations flags (struct sta_info::flags) */
#define WLAN_STA_AUTH BIT(0)
#define WLAN_STA_ASSOC BIT(1)
#define WLAN_STA_PS BIT(2)
#define WLAN_STA_TIM BIT(3) /* TIM bit is on for PS stations */
#define WLAN_STA_PERM BIT(4) /* permanent; do not remove entry on expiration */
#define WLAN_STA_AUTHORIZED BIT(5) /* If 802.1X is used, this flag is
				    * controlling whether STA is authorized to
				    * send and receive non-IEEE 802.1X frames
				    */
#define WLAN_STA_SHORT_PREAMBLE BIT(7)
#define WLAN_STA_WME BIT(9)
#define WLAN_STA_WDS BIT(27)

#define IW_CUSTOM_MAX 256

//FIXME: !!
enum ieee80211_tx_queue {
	IEEE80211_TX_QUEUE_DATA0,
	IEEE80211_TX_QUEUE_DATA1,
	IEEE80211_TX_QUEUE_DATA2,
	IEEE80211_TX_QUEUE_DATA3,
	IEEE80211_TX_QUEUE_DATA4,
	IEEE80211_TX_QUEUE_SVP,

	NUM_TX_DATA_QUEUES_F,

/* due to stupidity in the sub-ioctl userspace interface, the items in
 * this struct need to have fixed values. As soon as it is removed, we can
 * fix these entries. */
	IEEE80211_TX_QUEUE_AFTER_BEACON = 6,
	IEEE80211_TX_QUEUE_BEACON = 7
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#undef LIST_HEAD
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static LIST_HEAD(rate_ctrl_algs);

struct rate_control_alg {
	struct list_head list;
	struct rate_control_ops *ops;
};

/* Least common multiple of the used rates (in 100 kbps). This is used to
 * calculate rate_inv values for each rate so that only integers are needed. */
#define CHAN_UTIL_RATE_LCM 95040
/* 1 usec is 1/8 * (95040/10) = 1188 */
#define CHAN_UTIL_PER_USEC 1188
/* Amount of bits to shift the result right to scale the total utilization
 * to values that will not wrap around 32-bit integers. */
#define CHAN_UTIL_SHIFT 9
/* Theoretical maximum of channel utilization counter in 10 ms (stat_time=1):
 * (CHAN_UTIL_PER_USEC * 10000) >> CHAN_UTIL_SHIFT = 23203. So dividing the
 * raw value with about 23 should give utilization in 10th of a percentage
 * (1/1000). However, utilization is only estimated and not all intervals
 * between frames etc. are calculated. 18 seems to give numbers that are closer
 * to the real maximum. */
#define CHAN_UTIL_PER_10MS 18
#define CHAN_UTIL_HDR_LONG (202 * CHAN_UTIL_PER_USEC)
#define CHAN_UTIL_HDR_SHORT (40 * CHAN_UTIL_PER_USEC)

static inline int identical_mac_addr_allowed(int type1, int type2)
{
	return (type1 == IEEE80211_IF_TYPE_MNTR ||
		type2 == IEEE80211_IF_TYPE_MNTR ||
		(type1 == IEEE80211_IF_TYPE_AP &&
		 type2 == IEEE80211_IF_TYPE_WDS) ||
		(type1 == IEEE80211_IF_TYPE_WDS &&
		 (type2 == IEEE80211_IF_TYPE_WDS ||
		  type2 == IEEE80211_IF_TYPE_AP)) ||
		(type1 == IEEE80211_IF_TYPE_AP &&
		 type2 == IEEE80211_IF_TYPE_VLAN) ||
		(type1 == IEEE80211_IF_TYPE_VLAN &&
		 (type2 == IEEE80211_IF_TYPE_AP ||
		  type2 == IEEE80211_IF_TYPE_VLAN)));
}

static u8 my_mac_addr[6];
#define kPCIPMCSR                   (pmPCICapPtr + 4)
#define IEEE80211_ENCRYPT_HEADROOM 8
#define IEEE80211_ENCRYPT_TAILROOM 12
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define TOTAL_MAX_TX_BUFFER 512
#define STA_MAX_TX_BUFFER 128
#define AP_MAX_BC_BUFFER 128
#define ETH_HLEN        14              /* Total octets in header.       */
#define WEP_IV_LEN 4
#define WEP_ICV_LEN 4 
#define TKIP_IV_LEN 8
#define TKIP_ICV_LEN 4

#define ALG_CCMP_KEY_LEN 16
#define CCMP_HDR_LEN 8
#define CCMP_MIC_LEN 8
#define IEEE80211_RADIOTAP_F_RX_BADFCS	0x0001	/* frame failed crc check */

/* For IEEE80211_RADIOTAP_TX_FLAGS */
#define IEEE80211_RADIOTAP_F_TX_FAIL	0x0001	/* failed due to excessive
						 * retries */
#define IEEE80211_RADIOTAP_F_TX_CTS	0x0002	/* used cts 'protection' */
#define IEEE80211_RADIOTAP_F_TX_RTS	0x0004	/* used rts/cts handshake */



//this must be last lines in file. the includes are broken
#include "compatibility.h"	

//os x 10.4
/*extern void mutex_init(struct mutex *new_mutex);
extern void mutex_lock(struct mutex *new_mutex);
extern void mutex_unlock(struct mutex *new_mutex);*/
#endif //__DEFINES_H__