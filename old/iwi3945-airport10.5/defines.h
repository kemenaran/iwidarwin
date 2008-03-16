#ifndef __DEFINES_H__
#define __DEFINES_H__


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



/*
#include <IOKit/assert.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/pci/IOPCIDevice.h>
//#include <IOKit/network/IONetworkController.h>
//#include <IOKit/network/IONetworkInterface.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/network/IOMbufMemoryCursor.h>
#include <libkern/OSByteOrder.h>
#include <IOKit/pccard/IOPCCard.h>
#include <IOKit/apple80211/IO80211Controller.h>
#include <IOKit/apple80211/IO80211Interface.h>
#include <IOKit/network/IOPacketQueue.h>
#include <IOKit/network/IONetworkMedium.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/assert.h>
#include <IOKit/IODataQueue.h>
*/


//#include <i386/locks.h>
#include <IOKit/pccard/k_compat.h>
#include <IOKit/IOLocks.h>


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


typedef signed int	s32;
typedef signed short	s16;
//typedef unsigned long long u64;
typedef signed long long s64;


//typedef u16 __u16;
//typedef unsigned long long __le64;
#define __bitwise 1


/* Force a compilation error if condition is true */
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define ETH_ALEN 6
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BUG() do { \
printk("BUG: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __FUNCTION__); \
panic("BUG!"); \
} while (0)
#define BUG_ON(condition) do { if (unlikely((condition)!=0)) BUG(); } while(0)



#define cpu_to_le16(x) le16_to_cpu(x)
#define cpu_to_le32(x) le32_to_cpu(x)
#define __constant_cpu_to_le32(x) cpu_to_le32(x)
#define __constant_cpu_to_le16(x) cpu_to_le16(x)
#define le64_to_cpu(x) OSSwapLittleToHostInt64(x)
#define cpu_to_le64(x) OSSwapHostToLittleInt64(x)


typedef IOPhysicalAddress dma_addr_t;




#define __must_check

struct p_dev {
    void *kobj; // Device of type IOPCIDevice.
};

struct pci_dev {
    unsigned long device;
    unsigned long subsystem_device;
    struct p_dev dev;
    void *irq;
};


struct kobject {
    void *ptr;
};

struct mutex {
    lck_mtx_t *lock;
};


struct work_struct;

struct tasklet_struct {
    int padding;
};

struct delayed_work;

struct net_device;

union iwreq_data {
    char a;
};

struct iw_request_info {
    int padding;
};

typedef enum {
    SET_KEY, DISABLE_KEY, REMOVE_ALL_KEYS,
} set_key_cmd;


struct ieee80211_hw;

#define KERN_WARNING "warning "
#define KERN_ERR "error "
#define KERN_CRIT "critical "


// Bit manipulation, rewritten to use mach routines
#define test_bit(x, y) isset(y, x)
#define clear_bit(x, y) clrbit(y, x)

//#define spin_lock_irqsave(lock, fl) //lck_spin_lock((lock)->slock+flags-flags)
//#define spin_unlock_irqrestore(lock, fl) //lck_spin_unlock(((lock)->slock)+flags-flags)
#define time_after(x, y) 1
#define jiffies_to_msecs(x) x
#define msecs_to_jiffies(x) x
#define wdev_priv(x) x

//#include "iwi3945.h"
#include "net/compat.h"
#include "net/ieee80211.h"
#include "net/ieee80211_radiotap.h"

struct sta_local;
struct ieee80211_tx_control;
struct ieee80211_tx_stored_packet;










struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);



struct work_struct {
    long data;
#define WORK_STRUCT_PENDING 0       /* T if work item pending execution */
#define WORK_STRUCT_NOAUTOREL 1     /* F if work item automatically released on 
exec */
#define WORK_STRUCT_FLAG_MASK (3UL)
#define WORK_STRUCT_WQ_DATA_MASK (~WORK_STRUCT_FLAG_MASK)
    struct list_head entry;
    work_func_t func;
};


struct delayed_work {
    struct work_struct work;
    struct timer_list timer;
};



struct workqueue_struct {
    char data[4];
};



struct ieee80211_tx_control {
    int tx_rate; /* Transmit rate, given as the hw specific value for the
     * rate (from struct ieee80211_rate) */
    int rts_cts_rate; /* Transmit rate for RTS/CTS frame, given as the hw
     * specific value for the rate (from
     * struct ieee80211_rate) */
    
#define IEEE80211_TXCTL_REQ_TX_STATUS   (1<<0)/* request TX status callback for
* this frame */
#define IEEE80211_TXCTL_DO_NOT_ENCRYPT  (1<<1) /* send this frame without
* encryption; e.g., for EAPOL
* frames */
#define IEEE80211_TXCTL_USE_RTS_CTS (1<<2) /* use RTS-CTS before sending
* frame */
#define IEEE80211_TXCTL_USE_CTS_PROTECT (1<<3) /* use CTS protection for the
* frame (e.g., for combined
* 802.11g / 802.11b networks) */
#define IEEE80211_TXCTL_NO_ACK      (1<<4) /* tell the low level not to
* wait for an ack */
#define IEEE80211_TXCTL_RATE_CTRL_PROBE (1<<5)
#define IEEE80211_TXCTL_CLEAR_DST_MASK  (1<<6)
#define IEEE80211_TXCTL_REQUEUE     (1<<7)
#define IEEE80211_TXCTL_FIRST_FRAGMENT  (1<<8) /* this is a first fragment of
* the frame */
#define IEEE80211_TXCTL_TKIP_NEW_PHASE1_KEY (1<<9)
    u32 flags;                 /* tx control flags defined
     * above */
    u8 retry_limit;     /* 1 = only first attempt, 2 = one retry, .. */
    u8 power_level;     /* per-packet transmit power level, in dBm */
    u8 antenna_sel_tx;  /* 0 = default/diversity, 1 = Ant0, 2 = Ant1 */
    s8 key_idx;     /* -1 = do not encrypt, >= 0 keyidx from
     * hw->set_key() */
    u8 icv_len;     /* length of the ICV/MIC field in octets */
    u8 iv_len;      /* length of the IV field in octets */
    u8 tkip_key[16];    /* generated phase2/phase1 key for hw TKIP */
    u8 queue;       /* hardware queue to use for this frame;
     * 0 = highest, hw->queues-1 = lowest */
    u8 sw_retry_attempt;    /* number of times hw has tried to
     * transmit frame (not incl. hw retries) */
    
    int rateidx;        /* internal 80211.o rateidx */
    int rts_rateidx;    /* internal 80211.o rateidx for RTS/CTS */
    int alt_retry_rate; /* retry rate for the last retries, given as the
     * hw specific value for the rate (from
     * struct ieee80211_rate). To be used to limit
     * packet dropping when probing higher rates, if hw
     * supports multiple retry rates. -1 = not used */
    int type;   /* internal */
    int ifindex;    /* internal */
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
	unsigned int last_frag_rate_ctrl_probe:1;
};





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
    
	struct timer_list timer;
    
	struct sk_buff *skb; /* skb to transmit before changing channels,
     * maybe null for none */
	struct ieee80211_tx_control tx_control;
    
	unsigned int num_scans;
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
    
	enum {
		IEEE80211_DEV_UNINITIALIZED = 0,
		IEEE80211_DEV_REGISTERED,
		IEEE80211_DEV_UNREGISTERED,
	} reg_state;
    
	/* Tasklet and skb queue to process calls from IRQ mode. All frames
	 * added to skb_queue will be processed, but frames in
	 * skb_queue_unreliable may be dropped if the total length of these
	 * queues increases over the limit. */
#define IEEE80211_IRQSAFE_QUEUE_LIMIT 128
	struct tasklet_struct tasklet;
//	struct sk_buff_head skb_queue;
//	struct sk_buff_head skb_queue_unreliable;
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
	struct timer_list sta_cleanup;
    
	unsigned long state[NUM_TX_DATA_QUEUES];
	struct ieee80211_tx_stored_packet pending_packet[NUM_TX_DATA_QUEUES];
	struct tasklet_struct tx_pending_tasklet;
    
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
    
    
//	ieee80211_rx_handler *rx_pre_handlers;
//	ieee80211_rx_handler *rx_handlers;
//	ieee80211_tx_handler *tx_handlers;
    
	spinlock_t sub_if_lock; /* mutex for STA data structures */
	struct list_head sub_if_list;
	int sta_scanning;
	int scan_channel_idx;
	enum { SCAN_SET_CHANNEL, SCAN_SEND_PROBE } scan_state;
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
	struct timer_list stat_timer;
    
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




struct sk_buff {
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





struct sta_info {
	struct list_head list;
//	struct kobject kobj;
	struct sta_info *hnext; /* next entry in hash table list */
    
	struct ieee80211_local *local;
    
	u8 addr[ETH_ALEN];
	u16 aid; /* STA's unique AID (1..2007), 0 = not yet assigned */
	u32 flags; /* WLAN_STA_ */
    
/*	struct sk_buff_head ps_tx_buf; // buffer of TX frames for station in
     * power saving state */
	int pspoll; /* whether STA has send a PS Poll frame */
/*	struct sk_buff_head tx_filtered; // buffer of TX frames that were
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
    
	unsigned int sysfs_registered:1;
	unsigned int assoc_ap:1; /* whether this is an AP that we are
     * associated with as a client */
    
#ifdef CONFIG_HOSTAPD_WPA_TESTING
	u32 wpa_trigger;
#endif /* CONFIG_HOSTAPD_WPA_TESTING */
    
#ifdef CONFIG_MAC80211_DEBUG_COUNTERS
	unsigned int wme_rx_queue[NUM_RX_DATA_QUEUES];
	unsigned int wme_tx_queue[NUM_RX_DATA_QUEUES];
#endif /* CONFIG_MAC80211_DEBUG_COUNTERS */
    
	int vlan_id;
    
	u16 listen_interval;
};





struct rate_control_extra {
    /* values from rate_control_get_rate() to the caller: */
    struct ieee80211_rate *probe; /* probe with this rate, or NULL for no
     * probing */
    int startidx, endidx, rateidx;
    struct ieee80211_rate *nonerp;
    int nonerp_idx;
    
    /* parameters from the caller to rate_control_get_rate(): */
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
//    struct kref kref;
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


typedef enum { ALG_NONE, ALG_WEP, ALG_TKIP, ALG_CCMP, ALG_NULL }
ieee80211_key_alg;
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



struct device {
    void *driver_data;
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
	u8 data[0];
};




extern struct pci_device_id iwl3945_hw_card_ids[];
#define __devexit_p(x) x
#define module_param_named(w, x, y, z)
#define MODULE_PARM_DESC(x, y)
#define MODULE_DEVICE_TABLE(x, y)

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






static inline struct ieee80211_local *hw_to_local(struct ieee80211_hw *hw)
{
    return container_of(hw, struct ieee80211_local, hw);
}




#define INIT_DELAYED_WORK(_work, _func)             \
do {                            \
INIT_WORK(&(_work)->work, (_func));     \
} while (0)
#define INIT_WORK(_work, _func)                 \
do {                            \
PREPARE_WORK((_work), (_func));         \
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

#include "compatibility.h"




// If we could figure out how to get this to work, we could run nigh-unmodified
// vesions of the Linux code.
// #define skb->data   mbuf_data(skb->mac_data)
// #define skb->len    mbuf_len(skb->mac_data)




#endif //__DEFINES_H__
