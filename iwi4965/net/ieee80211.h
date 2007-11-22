/*
 * Merged with mainline ieee80211.h in Aug 2004.  Original ieee802_11
 * remains copyright by the original authors
 *
 * Portions of the merged code are based on Host AP (software wireless
 * LAN access point) driver for Intersil Prism2/2.5/3.
 *
 * Copyright (c) 2001-2002, SSH Communications Security Corp and Jouni Malinen
 * <jkmaline@cc.hut.fi>
 * Copyright (c) 2002-2003, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * Adaption to a generic IEEE 802.11 stack by James Ketrenos
 * <jketreno@linux.intel.com>
 * Copyright (c) 2004-2005, Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 *
 * API Version History
 * 1.0.x -- Initial version
 * 1.1.x -- Added radiotap, QoS, TIM, ieee80211_geo APIs,
 *          various structure changes, and crypto API init method
 */
#ifndef IEEE80211_H
#define IEEE80211_H

typedef signed char s8;
typedef unsigned char u8; 
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;
typedef signed char __s8;
typedef unsigned char __u8;
typedef signed short __s16;
typedef unsigned short __u16;
typedef signed int __s32;
typedef unsigned int __u32;
typedef signed long long __s64;
typedef unsigned long long __u64;
#define __bitwise __attribute__((bitwise))
typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;

#ifdef __KERNEL__
#include <linux/netdevice.h>
#include <linux/if_ether.h>	/* ETH_ALEN */
#include <linux/kernel.h>	/* ARRAY_SIZE */
#include <linux/wireless.h>
#include <linux/if_arp.h>	/* ARPHRD_ETHER */
#include <net/iw_handler.h>	/* new driver API */
#endif

#include "ieee80211_crypt.h"
#include "ieee80211_radiotap.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
/* miscellaneous IEEE 802.11 constants */
#define IEEE80211_MAX_FRAG_THRESHOLD	2346
#define IEEE80211_MAX_RTS_THRESHOLD	2347
#define IEEE80211_MAX_AID		2007
#define IEEE80211_MAX_TIM_LEN		251
#define IEEE80211_MAX_DATA_LEN		2304
#define RATE_CONTROL_NUM_DOWN 20
#define RATE_CONTROL_NUM_UP   15

#ifndef __KERNEL__
typedef struct {
	volatile unsigned int slock;
#ifdef CONFIG_DEBUG_SPINLOCK
	unsigned magic;
#endif
#ifdef CONFIG_PREEMPT
	unsigned int break_lock;
#endif
} spinlock_t;

#define IW_MAX_SPY		8
#define IW_ESSID_MAX_SIZE	32
#define ETH_ALEN	6
struct	iw_quality
{
	__u8		qual;		/* link quality (%retries, SNR,
					   %missed beacons or better...) */
	__u8		level;		/* signal level (dBm) */
	__u8		noise;		/* noise level (dBm) */
	__u8		updated;	/* Flags to know if updated */
};
struct iw_spy_data
{
	/* --- Standard spy support --- */
	int			spy_number;
	u_char			spy_address[IW_MAX_SPY][ETH_ALEN];
	struct iw_quality	spy_stat[IW_MAX_SPY];
	/* --- Enhanced spy support (event) */
	struct iw_quality	spy_thr_low;	/* Low threshold */
	struct iw_quality	spy_thr_high;	/* High threshold */
	u_char			spy_thr_under[IW_MAX_SPY];
};
struct	iw_missed
{
	__u32		beacon;		/* Missed beacons/superframe */
};
struct	iw_discarded
{
	__u32		nwid;		/* Rx : Wrong nwid/essid */
	__u32		code;		/* Rx : Unable to code/decode (WEP) */
	__u32		fragment;	/* Rx : Can't perform MAC reassembly */
	__u32		retries;	/* Tx : Max MAC retries num reached */
	__u32		misc;		/* Others cases */
};
struct	iw_statistics
{
	__u16		status;		/* Status
					 * - device dependent for now */

	struct iw_quality	qual;		/* Quality of the link
						 * (instant/mean/max) */
	struct iw_discarded	discard;	/* Packet discarded counts */
	struct iw_missed	miss;		/* Packet missed counts */
};
#define	NETDEV_ALIGN		32
#define	NETDEV_ALIGN_CONST	(NETDEV_ALIGN - 1)
static void *netdev_priv(struct net_device *dev)
{
	return (char *)dev + ((sizeof(struct net_device*)+ NETDEV_ALIGN_CONST)& ~NETDEV_ALIGN_CONST);
}
struct net_device_stats
{
	unsigned long	rx_packets;		/* total packets received	*/
	unsigned long	tx_packets;		/* total packets transmitted	*/
	unsigned long	rx_bytes;		/* total bytes received 	*/
	unsigned long	tx_bytes;		/* total bytes transmitted	*/
	unsigned long	rx_errors;		/* bad packets received		*/
	unsigned long	tx_errors;		/* packet transmit problems	*/
	unsigned long	rx_dropped;		/* no space in linux buffers	*/
	unsigned long	tx_dropped;		/* no space available in linux	*/
	unsigned long	multicast;		/* multicast packets received	*/
	unsigned long	collisions;

	/* detailed rx_errors: */
	unsigned long	rx_length_errors;
	unsigned long	rx_over_errors;		/* receiver ring buff overflow	*/
	unsigned long	rx_crc_errors;		/* recved pkt with crc error	*/
	unsigned long	rx_frame_errors;	/* recv'd frame alignment error */
	unsigned long	rx_fifo_errors;		/* recv'r fifo overrun		*/
	unsigned long	rx_missed_errors;	/* receiver missed packet	*/

	/* detailed tx_errors */
	unsigned long	tx_aborted_errors;
	unsigned long	tx_carrier_errors;
	unsigned long	tx_fifo_errors;
	unsigned long	tx_heartbeat_errors;
	unsigned long	tx_window_errors;
	
	/* for cslip etc */
	unsigned long	rx_compressed;
	unsigned long	tx_compressed;
};
#define MAX_ADDR_LEN	32
struct hlist_node {
	struct hlist_node *next, **pprev;
};
#define HW_KEY_IDX_INVALID -1

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
						//* frame (e.g., for combined
						//* 802.11g / 802.11b networks) */
#define IEEE80211_TXCTL_NO_ACK		(1<<4) /* tell the low level not to
						* wait for an ack */
#define IEEE80211_TXCTL_RATE_CTRL_PROBE	(1<<5)
#define IEEE80211_TXCTL_CLEAR_DST_MASK	(1<<6)
#define IEEE80211_TXCTL_REQUEUE		(1<<7)
#define IEEE80211_TXCTL_FIRST_FRAGMENT	(1<<8) /* this is a first fragment of
						* the frame */
#define IEEE80211_TXCTL_TKIP_NEW_PHASE1_KEY (1<<9)
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

#define IEEE80211_TX_STATUS_TX_FILTERED	(1<<0)
#define IEEE80211_TX_STATUS_ACK		(1<<1) /* whether the TX frame was ACKed */
	u32 flags;		/* tx staus flags defined above */

	int ack_signal; /* measured signal strength of the ACK frame */
	int excessive_retries;
	int retry_count;

	int queue_length;      /* information about TX queue */
	int queue_number;
	
};
struct net_device
{
	void* ieee80211_ptr;
	/*
	 * This is the first field of the "visible" part of this structure
	 * (i.e. as seen by users in the "Space.c" file).  It is the name
	 * the interface.
	 */
	char			name[IFNAMSIZ];

	/*
	 *	I/O specific fields
	 *	FIXME: Merge these and struct ifmap into one
	 */
	unsigned long		mem_end;	/* shared mem end	*/
	unsigned long		mem_start;	/* shared mem start	*/
	unsigned long		base_addr;	/* device I/O address	*/
	unsigned int		irq;		/* device IRQ number	*/

	/*
	 *	Some hardware also needs these fields, but they are not
	 *	part of the usual set specified in Space.c.
	 */

	unsigned char		if_port;	/* Selectable AUI, TP,..*/
	unsigned char		dma;		/* DMA channel		*/

	unsigned long		state;

	struct net_device	*next;
	
	/* The device initialization function. Called only once. */

	/* ------- Fields preinitialized in Space.c finish here ------- */

	struct net_device	*next_sched;

	/* Interface index. Unique device identifier	*/
	int			ifindex;
	int			iflink;


	struct net_device_stats* (*get_stats)(struct net_device *dev);
	struct iw_statistics*	(*get_wireless_stats)(struct net_device *dev);

	/* List of functions to handle Wireless Extensions (instead of ioctl).
	 * See <net/iw_handler.h> for details. Jean II */
	const struct iw_handler_def *	wireless_handlers;
	/* Instance data managed by the core of Wireless Extensions. */
	struct iw_public_data *	wireless_data;

	struct ethtool_ops *ethtool_ops;

	/*
	 * This marks the end of the "visible" part of the structure. All
	 * fields hereafter are internal to the system, and may change at
	 * will (read: may be cleaned up at will).
	 */

	/* These may be needed for future network-power-down code. */
	unsigned long		trans_start;	/* Time (in jiffies) of last Tx	*/
	unsigned long		last_rx;	/* Time of last Rx	*/

	unsigned short		flags;	/* interface flags (a la BSD)	*/
	unsigned short		gflags;
        unsigned short          priv_flags; /* Like 'flags' but invisible to userspace. */
	unsigned short		padded;	/* How much padding added by alloc_netdev() */

	unsigned		mtu;	/* interface MTU value		*/
	unsigned short		type;	/* interface hardware type	*/
	unsigned short		hard_header_len;	/* hardware hdr length	*/
	void			*priv;	/* pointer to private data	*/

	struct net_device	*master; /* Pointer to master device of a group,
					  * which this device is member of.
					  */

	/* Interface address info. */
	unsigned char		broadcast[MAX_ADDR_LEN];	/* hw bcast add	*/
	unsigned char		dev_addr[MAX_ADDR_LEN];	/* hw address	*/
	unsigned char		addr_len;	/* hardware address length	*/
	unsigned short          dev_id;		/* for shared network cards */

	struct dev_mc_list	*mc_list;	/* Multicast mac addresses	*/
	int			mc_count;	/* Number of installed mcasts	*/
	int			promiscuity;
	int			allmulti;

	int			watchdog_timeo;
	struct timer_list	watchdog_timer;

	/* Protocol specific pointers */
	
	void 			*atalk_ptr;	/* AppleTalk link 	*/
	void			*ip_ptr;	/* IPv4 specific data	*/  
	void                    *dn_ptr;        /* DECnet specific data */
	void                    *ip6_ptr;       /* IPv6 specific data */
	void			*ec_ptr;	/* Econet specific data	*/
	void			*ax25_ptr;	/* AX.25 specific data */

	struct list_head	poll_list;	/* Link to poll list	*/
	int			quota;
	int			weight;

	struct Qdisc		*qdisc;
	struct Qdisc		*qdisc_sleeping;
	struct Qdisc		*qdisc_ingress;
	struct list_head	qdisc_list;
	unsigned long		tx_queue_len;	/* Max frames per queue allowed */

	/* ingress path synchronizer */
	spinlock_t		ingress_lock;
	/* hard_start_xmit synchronizer */
	spinlock_t		xmit_lock;
	/* cpu id of processor entered to hard_start_xmit or -1,
	   if nobody entered there.
	 */
	int			xmit_lock_owner;
	/* device queue lock */
	spinlock_t		queue_lock;
	/* Number of references to this device */
	atomic_t		refcnt;
	/* delayed register/unregister */
	struct list_head	todo_list;
	/* device name hash chain */
	struct hlist_node	name_hlist;
	/* device index hash chain */
	struct hlist_node	index_hlist;

	/* register/unregister state machine */
	enum { NETREG_UNINITIALIZED=0,
	       NETREG_REGISTERING,	/* called register_netdevice */
	       NETREG_REGISTERED,	/* completed register todo */
	       NETREG_UNREGISTERING,	/* called unregister_netdevice */
	       NETREG_UNREGISTERED,	/* completed unregister todo */
	       NETREG_RELEASED,		/* called free_netdev */
	} reg_state;

	/* Net device features */
	unsigned long		features;
#define NETIF_F_SG		1	/* Scatter/gather IO. */
#define NETIF_F_IP_CSUM		2	/* Can checksum only TCP/UDP over IPv4. */
#define NETIF_F_NO_CSUM		4	/* Does not require checksum. F.e. loopack. */
#define NETIF_F_HW_CSUM		8	/* Can checksum all the packets. */
#define NETIF_F_HIGHDMA		32	/* Can DMA to high memory. */
#define NETIF_F_FRAGLIST	64	/* Scatter/gather IO. */
#define NETIF_F_HW_VLAN_TX	128	/* Transmit VLAN hw acceleration */
#define NETIF_F_HW_VLAN_RX	256	/* Receive VLAN hw acceleration */
#define NETIF_F_HW_VLAN_FILTER	512	/* Receive filtering on VLAN */
#define NETIF_F_VLAN_CHALLENGED	1024	/* Device cannot handle VLAN packets */
#define NETIF_F_TSO		2048	/* Can offload TCP/IP segmentation */
#define NETIF_F_LLTX		4096	/* LockLess TX */

	struct netpoll		*np;
	/* bridge stuff */
	struct net_bridge_port	*br_port;

	/* this will get initialized at each interface type init routine */
	struct divert_blk	*divert;
	/* class/net/name entry */
	//struct class_device	class_dev;
};
#endif

#define IEEE80211_VERSION_MAJOR 1
#define IEEE80211_VERSION_API 2
#define IEEE80211_VERSION_MINOR 15
#define IEEE80211_VERSION_CODE IEEE80211_VERSION_MAJOR * 65536 + \
			       IEEE80211_VERSION_API * 256 + \
			       IEEE80211_VERSION_MINOR
#define _STRX(x) #x
#define _VERSION_STR(a,b,c) _STRX(a) "." _STRX(b) "." _STRX(c)
#define IEEE80211_VERSION _VERSION_STR(IEEE80211_VERSION_MAJOR,\
				       IEEE80211_VERSION_API, \
				       IEEE80211_VERSION_MINOR)

#define IEEE80211_DATA_LEN		2304
/* Maximum size for the MA-UNITDATA primitive, 802.11 standard section
   6.2.1.1.2.

   The figure in section 7.1.2 suggests a body size of up to 2312
   bytes is allowed, which is a bit confusing, I suspect this
   represents the 2304 bytes of real data, plus a possible 8 bytes of
   WEP IV and ICV. (this interpretation suggested by Ramiro Barreiro) */

#define IEEE80211_1ADDR_LEN 10
#define IEEE80211_2ADDR_LEN 16
#define IEEE80211_3ADDR_LEN 24
#define IEEE80211_4ADDR_LEN 30
#define IEEE80211_FCS_LEN    4
#define IEEE80211_HLEN			(IEEE80211_4ADDR_LEN)
#define IEEE80211_FRAME_LEN		(IEEE80211_DATA_LEN + IEEE80211_HLEN)

#define MIN_FRAG_THRESHOLD     256U
#define	MAX_FRAG_THRESHOLD     2346U

/* Frame control field constants */
#define IEEE80211_FCTL_VERS		0x0003
#define IEEE80211_FCTL_FTYPE		0x000c
#define IEEE80211_FCTL_STYPE		0x00f0
#define IEEE80211_FCTL_TODS		0x0100
#define IEEE80211_FCTL_FROMDS		0x0200
#define IEEE80211_FCTL_MOREFRAGS	0x0400
#define IEEE80211_FCTL_RETRY		0x0800
#define IEEE80211_FCTL_PM		0x1000
#define IEEE80211_FCTL_MOREDATA		0x2000
#define IEEE80211_FCTL_PROTECTED	0x4000
#define IEEE80211_FCTL_ORDER		0x8000

#define IEEE80211_FTYPE_MGMT		0x0000
#define IEEE80211_FTYPE_CTL		0x0004
#define IEEE80211_FTYPE_DATA		0x0008

/* management */
#define IEEE80211_STYPE_ASSOC_REQ	0x0000
#define IEEE80211_STYPE_ASSOC_RESP 	0x0010
#define IEEE80211_STYPE_REASSOC_REQ	0x0020
#define IEEE80211_STYPE_REASSOC_RESP	0x0030
#define IEEE80211_STYPE_PROBE_REQ	0x0040
#define IEEE80211_STYPE_PROBE_RESP	0x0050
#define IEEE80211_STYPE_BEACON		0x0080
#define IEEE80211_STYPE_ATIM		0x0090
#define IEEE80211_STYPE_DISASSOC	0x00A0
#define IEEE80211_STYPE_AUTH		0x00B0
#define IEEE80211_STYPE_DEAUTH		0x00C0
#define IEEE80211_STYPE_ACTION		0x00D0

/* control */
#define IEEE80211_STYPE_PSPOLL		0x00A0
#define IEEE80211_STYPE_RTS		0x00B0
#define IEEE80211_STYPE_CTS		0x00C0
#define IEEE80211_STYPE_ACK		0x00D0
#define IEEE80211_STYPE_CFEND		0x00E0
#define IEEE80211_STYPE_CFENDACK	0x00F0

/* data */
#define IEEE80211_STYPE_DATA		0x0000
#define IEEE80211_STYPE_DATA_CFACK	0x0010
#define IEEE80211_STYPE_DATA_CFPOLL	0x0020
#define IEEE80211_STYPE_DATA_CFACKPOLL	0x0030
#define IEEE80211_STYPE_NULLFUNC	0x0040
#define IEEE80211_STYPE_CFACK		0x0050
#define IEEE80211_STYPE_CFPOLL		0x0060
#define IEEE80211_STYPE_CFACKPOLL	0x0070
#define IEEE80211_STYPE_QOS_DATA        0x0080

#define IEEE80211_SCTL_FRAG		0x000F
#define IEEE80211_SCTL_SEQ		0xFFF0

/* QOS control */
#define IEEE80211_QCTL_TID		0x000F

/* debug macros */

#ifdef CONFIG_IEEE80211_DEBUG
extern u32 ieee80211_debug_level;
#define IEEE80211_DEBUG(level, fmt, args...) \
do { if (ieee80211_debug_level & (level)) \
  printk(KERN_DEBUG "ieee80211: %c %s " fmt, \
         in_interrupt() ? 'I' : 'U', __FUNCTION__ , ## args); } while (0)
#else
#define IEEE80211_DEBUG(level, fmt, args...) do {} while (0)
#endif				/* CONFIG_IEEE80211_DEBUG */

/* debug macros not dependent on CONFIG_IEEE80211_DEBUG */

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((u8*)(x))[0],((u8*)(x))[1],((u8*)(x))[2],((u8*)(x))[3],((u8*)(x))[4],((u8*)(x))[5]

static inline int ieee80211_is_empty_essid(const char *essid, int essid_len)
{
	/* Single white space is for Linksys APs */
	if (essid_len == 1 && essid[0] == ' ')
		return 1;

	/* Otherwise, if the entire essid is 0, we assume it is hidden */
	while (essid_len) {
		essid_len--;
		if (essid[essid_len] != '\0')
			return 0;
	}

	return 1;
}

/* escape_essid() is intended to be used in debug (and possibly error)
 * messages. It should never be used for passing essid to user space. */
static const char *escape_essid(const char *essid, u8 essid_len)
{
	static char escaped[IW_ESSID_MAX_SIZE * 2 + 1];
	const char *s = essid;
	char *d = escaped;

	if (ieee80211_is_empty_essid(essid, essid_len)) {
		memcpy(escaped, "<hidden>", sizeof("<hidden>"));
		return escaped;
	}

	essid_len = min(essid_len, (u8) IW_ESSID_MAX_SIZE);
	while (essid_len--) {
		if (*s == '\0') {
			*d++ = '\\';
			*d++ = '0';
			s++;
		} else {
			*d++ = *s++;
		}
	}
	*d = '\0';
	return escaped;
}

/*
 * To use the debug system:
 *
 * If you are defining a new debug classification, simply add it to the #define
 * list here in the form of:
 *
 * #define IEEE80211_DL_xxxx VALUE
 *
 * shifting value to the left one bit from the previous entry.  xxxx should be
 * the name of the classification (for example, WEP)
 *
 * You then need to either add a IEEE80211_xxxx_DEBUG() macro definition for your
 * classification, or use IEEE80211_DEBUG(IEEE80211_DL_xxxx, ...) whenever you want
 * to send output to that classification.
 *
 * To add your debug level to the list of levels seen when you perform
 *
 * % cat /proc/net/ieee80211/debug_level
 *
 * you simply need to add your entry to the ieee80211_debug_level array.
 *
 * If you do not see debug_level in /proc/net/ieee80211 then you do not have
 * CONFIG_IEEE80211_DEBUG defined in your kernel configuration
 *
 */

#define IEEE80211_DL_INFO          (1<<0)
#define IEEE80211_DL_WX            (1<<1)
#define IEEE80211_DL_SCAN          (1<<2)
#define IEEE80211_DL_STATE         (1<<3)
#define IEEE80211_DL_MGMT          (1<<4)
#define IEEE80211_DL_FRAG          (1<<5)
#define IEEE80211_DL_DROP          (1<<7)

#define IEEE80211_DL_TX            (1<<8)
#define IEEE80211_DL_RX            (1<<9)
#define IEEE80211_DL_QOS           (1<<31)

#define IEEE80211_ERROR(f, a...) printk(KERN_ERR "ieee80211: " f, ## a)
#define IEEE80211_WARNING(f, a...) printk(KERN_WARNING "ieee80211: " f, ## a)
#define IEEE80211_DEBUG_INFO(f, a...)   IEEE80211_DEBUG(IEEE80211_DL_INFO, f, ## a)

#define IEEE80211_DEBUG_WX(f, a...)     IEEE80211_DEBUG(IEEE80211_DL_WX, f, ## a)
#define IEEE80211_DEBUG_SCAN(f, a...)   IEEE80211_DEBUG(IEEE80211_DL_SCAN, f, ## a)
#define IEEE80211_DEBUG_STATE(f, a...)  IEEE80211_DEBUG(IEEE80211_DL_STATE, f, ## a)
#define IEEE80211_DEBUG_MGMT(f, a...)  IEEE80211_DEBUG(IEEE80211_DL_MGMT, f, ## a)
#define IEEE80211_DEBUG_FRAG(f, a...)  IEEE80211_DEBUG(IEEE80211_DL_FRAG, f, ## a)
#define IEEE80211_DEBUG_DROP(f, a...)  IEEE80211_DEBUG(IEEE80211_DL_DROP, f, ## a)
#define IEEE80211_DEBUG_TX(f, a...)  IEEE80211_DEBUG(IEEE80211_DL_TX, f, ## a)
#define IEEE80211_DEBUG_RX(f, a...)  IEEE80211_DEBUG(IEEE80211_DL_RX, f, ## a)
#define IEEE80211_DEBUG_QOS(f, a...)  IEEE80211_DEBUG(IEEE80211_DL_QOS, f, ## a)
//#include <linux/netdevice.h>
//#include <linux/wireless.h>
//#include <linux/if_arp.h>	/* ARPHRD_ETHER */

#ifndef WIRELESS_SPY
#define WIRELESS_SPY		/* enable iwspy support */
#endif
//#include <net/iw_handler.h>	/* new driver API */

#ifndef ETH_P_PAE
#define ETH_P_PAE 0x888E	/* Port Access Entity (IEEE 802.1X) */
#endif				/* ETH_P_PAE */

#define ETH_P_PREAUTH 0x88C7	/* IEEE 802.11i pre-authentication */

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW (ETH_P_ECONET + 1)
#endif

/* IEEE 802.11 defines */

#define P80211_OUI_LEN 3

struct ieee80211_snap_hdr {

	u8 dsap;		/* always 0xAA */
	u8 ssap;		/* always 0xAA */
	u8 ctrl;		/* always 0x03 */
	u8 oui[P80211_OUI_LEN];	/* organizational universal id */

} __attribute__ ((packed));

#define SNAP_SIZE sizeof(struct ieee80211_snap_hdr)

#define WLAN_FC_GET_VERS(fc) ((fc) & IEEE80211_FCTL_VERS)
#define WLAN_FC_GET_TYPE(fc) ((fc) & IEEE80211_FCTL_FTYPE)
#define WLAN_FC_GET_STYPE(fc) ((fc) & IEEE80211_FCTL_STYPE)

#define WLAN_GET_SEQ_FRAG(seq) ((seq) & IEEE80211_SCTL_FRAG)
#define WLAN_GET_SEQ_SEQ(seq)  ((seq) & IEEE80211_SCTL_SEQ)

/* Authentication algorithms */
#define WLAN_AUTH_OPEN 0
#define WLAN_AUTH_SHARED_KEY 1
#define WLAN_AUTH_LEAP 2

#define WLAN_AUTH_CHALLENGE_LEN 128

#define WLAN_CAPABILITY_ESS (1<<0)
#define WLAN_CAPABILITY_IBSS (1<<1)
#define WLAN_CAPABILITY_CF_POLLABLE (1<<2)
#define WLAN_CAPABILITY_CF_POLL_REQUEST (1<<3)
#define WLAN_CAPABILITY_PRIVACY (1<<4)
#define WLAN_CAPABILITY_SHORT_PREAMBLE (1<<5)
#define WLAN_CAPABILITY_PBCC (1<<6)
#define WLAN_CAPABILITY_CHANNEL_AGILITY (1<<7)
#define WLAN_CAPABILITY_SPECTRUM_MGMT (1<<8)
#define WLAN_CAPABILITY_QOS (1<<9)
#define WLAN_CAPABILITY_SHORT_SLOT_TIME (1<<10)
#define WLAN_CAPABILITY_DSSS_OFDM (1<<13)

/* 802.11g ERP information element */
#define WLAN_ERP_NON_ERP_PRESENT (1<<0)
#define WLAN_ERP_USE_PROTECTION (1<<1)
#define WLAN_ERP_BARKER_PREAMBLE (1<<2)

/* Status codes */
enum ieee80211_statuscode {
	WLAN_STATUS_SUCCESS = 0,
	WLAN_STATUS_UNSPECIFIED_FAILURE = 1,
	WLAN_STATUS_CAPS_UNSUPPORTED = 10,
	WLAN_STATUS_REASSOC_NO_ASSOC = 11,
	WLAN_STATUS_ASSOC_DENIED_UNSPEC = 12,
	WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG = 13,
	WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION = 14,
	WLAN_STATUS_CHALLENGE_FAIL = 15,
	WLAN_STATUS_AUTH_TIMEOUT = 16,
	WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA = 17,
	WLAN_STATUS_ASSOC_DENIED_RATES = 18,
	/* 802.11b */
	WLAN_STATUS_ASSOC_DENIED_NOSHORTPREAMBLE = 19,
	WLAN_STATUS_ASSOC_DENIED_NOPBCC = 20,
	WLAN_STATUS_ASSOC_DENIED_NOAGILITY = 21,
	/* 802.11h */
	WLAN_STATUS_ASSOC_DENIED_NOSPECTRUM = 22,
	WLAN_STATUS_ASSOC_REJECTED_BAD_POWER = 23,
	WLAN_STATUS_ASSOC_REJECTED_BAD_SUPP_CHAN = 24,
	/* 802.11g */
	WLAN_STATUS_ASSOC_DENIED_NOSHORTTIME = 25,
	WLAN_STATUS_ASSOC_DENIED_NODSSSOFDM = 26,
	/* 802.11i */
	WLAN_STATUS_INVALID_IE = 40,
	WLAN_STATUS_INVALID_GROUP_CIPHER = 41,
	WLAN_STATUS_INVALID_PAIRWISE_CIPHER = 42,
	WLAN_STATUS_INVALID_AKMP = 43,
	WLAN_STATUS_UNSUPP_RSN_VERSION = 44,
	WLAN_STATUS_INVALID_RSN_IE_CAP = 45,
	WLAN_STATUS_CIPHER_SUITE_REJECTED = 46,
};

/* Reason codes */
enum ieee80211_reasoncode {
	WLAN_REASON_UNSPECIFIED = 1,
	WLAN_REASON_PREV_AUTH_NOT_VALID = 2,
	WLAN_REASON_DEAUTH_LEAVING = 3,
	WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY = 4,
	WLAN_REASON_DISASSOC_AP_BUSY = 5,
	WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA = 6,
	WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA = 7,
	WLAN_REASON_DISASSOC_STA_HAS_LEFT = 8,
	WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH = 9,
	/* 802.11h */
	WLAN_REASON_DISASSOC_BAD_POWER = 10,
	WLAN_REASON_DISASSOC_BAD_SUPP_CHAN = 11,
	/* 802.11i */
	WLAN_REASON_INVALID_IE = 13,
	WLAN_REASON_MIC_FAILURE = 14,
	WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT = 15,
	WLAN_REASON_GROUP_KEY_HANDSHAKE_TIMEOUT = 16,
	WLAN_REASON_IE_DIFFERENT = 17,
	WLAN_REASON_INVALID_GROUP_CIPHER = 18,
	WLAN_REASON_INVALID_PAIRWISE_CIPHER = 19,
	WLAN_REASON_INVALID_AKMP = 20,
	WLAN_REASON_UNSUPP_RSN_VERSION = 21,
	WLAN_REASON_INVALID_RSN_IE_CAP = 22,
	WLAN_REASON_IEEE8021X_FAILED = 23,
	WLAN_REASON_CIPHER_SUITE_REJECTED = 24,
};

/* Action categories - 802.11h */
enum ieee80211_actioncategories {
	WLAN_ACTION_SPECTRUM_MGMT = 0,
	/* Reserved 1-127  */
	/* Error    128-255 */
};

/* Action details - 802.11h */
enum ieee80211_actiondetails {
	WLAN_ACTION_CATEGORY_MEASURE_REQUEST = 0,
	WLAN_ACTION_CATEGORY_MEASURE_REPORT = 1,
	WLAN_ACTION_CATEGORY_TPC_REQUEST = 2,
	WLAN_ACTION_CATEGORY_TPC_REPORT = 3,
	WLAN_ACTION_CATEGORY_CHANNEL_SWITCH = 4,
	/* 5 - 255 Reserved */
};

#define IEEE80211_STATMASK_SIGNAL (1<<0)
#define IEEE80211_STATMASK_RSSI (1<<1)
#define IEEE80211_STATMASK_NOISE (1<<2)
#define IEEE80211_STATMASK_RATE (1<<3)
#define IEEE80211_STATMASK_WEMASK 0x7

#define IEEE80211_CCK_MODULATION    (1<<0)
#define IEEE80211_OFDM_MODULATION   (1<<1)

#define IEEE80211_24GHZ_BAND     (1<<0)
#define IEEE80211_52GHZ_BAND     (1<<1)

#define IEEE80211_CCK_RATE_1MB		        0x02
#define IEEE80211_CCK_RATE_2MB		        0x04
#define IEEE80211_CCK_RATE_5MB		        0x0B
#define IEEE80211_CCK_RATE_11MB		        0x16
#define IEEE80211_OFDM_RATE_6MB		        0x0C
#define IEEE80211_OFDM_RATE_9MB		        0x12
#define IEEE80211_OFDM_RATE_12MB		0x18
#define IEEE80211_OFDM_RATE_18MB		0x24
#define IEEE80211_OFDM_RATE_24MB		0x30
#define IEEE80211_OFDM_RATE_36MB		0x48
#define IEEE80211_OFDM_RATE_48MB		0x60
#define IEEE80211_OFDM_RATE_54MB		0x6C
#define IEEE80211_BASIC_RATE_MASK		0x80

#define IEEE80211_CCK_RATE_1MB_MASK		(1<<0)
#define IEEE80211_CCK_RATE_2MB_MASK		(1<<1)
#define IEEE80211_CCK_RATE_5MB_MASK		(1<<2)
#define IEEE80211_CCK_RATE_11MB_MASK		(1<<3)
#define IEEE80211_OFDM_RATE_6MB_MASK		(1<<4)
#define IEEE80211_OFDM_RATE_9MB_MASK		(1<<5)
#define IEEE80211_OFDM_RATE_12MB_MASK		(1<<6)
#define IEEE80211_OFDM_RATE_18MB_MASK		(1<<7)
#define IEEE80211_OFDM_RATE_24MB_MASK		(1<<8)
#define IEEE80211_OFDM_RATE_36MB_MASK		(1<<9)
#define IEEE80211_OFDM_RATE_48MB_MASK		(1<<10)
#define IEEE80211_OFDM_RATE_54MB_MASK		(1<<11)

#define IEEE80211_CCK_RATES_MASK	        0x0000000F
#define IEEE80211_CCK_BASIC_RATES_MASK	(IEEE80211_CCK_RATE_1MB_MASK | \
	IEEE80211_CCK_RATE_2MB_MASK)
#define IEEE80211_CCK_DEFAULT_RATES_MASK	(IEEE80211_CCK_BASIC_RATES_MASK | \
        IEEE80211_CCK_RATE_5MB_MASK | \
        IEEE80211_CCK_RATE_11MB_MASK)

#define IEEE80211_OFDM_RATES_MASK		0x00000FF0
#define IEEE80211_OFDM_BASIC_RATES_MASK	(IEEE80211_OFDM_RATE_6MB_MASK | \
	IEEE80211_OFDM_RATE_12MB_MASK | \
	IEEE80211_OFDM_RATE_24MB_MASK)
#define IEEE80211_OFDM_DEFAULT_RATES_MASK	(IEEE80211_OFDM_BASIC_RATES_MASK | \
	IEEE80211_OFDM_RATE_9MB_MASK  | \
	IEEE80211_OFDM_RATE_18MB_MASK | \
	IEEE80211_OFDM_RATE_36MB_MASK | \
	IEEE80211_OFDM_RATE_48MB_MASK | \
	IEEE80211_OFDM_RATE_54MB_MASK)
#define IEEE80211_DEFAULT_RATES_MASK (IEEE80211_OFDM_DEFAULT_RATES_MASK | \
                                IEEE80211_CCK_DEFAULT_RATES_MASK)

#define IEEE80211_NUM_OFDM_RATES	    8
#define IEEE80211_NUM_CCK_RATES	            4
#define IEEE80211_OFDM_SHIFT_MASK_A         4

/* NOTE: This data is for statistical purposes; not all hardware provides this
 *       information for frames received.
 *       For ieee80211_rx_mgt, you need to set at least the 'len' parameter.
 */
struct ieee80211_rx_stats {
	u32 mac_time;
	s8 rssi;
	u8 signal;
	u8 noise;
	u16 rate;		/* in 100 kbps */
	u8 received_channel;
	u8 control;
	u8 mask;
	u8 freq;
	u16 len;
	u64 tsf;
	u32 beacon_time;
};

/* IEEE 802.11 requires that STA supports concurrent reception of at least
 * three fragmented frames. This define can be increased to support more
 * concurrent frames, but it should be noted that each entry can consume about
 * 2 kB of RAM and increasing cache size will slow down frame reassembly. */
#define IEEE80211_FRAG_CACHE_LEN 4

struct ieee80211_frag_entry {
	unsigned long first_frag_time;
	unsigned int seq;
	unsigned int last_frag;
	mbuf_t skb;
	u8 src_addr[ETH_ALEN];
	u8 dst_addr[ETH_ALEN];
};

struct ieee80211_stats {
	unsigned int tx_unicast_frames;
	unsigned int tx_multicast_frames;
	unsigned int tx_fragments;
	unsigned int tx_unicast_octets;
	unsigned int tx_multicast_octets;
	unsigned int tx_deferred_transmissions;
	unsigned int tx_single_retry_frames;
	unsigned int tx_multiple_retry_frames;
	unsigned int tx_retry_limit_exceeded;
	unsigned int tx_discards;
	unsigned int rx_unicast_frames;
	unsigned int rx_multicast_frames;
	unsigned int rx_fragments;
	unsigned int rx_unicast_octets;
	unsigned int rx_multicast_octets;
	unsigned int rx_fcs_errors;
	unsigned int rx_discards_no_buffer;
	unsigned int tx_discards_wrong_sa;
	unsigned int rx_discards_undecryptable;
	unsigned int rx_message_in_msg_fragments;
	unsigned int rx_message_in_bad_msg_fragments;
};

struct ieee80211_device;



#define SEC_KEY_1		(1<<0)
#define SEC_KEY_2		(1<<1)
#define SEC_KEY_3		(1<<2)
#define SEC_KEY_4		(1<<3)
#define SEC_ACTIVE_KEY		(1<<4)
#define SEC_AUTH_MODE		(1<<5)
#define SEC_UNICAST_GROUP	(1<<6)
#define SEC_LEVEL		(1<<7)
#define SEC_ENABLED		(1<<8)
#define SEC_ENCRYPT		(1<<9)

#define SEC_LEVEL_0		0	/* None */
#define SEC_LEVEL_1		1	/* WEP 40 and 104 bit */
#define SEC_LEVEL_2		2	/* Level 1 + TKIP */
#define SEC_LEVEL_2_CKIP	3	/* Level 1 + CKIP */
#define SEC_LEVEL_3		4	/* Level 2 + CCMP */

#define SEC_ALG_NONE		0
#define SEC_ALG_WEP		1
#define SEC_ALG_TKIP		2
#define SEC_ALG_CCMP		3

#define WEP_KEYS		4
#define WEP_KEY_LEN		13
#define SCM_KEY_LEN		32
#define SCM_TEMPORAL_KEY_LENGTH	16

struct ieee80211_security {
	u16 active_key:2,
	    enabled:1,
	    auth_mode:2, auth_algo:4, unicast_uses_group:1, encrypt:1;
	u8 encode_alg[WEP_KEYS];
	u8 key_sizes[WEP_KEYS];
	u8 keys[WEP_KEYS][SCM_KEY_LEN];
	u8 level;
	u16 flags;
} __attribute__ ((packed));

/*

 802.11 data frame from AP

      ,-------------------------------------------------------------------.
Bytes |  2   |  2   |    6    |    6    |    6    |  2   | 0..2312 |   4  |
      |------|------|---------|---------|---------|------|---------|------|
Desc. | ctrl | dura |  DA/RA  |   TA    |    SA   | Sequ |  frame  |  fcs |
      |      | tion | (BSSID) |         |         | ence |  data   |      |
      `-------------------------------------------------------------------'

Total: 28-2340 bytes

*/

#define BEACON_PROBE_SSID_ID_POSITION 12

/* Management Frame Information Element Types */
enum ieee80211_mfie {
	MFIE_TYPE_SSID = 0,
	MFIE_TYPE_RATES = 1,
	MFIE_TYPE_FH_SET = 2,
	MFIE_TYPE_DS_SET = 3,
	MFIE_TYPE_CF_SET = 4,
	MFIE_TYPE_TIM = 5,
	MFIE_TYPE_IBSS_SET = 6,
	MFIE_TYPE_COUNTRY = 7,
	MFIE_TYPE_HOP_PARAMS = 8,
	MFIE_TYPE_HOP_TABLE = 9,
	MFIE_TYPE_REQUEST = 10,
	MFIE_TYPE_CHALLENGE = 16,
	MFIE_TYPE_POWER_CONSTRAINT = 32,
	MFIE_TYPE_POWER_CAPABILITY = 33,
	MFIE_TYPE_TPC_REQUEST = 34,
	MFIE_TYPE_TPC_REPORT = 35,
	MFIE_TYPE_SUPP_CHANNELS = 36,
	MFIE_TYPE_CSA = 37,
	MFIE_TYPE_MEASURE_REQUEST = 38,
	MFIE_TYPE_MEASURE_REPORT = 39,
	MFIE_TYPE_QUIET = 40,
	MFIE_TYPE_IBSS_DFS = 41,
	MFIE_TYPE_ERP_INFO = 42,
	MFIE_TYPE_RSN = 48,
	MFIE_TYPE_RATES_EX = 50,
	MFIE_TYPE_GENERIC = 221,
	MFIE_TYPE_QOS_PARAMETER = 222,
};

struct ieee80211_mgmt {
	__le16 frame_control;
	__le16 duration;
	__u8 da[6];
	__u8 sa[6];
	__u8 bssid[6];
	__le16 seq_ctrl;
	union {
		struct {
			__le16 auth_alg;
			__le16 auth_transaction;
			__le16 status_code;
			/* possibly followed by Challenge text */
			__u8 variable[0];
		} __attribute__ ((packed)) auth;
		struct {
			__le16 reason_code;
		} __attribute__ ((packed)) deauth;
		struct {
			__le16 capab_info;
			__le16 listen_interval;
			/* followed by SSID and Supported rates */
			u8 variable[0];
		} __attribute__ ((packed)) assoc_req;
		struct {
			__le16 capab_info;
			__le16 status_code;
			__le16 aid;
			/* followed by Supported rates */
			__u8 variable[0];
		} __attribute__ ((packed)) assoc_resp, reassoc_resp;
		struct {
			__le16 capab_info;
			__le16 listen_interval;
			__u8 current_ap[6];
			/* followed by SSID and Supported rates */
			__u8 variable[0];
		} __attribute__ ((packed)) reassoc_req;
		struct {
			__le16 reason_code;
		} __attribute__ ((packed)) disassoc;
		struct {
			__le64 timestamp;
			__le16 beacon_int;
			__le16 capab_info;
			/* followed by some of SSID, Supported rates,
			 * FH Params, DS Params, CF Params, IBSS Params, TIM */
			__u8 variable[0];
		} __attribute__ ((packed)) beacon;
		struct {
			/* only variable items: SSID, Supported rates */
			__u8 variable[0];
		} __attribute__ ((packed)) probe_req;
		struct {
			__le64 timestamp;
			__le16 beacon_int;
			__le16 capab_info;
			/* followed by some of SSID, Supported rates,
			 * FH Params, DS Params, CF Params, IBSS Params */
			__u8 variable[0];
		} __attribute__ ((packed)) probe_resp;
		struct {
			__u8 category;
			union {
				struct {
					__u8 action_code;
					__u8 dialog_token;
					__u8 status_code;
					__u8 variable[0];
				} __attribute__ ((packed)) wme_action;
				struct{
					__u8 action_code;
					__u8 element_id;
					__u8 length;
					__u8 switch_mode;
					__u8 new_chan;
					__u8 switch_count;
				} __attribute__((packed)) chan_switch;
			} u;
		} __attribute__ ((packed)) action;
	} u;
} __attribute__ ((packed));

enum {
	MODE_IEEE80211A = 0 /* IEEE 802.11a */,
	MODE_IEEE80211B = 1 /* IEEE 802.11b only */,
	MODE_ATHEROS_TURBO = 2 /* Atheros Turbo mode (2x.11a at 5 GHz) */,
	MODE_IEEE80211G = 3 /* IEEE 802.11g (and 802.11b compatibility) */,
	MODE_ATHEROS_TURBOG = 4 /* Atheros Turbo mode (2x.11g at 2.4 GHz) */,
	NUM_IEEE80211_MODES = 5
};

enum ieee80211_if_types {
	IEEE80211_IF_TYPE_AP = 0x00000000,
	IEEE80211_IF_TYPE_MGMT = 0x00000001,
	IEEE80211_IF_TYPE_STA = 0x00000002,
	IEEE80211_IF_TYPE_IBSS = 0x00000003,
	IEEE80211_IF_TYPE_MNTR = 0x00000004,
	IEEE80211_IF_TYPE_WDS = 0x5A580211,
	IEEE80211_IF_TYPE_VLAN = 0x00080211,
};

struct ieee80211_conf {
	int channel;			/* IEEE 802.11 channel number */
	int freq;			/* MHz */
	int channel_val;		/* hw specific value for the channel */

	int phymode;			/* MODE_IEEE80211A, .. */
	struct ieee80211_channel *chan;
	struct ieee80211_hw_mode *mode;
	unsigned int regulatory_domain;
	int radio_enabled;

	int beacon_int;

#define IEEE80211_CONF_SHORT_SLOT_TIME	(1<<0) /* use IEEE 802.11g Short Slot
						* Time */
#define IEEE80211_CONF_SSID_HIDDEN	(1<<1) /* do not broadcast the ssid */
#define IEEE80211_CONF_RADIOTAP		(1<<2) /* use radiotap if supported
						  check this bit at RX time */
#define IEEE80211_CONF_CHANNEL_SWITCH	(1<<3)
	u32 flags;			/* configuration flags defined above */

	u8 power_level;			/* transmit power limit for current
					 * regulatory domain; in dBm */
	u8 antenna_max;			/* maximum antenna gain */
	short tx_power_reduction; /* in 0.1 dBm */

	u8 power_management_enable;     /* flag to enable/disable*/
					/*power management*/
	/* 0 = default/diversity, 1 = Ant0, 2 = Ant1 */
	u8 antenna_sel_tx;
	u8 antenna_sel_rx;

	int antenna_def;
	int antenna_mode;

	/* Following five fields are used for IEEE 802.11H */
	unsigned int radar_detect;
	unsigned int spect_mgmt;
	/* All following fields are currently unused. */
	unsigned int quiet_duration; /* duration of quiet period */
	unsigned int quiet_offset; /* how far into the beacon is the quiet
				    * period */
	unsigned int quiet_period;
	u8 radar_firpwr_threshold;
	u8 radar_rssi_threshold;
	u8 pulse_height_threshold;
	u8 pulse_rssi_threshold;
	u8 pulse_inband_threshold;
};

struct ieee80211_rate {
	int rate; /* rate in 100 kbps */
	int val; /* hw specific value for the rate */
	int flags; /* IEEE80211_RATE_ flags */
	int val2; /* hw specific value for the rate when using short preamble
		   * (only when IEEE80211_RATE_PREAMBLE2 flag is set, i.e., for
		   * 2, 5.5, and 11 Mbps) */
	signed char min_rssi_ack;
	unsigned char min_rssi_ack_delta;

	/* following fields are set by 80211.o and need not be filled by the
	 * low-level driver */
	int rate_inv; /* inverse of the rate (LCM(all rates) / rate) for
		       * optimizing channel utilization estimates */
};

enum ieee80211_eid {
	WLAN_EID_SSID = 0,
	WLAN_EID_SUPP_RATES = 1,
	WLAN_EID_FH_PARAMS = 2,
	WLAN_EID_DS_PARAMS = 3,
	WLAN_EID_CF_PARAMS = 4,
	WLAN_EID_TIM = 5,
	WLAN_EID_IBSS_PARAMS = 6,
	WLAN_EID_CHALLENGE = 16,
	/* 802.11d */
	WLAN_EID_COUNTRY = 7,
	WLAN_EID_HP_PARAMS = 8,
	WLAN_EID_HP_TABLE = 9,
	WLAN_EID_REQUEST = 10,
	/* 802.11h */
	WLAN_EID_PWR_CONSTRAINT = 32,
	WLAN_EID_PWR_CAPABILITY = 33,
	WLAN_EID_TPC_REQUEST = 34,
	WLAN_EID_TPC_REPORT = 35,
	WLAN_EID_SUPPORTED_CHANNELS = 36,
	WLAN_EID_CHANNEL_SWITCH = 37,
	WLAN_EID_MEASURE_REQUEST = 38,
	WLAN_EID_MEASURE_REPORT = 39,
	WLAN_EID_QUIET = 40,
	WLAN_EID_IBSS_DFS = 41,
	/* 802.11g */
	WLAN_EID_ERP_INFO = 42,
	WLAN_EID_EXT_SUPP_RATES = 50,
	/* 802.11i */
	WLAN_EID_RSN = 48,
	WLAN_EID_WPA = 221,
	WLAN_EID_GENERIC = 221,
	WLAN_EID_VENDOR_SPECIFIC = 221,
	WLAN_EID_QOS_PARAMETER = 222
};

#define IEEE80211_CHAN_W_RADAR_DETECT 0x00000010

#define IEEE80211_CHAN_W_SCAN 0x00000001
#define IEEE80211_CHAN_W_ACTIVE_SCAN 0x00000002
#define IEEE80211_CHAN_W_IBSS 0x00000004

#define IEEE80211_RATE_ERP 0x00000001
#define IEEE80211_RATE_BASIC 0x00000002
#define IEEE80211_RATE_PREAMBLE2 0x00000004
#define IEEE80211_RATE_SUPPORTED 0x00000010
#define IEEE80211_RATE_OFDM 0x00000020
#define IEEE80211_RATE_CCK 0x00000040
#define IEEE80211_RATE_TURBO 0x00000080
#define IEEE80211_RATE_MANDATORY 0x00000100

#define IEEE80211_RATE_CCK_2 (IEEE80211_RATE_CCK | IEEE80211_RATE_PREAMBLE2)
#define IEEE80211_RATE_MODULATION(f) \
(f & (IEEE80211_RATE_CCK | IEEE80211_RATE_OFDM))

struct ieee80211_hw {
	/* points to the cfg80211 wiphy for this piece. Note
	 * that you must fill in the perm_addr and dev fields
	 * of this structure, use the macros provided below. */
	//struct wiphy *wiphy;

	/* assigned by mac80211, don't write */
	struct ieee80211_conf conf;

	/* Pointer to the private area that was
	 * allocated with this struct for you. */
	void *priv;

	/* The rest is information about your hardware */

	/* TODO: frame_type 802.11/802.3, sw_encryption requirements */

	/* Some wireless LAN chipsets generate beacons in the hardware/firmware
	 * and others rely on host generated beacons. This option is used to
	 * configure the upper layer IEEE 802.11 module to generate beacons.
	 * The low-level driver can use ieee80211_beacon_get() to fetch the
	 * next beacon frame. */
#define IEEE80211_HW_HOST_GEN_BEACON (1<<0)

	/* The device needs to be supplied with a beacon template only. */
#define IEEE80211_HW_HOST_GEN_BEACON_TEMPLATE (1<<1)

	/* Some devices handle decryption internally and do not
	 * indicate whether the frame was encrypted (unencrypted frames
	 * will be dropped by the hardware, unless specifically allowed
	 * through) */
#define IEEE80211_HW_DEVICE_HIDES_WEP (1<<2)

	/* Whether RX frames passed to ieee80211_rx() include FCS in the end */
#define IEEE80211_HW_RX_INCLUDES_FCS (1<<3)

	/* Some wireless LAN chipsets buffer broadcast/multicast frames for
	 * power saving stations in the hardware/firmware and others rely on
	 * the host system for such buffering. This option is used to
	 * configure the IEEE 802.11 upper layer to buffer broadcast/multicast
	 * frames when there are power saving stations so that low-level driver
	 * can fetch them with ieee80211_get_buffered_bc(). */
#define IEEE80211_HW_HOST_BROADCAST_PS_BUFFERING (1<<4)

#define IEEE80211_HW_WEP_INCLUDE_IV (1<<5)

	/* will data nullfunc frames get proper TX status callback */
#define IEEE80211_HW_DATA_NULLFUNC_ACK (1<<6)

	/* Force software encryption for TKIP packets if WMM is enabled. */
#define IEEE80211_HW_NO_TKIP_WMM_HWACCEL (1<<7)

	/* Some devices handle Michael MIC internally and do not include MIC in
	 * the received packets passed up. device_strips_mic must be set
	 * for such devices. The 'encryption' frame control bit is expected to
	 * be still set in the IEEE 802.11 header with this option unlike with
	 * the device_hides_wep configuration option.
	 */
#define IEEE80211_HW_DEVICE_STRIPS_MIC (1<<8)

	/* Device is capable of performing full monitor mode even during
	 * normal operation. */
#define IEEE80211_HW_MONITOR_DURING_OPER (1<<9)

	/* please fill this gap when adding new flags */

	/* calculate Michael MIC for an MSDU when doing hwcrypto */
#define IEEE80211_HW_TKIP_INCLUDE_MMIC (1<<12)
	/* Do TKIP phase1 key mixing in stack to support cards only do
	 * phase2 key mixing when doing hwcrypto */
#define IEEE80211_HW_TKIP_REQ_PHASE1_KEY (1<<13)
	/* Do TKIP phase1 and phase2 key mixing in stack and send the generated
	 * per-packet RC4 key with each TX frame when doing hwcrypto */
#define IEEE80211_HW_TKIP_REQ_PHASE2_KEY (1<<14)

	u32 flags;			/* hardware flags defined above */

	/* Set to the size of a needed device specific skb headroom for TX skbs. */
	unsigned int extra_tx_headroom;

	/* This is the time in us to change channels
	 */
	int channel_change_time;
	/* Maximum values for various statistics.
	 * Leave at 0 to indicate no support. Use negative numbers for dBm. */
	s8 max_rssi;
	s8 max_signal;
	s8 max_noise;

	/* Number of available hardware TX queues for data packets.
	 * WMM requires at least four queues. */
	int queues;
};

#define STA_HASH_SIZE 256
#define STA_HASH(sta) (sta[5])

struct rate_control_ref {
	struct rate_control_ops *ops;
	void* priv;
	void* kref;
};
enum {
	IEEE80211_TX_QUEUE_DATA0,
	IEEE80211_TX_QUEUE_DATA1,
	IEEE80211_TX_QUEUE_DATA2,
	IEEE80211_TX_QUEUE_DATA3,
	IEEE80211_TX_QUEUE_DATA4,
	IEEE80211_TX_QUEUE_SVP,

	NUM_TX_DATA_QUEUES,

/* due to stupidity in the sub-ioctl userspace interface, the items in
 * this struct need to have fixed values. As soon as it is removed, we can
 * fix these entries. */
	IEEE80211_TX_QUEUE_AFTER_BEACON = 6,
	IEEE80211_TX_QUEUE_BEACON = 7,
	NUM_TX_DATA_QUEUES_11N = 16 /* adding more data queues for 802.11n */
};
struct ieee80211_tx_stored_packet {
	struct ieee80211_tx_control control;
	mbuf_t skb;
	int num_extra_frag;
	mbuf_t extra_frag;
	int last_frag_rateidx;
	int last_frag_hwrate;
	struct ieee80211_rate *last_frag_rate;
	unsigned int last_frag_rate_ctrl_probe:1;
};
#define IEEE80211_MAX_SSID_LEN		32

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
#define IEEE80211_IRQSAFE_QUEUE_LIMIT 128
	//struct tasklet_struct 
	void* tasklet;
	//struct sk_buff_head 
	mbuf_t skb_queue;
	//struct sk_buff_head 
	mbuf_t skb_queue_unreliable;

	/* Station data structures */
	//spinlock_t 
	void* sta_lock; /* mutex for STA data structures */
	int num_sta; /* number of stations in sta_list */
	struct list_head sta_list;
	struct list_head deleted_sta_list;
	struct sta_info *sta_hash[STA_HASH_SIZE];
	//struct timer_list 
	void* sta_cleanup;

	unsigned long state[NUM_TX_DATA_QUEUES_11N];
	struct ieee80211_tx_stored_packet pending_packet[NUM_TX_DATA_QUEUES_11N];
	//struct tasklet_struct 
	void* tx_pending_tasklet;

	int mc_count;	/* total count of multicast entries in all interfaces */
	int iff_allmultis, iff_promiscs;
			/* number of interfaces with corresponding IFF_ flags */

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
	int fragmentation_threshold;
	int short_retry_limit; /* dot11ShortRetryLimit */
	int long_retry_limit; /* dot11LongRetryLimit */
	int short_preamble; /* use short preamble with IEEE 802.11b */

	//struct crypto_blkcipher 
	void* wep_tx_tfm;
	//struct crypto_blkcipher 
	void* wep_rx_tfm;
	u32 wep_iv;
	int key_tx_rx_threshold; /* number of times any key can be used in TX
				  * or RX before generating a rekey
				  * notification; 0 = notification disabled. */

	int bridge_packets; /* bridge packets between associated stations and
			     * deliver multicast frames both back to wireless
			     * media and to the local net stack */

	// ieee80211_rx_handler 
	void* rx_pre_handlers;
	// ieee80211_rx_handler 
	void* rx_handlers;
	// ieee80211_tx_handler 
	void* tx_handlers;

	//rwlock_t 
	void* sub_if_lock; /* Protects sub_if_list. Cannot be taken under
			       * sta_bss_lock or sta_lock. */
	struct list_head sub_if_list;
	int sta_scanning;
	int scan_channel_idx;
	enum { SCAN_SET_CHANNEL, SCAN_SEND_PROBE } scan_state;
	unsigned long last_scan_completed;
	//struct delayed_work 
	void* scan_work;
	struct net_device *scan_dev;
	struct ieee80211_channel *oper_channel, *scan_channel;
	struct ieee80211_hw_mode *oper_hw_mode, *scan_hw_mode;
	u8 scan_ssid[IEEE80211_MAX_SSID_LEN];
	size_t scan_ssid_len;
#define IEEE80211_MAX_TXPOWER 50
	u8 user_txpow;
	struct list_head sta_bss_list;
	struct ieee80211_sta_bss *sta_bss_hash[STA_HASH_SIZE];
	spinlock_t sta_bss_lock;
#define IEEE80211_SCAN_MATCH_SSID BIT(0)
#define IEEE80211_SCAN_WPA_ONLY BIT(1)
#define IEEE80211_SCAN_EXTRA_INFO BIT(2)
	int scan_flags;

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
	//struct timer_list 
	void* stat_timer;

#ifdef CONFIG_MAC80211_DEBUGFS
	struct work_struct sta_debugfs_add;
#endif

	enum {
		STA_ANTENNA_SEL_AUTO = 0,
		STA_ANTENNA_SEL_SW_CTRL = 1,
		STA_ANTENNA_SEL_SW_CTRL_DEBUG = 2
	} sta_antenna_sel;

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

#ifdef CONFIG_MAC80211_DEBUGFS
	struct local_debugfsdentries {
		struct dentry *channel;
		struct dentry *frequency;
		struct dentry *radar_detect;
		struct dentry *antenna_sel_tx;
		struct dentry *antenna_sel_rx;
		struct dentry *bridge_packets;
		struct dentry *key_tx_rx_threshold;
		struct dentry *rts_threshold;
		struct dentry *fragmentation_threshold;
		struct dentry *short_retry_limit;
		struct dentry *long_retry_limit;
		struct dentry *total_ps_buffered;
		struct dentry *mode;
		struct dentry *wep_iv;
		struct dentry *tx_power_reduction;
		struct dentry *modes;
		struct dentry *statistics;
		struct local_debugfsdentries_statsdentries {
			struct dentry *transmitted_fragment_count;
			struct dentry *multicast_transmitted_frame_count;
			struct dentry *failed_count;
			struct dentry *retry_count;
			struct dentry *multiple_retry_count;
			struct dentry *frame_duplicate_count;
			struct dentry *received_fragment_count;
			struct dentry *multicast_received_frame_count;
			struct dentry *transmitted_frame_count;
			struct dentry *wep_undecryptable_count;
			struct dentry *num_scans;
#ifdef CONFIG_MAC80211_DEBUG_COUNTERS
			struct dentry *tx_handlers_drop;
			struct dentry *tx_handlers_queued;
			struct dentry *tx_handlers_drop_unencrypted;
			struct dentry *tx_handlers_drop_fragment;
			struct dentry *tx_handlers_drop_wep;
			struct dentry *tx_handlers_drop_not_assoc;
			struct dentry *tx_handlers_drop_unauth_port;
			struct dentry *rx_handlers_drop;
			struct dentry *rx_handlers_queued;
			struct dentry *rx_handlers_drop_nullfunc;
			struct dentry *rx_handlers_drop_defrag;
			struct dentry *rx_handlers_drop_short;
			struct dentry *rx_handlers_drop_passive_scan;
			struct dentry *tx_expand_skb_head;
			struct dentry *tx_expand_skb_head_cloned;
			struct dentry *rx_expand_skb_head;
			struct dentry *rx_expand_skb_head2;
			struct dentry *rx_handlers_fragments;
			struct dentry *tx_status_drop;
			struct dentry *wme_tx_queue;
			struct dentry *wme_rx_queue;
#endif
			struct dentry *dot11ACKFailureCount;
			struct dentry *dot11RTSFailureCount;
			struct dentry *dot11FCSErrorCount;
			struct dentry *dot11RTSSuccessCount;
		} stats;
		struct dentry *stations;
		struct dentry *keys;
	} debugfs;
#endif
};

struct ieee80211_channel {
	short chan; /* channel number (IEEE 802.11) */
	short freq; /* frequency in MHz */
	int val; /* hw specific value for the channel */
	int flag; /* flag for hostapd use (IEEE80211_CHAN_*) */
	unsigned char power_level;
	unsigned char antenna_max;
};

struct ieee80211_hw_mode {
	int mode; /* MODE_IEEE80211... */
	int num_channels; /* Number of channels (below) */
	struct ieee80211_channel *channels; /* Array of supported channels */
	int num_rates; /* Number of rates (below) */
	struct ieee80211_rate *rates; /* Array of supported rates */

	struct list_head list; /* Internal, don't touch */
};

/* Minimal header; can be used for passing 802.11 frames with sufficient
 * information to determine what type of underlying data type is actually
 * stored in the data. */
struct ieee80211_hdr {
	__le16 frame_control;
	__le16 duration_id;
	__u8 addr1[6];
	__u8 addr2[6];
	__u8 addr3[6];
	__le16 seq_ctrl;
	__u8 addr4[6];
} __attribute__ ((packed));

struct ieee80211_hdr_1addr {
	__le16 frame_ctl;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 payload[0];
} __attribute__ ((packed));

struct ieee80211_hdr_2addr {
	__le16 frame_ctl;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 payload[0];
} __attribute__ ((packed));

struct ieee80211_hdr_3addr {
	__le16 frame_ctl;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 addr3[ETH_ALEN];
	__le16 seq_ctl;
	u8 payload[0];
} __attribute__ ((packed));

struct ieee80211_hdr_4addr {
	__le16 frame_ctl;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 addr3[ETH_ALEN];
	__le16 seq_ctl;
	u8 addr4[ETH_ALEN];
	u8 payload[0];
} __attribute__ ((packed));

struct ieee80211_hdr_3addrqos {
	__le16 frame_ctl;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 addr3[ETH_ALEN];
	__le16 seq_ctl;
	u8 payload[0];
	__le16 qos_ctl;
} __attribute__ ((packed));

struct ieee80211_hdr_4addrqos {
	__le16 frame_ctl;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 addr3[ETH_ALEN];
	__le16 seq_ctl;
	u8 addr4[ETH_ALEN];
	u8 payload[0];
	__le16 qos_ctl;
} __attribute__ ((packed));

struct ieee80211_info_element {
	u8 id;
	u8 len;
	u8 data[0];
} __attribute__ ((packed));

/*
 * These are the data types that can make up management packets
 *
	u16 auth_algorithm;
	u16 auth_sequence;
	u16 beacon_interval;
	u16 capability;
	u8 current_ap[ETH_ALEN];
	u16 listen_interval;
	struct {
		u16 association_id:14, reserved:2;
	} __attribute__ ((packed));
	u32 time_stamp[2];
	u16 reason;
	u16 status;
*/

struct ieee80211_auth {
	struct ieee80211_hdr_3addr header;
	__le16 algorithm;
	__le16 transaction;
	__le16 status;
	/* challenge */
	struct ieee80211_info_element info_element[0];
} __attribute__ ((packed));

struct ieee80211_channel_switch {
	u8 id;
	u8 len;
	u8 mode;
	u8 channel;
	u8 count;
} __attribute__ ((packed));

struct ieee80211_action {
	struct ieee80211_hdr_3addr header;
	u8 category;
	u8 action;
	union {
		struct ieee80211_action_exchange {
			u8 token;
			struct ieee80211_info_element info_element[0];
		} exchange;
		struct ieee80211_channel_switch channel_switch;

	} format;
} __attribute__ ((packed));

struct ieee80211_disassoc {
	struct ieee80211_hdr_3addr header;
	__le16 reason;
} __attribute__ ((packed));

/* Alias deauth for disassoc */
#define ieee80211_deauth ieee80211_disassoc

struct ieee80211_probe_request {
	struct ieee80211_hdr_3addr header;
	/* SSID, supported rates */
	struct ieee80211_info_element info_element[0];
} __attribute__ ((packed));

struct ieee80211_probe_response {
	struct ieee80211_hdr_3addr header;
	u32 time_stamp[2];
	__le16 beacon_interval;
	__le16 capability;
	/* SSID, supported rates, FH params, DS params,
	 * CF params, IBSS params, TIM (if beacon), RSN */
	struct ieee80211_info_element info_element[0];
} __attribute__ ((packed));

/* Alias beacon for probe_response */
#define ieee80211_beacon ieee80211_probe_response

struct ieee80211_assoc_request {
	struct ieee80211_hdr_3addr header;
	__le16 capability;
	__le16 listen_interval;
	/* SSID, supported rates, RSN */
	struct ieee80211_info_element info_element[0];
} __attribute__ ((packed));

struct ieee80211_reassoc_request {
	struct ieee80211_hdr_3addr header;
	__le16 capability;
	__le16 listen_interval;
	u8 current_ap[ETH_ALEN];
	struct ieee80211_info_element info_element[0];
} __attribute__ ((packed));

struct ieee80211_assoc_response {
	struct ieee80211_hdr_3addr header;
	__le16 capability;
	__le16 status;
	__le16 aid;
	/* supported rates */
	struct ieee80211_info_element info_element[0];
} __attribute__ ((packed));

struct ieee80211_txb {
	u8 nr_frags;
	u8 encrypted;
	u8 rts_included;
	u8 reserved;
	__le16 frag_size;
	__le16 payload_size;
	mbuf_t fragments[0];
};

/* SWEEP TABLE ENTRIES NUMBER */
#define MAX_SWEEP_TAB_ENTRIES		  42
#define MAX_SWEEP_TAB_ENTRIES_PER_PACKET  7
/* MAX_RATES_LENGTH needs to be 12.  The spec says 8, and many APs
 * only use 8, and then use extended rates for the remaining supported
 * rates.  Other APs, however, stick all of their supported rates on the
 * main rates information element... */
#define MAX_RATES_LENGTH                  ((u8)12)
#define MAX_RATES_EX_LENGTH               ((u8)16)
#define MAX_NETWORK_COUNT                  128

#define CRC_LENGTH                 4U

#define MAX_WPA_IE_LEN 64

#define NETWORK_EMPTY_ESSID    (1<<0)
#define NETWORK_HAS_OFDM       (1<<1)
#define NETWORK_HAS_CCK        (1<<2)

/* QoS structure */
#define NETWORK_HAS_QOS_PARAMETERS      (1<<3)
#define NETWORK_HAS_QOS_INFORMATION     (1<<4)
#define NETWORK_HAS_QOS_MASK            (NETWORK_HAS_QOS_PARAMETERS | \
					 NETWORK_HAS_QOS_INFORMATION)

/* 802.11h */
#define NETWORK_HAS_POWER_CONSTRAINT    (1<<5)
#define NETWORK_HAS_CSA                 (1<<6)
#define NETWORK_HAS_QUIET               (1<<7)
#define NETWORK_HAS_IBSS_DFS            (1<<8)
#define NETWORK_HAS_TPC_REPORT          (1<<9)

#define NETWORK_HAS_ERP_VALUE           (1<<10)

#define QOS_QUEUE_NUM                   4
#define QOS_OUI_LEN                     3
#define QOS_OUI_TYPE                    2
#define QOS_ELEMENT_ID                  221
#define QOS_OUI_INFO_SUB_TYPE           0
#define QOS_OUI_PARAM_SUB_TYPE          1
#define QOS_VERSION_1                   1
#define QOS_AIFSN_MIN_VALUE             2

struct ieee80211_qos_information_element {
	u8 elementID;
	u8 length;
	u8 qui[QOS_OUI_LEN];
	u8 qui_type;
	u8 qui_subtype;
	u8 version;
	u8 ac_info;
} __attribute__ ((packed));

struct ieee80211_qos_ac_parameter {
	u8 aci_aifsn;
	u8 ecw_min_max;
	__le16 tx_op_limit;
} __attribute__ ((packed));

struct ieee80211_qos_parameter_info {
	struct ieee80211_qos_information_element info_element;
	u8 reserved;
	struct ieee80211_qos_ac_parameter ac_params_record[QOS_QUEUE_NUM];
} __attribute__ ((packed));

struct ieee80211_qos_parameters {
	__le16 cw_min[QOS_QUEUE_NUM];
	__le16 cw_max[QOS_QUEUE_NUM];
	u8 aifs[QOS_QUEUE_NUM];
	u8 flag[QOS_QUEUE_NUM];
	__le16 tx_op_limit[QOS_QUEUE_NUM];
} __attribute__ ((packed));

struct ieee80211_qos_data {
	struct ieee80211_qos_parameters parameters;
	int active;
	int supported;
	u8 param_count;
	u8 old_param_count;
};

struct ieee80211_tim_parameters {
	u8 tim_count;
	u8 tim_period;
} __attribute__ ((packed));

/*******************************************************/

enum {				/* ieee80211_basic_report.map */
	IEEE80211_BASIC_MAP_BSS = (1 << 0),
	IEEE80211_BASIC_MAP_OFDM = (1 << 1),
	IEEE80211_BASIC_MAP_UNIDENTIFIED = (1 << 2),
	IEEE80211_BASIC_MAP_RADAR = (1 << 3),
	IEEE80211_BASIC_MAP_UNMEASURED = (1 << 4),
	/* Bits 5-7 are reserved */

};
struct ieee80211_basic_report {
	u8 channel;
	__le64 start_time;
	__le16 duration;
	u8 map;
} __attribute__ ((packed));

enum {				/* ieee80211_measurement_request.mode */
	/* Bit 0 is reserved */
	IEEE80211_MEASUREMENT_ENABLE = (1 << 1),
	IEEE80211_MEASUREMENT_REQUEST = (1 << 2),
	IEEE80211_MEASUREMENT_REPORT = (1 << 3),
	/* Bits 4-7 are reserved */
};

enum {
	IEEE80211_REPORT_BASIC = 0,	/* required */
	IEEE80211_REPORT_CCA = 1,	/* optional */
	IEEE80211_REPORT_RPI = 2,	/* optional */
	/* 3-255 reserved */
};

struct ieee80211_measurement_params {
	u8 channel;
	__le64 start_time;
	__le16 duration;
} __attribute__ ((packed));

struct ieee80211_measurement_request {
	struct ieee80211_info_element ie;
	u8 token;
	u8 mode;
	u8 type;
	struct ieee80211_measurement_params params[0];
} __attribute__ ((packed));

struct ieee80211_measurement_report {
	struct ieee80211_info_element ie;
	u8 token;
	u8 mode;
	u8 type;
	union {
		struct ieee80211_basic_report basic[0];
	} u;
} __attribute__ ((packed));

struct ieee80211_tpc_report {
	u8 transmit_power;
	u8 link_margin;
} __attribute__ ((packed));

struct ieee80211_channel_map {
	u8 channel;
	u8 map;
} __attribute__ ((packed));

struct ieee80211_ibss_dfs {
	struct ieee80211_info_element ie;
	u8 owner[ETH_ALEN];
	u8 recovery_interval;
	struct ieee80211_channel_map channel_map[0];
};

struct ieee80211_csa {
	u8 mode;
	u8 channel;
	u8 count;
} __attribute__ ((packed));

struct ieee80211_quiet {
	u8 count;
	u8 period;
	u8 duration;
	u8 offset;
} __attribute__ ((packed));

struct ieee80211_network {
	/* These entries are used to identify a unique network */
	u8 bssid[ETH_ALEN];
	u8 channel;
	/* Ensure null-terminated for any debug msgs */
	u8 ssid[IW_ESSID_MAX_SIZE + 1];
	u8 ssid_len;
	int exclude; // ip address filter
	struct ieee80211_qos_data qos_data;

	/* These are network statistics */
	struct ieee80211_rx_stats stats;
	u16 capability;
	u8 rates[MAX_RATES_LENGTH];
	u8 rates_len;
	u8 rates_ex[MAX_RATES_EX_LENGTH];
	u8 rates_ex_len;
	unsigned long last_scanned;
	u8 mode;
	u32 flags;
	u32 last_associate;
	u32 time_stamp[2];
	u16 beacon_interval;
	u16 listen_interval;
	u16 atim_window;
	u8 erp_value;
	u8 wpa_ie[MAX_WPA_IE_LEN];
	size_t wpa_ie_len;
	u8 rsn_ie[MAX_WPA_IE_LEN];
	size_t rsn_ie_len;
	struct ieee80211_tim_parameters tim;

	/* 802.11h info */

	/* Power Constraint - mandatory if spctrm mgmt required */
	u8 power_constraint;

	/* TPC Report - mandatory if spctrm mgmt required */
	struct ieee80211_tpc_report tpc_report;

	/* IBSS DFS - mandatory if spctrm mgmt required and IBSS
	 * NOTE: This is variable length and so must be allocated dynamically */
	struct ieee80211_ibss_dfs *ibss_dfs;

	/* Channel Switch Announcement - optional if spctrm mgmt required */
	struct ieee80211_csa csa;

	/* Quiet - optional if spctrm mgmt required */
	struct ieee80211_quiet quiet;

	struct list_head list;
};

enum ieee80211_state {
	IEEE80211_UNINITIALIZED = 0,
	IEEE80211_INITIALIZED,
	IEEE80211_ASSOCIATING,
	IEEE80211_ASSOCIATED,
	IEEE80211_AUTHENTICATING,
	IEEE80211_AUTHENTICATED,
	IEEE80211_SHUTDOWN
};

#define DEFAULT_MAX_SCAN_AGE (15 * HZ)
#define DEFAULT_FTS 2346

#define CFG_IEEE80211_RESERVE_FCS (1<<0)
#define CFG_IEEE80211_COMPUTE_FCS (1<<1)
#define CFG_IEEE80211_RTS (1<<2)

#define IEEE80211_24GHZ_MIN_CHANNEL 1
#define IEEE80211_24GHZ_MAX_CHANNEL 14
#define IEEE80211_24GHZ_CHANNELS (IEEE80211_24GHZ_MAX_CHANNEL - \
				  IEEE80211_24GHZ_MIN_CHANNEL + 1)

#define IEEE80211_52GHZ_MIN_CHANNEL 34
#define IEEE80211_52GHZ_MAX_CHANNEL 165
#define IEEE80211_52GHZ_CHANNELS (IEEE80211_52GHZ_MAX_CHANNEL - \
				  IEEE80211_52GHZ_MIN_CHANNEL + 1)

enum {
	IEEE80211_CH_PASSIVE_ONLY = (1 << 0),
	IEEE80211_CH_80211H_RULES = (1 << 1),
	IEEE80211_CH_B_ONLY = (1 << 2),
	IEEE80211_CH_NO_IBSS = (1 << 3),
	IEEE80211_CH_UNIFORM_SPREADING = (1 << 4),
	IEEE80211_CH_RADAR_DETECT = (1 << 5),
	IEEE80211_CH_INVALID = (1 << 6),
};

/*struct ieee80211_channel {
	u32 freq;	
	u8 channel;
	u8 flags;
	u8 max_power;	
};*/

struct ieee80211_geo {
	u8 name[4];
	u8 bg_channels;
	u8 a_channels;
	struct ieee80211_channel bg[IEEE80211_24GHZ_CHANNELS];
	struct ieee80211_channel a[IEEE80211_52GHZ_CHANNELS];
};

struct ieee80211_device {
	struct net_device *dev;
	struct ieee80211_security sec;

	/* Bookkeeping structures */
	struct net_device_stats stats;
	struct ieee80211_stats ieee_stats;

	struct ieee80211_geo geo;

	/* Probe / Beacon management */
	struct list_head network_free_list;
	struct list_head network_list;
	struct ieee80211_network *networks;
	int scans;
	int scan_age;

	int iw_mode;		/* operating mode (IW_MODE_*) */
	struct iw_spy_data spy_data;	/* iwspy support */
	spinlock_t lock;
	int tx_headroom;	/* Set to size of any additional room needed at front
				 * of allocated Tx SKBs */
	u32 config;

	/* WEP and other encryption related settings at the device level */
	int open_wep;		/* Set to 1 to allow unencrypted frames */

	int reset_on_keychange;	/* Set to 1 if the HW needs to be reset on
				 * WEP key changes */

	/* If the host performs {en,de}cryption, then set to 1 */
	int host_encrypt;
	int host_encrypt_msdu;
	int host_decrypt;
	/* host performs multicast decryption */
	int host_mc_decrypt;

	int host_open_frag;
	int host_build_iv;
	int ieee802_1x;		/* is IEEE 802.1X used */

	/* WPA data */
	int wpa_enabled;
	int drop_unencrypted;
	int privacy_invoked;
	size_t wpa_ie_len;
	u8 *wpa_ie;

	struct list_head crypt_deinit_list;
	struct ieee80211_crypt_data *crypt[WEP_KEYS];
	int tx_keyidx;		/* default TX key index (crypt[tx_keyidx]) */
	struct timer_list crypt_deinit_timer;
	int crypt_quiesced;

	int bcrx_sta_key;	/* use individual keys to override default keys even
				 * with RX of broad/multicast frames */

	/* Fragmentation structures */
	struct ieee80211_frag_entry frag_cache[IEEE80211_FRAG_CACHE_LEN];
	unsigned int frag_next_idx;
	u16 fts;		/* Fragmentation Threshold */
	u16 rts;		/* RTS threshold */

	/* Association info */
	u8 bssid[ETH_ALEN];

	enum ieee80211_state state;

	int mode;		/* A, B, G */
	int modulation;		/* CCK, OFDM */
	int freq_band;		/* 2.4Ghz, 5.2Ghz, Mixed */
	int abg_true;		/* ABG flag              */

	int perfect_rssi;
	int worst_rssi;

	/* Callback functions */
	void (*set_security) (struct net_device * dev,
			      struct ieee80211_security * sec);
	int (*hard_start_xmit) (struct ieee80211_txb * txb,
				struct net_device * dev, int pri);
	int (*reset_port) (struct net_device * dev);
	int (*is_queue_full) (struct net_device * dev, int pri);

	int (*handle_management) (struct net_device * dev,
				  struct ieee80211_network * network, u16 type);
	int (*is_qos_active) (struct net_device *dev, mbuf_t skb);

	/* Typical STA methods */
	int (*handle_auth) (struct net_device * dev,
			    struct ieee80211_auth * auth);
	int (*handle_deauth) (struct net_device * dev,
			      struct ieee80211_deauth * auth);
	int (*handle_action) (struct net_device * dev,
			      struct ieee80211_action * action,
			      struct ieee80211_rx_stats * stats);
	int (*handle_disassoc) (struct net_device * dev,
				struct ieee80211_disassoc * assoc);
	int (*handle_beacon) (struct net_device * dev,
			      struct ieee80211_beacon * beacon,
			      struct ieee80211_network * network);
	int (*handle_probe_response) (struct net_device * dev,
				      struct ieee80211_probe_response * resp,
				      struct ieee80211_network * network);
	int (*handle_probe_request) (struct net_device * dev,
				     struct ieee80211_probe_request * req,
				     struct ieee80211_rx_stats * stats);
	int (*handle_assoc_response) (struct net_device * dev,
				      struct ieee80211_assoc_response * resp,
				      struct ieee80211_network * network);

	/* Typical AP methods */
	int (*handle_assoc_request) (struct net_device * dev);
	int (*handle_reassoc_request) (struct net_device * dev,
				       struct ieee80211_reassoc_request * req);

	/* This must be the last item so that it points to the data
	 * allocated beyond this structure by alloc_ieee80211 */
	u8 priv[0];
};

#define IEEE_A            (1<<0)
#define IEEE_B            (1<<1)
#define IEEE_G            (1<<2)
#define IEEE_MODE_MASK    (IEEE_A|IEEE_B|IEEE_G)

//extern void *ieee80211_priv(struct net_device *dev);

//extern void *netdev_priv2(struct net_device *dev);

static void *ieee80211_priv(struct net_device *dev)
{
	return ((struct ieee80211_device *)netdev_priv(dev))->priv;
}

static inline int ieee80211_is_valid_mode(struct ieee80211_device *ieee,
					  int mode)
{
	/*
	 * It is possible for both access points and our device to support
	 * combinations of modes, so as long as there is one valid combination
	 * of ap/device supported modes, then return success
	 *
	 */
	if ((mode & IEEE_A) &&
	    (ieee->modulation & IEEE80211_OFDM_MODULATION) &&
	    (ieee->freq_band & IEEE80211_52GHZ_BAND))
		return 1;

	if ((mode & IEEE_G) &&
	    (ieee->modulation & IEEE80211_OFDM_MODULATION) &&
	    (ieee->freq_band & IEEE80211_24GHZ_BAND))
		return 1;

	if ((mode & IEEE_B) &&
	    (ieee->modulation & IEEE80211_CCK_MODULATION) &&
	    (ieee->freq_band & IEEE80211_24GHZ_BAND))
		return 1;

	return 0;
}

static inline int ieee80211_get_hdrlen(u16 fc)
{
	int hdrlen = IEEE80211_3ADDR_LEN;
	u16 stype = WLAN_FC_GET_STYPE(fc);

	switch (WLAN_FC_GET_TYPE(fc)) {
	case IEEE80211_FTYPE_DATA:
		if ((fc & IEEE80211_FCTL_FROMDS) && (fc & IEEE80211_FCTL_TODS))
			hdrlen = IEEE80211_4ADDR_LEN;
		if (stype & IEEE80211_STYPE_QOS_DATA)
			hdrlen += 2;
		break;
	case IEEE80211_FTYPE_CTL:
		switch (WLAN_FC_GET_STYPE(fc)) {
		case IEEE80211_STYPE_CTS:
		case IEEE80211_STYPE_ACK:
			hdrlen = IEEE80211_1ADDR_LEN;
			break;
		default:
			hdrlen = IEEE80211_2ADDR_LEN;
			break;
		}
		break;
	}

	return hdrlen;
}

static inline u8 *ieee80211_get_payload(struct ieee80211_hdr *hdr)
{
	switch (ieee80211_get_hdrlen(le16_to_cpu(hdr->frame_control))) {
	case IEEE80211_1ADDR_LEN:
		return ((struct ieee80211_hdr_1addr *)hdr)->payload;
	case IEEE80211_2ADDR_LEN:
		return ((struct ieee80211_hdr_2addr *)hdr)->payload;
	case IEEE80211_3ADDR_LEN:
		return ((struct ieee80211_hdr_3addr *)hdr)->payload;
	case IEEE80211_4ADDR_LEN:
		return ((struct ieee80211_hdr_4addr *)hdr)->payload;
	}
	return NULL;
}

static inline int ieee80211_is_ofdm_rate(u8 rate)
{
	switch (rate & ~IEEE80211_BASIC_RATE_MASK) {
	case IEEE80211_OFDM_RATE_6MB:
	case IEEE80211_OFDM_RATE_9MB:
	case IEEE80211_OFDM_RATE_12MB:
	case IEEE80211_OFDM_RATE_18MB:
	case IEEE80211_OFDM_RATE_24MB:
	case IEEE80211_OFDM_RATE_36MB:
	case IEEE80211_OFDM_RATE_48MB:
	case IEEE80211_OFDM_RATE_54MB:
		return 1;
	}
	return 0;
}

static inline int ieee80211_is_cck_rate(u8 rate)
{
	switch (rate & ~IEEE80211_BASIC_RATE_MASK) {
	case IEEE80211_CCK_RATE_1MB:
	case IEEE80211_CCK_RATE_2MB:
	case IEEE80211_CCK_RATE_5MB:
	case IEEE80211_CCK_RATE_11MB:
		return 1;
	}
	return 0;
}

extern const int ieee80211_api_version;

/* ieee80211.c */
//extern void free_ieee80211(struct net_device *dev);
//extern struct net_device *alloc_ieee80211(int sizeof_priv);

//extern int ieee80211_set_encryption(struct ieee80211_device *ieee);

/* ieee80211_tx.c */
//extern int ieee80211_xmit(mbuf_t skb, struct net_device *dev);
//extern void ieee80211_txb_free(struct ieee80211_txb *);
//extern int ieee80211_tx_frame(struct ieee80211_device *ieee,
//			      struct ieee80211_hdr *frame, int hdr_len,
//			      int total_len, int encrypt_mpdu);

/* ieee80211_rx.c */
//extern void ieee80211_rx_any(struct ieee80211_device *ieee,
//		     mbuf_t skb, struct ieee80211_rx_stats *stats);
//extern int ieee80211_rx(struct ieee80211_device *ieee, mbuf_t skb,
//			struct ieee80211_rx_stats *rx_stats);
/* make sure to set stats->len */
//extern void ieee80211_rx_mgt(struct ieee80211_device *ieee,
//			     struct ieee80211_hdr_4addr *header,
//			     struct ieee80211_rx_stats *stats);
//extern void ieee80211_network_reset(struct ieee80211_network *network);

/* ieee80211_geo.c */
//extern const struct ieee80211_geo *ieee80211_get_geo(struct ieee80211_device
//						     *ieee);
//extern int ieee80211_set_geo(struct ieee80211_device *ieee,
//			     const struct ieee80211_geo *geo);

//extern int ieee80211_is_valid_channel(struct ieee80211_device *ieee,
//				      u8 channel);
//extern int ieee80211_channel_to_index(struct ieee80211_device *ieee, u8 channel);
//extern u8 ieee80211_freq_to_channel(struct ieee80211_device *ieee, u32 freq);
//extern u8 ieee80211_get_channel_flags(struct ieee80211_device *ieee,
//				      u8 channel);
//extern const struct ieee80211_channel *ieee80211_get_channel(struct
//							     ieee80211_device
//							     *ieee, u8 channel);

/* ieee80211_wx.c */
/*extern int ieee80211_wx_get_scan(struct ieee80211_device *ieee,
				 struct iw_request_info *info,
				 union iwreq_data *wrqu, char *key);
extern int ieee80211_wx_set_encode(struct ieee80211_device *ieee,
				   struct iw_request_info *info,
				   union iwreq_data *wrqu, char *key);
extern int ieee80211_wx_get_encode(struct ieee80211_device *ieee,
				   struct iw_request_info *info,
				   union iwreq_data *wrqu, char *key);
extern int ieee80211_wx_set_encodeext(struct ieee80211_device *ieee,
				      struct iw_request_info *info,
				      union iwreq_data *wrqu, char *extra);
extern int ieee80211_wx_get_encodeext(struct ieee80211_device *ieee,
				      struct iw_request_info *info,
				      union iwreq_data *wrqu, char *extra);
extern int ieee80211_wx_set_auth(struct net_device *dev,
				 struct iw_request_info *info,
				 union iwreq_data *wrqu,
				 char *extra);
extern int ieee80211_wx_get_auth(struct net_device *dev,
				 struct iw_request_info *info,
				 union iwreq_data *wrqu,
				 char *extra);
*/
static inline void ieee80211_increment_scans(struct ieee80211_device *ieee)
{
	ieee->scans++;
}

static inline int ieee80211_get_scans(struct ieee80211_device *ieee)
{
	return ieee->scans;
}

#define NUM_RX_DATA_QUEUES 17
struct sta_info {
	void* kref;
	struct list_head list;
	struct sta_info *hnext; /* next entry in hash table list */

	struct ieee80211_local *local;

	u8 addr[ETH_ALEN];
	u16 aid; /* STA's unique AID (1..2007), 0 = not yet assigned */
	u32 flags; /* WLAN_STA_ */

	//struct sk_buff_head 
	struct list_head ps_tx_buf; /* buffer of TX frames for station in
					* power saving state */
	int pspoll; /* whether STA has send a PS Poll frame */
	//struct sk_buff_head 
	struct list_head tx_filtered; /* buffer of TX frames that were
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

struct rate_control_ops {
	struct module *module;
	const char *name;
	void (*tx_status)(void *priv, struct net_device *dev,
			  mbuf_t skb,
			  struct ieee80211_tx_status *status);
	struct ieee80211_rate *(*get_rate)(void *priv, struct net_device *dev,
					   mbuf_t skb,
					   struct rate_control_extra *extra);
	void (*rate_init)(void *priv, void *priv_sta,
			  struct ieee80211_local *local, struct sta_info *sta);
	void (*clear)(void *priv);

	void *(*alloc)(struct ieee80211_local *local);
	void (*free)(void *priv);
	void *(*alloc_sta)(void *priv, int gfp);
	void (*free_sta)(void *priv, void *priv_sta);

	int (*add_attrs)(void *priv, void *kobj);
	void (*remove_attrs)(void *priv, void *kobj);
	void (*add_sta_debugfs)(void *priv, void *priv_sta,
				struct dentry *dir);
	void (*remove_sta_debugfs)(void *priv, void *priv_sta);
};

struct rate_control_alg {
	struct list_head list;
	struct rate_control_ops *ops;
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
static inline int is_multicast_ether_addr(const u8 *addr)
{
       return addr[0] & 0x01;
}
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
#define RX_FLAG_MMIC_ERROR	(1<<0)
#define RX_FLAG_DECRYPTED	(1<<1)
#define RX_FLAG_RADIOTAP	(1<<2)
	int flag;
};

typedef enum {
	SET_KEY, DISABLE_KEY, REMOVE_ALL_KEYS,
} set_key_cmd;

struct ieee80211_tx_queue_stats_data {
	unsigned int len; /* num packets in queue */
	unsigned int limit; /* queue len (soft) limit */
	unsigned int count; /* total num frames sent */
};
struct ieee80211_tx_queue_stats {
	struct ieee80211_tx_queue_stats_data data[6];
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
						// key (used only for broadcast
						// keys). */
#define IEEE80211_KEY_DEFAULT_WEP_ONLY (1<<2) /* static WEP is the only
						 configured security policy;
						 this allows some low-level
						 drivers to determine when
						 hwaccel can be used */
	u32 flags; /* key configuration flags defined above */

	s8 keyidx;			/* WEP key index */
	u8 key[0];
};
struct ieee80211_if_conf {
	int type;
	u8 *bssid;
	u8 *ssid;
	size_t ssid_len;
	u8 *generic_elem;
	size_t generic_elem_len;
	mbuf_t beacon;
	struct ieee80211_tx_control *beacon_control;
};
struct ieee80211_if_init_conf {
	int if_id;
	int type;
	void *mac_addr;
};


struct ieee80211_ops {
	/* Handler that 802.11 module calls for each transmitted frame.
	 * skb contains the buffer starting from the IEEE 802.11 header.
	 * The low-level driver should send the frame out based on
	 * configuration in the TX control data.
	 * Must be atomic. */
	int (*tx)(struct ieee80211_hw *hw, mbuf_t skb,
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
	 * dev->mc_list is replaced by calling ieee80211_get_mc_list_item.
	 * Must be atomic. */
	void (*set_multicast_list)(struct ieee80211_hw *hw,
				   unsigned short flags, int mc_count);

	/* Set TIM bit handler. If the hardware/firmware takes care of beacon
	 * generation, IEEE 802.11 code uses this function to tell the
	 * low-level to set (or clear if set==0) TIM bit for the given aid. If
	 * host system is used to generate beacons, this handler is not used
	 * and low-level driver should set it to NULL.
	 * Must be atomic. */
	int (*set_tim)(struct ieee80211_hw *hw, int aid, int set);

	/* Set encryption key. IEEE 802.11 module calls this function to set
	 * encryption keys. addr is ff:ff:ff:ff:ff:ff for default keys and
	 * station hwaddr for individual keys. aid of the station is given
	 * to help low-level driver in selecting which key->hw_key_idx to use
	 * for this key. TX control data will use the hw_key_idx selected by
	 * the low-level driver.
	 * Must be atomic. */
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
	 * not require event notification about port state changes.
	 * Currently unused. */
	int (*set_port_auth)(struct ieee80211_hw *hw, u8 *addr,
			     int authorized);

	/* Ask the hardware to service the scan request, no need to start
	 * the scan state machine in stack. */
	int (*hw_scan)(struct ieee80211_hw *hw, u8 *ssid, size_t len);

	/* return low-level statistics */
	int (*get_stats)(struct ieee80211_hw *hw,
			 struct ieee80211_low_level_stats *stats);

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

	/* Number of STAs in STA table notification (NULL = disabled).
	 * Must be atomic. */
	void (*sta_table_notification)(struct ieee80211_hw *hw,
				       int num_sta);

	/* Configure TX queue parameters (EDCF (aifs, cw_min, cw_max),
	 * bursting) for a hardware TX queue.
	 * queue = IEEE80211_TX_QUEUE_*.
	 * Must be atomic. */
	int (*conf_tx)(struct ieee80211_hw *hw, int queue,
		       const struct ieee80211_tx_queue_params *params);

	/* Get statistics of the current TX queue status. This is used to get
	 * number of currently queued packets (queue length), maximum queue
	 * size (limit), and total number of packets sent using each TX queue
	 * (count).
	 * Currently unused. */
	int (*get_tx_stats)(struct ieee80211_hw *hw,
			    struct ieee80211_tx_queue_stats *stats);

	/* Get the current TSF timer value from firmware/hardware. Currently,
	 * this is only used for IBSS mode debugging and, as such, is not a
	 * required function.
	 * Must be atomic. */
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
			     mbuf_t skb,
			     struct ieee80211_tx_control *control);

	/* Determine whether the last IBSS beacon was sent by us. This is
	 * needed only for IBSS mode and the result of this function is used to
	 * determine whether to reply to Probe Requests. */
	int (*tx_last_beacon)(struct ieee80211_hw *hw);
};

struct ieee80211_fragment_entry {
	unsigned long first_frag_time;
	unsigned int seq;
	unsigned int rx_queue;
	unsigned int last_frag;
	unsigned int extra_len;
	struct list_head skb_list;
	int ccmp; /* Whether fragments were encrypted with CCMP */
	u8 last_pn[6]; /* PN of the last fragment if CCMP was used */
};

struct ieee80211_key {
	void* kref;

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
			//struct crypto_cipher 
			void* tfm;
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
	//atomic_t 
	int num_sta_ps; /* number of stations in PS mode */
	//struct sk_buff_head 
	struct list_head ps_bc_buf;
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

struct ieee80211_if_sta {
	enum {
		IEEE80211_DISABLED, IEEE80211_AUTHENTICATE,
		IEEE80211_ASSOCIATE, IEEE80211_ASSOCIATED,
		IEEE80211_IBSS_SEARCH, IEEE80211_IBSS_JOINED,
		IEEE80211_CHANNEL_SWITCH
	} state;
	//struct timer_list 
	void* timer;
	//struct work_struct 
	void* work;
	//struct timer_list 
	void* admit_timer; /* Recompute EDCA admitted time */
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
	//struct sk_buff_head 
	struct list_head skb_queue;

	int key_mgmt;
	unsigned long last_probe;

#define IEEE80211_AUTH_ALG_OPEN BIT(0)
#define IEEE80211_AUTH_ALG_SHARED_KEY BIT(1)
#define IEEE80211_AUTH_ALG_LEAP BIT(2)
	unsigned int auth_algs; /* bitfield of allowed auth algs */
	int auth_alg; /* currently used IEEE 802.11 authentication algorithm */
	int auth_transaction;

	unsigned long ibss_join_req;
	//struct sk_buff *
	mbuf_t probe_resp; /* ProbeResp template for IBSS */
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
#define container_of(ptr, type, member)					\
({									\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);		\
	(type *)( (char *)__mptr - offsetof(type,member) );		\
})
#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)
			  
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

static inline void prefetch(const void *x) {;}

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)
		
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))


#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

struct hlist_head {
	struct hlist_node *first;
};

static inline void __list_add(struct list_head *new2,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new2;
	new2->next = next;
	new2->prev = prev;
	prev->next = new2;
}

static inline void list_add_tail(struct list_head *new2, struct list_head *head)
{
	__list_add(new2, head->prev, head);
}

static inline void list_add(struct list_head *new2, struct list_head *head)
{
	__list_add(new2, head, head->next);
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
		next->pprev = pprev;
}

static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
	(void*)n->next = LIST_POISON1;
	(void*)n->pprev = LIST_POISON2;
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	(void*)entry->next = LIST_POISON1;
	(void*)entry->prev = LIST_POISON2;
}
static inline unsigned compare_ether_addr(const u8 *_a, const u8 *_b)
{
	const u16 *a = (const u16 *) _a;
	const u16 *b = (const u16 *) _b;

	//BUILD_BUG_ON(ETH_ALEN != 6);
	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
}
static inline int is_broadcast_ether_addr(const u8 *addr)
{
        return (addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff;
}
static inline int ieee80211_get_morefrag(struct ieee80211_hdr *hdr)
{
	return (le16_to_cpu(hdr->frame_control) &
		IEEE80211_FCTL_MOREFRAGS) != 0;
}
static struct ieee80211_local* hw_to_local(struct ieee80211_hw *hw)
{
	return container_of(hw, struct ieee80211_local, hw);
}
static struct ieee80211_hw* local_to_hw(struct ieee80211_local *local)
{
	return &local->hw;
}
static inline struct ieee80211_conf *ieee80211_get_hw_conf(struct ieee80211_hw *hw)
{
	return &hw->conf;
}
static void ieee80211_if_sdata_init(struct ieee80211_sub_if_data *sdata)
{
	int i;

	/* Default values for sub-interface parameters */
	sdata->drop_unencrypted = 0;
	sdata->eapol = 1;
	for (i = 0; i < IEEE80211_FRAGMENT_MAX; i++)
	{
		INIT_LIST_HEAD(&sdata->fragments[i].skb_list);
	//	skb_queue_head_init(&sdata->fragments[i].skb_list);
	}
}
static int ieee80211_hw_config(struct ieee80211_local *local)
{
	struct ieee80211_hw_mode *mode;
	struct ieee80211_channel *chan;
	int ret = 0;

	if (local->sta_scanning) {
		chan = local->scan_channel;
		mode = local->scan_hw_mode;
	} else {
		chan = local->oper_channel;
		mode = local->oper_hw_mode;
	}

	if (!chan || !mode) return 1;
	local->hw.conf.channel = chan->chan;
	local->hw.conf.channel_val = chan->val;
	local->hw.conf.power_level =
		(local->user_txpow < chan->power_level) ?
			local->user_txpow : chan->power_level;
	local->hw.conf.freq = chan->freq;
	local->hw.conf.phymode = mode->mode;
	local->hw.conf.antenna_max = chan->antenna_max;
	local->hw.conf.chan = chan;
	local->hw.conf.mode = mode;

//#ifdef CONFIG_MAC80211_VERBOSE_DEBUG
	printk("HW CONFIG: channel=%d freq=%d "
	       "phymode=%d\n", local->hw.conf.channel, local->hw.conf.freq,
	       local->hw.conf.phymode);
//#endif /* CONFIG_MAC80211_VERBOSE_DEBUG */

	if (local->ops->config)
		ret = local->ops->config(local_to_hw(local), &local->hw.conf);

	return ret;
}
static int __ieee80211_if_config(struct net_device *dev,
				 mbuf_t beacon,
				 struct ieee80211_tx_control *control)
{
	struct ieee80211_sub_if_data *sdata;
	sdata = (struct ieee80211_sub_if_data*)netdev_priv(dev);// IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = (struct ieee80211_local*)(dev->ieee80211_ptr);//wdev_priv
	struct ieee80211_if_conf conf;
	static u8 scan_bssid[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	if (!local->ops->config_interface)// || !netif_running(dev))
		return 0;

	memset(&conf, 0, sizeof(conf));
	conf.type = sdata->type;
	if (sdata->type == IEEE80211_IF_TYPE_STA ||
	    sdata->type == IEEE80211_IF_TYPE_IBSS) {
		if (local->sta_scanning &&
		    local->scan_dev == dev)
			conf.bssid = scan_bssid;
		else
			conf.bssid = sdata->u.sta.bssid;
		conf.ssid = sdata->u.sta.ssid;
		conf.ssid_len = sdata->u.sta.ssid_len;
		conf.generic_elem = sdata->u.sta.extra_ie;
		conf.generic_elem_len = sdata->u.sta.extra_ie_len;
	} else if (sdata->type == IEEE80211_IF_TYPE_AP) {
		conf.ssid = sdata->u.ap.ssid;
		conf.ssid_len = sdata->u.ap.ssid_len;
		conf.generic_elem = sdata->u.ap.generic_elem;
		conf.generic_elem_len = sdata->u.ap.generic_elem_len;
		conf.beacon = beacon;
		conf.beacon_control = control;
	}
	return local->ops->config_interface(local_to_hw(local),
					   dev->ifindex, &conf);
}

static int ieee80211_if_config(struct net_device *dev)
{
	return __ieee80211_if_config(dev, NULL, NULL);
}

static inline void skb_reserve(mbuf_t skb, int len)
{
	//skb->data += len;
	//skb->tail += len;
	/*        if (mbuf_len(skb)==0)
{
		void *data=(UInt8*)mbuf_data(skb)+len;
		mbuf_setdata(skb,data,mbuf_len(skb)+len);
} */
	//IWI_DUMP_MBUF(1,skb,len); 
	void *data = (UInt8*)mbuf_data(skb) + len;
	//IWI_DUMP_MBUF(2,skb,len);
	mbuf_setdata(skb,data, mbuf_len(skb));// m_len is not changed.
}

static inline void *skb_put(mbuf_t skb, unsigned int len)
{
	/*unsigned char *tmp = skb->tail;
	SKB_LINEAR_ASSERT(skb);
	skb->tail += len;
	skb->len  += len;
	return tmp;*/
	void *data = (UInt8*)mbuf_data(skb) + mbuf_len(skb);
	//mbuf_prepend(&skb,len,1); /* no prepend work */
	//IWI_DUMP_MBUF(1,skb,len);  
	if(mbuf_trailingspace(skb) > len ){
		mbuf_setlen(skb,mbuf_len(skb)+len);
		if(mbuf_flags(skb) & MBUF_PKTHDR)
			mbuf_pkthdr_setlen(skb,mbuf_pkthdr_len(skb)+len); 
	}
	//IWI_DUMP_MBUF(2,skb,len);  
	return data;
}

static inline void *skb_push(mbuf_t skb, unsigned int len)
{
	/*skb->data -= len;
	skb->len  += len;
	if (unlikely(skb->data<skb->head))
	skb_under_panic(skb, len, current_text_addr());
	return skb->data;*/
	/* void *data=(UInt8*)mbuf_data(skb)-len;
	mbuf_setdata(skb,data,mbuf_len(skb)+len); */
	//IWI_DUMP_MBUF(1,skb,len); 
	mbuf_prepend(&skb,len,0);
	//IWI_DUMP_MBUF(2,skb,len);
	return  (UInt8 *)mbuf_data(skb);
}

static inline void *skb_pull(mbuf_t skb, unsigned int len)
{
	/*skb->len -= len;
	BUG_ON(skb->len < skb->data_len);
	return skb->data += len;*/
	//IWI_DUMP_MBUF(1,skb,len);  
	mbuf_adj(skb,len);
	void *data=(UInt8*)mbuf_data(skb);
	//IWI_DUMP_MBUF(2,skb,len);		
	return data;
}
#define le16_to_cpu(x)	OSSwapLittleToHostInt16(x)
#define le32_to_cpu(x)	OSSwapLittleToHostInt32(x)
#define cpu_to_le16(x)	OSSwapLittleToHostInt16(x)
#define cpu_to_le32(x)	OSSwapLittleToHostInt32(x)
#define le64_to_cpu(x)	OSSwapLittleToHostInt64(x)

struct ieee80211_tx_packet_data {
	int ifindex;
	//unsigned long jiffies;
	unsigned int req_tx_status:1;
	unsigned int do_not_encrypt:1;
	unsigned int requeue:1;
	unsigned int mgmt_iface:1;
	unsigned int queue:4;
	unsigned int ht_queue:1;
};


extern void ieee80211_sta_tx(struct net_device *dev, mbuf_t skb, int encrypt);// in iwi3945.h

static void ieee80211_send_nullfunc(struct ieee80211_local *local,
				    struct ieee80211_sub_if_data *sdata,
				    int powersave)
{
	mbuf_t skb;
	struct ieee80211_hdr *nullfunc;
	u16 fc;

	//skb = dev_alloc_skb(local->hw.extra_tx_headroom + 24);
	if (mbuf_getpacket(MBUF_DONTWAIT, &skb)!=0) {
		printk(KERN_DEBUG "%s: failed to allocate buffer for nullfunc "
		       "frame\n", sdata->dev->name);
		return;
	}
	skb_reserve(skb, local->hw.extra_tx_headroom);

	nullfunc = (struct ieee80211_hdr *) skb_put(skb, 24);
	memset(nullfunc, 0, 24);
	fc = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_NULLFUNC |
	     IEEE80211_FCTL_TODS;
	if (powersave)
		fc |= IEEE80211_FCTL_PM;
	nullfunc->frame_control = cpu_to_le16(fc);
	memcpy(nullfunc->addr1, sdata->u.sta.bssid, ETH_ALEN);
	memcpy(nullfunc->addr2, sdata->dev->dev_addr, ETH_ALEN);
	memcpy(nullfunc->addr3, sdata->u.sta.bssid, ETH_ALEN);

	ieee80211_sta_tx(sdata->dev, skb, 0);
}

#define IEEE80211_HW_NO_PROBE_FILTERING (1<<10)
static void ieee80211_scan_completed(struct ieee80211_hw *hw)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct net_device *dev = local->mdev;//scan_dev;
	struct ieee80211_sub_if_data *sdata;
	//union iwreq_data wrqu;

	local->last_scan_completed = jiffies;
	//wmb();
	local->sta_scanning = 0;
	if (ieee80211_hw_config(local))
		printk("%s: failed to restore operational"
		       "channel after scan\n", dev->name);

	if (!(local->hw.flags & IEEE80211_HW_NO_PROBE_FILTERING) &&
	    ieee80211_if_config(dev))
		printk("%s: failed to restore operational"
		       "BSSID after scan\n", dev->name);

	//memset(&wrqu, 0, sizeof(wrqu));
	//wireless_send_event(dev, SIOCGIWSCAN, &wrqu, NULL);
	//read_lock(&local->sub_if_lock);
	list_for_each_entry(sdata, &local->sub_if_list, list) {

		/* No need to wake the master device. */
		if (sdata->dev == local->mdev)
			continue;

		if (sdata->type == IEEE80211_IF_TYPE_STA) {
			if (sdata->u.sta.associated)
				ieee80211_send_nullfunc(local, sdata, 0);
				printk("todo ieee80211_sta_timer\n");
			//ieee80211_sta_timer((unsigned long)sdata);
		}

		//netif_wake_queue(sdata->dev);
	}
	//read_unlock(&local->sub_if_lock);
	sdata = (struct ieee80211_sub_if_data*)netdev_priv(dev);// IEEE80211_DEV_TO_SUB_IF
	if (sdata->type == IEEE80211_IF_TYPE_IBSS) {
		struct ieee80211_if_sta *ifsta = &sdata->u.sta;
		/*if (!ifsta->bssid_set ||
		    (!ifsta->state == IEEE80211_IBSS_JOINED &&
		    !ieee80211_sta_active_ibss(dev)))
			//ieee80211_sta_find_ibss(dev, ifsta);*/
	}
}

#define IW_QUAL_QUAL_UPDATED	0x01	/* Value was updated since last read */
#define IW_QUAL_LEVEL_UPDATED	0x02
#define IW_QUAL_NOISE_UPDATED	0x04
#define IW_QUAL_ALL_UPDATED	0x07
#define IW_QUAL_DBM		0x08	/* Level + Noise are dBm */
#define IW_QUAL_QUAL_INVALID	0x10	/* Driver doesn't provide value */
#define IW_QUAL_LEVEL_INVALID	0x20
#define IW_QUAL_NOISE_INVALID	0x40
#define IW_QUAL_RCPI		0x80	/* Level + Noise are 802.11k RCPI */
#define IW_QUAL_ALL_INVALID	0x70

struct ieee80211_tx_status_rtap_hdr {
	struct ieee80211_radiotap_header hdr;
	__le16 tx_flags;
	u8 data_retries;
} __attribute__ ((packed));
#define CHAN_UTIL_RATE_LCM 95040
#define IEEE80211_HW_DEFAULT_REG_DOMAIN_CONFIGURED (1<<11)
static int rate_list_match(const int *rate_list, int rate)
{
	int i;

	if (!rate_list)
		return 0;

	for (i = 0; rate_list[i] >= 0; i++)
		if (rate_list[i] == rate)
			return 1;

	return 0;
}
static inline int ieee80211_is_erp_rate(int phymode, int rate)
{
	if (phymode == MODE_IEEE80211G) {
		if (rate != 10 && rate != 20 &&
		    rate != 55 && rate != 110)
			return 1;
	}
	return 0;
}

static int ieee80211_regdom = 0x10; /* FCC */
struct ieee80211_channel_range {
	short start_freq;
	short end_freq;
	unsigned char power_level;
	unsigned char antenna_max;
};
static const struct ieee80211_channel_range ieee80211_fcc_channels[] = {
	{ 2412, 2462, 27, 6 } /* IEEE 802.11b/g, channels 1..11 */,
	{ 5180, 5240, 17, 6 } /* IEEE 802.11a, channels 36..48 */,
	{ 5260, 5320, 23, 6 } /* IEEE 802.11a, channels 52..64 */,
	{ 5745, 5825, 30, 6 } /* IEEE 802.11a, channels 149..165, outdoor */,
	{ 0 }
};
static const struct ieee80211_channel_range *channel_range = ieee80211_fcc_channels;
static int ieee80211_japan_5ghz /* = 0 */;
static void ieee80211_unmask_channel(int mode, struct ieee80211_channel *chan)
{
	int i;

	chan->flag = 0;

	if (ieee80211_regdom == 64 &&
	    (mode == MODE_ATHEROS_TURBO || mode == MODE_ATHEROS_TURBOG)) {
		/* Do not allow Turbo modes in Japan. */
		return;
	}

	for (i = 0; channel_range[i].start_freq; i++) {
		const struct ieee80211_channel_range *r = &channel_range[i];
		if (r->start_freq <= chan->freq && r->end_freq >= chan->freq) {
			if (ieee80211_regdom == 64 && !ieee80211_japan_5ghz &&
			    chan->freq >= 5260 && chan->freq <= 5320) {
				/*
				 * Skip new channels in Japan since the
				 * firmware was not marked having been upgraded
				 * by the vendor.
				 */
				continue;
			}

			if (ieee80211_regdom == 0x10 &&
			    (chan->freq == 5190 || chan->freq == 5210 ||
			     chan->freq == 5230)) {
				    /* Skip MKK channels when in FCC domain. */
				    continue;
			}

			chan->flag |= IEEE80211_CHAN_W_SCAN |
				IEEE80211_CHAN_W_ACTIVE_SCAN |
				IEEE80211_CHAN_W_IBSS;
			chan->power_level = r->power_level;
			chan->antenna_max = r->antenna_max;

			if (ieee80211_regdom == 64 &&
			    (chan->freq == 5170 || chan->freq == 5190 ||
			     chan->freq == 5210 || chan->freq == 5230)) {
				/*
				 * New regulatory rules in Japan have backwards
				 * compatibility with old channels in 5.15-5.25
				 * GHz band, but the station is not allowed to
				 * use active scan on these old channels.
				 */
				chan->flag &= ~IEEE80211_CHAN_W_ACTIVE_SCAN;
			}

			if (ieee80211_regdom == 64 &&
			    (chan->freq == 5260 || chan->freq == 5280 ||
			     chan->freq == 5300 || chan->freq == 5320)) {
				/*
				 * IBSS is not allowed on 5.25-5.35 GHz band
				 * due to radar detection requirements.
				 */
				chan->flag &= ~IEEE80211_CHAN_W_IBSS;
			}

			break;
		}
	}
}
enum ieee80211_link_state_t {
	IEEE80211_LINK_STATE_XOFF = 0,
	IEEE80211_LINK_STATE_PENDING,
	IEEE80211_LINK_STATE_AGGREGATED,
};
static void ieee80211_start_queues(struct ieee80211_hw *hw)
{
	struct ieee80211_local *local = hw_to_local(hw);
	int i;

	for (i = 0; i < local->hw.queues; i++)
		//clear_bit(IEEE80211_LINK_STATE_XOFF, &local->state[i]);
		local->state[i]&=~IEEE80211_LINK_STATE_XOFF;
	//if (!ieee80211_qdisc_installed(local->mdev))
	//	netif_start_queue(local->mdev);
}
static void ieee80211_stop_queue(struct ieee80211_hw *hw, int queue)
{
	struct ieee80211_local *local = hw_to_local(hw);
	//if (!ieee80211_qdisc_installed(local->mdev) && queue == 0)
	//	netif_stop_queue(local->mdev);
	local->state[queue]|=IEEE80211_LINK_STATE_XOFF;	
	//set_bit(IEEE80211_LINK_STATE_XOFF, &local->state[queue]);
}
static void ieee80211_stop_queues(struct ieee80211_hw *hw)
{
	int i;

	for (i = 0; i < hw->queues; i++)
		ieee80211_stop_queue(hw, i);
}

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

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#undef LIST_HEAD
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)
#undef INIT_LIST_HEAD
#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

static LIST_HEAD(rate_ctrl_algs);

static int ieee80211_rate_control_register(struct rate_control_ops *ops)
{
	struct rate_control_alg *alg;

	alg = (struct rate_control_alg*)IOMalloc(sizeof(*alg));
	if (alg == NULL) {
		return -ENOMEM;
	}
	memset(alg, 0, sizeof(*alg));
	alg->ops = ops;

	//mutex_lock(&rate_ctrl_mutex);
	list_add_tail(&alg->list, &rate_ctrl_algs);
	//mutex_unlock(&rate_ctrl_mutex);

	return 0;
}
static void ieee80211_rate_control_unregister(struct rate_control_ops *ops)
{
	struct rate_control_alg *alg;

	//mutex_lock(&rate_ctrl_mutex);
	list_for_each_entry(alg, &rate_ctrl_algs, list) {
		if (alg->ops == ops) {
			list_del(&alg->list);
			break;
		}
	}
	//mutex_unlock(&rate_ctrl_mutex);
	IOFree(alg, sizeof(struct rate_control_alg));
}
#define BIT(x) (1 << (x))
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
#define WLAN_STA_HT  BIT(10)
#define WLAN_STA_WDS BIT(27)

#define STA_TID_NUM 16
#define ADDBA_RESP_INTERVAL HZ

/* For IEEE80211_RADIOTAP_RX_FLAGS */
#define IEEE80211_RADIOTAP_F_RX_BADFCS	0x0001	/* frame failed crc check */

/* For IEEE80211_RADIOTAP_TX_FLAGS */
#define IEEE80211_RADIOTAP_F_TX_FAIL	0x0001	/* failed due to excessive
						 * retries */
#define IEEE80211_RADIOTAP_F_TX_CTS	0x0002	/* used cts 'protection' */
#define IEEE80211_RADIOTAP_F_TX_RTS	0x0004	/* used rts/cts handshake */

#endif				/* IEEE80211_H */
