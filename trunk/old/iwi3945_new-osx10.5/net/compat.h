/*
 * Header file to maintain compatibility among different kernel versions.
 *
 * Copyright (c) 2004-2006  Zhu Yi <yi.zhu@intel.com>, Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#ifdef __KERNEL__
//#include <linux/version.h>
#include <linux/if_ether.h>	/* ETH_ALEN */
#include <linux/wireless.h>
#endif

typedef signed char s8;
//typedef unsigned char u8; 
typedef signed short s16;
//typedef unsigned short u16;
typedef signed int s32;
//typedef unsigned int u32;
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
/*#define __bitwise __attribute__((bitwise))
typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;*/
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;

#define        __iomem
//#define        __le32          u32

#ifndef        NETDEV_TX_OK
#define        NETDEV_TX_OK            0
#endif

#ifndef ARPHRD_IEEE80211_RADIOTAP
#define ARPHRD_IEEE80211_RADIOTAP 803  /* IEEE 802.11 + radiotap header */
#endif

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(s)	spinlock_t s = SPIN_LOCK_UNLOCKED
#endif

#ifndef WIRELESS_SPY
#define WIRELESS_SPY		/* enable iwspy support */
#endif

#ifndef __nocast
#define __nocast
#endif

#ifndef NETDEV_TX_BUSY
#define NETDEV_TX_BUSY 1
#endif

typedef unsigned gfp_t;

/* WE compatibility macros */
#if WIRELESS_EXT < 17
#define IW_QUAL_QUAL_UPDATED    0x01    /* Value was updated since last read */
#define IW_QUAL_LEVEL_UPDATED   0x02
#define IW_QUAL_NOISE_UPDATED   0x04
#define IW_QUAL_ALL_UPDATED     0x07
#define IW_QUAL_QUAL_INVALID    0x10    /* Driver doesn't provide value */
#define IW_QUAL_LEVEL_INVALID   0x20
#define IW_QUAL_NOISE_INVALID   0x40
#define IW_QUAL_ALL_INVALID     0x70
#endif

#if WIRELESS_EXT < 19
#define IW_QUAL_DBM             0x08    /* Level + Noise are dBm */
#endif


static inline int is_multicast_ether_addr(const u8 *addr)
{
       return addr[0] & 0x01;
}

static inline int is_broadcast_ether_addr(const u8 *addr)
{
        return (addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff;
}

static inline void *kzalloc(size_t size, unsigned __nocast flags)
{
	void *ret = kmalloc(size, flags);
	if (ret)
		memset(ret, 0, size);
	return ret;
}

static inline unsigned compare_ether_addr(const u8 *_a, const u8 *_b)
{
	const u16 *a = (const u16 *) _a;
	const u16 *b = (const u16 *) _b;

	BUILD_BUG_ON(ETH_ALEN != 6);
	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
}

