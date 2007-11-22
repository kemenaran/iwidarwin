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

#ifndef __iwl_helpers_h__
#define __iwl_helpers_h__
#include "defines.h"
/*
 * The structures defined by the hardware/uCode interface
 * have bit-wise operations.  For each bit-field there is
 * a data symbol in the structure, the start bit position
 * and the length of the bit-field.
 *
 * iwl_get_bits and iwl_set_bits will return or set the
 * appropriate bits on a 32-bit value.
 *
 * IWL_GET_BITS and IWL_SET_BITS use symbol expansion to
 * expand out to the appropriate call to iwl_get_bits
 * and iwl_set_bits without having to reference all of the
 * numerical constants and defines provided in the hardware
 * definition
 */

/**
 * iwl_get_bits - Extract a hardware bit-field value
 * @src: source hardware value (__le32)
 * @pos: bit-position (0-based) of first bit of value
 * @len: length of bit-field
 *
 * iwl_get_bits will return the bit-field in cpu endian ordering.
 *
 * NOTE:  If used from IWL_GET_BITS then pos and len are compile-constants and
 *        will collapse to minimal code by the compiler.
 */
#define iwl_get_bits(src, pos, len)   \
({                                    \
	u32 __tmp = le32_to_cpu(src); \
	__tmp >>= pos;                \
	__tmp &= (1UL << len) - 1;    \
	__tmp;                        \
})

/**
 * iwl_set_bits - Set a hardware bit-field value
 * @dst: Address of __le32 hardware value
 * @pos: bit-position (0-based) of first bit of value
 * @len: length of bit-field
 * @val: cpu endian value to encode into the bit-field
 *
 * iwl_set_bits will encode val into dst, masked to be len bits long at bit
 * position pos.
 *
 * NOTE:  If used IWL_SET_BITS pos and len will be compile-constants and
 *        will collapse to minimal code by the compiler.
 */
#define iwl_set_bits(dst, pos, len, val)                 \
({                                                       \
	u32 __tmp = le32_to_cpu(*dst);                   \
	__tmp &= ~((1ULL << (pos+len)) - (1 << pos));    \
	__tmp |= (val & ((1UL << len) - 1)) << pos;      \
	*dst = cpu_to_le32(__tmp);                       \
})

/*
 * The bit-field definitions in iwl-xxxx-hw.h are in the form of:
 *
 * struct example {
 *         __le32 val1;
 * #define IWL_name_POS 8
 * #define IWL_name_LEN 4
 * #define IWL_name_SYM val1
 * };
 *
 * The IWL_SET_BITS and IWL_GET_BITS macros are provided to allow the driver
 * to call:
 *
 * struct example bar;
 * u32 val = IWL_GET_BITS(bar, name);
 * val = val * 2;
 * IWL_SET_BITS(bar, name, val);
 *
 * All cpu / host ordering, masking, and shifts are performed by the macros
 * and iwl_{get,set}_bits.
 *
 */
#define _IWL_SET_BITS(s, d, o, l, v) \
	iwl_set_bits(&s.d, o, l, v)

#define IWL_SET_BITS(s, sym, v) \
	_IWL_SET_BITS((s), IWL_ ## sym ## _SYM, IWL_ ## sym ## _POS, \
		      IWL_ ## sym ## _LEN, (v))

#define _IWL_GET_BITS(s, v, o, l) \
	iwl_get_bits(s.v, o, l)

#define IWL_GET_BITS(s, sym) \
	_IWL_GET_BITS((s), IWL_ ## sym ## _SYM, IWL_ ## sym ## _POS, \
		      IWL_ ## sym ## _LEN)

/*
 * make C=2 CF=-Wall will complain if you use ARRAY_SIZE on global data
 */
#define GLOBAL_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* Debug and printf string expansion helpers for printing bitfields */
#define BIT_FMT8 "%c%c%c%c-%c%c%c%c"
#define BIT_FMT16 BIT_FMT8 ":" BIT_FMT8
#define BIT_FMT32 BIT_FMT16 " " BIT_FMT16

#define BITC(x, y) (((x>>y) & 1) ? '1' : '0')
#define BIT_ARG8(x) \
BITC(x, 7), BITC(x, 6), BITC(x, 5), BITC(x, 4), \
BITC(x, 3), BITC(x, 2), BITC(x, 1), BITC(x, 0)

#define BIT_ARG16(x) \
BITC(x, 15), BITC(x, 14), BITC(x, 13), BITC(x, 12), \
BITC(x, 11), BITC(x, 10), BITC(x, 9), BITC(x, 8), \
BIT_ARG8(x)

#define BIT_ARG32(x) \
BITC(x, 31), BITC(x, 30), BITC(x, 29), BITC(x, 28), \
BITC(x, 27), BITC(x, 26), BITC(x, 25), BITC(x, 24), \
BITC(x, 23), BITC(x, 22), BITC(x, 21), BITC(x, 20), \
BITC(x, 19), BITC(x, 18), BITC(x, 17), BITC(x, 16), \
BIT_ARG16(x)

#define KELVIN_TO_CELSIUS(x) ((x)-273)
#define CELSIUS_TO_KELVIN(x) ((x)+273)

#define IEEE80211_CHAN_W_RADAR_DETECT 0x00000010

/*
#define WLAN_FC_GET_TYPE(fc)    (((fc) & IEEE80211_FCTL_FTYPE))
#define WLAN_FC_GET_STYPE(fc)   (((fc) & IEEE80211_FCTL_STYPE))
#define WLAN_GET_SEQ_FRAG(seq)  ((seq) & 0x000f)
#define WLAN_GET_SEQ_SEQ(seq)   ((seq) >> 4)
*/
#define QOS_CONTROL_LEN 2

static inline __le16 *ieee80211_get_qos_ctrl(struct ieee80211_hdr *hdr)
{
	u16 fc = le16_to_cpu(hdr->frame_control);
	int hdr_len = ieee80211_get_hdrlen(fc);
	if ( (fc & 0x00cc) == (IEEE80211_STYPE_QOS_DATA|IEEE80211_FTYPE_DATA))
		return (u16 *) ((u8 *) hdr + hdr_len - QOS_CONTROL_LEN);
	return NULL;
}

#define IEEE80211_STYPE_BACK_REQ	0x0080
#define IEEE80211_STYPE_BACK		0x0090

#define ieee80211_is_back_request(fc) \
	((WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_CTL) && \
	(WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_BACK_REQ))

#define ieee80211_is_probe_response(fc) \
   ((WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) && \
    ( WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_PROBE_RESP ))

#define ieee80211_is_probe_request(fc) \
   ((WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) && \
    ( WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_PROBE_REQ ))

#define ieee80211_is_beacon(fc) \
   ((WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) && \
    ( WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_BEACON ))

#define ieee80211_is_atim(fc) \
   ((WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) && \
    ( WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_ATIM ))

#define ieee80211_is_management(fc) \
   (WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT)

#define ieee80211_is_control(fc) \
   (WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_CTL)

#define ieee80211_is_data(fc) \
   (WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_DATA)

#define ieee80211_is_assoc_request(fc) \
   ((WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) && \
   (WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_ASSOC_REQ))

#define ieee80211_is_assoc_response(fc) \
   ((WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) && \
   (WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_ASSOC_RESP))

#define ieee80211_is_auth(fc) \
   ((WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) && \
   (WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_ASSOC_REQ))

#define ieee80211_is_deauth(fc) \
   ((WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) && \
   (WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_ASSOC_REQ))

#define ieee80211_is_disassoc(fc) \
   ((WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) && \
   (WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_ASSOC_REQ))

#define ieee80211_is_reassoc_request(fc) \
   ((WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) && \
   (WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_REASSOC_REQ))

#define ieee80211_is_reassoc_response(fc) \
   ((WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) && \
   (WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_REASSOC_RESP))

static inline int iwl_is_empty_essid(const char *essid, int essid_len)
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

static inline int iwl_check_bits(unsigned long field, unsigned long mask)
{
	return ((field & mask) == mask) ? 1 : 0;
}

static inline const char *iwl_escape_essid(const char *essid, u8 essid_len)
{
	static char escaped[IW_ESSID_MAX_SIZE * 2 + 1];
	const char *s = essid;
	char *d = escaped;

	if (iwl_is_empty_essid(essid, essid_len)) {
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

static inline unsigned long elapsed_jiffies(unsigned long start,
					    unsigned long end)
{
	if (end > start)
		return end - start;

	return end + (0 - start);//MAX_JIFFY_OFFSET
}

//#include <linux/ctype.h>

static inline int snprint_line(char *buf, size_t count,
			       const u8 * data, u32 len, u32 ofs)
{
	int out, i, j, l;
	char c;

	out = snprintf(buf, count, "%08X", ofs);

	for (l = 0, i = 0; i < 2; i++) {
		out += snprintf(buf + out, count - out, " ");
		for (j = 0; j < 8 && l < len; j++, l++)
			out +=
			    snprintf(buf + out, count - out, "%02X ",
				     data[(i * 8 + j)]);
		for (; j < 8; j++)
			out += snprintf(buf + out, count - out, "   ");
	}
	out += snprintf(buf + out, count - out, " ");
	for (l = 0, i = 0; i < 2; i++) {
		out += snprintf(buf + out, count - out, " ");
		for (j = 0; j < 8 && l < len; j++, l++) {
			c = data[(i * 8 + j)];
			//if (!isascii(c) || !isprint(c))
			//	c = '.';

			out += snprintf(buf + out, count - out, "%c", c);
		}

		for (; j < 8; j++)
			out += snprintf(buf + out, count - out, " ");
	}

	return out;
}

#ifdef CONFIG_IWLWIFI_DEBUG
static inline void printk_buf(int level, const void *p, u32 len)
{
	const u8 *data;
	(void*)data = (void*)p;
	char line[81];
	u32 ofs = 0;
	if (!(iwl_debug_level & level))
		return;

	while (len) {
		snprint_line(line, sizeof(line), &data[ofs],
			     min(len, 16U), ofs);
		printk(KERN_DEBUG "%s\n", line);
		ofs += 16;
		len -= min(len, 16U);
	}
}
#else
#define printk_buf(level, p, len) do {} while (0)
#endif

#endif				/* __iwl_helpers_h__ */
