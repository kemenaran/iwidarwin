
#ifndef __iwi3945_h__
#define __iwi3945_h__

#include "defines.h"
#include "iwi3945-commands.h"
#include "iwl-prph.h"

#undef queue_init



/* Sizes and addresses for instruction and data memory (SRAM) in
 * 3945's embedded processor.  Driver access is via HBUS_TARG_MEM_* regs. */
#define RTC_INST_LOWER_BOUND            (0x000000)
#define ALM_RTC_INST_UPPER_BOUND        (0x014000)

#define RTC_DATA_LOWER_BOUND            (0x800000)
#define ALM_RTC_DATA_UPPER_BOUND        (0x808000)

#define ALM_RTC_INST_SIZE (ALM_RTC_INST_UPPER_BOUND - RTC_INST_LOWER_BOUND)
#define ALM_RTC_DATA_SIZE (ALM_RTC_DATA_UPPER_BOUND - RTC_DATA_LOWER_BOUND)

#define IWL_MAX_INST_SIZE ALM_RTC_INST_SIZE
#define IWL_MAX_DATA_SIZE ALM_RTC_DATA_SIZE

/* Size of uCode instruction memory in bootstrap state machine */
#define IWL_MAX_BSM_SIZE ALM_RTC_INST_SIZE






#define SEQ_TO_QUEUE(x)  ((x >> 8) & 0xbf)
#define QUEUE_TO_SEQ(x)  ((x & 0xbf) << 8)
#define SEQ_TO_INDEX(x) (x & 0xff)
#define INDEX_TO_SEQ(x) (x & 0xff)
#define SEQ_HUGE_FRAME  (0x4000)
#define SEQ_RX_FRAME    cpu_to_le16(0x8000)
#define SEQ_TO_SN(seq) (((seq) & IEEE80211_SCTL_SEQ) >> 4)
#define SN_TO_SEQ(ssn) (((ssn) << 4) & IEEE80211_SCTL_SEQ)
#define MAX_SN ((IEEE80211_SCTL_SEQ) >> 4)





/*
 * uCode queue management definitions ...
 * Queue #4 is the command queue for 3945 and 4965.
 */
#define IWL_CMD_QUEUE_NUM       4



//#define IWI_NOLOG
#define IWI_DEBUG_NORMAL
//#define IWI_DEBUG_FULL
#define CONFIG_IPW3945_DEBUG

#if defined(IWI_NOLOG)
	#define IWI_LOG(...) do{ }while(0)
#else
	#define IWI_LOG(...) printf("iwi3945: " __VA_ARGS__)
#endif

#define IOLog(...) IWI_LOG(__VA_ARGS__)

#if defined(IWI_DEBUG_FULL) || defined(IWI_DEBUG_NORMAL)
	#define IWI_DEBUG(...) IWI_LOG(__VA_ARGS__)
#else
	#define IWI_DEBUG(...) do{ }while(0)
#endif

#if defined(IWI_DEBUG_FULL)
	#define IWI_DEBUG_FULL(...) IWI_DEBUG(__VA_ARGS__)
#else
          #define IWI_DEBUG_FULL(...) do{ }while(0)
#endif


#define IEEE80211_DEBUG_MGMT(...) IWI_DEBUG("(80211_MGMT) "  __VA_ARGS__)
#define IEEE80211_DEBUG_SCAN(...) IWI_DEBUG("(80211_SCAN) "  __VA_ARGS__)


#define IWI_WARNING(...) IWI_LOG(" W " __VA_ARGS__)
#define IWI_ERR(...) IWI_LOG(" E " __VA_ARGS__)
#define IWL_ERROR(...) IWI_LOG(" E " __VA_ARGS__)

#define IWI_DEBUG_FN(fmt,...) IWI_DEBUG(" %s " fmt, __FUNCTION__, ##__VA_ARGS__)


#define IWI_DUMP_MBUF(...) do{ }while(0)



// I've added these IWL_XXX statements
#define IWL_WARNING(...) IWI_LOG(" W " __VA_ARGS__)
#define IWL_DEBUG(n, ...) IWI_LOG(" D " __VA_ARGS__)

#define IWL_DEBUG_ISR(...) IOLog(__VA_ARGS__)
#define IWL_DEBUG_INFO(...) IOLog(__VA_ARGS__)
#define IWL_DEBUG_RF_KILL(...) IOLog(__VA_ARGS__)
#define IWL_DEBUG_POWER(...) IOLog(__VA_ARGS__)
#define IWL_DEBUG_MAC80211(...) IOLog(__VA_ARGS__)
#define IWL_DELAY_NEXT_SCAN(...) IOLog(__VA_ARGS__)
#define IWL_DEBUG_SCAN(...) IOLog(__VA_ARGS__)
#define IWL_DEBUG_HC(...) IOLog(__VA_ARGS__)

#define IWL_DL_INFO 1
#define IWL_DL_RF_KILL 1
#define IWL_DL_ISR 1



#define IWL_PLCP_QUIET_THRESH       __constant_cpu_to_le16(1)	/* packets */
#define IWL_ACTIVE_QUIET_TIME       __constant_cpu_to_le16(5)	/* msec */







#define write_direct32(addr, data) write32(addr, data) /*IOMappedWrite32(memBase+addr, data)*/
#define read_direct32(addr) read32(addr) /*IOMappedRead32(memBase+addr)*/
#define set_bits_prph(reg, mask) \
    write_prph(reg, (read_prph(reg) | mask))
#define set_bits_mask_prph(reg, bits, mask) \
    write_prph(reg, ((read_prph(reg) & mask) | bits))




// Stolen from net/iee80211.h
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((u8*)(x))[0],((u8*)(x))[1],((u8*)(x))[2],((u8*)(x))[3],((u8*)(x))[4],((u8*)(x))[5]






/* SKU Capabilities */
#define EEPROM_SKU_CAP_SW_RF_KILL_ENABLE                (1 << 0)
#define EEPROM_SKU_CAP_HW_RF_KILL_ENABLE                (1 << 1)
#define EEPROM_SKU_CAP_OP_MODE_MRC                      (1 << 7)







#define IWL_SUPPORTED_RATES_IE_LEN         8

#define SCAN_INTERVAL 100

#define MAX_A_CHANNELS  252
#define MIN_A_CHANNELS  7

#define MAX_B_CHANNELS  14
#define MIN_B_CHANNELS  1

#define STATUS_HCMD_ACTIVE	0	/* host command in progress */
#define STATUS_INT_ENABLED	1
#define STATUS_RF_KILL_HW	2
#define STATUS_RF_KILL_SW	3
#define STATUS_INIT		4
#define STATUS_ALIVE		5
#define STATUS_READY		6
#define STATUS_TEMPERATURE	7
#define STATUS_GEO_CONFIGURED	8
#define STATUS_EXIT_PENDING	9
#define STATUS_IN_SUSPEND	10
#define STATUS_STATISTICS	11
#define STATUS_SCANNING		12
#define STATUS_SCAN_ABORTING	13
#define STATUS_SCAN_HW		14
#define STATUS_POWER_PMI	15
#define STATUS_FW_ERROR		16
#define STATUS_CONF_PENDING	17

#define MAX_TID_COUNT        9

#define IWL_INVALID_RATE     0xFF
#define IWL_INVALID_VALUE    -1




#define IWL3965_MAX_RATE (33)




/*
 * Driver API command-id
 */

static const char ipw_modes[] = {
	'a', 'b', 'g', '?'
};

struct ipw_ucode {
	u32 ver;
	u32 inst_size;		// size of runtime instructions
	u32 data_size;		// size of runtime data
	u32 boot_size;		// size of bootstrap instructions
	u32 boot_data_size;	// size of bootstrap data
	u8 data[0];		// data appears in same order as "size" elements
};


#define ipw_set_bits_mask_restricted_reg(priv, reg, bits, mask) \
__ipw_set_bits_mask_restricted_reg(__LINE__, priv, reg, bits, mask)

#define _ipw_set_bits_mask_restricted_reg(priv, reg, bits, mask) \
        _ipw_write_restricted_reg( \
            priv, reg, ((_ipw_read_restricted_reg(priv, reg) & mask) | bits))
			
#define ipw_set_bits_restricted_reg(priv, reg, mask) \
__ipw_set_bits_restricted_reg(__LINE__, priv, reg, mask)

#define _ipw_set_bits_restricted_reg(priv, reg, mask) \
	_ipw_write_restricted_reg(priv, reg, \
				  (_ipw_read_restricted_reg(priv, reg) | mask))
				  
struct ipw_status_code {
	u16 status;
	const char *reason;
};

#define container_of(ptr, type, member)					\
({									\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);		\
	(type *)( (char *)__mptr - offsetof(type,member) );		\
})

			  
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

static inline void prefetch(const void *x) {;}

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

/*
struct ipw_network_match {
	struct ieee80211_network *network;
	struct ipw_supported_rates rates;
};
 */

struct fw_header {
	u32 version;
	u32 mode;
};

struct fw_chunk {
	u32 address;
	u32 length;
};

struct firmware {
	size_t size;
	u8 *data;
};

struct iwi_hdr {
	UInt8	type;
#define IWI_HDR_TYPE_DATA	0
#define IWI_HDR_TYPE_COMMAND	1
#define IWI_HDR_TYPE_NOTIF	3
#define IWI_HDR_TYPE_FRAME	9

	UInt8	seq;
	UInt8	flags;
#define IWI_HDR_FLAG_IRQ	0x04

	UInt8	reserved;
}  __attribute__ ((packed));


/* command */
struct iwi_cmd_desc {
	struct iwi_hdr	hdr;
	UInt8		type;
#define IWI_CMD_ENABLE				2
#define IWI_CMD_SET_CONFIG			6
#define IWI_CMD_SET_ESSID			8
#define IWI_CMD_SET_MAC_ADDRESS			11
#define IWI_CMD_SET_RTS_THRESHOLD		15
#define IWI_CMD_SET_FRAG_THRESHOLD		16
#define IWI_CMD_SET_POWER_MODE			17
#define IWI_CMD_SET_WEP_KEY			18
#define IWI_CMD_SCAN				20
#define IWI_CMD_ASSOCIATE			21
#define IWI_CMD_SET_RATES			22
#define IWI_CMD_ABORT_SCAN			23
#define IWI_CMD_SET_WME_PARAMS			25
#define IWI_CMD_SET_OPTIE			31
#define IWI_CMD_DISABLE				33
#define IWI_CMD_SET_IV				34
#define IWI_CMD_SET_TX_POWER			35
#define IWI_CMD_SET_SENSITIVITY			42
#define IWI_CMD_SET_WMEIE			84

	UInt8		len;
	UInt16	reserved;
	UInt8		data[120];
} __attribute__ ((packed));


struct iwi_cmd_ring {
//	bus_dma_tag_t		desc_dmat;
//	bus_dmamap_t		desc_map;
//	bus_addr_t		physaddr;
	IOBufferMemoryDescriptor *memD;
	dma_addr_t	physaddr;
	struct iwi_cmd_desc	*desc;
	int			count;
	int			queued;
	int			cur;
	int			next;
};

struct iwi_rx_radiotap_header {
//	struct ieee80211_radiotap_header wr_ihdr;
	UInt8		wr_flags;
	UInt8		wr_rate;
	UInt16	wr_chan_freq;
	UInt16	wr_chan_flags;
	UInt8		wr_antsignal;
	UInt8		wr_antenna;
};

#define IWI_RX_RADIOTAP_PRESENT						\
	((1 << IEEE80211_RADIOTAP_FLAGS) |				\
	 (1 << IEEE80211_RADIOTAP_RATE) |				\
	 (1 << IEEE80211_RADIOTAP_CHANNEL) |				\
	 (1 << IEEE80211_RADIOTAP_DB_ANTSIGNAL) |			\
	 (1 << IEEE80211_RADIOTAP_ANTENNA))

struct iwi_tx_radiotap_header {
//	struct ieee80211_radiotap_header wt_ihdr;
	UInt8		wt_flags;
	UInt16	wt_chan_freq;
	UInt16	wt_chan_flags;
};

struct iwi_tx_data {
	IOMemoryMap*	map;
	mbuf_t			m;
//	struct ieee80211_node	*ni;
};

struct iwi_tx_ring {
//	bus_dma_tag_t		desc_dmat;
//	bus_dma_tag_t		data_dmat;
//	bus_dmamap_t		desc_map;
	dma_addr_t		physaddr;
//	bus_addr_t		csr_ridx;
//	bus_addr_t		csr_widx;
	struct iwi_tx_desc	*desc;
	struct iwi_tx_data	*data;
	int			count;
	int			queued;
	int			cur;
	IOBufferMemoryDescriptor *memD;
	int			next;
};

struct iwi_rx_data {
	IOBufferMemoryDescriptor *memD;
//	bus_dmamap_t	map;
	dma_addr_t	physaddr;
	UInt32	reg;
	mbuf_t		m;
	void *			m_data;
};

/*
struct iwi_rx_ring {
//	bus_dma_tag_t		data_dmat;
	struct iwi_rx_data	*data;
	int			count;
	int			cur;
};
 */

/* header for transmission */
struct iwi_tx_desc {
	struct iwi_hdr	hdr;
	UInt32	reserved1;
	UInt8		station;
	UInt8		reserved2[3];
	UInt8		cmd;
#define IWI_DATA_CMD_TX	0x0b

	UInt8		seq;
	UInt16	len;
	UInt8		priority;
	UInt8		flags;
#define IWI_DATA_FLAG_SHPREAMBLE	0x04
#define IWI_DATA_FLAG_NO_WEP		0x20
#define IWI_DATA_FLAG_NEED_ACK		0x80

	UInt8		xflags;
#define IWI_DATA_XFLAG_QOS	0x10

	UInt8		wep_txkey;
//	UInt8		wepkey[IEEE80211_KEYBUF_SIZE];
	UInt8		rate;
	UInt8		antenna;
	UInt8		reserved3[10];
//	struct ieee80211_qosframe_addr4	wh;
	UInt32	iv;
	UInt32	eiv;
	UInt32	nseg;
#define IWI_MAX_NSEG	6

	UInt32	seg_addr[IWI_MAX_NSEG];
	UInt16	seg_len[IWI_MAX_NSEG];
};

struct iwi_configuration {
	UInt8	bluetooth_coexistence;
	UInt8	reserved1;
	UInt8	answer_pbreq;
	UInt8	allow_invalid_frames;
	UInt8	multicast_enabled;
	UInt8	drop_unicast_unencrypted;
	UInt8	disable_unicast_decryption;
	UInt8	drop_multicast_unencrypted;
	UInt8	disable_multicast_decryption;
	UInt8	antenna;
	UInt8	reserved2;
	UInt8	use_protection;
	UInt8	protection_ctsonly;
	UInt8	enable_multicast_filtering;
	UInt8	bluetooth_threshold;
	UInt8	reserved4;
	UInt8	allow_beacon_and_probe_resp;
	UInt8	allow_mgt;
	UInt8	noise_reported;
	UInt8	reserved5;
} __attribute__ ((packed));

/* structure for command IWI_CMD_SET_RATES */
struct iwi_rateset {
	UInt8	mode;
	UInt8	nrates;
	UInt8	type;
#define IWI_RATESET_TYPE_NEGOCIATED	0
#define IWI_RATESET_TYPE_SUPPORTED	1

	UInt8	reserved;
	UInt8	rates[12];
} __attribute__ ((packed));



struct iwi_scan {
	UInt8		type;
#define IWI_SCAN_TYPE_PASSIVE	1
#define IWI_SCAN_TYPE_BROADCAST	3

	UInt16		dwelltime;
	UInt8		channels[54];
#define IWI_CHAN_5GHZ	(0 << 6)
#define IWI_CHAN_2GHZ	(1 << 6)

	UInt8		reserved[3];
} __attribute__ ((packed));


typedef enum {
    MEDIUM_TYPE_NONE = 0,
    MEDIUM_TYPE_AUTO,
    MEDIUM_TYPE_1MBIT,
    MEDIUM_TYPE_2MBIT,
    MEDIUM_TYPE_5MBIT,
    MEDIUM_TYPE_11MBIT,
    MEDIUM_TYPE_54MBIT,
	MEDIUM_TYPE_ADHOC,
    MEDIUM_TYPE_INVALID
} mediumType_t;





/* *regulatory* channel data from eeprom, one for each channel */
struct iwl3945_eeprom_channel {
	u8 flags;		/* flags copied from EEPROM */
	s8 max_power_avg;	/* max power (dBm) on this chnl, limit 31 */
} __attribute__ ((packed));
/*
 * Mapping of a Tx power level, at factory calibration temperature,
 *   to a radio/DSP gain table index.
 * One for each of 5 "sample" power levels in each band.
 * v_det is measured at the factory, using the 3945's built-in power amplifier
 *   (PA) output voltage detector.  This same detector is used during Tx of
 *   long packets in normal operation to provide feedback as to proper output
 *   level.
 * Data copied from EEPROM.
 * DO NOT ALTER THIS STRUCTURE!!!
 */
struct iwl3945_eeprom_txpower_sample {
	u8 gain_index;		/* index into power (gain) setup table ... */
	s8 power;		/* ... for this pwr level for this chnl group */
	u16 v_det;		/* PA output voltage */
} __attribute__ ((packed));

/*
 * Mappings of Tx power levels -> nominal radio/DSP gain table indexes.
 * One for each channel group (a.k.a. "band") (1 for BG, 4 for A).
 * Tx power setup code interpolates between the 5 "sample" power levels
 *    to determine the nominal setup for a requested power level.
 * Data copied from EEPROM.
 * DO NOT ALTER THIS STRUCTURE!!!
 */
struct iwl3945_eeprom_txpower_group {
	struct iwl3945_eeprom_txpower_sample samples[5];  /* 5 power levels */
	s32 a, b, c, d, e;	/* coefficients for voltage->power
     * formula (signed) */
	s32 Fa, Fb, Fc, Fd, Fe;	/* these modify coeffs based on
     * frequency (signed) */
	s8 saturation_power;	/* highest power possible by h/w in this
     * band */
	u8 group_channel;	/* "representative" channel # in this band */
	s16 temperature;	/* h/w temperature at factory calib this band
     * (signed) */
} __attribute__ ((packed));




/*
 * Temperature-based Tx-power compensation data, not band-specific.
 * These coefficients are use to modify a/b/c/d/e coeffs based on
 *   difference between current temperature and factory calib temperature.
 * Data copied from EEPROM.
 */
struct iwl3945_eeprom_temperature_corr {
	u32 Ta;
	u32 Tb;
	u32 Tc;
	u32 Td;
	u32 Te;
} __attribute__ ((packed));









/*
 * EEPROM map
 */
struct iwl3945_eeprom {
	u8 reserved0[16];
#define EEPROM_DEVICE_ID                    (2*0x08)	/* 2 bytes */
	u16 device_id;	/* abs.ofs: 16 */
	u8 reserved1[2];
#define EEPROM_PMC                          (2*0x0A)	/* 2 bytes */
	u16 pmc;		/* abs.ofs: 20 */
	u8 reserved2[20];
#define EEPROM_MAC_ADDRESS                  (2*0x15)	/* 6  bytes */
	u8 mac_address[6];	/* abs.ofs: 42 */
	u8 reserved3[58];
#define EEPROM_BOARD_REVISION               (2*0x35)	/* 2  bytes */
	u16 board_revision;	/* abs.ofs: 106 */
	u8 reserved4[11];
#define EEPROM_BOARD_PBA_NUMBER             (2*0x3B+1)	/* 9  bytes */
	u8 board_pba_number[9];	/* abs.ofs: 119 */
	u8 reserved5[8];
#define EEPROM_VERSION                      (2*0x44)	/* 2  bytes */
	u16 version;		/* abs.ofs: 136 */
#define EEPROM_SKU_CAP                      (2*0x45)	/* 1  bytes */
	u8 sku_cap;		/* abs.ofs: 138 */
#define EEPROM_LEDS_MODE                    (2*0x45+1)	/* 1  bytes */
	u8 leds_mode;		/* abs.ofs: 139 */
#define EEPROM_OEM_MODE                     (2*0x46)	/* 2  bytes */
	u16 oem_mode;
#define EEPROM_WOWLAN_MODE                  (2*0x47)	/* 2  bytes */
	u16 wowlan_mode;	/* abs.ofs: 142 */
#define EEPROM_LEDS_TIME_INTERVAL           (2*0x48)	/* 2  bytes */
	u16 leds_time_interval;	/* abs.ofs: 144 */
#define EEPROM_LEDS_OFF_TIME                (2*0x49)	/* 1  bytes */
	u8 leds_off_time;	/* abs.ofs: 146 */
#define EEPROM_LEDS_ON_TIME                 (2*0x49+1)	/* 1  bytes */
	u8 leds_on_time;	/* abs.ofs: 147 */
#define EEPROM_ALMGOR_M_VERSION             (2*0x4A)	/* 1  bytes */
	u8 almgor_m_version;	/* abs.ofs: 148 */
#define EEPROM_ANTENNA_SWITCH_TYPE          (2*0x4A+1)	/* 1  bytes */
	u8 antenna_switch_type;	/* abs.ofs: 149 */
	u8 reserved6[42];
#define EEPROM_REGULATORY_SKU_ID            (2*0x60)	/* 4  bytes */
	u8 sku_id[4];		/* abs.ofs: 192 */
    
    /*
     * Per-channel regulatory data.
     *
     * Each channel that *might* be supported by 3945 or 4965 has a fixed location
     * in EEPROM containing EEPROM_CHANNEL_* usage flags (LSB) and max regulatory
     * txpower (MSB).
     *
     * Entries immediately below are for 20 MHz channel width.  FAT (40 MHz)
     * channels (only for 4965, not supported by 3945) appear later in the EEPROM.
     *
     * 2.4 GHz channels 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
     */
#define EEPROM_REGULATORY_BAND_1            (2*0x62)	/* 2  bytes */
	u16 band_1_count;	/* abs.ofs: 196 */
#define EEPROM_REGULATORY_BAND_1_CHANNELS   (2*0x63)	/* 28 bytes */
	struct iwl3945_eeprom_channel band_1_channels[14];  /* abs.ofs: 196 */
    
    /*
     * 4.9 GHz channels 183, 184, 185, 187, 188, 189, 192, 196,
     * 5.0 GHz channels 7, 8, 11, 12, 16
     * (4915-5080MHz) (none of these is ever supported)
     */
#define EEPROM_REGULATORY_BAND_2            (2*0x71)	/* 2  bytes */
	u16 band_2_count;	/* abs.ofs: 226 */
#define EEPROM_REGULATORY_BAND_2_CHANNELS   (2*0x72)	/* 26 bytes */
	struct iwl3945_eeprom_channel band_2_channels[13];  /* abs.ofs: 228 */
    
    /*
     * 5.2 GHz channels 34, 36, 38, 40, 42, 44, 46, 48, 52, 56, 60, 64
     * (5170-5320MHz)
     */
#define EEPROM_REGULATORY_BAND_3            (2*0x7F)	/* 2  bytes */
	u16 band_3_count;	/* abs.ofs: 254 */
#define EEPROM_REGULATORY_BAND_3_CHANNELS   (2*0x80)	/* 24 bytes */
	struct iwl3945_eeprom_channel band_3_channels[12];  /* abs.ofs: 256 */
    
    /*
     * 5.5 GHz channels 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140
     * (5500-5700MHz)
     */
#define EEPROM_REGULATORY_BAND_4            (2*0x8C)	/* 2  bytes */
	u16 band_4_count;	/* abs.ofs: 280 */
#define EEPROM_REGULATORY_BAND_4_CHANNELS   (2*0x8D)	/* 22 bytes */
	struct iwl3945_eeprom_channel band_4_channels[11];  /* abs.ofs: 282 */
    
    /*
     * 5.7 GHz channels 145, 149, 153, 157, 161, 165
     * (5725-5825MHz)
     */
#define EEPROM_REGULATORY_BAND_5            (2*0x98)	/* 2  bytes */
	u16 band_5_count;	/* abs.ofs: 304 */
#define EEPROM_REGULATORY_BAND_5_CHANNELS   (2*0x99)	/* 12 bytes */
	struct iwl3945_eeprom_channel band_5_channels[6];  /* abs.ofs: 306 */
    
	u8 reserved9[194];
    
    /*
     * 3945 Txpower calibration data.
     */
#define EEPROM_TXPOWER_CALIB_GROUP0 0x200
#define EEPROM_TXPOWER_CALIB_GROUP1 0x240
#define EEPROM_TXPOWER_CALIB_GROUP2 0x280
#define EEPROM_TXPOWER_CALIB_GROUP3 0x2c0
#define EEPROM_TXPOWER_CALIB_GROUP4 0x300
#define IWL_NUM_TX_CALIB_GROUPS 5
	struct iwl3945_eeprom_txpower_group groups[IWL_NUM_TX_CALIB_GROUPS];
    /* abs.ofs: 512 */
#define EEPROM_CALIB_TEMPERATURE_CORRECT 0x340
	struct iwl3945_eeprom_temperature_corr corrections;  /* abs.ofs: 832 */
	u8 reserved16[172];	/* fill out to full 1024 byte block */
} __attribute__ ((packed));

#define IWL_EEPROM_IMAGE_SIZE 1024

/* End of EEPROM */






/**
 * REPLY_RXON = 0x10 (command, has simple generic response)
 *
 * RXON tunes the radio tuner to a service channel, and sets up a number
 * of parameters that are used primarily for Rx, but also for Tx operations.
 *
 * NOTE:  When tuning to a new channel, driver must set the
 *        RXON_FILTER_ASSOC_MSK to 0.  This will clear station-dependent
 *        info within the device, including the station tables, tx retry
 *        rate tables, and txpower tables.  Driver must build a new station
 *        table and txpower table before transmitting anything on the RXON
 *        channel.
 *
 * NOTE:  All RXONs wipe clean the internal txpower table.  Driver must
 *        issue a new REPLY_TX_PWR_TABLE_CMD after each REPLY_RXON (0x10),
 *        regardless of whether RXON_FILTER_ASSOC_MSK is set.
 */
/*
struct iwl3945_rxon_cmd {
    u8 node_addr[6];
    __le16 reserved1;
    u8 bssid_addr[6];
    __le16 reserved2;
    u8 wlap_bssid_addr[6];
    __le16 reserved3;
    u8 dev_type;
    u8 air_propagation;
    __le16 reserved4;
    u8 ofdm_basic_rates;
    u8 cck_basic_rates;
    __le16 assoc_id;
    __le32 flags;
    __le32 filter_flags;
    __le16 channel;
    __le16 reserved5;
} __attribute__ ((packed));
*/




struct iwl3945_rx_mem_buffer {
	dma_addr_t          dma_addr;
    mbuf_t              skb;
	struct list_head    list;
};




/**
 * struct iwl3945_rx_queue - Rx queue
 * @processed: Internal index to last handled Rx packet
 * @read: Shared index to newest available Rx buffer
 * @write: Shared index to oldest written Rx packet
 * @free_count: Number of pre-allocated buffers in rx_free
 * @rx_free: list of free SKBs for use
 * @rx_used: List of Rx buffers with no SKB
 * @need_update: flag to indicate we need to update read/write index
 *
 * NOTE:  rx_free and rx_used are used as a FIFO for iwl3945_rx_mem_buffers
 */
struct iwl3945_rx_queue {
	__le32 *bd;
	dma_addr_t dma_addr;
	struct iwl3945_rx_mem_buffer pool[RX_QUEUE_SIZE + RX_FREE_BUFFERS];
	struct iwl3945_rx_mem_buffer *queue[RX_QUEUE_SIZE];
	u32 processed;
	u32 read;
	u32 write;
	u32 free_count;
	struct list_head rx_free;
	struct list_head rx_used;
	int need_update;
	lck_spin_t *lock;
};


/*
 * Generic queue structure
 *
 * Contains common data for Rx and Tx queues
 */
struct iwl3945_queue {
    int n_bd;              /* number of BDs in this queue */
    int write_ptr;       /* 1-st empty entry (index) host_w*/
    int read_ptr;         /* last used entry (index) host_r*/
    dma_addr_t dma_addr;   /* physical addr for BD's */
    int n_window;          /* safe queue window */
    u32 id;
    int low_mark;          /* low watermark, resume queue if free
     * space more than this */
    int high_mark;         /* high watermark, stop queue if free
     * space less than this */
} __attribute__ ((packed));



#define MAX_NUM_OF_TBS          (20)



struct iwl3945_cmd;
struct iwl3945_priv;

struct iwl3945_cmd_meta {
    struct iwl3945_cmd_meta *source;
    union {
        mbuf_t skb;
        int (*callback)(struct iwl3945_cmd *cmd, mbuf_t skb);
    } __attribute__ ((packed)) u;
    
    /* The CMD_SIZE_HUGE flag bit indicates that the command
     * structure is stored at the end of the shared queue memory. */
    u32 flags;
    
} __attribute__ ((packed));




/**
 * struct iwl3945_tx_queue - Tx Queue for DMA
 * @q: generic Rx/Tx queue descriptor
 * @bd: base of circular buffer of TFDs
 * @cmd: array of command/Tx buffers
 * @dma_addr_cmd: physical address of cmd/tx buffer array
 * @txb: array of per-TFD driver data
 * @need_update: indicates need to update read/write index
 *
 * A Tx queue consists of circular buffer of BDs (a.k.a. TFDs, transmit frame
 * descriptors) and required locking structures.
 */
struct iwl3945_tx_queue {
    struct iwl3945_queue q;
    struct iwl3945_tfd_frame *bd;
    struct iwl3945_cmd *cmd;
    dma_addr_t dma_addr_cmd;
    struct iwl3945_tx_info *txb;
    int need_update;
    int active;
};






/* Power management (not Tx power) structures */

struct iwl3945_power_vec_entry {
    struct iwl3945_powertable_cmd cmd;
    u8 no_dtim;
};
#define IWL_POWER_RANGE_0  (0)
#define IWL_POWER_RANGE_1  (1)

#define IWL_POWER_MODE_CAM  0x00    /* Continuously Aware Mode, always on */
#define IWL_POWER_INDEX_3   0x03
#define IWL_POWER_INDEX_5   0x05
#define IWL_POWER_AC        0x06
#define IWL_POWER_BATTERY   0x07
#define IWL_POWER_LIMIT     0x07
#define IWL_POWER_MASK      0x0F
#define IWL_POWER_ENABLED   0x10
#define IWL_POWER_LEVEL(x)  ((x) & IWL_POWER_MASK)

struct iwl3945_power_mgr {
    lck_spin_t *slock;
    struct iwl3945_power_vec_entry pwr_range_0[IWL_POWER_AC];
    struct iwl3945_power_vec_entry pwr_range_1[IWL_POWER_AC];
    u8 active_index;
    u32 dtim_val;
};






#define is_associated() ((active_rxon.filter_flags & RXON_FILTER_ASSOC_MSK) ? 1 : 0)




struct iwl3945_channel_tgd_info {
	u8 type;
	s8 max_power;
};

struct iwl3945_channel_tgh_info {
	s64 last_radar_time;
};


/* current Tx power values to use, one for each rate for each channel.
 * requested power is limited by:
 * -- regulatory EEPROM limits for this channel
 * -- hardware capabilities (clip-powers)
 * -- spectrum management
 * -- user preference (e.g. iwconfig)
 * when requested power is set, base power index must also be set. */
struct iwl3945_channel_power_info {
	struct iwl3945_tx_power tpc;	/* actual radio and DSP gain settings */
	s8 power_table_index;	/* actual (compenst'd) index into gain table */
	s8 base_power_index;	/* gain index for power at factory temp. */
	s8 requested_power;	/* power (dBm) requested for this chnl/rate */
};


/* current scan Tx power values to use, one for each scan rate for each
 * channel. */
struct iwl3945_scan_power_info {
	struct iwl3945_tx_power tpc;	/* actual radio and DSP gain settings */
	s8 power_table_index;	/* actual (compenst'd) index into gain table */
	s8 requested_power;	/* scan pwr (dBm) requested for chnl/rate */
};




struct iwl3945_channel_info {
	struct iwl3945_channel_tgd_info tgd;
	struct iwl3945_channel_tgh_info tgh;
	struct iwl3945_eeprom_channel eeprom;	/* EEPROM regulatory limit */
	struct iwl3945_eeprom_channel fat_eeprom;	/* EEPROM regulatory limit for
     * FAT channel */
    
	u8 channel;	  /* channel number */
	u8 flags;	  /* flags copied from EEPROM */
	s8 max_power_avg; /* (dBm) regul. eeprom, normal Tx, any rate */
	s8 curr_txpow;	  /* (dBm) regulatory/spectrum/user (not h/w) */
	s8 min_power;	  /* always 0 */
	s8 scan_power;	  /* (dBm) regul. eeprom, direct scans, any rate */
    
	u8 group_index;	  /* 0-4, maps channel to group1/2/3/4/5 */
	u8 band_index;	  /* 0-4, maps channel to band1/2/3/4/5 */
	u8 phymode;	  /* MODE_IEEE80211{A,B,G} */
    
	/* Radio/DSP gain settings for each "normal" data Tx rate.
	 * These include, in addition to RF and DSP gain, a few fields for
	 *   remembering/modifying gain settings (indexes). */
	struct iwl3945_channel_power_info power_info[IWL3965_MAX_RATE];
    
	/* Radio/DSP gain settings for each scan rate, for directed scans. */
	struct iwl3945_scan_power_info scan_pwr_info[IWL_NUM_SCAN_RATES];
};




#pragma mark -
#pragma mark Define the station entry struct

struct iwl3945_tid_data {
    u16 seq_number;
};

struct iwl3945_hw_key {
    //ieee80211_key_alg alg;
    void *alg;
    int keylen;
    u8 key[32];
};


struct iwl3945_station_entry {
    struct iwl3945_addsta_cmd sta;
    struct iwl3945_tid_data tid[MAX_TID_COUNT];
    union {
        struct {
            u8 rate;
            u8 flags;
        } s;
        u16 rate_n_flags;
    } current_rate;
    u8 used;
    u8 ps_status;
    struct iwl3945_hw_key keyinfo;
};






/* one for each uCode image (inst/data, boot/init/runtime) */
struct fw_desc {
    void *v_addr;       /* access by driver */
    dma_addr_t p_addr;  /* access by card's busmaster DMA */
    u32 len;        /* bytes */
};


/* uCode file layout */
struct iwl3945_ucode {
    __le32 ver;     /* major/minor/subminor */
    __le32 inst_size;   /* bytes of runtime instructions */
    __le32 data_size;   /* bytes of runtime data */
    __le32 init_size;   /* bytes of initialization instructions */
    __le32 init_data_size;  /* bytes of initialization data */
    __le32 boot_size;   /* bytes of bootstrap instructions */
    u8 data[0];     /* data in same order as "size" elements */
};








enum {
    /* CMD_SIZE_NORMAL = 0, */
    CMD_SIZE_HUGE = (1 << 0),
    /* CMD_SYNC = 0, */
    CMD_ASYNC = (1 << 1),
    /* CMD_NO_SKB = 0, */
    CMD_WANT_SKB = (1 << 2),
};




/**
 * struct iwl3945_cmd
 *
 * For allocation of the command and tx queues, this establishes the overall
 * size of the largest command we send to uCode, except for a scan command
 * (which is relatively huge; space is allocated separately).
 */
struct iwl3945_cmd {
    struct iwl3945_cmd_meta meta;
    struct iwl3945_cmd_header hdr;
    union {
        struct iwl3945_addsta_cmd addsta;
        struct iwl3945_led_cmd led;
        u32 flags;
        u8 val8;
        u16 val16;
        u32 val32;
        struct iwl3945_bt_cmd bt;
        struct iwl3945_rxon_time_cmd rxon_time;
        struct iwl3945_powertable_cmd powertable;
        struct iwl3945_qosparam_cmd qosparam;
        struct iwl3945_tx_cmd tx;
        struct iwl3945_tx_beacon_cmd tx_beacon;
        struct iwl3945_rxon_assoc_cmd rxon_assoc;
        u8 *indirect;
        u8 payload[360];
    } __attribute__ ((packed)) cmd;
} __attribute__ ((packed));






/* One for each TFD */
struct iwl3945_tx_info {
//    struct ieee80211_tx_status status;
    char    status_stuff[128];
    mbuf_t  skb;
    //struct sk_buff *skb[MAX_NUM_OF_TBS];
};




struct iwl3945_tfd_frame_data {
    __le32 addr;
    __le32 len;
} __attribute__ ((packed));

struct iwl3945_tfd_frame {
    __le32 control_flags;
    struct iwl3945_tfd_frame_data pa[4];
    u8 reserved[28];
} __attribute__ ((packed));





/* Base physical address of iwl3945_shared is provided to FH_TSSR_CBB_BASE
 * and &iwl3945_shared.rx_read_ptr[0] is provided to FH_RCSR_RPTR_ADDR(0) */
struct iwl3945_shared {
    __le32 tx_base_ptr[8];
    __le32 rx_read_ptr[3];
} __attribute__ ((packed));


/**
 * struct iwl4965_driver_hw_info
 * @max_txq_num: Max # Tx queues supported
 * @ac_queue_count: # Tx queues for EDCA Access Categories (AC)
 * @tx_cmd_len: Size of Tx command (but not including frame itself)
 * @max_rxq_size: Max # Rx frames in Rx queue (must be power-of-2)
 * @rx_buffer_size:
 * @max_rxq_log: Log-base-2 of max_rxq_size
 * @max_stations:
 * @bcast_sta_id:
 * @shared_virt: Pointer to driver/uCode shared Tx Byte Counts and Rx status
 * @shared_phys: Physical Pointer to Tx Byte Counts and Rx status
 */
struct iwl3945_driver_hw_info {
    u16 max_txq_num;
    u16 ac_queue_count;
    u16 tx_cmd_len;
    u16 max_rxq_size;
    u32 rx_buffer_size;
    u16 max_rxq_log;
    u8  max_stations;
    u8  bcast_sta_id;
    void *shared_virt;
    dma_addr_t shared_phys;
};




enum iwl3945_antenna {
    IWL_ANTENNA_DIVERSITY,
    IWL_ANTENNA_MAIN,
    IWL_ANTENNA_AUX
};


const u8 iwl3945_broadcast_addr[ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };






struct iwl3945_rate_info {
	u8 plcp;		/* uCode API:  IWL_RATE_6M_PLCP, etc. */
	u8 ieee;		/* MAC header:  IWL_RATE_6M_IEEE, etc. */
	u8 prev_ieee;		/* previous rate in IEEE speeds */
	u8 next_ieee;		/* next rate in IEEE speeds */
	u8 prev_rs;		/* previous rate used in rs algo */
	u8 next_rs;		/* next rate used in rs algo */
	u8 prev_rs_tgg;		/* previous rate used in TGG rs algo */
	u8 next_rs_tgg;		/* next rate used in TGG rs algo */
    u8 table_rs_index;	/* index in rate scale table cmd */
    u8 prev_table_rs;	/* prev in rate table cmd */
};

/*
 * These serve as indexes into
 * struct iwl3945_rate_info iwl3945_rates[IWL_RATE_COUNT];
 */
enum {
	IWL_RATE_1M_INDEX = 0,
	IWL_RATE_2M_INDEX,
	IWL_RATE_5M_INDEX,
	IWL_RATE_11M_INDEX,
	IWL_RATE_6M_INDEX,
	IWL_RATE_9M_INDEX,
	IWL_RATE_12M_INDEX,
	IWL_RATE_18M_INDEX,
	IWL_RATE_24M_INDEX,
	IWL_RATE_36M_INDEX,
	IWL_RATE_48M_INDEX,
	IWL_RATE_54M_INDEX,
	IWL_RATE_COUNT,
	IWL_RATE_INVM_INDEX,
	IWL_RATE_INVALID = IWL_RATE_INVM_INDEX
};

enum {
	IWL_RATE_6M_INDEX_TABLE = 0,
	IWL_RATE_9M_INDEX_TABLE,
	IWL_RATE_12M_INDEX_TABLE,
	IWL_RATE_18M_INDEX_TABLE,
	IWL_RATE_24M_INDEX_TABLE,
	IWL_RATE_36M_INDEX_TABLE,
	IWL_RATE_48M_INDEX_TABLE,
	IWL_RATE_54M_INDEX_TABLE,
	IWL_RATE_1M_INDEX_TABLE,
	IWL_RATE_2M_INDEX_TABLE,
	IWL_RATE_5M_INDEX_TABLE,
	IWL_RATE_11M_INDEX_TABLE,
	IWL_RATE_INVM_INDEX_TABLE = IWL_RATE_INVM_INDEX,
};

enum {
	IWL_FIRST_OFDM_RATE = IWL_RATE_6M_INDEX,
	IWL_LAST_OFDM_RATE = IWL_RATE_54M_INDEX,
	IWL_FIRST_CCK_RATE = IWL_RATE_1M_INDEX,
	IWL_LAST_CCK_RATE = IWL_RATE_11M_INDEX,
};

/* #define vs. enum to keep from defaulting to 'large integer' */
#define	IWL_RATE_6M_MASK   (1<<IWL_RATE_6M_INDEX)
#define	IWL_RATE_9M_MASK   (1<<IWL_RATE_9M_INDEX)
#define	IWL_RATE_12M_MASK  (1<<IWL_RATE_12M_INDEX)
#define	IWL_RATE_18M_MASK  (1<<IWL_RATE_18M_INDEX)
#define	IWL_RATE_24M_MASK  (1<<IWL_RATE_24M_INDEX)
#define	IWL_RATE_36M_MASK  (1<<IWL_RATE_36M_INDEX)
#define	IWL_RATE_48M_MASK  (1<<IWL_RATE_48M_INDEX)
#define	IWL_RATE_54M_MASK  (1<<IWL_RATE_54M_INDEX)
#define	IWL_RATE_1M_MASK   (1<<IWL_RATE_1M_INDEX)
#define	IWL_RATE_2M_MASK   (1<<IWL_RATE_2M_INDEX)
#define	IWL_RATE_5M_MASK   (1<<IWL_RATE_5M_INDEX)
#define	IWL_RATE_11M_MASK  (1<<IWL_RATE_11M_INDEX)

/* 3945 uCode API values for (legacy) bit rates, both OFDM and CCK */
enum {
	IWL_RATE_6M_PLCP = 13,
	IWL_RATE_9M_PLCP = 15,
	IWL_RATE_12M_PLCP = 5,
	IWL_RATE_18M_PLCP = 7,
	IWL_RATE_24M_PLCP = 9,
	IWL_RATE_36M_PLCP = 11,
	IWL_RATE_48M_PLCP = 1,
	IWL_RATE_54M_PLCP = 3,
	IWL_RATE_1M_PLCP = 10,
	IWL_RATE_2M_PLCP = 20,
	IWL_RATE_5M_PLCP = 55,
	IWL_RATE_11M_PLCP = 110,
};

/* MAC header values for bit rates */
enum {
	IWL_RATE_6M_IEEE = 12,
	IWL_RATE_9M_IEEE = 18,
	IWL_RATE_12M_IEEE = 24,
	IWL_RATE_18M_IEEE = 36,
	IWL_RATE_24M_IEEE = 48,
	IWL_RATE_36M_IEEE = 72,
	IWL_RATE_48M_IEEE = 96,
	IWL_RATE_54M_IEEE = 108,
	IWL_RATE_1M_IEEE = 2,
	IWL_RATE_2M_IEEE = 4,
	IWL_RATE_5M_IEEE = 11,
	IWL_RATE_11M_IEEE = 22,
};

#define IWL_CCK_BASIC_RATES_MASK    \
(IWL_RATE_1M_MASK          | \
IWL_RATE_2M_MASK)

#define IWL_CCK_RATES_MASK          \
(IWL_BASIC_RATES_MASK      | \
IWL_RATE_5M_MASK          | \
IWL_RATE_11M_MASK)

#define IWL_OFDM_BASIC_RATES_MASK   \
(IWL_RATE_6M_MASK         | \
IWL_RATE_12M_MASK         | \
IWL_RATE_24M_MASK)

#define IWL_OFDM_RATES_MASK         \
(IWL_OFDM_BASIC_RATES_MASK | \
IWL_RATE_9M_MASK          | \
IWL_RATE_18M_MASK         | \
IWL_RATE_36M_MASK         | \
IWL_RATE_48M_MASK         | \
IWL_RATE_54M_MASK)

#define IWL_BASIC_RATES_MASK         \
(IWL_OFDM_BASIC_RATES_MASK | \
IWL_CCK_BASIC_RATES_MASK)

#define IWL_RATES_MASK ((1<<IWL_RATE_COUNT)-1)

#define IWL_INVALID_VALUE    -1

#define IWL_MIN_RSSI_VAL                 -100
#define IWL_MAX_RSSI_VAL                    0

extern const struct iwl3945_rate_info iwl3945_rates[IWL_RATE_COUNT];

static inline u8 iwl3945_get_prev_ieee_rate(u8 rate_index)
{
	u8 rate = iwl3945_rates[rate_index].prev_ieee;
    
	if (rate == IWL_RATE_INVALID)
		rate = rate_index;
	return rate;
}




/*
 * Regulatory channel usage flags in EEPROM struct iwl_eeprom_channel.flags.
 *
 * IBSS and/or AP operation is allowed *only* on those channels with
 * (VALID && IBSS && ACTIVE && !RADAR).  This restriction is in place because
 * RADAR detection is not supported by the 3945 driver, but is a
 * requirement for establishing a new network for legal operation on channels
 * requiring RADAR detection or restricting ACTIVE scanning.
 *
 * NOTE:  "WIDE" flag indicates that 20 MHz channel is supported;
 *        3945 does not support FAT 40 MHz-wide channels.
 *
 * NOTE:  Using a channel inappropriately will result in a uCode error!
 */
enum {
    EEPROM_CHANNEL_VALID = (1 << 0),    /* usable for this SKU/geo */
    EEPROM_CHANNEL_IBSS = (1 << 1),     /* usable as an IBSS channel */
    /* Bit 2 Reserved */
    EEPROM_CHANNEL_ACTIVE = (1 << 3),   /* active scanning allowed */
    EEPROM_CHANNEL_RADAR = (1 << 4),    /* radar detection required */
    EEPROM_CHANNEL_WIDE = (1 << 5),     /* 20 MHz channel okay */
    EEPROM_CHANNEL_NARROW = (1 << 6),   /* 10 MHz channel (not used) */
    EEPROM_CHANNEL_DFS = (1 << 7),  /* dynamic freq selection candidate */
};











#pragma mark -
#pragma mark Class definition





class darwin_iwi3945 : public IO80211Controller
{
	OSDeclareDefaultStructors(darwin_iwi3945)

public:
//virtual const char * getNamePrefix() const;
	virtual SInt32		apple80211Request( UInt32 req, int type, IO80211Interface * intf, void * data );
	virtual bool		init(OSDictionary *dictionary = 0);
	virtual void		free(void);

    virtual bool		start(IOService *provider);
    virtual void		stop(IOService *provider);

    
    virtual bool		createWorkLoop( void );
	virtual IOWorkLoop * getWorkLoop( void ) const;
	virtual IOOutputQueue * createOutputQueue( void );

    static void			interruptOccurred(OSObject * owner, void * src, IOService *nub, int count);
	virtual UInt32		handleInterrupt(void);
    
    
    virtual void setup_deferred_work();
    
    
    const struct iwl3945_channel_info *get_channel_info(int new_phymode, u16 new_channel);
	virtual bool		addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name = 0);
    
/*
//	virtual IOService *	probe(IOService *provider, SInt32 *score);
	virtual IOReturn	getHardwareAddress(IOEthernetAddress *addr);
	virtual IOReturn	enable(IONetworkInterface * netif);
	virtual IOReturn	disable(IONetworkInterface * netif);
	virtual bool		uploadFirmware2(UInt16 *base, const unsigned char *fw, UInt32 size, int offset);
	virtual bool		uploadFirmware(u8 * data, size_t len);
	virtual bool		uploadUCode(const unsigned char * data, UInt16 len);
	virtual bool		uploadUCode2(UInt16 *base, const unsigned char *uc, UInt16 size, int offset);
	virtual void		stopMaster(UInt16 *base);
	virtual void		stopDevice(UInt16 *base);
	virtual bool		resetDevice(UInt16 *);
	virtual UInt16		readPromWord(UInt16 *base, UInt8 addr);
	virtual IOBufferMemoryDescriptor * MemoryDmaAlloc(UInt32 buf_size, dma_addr_t *phys_add, void *virt_add);
//	virtual bool configureInterface( IONetworkInterface * interface );
	virtual const OSString * newModelString( void ) const;
	virtual const OSString * newVendorString( void ) const;
	virtual IOReturn	selectMedium(const IONetworkMedium * medium);
 

			
	virtual int			sendCommand(UInt8 type,void *data,UInt8 len,bool async);
	virtual int			ipw_scan(struct ipw_priv *priv, int type);
	virtual int			initCmdQueue();
	virtual int			resetCmdQueue();
	virtual int			initRxQueue();
	virtual int			resetRxQueue();
	virtual int			initTxQueue();
	virtual int			resetTxQueue();
	virtual void		RxQueueIntr();
	virtual int			configu(struct ipw_priv *priv);
	
	virtual IOReturn setPowerState ( unsigned long powerStateOrdinal, IOService* whatDevice );
virtual IOOptionBits getState( void ) const;

	virtual void notifIntr(struct ipw_priv *priv,
				struct ipw_rx_notification *notif);
*/
	
    
	/* Memory operation functions */
	virtual void inline write32(UInt32 offset, UInt32 data);
	virtual UInt32 inline read32(UInt32 offset);
	virtual void inline set_bit(UInt32 reg, UInt32 mask);
	virtual void inline clear_bit(UInt32 reg, UInt32 mask);
	virtual int poll_bit(u32 addr, u32 bits, u32 mask, int timeout);
	
	/* EEPROM functions */
    
    /*
	virtual void cacheEEPROM(struct ipw_priv *priv);
	virtual void inline eeprom_write_reg(UInt32 data);
	virtual void inline eeprom_cs(bool sel);
	virtual void inline eeprom_write_bit(UInt8 bit);
	virtual void eeprom_op(UInt8 op, UInt8 addr);
	virtual UInt16 eeprom_read_UInt16(UInt8 addr);
	virtual UInt32 read_reg_UInt32(UInt32 reg);
     */
    
    
    /* Our own functions */
    virtual inline void disable_interrupts(void);
    virtual inline void enable_interrupts(void);
    
    void tx_cmd_complete(struct iwl3945_rx_mem_buffer *rxb);

    
    void queue_te(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, bool start);
    void queue_td(int num , thread_call_func_t func);

    
    virtual int rx_queue_update_write_ptr(struct iwl3945_rx_queue *q);
    virtual int tx_queue_update_write_ptr(struct iwl3945_tx_queue *txq);
    
    virtual int eeprom_init(void);
    virtual inline int eeprom_acquire_semaphore(void);
    virtual void get_eeprom_mac(u8 *);
    
    
    virtual bool initialize_spinlocks(void);
    virtual void destroy_spinlocks(void);
    
    virtual void irq_handle_error(void);
    
    
    virtual int set_rxon_channel(u8 new_phymode, u16 channel);
	
    
    virtual void rx_handle();
    virtual void setup_rx_handlers();
    
	
	virtual int grab_nic_access(void);
	virtual void release_nic_access(void);
    
    
    virtual void cancel_deferred_work(void);
    
    virtual int hw_nic_init(void);
    virtual int power_init_handle(void);
    
    
    
    IOReturn bg_restart(void *arg0, void *arg1, void *arg2, void *arg3);
    IOReturn bg_up(void *arg0, void *arg1, void *arg2, void *arg3);
    IOReturn bg_down(void *arg0, void *arg1, void *arg2, void *arg3);
	
    virtual void down(void);
    virtual int up(void);
	
	
	SInt32	getSSID(IO80211Interface *interface,
							struct apple80211_ssid_data *sd);
	
	SInt32 getCHANNEL(IO80211Interface *interface,
							  struct apple80211_channel_data *cd);
	
	SInt32 getBSSID(IO80211Interface *interface,
							struct apple80211_bssid_data *bd);
	
	SInt32 getCARD_CAPABILITIES(IO80211Interface *interface,
										struct apple80211_capability_data *cd);
	
	SInt32 getSTATE(IO80211Interface *interface,
							struct apple80211_state_data *sd);
	
	SInt32 getRSSI(IO80211Interface *interface,
						   struct apple80211_rssi_data *rd);
	
	SInt32 getPOWER(IO80211Interface *interface,
							struct apple80211_power_data *pd);
	
	
	SInt32 getASSOCIATE_RESULT(IO80211Interface *interface,
                                    struct apple80211_assoc_result_data *ard);
	
	SInt32 getRATE(IO80211Interface *interface,
						   struct apple80211_rate_data *rd);
	
	SInt32 getSTATUS_DEV(IO80211Interface *interface,
								 struct apple80211_status_dev_data *dd);
	
	SInt32 getRATE_SET(IO80211Interface	*interface,
							   struct apple80211_rate_set_data *rd);
							   
	SInt32	getASSOCIATION_STATUS( IO80211Interface * interface, struct apple80211_assoc_status_data * asd );
    
    SInt32 getMCS_INDEX_SET(IO80211Interface*, apple80211_mcs_index_set_data*);

    SInt32 getPOWERSAVE(IO80211Interface*, apple80211_powersave_data*);

    SInt32 getHARDWARE_VERSION(IO80211Interface *interface,
                               struct apple80211_version_data *hv);
    
    SInt32 getDRIVER_VERSION(IO80211Interface *interface,
                             struct apple80211_version_data *hv);
    
    
    SInt32 getLOCALE(IO80211Interface *interface, apple80211_locale_data *ld);

    SInt32 getCOUNTRY_CODE(IO80211Interface *interface, apple80211_country_code_data *cd);
    
    SInt32 getPHY_MODE(IO80211Interface *interface, apple80211_phymode_data *pd);
    
    SInt32 getINT_MIT(IO80211Interface *interface, apple80211_intmit_data *mitd);
    
    SInt32 getTXPOWER(IO80211Interface *interface, apple80211_txpower_data *tx);

    SInt32 getOP_MODE(IO80211Interface *interface, apple80211_opmode_data *od);

    SInt32 getNOISE(IO80211Interface *interface, apple80211_noise_data *nd);
    
    SInt32 getSUPPORTED_CHANNELS(IO80211Interface *interface, apple80211_sup_channel_data *ad);

    SInt32 getTX_ANTENNA(IO80211Interface *interface, apple80211_antenna_data *ad);

    SInt32 getANTENNA_DIVERSITY(IO80211Interface *interface, apple80211_antenna_data *ad);
        
    SInt32 getSCAN_RESULT(IO80211Interface *interface, apple80211_scan_result **sr);
    
    SInt32 getSTATION_LIST(IO80211Interface *interface, apple80211_sta_data *sd);
    
    SInt32 setANTENNA_DIVERSITY(IO80211Interface *interface, apple80211_antenna_data *ad);
    
    SInt32 setTX_ANTENNA(IO80211Interface *interface, apple80211_antenna_data *ad);
    
    SInt32 setRATE(IO80211Interface *interface, apple80211_rate_data *rd);
    
    SInt32 setTXPOWER(IO80211Interface *interface, apple80211_txpower_data *td);

    SInt32 setINT_MIT(IO80211Interface *interface, apple80211_intmit_data *md);
    
    SInt32 setPROTMODE(IO80211Interface *interface, apple80211_protmode_data *pd);
    
    SInt32 setPHY_MODE(IO80211Interface *interface, apple80211_phymode_data *pd);
    
    SInt32 setLOCALE(IO80211Interface *interface, apple80211_locale_data *ld);
    
    SInt32 setPOWERSAVE(IO80211Interface*, apple80211_powersave_data*);

	SInt32 setSCAN_REQ(IO80211Interface *interface,
							   struct apple80211_scan_data *sd);
	
	SInt32 setASSOCIATE(IO80211Interface *interface,
								struct apple80211_assoc_data *ad);
	
	SInt32 setPOWER(IO80211Interface *interface,
							struct apple80211_power_data *pd);
	
	SInt32 setCIPHER_KEY(IO80211Interface *interface,
								 struct apple80211_key *key);
	
	SInt32 setAUTH_TYPE(IO80211Interface *interface,
								struct apple80211_authtype_data *ad);
	
	SInt32 setDISASSOCIATE(IO80211Interface	*interface);
	
	SInt32 setSSID(IO80211Interface *interface,
						   struct apple80211_ssid_data *sd);
	
	SInt32 setAP_MODE(IO80211Interface *interface,
							  struct apple80211_apmode_data *ad);

    SInt32 setCHANNEL(IO80211Interface *interface,
                      struct apple80211_channel_data *cd);

	virtual bool attachInterfaceWithMacAddress( void * macAddr, 
												UInt32 macLen, 
												IONetworkInterface ** interface, 
												bool doRegister ,
												UInt32 timeout  );

    virtual void	dataLinkLayerAttachComplete( IO80211Interface * interface );

    
    void postMessage(UInt32 message);
	
	int hw_set_hw_setting();
    void unset_hw_setting();
    
    int rx_queue_space(const struct iwl3945_rx_queue *q);

	u32 hw_get_rx_read();
    
    virtual bool configureInterface( IONetworkInterface *netif );
//    virtual SInt32 apple80211_ioctl(IO80211Interface *interface, 
//                                    ifnet_t ifn,
//                                    u_int32_t cmd,
//                                    void *data);
    virtual IOReturn getHardwareAddress(IOEthernetAddress *addr); 
    virtual IO80211Interface *getNetworkInterface();
    virtual IOService * getProvider();
    
    
    virtual UInt32		getFeatures() const;

    
    void clear_stations_table(void);
    int iwl3945_load_bsm();
    
    
    
    int tx_queue_reclaim(int txq_id, int index);

    virtual IOReturn enable( IONetworkInterface* netif );
	virtual IOReturn disable( IONetworkInterface* /*netif*/ );

    
    virtual int outputRaw80211Packet( IO80211Interface * interface, mbuf_t m );

    bool publishProperties();
    int iwl_read_ucode();
    int verify_bsm();
    int load_bsm();
    void nic_start();

    
    void iwl3945_txstatus_to_ieee(struct iwl3945_tx_info *tx_sta);
    int nic_set_pwr_src(int pwr_max);
    

    int tx_queue_init(struct iwl3945_tx_queue *txq, int slots_num, u32 txq_id);
    int tx_queue_alloc(struct iwl3945_tx_queue *txq, u32 id);
    int hw_tx_queue_init(struct iwl3945_tx_queue *txq);
    int txq_ctx_reset();
    void hw_txq_ctx_free();
    void tx_queue_free(struct iwl3945_tx_queue *txq);
    int hw_txq_free_tfd(struct iwl3945_tx_queue *txq);
    int tx_reset();
    void tx_queue_free();
    void hw_tx_queue_free();

    int rx_queue_alloc();
    void rx_queue_reset();
    void rx_replenish();
    void __rx_replenish();
    int rx_queue_restock();
    void rx_allocate();
    int rx_init();
    void rx_queue_free();

    int queue_init(struct iwl3945_queue *q, int count, int slots_num, u32 id);
    
    int mac_hw_scan(u8 *ssid, size_t len);
    int scan_initiate();


    inline int is_ready();
    inline int is_alive();
    inline int is_init();
    inline int is_ready_rf();
    inline int is_rfkill();
    
    __le32 get_antenna_flags();

    void bg_request_scan();
    u16 fill_probe_req(struct ieee80211_mgmt *frame,
                       int left, int is_direct);

    u16 supported_rate_to_ie(u8 *ie, u16 supported_rate, u16 basic_rate, int *left);
    int get_channels_for_scan(int phymode,
                                              u8 is_active, u8 direct_mask,
                                              struct iwl3945_scan_channel *scan_ch);
    const struct ieee80211_hw_mode *get_hw_mode(int mode);
    inline u16 get_active_dwell_time(int phymode);
    u16 get_passive_dwell_time(int phymode);

    
	// statistics
    IONetworkStats		*netStats;
    IOEthernetStats		*etherStats;
    
    // packet buffer variables
    IOMbufNaturalMemoryCursor                   *rxMbufCursor;
    IOMbufNaturalMemoryCursor                   *txMbufCursor;

    
inline UInt32 MEM_READ_4(UInt16 *base, UInt32 addr)
{
	CSR_WRITE_4(base, IWI_CSR_INDIRECT_ADDR, addr & IWI_INDIRECT_ADDR_MASK);
	return CSR_READ_4(base, IWI_CSR_INDIRECT_DATA);
}

inline UInt8 MEM_READ_1(UInt16 *base, UInt32 addr)
{
	CSR_WRITE_4(base, IWI_CSR_INDIRECT_ADDR, addr);
	return CSR_READ_1(base, IWI_CSR_INDIRECT_DATA);
}


inline void write_prph(u32 addr, u32 val)
{
	write_direct32(HBUS_TARG_PRPH_WADDR,
			      ((addr & 0x0000FFFF) | (3 << 24)));
	write_direct32(HBUS_TARG_PRPH_WDAT, val);
}

inline u32 read_prph(u32 reg)
{
	write_direct32(HBUS_TARG_PRPH_RADDR, reg | (3 << 24));
	return read_direct32(HBUS_TARG_PRPH_RDAT);
}
    
inline u8 get_cmd_index(struct iwl3945_queue *q, u32 index, int is_huge)
{
    /* This is for scan command, the big buffer at end of command array */
    if (is_huge)
        return q->n_window; /* must be power of 2 */
    
    /* Otherwise, use normal size buffers */
    return index & (q->n_window - 1);
}

inline int x2_queue_used(const struct iwl3945_queue *q, int i)
{
    return q->write_ptr > q->read_ptr ?
    (i >= q->read_ptr && i < q->write_ptr) :
    !(i < q->read_ptr && i >= q->write_ptr);
}
    
    /**
     * iwl3945_queue_inc_wrap - increment queue index, wrap back to beginning
     * @index -- current index
     * @n_bd -- total number of entries in queue (must be power of 2)
     */
    static inline int queue_inc_wrap(int index, int n_bd)
    {
        return ++index & (n_bd - 1);
    }
    
    /**
     * iwl3945_queue_dec_wrap - increment queue index, wrap back to end
     * @index -- current index
     * @n_bd -- total number of entries in queue (must be power of 2)
     */
    static inline int queue_dec_wrap(int index, int n_bd)
    {
        return --index & (n_bd - 1);
    }
    
    
    /**
     * iwl3945_dma_addr2rbd_ptr - convert a DMA address to a uCode read buffer ptr
     */
    inline __le32 dma_addr2rbd_ptr(dma_addr_t dma_addr)
    {
        return cpu_to_le32((u32)dma_addr);
    }
    
    
    inline int iwl3945_is_associated()
    {
        return ((active_rxon.filter_flags) & RXON_FILTER_ASSOC_MSK) ? 1 : 0;
    }
    
    inline int is_channel_valid(const struct iwl3945_channel_info *ch_info)
    {
        if (ch_info == NULL)
            return 0;
        return (ch_info->flags & EEPROM_CHANNEL_VALID) ? 1 : 0;
    }
    
    inline int is_channel_narrow(const struct iwl3945_channel_info *ch_info)
    {
        return (ch_info->flags & EEPROM_CHANNEL_NARROW) ? 1 : 0;
    }
    
    inline int is_channel_radar(const struct iwl3945_channel_info *ch_info)
    {
        return (ch_info->flags & EEPROM_CHANNEL_RADAR) ? 1 : 0;
    }
    
    inline u8 is_channel_a_band(const struct iwl3945_channel_info *ch_info)
    {
        return ch_info->phymode == MODE_IEEE80211A;
    }
    
    inline u8 is_channel_bg_band(const struct iwl3945_channel_info *ch_info)
    {
        return ((ch_info->phymode == MODE_IEEE80211B) ||
                (ch_info->phymode == MODE_IEEE80211G));
    }
    
    inline int is_channel_passive(const struct iwl3945_channel_info *ch)
    {
        return (!(ch->flags & EEPROM_CHANNEL_ACTIVE)) ? 1 : 0;
    }
    
    inline int is_channel_ibss(const struct iwl3945_channel_info *ch)
    {
        return ((ch->flags & EEPROM_CHANNEL_IBSS)) ? 1 : 0;
    }
    
    
    
    
    


#define CB_NUMBER_OF_ELEMENTS_SMALL 64

	IOPCIDevice *				fPCIDevice;		// PCI nub
	IOEthernetAddress			fEnetAddr;		// holds the mac address currently hardcoded
	IOWorkLoop *				workqueue;		// the workloop
    IO80211Interface*			fNetif;			// ???
	//IONetworkInterface2*			fNetif;
	IOInterruptEventSource *	fInterruptSrc;	// ???
//	IOTimerEventSource *		fWatchdogTimer;	// ???
	IOOutputQueue *				fTransmitQueue;	// ???
	UInt16 *					memBase;
	UInt32						event;
	//u8 eeprom[0x100];
	
	
	IOMemoryMap	*				map;			// io memory map
	UInt8						irqNumber;		// irq number
	UInt16						vendorID;		// vendor ID shld be 8086 (intel)
	UInt16						deviceID;		// device ID
	UInt16						pciReg;			// revision
	IOPhysicalAddress			ioBase;			// map->getPhysicalAddress();
//	IOMemoryDescriptor *		memDes;			// map->getMemoryDescriptor();
//	IODeviceMemory *			mem;			// fPCIDevice->getDeviceMemoryWithIndex(index);
	OSDictionary *				mediumDict;
	IONetworkMedium	*			mediumTable[MEDIUM_TYPE_INVALID];
	//IO80211Interface2			ieee80211;
	iwi_cmd_ring				cmdq;
//	iwi_rx_ring					rxq;
//	iwi_tx_ring					txq;
	

	//struct fw_image_desc sram_desc;
	//struct alive_command_responce dino_alive;
	u8 nic_type;
	u32 led_activity_on;
	u32 led_activity_off;
	u32 led_association_on;
	u32 led_association_off;
	u32 led_ofdm_on;
	u32 led_ofdm_off;
	u32 status;
	u32 config;
	u32 iw_mode;
	u32 assoc_networkmode;
	//struct ipw_sys_config sys_config;
//	int pl;
	
	
	 int cmdlog;
	 int debug;
	 int channel;
	 int mode;
	int disable2;
	 u32 ipw_debug_level;
	 int associate;
	 int auto_create;
	 int led;
	 int bt_coexist;
	 int hwcrypto;
	 int roaming;
	int antenna;
	//struct ipw_supported_rates rates;
	u32 power;
	//lck_mtx_t *mutex;
	IOSimpleLock *spin;
	u32 freq_band;
	u32 band;
	u32 modulation;
	u8 channel2;
	u16 rates_mask;
	u8 essid[IW_ESSID_MAX_SIZE];
	u8 essid_len;
	u8 speed_scan[MAX_SPEED_SCAN];
	u8 speed_scan_pos;
	//struct ipw_rx_queue *rxq;
	//struct clx2_tx_queue txq_cmd;
	//struct clx2_tx_queue txq[4];
	u16 rts_threshold;
	struct list_head network_list;
	struct list_head network_free_list;
	thread_call_t tlink[20];
//	ipw_priv *priv;
//	struct ieee80211_hw ieee2;
//	ipw_priv priv2;
//	net_device net_dev2;
	int qos_enable;
	int qos_burst_enable;
	int qos_no_ack_mask;
	int burst_duration_CCK;
	int burst_duration_OFDM;
	ifnet_t fifnet;
    
    
    
	IOLock *mutex;
	
    
    
    // Everything from here on down constitutes things I've added
    struct iwl3945_eeprom eeprom;
    u8 mac_addr[ETH_ALEN];
    
    struct iwl3945_power_mgr power_data;

    
    // Locks and lock groups, and their attributes
    lck_grp_attr_t *slock_grp_attr;
    lck_grp_t *slock_grp;
    lck_attr_t *slock_attr;
    lck_spin_t *slock;
    lck_spin_t *slock_sta;
    lck_spin_t *slock_hcmd;
    
    
    // Station table variables
    int num_stations;
    struct iwl3945_station_entry stations[IWL_STATION_COUNT];

    
    u8 phymode;
    
    
    /* We declare this const so it can only be
     * changed via explicit cast within the
     * routines that actually update the physical
     * hardware */
    struct iwl3945_rxon_cmd active_rxon;
    struct iwl3945_rxon_cmd staging_rxon;
    
    
    struct iwl3945_rx_queue rxq;
    struct iwl3945_tx_queue txq[IWL_MAX_NUM_QUEUES];

    void (*rx_handlers[REPLY_MAX])(struct iwl3945_rx_mem_buffer *rxb);
    struct iwl3945_rxon_cmd recovery_rxon;
    int error_recovering;
    
    u8 channel_count;	/* # of channels */
    struct iwl3945_channel_info *channel_info;	/* channel info array */

    
    //IONetworkInterface *createInterface();
    
    
    // Overrides from IONetworkController
    /*
    virtual bool publishProperties(void);
    IOReturn myPrepare(void);
    bool _propertiesPublished;
    virtual IOReturn myHandleCommand(void * target,
                  void * param0,
                  void * param1,
                  void * param2,
                  void * param3);
    bool attachInterface(IONetworkInterface ** interfaceP,
                    bool  doRegister);
     */


    static IOReturn powerChangeHandler(void *target, void *refCon, UInt32
            messageType, IOService *service, void *messageArgument,
            vm_size_t argSize );
    static IOReturn powerDownHandler(void *target, void *refCon, UInt32
            messageType, IOService *service, void *messageArgument,
            vm_size_t argSize );
    IOOutputQueue *getOutputQueue() const;
    
    
    
    /* uCode images, save to reload in case of failure */
    struct fw_desc ucode_code;  /* runtime inst */
    struct fw_desc ucode_data;  /* runtime data original */
    struct fw_desc ucode_data_backup;   /* runtime data save/restore */
    struct fw_desc ucode_init;  /* initialization inst */
    struct fw_desc ucode_init_data; /* initialization data */
    struct fw_desc ucode_boot;  /* bootstrap inst */
    
    struct iwl3945_driver_hw_info hw_setting;

    int alloc_rxb_skb;
    unsigned long next_scan_jiffies, last_scan_jiffies;
    int one_direct_scan;
    u8 direct_ssid_len;
    u8 direct_ssid[IW_ESSID_MAX_SIZE];
    int scan_bands;
    unsigned long scan_start;
    unsigned long scan_pass_start;
    u16 beacon_int;
    u16 active_rate;
    u16 active_rate_basic;
    const struct ieee80211_hw_mode *modes;
    u8 only_active_channel;
};

// Constants for handleCommand().
//
enum {
    kCommandEnable       = 1,
    kCommandDisable      = 2,
    kCommandPrepare      = 3,
    kCommandInitDebugger = 4
};


static char *get_cmd_string(u8 cmd);

#endif

