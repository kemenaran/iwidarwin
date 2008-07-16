
#ifndef __iwi2100_h__
#define __iwi2100_h__

#include "defines.h"




#define CONFIG_IPW2100_DEBUG
//#define CONFIG_IPW2200_QOS
#define TX_QUEUE_CHECK
//#define IW_RX_REPLACING
//#define IWI_NOLOG
//#define IWI_DEBUG_NORMAL
//#define IWI_DEBUG_FULL_MODE
#define IWI_WARNERR

#if defined(IWI_NOLOG)
	#define IWI_LOG(...)
#else
	#define IWI_LOG(...) printf("iwi2100: " __VA_ARGS__)
#endif

#define IOLog(...) IWI_LOG(__VA_ARGS__)

#if defined(IWI_DEBUG_FULL_MODE) || defined(IWI_DEBUG_NORMAL)
	#define IWI_DEBUG(fmt,...)IWI_LOG(" %s() " fmt, __FUNCTION__, ##__VA_ARGS__)
//	#define IWI_DEBUG(fmt,...)  \
//		do { IWI_LOG(" %s() " fmt, __FUNCTION__, ##__VA_ARGS__); \
//		      if(priv->status){ IWI_LOG("priv->status 0x010x\n",priv->status); } \
//		}while(0)
#else
//	#define IWI_DEBUG(...) IWI_LOG(__VA_ARGS__)
	#define IWI_DEBUG(...)
#endif

#if defined(IWI_DEBUG_FULL_MODE)
	#define IWI_DEBUG_FULL(...) IWI_DEBUG(__VA_ARGS__)
#else
          #define IWI_DEBUG_FULL(...)
#endif


#define IEEE80211_DEBUG_MGMT(...) IWI_DEBUG_FULL("(80211_MGMT) "  __VA_ARGS__)
#define IEEE80211_DEBUG_SCAN(...) IWI_DEBUG_FULL("(80211_SCAN) "  __VA_ARGS__)


#if defined(IWI_DEBUG_NORMAL) || defined(IWI_WARNERR) || defined(IWI_DEBUG_FULL_MODE)
	#define IWI_WARN(...) IWI_LOG(" W " __VA_ARGS__)
	#define IWI_ERR(...) IWI_LOG(" E " __VA_ARGS__)
#else
	#define IWI_WARN(...)
	#define IWI_ERR(...)
#endif


#define IWI_DEBUG_FN(...) IWI_DEBUG(__VA_ARGS__)

// #define IWI_DEBUG_FN(fmt,...) IWI_DEBUG(" %s " fmt, __FUNCTION__, ##__VA_ARGS__)


//#define IWI_DEBUG_STATUS(priv)  IWI_DEBUG("priv->status 0x%08x\n",priv->status)
#define IWI_DEBUG_STATUS(priv) do{ }while(0)

#ifdef IWI_DEBUG_FULL_MODE
	#define IWI_DEBUG_DUMP(...) printk_buf(__VA_ARGS__)
#else
	#define IWI_DEBUG_DUMP(...) do{ }while(0)
#endif

#define IWI_DUMP_MBUF(f, skb, len) \
    IWI_DEBUG_FULL(" %d(%s) DumpMbuf m_data 0x%08x datastart 0x%08x pktlen %d m_len  %d args len %d\n", \
        f , __FUNCTION__, mbuf_data(skb) ,mbuf_datastart(skb)  ,mbuf_len(skb) , mbuf_pkthdr_len(skb) , len  )


inline unsigned int
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

inline unsigned int jiffies_to_msecs(const unsigned long j)
{
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
	return (MSEC_PER_SEC / HZ) * j;
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
	return (j + (HZ / MSEC_PER_SEC) - 1)/(HZ / MSEC_PER_SEC);
#else
	return (j * MSEC_PER_SEC) / HZ;
#endif
}

#define time_after(a,b)	((long)(b) - (long)(a) < 0)

inline void skb_reserve(mbuf_t skb, int len)
{
	//skb->data += len;
	//skb->tail += len;
	/*        if (mbuf_len(skb)==0)
{
		void *data=(UInt8*)mbuf_data(skb)+len;
		mbuf_setdata(skb,data,mbuf_len(skb)+len);
} */
	IWI_DUMP_MBUF(1,skb,len); 
	void *data = (UInt8*)mbuf_data(skb) + len;
	IWI_DUMP_MBUF(2,skb,len);
	mbuf_setdata(skb,data, mbuf_len(skb));// m_len is not changed.
}

inline void *skb_put(mbuf_t skb, unsigned int len)
{
	/*unsigned char *tmp = skb->tail;
	SKB_LINEAR_ASSERT(skb);
	skb->tail += len;
	skb->len  += len;
	return tmp;*/
	void *data = (UInt8*)mbuf_data(skb) + mbuf_len(skb);
	
	IWI_DUMP_MBUF(1,skb,len);  
	
	if(mbuf_trailingspace(skb) > len ){
	//mbuf_prepend(&skb,len,MBUF_DONTWAIT); /* no prepend work */
		mbuf_setlen(skb,mbuf_len(skb)+len);
		if(mbuf_flags(skb) & MBUF_PKTHDR)
			mbuf_pkthdr_setlen(skb,mbuf_pkthdr_len(skb)+len); 
	}
	else
	{
		IWI_ERR("skb_put failed\n");
		data = (UInt8*)mbuf_data(skb);
	}
	IWI_DUMP_MBUF(2,skb,len);  
	return data;
}

inline void *skb_push(mbuf_t skb, unsigned int len)
{
	/*skb->data -= len;
	skb->len  += len;
	if (unlikely(skb->data<skb->head))
	skb_under_panic(skb, len, current_text_addr());
	return skb->data;*/
	/* void *data=(UInt8*)mbuf_data(skb)-len;
	mbuf_setdata(skb,data,mbuf_len(skb)+len); */
	IWI_DUMP_MBUF(1,skb,len); 
	mbuf_prepend(&skb,len,MBUF_DONTWAIT);
	IWI_DUMP_MBUF(2,skb,len);
	return  (UInt8 *)mbuf_data(skb);
}

inline void *skb_pull(mbuf_t skb, unsigned int len)
{
	/*skb->len -= len;
	BUG_ON(skb->len < skb->data_len);
	return skb->data += len;*/
	IWI_DUMP_MBUF(1,skb,len);  
	mbuf_adj(skb,len);
	void *data=(UInt8*)mbuf_data(skb);
	IWI_DUMP_MBUF(2,skb,len);		
	return data;
}

#define kTransmitQueueCapacity 1000

struct symbol_alive_response {
	u8 cmd_id;
	u8 seq_num;
	u8 ucode_rev;
	u8 eeprom_valid;
	u16 valid_flags;
	u8 IEEE_addr[6];
	u16 flags;
	u16 pcb_rev;
	u16 clock_settle_time;	// 1us LSB
	u16 powerup_settle_time;	// 1us LSB
	u16 hop_settle_time;	// 1us LSB
	u8 date[3];		// month, day, year
	u8 time[2];		// hours, minutes
	u8 ucode_valid;
};


static const char ipw2100_modes[] = {
	'a', 'b', 'g', '?'
};

struct ipw2100_ucode {
	u32 ver;
	u32 inst_size;
	u32 data_size;
	u32 boot_size;
	u8 data[0];
};

			  
struct ipw2100_status_code {
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

 static unsigned char rfc1042_header[] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };

/* Bridge-Tunnel header (for EtherTypes ETH_P_AARP and ETH_P_IPX) */
static unsigned char bridge_tunnel_header[] =   { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8 };

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

inline int is_multicast_ether_addr(const u8 *addr)
{
       return addr[0] & 0x01;
}

inline int is_broadcast_ether_addr(const u8 *addr)
{
        return (addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff;
}

typedef __u16 __be16;
struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	__be16		h_proto;		/* packet type ID field	*/
} __attribute__((packed));

struct fw_header {
	u32 version;
	u32 mode;
};

struct fw_chunk {
	u32 address;
	u32 length;
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

struct iwi_rx_ring {
//	bus_dma_tag_t		data_dmat;
	struct iwi_rx_data	*data;
	int			count;
	int			cur;
};

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


class darwin_iwi2100 : public IOEthernetController//IO80211Controller
{
	OSDeclareDefaultStructors(darwin_iwi2100)

public:
 virtual IOReturn registerWithPolicyMaker(IOService * policyMaker);
    virtual IOReturn setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker);
    virtual void setPowerStateOff(void);
    virtual void setPowerStateOn(void);
//virtual const char * getNamePrefix() const;
	virtual bool		init(OSDictionary *dictionary = 0);
	virtual void		free(void);
//	virtual IOService *	probe(IOService *provider, SInt32 *score);
	virtual bool		start(IOService *provider);
    virtual void		stop(IOService *provider);
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
	static void			interruptOccurred(OSObject * owner, void * src, IOService *nub, int count);
	virtual UInt32		handleInterrupt(void);
	virtual IOBufferMemoryDescriptor * MemoryDmaAlloc(UInt32 buf_size, dma_addr_t *phys_add, void *virt_add);
//	virtual bool configureInterface( IONetworkInterface * interface );
	virtual bool		createWorkLoop( void );
	virtual IOWorkLoop * getWorkLoop( void ) const;
	virtual IOOutputQueue * createOutputQueue( void );
	virtual const OSString * newModelString( void ) const;
	virtual const OSString * newVendorString( void ) const;
	virtual bool		addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name = 0);
	virtual IOReturn	selectMedium(const IONetworkMedium * medium);

			
	virtual int			sendCommand(UInt8 type,void *data,UInt8 len,bool async);
	virtual int			ipw2100_scan(struct ipw2100_priv *priv, int type);
	virtual int			initCmdQueue();
	virtual int			resetCmdQueue();
	virtual int			initRxQueue();
	virtual int			resetRxQueue();
	virtual int			initTxQueue();
	virtual int			resetTxQueue();
	virtual void		RxQueueIntr();
	virtual int			configu(struct ipw2100_priv *priv);
	
	//virtual IOReturn setPowerState ( unsigned long powerStateOrdinal, IOService* whatDevice );
virtual IOOptionBits getState( void ) const;

	virtual void notifIntr(struct ipw2100_priv *priv,
				struct ipw2100_rx_notification *notif);
	
	/* Memory operation functions */
	virtual void inline ipw2100_write32(UInt32 offset, UInt32 data);
	virtual UInt32 inline ipw2100_read32(UInt32 offset);
	virtual void inline ipw2100_set_bit(UInt32 reg, UInt32 mask);
	virtual void inline ipw2100_clear_bit(UInt32 reg, UInt32 mask);
	virtual int ipw2100_poll_bit(UInt32 reg, UInt32 mask, int timeout);
	
	/* EEPROM functions */
	virtual void cacheEEPROM(struct ipw2100_priv *priv);
	virtual void inline eeprom_write_reg(UInt32 data);
	virtual void inline eeprom_cs(bool sel);
	virtual void inline eeprom_write_bit(UInt8 bit);
	virtual void eeprom_op(UInt8 op, UInt8 addr);
	virtual UInt16 eeprom_read_UInt16(UInt8 addr);
	virtual UInt32 read_reg_UInt32(UInt32 reg);
	
	virtual void ipw2100_zero_memory(UInt32 start, UInt32 count);
	virtual inline void ipw2100_fw_dma_reset_command_blocks();
	virtual void ipw2100_write_reg32( UInt32 reg, UInt32 value);
	virtual int ipw2100_fw_dma_enable();
	virtual int ipw2100_fw_dma_add_buffer(UInt32 src_phys, UInt32 dest_address, UInt32 length);
	virtual int ipw2100_fw_dma_write_command_block(int index,
					  struct command_block *cb);
	virtual int ipw2100_fw_dma_kick();
	virtual int ipw2100_fw_dma_add_command_block(
					UInt32 src_address,
					UInt32 dest_address,
					UInt32 length,
					int interrupt_enabled, int is_last);
	virtual void ipw2100_write_indirect(UInt32 addr, UInt8 * buf,
				int num);
	virtual int ipw2100_fw_dma_wait();			
	virtual int ipw2100_fw_dma_command_block_index();
	virtual void ipw2100_fw_dma_dump_command_block();
	virtual void ipw2100_fw_dma_abort();
	virtual UInt32 ipw2100_read_reg32( UInt32 reg);
	virtual void ipw2100_write_reg8(UInt32 reg, UInt8 value);		
	virtual UInt8 ipw2100_read_reg8(UInt32 reg);
	virtual void ipw2100_write_reg16(UInt32 reg, UInt16 value);
	virtual int ipw2100_stop_nic();
	virtual int ipw2100_reset_nic(struct ipw2100_priv *priv);
	virtual int ipw2100_init_nic();									
	virtual void ipw2100_start_nic();
	virtual inline void ipw2100_enable_interrupts(struct ipw2100_priv *priv);
	virtual int ipw2100_set_geo(struct ieee80211_device *ieee,
		       const struct ieee80211_geo *geo);
	virtual int rf_kill_active(struct ipw2100_priv *priv);
	virtual void ipw2100_down(struct ipw2100_priv *priv);
	virtual int ipw2100_up(struct ipw2100_priv *priv, int deferred);
//	virtual inline int ipw2100_is_init(struct ipw2100_priv *priv);
//	virtual void ipw2100_deinit(struct ipw2100_priv *priv);
	virtual void ipw2100_led_shutdown(struct ipw2100_priv *priv);
	virtual u32 ipw2100_register_toggle(u32 reg);
	virtual void ipw2100_led_activity_off(struct ipw2100_priv *priv);
	virtual void ipw2100_led_link_off(struct ipw2100_priv *priv);
	virtual void ipw2100_led_band_off(struct ipw2100_priv *priv);
	virtual inline void ipw2100_disable_interrupts(struct ipw2100_priv *priv);
	virtual void ipw2100_led_radio_off(struct ipw2100_priv *priv);
	virtual void ipw2100_led_init(struct ipw2100_priv *priv);
	virtual void ipw2100_led_link_on(struct ipw2100_priv *priv);
	virtual void ipw2100_led_band_on(struct ipw2100_priv *priv);
	virtual int ipw2100_sw_reset(int option);
	virtual int ipw2100_get_fw(const struct firmware **fw, const char *name);
	virtual void ipw2100_led_link_down(struct ipw2100_priv *priv);
	virtual void ipw2100_rf_kill(ipw2100_priv *priv);
	virtual int ipw2100_best_network(struct ipw2100_priv *priv,
			    struct ipw_network_match *match,
			    struct ieee80211_network *network, int roaming);
	virtual int ipw2100_compatible_rates(struct ipw2100_priv *priv,
				const struct ieee80211_network *network,
				struct ipw_supported_rates *rates);
	virtual void ipw2100_copy_rates(struct ipw_supported_rates *dest,
			   const struct ipw_supported_rates *src);
	virtual int ipw2100_is_rate_in_mask(struct ipw2100_priv *priv, int ieee_mode, u8 rate);
	virtual void ipw2100_adhoc_create(struct ipw2100_priv *priv,
			     struct ieee80211_network *network);		   
	virtual int ipw2100_is_valid_channel(struct ieee80211_device *ieee, u8 channel);
	virtual int ipw2100_channel_to_index(struct ieee80211_device *ieee, u8 channel);
	virtual void ipw2100_create_bssid(struct ipw2100_priv *priv, u8 * bssid);
	virtual void ipw2100_set_fixed_rate(struct ipw2100_priv *priv, int mode);

	virtual int ipw2100_grab_restricted_access(struct ipw2100_priv *priv);
	virtual void _ipw_write_restricted(struct ipw2100_priv *priv,
					 u32 reg, u32 value);
	virtual void _ipw_write_restricted_reg(struct ipw2100_priv *priv,
					     u32 addr, u32 val);
	virtual void _ipw_release_restricted_access(struct ipw2100_priv
						  *priv);
	virtual int ipw2100_download_ucode_base(struct ipw2100_priv *priv, u8 * image, u32 len);
	virtual void ipw2100_write_restricted_reg_buffer(struct ipw2100_priv
						   *priv, u32 reg,
						   u32 len, u8 * values);
	virtual u32 _ipw_read_restricted_reg(struct ipw2100_priv *priv, u32 reg);
	virtual int ipw2100_download_ucode(struct ipw2100_priv *priv,
			      struct fw_image_desc *desc,
			      u32 mem_size, dma_addr_t dst_addr);
	virtual int attach_buffer_to_tfd_frame(struct tfd_frame *tfd,
				      dma_addr_t addr, u16 len);
	virtual void ipw2100_write_buffer_restricted(struct ipw2100_priv *priv,
					u32 reg, u32 len, u32 * values);
	virtual int ipw2100_poll_restricted_bit(struct ipw2100_priv *priv,
					  u32 addr, u32 mask, int timeout);
	virtual int ipw2100_nic_init(struct ipw2100_priv *priv);
	virtual int ipw2100_power_init_handle(struct ipw2100_priv *priv);				
	virtual void __ipw_set_bits_restricted_reg(u32 line, struct ipw2100_priv
						 *priv, u32 reg, u32 mask);				
	virtual int ipw2100_eeprom_init_sram(struct ipw2100_priv *priv);
	virtual int ipw2100_rate_scale_init_handle(struct ipw2100_priv *priv, s32 window_size);
	virtual int ipw2100_rate_scale_clear_window(struct ipw2100_rate_scale_data
				       *window);
	virtual int ipw2100_nic_set_pwr_src(struct ipw2100_priv *priv, int pwr_max);
	virtual void __ipw_set_bits_mask_restricted_reg(u32 line, struct ipw2100_priv
						      *priv, u32 reg,
						      u32 bits, u32 mask);
	virtual int ipw2100_rf_eeprom_ready(struct ipw2100_priv *priv);
	virtual int ipw2100_verify_ucode(struct ipw2100_priv *priv);
	virtual int darwin_iwi2100::ipw2100_enable_adapter(struct ipw2100_priv *priv);
	virtual void darwin_iwi2100::read_nic_memory(struct net_device *dev, u32 addr, u32 len, u8 * buf);
	virtual void darwin_iwi2100::read_register_byte(struct net_device *dev, u32 reg, u8 * val);
	virtual void darwin_iwi2100::read_nic_dword(struct net_device *dev, u32 addr, u32 * val);
	virtual void darwin_iwi2100::write_register(struct net_device *dev, u32 reg, u32 val);
	virtual void darwin_iwi2100::read_register(struct net_device *dev, u32 reg, u32 * val);
	virtual void darwin_iwi2100::write_nic_dword(struct net_device *dev, u32 addr, u32 val);
	virtual void darwin_iwi2100::write_register_word(struct net_device *dev, u32 reg, u16 val);
	virtual void darwin_iwi2100::write_nic_word(struct net_device *dev, u32 addr, u16 val);
	virtual void darwin_iwi2100::write_nic_byte(struct net_device *dev, u32 addr, u8 val);
	virtual void darwin_iwi2100::write_register_byte(struct net_device *dev, u32 reg, u8 val);
	virtual void darwin_iwi2100::read_nic_byte(struct net_device *dev, u32 addr, u8 * val);
	virtual void darwin_iwi2100::read_nic_word(struct net_device *dev, u32 addr, u16 * val);
	virtual void darwin_iwi2100::read_register_word(struct net_device *dev, u32 reg,
				      u16 * val);
	virtual void darwin_iwi2100::write_nic_memory(struct net_device *dev, u32 addr, u32 len,
			     const u8 * buf);

	virtual  void isr_indicate_associated(struct ipw2100_priv *priv, u32 status);
	virtual void ipw2100_reset_adapter(struct ipw2100_priv *priv);
	virtual int ipw2100_disable_adapter(struct ipw2100_priv *priv);
	virtual int ipw2100_read_mac_address(struct ipw2100_priv *priv);
	virtual int ipw2100_set_mac_address(struct ipw2100_priv *priv, int batch_mode);
	virtual int ipw2100_set_port_type(struct ipw2100_priv *priv, u32 port_type,
				 int batch_mode);
	virtual int ipw2100_set_channel(struct ipw2100_priv *priv, u32 channel,
			       int batch_mode);
	virtual int ipw2100_system_config(struct ipw2100_priv *priv, int batch_mode);
	virtual int ipw2100_set_tx_rates(struct ipw2100_priv *priv, u32 rate,
				int batch_mode);
	virtual int ipw2100_set_rts_threshold(struct ipw2100_priv *priv, u32 threshold);
	virtual int ipw2100_set_power_mode(struct ipw2100_priv *priv, int power_level);			
	virtual int ipw2100_set_mandatory_bssid(struct ipw2100_priv *priv, u8 * bssid,
				       int batch_mode);						
	virtual int ipw2100_set_essid(struct ipw2100_priv *priv, char *essid,
			     int length, int batch_mode);									
	virtual int ipw2100_set_ibss_beacon_interval(struct ipw2100_priv *priv,
					    u32 interval, int batch_mode);												
	virtual int ipw2100_set_tx_power(struct ipw2100_priv *priv, u32 tx_power);																		
	virtual void isr_rx(struct ipw2100_priv *priv, int i,
			  struct ieee80211_rx_stats *stats);
	virtual int ieee80211_rx(struct ieee80211_device *ieee, mbuf_t skb,
		 struct ieee80211_rx_stats *rx_stats);		  
	virtual UInt32 outputPacket(mbuf_t m, void * param);		  
	virtual int ieee80211_xmit(mbuf_t skb, struct net_device *dev);		  
	virtual struct ieee80211_txb *ieee80211_alloc_txb(int nr_frags, int txb_size,
						 int headroom, int gfp_mask);		  
	virtual int ieee80211_copy_snap(u8 * data, u16 h_proto);
	virtual int ipw_net_hard_start_xmit(struct ieee80211_txb *txb,
				   struct net_device *dev, int pri);		  
	virtual int ipw_tx_skb(struct ipw2100_priv *priv, struct ieee80211_txb *txb, int pri);				  
	virtual void ipw2100_wx_event_work(struct ipw2100_priv *priv);						  
				 
												  								  
			//kext control functions:
	
	friend  int 		sendNetworkList(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,int opt, void *data, size_t *len); //send network list to network selector app.
	friend  int 		setSelectedNetwork(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,mbuf_t m, int flags); //get slected network from network selector app.
	friend  int			ConnectClient(kern_ctl_ref kctlref,struct sockaddr_ctl *sac,void **unitinfo); //connect to network selector app.
	friend  int 		disconnectClient(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo); //disconnect network selector app.
	friend	int			configureConnection(kern_ctl_ref ctlref, u_int unit, void *userdata, int opt, void *data, size_t len);
										  
													  		  
	
/*	
	
	
	virtual SInt32	getSSID(IO80211Interface *interface,
							struct apple80211_ssid_data *sd);
	
	virtual SInt32 getCHANNEL(IO80211Interface *interface,
							  struct apple80211_channel_data *cd);
	
	virtual SInt32 getBSSID(IO80211Interface *interface,
							struct apple80211_bssid_data *bd);
	
	virtual SInt32 getCARD_CAPABILITIES(IO80211Interface *interface,
										struct apple80211_capability_data *cd);
	
	virtual SInt32 getSTATE(IO80211Interface *interface,
							struct apple80211_state_data *sd);
	
	virtual SInt32 getRSSI(IO80211Interface *interface,
						   struct apple80211_rssi_data *rd);
	
	virtual SInt32 getPOWER(IO80211Interface *interface,
							struct apple80211_power_data *pd);
	
	virtual SInt32 getSCAN_RESULT(IO80211Interface *interface,
								  struct apple80211_scan_result **scan_result);
	
	//virtual SInt32 getASSOCIATE_RESULT(IO80211Interface *interface,									   struct apple80211_assoc_result_data *ard);
	
	virtual SInt32 getRATE(IO80211Interface *interface,
						   struct apple80211_rate_data *rd);
	
	virtual SInt32 getSTATUS_DEV(IO80211Interface *interface,
								 struct apple80211_status_dev_data *dd);
	
	virtual SInt32 getRATE_SET(IO80211Interface	*interface,
							   struct apple80211_rate_set_data *rd);
							   
	virtual SInt32	getASSOCIATION_STATUS( IO80211Interface * interface, struct apple80211_assoc_status_data * asd );

	virtual SInt32 setSCAN_REQ(IO80211Interface *interface,
							   struct apple80211_scan_data *sd);
	
	virtual SInt32 setASSOCIATE(IO80211Interface *interface,
								struct apple80211_assoc_data *ad);
	
	virtual SInt32 setPOWER(IO80211Interface *interface,
							struct apple80211_power_data *pd);
	
	virtual SInt32 setCIPHER_KEY(IO80211Interface *interface,
								 struct apple80211_key *key);
	
	virtual SInt32 setAUTH_TYPE(IO80211Interface *interface,
								struct apple80211_authtype_data *ad);
	
	virtual SInt32 setDISASSOCIATE(IO80211Interface	*interface);
	
	virtual SInt32 setSSID(IO80211Interface *interface,
						   struct apple80211_ssid_data *sd);
	
	virtual SInt32 setAP_MODE(IO80211Interface *interface,
							  struct apple80211_apmode_data *ad);

	virtual bool attachInterfaceWithMacAddress( void * macAddr, 
												UInt32 macLen, 
												IONetworkInterface ** interface, 
												bool doRegister ,
												UInt32 timeout  );

virtual void	dataLinkLayerAttachComplete( IO80211Interface * interface );*/

    virtual int ipw2100_load(struct ipw2100_priv *priv);
	virtual void ipw2100_add_scan_channels(struct ipw2100_priv *priv,
				  struct ipw2100_scan_request_ext *scan,
				  int scan_type);
	virtual int ipw2100_associate(ipw2100_priv *data);
	virtual void ipw2100_adapter_restart(ipw2100_priv *adapter);
	virtual void ipw2100_arc_release();
	virtual int ipw2100_stop_master();
	virtual void queue_te(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, bool start);
	virtual void queue_td(int num , thread_call_func_t func);
	virtual void ipw2100_scan_check(ipw2100_priv *priv);
	virtual IOReturn message( UInt32 type, IOService * provider,
                              void * argument);
	virtual int ipw2100_associate_network(struct ipw2100_priv *priv,
				 struct ieee80211_network *network,
				 struct ipw_supported_rates *rates, int roaming);
	virtual void ipw2100_remove_current_network(struct ipw2100_priv *priv);
	virtual void ipw2100_abort_scan(struct ipw2100_priv *priv);
	virtual int ipw2100_disassociate(struct ipw2100_priv *data);
	virtual int ipw2100_set_tx_power(struct ipw2100_priv *priv);
	virtual void init_sys_config(struct ipw2100_sys_config *sys_config);
	virtual int init_supported_rates(struct ipw2100_priv *priv,
				struct ipw_supported_rates *rates);
	virtual void ipw2100_set_hwcrypto_keys(struct ipw2100_priv *priv);
	virtual void ipw2100_add_cck_scan_rates(struct ipw_supported_rates *rates,
				   u8 modulation, u32 rate_mask);
	virtual void ipw2100_add_ofdm_scan_rates(struct ipw_supported_rates *rates,
				    u8 modulation, u32 rate_mask);
	virtual void ipw2100_send_tgi_tx_key(struct ipw2100_priv *priv, int type, int index);
	virtual void ipw2100_send_wep_keys(struct ipw2100_priv *priv, int type);
	virtual void ipw2100_set_hw_decrypt_unicast(struct ipw2100_priv *priv, int level);
	virtual void ipw2100_set_hw_decrypt_multicast(struct ipw2100_priv *priv, int level);
	virtual const struct ieee80211_geo* ipw2100_get_geo(struct ieee80211_device *ieee);
	virtual void ipw2100_send_disassociate(struct ipw2100_priv *priv, int quiet);
	virtual int ipw2100_send_associate(struct ipw2100_priv *priv,
			      struct ipw2100_associate *associate);
	virtual void ipw2100_link_up(struct ipw2100_priv *priv);
	virtual void ipw2100_link_down(struct ipw2100_priv *priv);
	virtual const char* ipw2100_get_status_code(u16 status);
	virtual bool configureInterface(IONetworkInterface * netif);
	virtual int ipw2100_qos_activate(struct ipw2100_priv *priv,
			    struct ieee80211_qos_data *qos_network_data);
	virtual u8 ipw2100_qos_current_mode(struct ipw2100_priv *priv);
	virtual u32 ipw2100_qos_get_burst_duration(struct ipw2100_priv *priv);
	virtual void ipw2100_init_ordinals(struct ipw2100_priv *priv);
	virtual void ipw2100_reset_stats(struct ipw2100_priv *priv);
	virtual void ipw2100_read_indirect(struct ipw2100_priv *priv, u32 addr, u8 * buf,
			       int num);
	virtual u32 ipw2100_get_current_rate(struct ipw2100_priv *priv);
	virtual u32 ipw2100_get_max_rate(struct ipw2100_priv *priv);
	virtual void ipw2100_gather_stats(struct ipw2100_priv *priv);
	virtual void average_add(struct average *avg, s16 val);
	virtual int ipw2100_load_ucode(struct ipw2100_priv *priv);
	virtual void ipw2100_clear_stations_table(struct ipw2100_priv *priv);
	virtual void ipw2100_nic_start(struct ipw2100_priv *priv);
	virtual int ipw2100_card_show_info(struct ipw2100_priv *priv);
	virtual int ipw2100_query_eeprom(struct ipw2100_priv *priv, u32 offset,
			    u32 len, u8 * buf);
	virtual int ipw2100_copy_ucode_images(struct ipw2100_priv *priv,
				 u8 * image_code,
				 size_t image_len_code,
				 u8 * image_data, size_t image_len_data);
	virtual void ipw2100_initialize_ordinals(struct ipw2100_priv *priv);
	virtual int ipw2100_wait_for_card_state(struct ipw2100_priv *priv, int state);
	virtual int ipw2100_get_ordinal(struct ipw2100_priv *priv, u32 ord,
			       void *val, u32 * len);
	virtual void ipw2100_reset_fatalerror(struct ipw2100_priv *priv);
	virtual int ipw2100_power_cycle_adapter(struct ipw2100_priv *priv);
	virtual void ipw2100_hw_set_gpio(struct ipw2100_priv *priv);
	virtual int ipw2100_start_adapter(struct ipw2100_priv *priv);
	virtual int ipw2100_download_firmware(struct ipw2100_priv *priv);
	virtual int sw_reset_and_clock(struct ipw2100_priv *priv);
	virtual int ipw2100_verify(struct ipw2100_priv *priv);
	virtual int ipw2100_ucode_download(struct ipw2100_priv *priv,
				  struct ipw2100_fw *fw);
	virtual int ipw2100_fw_download(struct ipw2100_priv *priv, struct ipw2100_fw *fw);
	virtual int ipw2100_get_hw_features(struct ipw2100_priv *priv);
	virtual int ipw2100_set_ordinal(struct ipw2100_priv *priv, u32 ord, u32 * val,
			       u32 * len);			   
	virtual int ipw2100_hw_send_command(struct ipw2100_priv *priv,
				   struct host_command *cmd);
	virtual void ipw2100_tx_send_data(struct ipw2100_priv *priv);
	virtual void ipw2100_tx_send_commands(struct ipw2100_priv *priv);
	virtual int ipw2100_queues_allocate(struct ipw2100_priv *priv);
	virtual int ipw2100_tx_allocate(struct ipw2100_priv *priv);
	virtual int bd_queue_allocate(struct ipw2100_priv *priv,
			     struct ipw2100_bd_queue *q, int entries);
	virtual void bd_queue_free(struct ipw2100_priv *priv, struct ipw2100_bd_queue *q);
	virtual int ipw2100_rx_allocate(struct ipw2100_priv *priv);
	virtual int status_queue_allocate(struct ipw2100_priv *priv, int entries);
	virtual void status_queue_free(struct ipw2100_priv *priv);
	virtual int ipw2100_alloc_skb(struct ipw2100_priv *priv,
				    struct ipw2100_rx_packet *packet);
	virtual int ipw2100_msg_allocate(struct ipw2100_priv *priv);
	virtual void ipw2100_tx_free(struct ipw2100_priv *priv);
	virtual void ieee80211_txb_free(struct ieee80211_txb *txb);
	virtual void ipw2100_rx_free(struct ipw2100_priv *priv);
	virtual void ipw2100_msg_free(struct ipw2100_priv *priv);
	virtual void ipw2100_queues_initialize(struct ipw2100_priv *priv);
	virtual void ipw2100_tx_initialize(struct ipw2100_priv *priv);
	virtual void bd_queue_initialize(struct ipw2100_priv *priv,
				struct ipw2100_bd_queue *q, u32 base, u32 size,
				u32 r, u32 w);
	virtual void ipw2100_rx_initialize(struct ipw2100_priv *priv);
	virtual int ipw2100_msg_initialize(struct ipw2100_priv *priv);
	virtual int ipw2100_set_scan_options(struct ipw2100_priv *priv);
	virtual int ipw2100_start_scan(struct ipw2100_priv *priv);
	virtual void freePacket2(mbuf_t m);
	virtual mbuf_t mergePacket(mbuf_t m);
	virtual void getPacketBufferConstraints(IOPacketBufferConstraints * constraints) const;
	virtual void schedule_reset(struct ipw2100_priv *priv);
	virtual int ipw_set_geo(struct ieee80211_device *ieee,
		       const struct ieee80211_geo *geo);
	virtual int ipw2100_adapter_setup(struct ipw2100_priv *priv);
	virtual void __ipw2100_rx_process(struct ipw2100_priv *priv);
	virtual int ipw2100_corruption_check(struct ipw2100_priv *priv, int i);
	virtual void isr_rx_complete_command(struct ipw2100_priv *priv,
				    struct ipw2100_cmd_header *cmd);
	virtual void isr_status_change(struct ipw2100_priv *priv, int status);				
	virtual void ieee80211_rx_mgt(struct ieee80211_device *ieee, 
        struct ieee80211_hdr_4addr *header,struct ieee80211_rx_stats *stats);
	virtual void ipw2100_hang_check(struct ipw2100_priv *priv);
	virtual int ipw2100_hw_stop_adapter(struct ipw2100_priv *priv);
	virtual int ipw2100_hw_phy_off(struct ipw2100_priv *priv);
	virtual void __ipw2100_tx_complete(struct ipw2100_priv *priv);
	virtual int __ipw2100_tx_process(struct ipw2100_priv *priv);
	virtual void isr_indicate_association_lost(struct ipw2100_priv *priv, u32 status);
	virtual void isr_scan_complete(struct ipw2100_priv *priv, u32 status);
	virtual void isr_indicate_rf_kill(struct ipw2100_priv *priv, u32 status);
	virtual void isr_indicate_scanning(struct ipw2100_priv *priv, u32 status);
	void check_firstup(struct ipw2100_priv *priv);
	virtual int ieee80211_handle_assoc_resp(struct ieee80211_device *ieee, struct ieee80211_assoc_response
				       *frame, struct ieee80211_rx_stats *stats);
	virtual int ieee80211_parse_info_param(struct ieee80211_info_element
				      *info_element, u16 length,
				      struct ieee80211_network *network);
	virtual void ieee80211_process_probe_response(struct ieee80211_device *ieee,
        struct ieee80211_probe_response *beacon,
        struct ieee80211_rx_stats *stats);
	virtual int ieee80211_network_init(struct ieee80211_device *ieee, struct ieee80211_probe_response
					 *beacon,
					 struct ieee80211_network *network,
					 struct ieee80211_rx_stats *stats);
	int is_beacon(__le16 fc)
		{
			return (WLAN_FC_GET_STYPE(le16_to_cpu(fc)) == IEEE80211_STYPE_BEACON);
		}
	 unsigned compare_ether_addr(const u8 *_a, const u8 *_b)
		{
			const u16 *a = (const u16 *) _a;
			const u16 *b = (const u16 *) _b;

			if(ETH_ALEN != 6) return -1;
			return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
		}	
	 int is_same_network(struct ieee80211_network *src,
				  struct ieee80211_network *dst)
		{
			return ((src->ssid_len == dst->ssid_len) &&
			(src->channel == dst->channel) &&
			!compare_ether_addr(src->bssid, dst->bssid) &&
			!memcmp(src->ssid, dst->ssid, src->ssid_len));
		}
	 
	virtual void update_network(struct ieee80211_network *dst,
				  struct ieee80211_network *src);
	 void ieee80211_network_reset(struct ieee80211_network *network)
		{
			if (!network)
			return;

			if (network->ibss_dfs) {
			IOFree(network->ibss_dfs,sizeof(*network->ibss_dfs));
			network->ibss_dfs = NULL;
			}
		}			  					
							
								
										
		
		
		
	
	
	


	
	// statistics
    IONetworkStats		*netStats;
    IOEthernetStats		*etherStats;
    
    // packet buffer variables
    IOOutputQueue                               *transmitQueue;
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


#define CB_NUMBER_OF_ELEMENTS_SMALL 64

	IOPCIDevice *				fPCIDevice;		// PCI nub
	IOEthernetAddress			fEnetAddr;		// holds the mac address currently hardcoded
	IOWorkLoop *				fWorkLoop;		// the workloop
    //IO80211Interface*			fNetif;			// ???
	IOEthernetInterface*			fNetif;
	IOInterruptEventSource *	fInterruptSrc;	// ???
//	IOTimerEventSource *		fWatchdogTimer;	// ???
	IOOutputQueue *				fTransmitQueue;	// ???
	
	UInt32						event;
	u8 eeprom[0x100];
	
	
	IOMemoryMap	*				map;			// io memory map
	UInt8						irqNumber;		// irq number
	UInt16						vendorID;		// vendor ID shld be 8086 (intel)
	UInt16						deviceID;		// device ID
	UInt16						pciReg;			// revision
	IOPhysicalAddress			ioBase;			// map->getPhysicalAddress();
	IOMemoryDescriptor *		memDes;			// map->getMemoryDescriptor();
	IODeviceMemory *			mem;			// fPCIDevice->getDeviceMemoryWithIndex(index);
	OSDictionary *				mediumDict;
	IONetworkMedium	*			mediumTable[MEDIUM_TYPE_INVALID];
	//IO80211Interface2			ieee80211;
	iwi_cmd_ring				cmdq;
	iwi_rx_ring					rxq;
	iwi_tx_ring					txq;
	

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
	//struct ipw2100_sys_config sys_config;
	int pl;
	
	
	 int cmdlog;
	 int debug;
	 int channel;
	 int mode;
	int disable2;
	 u32 ipw2100_debug_level;
	 int associate;
	 int auto_create;
	 int led;
	 int bt_coexist;
	 int hwcrypto;
	 int roaming;
	int antenna;
	//struct ipw_supported_rates rates;
	u32 power;
	lck_mtx_t *mutex;
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
	//struct ipw2100_rx_queue *rxq;
	//struct clx2_tx_queue txq_cmd;
	//struct clx2_tx_queue txq[4];
	u16 rts_threshold;
	struct list_head network_list;
	struct list_head network_free_list;
	thread_call_t tlink[20];
	ipw2100_priv *priv;
	ieee80211_device ieee2;
	ipw2100_priv priv2;
	net_device net_dev2;
	int qos_enable;
	int qos_burst_enable;
	int qos_no_ack_mask;
	int burst_duration_CCK;
	int burst_duration_OFDM;
	ifnet_t fifnet;
	IOService *             _pmPolicyMaker;
	UInt32                  _pmPowerState;
    thread_call_t           _powerOffThreadCall;
    thread_call_t           _powerOnThreadCall;
	UInt16 *					memBase;
	//open link to user interface application flag:
	int userInterfaceLink; //this flag will be used to abort all non-necessary background operation while
							//the user is connected to the driver.
	int firstifup;

};

#endif

