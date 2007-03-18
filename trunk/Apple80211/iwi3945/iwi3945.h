
#ifndef __iwi3945_h__
#define __iwi3945_h__

#include "defines.h"

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

#define IWI_DEBUG_FN(fmt,...) IWI_DEBUG(" %s " fmt, __FUNCTION__, ##__VA_ARGS__)


#define IWI_DUMP_MBUF(...) do{ }while(0)

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

struct ipw_network_match {
	struct ieee80211_network *network;
	struct ipw_supported_rates rates;
};

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


class darwin_iwi3945 : public IO80211Controller
{
	OSDeclareDefaultStructors(darwin_iwi3945)

public:
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
	
	/* Memory operation functions */
	virtual void inline ipw_write32(UInt32 offset, UInt32 data);
	virtual UInt32 inline ipw_read32(UInt32 offset);
	virtual void inline ipw_set_bit(UInt32 reg, UInt32 mask);
	virtual void inline ipw_clear_bit(UInt32 reg, UInt32 mask);
	virtual int ipw_poll_bit(struct ipw_priv *priv, u32 addr,
			u32 bits, u32 mask, int timeout);

	
	/* EEPROM functions */
	virtual void cacheEEPROM(struct ipw_priv *priv);
	virtual void inline eeprom_write_reg(UInt32 data);
	virtual void inline eeprom_cs(bool sel);
	virtual void inline eeprom_write_bit(UInt8 bit);
	virtual void eeprom_op(UInt8 op, UInt8 addr);
	virtual UInt16 eeprom_read_UInt16(UInt8 addr);
	virtual UInt32 read_reg_UInt32(UInt32 reg);
	
	virtual void ipw_zero_memory(UInt32 start, UInt32 count);
	virtual inline void ipw_fw_dma_reset_command_blocks();
	virtual void ipw_write_reg32( UInt32 reg, UInt32 value);
	virtual int ipw_fw_dma_enable();
	virtual int ipw_fw_dma_add_buffer(UInt32 src_phys, UInt32 dest_address, UInt32 length);
	virtual int ipw_fw_dma_write_command_block(int index,
					  struct command_block *cb);
	virtual int ipw_fw_dma_kick();
	virtual int ipw_fw_dma_add_command_block(
					UInt32 src_address,
					UInt32 dest_address,
					UInt32 length,
					int interrupt_enabled, int is_last);
	virtual void ipw_write_indirect(UInt32 addr, UInt8 * buf,
				int num);
	virtual int ipw_fw_dma_wait();			
	virtual int ipw_fw_dma_command_block_index();
	virtual void ipw_fw_dma_dump_command_block();
	virtual void ipw_fw_dma_abort();
	virtual UInt32 ipw_read_reg32( UInt32 reg);
	virtual void ipw_write_reg8(UInt32 reg, UInt8 value);		
	virtual UInt8 ipw_read_reg8(UInt32 reg);
	virtual void ipw_write_reg16(UInt32 reg, UInt16 value);
	virtual int ipw_stop_nic();
	virtual int ipw_reset_nic(struct ipw_priv *priv);
	virtual int ipw_init_nic();									
	virtual void ipw_start_nic();
	virtual inline void ipw_enable_interrupts(struct ipw_priv *priv);
	virtual int ipw_set_geo(struct ieee80211_device *ieee,
		       const struct ieee80211_geo *geo);
	virtual int rf_kill_active(struct ipw_priv *priv);
	virtual void ipw_down(struct ipw_priv *priv);
	virtual int ipw_up(struct ipw_priv *priv);
	virtual inline int ipw_is_init(struct ipw_priv *priv);
	virtual void ipw_deinit(struct ipw_priv *priv);
	virtual void ipw_led_shutdown(struct ipw_priv *priv);
	virtual u32 ipw_register_toggle(u32 reg);
	virtual void ipw_led_activity_off(struct ipw_priv *priv);
	virtual void ipw_led_link_off(struct ipw_priv *priv);
	virtual void ipw_led_band_off(struct ipw_priv *priv);
	virtual inline void ipw_disable_interrupts(struct ipw_priv *priv);
	virtual void ipw_led_radio_off(struct ipw_priv *priv);
	virtual void ipw_led_init(struct ipw_priv *priv);
	virtual void ipw_led_link_on(struct ipw_priv *priv);
	virtual void ipw_led_band_on(struct ipw_priv *priv);
	virtual int ipw_sw_reset(int option);
	virtual int ipw_get_fw(const struct firmware **fw, const char *name);
	virtual void ipw_led_link_down(struct ipw_priv *priv);
	virtual void ipw_rf_kill(ipw_priv *priv);
	virtual int ipw_best_network(struct ipw_priv *priv,
			    struct ipw_network_match *match,
			    struct ieee80211_network *network, int roaming);
	virtual int ipw_compatible_rates(struct ipw_priv *priv,
				const struct ieee80211_network *network,
				struct ipw_supported_rates *rates);
	virtual void ipw_copy_rates(struct ipw_supported_rates *dest,
			   const struct ipw_supported_rates *src);
	virtual int ipw_is_rate_in_mask(struct ipw_priv *priv, int ieee_mode, u8 rate);
	virtual void ipw_adhoc_create(struct ipw_priv *priv,
			     struct ieee80211_network *network);		   
	virtual int ipw_is_valid_channel(struct ieee80211_device *ieee, u8 channel);
	virtual int ipw_channel_to_index(struct ieee80211_device *ieee, u8 channel);
	virtual void ipw_create_bssid(struct ipw_priv *priv, u8 * bssid);
	virtual void ipw_set_fixed_rate(struct ipw_priv *priv, int mode);
	virtual int ipw_grab_restricted_access(struct ipw_priv *priv);
	virtual void _ipw_write_restricted(struct ipw_priv *priv,
					 u32 reg, u32 value);
	virtual void _ipw_write_restricted_reg(struct ipw_priv *priv,
					     u32 addr, u32 val);
	virtual void _ipw_release_restricted_access(struct ipw_priv
						  *priv);
	virtual int ipw_download_ucode_base(struct ipw_priv *priv, u8 * image, u32 len);
	virtual void ipw_write_restricted_reg_buffer(struct ipw_priv
						   *priv, u32 reg,
						   u32 len, u8 * values);
	virtual u32 _ipw_read_restricted_reg(struct ipw_priv *priv, u32 reg);
	virtual u32 _ipw_read_restricted(struct ipw_priv *priv, u32 reg);
	virtual int ipw_download_ucode(struct ipw_priv *priv,
			      struct fw_image_desc *desc,
			      u32 mem_size, dma_addr_t dst_addr);
	virtual int attach_buffer_to_tfd_frame(void *ptr,
				      dma_addr_t addr, u16 len);
	virtual void ipw_write_buffer_restricted(struct ipw_priv *priv,
					u32 reg, u32 len, u32 * values);
	virtual int ipw_poll_restricted_bit(struct ipw_priv *priv,
					  u32 addr, u32 mask, int timeout);
	virtual int ipw_nic_init(struct ipw_priv *priv);
	virtual int ipw_power_init_handle(struct ipw_priv *priv);				
	virtual void __ipw_set_bits_restricted_reg(u32 line, struct ipw_priv
						 *priv, u32 reg, u32 mask);				
	virtual int ipw_eeprom_init_sram(struct ipw_priv *priv);
	virtual int ipw_rate_scale_init_handle(struct ipw_priv *priv, s32 window_size);
	virtual int ipw_rate_scale_clear_window(struct ipw_rate_scale_data
				       *window);
	virtual int ipw_nic_set_pwr_src(struct ipw_priv *priv, int pwr_max);
	virtual void __ipw_set_bits_mask_restricted_reg(u32 line, struct ipw_priv
						      *priv, u32 reg,
						      u32 bits, u32 mask);
	virtual int ipw_rf_eeprom_ready(struct ipw_priv *priv);
	virtual int ipw_verify_ucode(struct ipw_priv *priv);
	virtual void ipw_irq_handle_error(struct ipw_priv *priv);
	virtual int ipw3945_rx_queue_update_wr_ptr(struct ipw_priv *priv,
					  struct ipw_rx_queue *q);
	virtual void freePacket(mbuf_t m, IOOptionBits options=0);
	virtual void ipw_clear_bits_restricted_reg(struct ipw_priv
					  *priv, u32 reg, u32 mask);
	virtual void ipw_bg_resume_work();
	virtual int ipw_init_channel_map(struct ipw_priv *priv);
	virtual  void ipw_init_band_reference(struct ipw_priv *priv, int band,
				    int *eeprom_ch_count,
				    const struct ipw_eeprom_channel
				    **eeprom_ch_info,
				    const u8 ** eeprom_ch_index);
	virtual int is_channel_valid(const struct ipw_channel_info *ch_info);
	virtual u8 is_channel_a_band(const struct ipw_channel_info *ch_info);
	virtual int is_channel_passive(const struct ipw_channel_info *ch);
	virtual int is_channel_radar(const struct ipw_channel_info *ch_info);
	virtual int reg_txpower_set_from_eeprom(struct ipw_priv *priv);
	virtual int reg_txpower_get_temperature(struct ipw_priv *priv);
	virtual int ipw_get_temperature(struct ipw_priv *priv);
	virtual int reg_temp_out_of_range(int temperature);
	virtual void reg_init_channel_groups(struct ipw_priv *priv);
	virtual u16 reg_get_chnl_grp_index(struct ipw_priv *priv,
				  const struct ipw_channel_info *ch_info);
	virtual int reg_adjust_power_by_temp(int new_reading, int old_reading);			  
	virtual int reg_get_matched_power_index(struct ipw_priv *priv,
				       s8 requested_power,
				       s32 setting_index, s32 * new_index);			  
	virtual u8 reg_fix_power_index(int index);			  
	virtual void reg_set_scan_power(struct ipw_priv *priv, u32 scan_tbl_index,
			       s32 rate_index, const s8 * clip_pwrs,
			       struct ipw_channel_info *ch_info, int band_index);			  
	virtual void ipw_init_geos(struct ipw_priv *priv);
	virtual void ipw_init_hw_rates(struct ipw_priv *priv, struct ieee80211_rate *rates);
	virtual struct ipw_channel_info *ipw_get_channel_info(struct ipw_priv *priv,
						     int phymode, int channel);
	virtual void ipw_set_supported_rates_mask(struct ipw_priv *priv, int rates_mask);
	virtual int ipw_set_rate(struct ipw_priv *priv);
	virtual void ipw_set_supported_rates(struct ipw_priv *priv);
	virtual int ipw_rate_plcp2index(u8 x);
	virtual int ipw_send_power_mode(struct ipw_priv *priv, u32 mode);
	virtual int ipw3945_send_power_mode(struct ipw_priv *priv, u32 mode);
	virtual int ipw_update_power_cmd(struct ipw_priv *priv,
				struct ipw_powertable_cmd *cmd, u32 mode);
	virtual int ipw_send_cmd_pdu(struct ipw_priv *priv, u8 id, u16 len, void *data);
	virtual void ipw_connection_init_rx_config(struct ipw_priv *priv);
	virtual const struct ipw_channel_info *find_channel(struct ipw_priv *priv,
						   u8 channel);
	virtual void ipw_set_flags_for_channel(struct ipw_priv *priv,
				      const struct ipw_channel_info *ch_info);
	virtual int ipw_send_bt_config(struct ipw_priv *priv);
	virtual int ipw3945_queue_tx_free(struct ipw_priv *priv,
				 struct ipw_tx_queue *txq);
	virtual int ipw3945_queue_tx_init(struct ipw_priv *priv,
				 struct ipw_tx_queue *q, int count, u32 id);
	
	virtual int ieee80211_rate_control_register(struct rate_control_ops *ops);
	virtual void ipw_reset_channel_flag(struct ipw_priv *priv);
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
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

virtual void	dataLinkLayerAttachComplete( IO80211Interface * interface );

    virtual int ipw_load(struct ipw_priv *priv);
	virtual void ipw_add_scan_channels(struct ipw_priv *priv,
				  struct ipw_scan_request_ext *scan,
				  int scan_type);
	virtual int ipw_associate(ipw_priv *data);
	virtual void ipw_adapter_restart(ipw_priv *adapter);
	virtual void ipw_arc_release();
	virtual int ipw_stop_master();
	virtual void queue_te(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, bool start);
	virtual void queue_td(int num , thread_call_func_t func);
	virtual void ipw_scan_check(ipw_priv *priv);
	virtual IOReturn message( UInt32 type, IOService * provider,
                              void * argument);
	virtual int ipw_associate_network(struct ipw_priv *priv,
				 struct ieee80211_network *network,
				 struct ipw_supported_rates *rates, int roaming);
	virtual void ipw_remove_current_network(struct ipw_priv *priv);
	virtual void ipw_abort_scan(struct ipw_priv *priv);
	virtual int ipw_disassociate(struct ipw_priv *data);
	virtual int ipw_set_tx_power(struct ipw_priv *priv);
	virtual void init_sys_config(struct ipw_sys_config *sys_config);
	virtual int init_supported_rates(struct ipw_priv *priv,
				struct ipw_supported_rates *rates);
	virtual void ipw_set_hwcrypto_keys(struct ipw_priv *priv);
	virtual void ipw_add_cck_scan_rates(struct ipw_supported_rates *rates,
				   u8 modulation, u32 rate_mask);
	virtual void ipw_add_ofdm_scan_rates(struct ipw_supported_rates *rates,
				    u8 modulation, u32 rate_mask);
	virtual void ipw_send_tgi_tx_key(struct ipw_priv *priv, int type, int index);
	virtual void ipw_send_wep_keys(struct ipw_priv *priv, int type);
	virtual void ipw_set_hw_decrypt_unicast(struct ipw_priv *priv, int level);
	virtual void ipw_set_hw_decrypt_multicast(struct ipw_priv *priv, int level);
	virtual const struct ieee80211_geo* ipw_get_geo(struct ieee80211_device *ieee);
	virtual void ipw_send_disassociate(struct ipw_priv *priv, int quiet);
	virtual int ipw_send_associate(struct ipw_priv *priv,
			      struct ipw_associate *associate);
	virtual void ipw_link_up(struct ipw_priv *priv);
	virtual void ipw_link_down(struct ipw_priv *priv);
	virtual const char* ipw_get_status_code(u16 status);
	virtual bool configureInterface(IONetworkInterface * netif);
	virtual int ipw_qos_activate(struct ipw_priv *priv,
			    struct ieee80211_qos_data *qos_network_data);
	virtual u8 ipw_qos_current_mode(struct ipw_priv *priv);
	virtual u32 ipw_qos_get_burst_duration(struct ipw_priv *priv);
	virtual void ipw_init_ordinals(struct ipw_priv *priv);
	virtual void ipw_reset_stats(struct ipw_priv *priv);
	virtual int ipw_get_ordinal(struct ipw_priv *priv, u32 ord, void *val, u32 * len);
	virtual void ipw_read_indirect(struct ipw_priv *priv, u32 addr, u8 * buf,
			       int num);
	virtual u32 ipw_get_current_rate(struct ipw_priv *priv);
	virtual u32 ipw_get_max_rate(struct ipw_priv *priv);
	virtual void ipw_gather_stats(struct ipw_priv *priv);
	virtual void average_add(struct average *avg, s16 val);
	virtual int ipw_load_ucode(struct ipw_priv *priv,
			  struct fw_image_desc *desc,
			  u32 mem_size, dma_addr_t dst_addr);
	virtual void ipw_clear_stations_table(struct ipw_priv *priv);
	virtual void ipw_nic_start(struct ipw_priv *priv);
	virtual int ipw_card_show_info(struct ipw_priv *priv);
	virtual int ipw_query_eeprom(struct ipw_priv *priv, u32 offset,
			    u32 len, u8 * buf);
	virtual int ipw_copy_ucode_images(struct ipw_priv *priv,
				 u8 * image_code,
				 size_t image_len_code,
				 u8 * image_data, size_t image_len_data);
	virtual int ipw_read_ucode(struct ipw_priv *priv);
	virtual int ipw_setup_bootstrap(struct ipw_priv *priv);
	virtual int ipw_verify_bootstrap(struct ipw_priv *priv);
	virtual int ipw3945_nic_set_pwr_src(struct ipw_priv *priv, int pwr_max);
	virtual struct ipw_rx_queue *ipw_rx_queue_alloc(struct ipw_priv *priv);
	virtual void ipw_rx_queue_reset(struct ipw_priv *priv,
				      struct ipw_rx_queue *rxq);
	virtual void ipw_rx_queue_replenish(struct ipw_priv *priv);				  
	virtual int ipw_rx_queue_restock(struct ipw_priv *priv);
	virtual int ipw_rx_queue_update_write_ptr(struct ipw_priv *priv,
					 struct ipw_rx_queue *q);
	virtual int ipw_rx_queue_space(struct ipw_rx_queue *q);				  
	virtual void ipw_bg_alive_start();												  
	virtual int ipw_rx_init(struct ipw_priv *priv, struct ipw_rx_queue *rxq);																  				  
	virtual int ipw_queue_reset(struct ipw_priv *priv);
	virtual void ipw_queue_tx_free(struct ipw_priv *priv, struct ipw_tx_queue *txq);
	virtual void ipw_tx_queue_free(struct ipw_priv *priv);				  
	virtual int ipw_queue_inc_wrap(int index, int n_bd);								  
	virtual void ipw_queue_tx_free_tfd(struct ipw_priv *priv,
				  struct ipw_tx_queue *txq);												  				  
	virtual void ieee80211_txb_free(struct ieee80211_txb *txb);
	virtual int ipw_tx_reset(struct ipw_priv *priv);
	virtual int ipw_queue_tx_init(struct ipw_priv *priv,
			     struct ipw_tx_queue *q, int count, u32 id);
	virtual int ipw_queue_init(struct ipw_priv *priv, struct ipw_queue *q,
			  int count, int size, u32 id);
	virtual int ipw_nic_reset(struct ipw_priv *priv);
	virtual int ipw_nic_stop_master(struct ipw_priv *priv);
	virtual int ipw_tx_queue_update_write_ptr(struct ipw_priv *priv,
					 struct ipw_tx_queue *txq, int tx_id);
	virtual void getPacketBufferConstraints(IOPacketBufferConstraints * constraints) const;
	virtual int ipw_scan_completed(struct ipw_priv *priv, int success);
	virtual int ipw_scan_initiate(struct ipw_priv *priv, unsigned long ms);
	virtual int ipw_scan_schedule(struct ipw_priv *priv, unsigned long ms);
	virtual int ipw_is_ready(struct ipw_priv *priv);
	virtual int ipw_is_associated(struct ipw_priv *priv);
	virtual void ipw_handle_reply_tx(struct ipw_priv *priv, void *data, u16 sequence);
	virtual int x2_queue_used(const struct ipw_queue *q, int i);
	virtual void ipw_handle_reply_rx(struct ipw_priv *priv,
				struct ipw_rx_mem_buffer *rxb);
	virtual int is_network_packet(struct ipw_priv *priv,
			     struct ieee80211_hdr *header);
	virtual struct ieee80211_network *ieee80211_move_network_channel(struct
								ieee80211_device
								*ieee, struct
								ieee80211_network
								*network,
								u8 channel);			 
	virtual int is_same_network_channel_switch(struct ieee80211_network
					  *src, struct ieee80211_network
					  *dst, u8 channel);			 
	virtual void ipw_tx_complete(struct ipw_priv *priv,
			    struct ipw_rx_mem_buffer *rxb);			 
	virtual int ipw_queue_tx_reclaim(struct ipw_priv *priv, int fifo, int index);			 
	virtual int ipw_queue_space(const struct ipw_queue *q);
	virtual u8 get_next_cmd_index(struct ipw_queue *q, u32 index, int is_huge);
	virtual int ipw_fill_probe_req(struct ipw_priv *priv,
			      struct ieee80211_mgmt *frame,
			      int left, int is_direct);
	virtual u16 ipw_supported_rate_to_ie(u8 * ie,
				    u16 supported_rate,
				    u16 basic_rate, int max_count);
	virtual u8 ipw_rate_index2ieee(int x);
	virtual struct ieee80211_hw_mode *ipw_get_hw_mode(struct ipw_priv *priv,
						  int mode);
	virtual int ipw_get_antenna_flags(struct ipw_priv *priv);
	virtual int ipw_send_cmd(struct ipw_priv *priv, struct ipw_host_cmd *cmd);
	virtual int is_cmd_sync(struct ipw_host_cmd *cmd);
	virtual int ipw_queue_tx_hcmd(struct ipw_priv *priv, struct ipw_host_cmd *cmd);
	virtual int is_cmd_small(struct ipw_host_cmd *cmd);
	
	
	
	
	
	
	
	
	
	
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
	IOMemoryDescriptor *		memDes;			// map->getMemoryDescriptor();
	IODeviceMemory *			mem;			// fPCIDevice->getDeviceMemoryWithIndex(index);
	OSDictionary *				mediumDict;
	IONetworkMedium	*			mediumTable[MEDIUM_TYPE_INVALID];
	//IO80211Interface2			ieee80211;
	iwi_cmd_ring				cmdq;
	iwi_rx_ring					rxq;
	iwi_tx_ring					txq;
	

	struct fw_image_desc sram_desc;
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
	int pl;
	
	
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
	struct ipw_supported_rates rates;
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
	ipw_priv *priv;
	struct ieee80211_hw ieee2;
	ipw_priv priv2;
	net_device net_dev2;
	int qos_enable;
	int qos_burst_enable;
	int qos_no_ack_mask;
	int burst_duration_CCK;
	int burst_duration_OFDM;
	ifnet_t fifnet;
	IOLock *mutex;
	
};

#endif

