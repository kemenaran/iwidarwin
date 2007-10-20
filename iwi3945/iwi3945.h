
#ifndef __iwi3945_h__
#define __iwi3945_h__
	
#include "defines.h"
#include "iwlwifi.h"
#include "iwl-helpers.h"




//#define IWI_NOLOG
#define IWI_DEBUG_NORMAL
//#define IWI_DEBUG_FULL

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


//#define IEEE80211_DEBUG_MGMT(...) IWI_DEBUG("(80211_MGMT) "  __VA_ARGS__)
//#define IEEE80211_DEBUG_SCAN(...) IWI_DEBUG("(80211_SCAN) "  __VA_ARGS__)


#define IWI_WARNING(...) IWI_LOG(" W " __VA_ARGS__)
#define IWI_ERR(...) IWI_LOG(" E " __VA_ARGS__)

#define IWI_DEBUG_FN(fmt,...) IWI_DEBUG(" %s " fmt, __FUNCTION__, ##__VA_ARGS__)


#define IWI_DUMP_MBUF(...) do{ }while(0)

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

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

static LIST_HEAD(rate_ctrl_algs);
int ieee80211_rate_control_register(struct rate_control_ops *ops);
void ieee80211_rate_control_unregister(struct rate_control_ops *ops);


const struct ieee80211_hw_mode *iwl_get_hw_mode(struct iwl_priv *priv, int mode);
const struct ieee80211_hw *ieee80211_alloc_hw(size_t priv_data_len, const struct ieee80211_ops *ops);
IOBufferMemoryDescriptor * MemoryDmaAlloc(UInt32 buf_size, dma_addr_t *phys_add, void *virt_add);
void ieee80211_sta_tx(struct net_device *dev, mbuf_t skb, int encrypt);







class darwin_iwi3945 : public IOEthernetController //IO80211Controller
{
	OSDeclareDefaultStructors(darwin_iwi3945)
public:
	
	virtual IOReturn registerWithPolicyMaker(IOService * policyMaker);
    virtual IOReturn setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker);
    virtual void setPowerStateOff(void);
    virtual void setPowerStateOn(void);
	virtual bool		init(OSDictionary *dictionary = 0);
	virtual void		free(void);
	virtual bool		start(IOService *provider);
    virtual void		stop(IOService *provider);
	virtual IOReturn	getHardwareAddress(IOEthernetAddress *addr);
	virtual IOReturn	enable(IONetworkInterface * netif);
	virtual IOReturn	disable(IONetworkInterface * netif);
	static void			interruptOccurred(OSObject * owner, void * src, IOService *nub, int count);
	virtual bool		createWorkLoop( void );
	virtual IOWorkLoop * getWorkLoop( void ) const;
	virtual IOOutputQueue * createOutputQueue( void );
	virtual const OSString * newModelString( void ) const;
	virtual const OSString * newVendorString( void ) const;
	virtual bool		addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name = 0);
	virtual IOReturn	selectMedium(const IONetworkMedium * medium);
	virtual IOOptionBits getState( void ) const;
	virtual UInt32 outputPacket(mbuf_t m, void * param);
	virtual IOReturn message( UInt32 type, IOService * provider,void * argument);
	virtual bool configureInterface(IONetworkInterface * netif);
	virtual void getPacketBufferConstraints(IOPacketBufferConstraints * constraints) const;
	//kext control functions:	
	friend  int 		sendNetworkList(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,int opt, void *data, size_t *len); //send network list to network selector app.
	friend  int 		setSelectedNetwork(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,mbuf_t m, int flags); //get slected network from network selector app.
	friend  int			ConnectClient(kern_ctl_ref kctlref,struct sockaddr_ctl *sac,void **unitinfo); //connect to network selector app.
	friend  int 		disconnectClient(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo); //disconnect network selector app.
	friend	int			configureConnection(kern_ctl_ref ctlref, u_int unit, void *userdata, int opt, void *data, size_t len);
	
//private:	
	
	mbuf_t mergePacket(mbuf_t m);	
	void queue_te(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, bool start);
	void queue_td(int num , thread_call_func_t func);
	void check_firstup(struct iwl_priv *priv);
	int iwl_pci_probe();
	int iwl_hw_nic_init(struct iwl_priv *priv);
	int iwl_power_init_handle(struct iwl_priv *priv);
	int iwl3945_nic_set_pwr_src(struct iwl_priv *priv, int pwr_max);
	int iwl_up(struct iwl_priv *priv);
	void iwl_resume(struct iwl_priv *priv);
	void iwl_irq_tasklet(struct iwl_priv *priv);
	void iwl_bg_up(struct iwl_priv *priv);
	void iwl_bg_restart(struct iwl_priv *priv);
	void iwl_bg_rx_replenish(struct iwl_priv *priv);
	void iwl_bg_scan_completed(struct iwl_priv *priv);
	void iwl_bg_request_scan(struct iwl_priv *priv);
	void iwl_bg_abort_scan(struct iwl_priv *priv);
	void iwl_bg_rf_kill(struct iwl_priv *priv);
	void iwl_bg_post_associate(struct iwl_priv *priv);
	void iwl_bg_init_alive_start(struct iwl_priv *priv);
	void iwl_bg_alive_start(struct iwl_priv *priv);
	void iwl_bg_scan_check(struct iwl_priv *priv);
	void iwl3945_bg_reg_txpower_periodic(struct iwl_priv *priv);



	
	// statistics
    IONetworkStats		*netStats;
    IOEthernetStats		*etherStats;
	IOPCIDevice *				fPCIDevice;		// PCI nub
	IOEthernetAddress			fEnetAddr;		// holds the mac address currently hardcoded
	IOWorkLoop *				fWorkLoop;		// the workloop
    //IO80211Interface*			fNetif;			// ???
	IOEthernetInterface*			fNetif;
	//IONetworkInterface2*			fNetif;
	IOInterruptEventSource *	fInterruptSrc;	// ???
//	IOTimerEventSource *		fWatchdogTimer;	// ???
	IOOutputQueue *				fTransmitQueue;	// ???
	UInt16 *					memBase;
	UInt32						event;	
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

	
	struct iwl_priv *priv;
	
	ifnet_t fifnet;
	IOService *             _pmPolicyMaker;
	UInt32                  _pmPowerState;
    thread_call_t           _powerOffThreadCall;
    thread_call_t           _powerOnThreadCall;
	//open link to user interface application flag:
	int userInterfaceLink; //this flag will be used to abort all non-necessary background operation while
							//the user is connected to the driver.
	int firstifup;	
	
};
	
static darwin_iwi3945 *clone;
static thread_call_t tlink[20];
#endif

