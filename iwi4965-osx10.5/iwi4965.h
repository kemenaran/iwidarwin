/*
 *  iwi4965.h
 *  iwi4965
 *
 *  Created by Sean Cross on 1/19/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */

//#define IO80211_VERSION 1

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
//#include <IOKit/apple80211/IO80211Controller.h>
//#include <IOKit/apple80211/IO80211Interface.h>
#include <IOKit/network/IOPacketQueue.h>
#include <IOKit/network/IONetworkMedium.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/assert.h>
#include <IOKit/IODataQueue.h>
#include <IOKit/IOMapper.h>



//includes for fifnet functions
extern "C" {
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
#include <sys/kern_control.h>
#include <libkern/libkern.h>
#include <netinet/ip6.h>
#include <sys/random.h>
#include <sys/mbuf.h>
#include <libkern/OSMalloc.h>
#include <netinet/ip.h>

}

/*#include <sys/kernel_types.h>
#include <mach/vm_types.h>
#include <sys/kpi_mbuf.h>
#include <libkern/OSByteOrder.h>
#include <sys/kern_control.h>
#include <libkern/OSAtomic.h>
*/
#include <sys/kernel_types.h>
#include <sys/kern_control.h>
#include <sys/kpi_mbuf.h>

#include <IOKit/assert.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/network/IONetworkController.h>
#include <IOKit/network/IONetworkInterface.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/network/IOMbufMemoryCursor.h>
#include <IOKit/pccard/IOPCCard.h>
#include <IOKit/apple80211/IO80211Controller.h>
#include <IOKit/apple80211/IO80211Interface.h>
#include <IOKit/network/IOPacketQueue.h>
#include <IOKit/network/IONetworkMedium.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/assert.h>
#include <IOKit/IODataQueue.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/network/IONetworkController.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOInterruptEventSource.h>

#include "defines.h"
#include "iwl-4965.h"
#include "iwl-helpers.h"
#include "iwl-4965-debug.h"
// TODO: replace all IOLOG, printk and use the debug system


extern void iwl4965_bg_up(struct iwl4965_priv *priv);
extern void iwl4965_down(struct iwl4965_priv *priv);

#pragma mark -
#pragma mark Class definition

typedef enum {
	MEDIUM_TYPE_NONE = 0,
	MEDIUM_TYPE_AUTO,
	MEDIUM_TYPE_1MBIT,
	MEDIUM_TYPE_2MBIT,
	MEDIUM_TYPE_5MBIT,
	MEDIUM_TYPE_11MBIT,
	MEDIUM_TYPE_54MBIT,
	MEDIUM_TYPE_INVALID
} mediumType_t;

#ifdef IO80211_VERSION
class darwin_iwi4965 : public IO80211Controller
#else
class darwin_iwi4965 : public IOEthernetController
#endif
    {
        OSDeclareDefaultStructors(darwin_iwi4965)
        
    public:
        virtual void queue_td2(int num , thread_call_func_t func);
		virtual void queue_te2(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, bool start);
		virtual void adapter_start(void);
		virtual void check_firstup(void);
		//virtual const char * getNamePrefix() const;
        virtual bool		init(OSDictionary *dictionary = 0);
        virtual void		free(void);
        
        virtual bool		start(IOService *provider);
        virtual void		stop(IOService *provider);
        
        virtual bool		createWorkLoop( void );
        virtual IOWorkLoop * getWorkLoop( void ) const;
        virtual IOOutputQueue * createOutputQueue( void );
		virtual const OSString * newModelString( void ) const;
		virtual const OSString * newVendorString( void ) const;
	       
        virtual bool		addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name = 0);

#ifdef IO80211_VERSION
		virtual SInt32		apple80211Request( UInt32 req, int type, IO80211Interface * intf, void * data );

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
						  
		SInt32 getPROTMODE(IO80211Interface *interface, apple80211_protmode_data *pd);
		
		SInt32 getAUTH_TYPE(IO80211Interface *interface,
							struct apple80211_authtype_data *ad);
		
		virtual bool attachInterfaceWithMacAddress( void * macAddr, 
                                                   UInt32 macLen, 
                                                   IONetworkInterface ** interface, 
                                                   bool doRegister ,
                                                   UInt32 timeout  );
        
        virtual void	dataLinkLayerAttachComplete( IO80211Interface * interface );
		
#endif        

        
        
        void postMessage(UInt32 message);

        virtual bool configureInterface( IONetworkInterface *netif );
        //    virtual SInt32 apple80211_ioctl(IO80211Interface *interface, 
        //                                    ifnet_t ifn,
        //                                    u_int32_t cmd,
        //                                    void *data);
        virtual IOReturn getHardwareAddress(IOEthernetAddress *addr);
		#ifdef IO80211_VERSION
        virtual IO80211Interface *getNetworkInterface();
		#endif
        virtual IOService * getProvider();
        
        
        virtual UInt32		getFeatures() const;

        
        virtual IOReturn enable( IONetworkInterface* netif );
        virtual IOReturn disable( IONetworkInterface* /*netif*/ );
                
        virtual int outputRaw80211Packet( IO80211Interface * interface, mbuf_t m );
										
		virtual int up(void);
		virtual void down(void);
		
		static IOReturn powerChangeHandler(void *target, void *refCon, UInt32
            messageType, IOService *service, void *messageArgument,
            vm_size_t argSize );

		static IOReturn powerDownHandler(void *target, void *refCon, UInt32
            messageType, IOService *service, void *messageArgument,
            vm_size_t argSize );
		
		virtual IOOptionBits getState( void ) const;
		
		virtual IOReturn getMaxPacketSize(UInt32 * maxSize) const;
		virtual IOReturn getMinPacketSize(UInt32 * minSize) const;
		
		
		virtual IOReturn getPacketFilters(const OSSymbol * group,
                                      UInt32 *         filters) const;
									  
		virtual IOReturn enablePacketFilter(const OSSymbol * group,
                                        UInt32           aFilter,
                                        UInt32           enabledFilters,
                                        IOOptionBits     options);
		virtual void getPacketBufferConstraints(IOPacketBufferConstraints * constraints) const;
		
		virtual IOReturn registerWithPolicyMaker(IOService * policyMaker);
    virtual IOReturn setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker);
    virtual void setPowerStateOff(void);
    virtual void setPowerStateOn(void);
		virtual IOReturn setMulticastMode(bool active);
		virtual IOReturn setMulticastList(IOEthernetAddress * addrs, UInt32 count);
		virtual UInt32	 outputPacket(mbuf_t m, void * param);
		virtual UInt32	 outputPacket2(mbuf_t m, void * param);
		virtual mbuf_t mergePacket(mbuf_t m);

	//kext control functions:	
	friend  int 		sendNetworkList(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,int opt, void *data, size_t *len); //send network list to network selector app.
	friend  int 		setSelectedNetwork(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,mbuf_t m, int flags); //get slected network from network selector app.
	friend  int			ConnectClient(kern_ctl_ref kctlref,struct sockaddr_ctl *sac,void **unitinfo); //connect to network selector app.
	friend  int 		disconnectClient(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo); //disconnect network selector app.
	friend	int			configureConnection(kern_ctl_ref ctlref, u_int unit, void *userdata, int opt, void *data, size_t len);
		
        // statistics
        IONetworkStats		*netStats;
        IOEthernetStats		*etherStats;
        
        // packet buffer variables
        IOMbufNaturalMemoryCursor                   *rxMbufCursor;
        IOMbufNaturalMemoryCursor                   *txMbufCursor;
        

        IOPCIDevice *				fPCIDevice;		// PCI nub
        IOEthernetAddress			fEnetAddr;		// holds the mac address currently hardcoded
        IOWorkLoop *				workqueue;		// the workloop
        #ifdef IO80211_VERSION
		IO80211Interface*			fNetif;	
		#else
		IOEthernetInterface*			fNetif;
		#endif		
        IOInterruptEventSource *	fInterruptSrc;	// ???
        IOTimerEventSource *		fWatchdogTimer;	// ???
        IOBasicOutputQueue *				fTransmitQueue;	// ???
        UInt16 *					memBase;
        UInt32						event;
		IONetworkMedium	*			mediumTable[MEDIUM_TYPE_INVALID];
        
        
        IOMemoryMap	*				map;			// io memory map
        UInt8						irqNumber;		// irq number
        UInt16						vendorID;		// vendor ID shld be 8086 (intel)
        UInt16						deviceID;		// device ID
        UInt16						pciReg;			// revision
        IOPhysicalAddress			ioBase;			// map->getPhysicalAddress();
        OSDictionary *				mediumDict;
#define ETH_ALEN 6
		u8 *						mac_addr;		//MAC_ADRESS
        /**
			my state very important
		*/
		u32							myState;		//information of the state of the card
		
		ifnet_t						fifnet;
		//open link to user interface application flag:
	int userInterfaceLink; //this flag will be used to abort all non-necessary background operation while
							//the user is connected to the driver.
		struct iwl4965_priv *priv;
		const char *fakemac;
		IOService *             _pmPolicyMaker;
	UInt32                  _pmPowerState;
    thread_call_t           _powerOffThreadCall;
    thread_call_t           _powerOnThreadCall;
	UInt8                          pmPCICapPtr;	
	bool                          magicPacketEnabled;
							
    };