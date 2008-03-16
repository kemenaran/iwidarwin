/*
 *  iwi3945.h
 *  iwi3945
 *
 *  Created by Sean Cross on 1/19/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */

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
        
        virtual bool		addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name = 0);

        
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

        virtual bool configureInterface( IONetworkInterface *netif );
        //    virtual SInt32 apple80211_ioctl(IO80211Interface *interface, 
        //                                    ifnet_t ifn,
        //                                    u_int32_t cmd,
        //                                    void *data);
        virtual IOReturn getHardwareAddress(IOEthernetAddress *addr); 
        virtual IO80211Interface *getNetworkInterface();
        virtual IOService * getProvider();
        
        
        virtual UInt32		getFeatures() const;

        
        virtual IOReturn enable( IONetworkInterface* netif );
        virtual IOReturn disable( IONetworkInterface* /*netif*/ );
        
        
        virtual int outputRaw80211Packet( IO80211Interface * interface, mbuf_t m );


        // statistics
        IONetworkStats		*netStats;
        IOEthernetStats		*etherStats;
        
        // packet buffer variables
        IOMbufNaturalMemoryCursor                   *rxMbufCursor;
        IOMbufNaturalMemoryCursor                   *txMbufCursor;
        

        IOPCIDevice *				fPCIDevice;		// PCI nub
        IOEthernetAddress			fEnetAddr;		// holds the mac address currently hardcoded
        IOWorkLoop *				workqueue;		// the workloop
        IO80211Interface*			fNetif;			// ???
        IOInterruptEventSource *	fInterruptSrc;	// ???
        IOTimerEventSource *		fWatchdogTimer;	// ???
        IOOutputQueue *				fTransmitQueue;	// ???
        UInt16 *					memBase;
        UInt32						event;
        
        
        IOMemoryMap	*				map;			// io memory map
        UInt8						irqNumber;		// irq number
        UInt16						vendorID;		// vendor ID shld be 8086 (intel)
        UInt16						deviceID;		// device ID
        UInt16						pciReg;			// revision
        IOPhysicalAddress			ioBase;			// map->getPhysicalAddress();
        OSDictionary *				mediumDict;
//        IONetworkMedium	*			mediumTable[MEDIUM_TYPE_INVALID];
        
    };