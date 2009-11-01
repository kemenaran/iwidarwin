/*
 *  iwifi.cpp
 *  iwifi
 *
 *  Created by Sean Cross on 1/19/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */

#include "iwifi.h"

//#include "defines.h"
//#include "compatibility.h"

// Define my superclass
#ifdef IO80211_VERSION
#define super IO80211Controller
OSDefineMetaClassAndStructors(darwin_iwifi, IO80211Controller);
#else
#define super IOEthernetController
OSDefineMetaClassAndStructors(darwin_iwifi, IOEthernetController);
#endif

// Magic to make the init/exit routines public.
extern "C" {

    extern int (*init_routine)();
	extern int (*init_routine2)();
	extern IOPCIDevice* my_pci_device;
	extern UInt16 my_deviceID;
	extern int queuetx;
	extern IOService * my_provider;
	extern IONetworkController *currentController;
	extern u8 my_mac_addr[6];
	extern IOWorkLoop * my_workqueue;
	extern IOInterruptEventSource *	my_fInterruptSrc;
	extern IONetworkStats		*my_netStats;
	extern struct net_device *main_dev;
}

extern void ieee80211_tx_skb(struct ieee80211_sub_if_data *sdata, struct sk_buff *skb,
                       int encrypt);
extern int ieee80211_open();
extern int skb_set_data(const struct sk_buff *skb, void *data, size_t len);
extern struct ieee80211_local *hw_to_local(struct ieee80211_hw *hw);
extern int drv_start(struct ieee80211_local *local);
extern void drv_stop(struct ieee80211_local *local);
extern struct sk_buff *dev_alloc_skb(unsigned int length);
extern int ieee80211_reconfig(struct ieee80211_local *local);
extern IOPCIDevice * getPCIDevice();
extern IOMemoryMap * getMap();
extern void setUnloaded();
extern void start_undirect_scan();
extern void setMyfifnet(ifnet_t fifnet);
extern struct ieee80211_hw * get_my_hw();
extern void setfNetif(IOEthernetInterface*	Intf);
extern void setfTransmitQueue(IOBasicOutputQueue* fT);
extern struct sk_buff *dev_alloc_skb(unsigned int length);
				 
									 				 

static darwin_iwifi *clone;
int first_up;
static thread_call_t tlink2[256];//for the queue work...

#pragma mark -
#pragma mark Overrides required for implementation


#pragma mark -
#pragma mark IONetworkController overrides

IOOutputQueue * darwin_iwifi::createOutputQueue( void )
{
	// An IOGatedOutputQueue will serialize all calls to the driver's
    // x() function with its work loop. This essentially
    // serializes all access to the driver and the hardware through
    // the driver's work loop, which simplifies the driver but also
    // carries a small performance cost (relatively for 10/100 Mb).
    IOLog("createOutputQueue()\n");
    return IOBasicOutputQueue::withTarget(this,(IOOutputAction)&darwin_iwifi::outputPacket2,0);
}

int darwin_iwifi::outputRaw80211Packet( IO80211Interface * interface, mbuf_t m )
{
	return -1;
    /*IOLog("Someone called outputRaw80211Packet\n");
    int ret = super::outputRaw80211Packet(interface, m);
    IOLog("outputRaw80211Packet: Okay, returning %d\n", ret);
    return ret;*/
}

UInt32 darwin_iwifi::getFeatures() const {
    return kIONetworkFeatureSoftwareVlan;
}


#ifdef IO80211_VERSION
void darwin_iwifi::postMessage(UInt32 message) {
    
	if( fNetif )
        fNetif->postMessage(message, NULL, 0);
	
}
#endif


#pragma mark -
#pragma mark Setup and teardown

int ConnectClient(kern_ctl_ref kctlref,struct sockaddr_ctl *sac,void **unitinfo)
{
	IOLog("connect\n");
	clone->userInterfaceLink=1;
	return(0);
}

int disconnectClient(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo)
{
	clone->userInterfaceLink=0;
	IOLog("disconnect\n");
	return(0);
}

int configureConnection(kern_ctl_ref ctlref, u_int unit, void *userdata, int opt, void *data, size_t len)
{
	return(0);
}

int sendNetworkList(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,int opt, void *data, size_t *len)
{

	/*if (opt==0) memcpy(data,clone->priv,*len);
	if (opt==1) memcpy(data,clone->priv->ieee,*len);
	if (opt==2)
	{

	}
	if (opt==3) memcpy(data,clone->priv->assoc_network,*len);
	if (opt==4)
	{	
		if (clone->netStats->outputPackets<30 || !(clone->priv->status & STATUS_AUTH)) return 1;
		ifaddr_t *addresses;
		struct sockaddr *out_addr, ou0;
		out_addr=&ou0;
		int p=0;
		if (ifnet_get_address_list_family(clone->fifnet, &addresses, AF_INET)==0)
		{
			if (!addresses[0]) p=1;
			else
			if (ifaddr_address(addresses[0], out_addr, sizeof(*out_addr))==0)
			{
				//IWI_LOG("my ip address: " IP_FORMAT "\n",IP_LIST(out_addr->sa_data));
				memcpy(data,out_addr->sa_data,*len);

			}
			else p=1;
			ifnet_free_address_list(addresses);
		} else p=1;
		if (p==1) return 1;
	}
	if (opt==5) memcpy(data,clone->priv->net_dev,*len);*/
	return (0);
}

int setSelectedNetwork(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,mbuf_t m, int flags)
{
	return 0;
}

bool darwin_iwifi::init(OSDictionary *dict)
{

	
	return super::init(dict);
}

IOWorkLoop * darwin_iwifi::getWorkLoop( void ) const
{
    return workqueue;
}

bool darwin_iwifi::createWorkLoop( void )
{
    workqueue = IOWorkLoop::workLoop();
	
    return ( workqueue != 0 );
}

const OSString * darwin_iwifi::newVendorString( void ) const
{
    return OSString::withCString("Intel");
}

const OSString * darwin_iwifi::newModelString( void ) const
{
    const char * model = "IWIFI";
	/*if ((fPCIDevice->configRead16(kIOPCIConfigDeviceID) == 0x4223) ||
	    (fPCIDevice->configRead16(kIOPCIConfigDeviceID) == 0x4224)) 
	{
		model = "2915 ABG";
	};*/
    return OSString::withCString(model);
}


bool darwin_iwifi::start(IOService *provider)
{
	UInt16	reg;
	//Define the init state
	myState = APPLE80211_S_INIT;
    IOLog("Starting IWIFI Intel 3945, 4965, 5150, 5350, 6x00, 6x50, 1000 Wireless Driver\n");
    int err = 0;
    //linking the kext control clone to the driver:
	clone=this;

	do {
        
        // Note: super::start() calls createWorkLoop & getWorkLoop
		if ( super::start(provider) == 0) {
			IOLog("%s ERR: super::start failed\n", getName());
			break;
		}
		
		currentController=this;
		my_provider=provider;
		my_workqueue=workqueue;
		
		if ( (fPCIDevice = OSDynamicCast(IOPCIDevice, provider)) == 0) {
			IOLog("%s  fPCIDevice == 0 :(\n", getName());
			break;
		}

		fPCIDevice->retain();
		
		if (fPCIDevice->open(this) == 0) {
			IOLog("%s fPCIDevice->open(this) failed\n", getName());
			break;
		}
		
		if (fPCIDevice->requestPowerDomainState(kIOPMPowerOn, 
			(IOPowerConnection *) getParentEntry(gIOPowerPlane),
			IOPMLowestState ) != IOPMNoErr) {
				IOLog("%s Power thingi failed\n", getName());
				break;
       		}
	

				
		my_pci_device=fPCIDevice;	
		deviceID = fPCIDevice->configRead16(kIOPCIConfigDeviceID);		
		my_deviceID=deviceID;
		my_netStats=netStats;
		IOLog("Card ID: %04x\n", deviceID);

		if (deviceID==0x4222 || deviceID==0x4227)
		{
			//3945
			if( init_routine() )
			return false;
		}
		else
		{
			if( init_routine2() )
			return false;
		}
	
		queuetx=0;
		fTransmitQueue = (IOBasicOutputQueue*)createOutputQueue();
		setfTransmitQueue(fTransmitQueue);
		if (fTransmitQueue == NULL)
		{
			IOLog("ERR: getOutputQueue()\n");
			break;
		}
		fTransmitQueue->setCapacity(1024);
			
		fInterruptSrc=my_fInterruptSrc;

		mac_addr = my_mac_addr;


        // Attach the IO80211Interface to this card.  This also creates a
        // new IO80211Interface, and stores the resulting object in fNetif.
		if (attachInterface((IONetworkInterface **) &fNetif, false) == false) {
			IOLog("%s attach failed\n", getName());
			break;
		}
		setfNetif(fNetif);
		fNetif->registerOutputHandler(this,getOutputHandler());

		fNetif->registerService();
		registerService();
#ifdef IO80211_VERSION
		mediumDict = OSDictionary::withCapacity(MEDIUM_TYPE_INVALID + 1);
		addMediumType(kIOMediumIEEE80211None,  0,  MEDIUM_TYPE_NONE);
		addMediumType(kIOMediumIEEE80211Auto,  0,  MEDIUM_TYPE_AUTO);
		addMediumType(kIOMediumIEEE80211DS1,   1000000, MEDIUM_TYPE_1MBIT);
		addMediumType(kIOMediumIEEE80211DS2,   2000000, MEDIUM_TYPE_2MBIT);
		addMediumType(kIOMediumIEEE80211DS5,   5500000, MEDIUM_TYPE_5MBIT);
		addMediumType(kIOMediumIEEE80211DS11, 11000000, MEDIUM_TYPE_11MBIT);
		addMediumType(kIOMediumIEEE80211,     54000000, MEDIUM_TYPE_54MBIT, "OFDM54");
		//addMediumType(kIOMediumIEEE80211OptionAdhoc, 0, MEDIUM_TYPE_ADHOC,"ADHOC");
        
		publishMediumDictionary(mediumDict);
		setCurrentMedium(mediumTable[MEDIUM_TYPE_AUTO]);
		setSelectedMedium(mediumTable[MEDIUM_TYPE_AUTO]);
		setLinkStatus(kIONetworkLinkValid, mediumTable[MEDIUM_TYPE_AUTO]);
#else
		
		mediumDict = OSDictionary::withCapacity(MEDIUM_TYPE_INVALID + 1);
		addMediumType( kIOMediumEthernetAuto, 0, MEDIUM_TYPE_AUTO);
		//addMediumType(kIOMediumEthernetNone,  0,  MEDIUM_TYPE_NONE);
	

		publishMediumDictionary(mediumDict);
		setCurrentMedium(mediumTable[MEDIUM_TYPE_AUTO]);
		setSelectedMedium(mediumTable[MEDIUM_TYPE_AUTO]);
		setLinkStatus(kIONetworkLinkValid, mediumTable[MEDIUM_TYPE_AUTO]);
#endif			

		
		struct kern_ctl_reg		ep_ctl; // Initialize control
		kern_ctl_ref	kctlref;
		bzero(&ep_ctl, sizeof(ep_ctl));
		ep_ctl.ctl_id = 0; /* OLD STYLE: ep_ctl.ctl_id = kEPCommID; */
		ep_ctl.ctl_unit = 0;
		strcpy(ep_ctl.ctl_name,"insanelymac.iwidarwin.control");
		ep_ctl.ctl_flags = 0;
		ep_ctl.ctl_connect = ConnectClient;
		ep_ctl.ctl_disconnect = disconnectClient;
		ep_ctl.ctl_send = setSelectedNetwork;
		ep_ctl.ctl_setopt = configureConnection;
		ep_ctl.ctl_getopt = sendNetworkList;
		errno_t error = ctl_register(&ep_ctl, &kctlref);

		first_up=0;//ready for first load
		ieee80211_open();


		//queue_te2(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwifi::check_firstup),NULL,1000,true);
		
        return true;
    } while(false);
    
    free();
    return false;
}

void darwin_iwifi::queue_td2(int num , thread_call_func_t func)
{
	if (tlink2[num])
	{
		thread_call_cancel(tlink2[num]);
	}
}

void darwin_iwifi::queue_te2(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, int start)
{
		//par=my_hw->priv;
	//thread_call_func_t my_func;
	if (tlink2[num])
		queue_td2(num,NULL);
	if (!tlink2[num])
		tlink2[num]=thread_call_allocate(func,this);
	uint64_t timei2;
	if (timei)
		clock_interval_to_deadline(timei,kMillisecondScale,&timei2);
	int r;
	if (start==true && tlink2[num])
	{
		if (!par && !timei)	
			r=thread_call_enter(tlink2[num]);
		if (!par && timei)
			r=thread_call_enter_delayed(tlink2[num],timei2);
		if (par && !timei)
			r=thread_call_enter1(tlink2[num],par);
		if (par && timei)
			r=thread_call_enter1_delayed(tlink2[num],par,timei2);
	}

}

void darwin_iwifi::check_firstup(void)
{
	if (first_up==0) 
	{
		queue_te2(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwifi::check_firstup),NULL,1000,true);
		return;
	}



}


void darwin_iwifi::adapter_start(void)
{
	IOLog("ieee80211_open\n");
	//ieee80211_open(hw_to_local(get_my_hw()));
}

void darwin_iwifi::free(void)
{
	IOLog("Freeing\n");
	if( fTransmitQueue ) fTransmitQueue->release();
	IOPCIDevice *fPCIDevice = getPCIDevice();
	if( fPCIDevice) {
		printf("Stop PCI Device\n");
		fPCIDevice->setBusMasterEnable(false);
		fPCIDevice->setMemoryEnable(false);
		IOMemoryMap * map;
		map = getMap();
		if(map){
			map->unmap();
			map->release();
		}
		fPCIDevice->close(this);
		fPCIDevice->release();
	}
	super::free();
}


void darwin_iwifi::stop(IOService *provider)
{
	IOLog("Stopping\n");
	setUnloaded();//Stop all the workqueue
	IOSleep(1000);//wait for unfinished thread crappy oh Yeah!
	if (fInterruptSrc && workqueue){
        workqueue->removeEventSource(fInterruptSrc);
		fInterruptSrc->disable();
		fInterruptSrc->release();
		printf("Stopping OK\n");
	}

	if( fNetif ) {
        detachInterface( fNetif );
        fNetif->release();
    }
	super::stop(provider);
}

/******************************************************************************* 
 * Functions which MUST be implemented by any class which inherits
 * from IO80211Controller.
 ******************************************************************************/
#pragma mark -
#pragma mark IO80211Controller entry points

#ifdef IO80211_VERSION
SInt32
darwin_iwifi::getSSID(IO80211Interface *interface,
						struct apple80211_ssid_data *sd)
{
    if( NULL == sd ) {
        IOLog("Quit calling getSSID() with a null ssid_data field!\n");
        return 0;
    }
    
    
    /*
    // call interface->linkState()
    if( interface->linkState() != kIO80211NetworkLinkUp ) {
        return 0x6;
    }*/
    
    memset(sd, 0, sizeof(*sd));
    sd->version = APPLE80211_VERSION;
    strncpy((char*)sd->ssid_bytes, "anetwork", sizeof(sd->ssid_bytes));
    sd->ssid_len = strlen("anetwork");
        
	return 0;
}



SInt32 
darwin_iwifi::getMCS_INDEX_SET(IO80211Interface *interface,
                                 apple80211_mcs_index_set_data *misd)
{
    IOLog("Warning: fudged a getMCS_INDEX_SET()\n");
    
    misd->version = APPLE80211_VERSION;
    
    int offset;
    for(offset=0; offset<sizeof(misd->mcs_set_map); offset++) {
        misd->mcs_set_map[offset] = offset;
    }
    
    return kIOReturnSuccess;
}


SInt32
darwin_iwifi::getHARDWARE_VERSION(IO80211Interface *interface,
                                    struct apple80211_version_data *hv)
{
    hv->version = APPLE80211_VERSION;
    strncpy(hv->string, "Hacked up piece of code", sizeof(hv->string));
    hv->string_len = strlen("Hacked up piece of code");
    
    return kIOReturnSuccess;
}

SInt32
darwin_iwifi::getDRIVER_VERSION(IO80211Interface *interface,
                                    struct apple80211_version_data *hv)
{
    hv->version = APPLE80211_VERSION;
    strncpy(hv->string, "Version 0.0", sizeof(hv->string));
    hv->string_len = strlen("Version 0.0");
    
    return kIOReturnSuccess;
}    

SInt32
darwin_iwifi::setCHANNEL(IO80211Interface *interface,
                           struct apple80211_channel_data *cd)
{
    IOLog("Warning: ignored a setCHANNEL()\n");
    return kIOReturnSuccess;
}


SInt32
darwin_iwifi::getCHANNEL(IO80211Interface *interface,
						  struct apple80211_channel_data *cd)
{
//	IOLog("getCHANNEL c:%d f:%d\n",cd->channel.channel,cd->channel.flags);
    cd->version = APPLE80211_VERSION;
    cd->channel.version = APPLE80211_VERSION;
    cd->channel.channel = 6;
    cd->channel.flags = APPLE80211_C_FLAG_2GHZ;
	return kIOReturnSuccess;
}

SInt32
darwin_iwifi::getBSSID(IO80211Interface *interface,
						struct apple80211_bssid_data *bd)
{
    
    bd->version = APPLE80211_VERSION;
//    memcpy(bd->bssid.octet, "FEDCBA987654", sizeof(bd->bssid.octet));
    bd->bssid.octet[0] = 0xFE;
    bd->bssid.octet[1] = 0xDC;
    bd->bssid.octet[2] = 0xBA;
    bd->bssid.octet[3] = 0x98;
    bd->bssid.octet[4] = 0x76;
    bd->bssid.octet[5] = 0x54;

//    IOLog("getBSSID %s\n",escape_essid((const char*)bd->bssid.octet,sizeof(bd->bssid.octet)));

	return 0;
}

SInt32
darwin_iwifi::getCARD_CAPABILITIES(IO80211Interface *interface,
									  struct apple80211_capability_data *cd)
{
    if( !cd ) {
        IOLog("Quit calling getCARD_CAPABILITIES without specifying *cd!\n");
        return 0;
    }
    cd->version = APPLE80211_VERSION;
    cd->capabilities[0] = 0xab; // Values taken directly from AirPort_Brcm43xx
    cd->capabilities[1] = 0x7e; // I would guess they define settings for the various radios.
	return 0;
}

SInt32
darwin_iwifi::getSTATE(IO80211Interface *interface,
						  struct apple80211_state_data *sd)
{
    if( !sd ) {
        IOLog("Quit calling getSTATE without specifying *sd!\n");
        return 0;
    }
	
    sd->version = APPLE80211_VERSION;
    sd->state = APPLE80211_S_RUN;//= myState;
	/*APPLE80211_S_INIT	= 0,			// default state
	APPLE80211_S_SCAN	= 1,			// scanning
	APPLE80211_S_AUTH	= 2,			// try to authenticate
	APPLE80211_S_ASSOC	= 3,			// try to assoc
	APPLE80211_S_RUN	= 4,			// associated*/
	return 0;
}

SInt32
darwin_iwifi::getRSSI(IO80211Interface *interface,
					   struct apple80211_rssi_data *rd)
{
	IOLog("getRSSI \n");
	return 0;
}

SInt32
darwin_iwifi::getPOWER(IO80211Interface *interface,
						struct apple80211_power_data *pd)
{
    IOLog("getPOWER \n");
    
    //interface->setPowerState(kIO80211SystemPowerStateAwake, this);
    pd->version = APPLE80211_VERSION;
    pd->num_radios = 3;
    pd->power_state[0] = APPLE80211_POWER_ON;
    pd->power_state[1] = APPLE80211_POWER_ON;
    pd->power_state[2] = APPLE80211_POWER_ON;

    return kIOReturnSuccess;
    /*
	//IOPMprot *p=pm_vars;
	//memset(&(pd->power_state),0,sizeof(pd->power_state));

	//pd->num_radios=p->myCurrentState;//theNumberOfPowerStates;
	for (int c=0;c < p->theNumberOfPowerStates;c++)
	{
		IOPMPowerState *pstate=&p->thePowerStates[c];
		IOPMPowerFlags f=pstate->capabilityFlags;
		if (c < APPLE80211_MAX_RADIO) 
		{
			pd->power_state[c]=f;
		}
	
	IOPMPowerFlags pf=p->myCurrentState;
	IOLog("powerf 0x%4x\n",pf);
	//memcpy(&pd->power_state,(void*)pf,sizeof(IOPMPowerFlags));
	//IOLog("powerf 0x%4x\n",pd->power_state);
	//interface->setPowerState(pf,this);
	IOLog("getPOWER %d, %d %d %d %d\n",pd->num_radios, pd->power_state[0],pd->power_state[1],pd->power_state[2],pd->power_state[3]);
	return 0;
     */
}


SInt32
darwin_iwifi::getPOWERSAVE(IO80211Interface *interface,
                             apple80211_powersave_data *psd)
{
    psd->version = APPLE80211_VERSION;
    psd->powersave_level = APPLE80211_POWERSAVE_MODE_80211;
    
    return kIOReturnSuccess;
}

SInt32
darwin_iwifi::setPOWERSAVE(IO80211Interface *interface,
                             apple80211_powersave_data *psd)
{
    IOLog("Warning: Ignored a setPOWERSAVE\n");
    return kIOReturnSuccess;
}





SInt32 darwin_iwifi::getASSOCIATE_RESULT( IO80211Interface * interface, 
                           struct apple80211_assoc_result_data * ard )
{
	IOLog("getASSOCIATE_RESULT \n");
	return 0;
}

SInt32
darwin_iwifi::getRATE(IO80211Interface *interface,
					   struct apple80211_rate_data *rd)
{
	IOLog("getRATE %d\n",rd->rate);
	return 0;
}

SInt32
darwin_iwifi::getSTATUS_DEV(IO80211Interface *interface,
							 struct apple80211_status_dev_data *dd)
{
    if( !interface ) {
        IOLog("No interface object exists!\n");
        return -1;
    }
    if( dd == NULL ) {
        IOLog("Quit calling getSTATUS_DEV without *dd!\n");
        return -1;
    }



    dd->version = APPLE80211_VERSION;

    bzero(dd->dev_name, sizeof(dd->dev_name));
    strncpy((char*)dd->dev_name, "iwifi", sizeof(dd->dev_name));


	return kIOReturnSuccess;
}

SInt32
darwin_iwifi::getRATE_SET(IO80211Interface	*interface,
						   struct apple80211_rate_set_data *rd)
{
	IOLog("getRATE_SET %d r0:%d f0:%d\n",rd->num_rates, rd->rates[0].rate,rd->rates[0].flags);
	return 0;
}

SInt32	darwin_iwifi::getASSOCIATION_STATUS( IO80211Interface * interface, struct apple80211_assoc_status_data * asd )
{
	IOLog("getASSOCIATION_STATUS %d\n",asd->status);
	return 0;
}


SInt32 
darwin_iwifi::getLOCALE(IO80211Interface *interface, apple80211_locale_data *ld)
{
    
    ld->version = APPLE80211_VERSION;
    ld->locale  = APPLE80211_LOCALE_FCC;
 
    
    return kIOReturnSuccess;
}

SInt32 
darwin_iwifi::getCOUNTRY_CODE(IO80211Interface *interface, apple80211_country_code_data *cd) {
    cd->version = APPLE80211_VERSION;
    strncpy((char*)cd->cc, "us", sizeof(cd->cc));
    return kIOReturnSuccess;
}


SInt32
darwin_iwifi::getPHY_MODE(IO80211Interface *interface, apple80211_phymode_data *pd)
{
    pd->version = APPLE80211_VERSION;
    pd->phy_mode = APPLE80211_MODE_11A | APPLE80211_MODE_11B | APPLE80211_MODE_11G;
    pd->active_phy_mode = APPLE80211_MODE_11B;
    return kIOReturnSuccess;
}

SInt32 
darwin_iwifi::getINT_MIT(IO80211Interface *interface, apple80211_intmit_data *mitd)
{
    mitd->version = APPLE80211_VERSION;
    mitd->int_mit = APPLE80211_INT_MIT_AUTO;
    return kIOReturnSuccess;
}

SInt32 
darwin_iwifi::getTXPOWER(IO80211Interface *interface, apple80211_txpower_data *tx)
{
    tx->version = APPLE80211_VERSION;
    tx->txpower_unit = APPLE80211_UNIT_PERCENT;
    tx->txpower = 80;
    
    return kIOReturnSuccess;
}

SInt32 
darwin_iwifi::getOP_MODE(IO80211Interface *interface, apple80211_opmode_data *od)
{
    od->version = APPLE80211_VERSION;
    od->op_mode = APPLE80211_M_STA;
    return kIOReturnSuccess;
}

SInt32 
darwin_iwifi::getNOISE(IO80211Interface *interface, apple80211_noise_data *nd)
{
    nd->version = APPLE80211_VERSION;
    nd->num_radios = 3;
    nd->noise_unit = APPLE80211_UNIT_PERCENT;
    nd->noise[0] = 90;
    nd->noise[1] = 80;
    nd->noise[2] = 70;
    nd->aggregate_noise = 40;
    
    return kIOReturnSuccess;
}

SInt32
darwin_iwifi::getSCAN_RESULT(IO80211Interface *interface, apple80211_scan_result **sr)
{
    IOLog("Someone wanted a scan result.\n");
    IOLog("Scan result *sr: 0x%08x\n", sr);
	myState = APPLE80211_S_INIT;
	
	
	/*sr->version = APPLE80211_VERSION;
	sr->asr_noise = 60; //oh good AP XD
	sr->asr_cap = 0xab;		// Same as us ;)
	sr->asr_bssid.octet[0] = 0xFE;
    sr->asr_bssid.octet[1] = 0xDC;
    sr->asr_bssid.octet[2] = 0xBA;
    sr->asr_bssid.octet[3] = 0x98;
    sr->asr_bssid.octet[4] = 0x76;
    sr->asr_bssid.octet[5] = 0x54;
	
	
	strncpy((char*)sr->asr_ssid, "anetwork", sizeof(sr->asr_ssid));
    sr->asr_ssid_len = strlen("anetwork");
	
	sr->asr_age = 1;	// (ms) non-zero for cached scan result
	sr->asr_ie_len = 0;
	sr->asr_ie_data = NULL; */
	
    return kIOReturnSuccess;
}



SInt32 
darwin_iwifi::setRATE(IO80211Interface *interface, apple80211_rate_data *rd)
{
    IOLog("Warning: ignored setRATE\n");
    return kIOReturnSuccess;
}

SInt32 
darwin_iwifi::getSUPPORTED_CHANNELS(IO80211Interface *interface, apple80211_sup_channel_data *ad) {
    ad->version = APPLE80211_VERSION;
    ad->num_channels = 13;
    
    int i;
    for(i=1; i<=ad->num_channels; i++) {
        ad->supported_channels[i-1].version = APPLE80211_VERSION;
        ad->supported_channels[i-1].channel = i;
        ad->supported_channels[i-1].flags   = APPLE80211_C_FLAG_2GHZ;
    }
    
    return kIOReturnSuccess;
}
        

SInt32 
darwin_iwifi::getTX_ANTENNA(IO80211Interface *interface, apple80211_antenna_data *ad)
{
    ad->version = APPLE80211_VERSION;
    ad->num_radios = 3;
    ad->antenna_index[0] = 1;
    ad->antenna_index[1] = 1;
    ad->antenna_index[2] = 1;
    return kIOReturnSuccess;
}
    

SInt32 
darwin_iwifi::getANTENNA_DIVERSITY(IO80211Interface *interface, apple80211_antenna_data *ad)
{
    ad->version = APPLE80211_VERSION;
    ad->num_radios = 3;
    ad->antenna_index[0] = 1;
    ad->antenna_index[1] = 1;
    ad->antenna_index[2] = 1;
    return kIOReturnSuccess;
}

SInt32
darwin_iwifi::getSTATION_LIST(IO80211Interface *interface, apple80211_sta_data *sd)
{
    int i;
    IOLog("Feeding a list of stations to the driver...\n");
    sd->num_stations = 4;
    
    for(i=0; i<4; i++) {
        struct apple80211_station *sta = &(sd->station_list[i]);
        
        sta->version = APPLE80211_VERSION;
        
        memset(&(sta->sta_mac), i, sizeof(sta->sta_mac));
        sta->sta_rssi = 1;
    }
    
    
    return kIOReturnSuccess;
}

SInt32 
darwin_iwifi::setANTENNA_DIVERSITY(IO80211Interface *interface, apple80211_antenna_data *ad)
{
    IOLog("Warning: ignoring setANTENNA_DIVERSITY\n");
    return kIOReturnSuccess;
}

SInt32 
darwin_iwifi::setTX_ANTENNA(IO80211Interface *interface, apple80211_antenna_data *ad)
{
    IOLog("Warning: ignoring setTX_ANTENNA\n");
    return kIOReturnSuccess;
}


SInt32 
darwin_iwifi::setTXPOWER(IO80211Interface *interface, apple80211_txpower_data *td)
{
    IOLog("Warning: Ignored setTXPOWER\n");
    return kIOReturnSuccess;
}

SInt32 
darwin_iwifi::setINT_MIT(IO80211Interface *interface, apple80211_intmit_data *md)
{
    IOLog("Warning: Ignored setINT_MIT\n");
    return kIOReturnSuccess;
}

SInt32 
darwin_iwifi::getPROTMODE(IO80211Interface *interface, apple80211_protmode_data *pd)
{
	pd->version = APPLE80211_VERSION;
	pd->protmode = APPLE80211_PROTMODE_OFF; //no prot at this moment
	pd->threshold = 8;		// number of bytes
    return kIOReturnSuccess;
}


SInt32 
darwin_iwifi::setPROTMODE(IO80211Interface *interface, apple80211_protmode_data *pd)
{
    IOLog("Warning: Ignored setPROTMODE\n");
    return kIOReturnSuccess;
}



SInt32
darwin_iwifi::setPHY_MODE(IO80211Interface *interface, apple80211_phymode_data *pd)
{
    IOLog("Warning: Ignoring a setPHY_MODE\n");
    return kIOReturnSuccess;
}


SInt32
darwin_iwifi::setLOCALE(IO80211Interface *interface, apple80211_locale_data *ld) {
    IOLog("Warning: Ignored a setLOCALE\n");
    return kIOReturnSuccess;
}



SInt32
darwin_iwifi::setSCAN_REQ(IO80211Interface *interface,
						   struct apple80211_scan_data *sd)
{
    if( !sd ) {
        IOLog("Please don't call setSCAN_REQ without an *sd\n");
        return -1 ;
    }
    
    IOLog("Scan requested.  Type: %d\n", sd->scan_type);
    myState = APPLE80211_S_SCAN;
    //if( sd->scan_type == APPLE80211_SCAN_TYPE_ACTIVE ) {
    //    memcpy(sd->bssid.octet, "DACAFEBABE", sizeof(sd->bssid.octet));
    //}
	
	//hw scan
	start_undirect_scan();
	IOSleep(1000);
    myState = APPLE80211_S_INIT;
	
    postMessage(APPLE80211_IOC_SCAN_REQ);
    
	return kIOReturnSuccess;
}

SInt32
darwin_iwifi::setASSOCIATE(IO80211Interface *interface,struct apple80211_assoc_data *ad)
{
	IOLog("setASSOCIATE \n");
    
    postMessage(APPLE80211_IOC_SCAN_RESULT);
	return 0;
}

SInt32
darwin_iwifi::setPOWER(IO80211Interface *interface,
						struct apple80211_power_data *pd)
{
    if( NULL == pd ) {
        IOLog("Please don't call setPOWER without a *pd struct\n");
        return -1;
    }
    
    
    /*
	IOLog("setPOWER %d, %d %d %d %d\n",pd->num_radios, pd->power_state[0],pd->power_state[1],pd->power_state[2],pd->power_state[3]);
	if (pd->power_state[pd->num_radios]==1) {
		IOLog("power on\n");
	}
	else
	{
		IOLog("power off ignored\n");
		return -1;
	}
    */
    
	return kIOReturnSuccess;
}

SInt32
darwin_iwifi::setCIPHER_KEY(IO80211Interface *interface,
							 struct apple80211_key *key)
{
	IOLog("setCIPHER_KEY \n");
	return 0;
}

SInt32
darwin_iwifi::getAUTH_TYPE(IO80211Interface *interface,
							struct apple80211_authtype_data *ad)
{

	ad->version = APPLE80211_VERSION;
	ad->authtype_lower = APPLE80211_AUTHTYPE_OPEN;	//	open at this moment
	ad->authtype_upper = APPLE80211_AUTHTYPE_NONE;	//	NO upper AUTHTYPE
	return 0;
}

SInt32
darwin_iwifi::setAUTH_TYPE(IO80211Interface *interface,
							struct apple80211_authtype_data *ad)
{
	IOLog("setAUTH_TYPE \n");
	return 0;
}

SInt32
darwin_iwifi::setDISASSOCIATE(IO80211Interface	*interface)
{
	IOLog("setDISASSOCIATE \n");
	return 0;
}

SInt32
darwin_iwifi::setSSID(IO80211Interface *interface,
					   struct apple80211_ssid_data *sd)
{
	IOLog("setSSID \n");
	return 0;
}

SInt32
darwin_iwifi::setAP_MODE(IO80211Interface *interface,
						  struct apple80211_apmode_data *ad)
{
	IOLog("setAP_MODE \n");
	return 0;
}

SInt32 darwin_iwifi::apple80211Request( UInt32 req, int type, IO80211Interface * intf, void * data ) {
    SInt32 ret = 0;
    static int counter = 0;

    if( counter < 30 ) {
        counter++;
        IOLog("Someone called apple80211Request(0x%08x, %d, 0x%08x, 0x%08x)\n", req, type, intf, data);
    }
    
    // These two are defined in apple80211_ioctl.h, and ought to be the only
    // two valies /req/ can take.  They specify that /data/ should be of type apple80211req.
    // Note that SIOCGA80211 is sent to GET a value, and SIOCSA80211 is sent to SET a value.
    if( req != SIOCGA80211 && req != SIOCSA80211 ) {
        IOLog("Don't know how to deal with a request on an object of type 0x%08x\n", req);
        return 0;
    }
    
    

    // Used IOCTLs:
    // 44 43 28 51 12 19 4 5 
    switch( type ) {

            // 1:
        case APPLE80211_IOC_SSID: //req_type
            if( SIOCGA80211 == req ) {
                IOLog("Request to GET SSID\n");
                ret = getSSID(intf, (apple80211_ssid_data *)(data));
            }
            else {
                IOLog("Request to SET SSID\n");
                ret = setSSID(intf, (apple80211_ssid_data *)data);
            }
            
            break;
            
            
            // 12:
        case APPLE80211_IOC_CARD_CAPABILITIES: //req_type
            //IOLog("APPLE80211_IOC_CARD_CAPABILITIES:"
            //        " 0x%08x [%d]\n", data, data);
            if( SIOCSA80211 == req ) {
                IOLog("Don't know how to SET Capabilities!\n");
            }
            else {
                ret = getCARD_CAPABILITIES(intf,
                        (apple80211_capability_data *)data);
            }            

            break;
            
            
            
            // 23:
        case APPLE80211_IOC_STATUS_DEV_NAME: //req_type
            IOLog("APPLE80211_IOC_STATUS_DEV_NAME:"
                    " 0x%08x [%d]\n", data, data);
            if( SIOCSA80211 == req ) {
                IOLog("Don't how how to SET device name!\n");
            }
            else {
                ret = getSTATUS_DEV(intf, (apple80211_status_dev_data *)data);
            }
            
            break;
            


            // 19:
        case APPLE80211_IOC_POWER: //req_type
                
//            IOLog("APPLE80211_IOC_POWER:"
//                    " 0x%08x [%d]\n", data, data);
            if( SIOCSA80211 == req ) {
                ret = setPOWER(intf, (apple80211_power_data *)data);
            }
            else {
                ret = getPOWER(intf, (apple80211_power_data *)data);
            }
            break;
            
            
            // 4:
        case APPLE80211_IOC_CHANNEL: //req_type
        
            if( SIOCSA80211 == req ) {
                ret = setCHANNEL(intf, (apple80211_channel_data *)data);
            }
            else {
                ret = getCHANNEL(intf, (apple80211_channel_data *)data);
            }
            break;
            
            
            
        case APPLE80211_IOC_MCS_INDEX_SET:

            if( SIOCSA80211 == req ) {
                IOLog("Don't know how to SET MCS index!\n");
            }
            else {
                ret = getMCS_INDEX_SET(intf, (apple80211_mcs_index_set_data *)data);
            }
                
            break;
            
            
            
            
            // 5:
        case APPLE80211_IOC_POWERSAVE: //req_type
            if( SIOCSA80211 == req ) {
                ret = setPOWERSAVE(intf, (apple80211_powersave_data *)data);
            }
            else {
                ret = getPOWERSAVE(intf, (apple80211_powersave_data *)data);
            }
            
            
            break;
            


            
            
            // 44:
        case APPLE80211_IOC_HARDWARE_VERSION: //req_type
            if( SIOCSA80211 == req ) {
                IOLog("Don't know how to SET hardware version!\n");
            }
            else {
                ret = getHARDWARE_VERSION(intf, (apple80211_version_data *)data);
            }
             
             
            break;

            
             
             // 43:
        case APPLE80211_IOC_DRIVER_VERSION: //req_type 
            if( SIOCSA80211 == req ) {
                IOLog("Don't know how to SET driver version!\n");
            }
            else {
                ret = getDRIVER_VERSION(intf, (apple80211_version_data *)data);
            }
             
             
             break;
             

             // 28:
        case APPLE80211_IOC_LOCALE: { //req_type
            if( SIOCSA80211 == req ) {
                ret = setLOCALE(intf, (apple80211_locale_data *)data);
            }
            else {
                ret = getLOCALE(intf, (apple80211_locale_data *)data);
            }
            
            break;
        }
            
            
            // 51:
        case APPLE80211_IOC_COUNTRY_CODE: //req_type
            if( SIOCSA80211 == req ) {
                IOLog("Don't know how to SET country code!\n");
            }
            else {
                ret = getCOUNTRY_CODE(intf, (apple80211_country_code_data *)data);
            }
            
            break;
            
            
            // 14:
        case APPLE80211_IOC_PHY_MODE:
            if( SIOCSA80211 == req ) {
                ret = setPHY_MODE(intf, (apple80211_phymode_data *)data);
            }
            else {
                ret = getPHY_MODE(intf, (apple80211_phymode_data *)data);
            }
            break;
            
            //18:
        case APPLE80211_IOC_INT_MIT:
            if( SIOCSA80211 == req ) {
                ret = setINT_MIT(intf, (apple80211_intmit_data *)data);
            }
            else {
                ret = getINT_MIT(intf, (apple80211_intmit_data *)data);
            }
            break;
    
            //7:
        case APPLE80211_IOC_TXPOWER:
            if( SIOCSA80211 == req ) {
                ret = setTXPOWER(intf, (apple80211_txpower_data *)data);
            }
            else {
                ret = getTXPOWER(intf, (apple80211_txpower_data *)data);
            }
            break;
            
            //13:
        case APPLE80211_IOC_STATE:
            if( SIOCSA80211 == req ) {
                IOLog("Don't know how to SET IOC state\n");
            }
            else {
				ret = getSTATE(intf,(apple80211_state_data *)data);
            }
            break;
            
            //15:
        case APPLE80211_IOC_OP_MODE:
            if( SIOCSA80211 == req ) {
                IOLog("Don't know how to SET op mode\n");
            }
            else {
                ret = getOP_MODE(intf, (apple80211_opmode_data *)data);
            }
            break;
            
            
            //17:
        case APPLE80211_IOC_NOISE:
            if( SIOCSA80211 == req ) {
                IOLog("Don't know how to SET noise\n");
            }
            else {
                ret = getNOISE(intf, (apple80211_noise_data *)data);
            }
            break;
            
            //8:
        case APPLE80211_IOC_RATE:
            if( SIOCSA80211 == req ) {
                ret = setRATE(intf, (apple80211_rate_data *)data);
            }
            else {
                ret = getRATE(intf, (apple80211_rate_data *)data);
            }
            break;
            
            
            //16:
        case APPLE80211_IOC_RSSI:
            if( SIOCSA80211 == req ) {
                IOLog("Don't know how to SET RSSI\n");
            }
            else {
                ret = getRSSI(intf, (apple80211_rssi_data *)data);
            }
            break;
            
            
            //2:
        case APPLE80211_IOC_AUTH_TYPE:
            if( SIOCGA80211 == req ) {
                ret = getAUTH_TYPE(intf, (apple80211_authtype_data *)data);
            }
            else {
                ret = setAUTH_TYPE(intf, (apple80211_authtype_data *)data);
            }
            break;
            
            
            //6:
        case APPLE80211_IOC_PROTMODE:
            if( SIOCGA80211 == req ) {
                //IOLog("Don't know how to GET protmode\n");
				ret = getPROTMODE(intf, (apple80211_protmode_data *)data);
            }
            else {
                ret = setPROTMODE(intf, (apple80211_protmode_data *)data);
            }
            break;
            
            
            //9:
        case APPLE80211_IOC_BSSID:
            if( SIOCSA80211 == req ) {
                IOLog("Don't know how to SET bssid\n");
            }
            else {
                ret = getBSSID(intf, (apple80211_bssid_data *)data);
            }
            break;
            
            
            //39:
        case APPLE80211_IOC_ANTENNA_DIVERSITY:
            if( SIOCSA80211 == req ) {
                ret = setANTENNA_DIVERSITY(intf, (apple80211_antenna_data *)data);
            }
            else {
                ret = getANTENNA_DIVERSITY(intf, (apple80211_antenna_data *)data);
            }
            break;
            
            
            //37:
        case APPLE80211_IOC_TX_ANTENNA:
            if( SIOCSA80211 == req ) {
                ret = setTX_ANTENNA(intf, (apple80211_antenna_data *)data);
            }
            else {
                ret = getTX_ANTENNA(intf, (apple80211_antenna_data *)data);
            }
            break;
            
            
            //27:
        case APPLE80211_IOC_SUPPORTED_CHANNELS:
            if( SIOCSA80211 == req ) {
                IOLog("Don't know how to SET supported channels\n");
            }
            else {
                ret = getSUPPORTED_CHANNELS(intf, (apple80211_sup_channel_data *)data);
            }
            break;
            
            //10:
        case APPLE80211_IOC_SCAN_REQ:
            if( SIOCGA80211 == req ) {
                IOLog("Don't know how to GET scan request\n");
            }
            else {
                ret = setSCAN_REQ(intf, (apple80211_scan_data *)data);
            }
            break;
            
            
            //11:
        case APPLE80211_IOC_SCAN_RESULT:
            if( SIOCSA80211 == req ) {
                IOLog("Don't know how to SET scan result request\n");
            }
            else {
                ret = getSCAN_RESULT(intf, (apple80211_scan_result **)data);
            }
            break;
            
            
            //22:
        case APPLE80211_IOC_DISASSOCIATE:
            if( SIOCGA80211 == req ) {
                IOLog("Don't know how to GET disassociate\n");
            }
            else {
                ret = setDISASSOCIATE(intf);
            }
            break;
            
            
        default:
            IOLog("Unknown command: apple80211Request(0x%08x, %d, 0x%08x, 0x%08x)\n", req, type, intf, data);
            break;
    }


//    IOLog("Done with ioctl, returning %d.\n", ret);
    return ret;
}

int darwin_iwifi::attachInterfaceWithMacAddress( void * macAddr, 
												UInt32 macLen, 
												IONetworkInterface ** interface, 
												int doRegister ,
												UInt32 timeout  )
{
	IOLog("attachInterfaceWithMacAddress \n");
	return super::attachInterfaceWithMacAddress(macAddr,macLen,interface,doRegister,timeout);
	return true;
}												
												
void darwin_iwifi::dataLinkLayerAttachComplete( IO80211Interface * interface )											
{
	IOLog("dataLinkLayerAttachComplete \n");
	super::dataLinkLayerAttachComplete(interface);
	return;
}

#endif




#pragma mark -
#pragma mark System entry points

IOOptionBits darwin_iwifi::getState( void ) const
{
	IOOptionBits r=super::getState();
	//IWI_DEBUG_FN("getState = %x\n",r);
	return r;
}


IOReturn setWakeOnMagicPacket( int active )
{
    //magicPacketEnabled = active;
    return kIOReturnSuccess;
}

/*-------------------------------------------------------------------------
 * Called by IOEthernetInterface client to enable the controller.
 * This method is always called while running on the default workloop thread.
 *-------------------------------------------------------------------------*/


IOReturn darwin_iwifi::enable( IONetworkInterface* netif )
{

    
	if (!fifnet)
	{
		char ii[4];
		sprintf(ii,"%s%d" ,netif->getNamePrefix(), netif->getUnitNumber());
		ifnet_find_by_name(ii,&fifnet);
		setMyfifnet(fifnet);
	}
    if (first_up==0)
			first_up=1;

	if ((netif->getFlags() & IFF_RUNNING)==0)
	{
		IOLog("ifconfig going up\n ");
		ifnet_set_flags(fifnet, IFF_RUNNING, IFF_RUNNING );
		fTransmitQueue->setCapacity(1024);
		fTransmitQueue->service(IOBasicOutputQueue::kServiceAsync);
		fTransmitQueue->start();
		//struct ieee80211_local *local =hw_to_local(get_my_hw());
		//if (local) drv_start(local);
		return kIOReturnSuccess;
	}
	else
	{
		IOLog("ifconfig already up\n");
		return kIOReturnExclusiveAccess;

	}
	
    return kIOReturnSuccess;
}/* end enable netif */

void *skb_put_mbuf( mbuf_t mb, unsigned int len) {

    void *data = (UInt8*)mbuf_data(mb) + mbuf_len(mb);
    if(mbuf_trailingspace(mb) > len ){
        mbuf_setlen(mb, mbuf_len(mb)+len);
        if(mbuf_flags(mb) & MBUF_PKTHDR)
            mbuf_pkthdr_setlen(mb, mbuf_pkthdr_len(mb)+len);
    }
    //IWI_DUMP_MBUF(2,skb,len);  
    return data;
}

mbuf_t darwin_iwifi::mergePacket(mbuf_t m)
{
	mbuf_t nm,nm2;
	int offset;
	if(!mbuf_next(m))
	{
		//offset = (4 - ((int)(mbuf_data(m)) & 3)) % 4;    //packet needs to be 4 byte aligned
		offset = (1 - ((int)(mbuf_data(m)) & 3)) % 1;   
		if (offset==0) return m;
		IOLog("this packet dont have mbuf_next, merge  is not required\n");
		goto copy_packet;
	}

	/* allocate and Initialize New mbuf */
	nm = allocatePacket(mbuf_pkthdr_len(m));
	if (nm==0) return NULL;
	//if (mbuf_getpacket(MBUF_WAITOK, &nm)!=0) return NULL;
	mbuf_setlen(nm,0);
	mbuf_pkthdr_setlen(nm,0);
	if( mbuf_next(nm)) IOLog("merged mbuf_next\n");
	
	/* merging chains to single mbuf */
	for (nm2 = m; nm2;  nm2 = mbuf_next(nm2)) {
		bcopy (mbuf_data(nm2), skb_put_mbuf(nm, mbuf_len(nm2)), mbuf_len(nm2));
		//skb_put (nm, mbuf_len(nm2));
		//mbuf_copyback(nm, mbuf_len(nm), mbuf_len(nm2), mbuf_data(nm2), MBUF_WAITOK);
	}
	/* checking if merged or not. */
	if( mbuf_len(nm) == mbuf_pkthdr_len(m) ) 
	{
		if (m!=NULL)
		if (!(mbuf_type(m) == MBUF_TYPE_FREE)) freePacket(m);
		m=NULL;
		return nm;
	}
	/* merging is not completed. */
	IOLog("mergePacket is failed: data copy dont work collectly\n");
	IOLog("orig_len %d orig_pktlen %d new_len  %d new_pktlen  %d\n",
					mbuf_len(m),mbuf_pkthdr_len(m),
					mbuf_len(nm),mbuf_pkthdr_len(nm) );
	if (m!=NULL)
	if (!(mbuf_type(m) == MBUF_TYPE_FREE)) freePacket(m);
	m=NULL;
	if (nm!=NULL)
	if (!(mbuf_type(nm) == MBUF_TYPE_FREE) ) freePacket(nm);
	nm=NULL;
	return NULL;

copy_packet: 
		if (mbuf_dup(m, MBUF_WAITOK , &nm)!=0)
		{
			if (m!=NULL)
			if (!(mbuf_type(m) == MBUF_TYPE_FREE)) freePacket(m);
			m=NULL;
			return NULL;
		}
		if (m!=NULL)
		if (!(mbuf_type(m) == MBUF_TYPE_FREE) ) freePacket(m);
		m=NULL;
		return nm;
		//return copyPacket(m, 0); 
}

/*-------------------------------------------------------------------------
 * Called by IOEthernetInterface client to disable the controller.
 * This method is always called while running on the default workloop
 * thread.
 *-------------------------------------------------------------------------*/
 UInt32 darwin_iwifi::outputPacket2(mbuf_t m, void * param)
{


	IOInterruptState flags;
	//spin_lock_irqsave(spin, flags);
	
	if(m==NULL){
		IOLog("null pkt \n");
		netStats->outputErrors++;
		//goto finish;
		return kIOReturnOutputSuccess;//kIOReturnOutputDropped;
	}
	
	if(get_my_hw()){
		if((fNetif->getFlags() & IFF_RUNNING)==0
			/*|| !is_associated((struct iwl3945_priv*)get_my_hw()->priv)*/)
		{
			netStats->outputPackets++;
			IOLog("tx pkt with net down\n");
			//goto finish;
			return kIOReturnOutputSuccess;//kIOReturnOutputDropped;
		}
	}

	mbuf_t nm;
	
	IOLog("outputPacket2 t: %d f:%04x\n",mbuf_type(m),mbuf_flags(m));
	
	//drop mbuf is not PKTHDR
	if (!(mbuf_flags(m) & MBUF_PKTHDR) ){
		IOLog("BUG: dont support mbuf without pkthdr and dropped \n");
		netStats->outputErrors++;
		//goto finish;
		return kIOReturnOutputSuccess;//kIOReturnOutputDropped;
	}
	
	if(m==NULL || mbuf_type(m) == MBUF_TYPE_FREE){
		IOLog("BUG: this is freed packet and dropped \n");
		netStats->outputErrors++;
		//goto finish;
		return kIOReturnOutputSuccess;//kIOReturnOutputDropped;
	}
	if(mbuf_next(m)){
		nm = mergePacket(m);
		if (nm==NULL) 
		{
			netStats->outputErrors++;
			IOLog("merger pkt failed\n");
			return kIOReturnOutputSuccess;//kIOReturnOutputDropped;
		}
		m=nm;
	}
	if(mbuf_next(m)){
		IOLog("BUG: dont support chains mbuf\n");
		//IWI_ERR("BUG: tx packet is not single mbuf mbuf_len(%d) mbuf_pkthdr_len(%d)\n",mbuf_len(m) , mbuf_pkthdr_len(m) );
		//IWI_ERR("BUG: next mbuf size %d\n",mbuf_len(mbuf_next(m)));
		netStats->outputErrors++;
		return kIOReturnOutputSuccess;//kIOReturnOutputDropped;
	}
	IOLog("outputpacket2\n");
	if (!main_dev) return kIOReturnOutputSuccess;
	struct sk_buff *skb=dev_alloc_skb(mbuf_len(m));
	skb_set_data(skb,mbuf_data(m),mbuf_len(m));
	struct ieee80211_sub_if_data *sdata = (struct ieee80211_sub_if_data*)netdev_priv(main_dev);
	ieee80211_tx_skb(sdata, skb, 0);
	netStats->outputPackets++;
	
finish:	
	//spin_unlock_irqrestore(spin, flags);

	return kIOReturnOutputSuccess;
}


UInt32 darwin_iwifi::outputPacket(mbuf_t m, void * param)
{
	if (1)//queuetx)
	{
		if (!(fTransmitQueue->getState() & 0x1))
		{
			fTransmitQueue->setCapacity(1024);
			fTransmitQueue->service(IOBasicOutputQueue::kServiceAsync);
			fTransmitQueue->start();
			return kIOReturnOutputSuccess;//kIOReturnOutputStall; 
		}
		fTransmitQueue->enqueue(m, 0);
	}
	return kIOReturnOutputSuccess;
}


IOReturn darwin_iwifi::disable( IONetworkInterface* netif )
{

	if ((netif->getFlags() & IFF_RUNNING)!=0)
	{
		IOLog("ifconfig going down\n");
		//setLinkStatus(kIONetworkLinkValid);
		fTransmitQueue->stop();
		fTransmitQueue->setCapacity(0);
		fTransmitQueue->flush();
		ifnet_set_flags(fifnet, 0 , IFF_RUNNING);
		//struct ieee80211_local *local =hw_to_local(get_my_hw());
		//if (local) drv_stop(local);			
		return kIOReturnSuccess;
		
	}
	else
	{
		IOLog("ifconfig already down\n");
		return -1;
	}
}/* end disable netif */



/*SInt32 darwin_iwifi::apple80211_ioctl(
                                        IO80211Interface *interface, 
                                        ifnet_t ifn, 
                                        u_int32_t cmd, 
                                        void *data)
{
    IOLog("darwin_iwifi::apple80211_ioctl(%d, %d, %p)\n", ifn, cmd, data);
    return super::apple80211_ioctl(interface, ifn, cmd, data);
}*/

IOReturn darwin_iwifi::setMulticastMode(int active) {

	return kIOReturnSuccess;
}

IOReturn darwin_iwifi::setMulticastList(IOEthernetAddress * addrs, UInt32 count) {
	 return kIOReturnSuccess;
}

IOReturn darwin_iwifi::getPacketFilters(const OSSymbol * group, UInt32 *         filters) const
{
	 if ( ( group == gIOEthernetWakeOnLANFilterGroup ) )//&& ( magicPacketSupported ) )
	{
		*filters = kIOEthernetWakeOnMagicPacket;
		return kIOReturnSuccess;
	}

    // For any other filter groups, return the default set of filters
    // reported by IOEthernetController.

	return super::getPacketFilters( group, filters );
}

void darwin_iwifi::getPacketBufferConstraints(IOPacketBufferConstraints * constraints) const {
	assert(constraintsP);
    constraints->alignStart  = kIOPacketBufferAlign4;//FIXME	
    constraints->alignLength = kIOPacketBufferAlign4;	
}

IOReturn darwin_iwifi::enablePacketFilter(const OSSymbol * group,
                                        UInt32           aFilter,
                                        UInt32           enabledFilters,
                                        IOOptionBits     options)
{
	return super::enablePacketFilter(group,aFilter,enabledFilters,options);
}

IOReturn darwin_iwifi::getMaxPacketSize(UInt32 * maxSize) const
{
    *maxSize = 1518;//kIOEthernetMaxPacketSize;//;//IPW_RX_BUF_SIZE;
    return kIOReturnSuccess;
}

IOReturn darwin_iwifi::getMinPacketSize(UInt32 * minSize) const
{
    *minSize = 64;//kIOEthernetMinPacketSize;//;
    return kIOReturnSuccess;
}

bool darwin_iwifi::configureInterface( IONetworkInterface *netif )
{
    IOLog("darwin_iwifi::configureInterface()\n");
    IONetworkData * data;
    if (super::configureInterface(netif) == false)
            return false;
    
    // Get the generic network statistics structure.

   data = netif->getParameter(kIONetworkStatsKey);
    if (!data || !(netStats = (IONetworkStats *)data->getBuffer())) {
            return false;
    }

    // Get the Ethernet statistics structure.

   /* data = netif->getParameter(kIOEthernetStatsKey);
    if (!data || !(etherStats = (IOEthernetStats *)data->getBuffer())) {
            return false;
    }*/
    return true;
}



IOReturn darwin_iwifi::getHardwareAddress(IOEthernetAddress *addr)
{
	u8 *tmp = my_mac_addr;
	addr->bytes[0] = tmp[0];
	addr->bytes[1] = tmp[1];
	addr->bytes[2] = tmp[2];
	addr->bytes[3] = tmp[3];
	addr->bytes[4] = tmp[4];
	addr->bytes[5] = tmp[5];
    return kIOReturnSuccess;
}

#ifdef IO80211_VERSION
IO80211Interface *darwin_iwifi::getNetworkInterface()
{
    return super::getNetworkInterface();
}
#endif

int darwin_iwifi::addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name) {    
    IONetworkMedium * medium;
    int              ret = false;
    
    medium = IONetworkMedium::medium(type, speed, 0, code, name);
    if (medium) {
        ret = IONetworkMedium::addMedium(mediumDict, medium);
        if (ret)
            mediumTable[code] = medium;
        medium->release();
    }
    return ret;
}



