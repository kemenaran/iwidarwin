/*
 *  iwi3945.cpp
 *  iwi3945
 *
 *  Created by Sean Cross on 1/19/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */

#include "iwi3945.h"
//#include "defines.h"
//#include "compatibility.h"

// Define my superclass
#ifdef IO80211_VERSION
#define super IO80211Controller
OSDefineMetaClassAndStructors(darwin_iwi3945, IO80211Controller);
#else
#define super IOEthernetController
OSDefineMetaClassAndStructors(darwin_iwi3945, IOEthernetController);
#endif

// Magic to make the init/exit routines public.
extern "C" {
    
	extern void (*iwl_scan)(struct iwl3945_priv *);
    extern int (*iwlready)(struct iwl3945_priv *);
	extern int (*init_routine)();
    extern void (*exit_routine)();
	extern int (*is_associated)(void *);
	extern int (*mac_tx)(struct ieee80211_hw *hw, struct sk_buff *skb,struct ieee80211_tx_control *ctl);
	extern void dev_kfree_skb(struct sk_buff *skb);
	
	extern void (*iwl_down)(struct iwl3945_priv *);
	extern void (*iwl_up)(struct iwl3945_priv *);
	
	//
}

extern void setCurController(IONetworkController * tmp);
extern IOWorkLoop * getWorkLoop();
extern IOInterruptEventSource * getInterruptEventSource();
extern int if_down();
extern IOPCIDevice * getPCIDevice();
extern IOMemoryMap * getMap();
extern void setUnloaded();
extern void start_undirect_scan();
extern u8 * getMyMacAddr();
extern void setMyfifnet(ifnet_t fifnet);
extern struct ieee80211_hw * get_my_hw();
extern void * get_my_priv();
extern void setfNetif(IOEthernetInterface*	Intf);
extern void setfTransmitQueue(IOBasicOutputQueue* fT);
extern struct sk_buff *dev_alloc_skb(unsigned int length);
extern int ieee80211_sta_set_bssid(struct net_device *dev, u8 *bssid);
extern  void ieee80211_sta_req_auth(struct net_device *dev,
			    struct ieee80211_if_sta *ifsta);
extern int ieee80211_sta_set_ssid(struct net_device *dev, char *ssid, size_t len);
extern void ieee80211_associated(struct net_device *dev,
				 struct ieee80211_if_sta *ifsta);
extern void ieee80211_if_set_type(struct net_device *dev, int type);
extern void ieee80211_auth_completed(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta);
extern int ieee80211_set_channel(struct ieee80211_local *local, int channel, int freq);					 
									 				 
//struct ieee80211_tx_control tx_ctrl;//need to init this?			  
IOService * my_provider;
static darwin_iwi3945 *clone;
int first_up;
static thread_call_t tlink2[256];//for the queue work...

#pragma mark -
#pragma mark Overrides required for implementation

IOService *darwin_iwi3945::getProvider() {
    return my_provider;
}


#pragma mark -
#pragma mark IONetworkController overrides

IOOutputQueue * darwin_iwi3945::createOutputQueue( void )
{
	// An IOGatedOutputQueue will serialize all calls to the driver's
    // x() function with its work loop. This essentially
    // serializes all access to the driver and the hardware through
    // the driver's work loop, which simplifies the driver but also
    // carries a small performance cost (relatively for 10/100 Mb).
    IOLog("Someone called createOutputQueue()\n");
    return IOBasicOutputQueue::withTarget(this,(IOOutputAction)&darwin_iwi3945::outputPacket2,0);
}

int darwin_iwi3945::outputRaw80211Packet( IO80211Interface * interface, mbuf_t m )
{
	return -1;
    /*IOLog("Someone called outputRaw80211Packet\n");
    int ret = super::outputRaw80211Packet(interface, m);
    IOLog("outputRaw80211Packet: Okay, returning %d\n", ret);
    return ret;*/
}

UInt32 darwin_iwi3945::getFeatures() const {
    return kIONetworkFeatureSoftwareVlan;
}


#ifdef IO80211_VERSION
void darwin_iwi3945::postMessage(UInt32 message) {
    
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
	if (opt==1)
	{
		if (test_bit(3, &clone->priv->status)) // off -> on 3=STATUS_RF_KILL_SW
		{
			//clone->priv->config &= ~CFG_ASSOCIATE;
			IOLog("Trying to turn card on... don't work use kextload\n");	
			return(0);
			clear_bit(3, &clone->priv->status);
			if(get_my_priv())
				iwl_up((struct iwl3945_priv*)get_my_priv());
			else
				IOLog("No Priv\n");
			
		}
		else
		{
			IOLog("Trying to turn card off... don't work use kextunload\n");
			return(0);
			set_bit(3, &clone->priv->status);
			if(get_my_priv())
				iwl_down((struct iwl3945_priv*)get_my_priv());
			else
				IOLog("No Priv\n");
		}	
	}
	if(opt == 3){
		IOLog("to associate to a unsecure network reboot and check system.log\n");
		return 0;
		struct ieee80211_local *local=hw_to_local(get_my_hw());
		struct ieee80211_sta_bss *bss=NULL;
		u8 bssid[ETH_ALEN];
		bcopy(data,bssid,6);
		int i=0;
		int f=0;
		list_for_each_entry(bss, &local->sta_bss_list, list) {
			i++;
			if (!memcmp(bss->bssid,bssid,6)) 
			{
				f=1;
				break;
			}
		}
		if (!f) return 1;
		printk("%d) " MAC_FMT " ('%s') cap %x hw %d ch %d\n", i,MAC_ARG(bss->bssid),
			escape_essid((const char*)bss->ssid, bss->ssid_len),bss->capability,bss->hw_mode,bss->channel);
			
		struct net_device *dev=local->scan_dev;
		struct ieee80211_sub_if_data *sdata = (ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
		struct ieee80211_if_sta *ifsta = &sdata->u.sta;
		bcopy(bss->bssid,ifsta->bssid,ETH_ALEN);
		bcopy(bss->ssid,ifsta->ssid,bss->ssid_len);
		ifsta->ssid_len=bss->ssid_len;
		//iwl3945_add_station((struct iwl3945_priv*)get_my_priv(), ifsta->bssid, 1,0);
		//ieee80211_sta_config_auth(dev, ifsta);
		//ieee80211_authenticate(dev, ifsta);
		//ieee80211_associate(dev, ifsta);	
	}
	return(0);
}

int sendNetworkList(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,int opt, void *data, size_t *len)
{
	if(opt == 2){
		IOLog("request scan - reboot and check system.log\n");
		return 0;
		struct ieee80211_local *local=hw_to_local(get_my_hw());
		if (local)
		{
			struct net_device *dev=local->scan_dev;
			if (!local->sta_scanning)
			{
				struct ieee80211_sub_if_data *sdata = (ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
				struct ieee80211_if_sta *ifsta = &sdata->u.sta;
				bcopy(my_mac_addr,ifsta->bssid,ETH_ALEN);
				bzero(ifsta->ssid,32);
				ifsta->ssid_len=0;
				ieee80211_sta_req_scan(dev,NULL,0);
			}
			int b=0;
			while (local->sta_scanning) 
			{
				b++;
				IOSleep(10);
				if (b==500) break;
			}
			IOLog("networks found:\n");
			struct ieee80211_sta_bss *bss=NULL;
			struct ieee80211_sta_bss *bdata=(struct ieee80211_sta_bss*)data;
			int i=0;
			list_for_each_entry(bss, &local->sta_bss_list, list) {
				i++;
				bcopy(bss,&bdata[i],sizeof(*bss));
				printk("%d) " MAC_FMT " ('%s') cap %x hw %d ch %d\n", i,MAC_ARG(bss->bssid),
				escape_essid((const char*)bss->ssid, bss->ssid_len),bss->capability,bss->hw_mode,bss->channel);
			}
			bdata[0].ssid_len=i;
			if (i==0) return 1;
			//memcpy(data,&local->sta_bss_list,*len);
		}
		else
			return 1;
	}
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

bool darwin_iwi3945::init(OSDictionary *dict)
{
	fakemac=OSDynamicCast(OSString,dict->getObject("p_mac"))->getCStringNoCopy();
	
	return super::init(dict);
}

bool darwin_iwi3945::createWorkLoop( void )
{
    workqueue = IOWorkLoop::workLoop();
	
    return ( workqueue != 0 );
}

const OSString * darwin_iwi3945::newVendorString( void ) const
{
    return OSString::withCString("Intel");
}

const OSString * darwin_iwi3945::newModelString( void ) const
{
    const char * model = "3945 ABG";
	/*if ((fPCIDevice->configRead16(kIOPCIConfigDeviceID) == 0x4223) ||
	    (fPCIDevice->configRead16(kIOPCIConfigDeviceID) == 0x4224)) 
	{
		model = "2915 ABG";
	};*/
    return OSString::withCString(model);
}


bool darwin_iwi3945::start(IOService *provider)
{
	UInt16	reg;
	//Define the init state
	myState = APPLE80211_S_INIT;
    IOLog("iwi3945: Starting\n");
    int err = 0;
    //linking the kext control clone to the driver:
	clone=this;

	do {
        
        // Note: super::start() calls createWorkLoop & getWorkLoop
		if ( super::start(provider) == 0) {
			IOLog("%s ERR: super::start failed\n", getName());
			break;
		}
		
		setCurController(this);
		my_provider=provider;
		if( init_routine() )
			return false;

		fTransmitQueue = (IOBasicOutputQueue*)createOutputQueue();
		setfTransmitQueue(fTransmitQueue);
		if (fTransmitQueue == NULL)
		{
			IOLog("ERR: getOutputQueue()\n");
			break;
		}
		fTransmitQueue->setCapacity(1024);
		mac_addr = getMyMacAddr();
		//getHardwareAddress(mac_addr);
		        // Publish the MAC address
        if ( (setProperty(kIOMACAddress, mac_addr, kIOEthernetAddressSize) == false) )
        {
            IOLog("Couldn't set the kIOMACAddress property\n");
        }
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
		queue_te2(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::check_firstup),NULL,2000,true);
		
        return true;
    } while(false);
    
    free();
    return false;
}

void darwin_iwi3945::queue_td2(int num , thread_call_func_t func)
{
	if (tlink2[num])
	{
		thread_call_cancel(tlink2[num]);
	}
}

void darwin_iwi3945::queue_te2(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, bool start)
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

void darwin_iwi3945::check_firstup(void)
{

	if (first_up==0) 
	//if (_pmPowerState != 1)
	{
		//IOLog("goto system preferences -> networks and press apply if you keep seeing this\n");
		queue_te2(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::check_firstup),NULL,2000,true);
		return;
	}
	//disable(fNetif);
	struct ieee80211_local *local =hw_to_local(get_my_hw());
	u8 addr[6];
	const char *buf=fakemac;
	int i,n;
	i=0;
	if (strlen(buf)==17)
	{
		if (*(buf+2)==':' && *(buf+5)==':')
		{
			while( sscanf( buf, "%x", &n ) == 1 )
			{
				addr[i++]=n;
				buf=buf+3;
			}
		}
		IOLog("Setting mac address from parameter to " MAC_FMT "\n",MAC_ARG(addr));
		ifnet_set_lladdr(fifnet,addr,6);
		bcopy(addr, my_mac_addr, ETH_ALEN);
		bcopy(addr, local->mdev->dev_addr, ETH_ALEN);
		bcopy(addr, local->scan_dev->dev_addr, ETH_ALEN);
		setProperty(kIOMACAddress, my_mac_addr, kIOEthernetAddressSize);
	}
	//queue_te2(1,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::adapter_start),NULL,NULL,true);

	struct net_device *dev=local->scan_dev;
	int rt=0;


	//ieee80211_open(dev);
	
	retry:
			if (!local->sta_scanning)
				ieee80211_sta_req_scan(dev,NULL,0);

			int b=0;
			while (local->sta_scanning) 
			{
				b++;
				IOSleep(100);
				if (b==100) break;
			}
			IOSleep(jiffies_to_msecs(HZ*2+1));
			IOSleep(jiffies_to_msecs(HZ*2+1));
			rt++;
			IOLog("searching for networks...\n");
			struct ieee80211_sta_bss *bss=NULL;
			 i=0;
			list_for_each_entry(bss, &local->sta_bss_list, list) {
				i++;
				printk("%d) " MAC_FMT " ('%s') cap %x hw %d ch %d\n", i,MAC_ARG(bss->bssid),
				escape_essid((const char*)bss->ssid, bss->ssid_len),bss->capability,bss->hw_mode,bss->channel);
				break;
			}
			if (rt<5 && i==0)
			{
				goto retry;
			}
			if (i==0) return;

		IOLog("trying to authenticate\n");

		struct iwl3945_priv *priv=(struct iwl3945_priv*)get_my_priv();
		struct ieee80211_sub_if_data *sdata = (ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
		struct ieee80211_if_sta *ifsta = &sdata->u.sta;
		struct ieee80211_hw_mode *mode;
		struct sta_info *sta;
		u32 rates;
		int j;


	
		
		int rep=0;
	rscan:	
		memcpy(priv->staging_rxon.bssid_addr, bss->bssid, ETH_ALEN);		
		ieee80211_set_channel(local, -1, bss->freq);
		ieee80211_sta_set_ssid(dev, (char*)bss->ssid, bss->ssid_len);	
		//priv->staging_rxon.filter_flags |= RXON_FILTER_ASSOC_MSK;	
		ieee80211_sta_set_bssid(dev, bss->bssid);
		//ifsta->auth_tries = IEEE80211_AUTH_MAX_TRIES-1;
	
		

		if (!local->sta_scanning) 
		ieee80211_sta_req_scan(dev,bss->ssid,bss->ssid_len);
				
		//ieee80211_associated(dev, ifsta);
		rep++;
			while (local->sta_scanning) 
			{
				b++;
				IOSleep(100);
				if (b==100) break;
			}
		IOSleep(jiffies_to_msecs(HZ*2+1));
		IOSleep(jiffies_to_msecs(HZ*2+1));
		if (rep<1 && !ifsta->associated) goto rscan;
	
	
	//memcpy(local->mdev->dev_addr, bss->bssid, ETH_ALEN);
	
	//ifsta->aid = aid;
	ifsta->ap_capab = bss->capability;

	//kfree(ifsta->assocresp_ies);
	//ifsta->assocresp_ies_len = len - (pos - (u8 *) mgmt);
	//ifsta->assocresp_ies = (u8*)kmalloc(ifsta->assocresp_ies_len, GFP_ATOMIC);
	//if (ifsta->assocresp_ies)
	//	memcpy(ifsta->assocresp_ies, pos, ifsta->assocresp_ies_len);
	
	sta = sta_info_get(local, bss->bssid);
	
	if (!sta) {
		sta = sta_info_add(local, dev, bss->bssid, GFP_ATOMIC);
		if (!sta) {
			printk(KERN_DEBUG "%s: failed to add STA entry for the"
			       " AP\n", dev->name);
			return;
		}
			sta->last_rssi = bss->rssi;
			sta->last_signal = bss->signal;
			sta->last_noise = bss->noise;
	}

	sta->dev = dev;
	sta->flags |= WLAN_STA_AUTH | WLAN_STA_ASSOC;
	sta->assoc_ap = 1;

	rates = 0;
	mode = local->oper_hw_mode;
	for (i = 0; i < bss->supp_rates_len; i++) {
		int rate = (bss->supp_rates[i] & 0x7f) * 5;
		if (mode->mode == MODE_ATHEROS_TURBO)
			rate *= 2;
		for (j = 0; j < mode->num_rates; j++)
			if (mode->rates[j].rate == rate)
				rates |= BIT(j);
	}

	sta->supp_rates = rates;

	rate_control_rate_init(sta, local);

	if (bss->wmm_ie ) {
		ifsta->wmm_enabled=1;
		sta->flags |= WLAN_STA_WME;
		ieee80211_sta_wmm_params(dev, ifsta, bss->wmm_ie,
					 bss->wmm_ie_len);
	}


	sta_info_put(sta);
	
	IOSleep(1000);
	ieee80211_sta_reset_auth(dev, ifsta);
	ieee80211_sta_config_auth(dev, ifsta);
	//ieee80211_sta_req_auth(dev, ifsta);
	ieee80211_authenticate(dev, ifsta);
	//IOSleep(1000);	
	//ifsta->state = IEEE80211_ASSOCIATED;
	//ieee80211_associate(dev, ifsta);
	//priv->staging_rxon.filter_flags |= RXON_FILTER_ASSOC_MSK;	
	//ieee80211_sta_req_scan(dev,bss->ssid,bss->ssid_len);
	//ifsta->last_rate=54*1000000;
	//ieee80211_sta_req_auth(dev, ifsta);		
	//ieee80211_auth_completed(dev, ifsta);
//	ieee80211_associated(dev, ifsta);
//	IOSleep(1000);
	//priv->call_post_assoc_from_beacon = 1;

	//ifsta->last_rate=54*1000000;
	//setLinkStatus(kIONetworkLinkValid | (ifsta->last_rate ? kIONetworkLinkActive : 0), mediumTable[MEDIUM_TYPE_AUTO],ifsta->last_rate);
/*
#define AUTH_REQ        \
    "\xB0\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC" \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xB0\x00\x00\x00\x01\x00\x00\x00"

	rep=0;
raut:
	struct sk_buff *m=dev_alloc_skb(30);
	mbuf_pkthdr_setlen(m->mac_data,30);
	mbuf_setlen(m->mac_data,30);
	struct ieee80211_tx_packet_data *pkt_data = (struct ieee80211_tx_packet_data *)m->cb;
	memset(pkt_data, 0, sizeof(struct ieee80211_tx_packet_data));
	pkt_data->ifindex=2;
	memcpy( mbuf_data(m->mac_data), AUTH_REQ, 30 );
	memcpy( (u8*)mbuf_data(m->mac_data) +  4, bss->bssid, 6 );
	memcpy( (u8*)mbuf_data(m->mac_data) + 10, dev->dev_addr , 6 );
	memcpy( (u8*)mbuf_data(m->mac_data) + 16, bss->bssid, 6 );
	((u8*)mbuf_data(m->mac_data))[24]=0x01;
	IOLog("send authentication packet %d\n",rep);
	dev_queue_xmit(m);				
	IOSleep(1000);	
	if (rep<10 && !ifsta->authenticated) goto raut;	*/		
}


void darwin_iwi3945::adapter_start(void)
{
	IOLog("ieee80211_open\n");
	//ieee80211_open(hw_to_local(get_my_hw()));
}

void darwin_iwi3945::free(void)
{
	IOLog("iwi3945: Freeing\n");
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


void darwin_iwi3945::stop(IOService *provider)
{
	IOLog("iwi3945: Stopping\n");
	setUnloaded();//Stop all the workqueue
	IOSleep(1000);//wait for unfinished thread crappy oh Yeah!
	IOWorkLoop * workqueue = getWorkLoop();
	IOInterruptEventSource * fInterruptSrc = getInterruptEventSource();
	if (fInterruptSrc && workqueue){
        workqueue->removeEventSource(fInterruptSrc);
		fInterruptSrc->disable();
		fInterruptSrc->release();
		printf("Stopping OK\n");
	}
	if_down();
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
darwin_iwi3945::getSSID(IO80211Interface *interface,
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
darwin_iwi3945::getMCS_INDEX_SET(IO80211Interface *interface,
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
darwin_iwi3945::getHARDWARE_VERSION(IO80211Interface *interface,
                                    struct apple80211_version_data *hv)
{
    hv->version = APPLE80211_VERSION;
    strncpy(hv->string, "Hacked up piece of code", sizeof(hv->string));
    hv->string_len = strlen("Hacked up piece of code");
    
    return kIOReturnSuccess;
}

SInt32
darwin_iwi3945::getDRIVER_VERSION(IO80211Interface *interface,
                                    struct apple80211_version_data *hv)
{
    hv->version = APPLE80211_VERSION;
    strncpy(hv->string, "Version 0.0", sizeof(hv->string));
    hv->string_len = strlen("Version 0.0");
    
    return kIOReturnSuccess;
}    

SInt32
darwin_iwi3945::setCHANNEL(IO80211Interface *interface,
                           struct apple80211_channel_data *cd)
{
    IOLog("Warning: ignored a setCHANNEL()\n");
    return kIOReturnSuccess;
}


SInt32
darwin_iwi3945::getCHANNEL(IO80211Interface *interface,
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
darwin_iwi3945::getBSSID(IO80211Interface *interface,
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
darwin_iwi3945::getCARD_CAPABILITIES(IO80211Interface *interface,
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
darwin_iwi3945::getSTATE(IO80211Interface *interface,
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
darwin_iwi3945::getRSSI(IO80211Interface *interface,
					   struct apple80211_rssi_data *rd)
{
	IOLog("getRSSI \n");
	return 0;
}

SInt32
darwin_iwi3945::getPOWER(IO80211Interface *interface,
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
darwin_iwi3945::getPOWERSAVE(IO80211Interface *interface,
                             apple80211_powersave_data *psd)
{
    psd->version = APPLE80211_VERSION;
    psd->powersave_level = APPLE80211_POWERSAVE_MODE_80211;
    
    return kIOReturnSuccess;
}

SInt32
darwin_iwi3945::setPOWERSAVE(IO80211Interface *interface,
                             apple80211_powersave_data *psd)
{
    IOLog("Warning: Ignored a setPOWERSAVE\n");
    return kIOReturnSuccess;
}





SInt32 darwin_iwi3945::getASSOCIATE_RESULT( IO80211Interface * interface, 
                           struct apple80211_assoc_result_data * ard )
{
	IOLog("getASSOCIATE_RESULT \n");
	return 0;
}

SInt32
darwin_iwi3945::getRATE(IO80211Interface *interface,
					   struct apple80211_rate_data *rd)
{
	IOLog("getRATE %d\n",rd->rate);
	return 0;
}

SInt32
darwin_iwi3945::getSTATUS_DEV(IO80211Interface *interface,
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
    strncpy((char*)dd->dev_name, "iwi3945", sizeof(dd->dev_name));


	return kIOReturnSuccess;
}

SInt32
darwin_iwi3945::getRATE_SET(IO80211Interface	*interface,
						   struct apple80211_rate_set_data *rd)
{
	IOLog("getRATE_SET %d r0:%d f0:%d\n",rd->num_rates, rd->rates[0].rate,rd->rates[0].flags);
	return 0;
}

SInt32	darwin_iwi3945::getASSOCIATION_STATUS( IO80211Interface * interface, struct apple80211_assoc_status_data * asd )
{
	IOLog("getASSOCIATION_STATUS %d\n",asd->status);
	return 0;
}


SInt32 
darwin_iwi3945::getLOCALE(IO80211Interface *interface, apple80211_locale_data *ld)
{
    
    ld->version = APPLE80211_VERSION;
    ld->locale  = APPLE80211_LOCALE_FCC;
 
    
    return kIOReturnSuccess;
}

SInt32 
darwin_iwi3945::getCOUNTRY_CODE(IO80211Interface *interface, apple80211_country_code_data *cd) {
    cd->version = APPLE80211_VERSION;
    strncpy((char*)cd->cc, "us", sizeof(cd->cc));
    return kIOReturnSuccess;
}


SInt32
darwin_iwi3945::getPHY_MODE(IO80211Interface *interface, apple80211_phymode_data *pd)
{
    pd->version = APPLE80211_VERSION;
    pd->phy_mode = APPLE80211_MODE_11A | APPLE80211_MODE_11B | APPLE80211_MODE_11G;
    pd->active_phy_mode = APPLE80211_MODE_11B;
    return kIOReturnSuccess;
}

SInt32 
darwin_iwi3945::getINT_MIT(IO80211Interface *interface, apple80211_intmit_data *mitd)
{
    mitd->version = APPLE80211_VERSION;
    mitd->int_mit = APPLE80211_INT_MIT_AUTO;
    return kIOReturnSuccess;
}

SInt32 
darwin_iwi3945::getTXPOWER(IO80211Interface *interface, apple80211_txpower_data *tx)
{
    tx->version = APPLE80211_VERSION;
    tx->txpower_unit = APPLE80211_UNIT_PERCENT;
    tx->txpower = 80;
    
    return kIOReturnSuccess;
}

SInt32 
darwin_iwi3945::getOP_MODE(IO80211Interface *interface, apple80211_opmode_data *od)
{
    od->version = APPLE80211_VERSION;
    od->op_mode = APPLE80211_M_STA;
    return kIOReturnSuccess;
}

SInt32 
darwin_iwi3945::getNOISE(IO80211Interface *interface, apple80211_noise_data *nd)
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
darwin_iwi3945::getSCAN_RESULT(IO80211Interface *interface, apple80211_scan_result **sr)
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
darwin_iwi3945::setRATE(IO80211Interface *interface, apple80211_rate_data *rd)
{
    IOLog("Warning: ignored setRATE\n");
    return kIOReturnSuccess;
}

SInt32 
darwin_iwi3945::getSUPPORTED_CHANNELS(IO80211Interface *interface, apple80211_sup_channel_data *ad) {
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
darwin_iwi3945::getTX_ANTENNA(IO80211Interface *interface, apple80211_antenna_data *ad)
{
    ad->version = APPLE80211_VERSION;
    ad->num_radios = 3;
    ad->antenna_index[0] = 1;
    ad->antenna_index[1] = 1;
    ad->antenna_index[2] = 1;
    return kIOReturnSuccess;
}
    

SInt32 
darwin_iwi3945::getANTENNA_DIVERSITY(IO80211Interface *interface, apple80211_antenna_data *ad)
{
    ad->version = APPLE80211_VERSION;
    ad->num_radios = 3;
    ad->antenna_index[0] = 1;
    ad->antenna_index[1] = 1;
    ad->antenna_index[2] = 1;
    return kIOReturnSuccess;
}

SInt32
darwin_iwi3945::getSTATION_LIST(IO80211Interface *interface, apple80211_sta_data *sd)
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
darwin_iwi3945::setANTENNA_DIVERSITY(IO80211Interface *interface, apple80211_antenna_data *ad)
{
    IOLog("Warning: ignoring setANTENNA_DIVERSITY\n");
    return kIOReturnSuccess;
}

SInt32 
darwin_iwi3945::setTX_ANTENNA(IO80211Interface *interface, apple80211_antenna_data *ad)
{
    IOLog("Warning: ignoring setTX_ANTENNA\n");
    return kIOReturnSuccess;
}


SInt32 
darwin_iwi3945::setTXPOWER(IO80211Interface *interface, apple80211_txpower_data *td)
{
    IOLog("Warning: Ignored setTXPOWER\n");
    return kIOReturnSuccess;
}

SInt32 
darwin_iwi3945::setINT_MIT(IO80211Interface *interface, apple80211_intmit_data *md)
{
    IOLog("Warning: Ignored setINT_MIT\n");
    return kIOReturnSuccess;
}

SInt32 
darwin_iwi3945::getPROTMODE(IO80211Interface *interface, apple80211_protmode_data *pd)
{
	pd->version = APPLE80211_VERSION;
	pd->protmode = APPLE80211_PROTMODE_OFF; //no prot at this moment
	pd->threshold = 8;		// number of bytes
    return kIOReturnSuccess;
}


SInt32 
darwin_iwi3945::setPROTMODE(IO80211Interface *interface, apple80211_protmode_data *pd)
{
    IOLog("Warning: Ignored setPROTMODE\n");
    return kIOReturnSuccess;
}



SInt32
darwin_iwi3945::setPHY_MODE(IO80211Interface *interface, apple80211_phymode_data *pd)
{
    IOLog("Warning: Ignoring a setPHY_MODE\n");
    return kIOReturnSuccess;
}


SInt32
darwin_iwi3945::setLOCALE(IO80211Interface *interface, apple80211_locale_data *ld) {
    IOLog("Warning: Ignored a setLOCALE\n");
    return kIOReturnSuccess;
}



SInt32
darwin_iwi3945::setSCAN_REQ(IO80211Interface *interface,
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
darwin_iwi3945::setASSOCIATE(IO80211Interface *interface,struct apple80211_assoc_data *ad)
{
	IOLog("setASSOCIATE \n");
    
    postMessage(APPLE80211_IOC_SCAN_RESULT);
	return 0;
}

SInt32
darwin_iwi3945::setPOWER(IO80211Interface *interface,
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
darwin_iwi3945::setCIPHER_KEY(IO80211Interface *interface,
							 struct apple80211_key *key)
{
	IOLog("setCIPHER_KEY \n");
	return 0;
}

SInt32
darwin_iwi3945::getAUTH_TYPE(IO80211Interface *interface,
							struct apple80211_authtype_data *ad)
{

	ad->version = APPLE80211_VERSION;
	ad->authtype_lower = APPLE80211_AUTHTYPE_OPEN;	//	open at this moment
	ad->authtype_upper = APPLE80211_AUTHTYPE_NONE;	//	NO upper AUTHTYPE
	return 0;
}

SInt32
darwin_iwi3945::setAUTH_TYPE(IO80211Interface *interface,
							struct apple80211_authtype_data *ad)
{
	IOLog("setAUTH_TYPE \n");
	return 0;
}

SInt32
darwin_iwi3945::setDISASSOCIATE(IO80211Interface	*interface)
{
	IOLog("setDISASSOCIATE \n");
	return 0;
}

SInt32
darwin_iwi3945::setSSID(IO80211Interface *interface,
					   struct apple80211_ssid_data *sd)
{
	IOLog("setSSID \n");
	return 0;
}

SInt32
darwin_iwi3945::setAP_MODE(IO80211Interface *interface,
						  struct apple80211_apmode_data *ad)
{
	IOLog("setAP_MODE \n");
	return 0;
}

SInt32 darwin_iwi3945::apple80211Request( UInt32 req, int type, IO80211Interface * intf, void * data ) {
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

bool darwin_iwi3945::attachInterfaceWithMacAddress( void * macAddr, 
												UInt32 macLen, 
												IONetworkInterface ** interface, 
												bool doRegister ,
												UInt32 timeout  )
{
	IOLog("attachInterfaceWithMacAddress \n");
	return super::attachInterfaceWithMacAddress(macAddr,macLen,interface,doRegister,timeout);
	return true;
}												
												
void darwin_iwi3945::dataLinkLayerAttachComplete( IO80211Interface * interface )											
{
	IOLog("dataLinkLayerAttachComplete \n");
	super::dataLinkLayerAttachComplete(interface);
	return;
}

#endif




#pragma mark -
#pragma mark System entry points

IOOptionBits darwin_iwi3945::getState( void ) const
{
	IOOptionBits r=super::getState();
	//IWI_DEBUG_FN("getState = %x\n",r);
	return r;
}


IOReturn setWakeOnMagicPacket( bool active )
{
    //magicPacketEnabled = active;
    return kIOReturnSuccess;
}

int darwin_iwi3945::up()
{
	//if_up()
}



void darwin_iwi3945::down()
{
	//if_down();
}


/*-------------------------------------------------------------------------
 * Called by IOEthernetInterface client to enable the controller.
 * This method is always called while running on the default workloop thread.
 *-------------------------------------------------------------------------*/


IOReturn darwin_iwi3945::enable( IONetworkInterface* netif )
{
	IOLog("darwin_iwi3945::enable()\n");
    
	if (!fifnet)
	{
		char ii[4];
		sprintf(ii,"%s%d" ,netif->getNamePrefix(), netif->getUnitNumber());
		ifnet_find_by_name(ii,&fifnet);
		setMyfifnet(fifnet);
		struct ieee80211_local *local;
		local=hw_to_local(get_my_hw());
		if (local)
		{
		struct net_device *dev=local->mdev;
		if (dev)
		bcopy(ii,dev->name,sizeof(ii));
		dev=local->scan_dev;
		if (dev)
		bcopy(ii,dev->name,sizeof(ii));
		dev=local->apdev;
		if (dev)
		bcopy(ii,dev->name,sizeof(ii));
		}
	}
    if (first_up==0)
		{
			first_up=1;
		}
	if (1)//(fNetif->getFlags() & IFF_RUNNING)==0)
	{
		IOLog("ifconfig going up\n ");
		//FIXME: if associated set IFF_RUNNING
		//if (priv->status & STATUS_ASSOCIATED) 
		//if(get_my_hw())
		//	if (is_associated((void *)get_my_hw()->priv))
				ifnet_set_flags(fifnet, IFF_RUNNING, IFF_RUNNING );
		fTransmitQueue->setCapacity(1024);
		fTransmitQueue->service(IOBasicOutputQueue::kServiceAsync);
		fTransmitQueue->start();
		
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

mbuf_t darwin_iwi3945::mergePacket(mbuf_t m)
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
 UInt32 darwin_iwi3945::outputPacket2(mbuf_t m, void * param)
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
	
	//IOLog("outputPacket t: %d f:%04x\n",mbuf_type(m),mbuf_flags(m));
	
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
	
	struct ieee80211_local *local=hw_to_local(get_my_hw());
	if (!local) return kIOReturnOutputSuccess;
	//if(!local->mdev) return kIOReturnOutputSuccess;
	struct sk_buff *skb=dev_alloc_skb(mbuf_len(m));//TODO: make this work better
	struct ieee80211_tx_packet_data *pkt_data = (struct ieee80211_tx_packet_data *)skb->cb;
	memset(pkt_data, 0, sizeof(struct ieee80211_tx_packet_data));
	pkt_data->ifindex=2;
	skb_set_data(skb,mbuf_data(m),mbuf_len(m));
	dev_queue_xmit(skb);
	int ret=0; 
	//ret= ieee80211_master_start_xmit(skb,local->mdev);
	if (ret==0) 
	netStats->outputPackets++;	

finish:	
	//spin_unlock_irqrestore(spin, flags);

	return kIOReturnOutputSuccess;
}


UInt32 darwin_iwi3945::outputPacket(mbuf_t m, void * param)
{

	if (!(fTransmitQueue->getState() & 0x1))
	{
		fTransmitQueue->service(IOBasicOutputQueue::kServiceAsync);
		fTransmitQueue->start();
		return kIOReturnOutputSuccess;//kIOReturnOutputStall; 
	}
	

	fTransmitQueue->enqueue(m, 0);
	
	return kIOReturnOutputSuccess;
}


IOReturn darwin_iwi3945::disable( IONetworkInterface* /*netif*/ )
{
    IOLog("darwin_iwi3945::disable()\n");
	if (1)//(fNetif->getFlags() & IFF_RUNNING)!=0)
	{
		IOLog("ifconfig going down\n");
		setLinkStatus(kIONetworkLinkValid);
		fTransmitQueue->stop();
		fTransmitQueue->setCapacity(0);
		fTransmitQueue->flush();
		ifnet_set_flags(fifnet, 0 , IFF_RUNNING);
					
		return kIOReturnSuccess;
		
	}
	else
	{
		IOLog("ifconfig already down\n");
		return -1;
	}
}/* end disable netif */



/*SInt32 darwin_iwi3945::apple80211_ioctl(
                                        IO80211Interface *interface, 
                                        ifnet_t ifn, 
                                        u_int32_t cmd, 
                                        void *data)
{
    IOLog("darwin_iwi3945::apple80211_ioctl(%d, %d, %p)\n", ifn, cmd, data);
    return super::apple80211_ioctl(interface, ifn, cmd, data);
}*/

IOReturn darwin_iwi3945::setMulticastMode(bool active) {

	return kIOReturnSuccess;
}

IOReturn darwin_iwi3945::setMulticastList(IOEthernetAddress * addrs, UInt32 count) {
	 return kIOReturnSuccess;
}

IOReturn darwin_iwi3945::getPacketFilters(const OSSymbol * group, UInt32 *         filters) const
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

void darwin_iwi3945::getPacketBufferConstraints(IOPacketBufferConstraints * constraints) const {
	assert(constraintsP);
    constraints->alignStart  = kIOPacketBufferAlign1;	
    constraints->alignLength = kIOPacketBufferAlign1;	
}

IOReturn darwin_iwi3945::enablePacketFilter(const OSSymbol * group,
                                        UInt32           aFilter,
                                        UInt32           enabledFilters,
                                        IOOptionBits     options)
{
	return super::enablePacketFilter(group,aFilter,enabledFilters,options);
}

IOReturn darwin_iwi3945::getMaxPacketSize(UInt32 * maxSize) const
{
    *maxSize = 1600;//kIOEthernetMaxPacketSize;//;//IPW_RX_BUF_SIZE;
    return kIOReturnSuccess;
}

IOReturn darwin_iwi3945::getMinPacketSize(UInt32 * minSize) const
{
    *minSize = 32;//kIOEthernetMinPacketSize;//;
    return kIOReturnSuccess;
}

bool darwin_iwi3945::configureInterface( IONetworkInterface *netif )
{
    IOLog("darwin_iwi3945::configureInterface()\n");
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



//FIXME: Mac from iwl3945
IOReturn darwin_iwi3945::getHardwareAddress(IOEthernetAddress *addr)
{
	u8 *tmp = getMyMacAddr();
	//addr = (IOEthernetAddress *)IOMalloc(sizeof(IOEthernetAddress));
	addr->bytes[0] = tmp[0];
	addr->bytes[1] = tmp[1];
	addr->bytes[2] = tmp[2];
	addr->bytes[3] = tmp[3];
	addr->bytes[4] = tmp[4];
	addr->bytes[5] = tmp[5];
    return kIOReturnSuccess;
}

#ifdef IO80211_VERSION
IO80211Interface *darwin_iwi3945::getNetworkInterface()
{
    return super::getNetworkInterface();
}
#endif

bool darwin_iwi3945::addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name) {    
    IONetworkMedium * medium;
    bool              ret = false;
    
    medium = IONetworkMedium::medium(type, speed, 0, code, name);
    if (medium) {
        ret = IONetworkMedium::addMedium(mediumDict, medium);
        if (ret)
            mediumTable[code] = medium;
        medium->release();
    }
    return ret;
}


/*static IOReturn darwin_iwi3945::powerChangeHandler(void *target, void *refCon, UInt32
            messageType, IOService *service, void *messageArgument,
            vm_size_t argSize ) {
    IOLog("Called powerChangeHandler.  Ignoring.\n");
    return 0;
}

static IOReturn darwin_iwi3945::powerDownHandler(void *target, void *refCon, UInt32
            messageType, IOService *service, void *messageArgument,
            vm_size_t argSize ) {
    IOLog("Called powerDownHandler.  Ignoring.\n");
    return 0;
}*/
