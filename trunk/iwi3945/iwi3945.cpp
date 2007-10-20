#include "defines.h"



// Define my superclass
#define super IOEthernetController
//IO80211Controller
// REQUIRED! This macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires. Do NOT use super as the
// second parameter. You must use the literal name of the superclass.
OSDefineMetaClassAndStructors(darwin_iwi3945, IOEthernetController);//IO80211Controller);


	
bool darwin_iwi3945::init(OSDictionary *dict)
{

/* module parameters */
param_disable_hw_scan = 0;
param_debug =  0xffffffff;
param_debug &= ~(IWL_DL_IO | IWL_DL_ISR);
param_disable = 0;      /* def: enable radio */
param_antenna = 0;      /* def: 0 = both antennas (use diversity) */
param_hwcrypto = 0;     /* def: using software encryption */
param_qos_enable = 0;
 
param_disable=OSDynamicCast(OSNumber,dict->getObject("param_disable"))->unsigned32BitValue();

 IOLog("debug_level %x sw_disable %d\n",param_debug, param_disable);

 return super::init(dict);
}

const struct ieee80211_hw_mode *iwl_get_hw_mode(struct iwl_priv *priv, int mode)
{
	int i;

	for (i = 0; i < 3; i++)
		if (priv->modes[i].mode == mode)
			return &priv->modes[i];

	return NULL;
}
const struct ieee80211_hw *ieee80211_alloc_hw(size_t priv_data_len,const struct ieee80211_ops *ops)
{
	struct net_device *mdev;
	struct ieee80211_local *local;
	
	struct ieee80211_sub_if_data *sdata;
	int priv_size;
	//struct wiphy *wiphy;

	priv_size = ((sizeof(struct ieee80211_local) +
		      NETDEV_ALIGN_CONST) & ~NETDEV_ALIGN_CONST) +
		    priv_data_len;

/*	wiphy = wiphy_new(&mac80211_config_ops, priv_size);

	if (!wiphy)
		return NULL;

	wiphy->privid = mac80211_wiphy_privid;

	local = wiphy_priv(wiphy);
	local->hw.wiphy = wiphy;
*/

	local=(struct ieee80211_local*)IOMalloc(priv_size);

	local->hw.priv = 
	(char *)local +
			((sizeof(struct ieee80211_local) +
			   NETDEV_ALIGN_CONST) & ~NETDEV_ALIGN_CONST);

	local->ops = ops;

	/* for now, mdev needs sub_if_data :/ */
/*	mdev = alloc_netdev(sizeof(struct ieee80211_sub_if_data),
			    "wmaster%d", ether_setup);
	if (!mdev) {
		wiphy_free(wiphy);
		return NULL;
	}

	sdata = IEEE80211_DEV_TO_SUB_IF(mdev);
	mdev->ieee80211_ptr = &sdata->wdev;
	sdata->wdev.wiphy = wiphy;
*/

	(void*)mdev=IOMalloc(sizeof(struct ieee80211_sub_if_data));
	(void*)sdata = netdev_priv(mdev);
	mdev->ieee80211_ptr=local;
	local->mdev=mdev;
	local->hw.queues = 1; /* default */
	
/*	local->mdev = mdev;
	local->rx_pre_handlers = ieee80211_rx_pre_handlers;
	local->rx_handlers = ieee80211_rx_handlers;
	local->tx_handlers = ieee80211_tx_handlers;
*/
	local->bridge_packets = 1;

	local->rts_threshold = IEEE80211_MAX_RTS_THRESHOLD;
	local->fragmentation_threshold = IEEE80211_MAX_FRAG_THRESHOLD;
	local->short_retry_limit = 7;
	local->long_retry_limit = 4;
	local->hw.conf.radio_enabled = 1;
	//local->rate_ctrl_num_up = RATE_CONTROL_NUM_UP;
	//local->rate_ctrl_num_down = RATE_CONTROL_NUM_DOWN;

	local->enabled_modes = (unsigned int) -1;

	INIT_LIST_HEAD(&local->modes_list);

//	rwlock_init(&local->sub_if_lock);
	INIT_LIST_HEAD(&local->sub_if_list);

//	INIT_DELAYED_WORK(&local->scan_work, ieee80211_sta_scan_work);
//	init_timer(&local->stat_timer);
//	local->stat_timer.function = ieee80211_stat_refresh;
	//local->stat_timer.data = (unsigned long) local;
//	ieee80211_rx_bss_list_init(mdev);

	//sta_info_init(local);
	INIT_LIST_HEAD(&local->sta_list);
	INIT_LIST_HEAD(&local->deleted_sta_list);
	//local->sta_cleanup.expires = jiffies + STA_INFO_CLEANUP_INTERVAL;
	//local->sta_cleanup.data = (unsigned long) local;
	
/*	mdev->hard_start_xmit = ieee80211_master_start_xmit;
	mdev->open = ieee80211_master_open;
	mdev->stop = ieee80211_master_stop;
	mdev->type = ARPHRD_IEEE80211;
	mdev->hard_header_parse = header_parse_80211;*/
	sdata->type = IEEE80211_IF_TYPE_AP;
	sdata->dev = mdev;
	sdata->local = local;
	sdata->u.ap.force_unicast_rateidx = -1;
	sdata->u.ap.max_ratectrl_rateidx = -1;
	ieee80211_if_sdata_init(sdata);
	list_add_tail(&sdata->list, &local->sub_if_list);
/*	tasklet_init(&local->tx_pending_tasklet, ieee80211_tx_pending,
		     (unsigned long)local);
	tasklet_disable(&local->tx_pending_tasklet);

	tasklet_init(&local->tasklet,
		     ieee80211_tasklet_handler,
		     (unsigned long) local);
	tasklet_disable(&local->tasklet);

	skb_queue_head_init(&local->skb_queue);
	skb_queue_head_init(&local->skb_queue_unreliable);
*/
	INIT_LIST_HEAD(&local->skb_queue);
	INIT_LIST_HEAD(&local->skb_queue_unreliable);
	
	return local_to_hw(local);
}

bool darwin_iwi3945::start(IOService *provider)
{
	UInt16	reg;
//linking the kext control clone to the driver:
		clone=this;
		firstifup=0;
	do {
				
		if ( super::start(provider) == 0) {
			IOLog("%s ERR: super::start failed\n", getName());
			break;
		}
			
		if ( (fPCIDevice = OSDynamicCast(IOPCIDevice, provider)) == 0) {
			IOLog("%s ERR: fPCIDevice == 0 :(\n", getName());
			break;
		}

		fPCIDevice->retain();
		
		if (fPCIDevice->open(this) == 0) {
			IOLog("%s ERR: fPCIDevice->open(this) failed\n", getName());
			break;
		}
		
		// Request domain power.
        	// Without this, the PCIDevice may be in state 0, and the
        	// PCI config space may be invalid if the machine has been
       		// sleeping.
		if (fPCIDevice->requestPowerDomainState(kIOPMPowerOn, 
			(IOPowerConnection *) getParentEntry(gIOPowerPlane),
			IOPMLowestState ) != IOPMNoErr) {
				IOLog("%s Power thingi failed\n", getName());
				break;
       		}

		fPCIDevice->setBusMasterEnable(true);
		fPCIDevice->setMemoryEnable(true);
		//fPCIDevice->setIOEnable(true);
		
		irqNumber = fPCIDevice->configRead8(kIOPCIConfigInterruptLine);
		vendorID = fPCIDevice->configRead16(kIOPCIConfigVendorID);
		deviceID = fPCIDevice->configRead16(kIOPCIConfigDeviceID);		
		pciReg = fPCIDevice->configRead16(kIOPCIConfigRevisionID);

  		map = fPCIDevice->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0, kIOMapInhibitCache);
  		if (map == 0) {
			IOLog("%s map is zero\n", getName());
			break;
		}
		ioBase = map->getPhysicalAddress();
		memBase = (UInt16 *)map->getVirtualAddress();
		memDes = map->getMemoryDescriptor();
		mem = fPCIDevice->getDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0);
		
		memDes->initWithPhysicalAddress(ioBase, map->getLength(), kIODirectionOutIn);
					 
		/* We disable the RETRY_TIMEOUT register (0x41) to keep
		 * PCI Tx retries from interfering with C3 CPU state */
		reg = fPCIDevice->configRead16(0x40);
		if((reg & 0x0000ff00) != 0)
			fPCIDevice->configWrite16(0x40, reg & 0xffff00ff);
			

		IOLog("%s iomemory length: 0x%x @ 0x%x\n", getName(), map->getLength(), ioBase);
		IOLog("%s virt: 0x%x physical: 0x%x\n", getName(), memBase, ioBase);
		IOLog("%s IRQ: %d, Vendor ID: %04x, Product ID: %04x\n", getName(), irqNumber, vendorID, deviceID);
		
		fWorkLoop = (IOWorkLoop *) getWorkLoop();
		if (!fWorkLoop) {
			IOLog("%s ERR: start - getWorkLoop failed\n", getName());
			break;
		}
		fInterruptSrc = IOInterruptEventSource::interruptEventSource(
			this, (IOInterruptEventAction) &darwin_iwi3945::interruptOccurred,
			provider);
		if(!fInterruptSrc || (fWorkLoop->addEventSource(fInterruptSrc) != kIOReturnSuccess)) {
			IOLog("%s fInterruptSrc error\n", getName());
			break;;
		}
		// This is important. If the interrupt line is shared with other devices,
		// then the interrupt vector will be enabled only if all corresponding
		// interrupt event sources are enabled. To avoid masking interrupts for
		// other devices that are sharing the interrupt line, the event source
		// is enabled immediately.
		fInterruptSrc->enable();
		//mutex=IOLockAlloc();
		
		fTransmitQueue = createOutputQueue();
		if (fTransmitQueue == NULL)
		{
			IWI_ERR("ERR: getOutputQueue()\n");
			break;
		}
		fTransmitQueue->setCapacity(1024);

		iwl_pci_probe();
		iwl_hw_nic_init(priv);
		iwl_hw_nic_stop_master(priv);
		
		if (attachInterface((IONetworkInterface **) &fNetif, false) == false) {
			IOLog("%s attach failed\n", getName());
			break;
		}
		
		setProperty(kIOMinPacketSize,42);
		setProperty(kIOMaxPacketSize, IWL_RX_BUF_SIZE);
	
		fNetif->registerOutputHandler(this,getOutputHandler());
		
		fNetif->registerService();
		registerService();
		
		mediumDict = OSDictionary::withCapacity(MEDIUM_TYPE_INVALID + 1);
		addMediumType(kIOMediumIEEE80211None,  0,  MEDIUM_TYPE_NONE);
		addMediumType(kIOMediumIEEE80211Auto,  0,  MEDIUM_TYPE_AUTO);
		publishMediumDictionary(mediumDict);
		setCurrentMedium(mediumTable[MEDIUM_TYPE_AUTO]);
		setSelectedMedium(mediumTable[MEDIUM_TYPE_AUTO]);
		setLinkStatus(kIONetworkLinkValid, mediumTable[MEDIUM_TYPE_AUTO]);
		
		//kext control registration:
		//these functions registers the control which enables
		//the user to interact with the driver
		
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
		
		queue_te(12,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::check_firstup),NULL,NULL,false);
		queue_te(12,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::check_firstup),priv,1000,true);

		return true;			// end start successfully
	} while (false);
		
	//stop(provider);
	//free();
	return false;			// end start insuccessfully
}

void darwin_iwi3945::check_firstup(struct iwl_priv *priv)
{
	if (firstifup==0) 
	{
		queue_te(12,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::check_firstup),priv,1000,true);
		return;
	}
	disable(fNetif);
	iwl_bg_up(priv);
	//base threads can't be called from here!!
	//queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::iwl_bg_up),priv,NULL,true);
}

IOReturn darwin_iwi3945::selectMedium(const IONetworkMedium * medium)
{
	bool  r;

	if ( OSDynamicCast(IONetworkMedium, medium) == 0 )
    {
        // Defaults to Auto.
		medium = mediumTable[MEDIUM_TYPE_AUTO];
        if ( medium == 0 ) {
		IOLog("selectMedium failed\n");
		return kIOReturnError;
	}
    }

	// Program PHY to select the desired medium.
	//r = _phySetMedium( (mediumType_t) medium->getIndex() );

	if ( r && !setCurrentMedium(medium) )
		IOLog("%s: setCurrentMedium error\n", getName());

	IOLog("Medium is set to: %s\n", medium->getName()->getCStringNoCopy());
	return ( r ? kIOReturnSuccess : kIOReturnIOError );
}

bool darwin_iwi3945::addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name) {	
    IONetworkMedium	* medium;
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

IOOutputQueue * darwin_iwi3945::createOutputQueue( void )
{
	// An IOGatedOutputQueue will serialize all calls to the driver's
    // outputPacket() function with its work loop. This essentially
    // serializes all access to the driver and the hardware through
    // the driver's work loop, which simplifies the driver but also
    // carries a small performance cost (relatively for 10/100 Mb).

    return IOGatedOutputQueue::withTarget( this, getWorkLoop() );
}

bool darwin_iwi3945::createWorkLoop( void )
{
    fWorkLoop = IOWorkLoop::workLoop();
	
    return ( fWorkLoop != 0 );
}

IOWorkLoop * darwin_iwi3945::getWorkLoop( void ) const
{
    // Override IOService::getWorkLoop() method to return the work loop
    // we allocated in createWorkLoop().

	return fWorkLoop;
}

const OSString * darwin_iwi3945::newVendorString( void ) const
{
    return OSString::withCString("Intel");
}

const OSString * darwin_iwi3945::newModelString( void ) const
{
    const char * model = "3945";

    return OSString::withCString(model);
}

IOReturn darwin_iwi3945::disable( IONetworkInterface * netif )
{
	IWI_DEBUG("ifconfig down\n");
	if ((fNetif->getFlags() & IFF_RUNNING)!=0)
	{
		IWI_DEBUG("ifconfig going down\n");
		//super::disable(fNetif);
		//fNetif->setPoweredOnByUser(false);
		fTransmitQueue->stop();
		setLinkStatus(kIONetworkLinkValid);
		//fNetif->setLinkState(kIO80211NetworkLinkDown);
		//fNetif->syncSIOCSIFFLAGS( /*IONetworkController * */this);
		//(if_flags & ~mask) | (new_flags & mask) if mask has IFF_UP if_updown fires up (kpi_interface.c in xnu)
		ifnet_set_flags(fifnet, 0 , IFF_RUNNING );
		
		
		//fTransmitQueue->setCapacity(0);
		fTransmitQueue->flush();
		fTransmitQueue->start();
				
		//if ((priv->status & STATUS_AUTH)) enable(fNetif);
		
		return kIOReturnSuccess;
		
	}
	else
	{
		IWI_DEBUG("ifconfig already down\n");
		return -1;
	}

}

IOReturn darwin_iwi3945::enable( IONetworkInterface * netif ) 
{
	if (!fifnet)
	{
		char ii[4];
		sprintf(ii,"%s%d" ,fNetif->getNamePrefix(), fNetif->getUnitNumber());
		ifnet_find_by_name(ii,&fifnet);
		IWI_DEBUG("ifnet_t %s%d = %x\n",ifnet_name(fifnet),ifnet_unit(fifnet),fifnet);
		struct ieee80211_local* loc=hw_to_local(priv->hw);
		memcpy(&loc->mdev->name,ii,sizeof(ii));
		loc->mdev->ifindex=fNetif->getUnitNumber();
	}
	if (firstifup==0)
	{
		firstifup=1;
		return -1;
	}
	
	IWI_DEBUG("ifconfig up\n");
	if ((fNetif->getFlags() & IFF_RUNNING)==0)
	{
		IWI_DEBUG("ifconfig going up\n ");
		
		//super::enable(fNetif);
		//fNetif->setPoweredOnByUser(true);
		//fNetif->setLinkState(kIO80211NetworkLinkUp);

		//(if_flags & ~mask) | (new_flags & mask) if mask has IFF_UP if_updown fires up (kpi_interface.c in xnu)	
		if (priv->status & STATUS_AUTH) ifnet_set_flags(fifnet, IFF_RUNNING, IFF_RUNNING );
		//fNetif->inputEvent(kIONetworkEventTypeLinkUp,NULL);
		fTransmitQueue->setCapacity(1024);
		fTransmitQueue->start();
		return kIOReturnSuccess;
	}
	else
	{
		IWI_DEBUG("ifconfig already up\n");
		return kIOReturnExclusiveAccess;

	}

}

mbuf_t darwin_iwi3945::mergePacket(mbuf_t m)
{
	mbuf_t nm,nm2;
	int offset;
	if(!mbuf_next(m))
	{
		offset = (4 - ((int)(mbuf_data(m)) & 3)) % 4;    //packet needs to be 4 byte aligned
		if (offset==0) return m;
		IWI_DEBUG_FULL("this packet dont have mbuf_next, merge  is not required\n");
		goto copy_packet;
	}

	/* allocate and Initialize New mbuf */
	//nm = allocatePacket(mbuf_pkthdr_len(m));
	//if (nm==0) return NULL;
	if (mbuf_getpacket(MBUF_WAITOK, &nm)!=0) return NULL;
	mbuf_setlen(nm,0);
	mbuf_pkthdr_setlen(nm,0);
	if( mbuf_next(nm)) IWI_ERR("merged mbuf_next\n");
	
	/* merging chains to single mbuf */
	for (nm2 = m; nm2;  nm2 = mbuf_next(nm2)) {
		memcpy (skb_put (nm, mbuf_len(nm2)), (UInt8*)mbuf_data(nm2), mbuf_len(nm2));
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
	IWI_LOG("mergePacket is failed: data copy dont work collectly\n");
	//IWI_WARN("orig_len %d orig_pktlen %d new_len  %d new_pktlen  %d\n",
	//				mbuf_len(m),mbuf_pkthdr_len(m),
	//				mbuf_len(nm),mbuf_pkthdr_len(nm) );
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

UInt32 darwin_iwi3945::outputPacket(mbuf_t m, void * param)
{
	IOLog("outputPacket\n");
	if((fNetif->getFlags() & IFF_RUNNING)!=0 || m==NULL)
	{
		if (m)
		if (!(mbuf_type(m) == MBUF_TYPE_FREE) ) freePacket(m);
		m=NULL;
		netStats->outputErrors++;
		return kIOReturnOutputDropped;
	}
	
	
	mbuf_t nm;
	int ret = kIOReturnOutputDropped;

	//checking supported packet
	
	IWI_DEBUG("outputPacket t: %d f:%04x\n",mbuf_type(m),mbuf_flags(m));
	
	//drop mbuf is not PKTHDR
	if (!(mbuf_flags(m) & MBUF_PKTHDR) ){
		IWI_ERR("BUG: dont support mbuf without pkthdr and dropped \n");
		netStats->outputErrors++;
		goto finish;
	}
	
	if(mbuf_type(m) == MBUF_TYPE_FREE){
		IWI_ERR("BUG: this is freed packet and dropped \n");
		netStats->outputErrors++;
		goto finish;
	}
	
	nm = mergePacket(m);
	
	if (nm==NULL) 
	{
		netStats->outputErrors++;
		goto finish;
	}
	
	if(mbuf_next(nm)){
		IWI_ERR("BUG: dont support chains mbuf\n");
		IWI_ERR("BUG: tx packet is not single mbuf mbuf_len(%d) mbuf_pkthdr_len(%d)\n",mbuf_len(nm) , mbuf_pkthdr_len(nm) );
		IWI_ERR("BUG: next mbuf size %d\n",mbuf_len(mbuf_next(nm)));
	}
	
	IWI_DEBUG_FULL("call ieee80211_xmit - not done yet\n");
	//ret  = ieee80211_xmit(nm,priv->net_dev);
	//struct ieee80211_tx_control ctrl;
	//ret=ipw_tx_skb(priv, nm, &ctrl);

finish:	
	
	/* free finished packet */
	//freePacket(m);
	//m=NULL;
	if (ret ==  kIOReturnOutputDropped) { 
		//if (nm)
		//if (!(mbuf_type(nm) == MBUF_TYPE_FREE) ) freePacket(nm);
		//nm=NULL;
	}
	return ret;	
}

void darwin_iwi3945::interruptOccurred(OSObject * owner, 
	//IOInterruptEventSource * src, int /*count*/) 
	void		*src,  IOService *nub, int source)
{
	darwin_iwi3945 *self = OSDynamicCast(darwin_iwi3945, owner); //(darwin_iwi3945 *)owner;
	self->iwl_irq_tasklet(self->priv);
}

IOReturn darwin_iwi3945::getHardwareAddress( IOEthernetAddress * addr )
{
	UInt16 val;
	if (fEnetAddr.bytes[0]==0 && fEnetAddr.bytes[1]==0 && fEnetAddr.bytes[2]==0
	&& fEnetAddr.bytes[3]==0 && fEnetAddr.bytes[4]==0 && fEnetAddr.bytes[5]==0)
	{
		//00:0e:35:e0:3d:b3
		/*fEnetAddr.bytes[0]=0x00;
		fEnetAddr.bytes[1]=0x0e;
		fEnetAddr.bytes[2]=0x35;
		fEnetAddr.bytes[3]=0xe0;
		fEnetAddr.bytes[4]=0x3d;
		fEnetAddr.bytes[5]=0xb3;
		if (priv) memcpy(priv->eeprom.mac_address, fEnetAddr.bytes, ETH_ALEN);*/
		if (priv) memcpy(fEnetAddr.bytes, priv->eeprom.mac_address, ETH_ALEN);	
		IOLog("getHardwareAddress " MAC_FMT "\n",MAC_ARG(fEnetAddr.bytes));	
	}
	memcpy(addr, &fEnetAddr, sizeof(*addr));
	if (priv)
	{
		memcpy(priv->mac_addr, &fEnetAddr.bytes, ETH_ALEN);
		struct ieee80211_local* loc=hw_to_local(priv->hw);
		memcpy(loc->mdev->dev_addr, &fEnetAddr.bytes, ETH_ALEN);
		//IOLog("getHardwareAddress " MAC_FMT "\n",MAC_ARG(priv->mac_addr));
	}
	
	return kIOReturnSuccess;
}

IOBufferMemoryDescriptor* MemoryDmaAlloc(UInt32 buf_size, dma_addr_t *phys_add, void *virt_add)
{
	IOBufferMemoryDescriptor *memBuffer;
	void *virt_address;
	dma_addr_t phys_address;
	IOMemoryMap *memMap;
	
	memBuffer = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
						kIODirectionOutIn | kIOMemoryPhysicallyContiguous | \
						kIOMemoryAutoPrepare | kIOMapInhibitCache, buf_size, \
						PAGE_SIZE);

	if (memBuffer == NULL) {
		IOLog("Memory Allocation failed - RLC");

		return NULL;
	}

	memMap = memBuffer->map();

	if (memMap == NULL) {
		IOLog("mapping failed\n");
		memBuffer->release();
		memBuffer = NULL;
		
		return NULL;	
	}

	phys_address = memMap->getPhysicalAddress();

	virt_address = (void *)memMap->getVirtualAddress();

	if (virt_address == NULL || phys_address == NULL) {
		memMap->release();
		memBuffer->release();
		memBuffer = NULL;
		
		return NULL;
	}

	*phys_add = phys_address;
	*(IOVirtualAddress*)virt_add = (IOVirtualAddress)virt_address;
	memMap->release();

	return memBuffer;
}

bool darwin_iwi3945::configureInterface(IONetworkInterface * netif)
 {
    IONetworkData * data;
    IWI_DEBUG("configureInterface\n");
    if (super::configureInterface(netif) == false)
            return false;
    
    // Get the generic network statistics structure.
   data = netif->getParameter(kIONetworkStatsKey);
    if (!data || !(netStats = (IONetworkStats *)data->getBuffer())) {
            return false;
    }

    // Get the Ethernet statistics structure.

    data = netif->getParameter(kIOEthernetStatsKey);
    if (!data || !(etherStats = (IOEthernetStats *)data->getBuffer())) {
            return false;
    }
	
    return true;

}

void darwin_iwi3945::queue_te(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, bool start)
{
	if (tlink[num]) queue_td(num,NULL);
	//IWI_DEBUG("queue_te0 %d\n",tlink[num]);
	if (!tlink[num]) tlink[num]=thread_call_allocate(func,this);
	//IWI_DEBUG("queue_te1 %d\n",tlink[num]);
	uint64_t timei2;
	if (timei) clock_interval_to_deadline(timei,kMillisecondScale,&timei2);
	//IWI_DEBUG("queue_te time %d %d\n",timei,timei2);
	int r;
	if (start==true && tlink[num])
	{
		if (!par && !timei)	r=thread_call_enter(tlink[num]);
		if (!par && timei)	r=thread_call_enter_delayed(tlink[num],timei2);
		if (par && !timei)	r=thread_call_enter1(tlink[num],par);
		if (par && timei)	r=thread_call_enter1_delayed(tlink[num],par,timei2);
	}
	//IWI_DEBUG("queue_te result %d\n",r);
}

void darwin_iwi3945::queue_td(int num , thread_call_func_t func)
{
	//IWI_DEBUG("queue_td0 %d\n",tlink[num]);
	//IWI_DEBUG("queue_td0 %d\n",tlink[num]);
	if (tlink[num])
	{
		thread_call_cancel(tlink[num]);
		/*if (thread_call_cancel(tlink[num])==0)
			thread_call_free(tlink[num]);
		tlink[num]=NULL;*/
	}
	//IWI_DEBUG("queue_td1-%d , %d %d\n",num,r,r1);
}

int ConnectClient(kern_ctl_ref kctlref,struct sockaddr_ctl *sac,void **unitinfo)
{
	IWI_LOG("connect\n");
	clone->userInterfaceLink=1;
	return(0);
}

int disconnectClient(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo)
{
	clone->userInterfaceLink=0;
	IWI_LOG("disconnect\n");
	return(0);
}

int configureConnection(kern_ctl_ref ctlref, u_int unit, void *userdata, int opt, void *data, size_t len)
{
	/*
	//int i=*((int*)data);
	if (opt==4)// mode
	{
		int m=*((int*)data);
		m=m-1;
		IWI_LOG("setting mode to %d\n",m);
		if (clone->priv->config & CFG_NO_LED) clone->led=0; else clone->led=1;
		clone->associate=0;
		clone->mode=m;
		clone->ipw_sw_reset(0);
		clone->queue_te(12,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::ipw_down),clone->priv,NULL,true);
	}
	if (opt==3)// led
	{

	}
	if (opt==2) //associate network.
	{

	}
	if (opt==1) //HACK: start/stop the nic
	{
		u32 rfkill,r1, rfkill2=0;
		//clone->ipw_grab_restricted_access(clone->priv);
		rfkill = clone->_ipw_read_restricted_reg(clone->priv, ALM_APMG_RFKILL);
		//clone->_ipw_release_restricted_access(clone->priv);
		if (!(clone->ipw_read32(CSR_GP_CNTRL) & CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW)) rfkill2 = 1;
		IOLog("RFKILL base status: 0x%x rfkill2 0x%x\n", rfkill, rfkill2);

		if (clone->priv->status & (STATUS_RF_KILL_SW | STATUS_RF_KILL_HW)) // off -> on
		{
			clone->priv->config &= ~CFG_ASSOCIATE;
			IOLog("Trying to turn card on...\n");	
			clone->queue_te(3,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::ipw_rf_kill),clone->priv,NULL,true);
			clone->priv->status &= ~STATUS_RF_KILL_HW;
			clone->priv->status &= ~STATUS_RF_KILL_SW;
			clone->priv->status &= ~(STATUS_AUTH);
			//clone->ipw_grab_restricted_access(clone->priv);
			rfkill = clone->_ipw_read_restricted_reg(clone->priv, ALM_APMG_RFKILL);
			//clone->_ipw_release_restricted_access(clone->priv);
			rfkill2=0;
			if (!(clone->ipw_read32(CSR_GP_CNTRL) & CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW)) rfkill2 = 1;
			IWI_LOG("radio on rfkill 0x%x rfkill2 0x%x\n", rfkill, rfkill2);
		}
		else
		{
			IOLog("Trying to turn card off...\n");
			//clone->ipw_grab_restricted_access(clone->priv);
			rfkill = clone->_ipw_read_restricted_reg(clone->priv, ALM_APMG_RFKILL);
			//clone->_ipw_release_restricted_access(clone->priv);
			rfkill2=0;
			//if (!(clone->ipw_read32(CSR_GP_CNTRL) & CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW)) rfkill2 = 1;
			IWI_LOG("radio off rfkill 0x%x rfkill2 0x%x\n", rfkill, rfkill2);
			clone->setLinkStatus(kIONetworkLinkValid);
			//clone->queue_te(12,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::ipw_down),clone->priv,NULL,true);
			clone->priv->status |= STATUS_RF_KILL_HW;
			clone->priv->status |= STATUS_RF_KILL_SW;
			clone->priv->status &= ~(STATUS_AUTH);
			//clone->queue_te(3,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::ipw_rf_kill),clone->priv,NULL,true);
		}	
	}

	return(0);*/
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


int ieee80211_rate_control_register(struct rate_control_ops *ops)
{
	struct rate_control_alg *alg;

	(void*)alg = IOMalloc(sizeof(*alg));
	if (alg == NULL) {
		return -ENOMEM;
	}
	memset(alg, 0, sizeof(*alg));
	alg->ops = ops;

	//mutex_lock(&rate_ctrl_mutex);
	list_add_tail(&alg->list, &rate_ctrl_algs);
	//mutex_unlock(&rate_ctrl_mutex);

	return 0;
}
void ieee80211_rate_control_unregister(struct rate_control_ops *ops)
{
	struct rate_control_alg *alg;

	//mutex_lock(&rate_ctrl_mutex);
	list_for_each_entry(alg, &rate_ctrl_algs, list) {
		if (alg->ops == ops) {
			list_del(&alg->list);
			break;
		}
	}
	//mutex_unlock(&rate_ctrl_mutex);
	IOFree(alg, sizeof(struct rate_control_alg));
}

void ieee80211_sta_tx(struct net_device *dev, mbuf_t skb, int encrypt)
{
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_tx_packet_data *pkt_data;
	//sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	(void*)sdata = netdev_priv(dev);
	//skb->dev = sdata->local->mdev;
	//skb_set_mac_header(skb, 0);
	//skb_set_network_header(skb, 0);
	//skb_set_transport_header(skb, 0);

	pkt_data = (struct ieee80211_tx_packet_data *) mbuf_data(skb);//->cb;
	memset(pkt_data, 0, sizeof(struct ieee80211_tx_packet_data));
	pkt_data->ifindex = sdata->dev->ifindex;
	pkt_data->mgmt_iface = (sdata->type == IEEE80211_IF_TYPE_MGMT);
	pkt_data->do_not_encrypt = !encrypt;

	//dev_queue_xmit(skb);
	clone->outputPacket(skb,0);
}
