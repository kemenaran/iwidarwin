/*ipw3945: priv->ucode_raw->size: 111572
ipw3945: ucode->boot_size: 900
ipw3945: ucode->inst_size: 77888
ipw3945: ucode->data_size: 32768
ipw3945: sizeof(*ucode):  16
*/
#include "firmware/ipw3945.ucode.h"
#include "defines.h"

UInt32 iwl3945_debug_level = 0;

#define DLOG(fmt, args...)  IOLog(fmt, ## args)

#define DRIVER_DEV_NAME "iwi3945"

// Define my superclass
#define super IO80211Controller
// REQUIRED! This macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires. Do NOT use super as the
// second parameter. You must use the literal name of the superclass.
OSDefineMetaClassAndStructors(darwin_iwi3945, IO80211Controller);





/*
 * Power management (not Tx power!) functions
 */
#define MSEC_TO_USEC 1024

#define NOSLP __constant_cpu_to_le32(0)
#define SLP IWL_POWER_DRIVER_ALLOW_SLEEP_MSK
#define SLP_TIMEOUT(T) __constant_cpu_to_le32((T) * MSEC_TO_USEC)
#define SLP_VEC(X0, X1, X2, X3, X4) {__constant_cpu_to_le32(X0), \
__constant_cpu_to_le32(X1), \
__constant_cpu_to_le32(X2), \
__constant_cpu_to_le32(X3), \
__constant_cpu_to_le32(X4)}




/* default power management (not Tx power) table values */
/* for tim  0-10 */
static struct iwl3945_power_vec_entry range_0[IWL_POWER_AC] = {
	{{NOSLP, SLP_TIMEOUT(0), SLP_TIMEOUT(0), SLP_VEC(0, 0, 0, 0, 0)}, 0},
	{{SLP, SLP_TIMEOUT(200), SLP_TIMEOUT(500), SLP_VEC(1, 2, 3, 4, 4)}, 0},
	{{SLP, SLP_TIMEOUT(200), SLP_TIMEOUT(300), SLP_VEC(2, 4, 6, 7, 7)}, 0},
	{{SLP, SLP_TIMEOUT(50), SLP_TIMEOUT(100), SLP_VEC(2, 6, 9, 9, 10)}, 0},
	{{SLP, SLP_TIMEOUT(50), SLP_TIMEOUT(25), SLP_VEC(2, 7, 9, 9, 10)}, 1},
	{{SLP, SLP_TIMEOUT(25), SLP_TIMEOUT(25), SLP_VEC(4, 7, 10, 10, 10)}, 1}
};

/* for tim > 10 */
static struct iwl3945_power_vec_entry range_1[IWL_POWER_AC] = {
	{{NOSLP, SLP_TIMEOUT(0), SLP_TIMEOUT(0), SLP_VEC(0, 0, 0, 0, 0)}, 0},
	{{SLP, SLP_TIMEOUT(200), SLP_TIMEOUT(500),
    SLP_VEC(1, 2, 3, 4, 0xFF)}, 0},
	{{SLP, SLP_TIMEOUT(200), SLP_TIMEOUT(300),
    SLP_VEC(2, 4, 6, 7, 0xFF)}, 0},
	{{SLP, SLP_TIMEOUT(50), SLP_TIMEOUT(100),
    SLP_VEC(2, 6, 9, 9, 0xFF)}, 0},
	{{SLP, SLP_TIMEOUT(50), SLP_TIMEOUT(25), SLP_VEC(2, 7, 9, 9, 0xFF)}, 0},
	{{SLP, SLP_TIMEOUT(25), SLP_TIMEOUT(25),
    SLP_VEC(4, 7, 10, 10, 0xFF)}, 0}
};



/*
 #define IWL_DECLARE_RATE_INFO(r, ip, in, rp, rn, pp, np)    \
[IWL_RATE_##r##M_INDEX] = { IWL_RATE_##r##M_PLCP,   \
IWL_RATE_##r##M_IEEE,   \
IWL_RATE_##ip##M_INDEX, \
IWL_RATE_##in##M_INDEX, \
IWL_RATE_##rp##M_INDEX, \
IWL_RATE_##rn##M_INDEX, \
IWL_RATE_##pp##M_INDEX, \
IWL_RATE_##np##M_INDEX, \
IWL_RATE_##r##M_INDEX_TABLE, \
IWL_RATE_##ip##M_INDEX_TABLE }
*/

#define IWL_DECLARE_RATE_INFO(r, ip, in, rp, rn, pp, np)    \
{ IWL_RATE_##r##M_PLCP,   \
IWL_RATE_##r##M_IEEE,   \
IWL_RATE_##ip##M_INDEX, \
IWL_RATE_##in##M_INDEX, \
IWL_RATE_##rp##M_INDEX, \
IWL_RATE_##rn##M_INDEX, \
IWL_RATE_##pp##M_INDEX, \
IWL_RATE_##np##M_INDEX }

/*
 * Parameter order:
 *   rate, prev rate, next rate, prev tgg rate, next tgg rate
 *
 * If there isn't a valid next or previous rate then INV is used which
 * maps to IWL_RATE_INVALID
 *
 */
const struct iwl3945_rate_info iwl3945_rates[IWL_RATE_COUNT] = {
	IWL_DECLARE_RATE_INFO(1, INV, 2, INV, 2, INV, 2),    /*  1mbps */
	IWL_DECLARE_RATE_INFO(2, 1, 5, 1, 5, 1, 5),          /*  2mbps */
	IWL_DECLARE_RATE_INFO(5, 2, 6, 2, 11, 2, 11),        /*5.5mbps */
	IWL_DECLARE_RATE_INFO(11, 9, 12, 5, 12, 5, 18),      /* 11mbps */
	IWL_DECLARE_RATE_INFO(6, 5, 9, 5, 11, 5, 11),        /*  6mbps */
	IWL_DECLARE_RATE_INFO(9, 6, 11, 5, 11, 5, 11),       /*  9mbps */
	IWL_DECLARE_RATE_INFO(12, 11, 18, 11, 18, 11, 18),   /* 12mbps */
	IWL_DECLARE_RATE_INFO(18, 12, 24, 12, 24, 11, 24),   /* 18mbps */
	IWL_DECLARE_RATE_INFO(24, 18, 36, 18, 36, 18, 36),   /* 24mbps */
	IWL_DECLARE_RATE_INFO(36, 24, 48, 24, 48, 24, 48),   /* 36mbps */
	IWL_DECLARE_RATE_INFO(48, 36, 54, 36, 54, 36, 54),   /* 48mbps */
	IWL_DECLARE_RATE_INFO(54, 48, INV, 48, INV, 48, INV),/* 54mbps */
};








#pragma mark -
#pragma mark IONetworkController overrides

IOOutputQueue * darwin_iwi3945::createOutputQueue( void )
{
	// An IOGatedOutputQueue will serialize all calls to the driver's
    // outputPacket() function with its work loop. This essentially
    // serializes all access to the driver and the hardware through
    // the driver's work loop, which simplifies the driver but also
    // carries a small performance cost (relatively for 10/100 Mb).
    IOLog("Someone called createOutputQueue()\n");
    return IOGatedOutputQueue::withTarget( this, getWorkLoop() );
}


bool darwin_iwi3945::createWorkLoop( void )
{
    IOLog("Creating workloop...\n");
    workqueue = IOWorkLoop::workLoop();
	if(workqueue)
        IOLog("Workloop creation successful!\n");
    else
        IOLog("FAILED!  Couldn't create workloop\n");
    if( workqueue )
        workqueue->init();
    return ( workqueue != 0 );
}

int darwin_iwi3945::outputRaw80211Packet( IO80211Interface * interface, mbuf_t m ) {
    IOLog("Someone called outputRaw80211Packet\n");
    int ret = super::outputRaw80211Packet(interface, m);
    IOLog("outputRaw80211Packet: Okay, returning %d\n", ret);
    return ret;
}
    
UInt32 darwin_iwi3945::getFeatures() const {
    return kIONetworkFeatureSoftwareVlan;
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
            IOLog("APPLE80211_IOC_CARD_CAPABILITIES:"
                    " 0x%08x [%d]\n", data, data);
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
                apple80211_state_data *state = (apple80211_state_data *)data;
                state->version = APPLE80211_VERSION;
                state->state = 0x04;
                ret = kIOReturnSuccess;
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
                IOLog("Don't know how to GET auth type\n");
            }
            else {
                ret = setAUTH_TYPE(intf, (apple80211_authtype_data *)data);
            }
            break;
            
            
            //6:
        case APPLE80211_IOC_PROTMODE:
            if( SIOCGA80211 == req ) {
                IOLog("Don't know how to GET protmode\n");
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



IOWorkLoop * darwin_iwi3945::getWorkLoop( void ) const
{
    // Override IOService::getWorkLoop() method to return the work loop
    // we allocated in createWorkLoop().
//    IOLog("Someone wanted to get the workloop.  Returning workqueue\n");
	return workqueue;
}



void darwin_iwi3945::interruptOccurred(OSObject * owner, 
                                       void		*src,  IOService *nub, int source)
{
	darwin_iwi3945 *self = OSDynamicCast(darwin_iwi3945, owner); //(darwin_iwi3945 *)owner;
	self->handleInterrupt();
}


UInt32 darwin_iwi3945::handleInterrupt(void)
{
    u32 inta, handled = 0;
	u32 inta_fh;
	unsigned long flags;
//#ifdef CONFIG_IWL3945_DEBUG
	u32 inta_mask;
//#endif
    
	//lck_spin_lock(slock);
	/* Ack/clear/reset pending uCode interrupts.
	 * Note:  Some bits in CSR_INT are "OR" of bits in CSR_FH_INT_STATUS,
	 *  and will clear only when CSR_FH_INT_STATUS gets cleared. */
	inta = read32(CSR_INT);
	write32(CSR_INT, inta);
    
	/* Ack/clear/reset pending flow-handler (DMA) interrupts.
	 * Any new interrupts that happen after this, either while we're
	 * in this tasklet, or later, will show up in next ISR/tasklet. */
	inta_fh = read32(CSR_FH_INT_STATUS);
	write32(CSR_FH_INT_STATUS, inta_fh);
    
//#ifdef CONFIG_IWL3945_DEBUG
	if (iwl3945_debug_level & IWL_DL_ISR) {
		/* just for debug */
		inta_mask = read32(CSR_INT_MASK);
		IWL_DEBUG_ISR("inta 0x%08x, enabled 0x%08x, fh 0x%08x\n",
                      inta, inta_mask, inta_fh);
	}
//#endif
    
	/* Since CSR_INT and CSR_FH_INT_STATUS reads and clears are not
	 * atomic, make sure that inta covers all the interrupts that
	 * we've discovered, even if FH interrupt came in just after
	 * reading CSR_INT. */
	if (inta_fh & CSR_FH_INT_RX_MASK)
		inta |= CSR_INT_BIT_FH_RX;
	if (inta_fh & CSR_FH_INT_TX_MASK)
		inta |= CSR_INT_BIT_FH_TX;
    
	/* Now service all interrupt bits discovered above. */
	if (inta & CSR_INT_BIT_HW_ERR) {
		IWL_ERROR("Microcode HW error detected.  Restarting.\n");
        
		/* Tell the device to stop sending interrupts */
		disable_interrupts();
        
		irq_handle_error();
        
		handled |= CSR_INT_BIT_HW_ERR;
        
		//lck_spin_unlock(slock);
        
		return true;
	}
    
//#ifdef CONFIG_IWL3945_DEBUG
	if (iwl3945_debug_level & (IWL_DL_ISR)) {
		/* NIC fires this, but we don't use it, redundant with WAKEUP */
		if (inta & CSR_INT_BIT_MAC_CLK_ACTV)
			IWL_DEBUG_ISR("Microcode started or stopped.\n");
        
		/* Alive notification via Rx interrupt will do the real work */
		if (inta & CSR_INT_BIT_ALIVE)
			IWL_DEBUG_ISR("Alive interrupt\n");
	}
//#endif
	/* Safely ignore these bits for debug checks below */
	inta &= ~(CSR_INT_BIT_MAC_CLK_ACTV | CSR_INT_BIT_ALIVE);
    
	/* HW RF KILL switch toggled (4965 only) */
	if (inta & CSR_INT_BIT_RF_KILL) {
		int hw_rf_kill = 0;
		if (!(read32(CSR_GP_CNTRL) &
              CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW))
			hw_rf_kill = 1;
        
		IWL_DEBUG(IWL_DL_INFO | IWL_DL_RF_KILL | IWL_DL_ISR, 
                  "RF_KILL bit toggled to %s.\n",
                  hw_rf_kill ? "disable radio":"enable radio");
        
		/* Queue restart only if RF_KILL switch was set to "kill"
		 *   when we loaded driver, and is now set to "enable".
		 * After we're Alive, RF_KILL gets handled by
		 *   iwl3945_rx_card_state_notif() */
		if (!hw_rf_kill && !isset(&status, STATUS_ALIVE)) {
			setbit(&status, STATUS_RF_KILL_HW);

            IOLog("Queueing bg_restart because of kill\n");
#warning Is this the correct way to adapt it?
            workqueue->runAction(OSMemberFunctionCast(IOWorkLoop::Action, this,
                                                      &darwin_iwi3945::bg_restart), (OSObject *)this, 0, 0, 0, 0);
		}
        
		handled |= CSR_INT_BIT_RF_KILL;
	}
    
	/* Chip got too hot and stopped itself (4965 only) */
	if (inta & CSR_INT_BIT_CT_KILL) {
		IWL_ERROR("Microcode CT kill error detected.\n");
		handled |= CSR_INT_BIT_CT_KILL;
	}
    
	/* Error detected by uCode */
	if (inta & CSR_INT_BIT_SW_ERR) {
		IWL_ERROR("Microcode SW error detected.  Restarting 0x%X.\n",
                  inta);
		irq_handle_error();
		handled |= CSR_INT_BIT_SW_ERR;
	}
    
	/* uCode wakes up after power-down sleep */
	if (inta & CSR_INT_BIT_WAKEUP) {
		IWL_DEBUG_ISR("Wakeup interrupt\n");
		rx_queue_update_write_ptr(&rxq);
		tx_queue_update_write_ptr(&txq[0]);
		tx_queue_update_write_ptr(&txq[1]);
		tx_queue_update_write_ptr(&txq[2]);
		tx_queue_update_write_ptr(&txq[3]);
		tx_queue_update_write_ptr(&txq[4]);
		tx_queue_update_write_ptr(&txq[5]);
        
		handled |= CSR_INT_BIT_WAKEUP;
	}
    
	/* All uCode command responses, including Tx command responses,
	 * Rx "responses" (frame-received notification), and other
	 * notifications from uCode come through here*/
	if (inta & (CSR_INT_BIT_FH_RX | CSR_INT_BIT_SW_RX)) {
		rx_handle();
		handled |= (CSR_INT_BIT_FH_RX | CSR_INT_BIT_SW_RX);
	}
    
	if (inta & CSR_INT_BIT_FH_TX) {
		IWL_DEBUG_ISR("Tx interrupt\n");
        
		write32(CSR_FH_INT_STATUS, (1 << 6));
		if (!grab_nic_access()) {
			write_direct32(FH_TCSR_CREDIT  (ALM_FH_SRVC_CHNL), 0x0);
			release_nic_access();
		}
		handled |= CSR_INT_BIT_FH_TX;
	}
    
	if (inta & ~handled)
		IWL_ERROR("Unhandled INTA bits 0x%08x\n", inta & ~handled);
    
	if (inta & ~CSR_INI_SET_MASK) {
		IWL_WARNING("Disabled INTA bits 0x%08x were pending\n",
                    inta & ~CSR_INI_SET_MASK);
		IWL_WARNING("   with FH_INT = 0x%08x\n", inta_fh);
	}
    
	/* Re-enable all interrupts */
	enable_interrupts();
    
//#ifdef CONFIG_IWL3945_DEBUG
//	if (iwl3945_debug_level & (IWL_DL_ISR)) {
		inta = read32(CSR_INT);
		inta_mask = read32(CSR_INT_MASK);
		inta_fh = read32(CSR_FH_INT_STATUS);
		IWL_DEBUG_ISR("End inta 0x%08x, enabled 0x%08x, fh 0x%08x, "
                      "flags 0x%08lx\n", inta, inta_mask, inta_fh, flags);
//	}
//#endif
	//lck_spin_unlock(slock);
}

#pragma mark -
#pragma mark Driver status functions

inline int darwin_iwi3945::is_ready()
{
	/* The adapter is 'ready' if READY and GEO_CONFIGURED bits are
	 * set but EXIT_PENDING is not */
	return isset(&status, STATUS_READY) &&
    isset(&status, STATUS_GEO_CONFIGURED) &&
    !isset(&status, STATUS_EXIT_PENDING);
}

inline int darwin_iwi3945::is_alive()
{
	return isset(&status, STATUS_ALIVE);
}

inline int darwin_iwi3945::is_init()
{
	return isset(&status, STATUS_INIT);
}

inline int darwin_iwi3945::is_rfkill()
{
	return isset(&status, STATUS_RF_KILL_HW) ||
           isset(&status, STATUS_RF_KILL_SW);
}


inline int darwin_iwi3945::is_ready_rf()
{
    
	if (is_rfkill())
		return 0;
    
	return is_ready();
}



#pragma mark -
#pragma mark Driver callbacks

#define IWL_DELAY_NEXT_SCAN (HZ*2)

int darwin_iwi3945::mac_hw_scan(u8 *ssid, size_t len)
{
	int rc = 0;
	unsigned long flags;
    
	IWL_DEBUG_MAC80211("enter\n");
    
	//mutex_lock(&mutex);
	//spin_lock_irqsave(&lock, flags);
    
	if (!is_ready_rf()) {
		rc = -EIO;
		IWL_DEBUG_MAC80211("leave - not ready or exit pending\n");
		goto out_unlock;
	}
    
	if (iw_mode == IEEE80211_IF_TYPE_AP) {	/* APs don't scan */
		rc = -EIO;
		IWL_ERROR("ERROR: APs don't scan\n");
		goto out_unlock;
	}
    
	/* we don't schedule scan within next_scan_jiffies period */
    /*
	if (next_scan_jiffies &&
        time_after(next_scan_jiffies, jiffies)) {
		rc = -EAGAIN;
		goto out_unlock;
	}*/
	/* if we just finished scan ask for delay */
    /*
	if (last_scan_jiffies && time_after(last_scan_jiffies +
                                              IWL_DELAY_NEXT_SCAN, jiffies)) {
		rc = -EAGAIN;
		goto out_unlock;
	}
     */
	if (len) {
		IWL_DEBUG_SCAN("direct scan for %s [%d]\n ",
                       escape_essid(ssid, len), (int)len);
        
		one_direct_scan = 1;
		direct_ssid_len = (u8)
        min((u8) len, (u8) IW_ESSID_MAX_SIZE);
		memcpy(direct_ssid, ssid, direct_ssid_len);
	} else
		one_direct_scan = 0;
    
	rc = scan_initiate();
    
	IWL_DEBUG_MAC80211("leave\n");
    
out_unlock:
	//spin_unlock_irqrestore(&priv->lock, flags);
	//mutex_unlock(&priv->mutex);
    
	return rc;
}


const struct ieee80211_hw_mode *darwin_iwi3945::get_hw_mode(int mode)
{
	int i;
    
	for (i = 0; i < 3; i++)
		if (modes[i].mode == mode)
			return &modes[i];
    
	return NULL;
}

/* For active scan, listen ACTIVE_DWELL_TIME (msec) on each channel after
 * sending probe req.  This should be set long enough to hear probe responses
 * from more than one AP.  */
#define IWL_ACTIVE_DWELL_TIME_24    (20)	/* all times in msec */
#define IWL_ACTIVE_DWELL_TIME_52    (10)

/* For faster active scanning, scan will move to the next channel if fewer than
 * PLCP_QUIET_THRESH packets are heard on this channel within
 * ACTIVE_QUIET_TIME after sending probe request.  This shortens the dwell
 * time if it's a quiet channel (nothing responded to our probe, and there's
 * no other traffic).
 * Disable "quiet" feature by setting PLCP_QUIET_THRESH to 0. */
#define IWL_PLCP_QUIET_THRESH       __constant_cpu_to_le16(1)	/* packets */
#define IWL_ACTIVE_QUIET_TIME       __constant_cpu_to_le16(5)	/* msec */

/* For passive scan, listen PASSIVE_DWELL_TIME (msec) on each channel.
 * Must be set longer than active dwell time.
 * For the most reliable scan, set > AP beacon interval (typically 100msec). */
#define IWL_PASSIVE_DWELL_TIME_24   (20)	/* all times in msec */
#define IWL_PASSIVE_DWELL_TIME_52   (10)
#define IWL_PASSIVE_DWELL_BASE      (100)
#define IWL_CHANNEL_TUNE_TIME       5


inline u16 darwin_iwi3945::get_active_dwell_time(int phymode)
{
	if (phymode == MODE_IEEE80211A)
		return IWL_ACTIVE_DWELL_TIME_52;
	else
		return IWL_ACTIVE_DWELL_TIME_24;
}

u16 darwin_iwi3945::get_passive_dwell_time(int phymode)
{
	u16 active = get_active_dwell_time(phymode);
	u16 passive = (phymode != MODE_IEEE80211A) ?
    IWL_PASSIVE_DWELL_BASE + IWL_PASSIVE_DWELL_TIME_24 :
    IWL_PASSIVE_DWELL_BASE + IWL_PASSIVE_DWELL_TIME_52;
    
	if (is_associated()) {
		/* If we're associated, we clamp the maximum passive
		 * dwell time to be 98% of the beacon interval (minus
		 * 2 * channel tune time) */
		passive = beacon_int;
		if ((passive > IWL_PASSIVE_DWELL_BASE) || !passive)
			passive = IWL_PASSIVE_DWELL_BASE;
		passive = (passive * 98) / 100 - IWL_CHANNEL_TUNE_TIME * 2;
	}
    
	if (passive <= active)
		passive = active + 1;
    
	return passive;
}



int darwin_iwi3945::get_channels_for_scan(int phymode,
                                         u8 is_active, u8 direct_mask,
                                         struct iwl3945_scan_channel *scan_ch)
{
	const struct ieee80211_channel *channels = NULL;
	const struct ieee80211_hw_mode *hw_mode;
	const struct iwl3945_channel_info *ch_info;
	u16 passive_dwell = 0;
	u16 active_dwell = 0;
	int added, i;
    
	hw_mode = get_hw_mode(phymode);
	if (!hw_mode)
		return 0;
    
	channels = hw_mode->channels;
    
	active_dwell = get_active_dwell_time(phymode);
	passive_dwell = get_passive_dwell_time(phymode);
    
	for (i = 0, added = 0; i < hw_mode->num_channels; i++) {
		if (channels[i].chan ==
		    le16_to_cpu(active_rxon.channel)) {
			if (is_associated()) {
				IWL_DEBUG_SCAN
                ("Skipping current channel %d\n",
                 le16_to_cpu(active_rxon.channel));
				continue;
			}
		} else if (only_active_channel)
			continue;
        
		scan_ch->channel = channels[i].chan;
        
		ch_info = get_channel_info(phymode, scan_ch->channel);
		if (!is_channel_valid(ch_info)) {
			IWL_DEBUG_SCAN("Channel %d is INVALID for this SKU.\n",
                           scan_ch->channel);
			continue;
		}
        
		if (!is_active || is_channel_passive(ch_info) ||
		    !(channels[i].flag & IEEE80211_CHAN_W_ACTIVE_SCAN))
			scan_ch->type = 0;	/* passive */
		else
			scan_ch->type = 1;	/* active */
        
		if (scan_ch->type & 1)
			scan_ch->type |= (direct_mask << 1);
        
		if (is_channel_narrow(ch_info))
			scan_ch->type |= (1 << 7);
        
		scan_ch->active_dwell = cpu_to_le16(active_dwell);
		scan_ch->passive_dwell = cpu_to_le16(passive_dwell);
        
		/* Set txpower levels to defaults */
		scan_ch->tpc.dsp_atten = 110;
		/* scan_pwr_info->tpc.dsp_atten; */
        
		/*scan_pwr_info->tpc.tx_gain; */
		if (phymode == MODE_IEEE80211A)
			scan_ch->tpc.tx_gain = ((1 << 5) | (3 << 3)) | 3;
		else {
			scan_ch->tpc.tx_gain = ((1 << 5) | (5 << 3));
			/* NOTE: if we were doing 6Mb OFDM for scans we'd use
			 * power level:
			 * scan_ch->tpc.tx_gain = ((1<<5) | (2 << 3)) | 3;
			 */
		}
        
		IWL_DEBUG_SCAN("Scanning %d [%s %d]\n",
                       scan_ch->channel,
                       (scan_ch->type & 1) ? "ACTIVE" : "PASSIVE",
                       (scan_ch->type & 1) ?
                       active_dwell : passive_dwell);
        
		scan_ch++;
		added++;
	}
    
	IWL_DEBUG_SCAN("total channels to scan %d \n", added);
	return added;
}




#pragma mark -
#pragma mark Useful routines


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
        if (!par && !timei) r=thread_call_enter(tlink[num]);
        if (!par && timei)  r=thread_call_enter_delayed(tlink[num],timei2);
        if (par && !timei)  r=thread_call_enter1(tlink[num],par);
        if (par && timei)   r=thread_call_enter1_delayed(tlink[num],par,timei2);
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



void darwin_iwi3945::postMessage(UInt32 message) {
    if( fNetif )
        fNetif->postMessage(message, NULL, 0);
}


#define IPW_CMD(x) case IPW_CMD_ ## x : return #x
static char *get_cmd_string(u8 cmd)
{
    switch (cmd) {
            IPW_CMD(HOST_COMPLETE);
            IPW_CMD(POWER_DOWN);
            IPW_CMD(SYSTEM_CONFIG);
            IPW_CMD(MULTICAST_ADDRESS);
            IPW_CMD(SSID);
            IPW_CMD(ADAPTER_ADDRESS);
            IPW_CMD(PORT_TYPE);
            IPW_CMD(RTS_THRESHOLD);
            IPW_CMD(FRAG_THRESHOLD);
            IPW_CMD(POWER_MODE);
            IPW_CMD(WEP_KEY);
            IPW_CMD(TGI_TX_KEY);
            IPW_CMD(SCAN_REQUEST);
            IPW_CMD(SCAN_REQUEST_EXT);
            IPW_CMD(ASSOCIATE);
            IPW_CMD(SUPPORTED_RATES);
            IPW_CMD(SCAN_ABORT);
            IPW_CMD(TX_FLUSH);
            IPW_CMD(QOS_PARAMETERS);
            IPW_CMD(DINO_CONFIG);
            IPW_CMD(RSN_CAPABILITIES);
            IPW_CMD(RX_KEY);
            IPW_CMD(CARD_DISABLE);
            IPW_CMD(SEED_NUMBER);
            IPW_CMD(TX_POWER);
            IPW_CMD(COUNTRY_INFO);
            IPW_CMD(AIRONET_INFO);
            IPW_CMD(AP_TX_POWER);
            IPW_CMD(CCKM_INFO);
            IPW_CMD(CCX_VER_INFO);
            IPW_CMD(SET_CALIBRATION);
            IPW_CMD(SENSITIVITY_CALIB);
            IPW_CMD(RETRY_LIMIT);
            IPW_CMD(IPW_PRE_POWER_DOWN);
            IPW_CMD(VAP_BEACON_TEMPLATE);
            IPW_CMD(VAP_DTIM_PERIOD);
            IPW_CMD(EXT_SUPPORTED_RATES);
            IPW_CMD(VAP_LOCAL_TX_PWR_CONSTRAINT);
            IPW_CMD(VAP_QUIET_INTERVALS);
            IPW_CMD(VAP_CHANNEL_SWITCH);
            IPW_CMD(VAP_MANDATORY_CHANNELS);
            IPW_CMD(VAP_CELL_PWR_LIMIT);
            IPW_CMD(VAP_CF_PARAM_SET);
            IPW_CMD(VAP_SET_BEACONING_STATE);
            IPW_CMD(MEASUREMENT);
            IPW_CMD(POWER_CAPABILITY);
            IPW_CMD(SUPPORTED_CHANNELS);
            IPW_CMD(TPC_REPORT);
            IPW_CMD(WME_INFO);
            IPW_CMD(PRODUCTION_COMMAND);
        default:
            return "UNKNOWN";
    }
}



void darwin_iwi3945::iwl3945_txstatus_to_ieee(struct iwl3945_tx_info *tx_sta)
{
    IOLog("Warning: Ignoring txstatus_to_ieee\n");
    /*
    tx_sta->status.ack_signal = 0;
    tx_sta->status.excessive_retries = 0;
    tx_sta->status.queue_length = 0;
    tx_sta->status.queue_number = 0;
    
    if (in_interrupt())
        ieee80211_tx_status_irqsafe(hw,
                                    tx_sta->skb[0], &(tx_sta->status));
    else
        ieee80211_tx_status(hw,
                            tx_sta->skb[0], &(tx_sta->status));
    
    tx_sta->skb[0] = NULL;
    */
}


/**
 * iwl3945_queue_init - Initialize queue's high/low-water and read/write indexes
 */
int darwin_iwi3945::queue_init(struct iwl3945_queue *q, int count, int slots_num, u32 id)
{
    q->n_bd = count;
    q->n_window = slots_num;
    q->id = id;
    
    /* count must be power-of-two size, otherwise iwl3945_queue_inc_wrap
     * and iwl3945_queue_dec_wrap are broken. */
//    BUG_ON(!is_power_of_2(count));
    
    /* slots_num must be power-of-two size, otherwise
     * get_cmd_index is broken. */
//    BUG_ON(!is_power_of_2(slots_num));
    
    q->low_mark = q->n_window / 4;
    if (q->low_mark < 4)
        q->low_mark = 4;
    
    q->high_mark = q->n_window / 8;
    if (q->high_mark < 2)
        q->high_mark = 2;
    
    q->write_ptr = q->read_ptr = 0;
    
    return 0;
}




#pragma mark -
#pragma mark Tx Queue


/**
 * iwl3945_tx_queue_reclaim - Reclaim Tx queue entries already Tx'd
 *
 * When FW advances 'R' index, all entries between old and new 'R' index
 * need to be reclaimed. As result, some free space forms. If there is
 * enough free space (> low mark), wake the stack that feeds us.
 */
int darwin_iwi3945::tx_queue_reclaim(int txq_id, int index)
{
    struct iwl3945_tx_queue *txq = &txq[txq_id];
    struct iwl3945_queue *q = &txq->q;
    int nfreed = 0;
    
    if ((index >= q->n_bd) || (x2_queue_used(q, index) == 0)) {
        IWL_ERROR("Read index for DMA queue txq id (%d), index %d, "
                  "is out of range [0-%d] %d %d.\n", txq_id,
                  index, q->n_bd, q->write_ptr, q->read_ptr);
        return 0;
    }
    
    for (index = queue_inc_wrap(index, q->n_bd);
         q->read_ptr != index;
         q->read_ptr = queue_inc_wrap(q->read_ptr, q->n_bd)) {
        /*
        if (txq_id != IWL_CMD_QUEUE_NUM) {
            txstatus_to_ieee(&(txq->txb[txq->q.read_ptr]));
            hw_txq_free_tfd(txq);
        } else if (nfreed > 1) {
            IWL_ERROR("HCMD skipped: index (%d) %d %d\n", index,
                      q->write_ptr, q->read_ptr);
//            queue_work(workqueue, &restart);
            queue_te(5,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::bg_restart),NULL,NULL,true);
        }
        */
        nfreed++;
    }
    
    /*
    if (queue_space(q) > q->low_mark && (txq_id >= 0) &&
        (txq_id != IWL_CMD_QUEUE_NUM) && mac80211_registered)
        ieee80211_wake_queue(hw, txq_id);
    
    */
    return nfreed;
}



/**
* iwl3945_tx_cmd_complete - Pull unused buffers off the queue and reclaim them
* @rxb: Rx buffer to reclaim
*
* If an Rx buffer has an async callback associated with it the callback
* will be executed.  The attached skb (if present) will only be freed
* if the callback returns 1
*/
void darwin_iwi3945::tx_cmd_complete(struct iwl3945_rx_mem_buffer *rxb)
{
    struct iwl3945_rx_packet *pkt = (struct iwl3945_rx_packet *)rxb->skb;
    u16 sequence = le16_to_cpu(pkt->hdr.sequence);
    int txq_id = SEQ_TO_QUEUE(sequence);
    int index = SEQ_TO_INDEX(sequence);
    int huge = sequence & SEQ_HUGE_FRAME;
    int cmd_index;
    struct iwl3945_cmd *cmd;
    
    /* If a Tx command is being handled and it isn't in the actual
     * command queue then there a command routing bug has been introduced
     * in the queue management code. */
    if (txq_id != IWL_CMD_QUEUE_NUM)
        IWL_ERROR("Error wrong command queue %d command id 0x%X\n",
                  txq_id, pkt->hdr.cmd);
//    BUG_ON(txq_id != IWL_CMD_QUEUE_NUM);
    
    /*
    cmd_index = get_cmd_index(&txq[IWL_CMD_QUEUE_NUM].q, index, huge);
    cmd = &txq[IWL_CMD_QUEUE_NUM].cmd[cmd_index];
    
    // Input error checking is done when commands are added to queue.
    if (cmd->meta.flags & CMD_WANT_SKB) {
        cmd->meta.source->u.skb = rxb->skb;
        rxb->skb = NULL;
    } else if (cmd->meta.u.callback &&
               !cmd->meta.u.callback(cmd, rxb->skb))
        rxb->skb = NULL;
    
    tx_queue_reclaim(txq_id, index);
    */
    
    if (!(cmd->meta.flags & CMD_ASYNC)) {
        clrbit(&status, STATUS_HCMD_ACTIVE);
        //wake_up_interruptible(&wait_command_queue);
    }
}


/**
 * iwl3945_txq_ctx_reset - Reset TX queue context
 *
 * Destroys all DMA structures and initialize them again
 */
int darwin_iwi3945::txq_ctx_reset()
{
    int rc;
    int txq_id, slots_num;
    
    hw_txq_ctx_free();
    
    /* Tx CMD queue */
    rc = tx_reset();
    if (rc)
        goto error;
    
    /* Tx queue(s) */
    for (txq_id = 0; txq_id < TFD_QUEUE_MAX; txq_id++) {
        slots_num = (txq_id == IWL_CMD_QUEUE_NUM) ?
        TFD_CMD_SLOTS : TFD_TX_CMD_SLOTS;
        rc = tx_queue_init(&txq[txq_id], slots_num, txq_id);
        if (rc) {
            IWL_ERROR("Tx %d queue init failed\n", txq_id);
            goto error;
        }
    }
    
    return rc;
    
error:
    hw_txq_ctx_free();
    return rc;
}



/**
 * iwl3945_hw_txq_ctx_free - Free TXQ Context
 *
 * Destroy all TX DMA queues and structures
 */
void darwin_iwi3945::hw_txq_ctx_free()
{
    int txq_id;
    
    /* Tx queues */
    for (txq_id = 0; txq_id < TFD_QUEUE_MAX; txq_id++)
        tx_queue_free(&txq[txq_id]);
}

/**
 * iwl3945_tx_queue_free - Deallocate DMA queue.
 * @txq: Transmit queue to deallocate.
 *
 * Empty queue by removing and destroying all BD's.
 * Free all buffers.
 * 0-fill, but do not free "txq" descriptor structure.
 */
void darwin_iwi3945::tx_queue_free(struct iwl3945_tx_queue *txq)
{
    struct iwl3945_queue *q = &txq->q;
    int len;
    
    if (q->n_bd == 0)
        return;
    
    /* first, empty all BD's */
    for (; q->write_ptr != q->read_ptr;
         q->read_ptr = queue_inc_wrap(q->read_ptr, q->n_bd))
        hw_txq_free_tfd(txq);
    
    len = sizeof(struct iwl3945_cmd) * q->n_window;
    if (q->id == IWL_CMD_QUEUE_NUM)
        len += IWL_MAX_SCAN_SIZE;
    
    /* De-alloc array of command/tx buffers */
    IOFreeContiguous(txq->cmd, len);
    
    /* De-alloc circular buffer of TFDs */
    if (txq->q.n_bd)
        IOFreeContiguous(txq->bd, sizeof(struct iwl3945_tfd_frame) *
                         txq->q.n_bd);
    
    /* De-alloc array of per-TFD driver data */
    if (txq->txb) {
        IOFree(txq->txb,sizeof(txq->txb[0]) * 64);// todo: check size
        txq->txb = NULL;
    }
    
    /* 0-fill queue descriptor structure */
    memset(txq, 0, sizeof(txq));
}



/**
 * iwl3945_hw_txq_free_tfd - Free one TFD, those at index [txq->q.read_ptr]
 *
 * Does NOT advance any indexes
 */
int darwin_iwi3945::hw_txq_free_tfd(struct iwl3945_tx_queue *txq)
{
    struct iwl3945_tfd_frame *bd_tmp = (struct iwl3945_tfd_frame *)&txq->bd[0];
    struct iwl3945_tfd_frame *bd = &bd_tmp[txq->q.read_ptr];
    int i;
    int counter;
    
    /* classify bd */
    if (txq->q.id == IWL_CMD_QUEUE_NUM)
    /* nothing to cleanup after for host commands */
        return 0;
    
    /* sanity check */
    counter = TFD_CTL_COUNT_GET(le32_to_cpu(bd->control_flags));
    if (counter > NUM_TFD_CHUNKS) {
        IWL_ERROR("Too many chunks: %i\n", counter);
        /* @todo issue fatal error, it is quite serious situation */
        return 0;
    }
    
    /* unmap chunks if any */
    
#warning Fill this in
    /*
    for (i = 1; i < counter; i++) {
//        pci_unmap_single(dev, le32_to_cpu(bd->pa[i].addr),
//                         le32_to_cpu(bd->pa[i].len), PCI_DMA_TODEVICE);
        IOMemoryDescriptor::withPhysicalAddress(bd->pa[i].addr,
                                                bd->pa[i].len[i],kIODirectionInOut)->complete(kIODirectionInOut);
        IOMemoryDescriptor::withPhysicalAddress(bd->pa[i].addr[i],
                                                bd->pa[i].len[i],kIODirectionInOut)->release();
        
        if (txq->txb[txq->q.read_ptr].skb) {
            mbuf_t skb = txq->txb[txq->q.read_ptr].skb;
            if (txq->txb[txq->q.read_ptr].skb) {
                // Can be called from interrupt context
                freePacket(skb, 0);
                txq->txb[txq->q.read_ptr].skb = NULL;
            }
        }
    }
     */
    return 0;
}



/**
 * iwl3945_tx_queue_init - Allocate and initialize one tx/cmd queue
 */
int darwin_iwi3945::tx_queue_init(
                          struct iwl3945_tx_queue *txq, int slots_num, u32 txq_id)
{
    int len;
    int rc = 0;
    
    /*
     * Alloc buffer array for commands (Tx or other types of commands).
     * For the command queue (#4), allocate command space + one big
     * command for scan, since scan command is very huge; the system will
     * not have two scans at the same time, so only one is needed.
     * For data Tx queues (all other queues), no super-size command
     * space is needed.
     */
    len = sizeof(struct iwl3945_cmd) * slots_num;
    if (txq_id == IWL_CMD_QUEUE_NUM)
        len +=  IWL_MAX_SCAN_SIZE;
    txq->cmd = IOMallocContiguous(len, sizeof(__le32), &txq->dma_addr_cmd);
    if (!txq->cmd)
        return -ENOMEM;
    
    /* Alloc driver data array and TFD circular buffer */
    rc = tx_queue_alloc(txq, txq_id);
    if (rc) {
        IOFreeContiguous(txq->cmd, len);
//        pci_free_consistent(dev, len, txq->cmd, txq->dma_addr_cmd);
        
        return -ENOMEM;
    }
    txq->need_update = 0;
    
    /* TFD_QUEUE_SIZE_MAX must be power-of-two size, otherwise
     * iwl3945_queue_inc_wrap and iwl3945_queue_dec_wrap are broken. */
//    BUILD_BUG_ON(TFD_QUEUE_SIZE_MAX & (TFD_QUEUE_SIZE_MAX - 1));
    
    /* Initialize queue high/low-water, head/tail indexes */
    queue_init(&txq->q, TFD_QUEUE_SIZE_MAX, slots_num, txq_id);
    
    /* Tell device where to find queue, enable DMA channel. */
    hw_tx_queue_init(txq);
    
    return 0;
}

int darwin_iwi3945::hw_tx_queue_init(struct iwl3945_tx_queue *txq)
{
    int rc;
    unsigned long flags;
    int txq_id = txq->q.id;
    
    struct iwl3945_shared *shared_data = hw_setting.shared_virt;
    
    shared_data->tx_base_ptr[txq_id] = cpu_to_le32((u32)txq->q.dma_addr);
    
    //lck_spin_lock(slock);
    rc = grab_nic_access();
    if (rc) {
        //lck_spin_unlock(slock);
        return rc;
    }
    write_direct32(FH_CBCC_CTRL(txq_id), 0);
    write_direct32(FH_CBCC_BASE(txq_id), 0);
    
    write_direct32(FH_TCSR_CONFIG(txq_id),
                           ALM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_NOINT |
                           ALM_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_TXF |
                           ALM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_IFTFD |
                           ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL |
                           ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE);
    release_nic_access();
    
    /* fake read to flush all prev. writes */
    read32(FH_TSSR_CBB_BASE);
    //lck_spin_unlock(slock);
    
    return 0;
}



/**
 * iwl3945_tx_queue_alloc - Alloc driver data and TFD CB for one Tx/cmd queue
 */
int darwin_iwi3945::tx_queue_alloc(struct iwl3945_tx_queue *txq, u32 id)
{
    
    /* Driver private data, only for Tx (not command) queues,
     * not shared with device. */
    if (id != IWL_CMD_QUEUE_NUM) {
        txq->txb = IOMalloc(sizeof(txq->txb[0]) *
                            TFD_QUEUE_SIZE_MAX);
        if (!txq->txb) {
            IWL_ERROR("kmalloc for auxiliary BD "
                      "structures failed\n");
            goto error;
        }
    } else
        txq->txb = NULL;
    
    /* Circular buffer of transmit frame descriptors (TFDs),
     * shared with device */
//    txq->bd = pci_alloc_consistent(dev,
//                                   sizeof(txq->bd[0]) * TFD_QUEUE_SIZE_MAX,
//                                   &txq->q.dma_addr);
    txq->bd = IOMallocContiguous(sizeof(txq->bd[0]) * TFD_QUEUE_SIZE_MAX, 4, &txq->q.dma_addr);
    
    if (!txq->bd) {
        IWL_ERROR("pci_alloc_consistent(%zd) failed\n",
                  sizeof(txq->bd[0]) * TFD_QUEUE_SIZE_MAX);
        goto error;
    }
    txq->q.id = id;
    
    return 0;
    
error:
    if (txq->txb) {
        kfree(txq->txb);
        IOFree(txq->txb, sizeof(txq->txb[0]) *
               TFD_QUEUE_SIZE_MAX);
        txq->txb = NULL;
    }
    
    return -ENOMEM;
}

int darwin_iwi3945::tx_reset()
{
    int rc;
    unsigned long flags;
    
    //spin_lock_irqsave(&priv->lock, flags);
    //lck_spin_lock(slock);
    rc = grab_nic_access();
    if (rc) {
        //spin_unlock_irqrestore(&priv->lock, flags);
        //lck_spin_unlock(slock);
        return rc;
    }
    
    /* bypass mode */
    write_prph(ALM_SCD_MODE_REG, 0x2);
    
    /* RA 0 is active */
    write_prph(ALM_SCD_ARASTAT_REG, 0x01);
    
    /* all 6 fifo are active */
    write_prph(ALM_SCD_TXFACT_REG, 0x3f);
    
    write_prph(ALM_SCD_SBYP_MODE_1_REG, 0x010000);
    write_prph(ALM_SCD_SBYP_MODE_2_REG, 0x030002);
    write_prph(ALM_SCD_TXF4MF_REG, 0x000004);
    write_prph(ALM_SCD_TXF5MF_REG, 0x000005);
    
    write_direct32(FH_TSSR_CBB_BASE,
                           hw_setting.shared_phys);
    
    write_direct32(FH_TSSR_MSG_CONFIG,
                           ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TXPD_ON |
                           ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_TXPD_ON |
                           ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_128B |
                           ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TFD_ON |
                           ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_CBB_ON |
                           ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RSP_WAIT_TH |
                           ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_RSP_WAIT_TH);
    
    release_nic_access();
    //spin_unlock_irqrestore(&priv->lock, flags);
    //lck_spin_unlock(slock);
    
    return 0;
}














#pragma mark -
#pragma mark Rx Queue

int darwin_iwi3945::rx_queue_alloc()
{
    int i;
    
    //spin_lock_init(rxq.lock);
    INIT_LIST_HEAD(&(rxq.rx_free));
    INIT_LIST_HEAD(&(rxq.rx_used));
    
    /* Alloc the circular buffer of Read Buffer Descriptors (RBDs) */
    //rxq->bd = pci_alloc_consistent(dev, 4 * RX_QUEUE_SIZE, &rxq->dma_addr);
    rxq.bd = IOMallocContiguous(4 * RX_QUEUE_SIZE, 
            sizeof(struct tfd_frame *), &rxq.dma_addr);
    if (!rxq.bd)
        return -ENOMEM;
    
    /* Fill the rx_used queue with _all_ of the Rx buffers */
    for (i = 0; i < RX_FREE_BUFFERS + RX_QUEUE_SIZE; i++)
        list_add_tail(&(rxq.pool[i].list), &(rxq.rx_used));
    
    /* Set us so that we have processed and used all buffers, but have
     * not restocked the Rx queue with fresh buffers */
    rxq.read = rxq.write = 0;
    rxq.free_count = 0;
    rxq.need_update = 0;
    return 0;
}



/* Assumes that the skb field of the buffers in 'pool' is kept accurate.
 * If an SKB has been detached, the POOL needs to have its SKB set to NULL
 * This free routine walks the list of POOL entries and if SKB is set to
 * non NULL it is unmapped and freed
 */
void darwin_iwi3945::rx_queue_free()
{
	int i;
	for (i = 0; i < RX_QUEUE_SIZE + RX_FREE_BUFFERS; i++) {
		if (rxq.pool[i].skb != NULL) {
            freePacket(rxq.pool[i].skb, 0);
		}
	}
    
    IOFreeContiguous(rxq.bd, 4 * RX_QUEUE_SIZE);
	rxq.bd = NULL;
}




void darwin_iwi3945::rx_queue_reset()
{
    unsigned long flags;
    int i;
    //lck_spin_lock(trxq.lock);
    INIT_LIST_HEAD(&(rxq.rx_free));
    INIT_LIST_HEAD(&(rxq.rx_used));
    /* Fill the rx_used queue with _all_ of the Rx buffers */
    for (i = 0; i < RX_FREE_BUFFERS + RX_QUEUE_SIZE; i++) {
        /* In the reset function, these buffers may have been allocated
         * to an SKB, so we need to unmap and free potential storage */
        if (rxq.pool[i].skb != NULL) {
            freePacket(rxq.pool[i].skb, 0);//, IWL_RX_FRAME_SIZE);
            alloc_rxb_skb--;
            rxq.pool[i].skb = NULL;
        }
        list_add_tail(&(rxq.pool[i].list), &(rxq.rx_used));
    }
    
    /* Set us so that we have processed and used all buffers, but have
     * not restocked the Rx queue with fresh buffers */
    rxq.read = rxq.write = 0;
    rxq.free_count = 0;
    //lck_spin_unlock(trxq.slock);
}




/*
 * this should be called while priv->lock is locked
 */
void darwin_iwi3945::__rx_replenish()
{
    rx_allocate();
    rx_queue_restock();
}


void darwin_iwi3945::rx_replenish()
{
    unsigned long flags;
    
    rx_allocate();
    
    lck_spin_lock(slock);
    rx_queue_restock();
    lck_spin_unlock(slock);
}





/**
 * iwl3945_rx_replenish - Move all used packet from rx_used to rx_free
 *
 * When moving to rx_free an SKB is allocated for the slot.
 *
 * Also restock the Rx queue via iwl3945_rx_queue_restock.
 * This is called as a scheduled work item (except for during initialization)
 */
void darwin_iwi3945::rx_allocate()
{
    struct list_head *element;
    struct iwl3945_rx_mem_buffer *rxb;
    unsigned long flags;
    //lck_spin_lock(rxq.slock);
    while (!list_empty(&rxq.rx_used)) {
        element = rxq.rx_used.next;
        rxb = list_entry(element, struct iwl3945_rx_mem_buffer, list);
        
        /* Alloc a new receive buffer */
        rxb->skb = allocatePacket(IWL_RX_FRAME_SIZE);
        //alloc_skb(IWL_RX_BUF_SIZE, __GFP_NOWARN | GFP_ATOMIC);
        if (!rxb->skb) {
//            if (net_ratelimit())
                IOLog("Can not allocate SKB buffers\n");
            /* We don't reschedule replenish work here -- we will
             * call the restock method and if it still needs
             * more buffers it will schedule replenish */
            break;
        }
        alloc_rxb_skb++;
        list_del(element);
        
        /* Get physical address of RB/SKB */
//        rxb->dma_addr =
//        pci_map_single(priv->pci_dev, rxb->skb->data,
//                       IWL_RX_BUF_SIZE, PCI_DMA_FROMDEVICE);
        rxb->dma_addr =IOMemoryDescriptor::withAddress(mbuf_data(rxb->skb),
                                                           IWL_RX_FRAME_SIZE,kIODirectionOutIn)->getPhysicalAddress();
        IOMemoryDescriptor::withPhysicalAddress(rxb->dma_addr,
                                                    IWL_RX_FRAME_SIZE,kIODirectionOutIn)->prepare(kIODirectionOutIn);
            //rxb->dma_addr = mbuf_data_to_physical(mbuf_data(rxb->skb));   
        
        list_add_tail(&rxb->list, &(rxq.rx_free));
        rxq.free_count++;
    }
    //lck_spin_unlock(rxq.slock);
}



/**
 * iwl3945_rx_queue_restock - refill RX queue from pre-allocated pool
 *
 * If there are slots in the RX queue that need to be restocked,
 * and we have free pre-allocated buffers, fill the ranks as much
 * as we can, pulling from rx_free.
 *
 * This moves the 'write' index forward to catch up with 'processed', and
 * also updates the memory address in the firmware to reference the new
 * target buffer.
 */
int darwin_iwi3945::rx_queue_restock()
{
    struct list_head *element;
    struct iwl3945_rx_mem_buffer *rxb;
    unsigned long flags;
    int write, rc;
    
    //lck_spin_lock(rxq.slock);
    write = rxq.write & ~0x7;
    while ((rx_queue_space(&rxq) > 0) && (rxq.free_count)) {
        /* Get next free Rx buffer, remove from free list */
        element = rxq.rx_free.next;
        rxb = list_entry(element, struct iwl3945_rx_mem_buffer, list);
        list_del(element);
        
        /* Point to Rx buffer via next RBD in circular buffer */
        rxq.bd[rxq.write] = dma_addr2rbd_ptr(rxb->dma_addr);
        rxq.queue[rxq.write] = rxb;
        rxq.write = (rxq.write + 1) & RX_QUEUE_MASK;
        rxq.free_count--;
    }
    //lck_spin_unlock(rxq.slock);
    /* If the pre-allocated buffer pool is dropping low, schedule to
     * refill it */
    if (rxq.free_count <= RX_LOW_WATERMARK)
//        queue_work(workqueue, rx_replenish);
        queue_te(5,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::rx_replenish),NULL,NULL,true);
    
#define abs(x) (x<0?-x:x)
    
    /* If we've added more space for the firmware to place data, tell it.
     * Increment device's write pointer in multiples of 8. */
    if ((write != (rxq.write & ~0x7))
        || (abs(rxq.write - rxq.read) > 7)) {
        //lck_spin_lock(rxq.slock);
        rxq.need_update = 1;
        //lck_spin_unlock(rxq.slock);
        rc = rx_queue_update_write_ptr(&rxq);
        if (rc)
            return rc;
    }
    
    return 0;
}



/**
 * iwl3945_rx_queue_update_write_ptr - Update the write pointer for the RX queue
 */
int darwin_iwi3945::rx_queue_update_write_ptr(struct iwl3945_rx_queue *q)
{
    u32 reg = 0;
    int rc = 0;
    unsigned long flags;
    
    //spin_lock_irqsave(&q->lock, flags);
    //lck_spin_lock(slock);
    
    if (q->need_update == 0)
        goto exit_unlock;
    
    /* If power-saving is in use, make sure device is awake */
    if (isset(&status, STATUS_POWER_PMI)) {
        reg = read32(CSR_UCODE_DRV_GP1);
        
        if (reg & CSR_UCODE_DRV_GP1_BIT_MAC_SLEEP) {
            set_bit(CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
            goto exit_unlock;
        }
        
        rc = grab_nic_access();
        if (rc)
            goto exit_unlock;
        
        /* Device expects a multiple of 8 */
        write_direct32(FH_RSCSR_CHNL0_WPTR,
                               q->write & ~0x7);
        release_nic_access();
        
        /* Else device is assumed to be awake */
    } else
    /* Device expects a multiple of 8 */
        write32(FH_RSCSR_CHNL0_WPTR, q->write & ~0x7);
    
    
    q->need_update = 0;
    
exit_unlock:
    //lck_spin_unlock(q->slock);
    return rc;
}    


/**
 * iwl3945_rx_queue_space - Return number of free slots available in queue.
 */
int darwin_iwi3945::rx_queue_space(const struct iwl3945_rx_queue *q)
{
    int s = q->read - q->write;
    if (s <= 0)
        s += RX_QUEUE_SIZE;
    /* keep some buffer to not confuse full and empty queue */
    s -= 2;
    if (s < 0)
        s = 0;
    return s;
}



int darwin_iwi3945::rx_init()
{
    int rc;
    unsigned long flags;
    
    //spin_lock_irqsave(&priv->lock, flags);
    //lck_spin_lock(slock);
    rc = grab_nic_access();
    if (rc) {
        //spin_unlock_irqrestore(&priv->lock, flags);
        //lck_spin_unlock(slock);
        return rc;
    }
    
    write_direct32(FH_RCSR_RBD_BASE(0), rxq.dma_addr);
    IOLog("Informing the card to write RPTR data to 0x%08x\n",
                           hw_setting.shared_phys +
                           offsetof(struct iwl3945_shared, rx_read_ptr[0]));
    write_direct32(FH_RCSR_RPTR_ADDR(0),
                           hw_setting.shared_phys +
                           offsetof(struct iwl3945_shared, rx_read_ptr[0]));
    write_direct32(FH_RCSR_WPTR(0), 0);
    write_direct32(FH_RCSR_CONFIG(0),
                           ALM_FH_RCSR_RX_CONFIG_REG_VAL_DMA_CHNL_EN_ENABLE |
                           ALM_FH_RCSR_RX_CONFIG_REG_VAL_RDRBD_EN_ENABLE |
                           ALM_FH_RCSR_RX_CONFIG_REG_BIT_WR_STTS_EN |
                           ALM_FH_RCSR_RX_CONFIG_REG_VAL_MAX_FRAG_SIZE_128 |
                           (RX_QUEUE_SIZE_LOG << ALM_FH_RCSR_RX_CONFIG_REG_POS_RBDC_SIZE) |
                           ALM_FH_RCSR_RX_CONFIG_REG_VAL_IRQ_DEST_INT_HOST |
                           (1 << ALM_FH_RCSR_RX_CONFIG_REG_POS_IRQ_RBTH) |
                           ALM_FH_RCSR_RX_CONFIG_REG_VAL_MSG_MODE_FH);
    
    /* fake read to flush all prev I/O */
    read_direct32(FH_RSSR_CTRL);
    
    release_nic_access();
    //spin_unlock_irqrestore(&priv->lock, flags);
    //lck_spin_unlock(slock);
    
    return 0;
}





        

#pragma mark -
#pragma mark Direct hardware access methods
void inline darwin_iwi3945::write32(UInt32 offset, UInt32 data)
{
	//OSWriteLittleInt32((void*)memBase, offset, data);
	_ipw_write32(memBase, offset, data);
}

UInt32 inline darwin_iwi3945::read32(UInt32 offset)
{
	//return OSReadLittleInt32((void*)memBase, offset);
	return _ipw_read32(memBase,offset);
}

void inline darwin_iwi3945::clear_bit(UInt32 reg, UInt32 mask)
{
	write32(reg, read32(reg) & ~mask);
}

void inline darwin_iwi3945::set_bit(UInt32 reg, UInt32 mask)
{
	write32(reg, read32(reg) | mask);
}

int
darwin_iwi3945::poll_bit(u32 addr, u32 bits, u32 mask, int timeout)
{
	int i = 0;
    
	do {
		if ((_ipw_read32(memBase,addr) & mask) == (bits & mask))
			return i;
		mdelay(10);
		i += 10;
	} while (i < timeout);
    
	return -ETIMEDOUT;
	
}





inline int darwin_iwi3945::grab_nic_access()
{
    int ret;
    u32 gp_ctl;
    
#ifdef CONFIG_IWL3945_DEBUG
    if (atomic_read(&priv->restrict_refcnt))
        return 0;
#endif
    if (isset(&status, STATUS_RF_KILL_HW) ||
        isset(&status, STATUS_RF_KILL_SW)) {
        IWL_WARNING("WARNING: Requesting MAC access during RFKILL "
                    "wakes up NIC\n");
        
        /* 10 msec allows time for NIC to complete its data save */
        gp_ctl = read32(CSR_GP_CNTRL);
        if (gp_ctl & CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY) {
            IWL_DEBUG_RF_KILL("Wait for complete power-down, "
                              "gpctl = 0x%08x\n", gp_ctl);
            mdelay(10);
        } else
            IWL_DEBUG_RF_KILL("power-down complete, "
                              "gpctl = 0x%08x\n", gp_ctl);
    }
    
    /* this bit wakes up the NIC */
    set_bit(CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
    ret = poll_bit(CSR_GP_CNTRL, CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN,
                            (CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY |
                             CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP), 50);
    if (ret < 0) {
        IWL_ERROR("MAC is in deep sleep!\n");
        return -EIO;
    }
    
#ifdef CONFIG_IWL3945_DEBUG
    atomic_inc(&restrict_refcnt);
#endif
    return 0;
}


inline void darwin_iwi3945::release_nic_access()
{
#ifdef CONFIG_IWL3945_DEBUG
    if (atomic_dec_and_test(&priv->restrict_refcnt))
#endif
        clear_bit(CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
}









#pragma mark -
#pragma mark Main uCode callback routines

/**
 * iwl3945_rx_handle - Main entry function for receiving responses from uCode
 *
 * Uses the priv->rx_handlers callback function array to invoke
 * the appropriate handlers, including command responses,
 * frame-received notifications, and other notifications.
 */
void darwin_iwi3945::rx_handle()
{
	struct iwl3945_rx_mem_buffer *rxb;
	struct iwl3945_rx_packet *pkt;
	u32 r, i;
	int reclaim;
	unsigned long flags;
	u8 fill_rx = 0;
	u32 count = 0;
    
	/* uCode's read index (stored in shared DRAM) indicates the last Rx
	 * buffer that the driver may process (last buffer filled by ucode). */
	r = hw_get_rx_read();
	i = rxq.read;

    if( r > 16384 ) {
        IOLog("The read pointer doesn't make sense.  It's too large: %d\n", r);
        return;
    }

    
	if (rx_queue_space(&rxq) > (RX_QUEUE_SIZE / 2)) {
		fill_rx = 1;
    }

	/* Rx interrupt, but nothing sent from uCode */
	if (i == r)
		IWL_DEBUG(IWL_DL_RX | IWL_DL_ISR, "r = %d, i = %d\n", r, i);
    
	while (i != r) {
		rxb = rxq.queue[i];
        
		/* If an RXB doesn't have a Rx queue slot associated with it,
		 * then a bug has been introduced in the queue refilling
		 * routines -- catch it here */
#warning Catch this bug!
//		BUG_ON(rxb == NULL);
        
		rxq.queue[i] = NULL;
        
#warning This doesn't seem necessary on OS X
//		pci_dma_sync_single_for_cpu(priv->pci_dev, rxb->dma_addr,
//                                    IWL_RX_BUF_SIZE,
//                                    PCI_DMA_FROMDEVICE);
        if( NULL == rxb ) {
            IOLog("Something very bad happened: rxb went NULL somehow on the %dth buffer.  Prepare to panic.\n", i);
        }
		pkt = (struct iwl3945_rx_packet *)rxb->skb;
        
		/* Reclaim a command buffer only if this packet is a response
		 *   to a (driver-originated) command.
		 * If the packet (e.g. Rx frame) originated from uCode,
		 *   there is no command buffer to reclaim.
		 * Ucode should set SEQ_RX_FRAME bit if ucode-originated,
		 *   but apparently a few don't get set; catch them here. */
		reclaim = !(pkt->hdr.sequence & SEQ_RX_FRAME) &&
        (pkt->hdr.cmd != STATISTICS_NOTIFICATION) &&
        (pkt->hdr.cmd != REPLY_TX);
        
		// Based on type of command response or notification,
        // handle those that need handling via function in
        // rx_handlers table.  See iwl3945_setup_rx_handlers()
        /*
		if (rx_handlers[pkt->hdr.cmd]) {
			IWL_DEBUG(IWL_DL_HOST_COMMAND | IWL_DL_RX | IWL_DL_ISR,
                      "r = %d, i = %d, %s, 0x%02x\n", r, i,
                      get_cmd_string(pkt->hdr.cmd), pkt->hdr.cmd);
			rx_handlers[pkt->hdr.cmd] (rxb);
		} else*/ {
            
			// No handling needed
			IWL_DEBUG(IWL_DL_HOST_COMMAND | IWL_DL_RX | IWL_DL_ISR,
                      "r %d i %d No handler needed for %s, 0x%02x\n",
                      r, i, get_cmd_string(pkt->hdr.cmd),
                      pkt->hdr.cmd);
		}
        
		if (reclaim) {
            /* Invoke any callbacks, transfer the skb to caller, and
			 * fire off the (possibly) blocking iwl3945_send_cmd()
			 * as we reclaim the driver command queue */
			if (rxb && rxb->skb) {
				tx_cmd_complete(rxb);
            }
			else
				IWL_WARNING("Claim null rxb?\n");
		}
        
		/* For now we just don't re-use anything.  We can tweak this
		 * later to try and re-use notification packets and SKBs that
		 * fail to Rx correctly */
		if (rxb->skb != NULL) {
			alloc_rxb_skb--;
            freePacket(rxb->skb, 0);
			rxb->skb = NULL;
		}
     
#warning This doesn't seem necessary on OS X
//		pci_unmap_single(priv->pci_dev, rxb->dma_addr,
//                         IWL_RX_BUF_SIZE, PCI_DMA_FROMDEVICE);
        
		//lck_spin_lock(rxq->slock);
        
		list_add_tail(&rxb->list, &rxq.rx_used);
		//lck_spin_unlock(rxq->slock);
		i = (i + 1) & RX_QUEUE_MASK;
		/* If there are a lot of unused frames,
		 * restock the Rx queue so ucode won't assert. */
		if (fill_rx) {
			count++;
			if (count >= 8) {
				rxq.read = i;
				__rx_replenish();
				count = 0;
			}
		}
	}
    
	/* Backtrack one entry */
	rxq.read = i;
	rx_queue_restock();
}





u32 darwin_iwi3945::hw_get_rx_read()
{
    struct iwl3945_shared *shared_data = hw_setting.shared_virt;
    
    return le32_to_cpu(shared_data->rx_read_ptr[0]);
}






/**
 * iwl3945_get_channel_info - Find driver's private channel info
 *
 * Based on band and channel number.
 */
const struct iwl3945_channel_info *darwin_iwi3945::get_channel_info(int new_phymode, u16 new_channel)
{
	int i;
    
	switch (new_phymode) {
        case MODE_IEEE80211A:
            for (i = 14; i < channel_count; i++) {
                if (channel_info[i].channel == new_channel)
                    return &channel_info[i];
            }
            break;
            
            case MODE_IEEE80211B:
            case MODE_IEEE80211G:
            if (new_channel >= 1 && new_channel <= 14)
                return &channel_info[new_channel - 1];
            break;
            
	}
    
	return NULL;
}



/**
 * iwl3945_get_antenna_flags - Get antenna flags for RXON command
 * @priv: eeprom and antenna fields are used to determine antenna flags
 *
 * priv->eeprom  is used to determine if antenna AUX/MAIN are reversed
 * priv->antenna specifies the antenna diversity mode:
 *
 * IWL_ANTENNA_DIVERISTY - NIC selects best antenna by itself
 * IWL_ANTENNA_MAIN      - Force MAIN antenna
 * IWL_ANTENNA_AUX       - Force AUX antenna
 */
__le32 darwin_iwi3945::get_antenna_flags()
{
	switch (antenna) {
        case IWL_ANTENNA_DIVERSITY:
            return 0;
            
        case IWL_ANTENNA_MAIN:
            if (eeprom.antenna_switch_type)
                return RXON_FLG_DIS_DIV_MSK | RXON_FLG_ANT_B_MSK;
            return RXON_FLG_DIS_DIV_MSK | RXON_FLG_ANT_A_MSK;
            
            case IWL_ANTENNA_AUX:
            if (eeprom.antenna_switch_type)
                return RXON_FLG_DIS_DIV_MSK | RXON_FLG_ANT_A_MSK;
            return RXON_FLG_DIS_DIV_MSK | RXON_FLG_ANT_B_MSK;
	}
    
	/* bad antenna selector value */
	IWL_ERROR("Bad antenna selector value (0x%x)\n", antenna);
	return 0;		/* "diversity" is default if error */
}




/**
 * iwl3945_supported_rate_to_ie - fill in the supported rate in IE field
 *
 * return : set the bit for each supported rate insert in ie
 */
u16 darwin_iwi3945::supported_rate_to_ie(u8 *ie, u16 supported_rate,
                                        u16 basic_rate, int *left)
{
	u16 ret_rates = 0, bit;
	int i;
	u8 *cnt = ie;
	u8 *rates = ie + 1;
    
	for (bit = 1, i = 0; i < IWL_RATE_COUNT; i++, bit <<= 1) {
		if (bit & supported_rate) {
			ret_rates |= bit;
			rates[*cnt] = iwl3945_rates[i].ieee |
            ((bit & basic_rate) ? 0x80 : 0x00);
			(*cnt)++;
			(*left)--;
			if ((*left <= 0) ||
			    (*cnt >= IWL_SUPPORTED_RATES_IE_LEN))
				break;
		}
	}
    
	return ret_rates;
}


/**
 * iwl3945_fill_probe_req - fill in all required fields and IE for probe request
 */
u16 darwin_iwi3945::fill_probe_req(struct ieee80211_mgmt *frame,
                                  int left, int is_direct)
{
	int len = 0;
	u8 *pos = NULL;
	u16 active_rates, ret_rates, cck_rates;
    
	/* Make sure there is enough space for the probe request,
	 * two mandatory IEs and the data */
	left -= 24;
	if (left < 0)
		return 0;
	len += 24;
    
	frame->frame_control = cpu_to_le16(IEEE80211_STYPE_PROBE_REQ);
	memcpy(frame->da, iwl3945_broadcast_addr, ETH_ALEN);
	memcpy(frame->sa, mac_addr, ETH_ALEN);
	memcpy(frame->bssid, iwl3945_broadcast_addr, ETH_ALEN);
	frame->seq_ctrl = 0;
    
	/* fill in our indirect SSID IE */
	/* ...next IE... */
    
	left -= 2;
	if (left < 0)
		return 0;
	len += 2;
	pos = &(frame->u.probe_req.variable[0]);
	*pos++ = WLAN_EID_SSID;
	*pos++ = 0;
    
	/* fill in our direct SSID IE... */
	if (is_direct) {
		/* ...next IE... */
		left -= 2 + essid_len;
		if (left < 0)
			return 0;
		/* ... fill it in... */
		*pos++ = WLAN_EID_SSID;
		*pos++ = essid_len;
		memcpy(pos, essid, essid_len);
		pos += essid_len;
		len += 2 + essid_len;
	}
    
	/* fill in supported rate */
	/* ...next IE... */
	left -= 2;
	if (left < 0)
		return 0;
    
	/* ... fill it in... */
	*pos++ = WLAN_EID_SUPP_RATES;
	*pos = 0;
    
	active_rate = rates_mask;
	active_rates = active_rate;
	active_rate_basic = rates_mask & IWL_BASIC_RATES_MASK;
    
	cck_rates = IWL_CCK_RATES_MASK & active_rates;
	ret_rates = supported_rate_to_ie(pos, cck_rates, active_rate_basic, &left);
	active_rates &= ~ret_rates;
    
	ret_rates = supported_rate_to_ie(pos, active_rates,
                                             active_rate_basic, &left);
	active_rates &= ~ret_rates;
    
	len += 2 + *pos;
	pos += (*pos) + 1;
	if (active_rates == 0)
		goto fill_end;
    
	/* fill in supported extended rate */
	/* ...next IE... */
	left -= 2;
	if (left < 0)
		return 0;
	/* ... fill it in... */
	*pos++ = WLAN_EID_EXT_SUPP_RATES;
	*pos = 0;
	supported_rate_to_ie(pos, active_rates,
                                 active_rate_basic, &left);
	if (*pos > 0)
		len += 2 + *pos;
    
fill_end:
	return (u16)len;
}




void darwin_iwi3945::bg_request_scan()
{
    /*
	struct iwl3945_host_cmd cmd = {
		.id = REPLY_SCAN_CMD,
		.len = sizeof(struct iwl3945_scan_cmd),
		.meta.flags = CMD_SIZE_HUGE,
	};
    */
	int rc = 0;
	struct iwl3945_scan_cmd *scan;
	u8 direct_mask;
	int phymode;
        
//	mutex_lock(&priv->mutex);
    
	if (!is_ready()) {
		IWL_WARNING("request scan called when driver not ready.\n");
		goto done;
	}
    
	/* Make sure the scan wasn't cancelled before this queued work
	 * was given the chance to run... */
	if (!isset(&status, STATUS_SCANNING))
		goto done;
    
	/* This should never be called or scheduled if there is currently
	 * a scan active in the hardware. */
	if (isset(&status, STATUS_SCAN_HW)) {
		IWL_DEBUG_INFO("Multiple concurrent scan requests in parallel. "
                       "Ignoring second request.\n");
		rc = -EIO;
		goto done;
	}
    
	if (isset(&status, STATUS_EXIT_PENDING)) {
		IWL_DEBUG_SCAN("Aborting scan due to device shutdown\n");
		goto done;
	}
    
	if (isset(&status, STATUS_SCAN_ABORTING)) {
		IWL_DEBUG_HC("Scan request while abort pending.  Queuing.\n");
		goto done;
	}
    
	if (is_rfkill()) {
		IWL_DEBUG_HC("Aborting scan due to RF Kill activation\n");
		goto done;
	}
    
	if (!isset(&status, STATUS_READY)) {
		IWL_DEBUG_HC("Scan request while uninitialized.  Queuing.\n");
		goto done;
	}
    
	if (!scan_bands) {
		IWL_DEBUG_HC("Aborting scan due to no requested bands\n");
		goto done;
	}
    
	if (!scan) {
		scan = IOMalloc(sizeof(struct iwl3945_scan_cmd) + IWL_MAX_SCAN_SIZE);
        if (!scan) {
			rc = -ENOMEM;
			goto done;
		}
	}
	memset(scan, 0, sizeof(struct iwl3945_scan_cmd) + IWL_MAX_SCAN_SIZE);
    
	scan->quiet_plcp_th = IWL_PLCP_QUIET_THRESH;
	scan->quiet_time = IWL_ACTIVE_QUIET_TIME;
    
	if (is_associated()) {
		u16 interval = 0;
		u32 extra;
		u32 suspend_time = 100;
		u32 scan_suspend_time = 100;
		unsigned long flags;
        
		IWL_DEBUG_INFO("Scanning while associated...\n");
        
//		spin_lock_irqsave(&priv->lock, flags);
		interval = beacon_int;
//		spin_unlock_irqrestore(&priv->lock, flags);
        
		scan->suspend_time = 0;
		scan->max_out_time = cpu_to_le32(200 * 1024);
		if (!interval)
			interval = suspend_time;
		/*
		 * suspend time format:
		 *  0-19: beacon interval in usec (time before exec.)
		 * 20-23: 0
		 * 24-31: number of beacons (suspend between channels)
		 */
        
		extra = (suspend_time / interval) << 24;
		scan_suspend_time = 0xFF0FFFFF &
        (extra | ((suspend_time % interval) * 1024));
        
		scan->suspend_time = cpu_to_le32(scan_suspend_time);
		IWL_DEBUG_SCAN("suspend_time 0x%X beacon interval %d\n",
                       scan_suspend_time, interval);
	}
    
	/* We should add the ability for user to lock to PASSIVE ONLY */
	if (one_direct_scan) {
		IWL_DEBUG_SCAN
        ("Kicking off one direct scan for '%s'\n",
         escape_essid(direct_ssid, direct_ssid_len));
		scan->direct_scan[0].id = WLAN_EID_SSID;
		scan->direct_scan[0].len = direct_ssid_len;
		memcpy(scan->direct_scan[0].ssid, direct_ssid, direct_ssid_len);
		direct_mask = 1;
	} else if (!is_associated() && essid_len) {
		scan->direct_scan[0].id = WLAN_EID_SSID;
		scan->direct_scan[0].len = essid_len;
		memcpy(scan->direct_scan[0].ssid, essid, essid_len);
		direct_mask = 1;
	} else
		direct_mask = 0;
    
	/* We don't build a direct scan probe request; the uCode will do
	 * that based on the direct_mask added to each channel entry */
	scan->tx_cmd.len = cpu_to_le16( fill_probe_req((struct ieee80211_mgmt *)scan->data,
                                                          IWL_MAX_SCAN_SIZE - sizeof(scan), 0));
	scan->tx_cmd.tx_flags = TX_CMD_FLG_SEQ_CTL_MSK;
	scan->tx_cmd.sta_id = hw_setting.bcast_sta_id;
	scan->tx_cmd.stop_time.life_time = TX_CMD_LIFE_TIME_INFINITE;
    
	/* flags + rate selection */
    
	switch (scan_bands) {
        case 2:
            scan->flags = RXON_FLG_BAND_24G_MSK | RXON_FLG_AUTO_DETECT_MSK;
            scan->tx_cmd.rate = 10; //IWL_RATE_1M_PLCP;
            scan->good_CRC_th = 0;
            phymode = MODE_IEEE80211G;
            break;
            
        case 1:
            scan->tx_cmd.rate = 13; //IWL_RATE_6M_PLCP;
            scan->good_CRC_th = IWL_GOOD_CRC_TH;
            phymode = MODE_IEEE80211A;
            break;
            
        default:
            IWL_WARNING("Invalid scan band count\n");
            goto done;
	}
    
	/* select Rx antennas */
	scan->flags |= get_antenna_flags();
    
	if (iw_mode == IEEE80211_IF_TYPE_MNTR)
		scan->filter_flags = RXON_FILTER_PROMISC_MSK;
    
	if (direct_mask)
		IWL_DEBUG_SCAN
        ("Initiating direct scan for %s.\n",
         escape_essid(essid, essid_len));
	else
		IWL_DEBUG_SCAN("Initiating indirect scan.\n");
    
	scan->channel_count =
    get_channels_for_scan(
                                  phymode, 1, /* active */
                                  direct_mask,
                                  (void *)&scan->data[le16_to_cpu(scan->tx_cmd.len)]);
    
	cmd.len += le16_to_cpu(scan->tx_cmd.len) +
    scan->channel_count * sizeof(struct iwl3945_scan_channel);
	cmd.data = scan;
	scan->len = cpu_to_le16(cmd.len);
    
	setbit(&status, STATUS_SCAN_HW);
	rc = send_cmd_sync(&cmd);
	if (rc)
		goto done;
    
    
	queue_delayed_work(priv->workqueue, &priv->scan_check,
                       IWL_SCAN_CHECK_WATCHDOG);
    
	mutex_unlock(&priv->mutex);
	return;
    
done:
	/* inform mac80211 scan aborted */
	queue_work(priv->workqueue, &priv->scan_completed);
	mutex_unlock(&priv->mutex);
}



IOReturn darwin_iwi3945::bg_restart(void *arg0, void *arg1, void *arg2, void *arg3)
{    
	if (isset(&status, STATUS_EXIT_PENDING))
		return 0;
    
	down();
    
    workqueue->runAction(OSMemberFunctionCast(IOWorkLoop::Action, this,
                                              &darwin_iwi3945::bg_up), (OSObject *)this, 0, 0, 0, 0);

    
    return 0;
}



IOReturn darwin_iwi3945::bg_up(void *arg0, void *arg1, void *arg2, void *arg3)
{
    
	if (isset(&status, STATUS_EXIT_PENDING))
		return 0;
    
    
    iwl_read_ucode();
    
	IOLockLock(mutex);
	up();
	IOLockUnlock(mutex);
}


IOReturn darwin_iwi3945::bg_down(void *arg0, void *arg1, void *arg2, void *arg3)
{
	IOLockLock(mutex);
	down();
	IOLockUnlock(mutex);
    
	cancel_deferred_work();
}

int darwin_iwi3945::iwl_read_ucode()
{
	struct iwl3945_ucode *ucode;
	int rc = 0;
	//struct firmware *ucode_raw;
	const char *name = "iwlwifi-3945.ucode";	
	u8 *src;
	size_t len;
	u32 ver,inst_size,data_size,init_size,init_data_size,boot_size;
    
	/* data from ucode file:  header followed by uCode images */
	ucode = (struct iwl3945_ucode*)ipw_ucode_raw;
	ver = le32_to_cpu(ucode->ver);
	inst_size = le32_to_cpu(ucode->inst_size);
	data_size = le32_to_cpu(ucode->data_size);
	init_size = le32_to_cpu(ucode->init_size);
	init_data_size = le32_to_cpu(ucode->init_data_size);
	boot_size = le32_to_cpu(ucode->boot_size);
    
	IWL_DEBUG_INFO("f/w package hdr ucode version = 0x%x\n", ver);
	IWL_DEBUG_INFO("f/w package hdr runtime inst size = %u\n",
                   inst_size);
	IWL_DEBUG_INFO("f/w package hdr runtime data size = %u\n",
                   data_size);
	IWL_DEBUG_INFO("f/w package hdr init inst size = %u\n",
                   init_size);
	IWL_DEBUG_INFO("f/w package hdr init data size = %u\n",
                   init_data_size);
	IWL_DEBUG_INFO("f/w package hdr boot inst size = %u\n",
                   boot_size);
    
	/* Verify size of file vs. image size info in file's header */
	/*if (ucode_raw->size < sizeof(*ucode) +
     inst_size + data_size + init_size +
     init_data_size + boot_size) {
     
     IWL_DEBUG_INFO("uCode file size %d too small\n",
     (int)ucode_raw->size);
     rc = -EINVAL;
     goto err_release;
     }*/
    
	/* Verify that uCode images will fit in card's SRAM */
	if (inst_size > IWL_MAX_INST_SIZE) {
		IWL_DEBUG_INFO("uCode instr len %d too large to fit in card\n",
                       (int)inst_size);
		rc = -EINVAL;
		goto err_release;
	}
    
	if (data_size > IWL_MAX_DATA_SIZE) {
		IWL_DEBUG_INFO("uCode data len %d too large to fit in card\n",
                       (int)data_size);
		rc = -EINVAL;
		goto err_release;
	}
	if (init_size > IWL_MAX_INST_SIZE) {
		IWL_DEBUG_INFO
        ("uCode init instr len %d too large to fit in card\n",
         (int)init_size);
		rc = -EINVAL;
		goto err_release;
	}
	if (init_data_size > IWL_MAX_DATA_SIZE) {
		IWL_DEBUG_INFO
        ("uCode init data len %d too large to fit in card\n",
         (int)init_data_size);
		rc = -EINVAL;
		goto err_release;
	}
	if (boot_size > IWL_MAX_BSM_SIZE) {
		IWL_DEBUG_INFO
        ("uCode boot instr len %d too large to fit in bsm\n",
         (int)boot_size);
		rc = -EINVAL;
		goto err_release;
	}
    
	/* Allocate ucode buffers for card's bus-master loading ... */
    
	/* Runtime instructions and 2 copies of data:
	 * 1) unmodified from disk
	 * 2) backup cache for save/restore during power-downs */
	ucode_code.len = inst_size;
	/*priv->ucode_code.v_addr =
     pci_alloc_consistent(priv->pci_dev,
     priv->ucode_code.len,
     &(priv->ucode_code.p_addr));*/
	//MemoryDmaAlloc(priv->ucode_code.len, &(priv->ucode_code.p_addr), &(priv->ucode_code.v_addr));
	ucode_code.v_addr=IOMallocContiguous( ucode_code.len, sizeof(__le32), &ucode_code.p_addr);
	ucode_data.len = data_size;
	/*priv->ucode_data.v_addr =
     pci_alloc_consistent(priv->pci_dev,
     priv->ucode_data.len,
     &(priv->ucode_data.p_addr));*/
	//MemoryDmaAlloc(priv->ucode_data.len, &(priv->ucode_data.p_addr), &(priv->ucode_data.v_addr));
	ucode_data.v_addr=IOMallocContiguous(ucode_data.len, sizeof(__le32), &ucode_data.p_addr);
	ucode_data_backup.len = data_size;
	/*priv->ucode_data_backup.v_addr =
     pci_alloc_consistent(priv->pci_dev,
     priv->ucode_data_backup.len,
     &(priv->ucode_data_backup.p_addr));*/
	//MemoryDmaAlloc(priv->ucode_data_backup.len, &(priv->ucode_data_backup.p_addr), &(priv->ucode_data_backup.v_addr));
	ucode_data_backup.v_addr=IOMallocContiguous(ucode_data_backup.len, sizeof(__le32), &ucode_data_backup.p_addr);
	/* Initialization instructions and data */
	ucode_init.len = init_size;
	/*priv->ucode_init.v_addr =
     pci_alloc_consistent(priv->pci_dev,
     priv->ucode_init.len,
     &(priv->ucode_init.p_addr));*/
	//MemoryDmaAlloc(priv->ucode_init.len, &(priv->ucode_init.p_addr), &(priv->ucode_init.v_addr));
	ucode_init.v_addr=IOMallocContiguous(ucode_init.len, sizeof(__le32), &ucode_init.p_addr);
	ucode_init_data.len = init_data_size;
	/*priv->ucode_init_data.v_addr =
     pci_alloc_consistent(priv->pci_dev,
     priv->ucode_init_data.len,
     &(priv->ucode_init_data.p_addr));*/
	//MemoryDmaAlloc(priv->ucode_init_data.len, &(priv->ucode_init_data.p_addr), &(priv->ucode_init_data.v_addr));
	ucode_init_data.v_addr=IOMallocContiguous(ucode_init_data.len, sizeof(__le32), &ucode_init_data.p_addr);
	/* Bootstrap (instructions only, no data) */
	ucode_boot.len = boot_size;
	/*priv->ucode_boot.v_addr =
     pci_alloc_consistent(priv->pci_dev,
     priv->ucode_boot.len,
     &(priv->ucode_boot.p_addr));*/
	//MemoryDmaAlloc(priv->ucode_boot.len, &(priv->ucode_boot.p_addr), &(priv->ucode_boot.v_addr));
	ucode_boot.v_addr=IOMallocContiguous(ucode_boot.len, sizeof(__le32), &ucode_boot.p_addr);
	if (!ucode_code.v_addr || !ucode_data.v_addr ||
	    !ucode_init.v_addr || !ucode_init_data.v_addr ||
	    !ucode_boot.v_addr || !ucode_data_backup.v_addr)
		goto err_pci_alloc;
    
	/* Copy images into buffers for card's bus-master reads ... */
    
	/* Runtime instructions (first block of data in file) */
	src = &ucode->data[0];
	len = ucode_code.len;
	IWL_DEBUG_INFO("Copying (but not loading) uCode instr len %d\n",
                   (int)len);
	memcpy(ucode_code.v_addr, src, len);
	IWL_DEBUG_INFO("uCode instr buf vaddr = 0x%p, paddr = 0x%08x\n",
                   ucode_code.v_addr, (u32)ucode_code.p_addr);
    
	/* Runtime data (2nd block)
	 * NOTE:  Copy into backup buffer will be done in iwl_up()  */
	src = &ucode->data[inst_size];
	len = ucode_data.len;
	IWL_DEBUG_INFO("Copying (but not loading) uCode data len %d\n",
                   (int)len);
	memcpy(ucode_data.v_addr, src, len);
	memcpy(ucode_data_backup.v_addr, src, len);
    
	/* Initialization instructions (3rd block) */
	if (init_size) {
		src = &ucode->data[inst_size + data_size];
		len = ucode_init.len;
		IWL_DEBUG_INFO("Copying (but not loading) init instr len %d\n",
                       (int)len);
		memcpy(ucode_init.v_addr, src, len);
	}
    
	/* Initialization data (4th block) */
	if (init_data_size) {
		src = &ucode->data[inst_size + data_size + init_size];
		len = ucode_init_data.len;
		IWL_DEBUG_INFO("Copying (but not loading) init data len %d\n",
                       (int)len);
		memcpy(ucode_init_data.v_addr, src, len);
	}
    
	/* Bootstrap instructions (5th block) */
	src = &ucode->data[inst_size + data_size + init_size + init_data_size];
	len = ucode_boot.len;
	IWL_DEBUG_INFO("Copying (but not loading) boot instr len %d\n",
                   (int)len);
	memcpy(ucode_boot.v_addr, src, len);
    
	/* We have our copies now, allow OS release its copies */
	return 0;
    
err_pci_alloc:
    
    
err_release:
	//release_firmware(ucode_raw);
    
error:
	return rc;
}



/******************************************************************************* 
 * Functions which MUST be implemented by any class which inherits
 * from IO80211Controller.
 ******************************************************************************/
#pragma mark -
#pragma mark IO80211Controller entry points


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
    strncpy(sd->ssid_bytes, "anetwork", sizeof(sd->ssid_bytes));
    sd->ssid_len = strlen("anetwork");
        
//	IOLog("getSSID %s l:%d\n",escape_essid((const char*)sd->ssid_bytes, sd->ssid_len));
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
//	IOLog("getCARD_CAPABILITIES %x %d\n", interface, sizeof(cd->capabilities));
	//publishProperties();
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
    sd->state = kIO80211NetworkLinkUp;
    
//	IOLog("getSTATE %d\n",sd->state);
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
        return;
    }
    if( dd == NULL ) {
        IOLog("Quit calling getSTATUS_DEV without *dd!\n");
        return;
    }



    dd->version = APPLE80211_VERSION;

    bzero(dd->dev_name, sizeof(dd->dev_name));
    strncpy(dd->dev_name, DRIVER_DEV_NAME, sizeof(dd->dev_name));


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
    strncpy(cd->cc, "us", sizeof(cd->cc));
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
    return kIOReturnSuccess;
}



SInt32 
darwin_iwi3945::setRATE(IO80211Interface *interface, apple80211_rate_data *rd)
{
    /*
    rd->version = APPLE80211_VERSION;
    rd->num_radios = 3;
    rd->rate[0] = 11;
    rd->rate[1] = 54;
    rd->rate[2] = 54;
    */
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
        return;
    }
    
    IOLog("Scan requested.  Type: %d\n", sd->scan_type);
    
    if( sd->scan_type == APPLE80211_SCAN_TYPE_ACTIVE ) {
        memcpy(sd->bssid.octet, "DACAFEBABE", sizeof(sd->bssid.octet));
    }
    
    postMessage(APPLE80211_IOC_STATION_LIST);
    
	return kIOReturnSuccess;
}

SInt32
darwin_iwi3945::setASSOCIATE(IO80211Interface *interface,
							struct apple80211_assoc_data *ad)
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
        return;
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

bool darwin_iwi3945::attachInterfaceWithMacAddress( void * macAddr, 
												UInt32 macLen, 
												IONetworkInterface ** interface, 
												bool doRegister ,
												UInt32 timeout  )
{
	IOLog("attachInterfaceWithMacAddress \n");
	return super::attachInterfaceWithMacAddress(macAddr,macLen,interface,doRegister,timeout);
}												
												
void darwin_iwi3945::dataLinkLayerAttachComplete( IO80211Interface * interface )											
{
	IOLog("dataLinkLayerAttachComplete \n");
	super::dataLinkLayerAttachComplete(interface);
}




#pragma mark -
#pragma mark Our own functions (mostly cribbed from iwl3945-base.c)


/**
 * irq_handle_error - called for HW or SW error interrupt from card
 */
void darwin_iwi3945::irq_handle_error(void)
{
	/* Set the FW error flag -- cleared on iwl3945_down */
	set_bit(STATUS_FW_ERROR, status);
    
	/* Cancel currently queued command. */
	clear_bit(STATUS_HCMD_ACTIVE, status);
    
#ifdef CONFIG_IWL3945_DEBUG
	if (iwl3945_debug_level & IWL_DL_FW_ERRORS) {
		dump_nic_error_log();
		dump_nic_event_log();
		print_rx_config_cmd(staging_rxon);
	}
#endif
    
	//wake_up_interruptible(wait_command_queue);
    
	/* Keep the restart process from trying to send host
	 * commands by clearing the INIT status bit */
	clear_bit(STATUS_READY, status);
    
	if (!isset(&status, STATUS_EXIT_PENDING)) {
		IWL_DEBUG(IWL_DL_INFO | IWL_DL_FW_ERRORS,
                  "Restarting adapter due to uCode error.\n");
        
		if (is_associated()) {
			memcpy(&recovery_rxon, &active_rxon,
			       sizeof(recovery_rxon));
			error_recovering = 1;
		}
		//queue_work(workqueue, &restart);
        queue_te(5,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::bg_restart),NULL,NULL,true);
	}
}



/**
 * Initialize spinlocks, so we can reuse much code from the Linux IWL drivers.
 * Note: Most of this code is stolen from the Kernel Programming Guide: Locks
 * section, and hence lifted liberally from kern_time.c.
 */
inline bool darwin_iwi3945::initialize_spinlocks(void) {
    
    
    /* allocate lock group attribute and group */
    slock_grp_attr = lck_grp_attr_alloc_init();
    lck_grp_attr_setstat(slock_grp_attr);
    
    slock_grp =  lck_grp_alloc_init("iwi3945", slock_grp_attr);
    
    /* Allocate lock attribute */
    slock_attr = lck_attr_alloc_init();
    //lck_attr_setdebug(iwi3945_slock_attr); // set the debug flag
    //lck_attr_setdefault(iwi3945_slock_attr); // clear the debug flag
    
    /* Allocate the spin locks */
    slock = lck_spin_alloc_init(slock_grp, slock_attr);
    slock_sta = lck_spin_alloc_init(slock_grp, slock_attr);
    slock_hcmd = lck_spin_alloc_init(slock_grp, slock_attr);
    power_data.slock = lck_spin_alloc_init(slock_grp, slock_attr);

    
    return true;
}


inline void darwin_iwi3945::destroy_spinlocks(void) {
    if( power_data.slock ) lck_spin_free(power_data.slock, slock_grp);
    if( slock_hcmd ) lck_spin_free(slock_hcmd, slock_grp);
    if( slock_sta ) lck_spin_free(slock_sta, slock_grp);
    if( slock ) lck_spin_free(slock, slock_grp);

    if( slock_attr) lck_attr_free(slock_attr);
    if( slock_grp) lck_grp_free(slock_grp);
    if( slock_grp_attr) lck_grp_attr_free(slock_grp_attr);
}





/**
 * iwl3945_tx_queue_update_write_ptr - Send new write index to hardware
 */
int darwin_iwi3945::tx_queue_update_write_ptr(struct iwl3945_tx_queue *txq)
{
	u32 reg = 0;
	int rc = 0;
	int txq_id = txq->q.id;
    
	if (txq->need_update == 0)
		return rc;
    
	/* if we're trying to save power */
	if (isset(&status, STATUS_POWER_PMI)) {
		/* wake up nic if it's powered down ...
		 * uCode will wake up, and interrupt us again, so next
		 * time we'll skip this part. */
		reg = read32(CSR_UCODE_DRV_GP1);
        
		if (reg & CSR_UCODE_DRV_GP1_BIT_MAC_SLEEP) {
			IWL_DEBUG_INFO("Requesting wakeup, GP1 = 0x%x\n", reg);
			set_bit(CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
			return rc;
		}
        
		/* restore this queue's parameters in nic hardware. */
		rc = grab_nic_access();
		if (rc)
			return rc;
		write_direct32(HBUS_TARG_WRPTR, txq->q.write_ptr | (txq_id << 8));
		release_nic_access();
        
        /* else not in power-save mode, uCode will never sleep when we're
         * trying to tx (during RFKILL, we're not trying to tx). */
	} else
		write32(HBUS_TARG_WRPTR, txq->q.write_ptr | (txq_id << 8));
    
	txq->need_update = 0;
    
	return rc;
}


/**
 * iwl3945_clear_stations_table - Clear the driver's station table
 *
 * NOTE:  This does not clear or otherwise alter the device's station table.
 */
void darwin_iwi3945::clear_stations_table()
{
	unsigned long flags;
    
    //lck_spin_lock(slock_sta);
    
	num_stations = 0;
	memset(stations, 0, sizeof(stations));

    //lck_spin_unlock(slock_sta);
}



int darwin_iwi3945::scan_initiate()
{
	if (iw_mode == IEEE80211_IF_TYPE_AP) {
		IWL_ERROR("APs don't scan.\n");
		return 0;
	}
    
	if (!is_ready_rf()) {
		IWL_DEBUG_SCAN("Aborting scan due to not ready.\n");
		return -EIO;
	}
    
	if (isset(&status, STATUS_SCANNING)) {
		IWL_DEBUG_SCAN("Scan already in progress.\n");
		return -EAGAIN;
	}
    
	if (isset(&status, STATUS_SCAN_ABORTING)) {
		IWL_DEBUG_SCAN("Scan request while abort pending.  "
                       "Queuing.\n");
		return -EAGAIN;
	}
    
	IWL_DEBUG_INFO("Starting scan...\n");
	scan_bands = 2;
	setbit(&status, STATUS_SCANNING);
	scan_start = jiffies;
	scan_pass_start = scan_start;
    
	//queue_work(priv->workqueue, &priv->request_scan);
    queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::request_scan),NULL,NULL,false);

    
	return 0;
}





#pragma mark -
#pragma mark EEPROM routines


/**
 * iwl3945_load_bsm - Load bootstrap instructions
 *
 * BSM operation:
 *
 * The Bootstrap State Machine (BSM) stores a short bootstrap uCode program
 * in special SRAM that does not power down during RFKILL.  When powering back
 * up after power-saving sleeps (or during initial uCode load), the BSM loads
 * the bootstrap program into the on-board processor, and starts it.
 *
 * The bootstrap program loads (via DMA) instructions and data for a new
 * program from host DRAM locations indicated by the host driver in the
 * BSM_DRAM_* registers.  Once the new program is loaded, it starts
 * automatically.
 *
 * When initializing the NIC, the host driver points the BSM to the
 * "initialize" uCode image.  This uCode sets up some internal data, then
 * notifies host via "initialize alive" that it is complete.
 *
 * The host then replaces the BSM_DRAM_* pointer values to point to the
 * normal runtime uCode instructions and a backup uCode data cache buffer
 * (filled initially with starting data values for the on-board processor),
 * then triggers the "initialize" uCode to load and launch the runtime uCode,
 * which begins normal operation.
 *
 * When doing a power-save shutdown, runtime uCode saves data SRAM into
 * the backup data cache in DRAM before SRAM is powered down.
 *
 * When powering back up, the BSM loads the bootstrap program.  This reloads
 * the runtime uCode instructions and the backup data cache into SRAM,
 * and re-launches the runtime uCode from where it left off.
 */
int darwin_iwi3945::load_bsm()
{
	__le32 *image = ucode_boot.v_addr;
	u32 len = ucode_boot.len;
	dma_addr_t pinst;
	dma_addr_t pdata;
	u32 inst_len;
	u32 data_len;
	int rc;
	int i;
	u32 done;
	u32 reg_offset;
    
	IWL_DEBUG_INFO("Begin load bsm\n");
    
	/* make sure bootstrap program is no larger than BSM's SRAM size */
	if (len > IWL_MAX_BSM_SIZE)
		return -EINVAL;
    
	/* Tell bootstrap uCode where to find the "Initialize" uCode
	 *   in host DRAM ... host DRAM physical address bits 31:0 for 3945.
	 * NOTE:  iwl3945_initialize_alive_start() will replace these values,
	 *        after the "initialize" uCode has run, to point to
	 *        runtime/protocol instructions and backup data cache. */
	pinst = ucode_init.p_addr;
	pdata = ucode_init_data.p_addr;
	inst_len = ucode_init.len;
	data_len = ucode_init_data.len;
    
	rc = grab_nic_access();
	if (rc)
		return rc;
    
	write_prph(BSM_DRAM_INST_PTR_REG, pinst);
	write_prph(BSM_DRAM_DATA_PTR_REG, pdata);
	write_prph(BSM_DRAM_INST_BYTECOUNT_REG, inst_len);
	write_prph(BSM_DRAM_DATA_BYTECOUNT_REG, data_len);
    
	/* Fill BSM memory with bootstrap instructions */
	for (reg_offset = BSM_SRAM_LOWER_BOUND;
	     reg_offset < BSM_SRAM_LOWER_BOUND + len;
	     reg_offset += sizeof(u32), image++)
		write_prph(reg_offset, le32_to_cpu(*image));
    
	rc = verify_bsm();
	if (rc) {
		release_nic_access();
		return rc;
	}
    
	/* Tell BSM to copy from BSM SRAM into instruction SRAM, when asked */
	write_prph(BSM_WR_MEM_SRC_REG, 0x0);
	write_prph(BSM_WR_MEM_DST_REG, RTC_INST_LOWER_BOUND);
	write_prph(BSM_WR_DWCOUNT_REG, len / sizeof(u32));
    
	/* Load bootstrap code into instruction SRAM now,
	 *   to prepare to load "initialize" uCode */
	write_prph(BSM_WR_CTRL_REG, BSM_WR_CTRL_REG_BIT_START);
    
	/* Wait for load of bootstrap uCode to finish */
	for (i = 0; i < 100; i++) {
		done = read_prph(BSM_WR_CTRL_REG);
		if (!(done & BSM_WR_CTRL_REG_BIT_START))
			break;
		udelay(10);
	}
	if (i < 100)
		IWL_DEBUG_INFO("BSM write complete, poll %d iterations\n", i);
	else {
		IWL_ERROR("BSM write did not complete!\n");
		return -EIO;
	}
    
	/* Enable future boot loads whenever power management unit triggers it
	 *   (e.g. when powering back up after power-save shutdown) */
	write_prph(BSM_WR_CTRL_REG, BSM_WR_CTRL_REG_BIT_START_EN);
    
	release_nic_access();
    
	return 0;
}



/* check contents of special bootstrap uCode SRAM */
int darwin_iwi3945::verify_bsm()
{
	__le32 *image = ucode_boot.v_addr;
	u32 len = ucode_boot.len;
	u32 reg;
	u32 val;
    
	IWL_DEBUG_INFO("Begin verify bsm\n");
    
	/* verify BSM SRAM contents */
	val = read_prph(BSM_WR_DWCOUNT_REG);
	for (reg = BSM_SRAM_LOWER_BOUND;
	     reg < BSM_SRAM_LOWER_BOUND + len;
	     reg += sizeof(u32), image ++) {
		val = read_prph(reg);
		if (val != le32_to_cpu(*image)) {
			IWL_ERROR("BSM uCode verification failed at "
                      "addr 0x%08X+%u (of %u), is 0x%x, s/b 0x%x\n",
                      BSM_SRAM_LOWER_BOUND,
                      reg - BSM_SRAM_LOWER_BOUND, len,
                      val, le32_to_cpu(*image));
			return -EIO;
		}
	}
    
	IWL_DEBUG_INFO("BSM bootstrap uCode image OK\n");
    
	return 0;
}


void darwin_iwi3945::nic_start()
{
	/* Remove all resets to allow NIC to operate */
	write32(CSR_RESET, 0);
}






inline void darwin_iwi3945::disable_interrupts(void)
{
	clear_bit(STATUS_INT_ENABLED, status);
    
	/* disable interrupts from uCode/NIC to host */
    write32(CSR_INT_MASK, 0x00000000);
    
	/* acknowledge/clear/reset any interrupts still pending
	 * from uCode or flow handler (Rx/Tx DMA) */
    write32(CSR_INT, 0xffffffff);
    write32(CSR_FH_INT_STATUS, 0xffffffff);
	IWL_DEBUG_ISR("Disabled interrupts\n");
}



inline void darwin_iwi3945::enable_interrupts()
{
//    IWL_DEBUG_ISR("Enabling interrupts\n");
    set_bit(STATUS_INT_ENABLED, status);
    write32(CSR_INT_MASK, CSR_INI_SET_MASK);
}








/*
 * Clear the OWNER_MSK, to establish driver (instead of uCode running on
 * embedded controller) as EEPROM reader; each read is a series of pulses
 * to/from the EEPROM chip, not a single event, so even reads could conflict
 * if they weren't arbitrated by some ownership mechanism.  Here, the driver
 * simply claims ownership, which should be safe when this function is called
 * (i.e. before loading uCode!).
 */
inline int darwin_iwi3945::eeprom_acquire_semaphore()
{
    _ipw_write32(memBase, CSR_EEPROM_GP, _ipw_read32(memBase, CSR_EEPROM_GP) & ~CSR_EEPROM_GP_IF_OWNER_MSK);
    return 0;
}



inline void darwin_iwi3945::get_eeprom_mac(u8 *mac)
{
	memcpy(mac, eeprom.mac_address, 6);
}




/**
 * iwl3945_eeprom_init - read EEPROM contents
 *
 * Load the EEPROM contents from adapter into priv->eeprom
 *
 * NOTE:  This routine uses the non-debug IO access functions.
 */
int darwin_iwi3945::eeprom_init(void)
{
	u16 *e = (u16 *)&eeprom;
	u32 gp = read32(CSR_EEPROM_GP);
	u32 r;
	int sz = sizeof(eeprom);
	int rc;
	int i;
	u16 addr;
    
	/* The EEPROM structure has several padding buffers within it
	 * and when adding new EEPROM maps is subject to programmer errors
	 * which may be very difficult to identify without explicitly
	 * checking the resulting size of the eeprom map. */
	if( (sizeof(eeprom) != IWL_EEPROM_IMAGE_SIZE) ) {
        IWL_ERROR("EEPROM does not have correct size\n");
        return -1;
    }
    
	if ((gp & CSR_EEPROM_GP_VALID_MSK) == CSR_EEPROM_GP_BAD_SIGNATURE) {
		IWL_ERROR("EEPROM not found, EEPROM_GP=0x%08x", gp);
		return -ENOENT;
	}
    
	/* Make sure driver (instead of uCode) is allowed to read EEPROM */
	rc = eeprom_acquire_semaphore();
	if (rc < 0) {
		IWL_ERROR("Failed to acquire EEPROM semaphore.\n");
		return -ENOENT;
	}
    
	/* eeprom is an array of 16bit values */
	for (addr = 0; addr < sz; addr += sizeof(u16)) {
		_ipw_write32(memBase, CSR_EEPROM_REG, addr << 1);
		_ipw_write32(memBase, CSR_EEPROM_REG, _ipw_read32(memBase, CSR_EEPROM_REG_BIT_CMD) & ~CSR_EEPROM_REG_BIT_CMD);
        
		for (i = 0; i < IWL_EEPROM_ACCESS_TIMEOUT;
             i += IWL_EEPROM_ACCESS_DELAY) {
			r = _ipw_read32(memBase, CSR_EEPROM_REG);
			if (r & CSR_EEPROM_REG_READ_VALID_MSK)
				break;
			udelay(IWL_EEPROM_ACCESS_DELAY);
		}
        
		if (!(r & CSR_EEPROM_REG_READ_VALID_MSK)) {
			IWL_ERROR("Time out reading EEPROM[%d]", addr);
			return -ETIMEDOUT;
		}
		e[addr / 2] = le16_to_cpu(r >> 16);
	}
    
	return 0;
}





#pragma mark -
#pragma mark Setup routines
/**
 * iwl3945_set_rxon_channel - Set the phymode and channel values in staging RXON
 * @phymode: MODE_IEEE80211A sets to 5.2GHz; all else set to 2.4GHz
 * @channel: Any channel valid for the requested phymode
 
 * In addition to setting the staging RXON, priv->phymode is also set.
 *
 * NOTE:  Does not commit to the hardware; it sets appropriate bit fields
 * in the staging RXON flag structure based on the phymode
 */
int darwin_iwi3945::set_rxon_channel(u8 new_phymode, u16 channel)
{
	if (!get_channel_info(new_phymode, channel)) {
		IWL_DEBUG_INFO("Could not set channel to %d [%d]\n",
                       channel, new_phymode);
		return -EINVAL;
	}
    
	if ((le16_to_cpu(staging_rxon.channel) == channel) &&
	    (phymode == new_phymode))
		return 0;
    
	staging_rxon.channel = cpu_to_le16(channel);
	if (new_phymode == MODE_IEEE80211A)
		staging_rxon.flags &= ~RXON_FLG_BAND_24G_MSK;
	else
		staging_rxon.flags |= RXON_FLG_BAND_24G_MSK;
    
	phymode = new_phymode;
    
	IWL_DEBUG_INFO("Staging channel set to %d [%d]\n", channel, new_phymode);
    
	return 0;
}



void darwin_iwi3945::setup_deferred_work() {
#warning XXX Fill this in, perhaps, if it's needed
    return;
}


/**
 * iwl3945_setup_rx_handlers - Initialize Rx handler callbacks
 *
 * Setup the RX handlers for each of the reply types sent from the uCode
 * to the host.
 *
 * This function chains into the hardware specific files for them to setup
 * any hardware specific handlers as well.
 */
void darwin_iwi3945::setup_rx_handlers()
{
    /*
	rx_handlers[REPLY_ALIVE] = rx_reply_alive;
	rx_handlers[REPLY_ADD_STA] = rx_reply_add_sta;
	rx_handlers[REPLY_ERROR] = rx_reply_error;
	rx_handlers[CHANNEL_SWITCH_NOTIFICATION] = rx_csa;
	rx_handlers[SPECTRUM_MEASURE_NOTIFICATION] = rx_spectrum_measure_notif;
	rx_handlers[PM_SLEEP_NOTIFICATION] = rx_pm_sleep_notif;
	rx_handlers[PM_DEBUG_STATISTIC_NOTIFIC] = rx_pm_debug_statistics_notif;
	rx_handlers[BEACON_NOTIFICATION] = rx_beacon_notif;
    */
	/*
	 * The same handler is used for both the REPLY to a discrete
	 * statistics request from the host as well as for the periodic
	 * statistics notifications (after received beacons) from the uCode.
	 */
    /*
	rx_handlers[REPLY_STATISTICS_CMD] = hw_rx_statistics;
	rx_handlers[STATISTICS_NOTIFICATION] = hw_rx_statistics;
    
	rx_handlers[REPLY_SCAN_CMD] = rx_reply_scan;
	rx_handlers[SCAN_START_NOTIFICATION] = rx_scan_start_notif;
	rx_handlers[SCAN_RESULTS_NOTIFICATION] = rx_scan_results_notif;
	rx_handlers[SCAN_COMPLETE_NOTIFICATION] = rx_scan_complete_notif;
	rx_handlers[CARD_STATE_NOTIFICATION] = rx_card_state_notif;
	rx_handlers[REPLY_TX] = rx_reply_tx;
    */
	/* Set up hardware specific Rx handlers */
	//hw_rx_handler_setup();
}



int darwin_iwi3945::power_init_handle()
{
	int rc = 0, i;
	struct iwl3945_power_mgr *pow_data;
	int size = sizeof(struct iwl3945_power_vec_entry) * IWL_POWER_AC;
	u16 pci_pm;
    
	IWL_DEBUG_POWER("Initialize power \n");
    
	pow_data = &power_data;
    
	memset(pow_data, 0, sizeof(*pow_data));
    
	pow_data->active_index = IWL_POWER_RANGE_0;
	pow_data->dtim_val = 0xffff;
    
	memcpy(&pow_data->pwr_range_0[0], &range_0[0], size);
	memcpy(&pow_data->pwr_range_1[0], &range_1[0], size);
    
    pci_pm = fPCIDevice->configRead32(PCI_LINK_CTRL);

    struct iwl3945_powertable_cmd *cmd;
    
    IWL_DEBUG_POWER("adjust power command flags\n");
    
    for (i = 0; i < IWL_POWER_AC; i++) {
        cmd = &pow_data->pwr_range_0[i].cmd;
        
        if (pci_pm & 0x1)
            cmd->flags &= ~IWL_POWER_PCI_PM_MSK;
        else
            cmd->flags |= IWL_POWER_PCI_PM_MSK;
    }
    return 0;
}




int darwin_iwi3945::nic_set_pwr_src(int pwr_max)
{
    int rc;
    unsigned long flags;
    
    //lck_spin_lock(slock);
    rc = grab_nic_access();
    if (rc) {
        //lck_spin_unlock(slock);
        return rc;
    }
    
    if (!pwr_max) {
        u32 val;
        
        val = fPCIDevice->configRead32(PCI_POWER_SOURCE);
        if (val & PCI_CFG_PMC_PME_FROM_D3COLD_SUPPORT) {
            set_bits_mask_prph(APMG_PS_CTRL_REG,
                                       APMG_PS_CTRL_VAL_PWR_SRC_VAUX,
                                       ~APMG_PS_CTRL_MSK_PWR_SRC);
            release_nic_access();
            
            poll_bit(CSR_GPIO_IN,
                             CSR_GPIO_IN_VAL_VAUX_PWR_SRC,
                             CSR_GPIO_IN_BIT_AUX_POWER, 5000);
        } else
            release_nic_access();
    } else {
        set_bits_mask_prph(APMG_PS_CTRL_REG,
                                   APMG_PS_CTRL_VAL_PWR_SRC_VMAIN,
                                   ~APMG_PS_CTRL_MSK_PWR_SRC);
        
        release_nic_access();
        poll_bit(CSR_GPIO_IN, CSR_GPIO_IN_VAL_VMAIN_PWR_SRC,
                         CSR_GPIO_IN_BIT_AUX_POWER, 5000);  /* uS */
    }
    //lck_spin_unlock(slock);
    
    return rc;
}






int darwin_iwi3945::hw_nic_init()
{
	u8 rev_id;
	int rc;
	unsigned long flags;
    
	power_init_handle();
    
    //lck_spin_lock(slock);
	set_bit(CSR_ANA_PLL_CFG, (1 << 24));
	set_bit(CSR_GIO_CHICKEN_BITS,
                    CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX);
    
	set_bit(CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_INIT_DONE);
	rc = poll_bit(CSR_GP_CNTRL,
                          CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
                          CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY, 25000);
	if (rc < 0) {
        //lck_spin_unlock(slock);
		IWL_DEBUG_INFO("Failed to init the card\n");
		return rc;
	}
    
	rc = grab_nic_access();
	if (rc) {
        //lck_spin_unlock(slock);
		return rc;
	}
	write_prph(APMG_CLK_EN_REG,
                       APMG_CLK_VAL_DMA_CLK_RQT |
                       APMG_CLK_VAL_BSM_CLK_RQT);
	udelay(20);
	set_bits_prph(APMG_PCIDEV_STT_REG,
                          APMG_PCIDEV_STT_VAL_L1_ACT_DIS);
	release_nic_access();
    //lck_spin_lock(slock);
    
	/* Determine HW type */
    rev_id = fPCIDevice->configRead8(kIOPCIConfigRevisionID);
	IWL_DEBUG_INFO("HW Revision ID = 0x%X\n", rev_id);
    
	nic_set_pwr_src(1);
    //lck_spin_lock(slock);
    
	if (rev_id & PCI_CFG_REV_ID_BIT_RTP)
		IWL_DEBUG_INFO("RTP type \n");
	else if (rev_id & PCI_CFG_REV_ID_BIT_BASIC_SKU) {
		IWL_DEBUG_INFO("ALM-MB type\n");
		set_bit(CSR_HW_IF_CONFIG_REG,
                        CSR_HW_IF_CONFIG_REG_BIT_ALMAGOR_MB);
	} else {
		IWL_DEBUG_INFO("ALM-MM type\n");
		set_bit(CSR_HW_IF_CONFIG_REG,
                        CSR_HW_IF_CONFIG_REG_BIT_ALMAGOR_MM);
	}
    
	if (EEPROM_SKU_CAP_OP_MODE_MRC == eeprom.sku_cap) {
		IWL_DEBUG_INFO("SKU OP mode is mrc\n");
		set_bit(CSR_HW_IF_CONFIG_REG, CSR_HW_IF_CONFIG_REG_BIT_SKU_MRC);
	} else
		IWL_DEBUG_INFO("SKU OP mode is basic\n");
    
	if ((eeprom.board_revision & 0xF0) == 0xD0) {
		IWL_DEBUG_INFO("3945ABG revision is 0x%X\n", eeprom.board_revision);
		set_bit(CSR_HW_IF_CONFIG_REG, CSR_HW_IF_CONFIG_REG_BIT_BOARD_TYPE);
	} else {
		IWL_DEBUG_INFO("3945ABG revision is 0x%X\n", eeprom.board_revision);
		clear_bit(CSR_HW_IF_CONFIG_REG, CSR_HW_IF_CONFIG_REG_BIT_BOARD_TYPE);
	}
    
	if (eeprom.almgor_m_version <= 1) {
		set_bit(CSR_HW_IF_CONFIG_REG, CSR_HW_IF_CONFIG_REG_BITS_SILICON_TYPE_A);
		IWL_DEBUG_INFO("Card M type A version is 0x%X\n", eeprom.almgor_m_version);
	} else {
		IWL_DEBUG_INFO("Card M type B version is 0x%X\n", eeprom.almgor_m_version);
		set_bit(CSR_HW_IF_CONFIG_REG, CSR_HW_IF_CONFIG_REG_BITS_SILICON_TYPE_B);
	}
    //lck_spin_unlock(slock);
    
	if (eeprom.sku_cap & EEPROM_SKU_CAP_SW_RF_KILL_ENABLE)
		IWL_DEBUG_RF_KILL("SW RF KILL supported in EEPROM.\n");
    
	if (eeprom.sku_cap & EEPROM_SKU_CAP_HW_RF_KILL_ENABLE)
		IWL_DEBUG_RF_KILL("HW RF KILL supported in EEPROM.\n");
    
	/* Allocate the RX queue, or reset if it is already allocated */
	if (!rxq.bd) {
		rc = rx_queue_alloc();
		if (rc) {
			IWL_ERROR("Unable to initialize Rx queue\n");
			return -ENOMEM;
		}
	} else
		rx_queue_reset();
    
	rx_replenish();
    
	rx_init();
    
    //lck_spin_lock(slock);
    
	/* Look at using this instead:
     rxq->need_update = 1;
     iwl3945_rx_queue_update_write_ptr(priv, rxq);
     */
    
	rc = grab_nic_access();
	if (rc) {
		//lck_spin_unlock(slock);
		return rc;
	}
	write_direct32(FH_RCSR_WPTR(0), rxq.write & ~7);
	release_nic_access();
    
    //lck_spin_unlock(slock);
    
	rc = txq_ctx_reset();
	if (rc)
		return rc;
    
	setbit(&status, STATUS_INIT);
	return 0;
}



/* Called when initializing driver */
int darwin_iwi3945::hw_set_hw_setting()
{
    memset((void *)&hw_setting, 0,
           sizeof(struct iwl3945_driver_hw_info));
    
    hw_setting.shared_virt =
        IOMallocContiguous(sizeof(struct iwl3945_shared), sizeof(__le32),
                &(hw_setting.shared_phys));

    IOLog("-----> Allocated HW shared memory at 0x%08x (0x%08x)\n",
            hw_setting.shared_virt, hw_setting.shared_phys);
    //pci_alloc_consistent(priv->pci_dev,
    //                     sizeof(struct iwl3945_shared),
    //                     &priv->hw_setting.shared_phys);
    
    if (!hw_setting.shared_virt) {
        IWL_ERROR("failed to allocate pci memory\n");
//        IOLockUnlock(mutex);
        return -ENOMEM;
    }
    
    hw_setting.ac_queue_count = AC_NUM;
    hw_setting.rx_buffer_size = IWL_RX_BUF_SIZE;
    hw_setting.tx_cmd_len = sizeof(struct iwl3945_tx_cmd);
    hw_setting.max_rxq_size = RX_QUEUE_SIZE;
    hw_setting.max_rxq_log = RX_QUEUE_SIZE_LOG;
    hw_setting.max_stations = IWL3945_STATION_COUNT;
    hw_setting.bcast_sta_id = IWL3945_BROADCAST_ID;
    return 0;
}




void darwin_iwi3945::unset_hw_setting()
{
	if (hw_setting.shared_virt)
        IOFreeContiguous( hw_setting.shared_virt, sizeof(struct iwl3945_shared) );
}







#pragma mark -
#pragma mark Teardown routines

void darwin_iwi3945::cancel_deferred_work()
{
    /*
	iwl3945_hw_cancel_deferred_work(priv);
    
	cancel_delayed_work(&priv->init_alive_start);
	cancel_delayed_work(&priv->scan_check);
	cancel_delayed_work(&priv->alive_start);
	cancel_delayed_work(&priv->post_associate);
	cancel_work_sync(&priv->beacon_update);
     */
}






#pragma mark -
#pragma mark System entry points

#define MAX_HW_RESTARTS 5

int darwin_iwi3945::up()
{
	int rc, i;
    
	if (isset(&status, STATUS_EXIT_PENDING)) {
		IWL_WARNING("Exit pending; will not bring the NIC up\n");
		return -EIO;
	}
    
	if (isset(&status, STATUS_RF_KILL_SW)) {
		IWL_WARNING("Radio disabled by SW RF kill (module "
                    "parameter)\n");
		return -ENODEV;
	}
    
	/* If platform's RF_KILL switch is NOT set to KILL */
	if (read32(CSR_GP_CNTRL) &
        CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW)
		clrbit(&status, STATUS_RF_KILL_HW);
	else {
		setbit(&status, STATUS_RF_KILL_HW);
		if (!isset(&status, STATUS_IN_SUSPEND)) {
			IWL_WARNING("Radio disabled by HW RF Kill switch\n");
			return -ENODEV;
		}
	}
    
	write32(CSR_INT, 0xFFFFFFFF);
    
	rc = hw_nic_init();
	if (rc) {
		IWL_ERROR("Unable to int nic\n");
		return rc;
	}
    
	/* make sure rfkill handshake bits are cleared */
	write32(CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	write32(CSR_UCODE_DRV_GP1_CLR,
                    CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);
    
	/* clear (again), then enable host interrupts */
	write32(CSR_INT, 0xFFFFFFFF);
	enable_interrupts();
    
	/* really make sure rfkill handshake bits are cleared */
	write32(CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	write32(CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
    
	/* Copy original ucode data image from disk into backup cache.
	 * This will be used to initialize the on-board processor's
	 * data SRAM for a clean start when the runtime program first loads. */
	memcpy(ucode_data_backup.v_addr, ucode_data.v_addr, ucode_data.len);
    
	/* We return success when we resume from suspend and rf_kill is on. */
	if (isset(&status, STATUS_RF_KILL_HW))
		return 0;
    
	for (i = 0; i < MAX_HW_RESTARTS; i++) {
        
		clear_stations_table();
        
		/* load bootstrap state machine,
		 * load bootstrap program into processor's memory,
		 * prepare to load the "initialize" uCode */
		rc = load_bsm();
        
		if (rc) {
			IWL_ERROR("Unable to set up bootstrap uCode: %d\n", rc);
			continue;
		}
        
		/* start card; "initialize" will load runtime ucode */
		nic_start();
        
		IWL_DEBUG_INFO("iwi3945 is coming up\n");
        
		return 0;
	}
    
	setbit(&status, STATUS_EXIT_PENDING);
	down();
    
	/* tried to restart and config the device for as long as our
	 * patience could withstand */
	IWL_ERROR("Unable to initialize device after %d attempts.\n", i);
	return -EIO;
}



void darwin_iwi3945::down()
{
	unsigned long flags;
	int exit_pending = isset(&status, STATUS_EXIT_PENDING);
	struct ieee80211_conf *conf = NULL;
    
#if 0
	IWL_DEBUG_INFO("iwi3945 is going down\n");
    
	conf = ieee80211_get_hw_conf(hw);
    
	if (!exit_pending)
		setbit(&status, STATUS_EXIT_PENDING);
    
	clear_stations_table();
    
	/* Unblock any waiting calls */
	wake_up_interruptible_all(wait_command_queue);
    
	/* Wipe out the EXIT_PENDING status bit if we are not actually
	 * exiting the module */
	if (!exit_pending)
		clrbit(&status, STATUS_EXIT_PENDING);
    
	/* stop and reset the on-board processor */
	write32(CSR_RESET, CSR_RESET_REG_FLAG_NEVO_RESET);
    
	/* tell the device to stop sending interrupts */
	disable_interrupts();
    
	if (mac80211_registered)
		ieee80211_stop_queues(hw);
    
	/* If we have not previously called iwl3945_init() then
	 * clear all bits but the RF Kill and SUSPEND bits and return */
	if (!is_init()) {
		status = isset(&status, STATUS_RF_KILL_HW) <<
        STATUS_RF_KILL_HW |
        isset(&status, STATUS_RF_KILL_SW) <<
        STATUS_RF_KILL_SW |
        isset(&status, STATUS_IN_SUSPEND) <<
        STATUS_IN_SUSPEND;
		goto exit;
	}
    
	/* ...otherwise clear out all the status bits but the RF Kill and
	 * SUSPEND bits and continue taking the NIC down. */
	status &= isset(&status, STATUS_RF_KILL_HW) <<
    STATUS_RF_KILL_HW |
    isset(&status, STATUS_RF_KILL_SW) <<
    STATUS_RF_KILL_SW |
    isset(&status, STATUS_IN_SUSPEND) <<
    STATUS_IN_SUSPEND |
    isset(&status, STATUS_FW_ERROR) <<
    STATUS_FW_ERROR;
    
    //lck_spin_lock(slock);
	clear_bit(CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
	//lck_spin_unlock(slock);
    
	hw_txq_ctx_stop();
	hw_rxq_stop();
    
    //lck_spin_lock(slock);
	if (!grab_nic_access()) {
		write_prph(APMG_CLK_DIS_REG,
                           APMG_CLK_VAL_DMA_CLK_RQT);
		release_nic_access();
	}
    //lck_spin_unlock(slock);
    
	udelay(5);
    
	hw_nic_stop_master();
	set_bit(CSR_RESET, CSR_RESET_REG_FLAG_SW_RESET);
	hw_nic_reset();
    
exit:
	memset(&card_alive, 0, sizeof(struct iwl3945_alive_resp));
    
	if (ibss_beacon)
		dev_kfree_skb(ibss_beacon);
	ibss_beacon = NULL;
    
	/* clear out any free frames */
	clear_free_frames();
    
#endif
}




/*-------------------------------------------------------------------------
 * Called by IOEthernetInterface client to enable the controller.
 * This method is always called while running on the default workloop thread.
 *-------------------------------------------------------------------------*/

IOReturn darwin_iwi3945::enable( IONetworkInterface* netif )
{
	IOLog("darwin_iwi3945::enable()\n");
    
    /* If an interface client has previously enabled us,	*/
    /* and we know there can only be one interface client	*/
    /* for this driver, then simply return true.			*/
    
    /*
    if ( netifEnabled )
    {
        IOLog( "EtherNet(UniN): already enabled\n" );
        return kIOReturnSuccess;
    }
    
    if ( (fReady == false) && !wakeUp( false ) )
        return kIOReturnIOError;
    
    netifEnabled = true;	// Mark the controller as enabled by the interface.
    */
    
    
    /* Start our IOOutputQueue object:	*/
    fTransmitQueue->setCapacity( 1024 );
    fTransmitQueue->start();
    
    return kIOReturnSuccess;
}/* end enable netif */


/*-------------------------------------------------------------------------
 * Called by IOEthernetInterface client to disable the controller.
 * This method is always called while running on the default workloop
 * thread.
 *-------------------------------------------------------------------------*/

IOReturn darwin_iwi3945::disable( IONetworkInterface* /*netif*/ )
{
#if USE_ELG
    ///	if ( (fpELG->evLogFlag == 0) || (fpELG->evLogFlag == 0xFEEDBEEF) )
    ///	fpELG->evLogFlag = 0xDEBEEFED;
#endif // USE_ELG
    IOLog("darwin_iwi3945::disable()\n");
    
    /* Disable our IOOutputQueue object. This will prevent the
     * outputPacket() method from being called.
     */
    
    fTransmitQueue->stop();
    
    fTransmitQueue->setCapacity( 0 );
    fTransmitQueue->flush();	/* Flush all packets currently in the output queue.	*/
    
    /* If we have no active clients, then disable the controller.	*/
    /*
	if ( debugEnabled == false )
		putToSleep( false );
    
    netifEnabled = false;
    */
    return kIOReturnSuccess;
}/* end disable netif */


/*
SInt32 darwin_iwi3945::apple80211_ioctl(
                                        IO80211Interface *interface, 
                                        ifnet_t ifn, 
                                        u_int32_t cmd, 
                                        void *data)
{
    IOLog("darwin_iwi3945::apple80211_ioctl(%d, %d, %p)\n", ifn, cmd, data);
    return super::apple80211_ioctl(interface, ifn, cmd, data);
}*/


/*
bool darwin_iwi3945::configureInterface( IONetworkInterface *netif )
{
    IOLog("darwin_iwi3945::configureInterface()\n");
    return super::configureInterface(netif);
}
 */

IOReturn darwin_iwi3945::getHardwareAddress(IOEthernetAddress *addr)
{
    IOLog("darwin_iwi3945::getHardwareAddress() entering\n");
	bcopy(eeprom.mac_address, addr->bytes, sizeof(addr->bytes));
    IOLog("darwin_iwi3945::getHardwareAddress() leaving\n");
    return kIOReturnSuccess;
}

IO80211Interface *darwin_iwi3945::getNetworkInterface()
{
    IOLog("darwin_iwi3945::getNetworkInterface()\n");
    return super::getNetworkInterface();
}


IOService * darwin_iwi3945::getProvider() {
    IOLog("darwin_iwi3945::getProvider()\n");
    return super::getProvider();
}

IOOutputQueue *darwin_iwi3945::getOutputQueue() const {
    IOLog("Getting output queue\n");
    return fTransmitQueue;
}



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







#pragma mark -
#pragma mark Driver entry points



bool darwin_iwi3945::start(IOService *provider)
{
	UInt16	reg;
    IOLog("iwi3945: Starting\n");
    int err = 0;
    
	do {
        
        // Note: super::start() calls createWorkLoop & getWorkLoop
		if ( super::start(provider) == 0) {
			IOLog("%s ERR: super::start failed\n", getName());
			break;
		}
        
		if ( (fPCIDevice = OSDynamicCast(IOPCIDevice, provider)) == 0) {
			IOLog("%s ERR: fPCIDevice == 0 :(\n", getName());
			break;
		}
        

        if( !initialize_spinlocks() ) {
            IOLog("%s ERR: Unable to initialize spinlocks\n", getName());
            break;
        }
        

        if( !(mutex = IOLockAlloc()) ) {
            IOLog("%s ERR: Unable to allocate mutex\n", getName());
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
            IOLog("%s Couldn't request power state\n", getName());
            break;
        }
        
		fPCIDevice->setBusMasterEnable(true);
		fPCIDevice->setMemoryEnable(true);
		//fPCIDevice->setIOEnable(true);    // Disabled, as we use memory-mapped IO
		
        // Grab various pieces of interesting information.
		irqNumber   = fPCIDevice->configRead8(kIOPCIConfigInterruptLine);
		vendorID    = fPCIDevice->configRead16(kIOPCIConfigVendorID);
		deviceID    = fPCIDevice->configRead16(kIOPCIConfigDeviceID);		
		pciReg      = fPCIDevice->configRead16(kIOPCIConfigRevisionID);
        
        
		// We disable the RETRY_TIMEOUT register (0x41) to keep
        // PCI Tx retries from interfering with C3 CPU state
		reg = fPCIDevice->configRead16(0x40);
		if((reg & 0x0000ff00) != 0)
			fPCIDevice->configWrite16(0x40, reg & 0xffff00ff);
        
        
#warning Determine if it's an ABG card here.  It's an ABG card if the PCI id is not 0x422210(05|32|14|44)
        
        
        
        
        // Allocate a memory map used to communicate with the card.
  		map = fPCIDevice->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0, kIOMapInhibitCache);
  		if (map == 0) {
			IOLog("%s map is zero\n", getName());
            break;
		}
                
		ioBase = map->getPhysicalAddress();
		memBase = (UInt16 *)map->getVirtualAddress();
		
#warning Is any of this memory information really necessary?
        //memDes = map->getMemoryDescriptor();
		//mem = fPCIDevice->getDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0);
		
		//memDes->initWithPhysicalAddress(ioBase, map->getLength(), kIODirectionOutIn);
        
		IOLog("%s iomemory length: 0x%x @ 0x%x\n", getName(), map->getLength(), ioBase);
		IOLog("%s virt: 0x%x physical: 0x%x\n", getName(), memBase, ioBase);
		IOLog("%s IRQ: %d, Vendor ID: %04x, Product ID: %04x\n", getName(), irqNumber, vendorID, deviceID);
        
        if( hw_set_hw_setting() ) {
            IOLog("Unable to set the hw setting\n");
            return false;
        }
		
        
        set_rxon_channel(MODE_IEEE80211G, 6);
        setup_deferred_work();
        setup_rx_handlers();
        
        workqueue = (IOWorkLoop *) getWorkLoop();
        if (!workqueue) {
            IOLog("%s ERR: start - getWorkLoop failed\n", getName());
            break;
        }
        
        
        
		fInterruptSrc = IOInterruptEventSource::interruptEventSource(
                                                                     this, (IOInterruptEventAction) &darwin_iwi3945::interruptOccurred,
                                                                     provider);
		if(!fInterruptSrc || (workqueue->addEventSource(fInterruptSrc) != kIOReturnSuccess)) {
			IOLog("%s fInterruptSrc error\n", getName());
            break;
		}
		// This is important. If the interrupt line is shared with other devices,
		// then the interrupt vector will be enabled only if all corresponding
		// interrupt event sources are enabled. To avoid masking interrupts for
		// other devices that are sharing the interrupt line, the event source
		// is enabled immediately.
		fInterruptSrc->enable();
		
		
		fTransmitQueue = createOutputQueue();
		if (fTransmitQueue == NULL)
		{
			IWI_ERR("ERR: getOutputQueue()\n");
			break;
		}
		fTransmitQueue->setCapacity(1024);
        
        
        disable_interrupts();
		
        
        // Initialize the card
        set_bit(CSR_GIO_CHICKEN_BITS,
                        CSR_GIO_CHICKEN_BITS_REG_BIT_DIS_L0S_EXIT_TIMER);
        
        set_bit(CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_INIT_DONE);
        err = poll_bit(CSR_GP_CNTRL,
                               CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
                               CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY, 25000);
        if (err < 0) {
            IWL_DEBUG_INFO("Failed to init the card\n");
            break;
        }

        
        
        
        // Initialize the EEPROM
        err = eeprom_init();
        if (err) {
            IWL_ERROR("Unable to init EEPROM\n");
            break;
        }

        get_eeprom_mac(mac_addr);
        IOLog("MAC address: " MAC_FMT "\n", MAC_ARG(mac_addr));
        

        // Publish the MAC address
        if ( (setProperty(kIOMACAddress,  (void *) mac_addr,
                         kIOEthernetAddressSize) == false) )
        {
            IOLog("Couldn't set the kIOMACAddress property\n");
        }
        
        
        
        // Attach the IO80211Interface to this card.  This also creates a
        // new IO80211Interface, and stores the resulting object in fNetif.
		if (attachInterface((IONetworkInterface **) &fNetif, true) == false) {
			IOLog("%s attach failed\n", getName());
			break;
		}
//		fNetif->registerService();


		//ipw_sw_reset(1);
		//ipw_nic_init(priv);
		//ipw_nic_reset(priv);
		//ipw_bg_resume_work();
        
        
		
		
		mediumDict = OSDictionary::withCapacity(MEDIUM_TYPE_INVALID + 1);
		addMediumType(kIOMediumIEEE80211None,  0,  MEDIUM_TYPE_NONE);
		addMediumType(kIOMediumIEEE80211Auto,  0,  MEDIUM_TYPE_AUTO);
		addMediumType(kIOMediumIEEE80211DS1,   1000000, MEDIUM_TYPE_1MBIT);
		addMediumType(kIOMediumIEEE80211DS2,   2000000, MEDIUM_TYPE_2MBIT);
		addMediumType(kIOMediumIEEE80211DS5,   5500000, MEDIUM_TYPE_5MBIT);
		addMediumType(kIOMediumIEEE80211DS11, 11000000, MEDIUM_TYPE_11MBIT);
		addMediumType(kIOMediumIEEE80211,     54000000, MEDIUM_TYPE_54MBIT, "OFDM54");
		addMediumType(kIOMediumIEEE80211OptionAdhoc, 0, MEDIUM_TYPE_ADHOC,"ADHOC");
        
		publishMediumDictionary(mediumDict);
		setCurrentMedium(mediumTable[MEDIUM_TYPE_AUTO]);
		setSelectedMedium(mediumTable[MEDIUM_TYPE_AUTO]);
		setLinkStatus(kIONetworkLinkValid, mediumTable[MEDIUM_TYPE_AUTO]);
		
        IOLog("registerService()\n");
		registerService();
        
        
        
		//IW_SCAN_TYPE_ACTIVE
        /*
		queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan),NULL,NULL,false);
		queue_te(1,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_adapter_restart),NULL,NULL,false);
		queue_te(2,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_led_link_on),NULL,NULL,false);
		queue_te(3,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_rf_kill),NULL,NULL,false);
		queue_te(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan_check),NULL,NULL,false);
		queue_te(5,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_associate),NULL,NULL,false);
		queue_te(6,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_gather_stats),NULL,NULL,false);
		queue_te(7,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_rx_queue_replenish),NULL,NULL,false);
		queue_te(8,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_led_activity_off),NULL,NULL,false);
		queue_te(9,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_bg_alive_start),NULL,NULL,false);
        */

//        workqueue->runAction(OSMemberFunctionCast(IOWorkLoop::Action, this,
//                                                  &darwin_iwi3945::bg_up), (OSObject *)this, 0, 0, 0, 0);
        
        queue_te(12,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::bg_up),0,1000,true);


        

        
        IOLog("iwi3945: Successfully started\n");
        
		return true;			// end start successfully
	} while (false);
  

    free();
    
    
	return false;			// end start unsuccessfully
}





void darwin_iwi3945::free(void)
{
	IOLog("iwi3945: Freeing\n");


    if( fInterruptSrc ) fInterruptSrc->release();
    if( fTransmitQueue ) fTransmitQueue->release();

	if( fPCIDevice) {
        fPCIDevice->close(this);
        fPCIDevice->release();
    }
    

    destroy_spinlocks();

    super::free();
}

void darwin_iwi3945::stop(IOService *provider)
{
	IOLog("iwi3945: Stopping\n");


	if (fInterruptSrc && workqueue)
        workqueue->removeEventSource(fInterruptSrc);

    if( fNetif ) {
        detachInterface( fNetif );
        fNetif->release();
    }

    //    txq->cmd = IOMallocContiguous(len, sizeof(__le32), &txq->dma_addr_cmd);
    //        txq->txb = IOMalloc(sizeof(txq->txb[0]) * TFD_QUEUE_SIZE_MAX);
    //    txq->bd = IOMallocContiguous(sizeof(txq->bd[0]) * TFD_QUEUE_SIZE_MAX, 4, &txq->q.dma_addr);
    hw_txq_ctx_free();

    
    //    rxq.bd = IOMallocContiguous(4 * RX_QUEUE_SIZE, sizeof(struct tfd_frame *), &rxq.dma_addr);
    rx_queue_free();
    
    //	ucode_code.v_addr=IOMallocContiguous( ucode_code.len, sizeof(__le32), &ucode_code.p_addr);
    //	ucode_data.v_addr=IOMallocContiguous(ucode_data.len, sizeof(__le32), &ucode_data.p_addr);
    //	ucode_data_backup.v_addr=IOMallocContiguous(ucode_data_backup.len, sizeof(__le32), &ucode_data_backup.p_addr);
    //	ucode_init.v_addr=IOMallocContiguous(ucode_init.len, sizeof(__le32), &ucode_init.p_addr);
    //  	ucode_init_data.v_addr=IOMallocContiguous(ucode_init_data.len, sizeof(__le32), &ucode_init_data.p_addr);
    //	ucode_boot.v_addr=IOMallocContiguous(ucode_boot.len, sizeof(__le32), &ucode_boot.p_addr);
    if( ucode_code.v_addr) IOFreeContiguous( ucode_code.v_addr, ucode_code.len );
    if( ucode_data.v_addr) IOFreeContiguous( ucode_data.v_addr, ucode_data.len );
    if( ucode_data_backup.v_addr) IOFreeContiguous( ucode_data_backup.v_addr, ucode_data_backup.len );
    if( ucode_init.v_addr) IOFreeContiguous( ucode_init.v_addr, ucode_init.len );
  	if( ucode_init_data.v_addr) IOFreeContiguous( ucode_init_data.v_addr, ucode_init_data.len );
    if( ucode_boot.v_addr) IOFreeContiguous( ucode_boot.v_addr, ucode_boot.len );
                     
    //    hw_setting.shared_virt = IOMallocContiguous(sizeof(struct iwl3945_shared), sizeof(__le32), &(hw_setting.shared_phys));
    unset_hw_setting();
    
    
	if (provider) super::stop(provider);
}



static IOReturn darwin_iwi3945::powerChangeHandler(void *target, void *refCon, UInt32
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
}



