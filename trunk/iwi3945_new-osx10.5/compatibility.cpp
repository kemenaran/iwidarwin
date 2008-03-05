/*
 *  compatibility.cpp
 *  iwi3945
 *
 *  Created by Sean Cross on 2/8/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */

#define NO_SPIN_LOCKS 0
//#define NO_MUTEX_LOCKS 0

#include <sys/kernel_types.h>
#include <mach/vm_types.h>
#include <sys/kpi_mbuf.h>

#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/network/IONetworkController.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/OSAtomic.h>
#include <IOKit/IOInterruptEventSource.h>

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



#include "defines.h"
#include "compatibility.h"
#include "firmware/ipw3945.ucode.h"


// Note: This, in itself, makes this very much non-reentrant.  It's used
// primarily when allocating sk_buff entries.
static IONetworkController *currentController;
static ieee80211_hw * my_hw;
static IOWorkLoop * workqueue;
static IOInterruptEventSource *	fInterruptSrc;
static IOInterruptEventSource *	DMAInterruptSource;
static irqreturn_t (*realHandler)(int, void *);
static pci_driver * my_drv;
struct pci_dev* my_pci_dev;
IOPCIDevice* my_pci_device;
IOMemoryMap	*				my_map;
u8 my_mac_addr[6];

static int next_thread=0;
static int thread_pos=0;
static IOLock* thread_lock;
static bool is_unloaded=false;

#define MAX_MUTEXES 256
static struct mutex *mutexes[MAX_MUTEXES];
unsigned long current_mutex = 0;

/*
	Getters
*/

u8 * getMyMacAddr(){
	return my_mac_addr;
}

void setCurController(IONetworkController *tmp){
	currentController=tmp;
	printf("settCurController [OK]\n");
}

struct ieee80211_hw * get_my_hw(){
	return my_hw;
}

IOWorkLoop * getWorkLoop(){
	if(workqueue)
		return workqueue;
	return NULL;
}

IOInterruptEventSource * getInterruptEventSource(){
	if(fInterruptSrc)
		return fInterruptSrc;
	return NULL;
}
IOPCIDevice * getPCIDevice(){
	if(my_pci_device)
		return my_pci_device;
	return NULL;
}
IOMemoryMap * getMap(){
	if(my_map)
		return my_map;
	return NULL;
}
/*
	Setters
*/
void setUnloaded(){
	is_unloaded=true;
}
//added
int sysfs_create_group(struct kobject * kobj,const struct attribute_group * grp){
	return 0;
}
/**
	name not used for the moment
	device too
	size error
*/


int request_firmware(const struct firmware ** firmware_p, const char * name, struct device * device){
	struct firmware *firmware;
	*firmware_p = firmware =(struct firmware*) IOMalloc(sizeof(struct firmware));
	
	firmware->data = (u8*)ipw3945_ucode_raw;
	firmware->size = sizeof(ipw3945_ucode_raw); //149652;//crappy

	//load the file "name" in
	return 0;
}

void release_firmware (	const struct firmware *  fw){
    if( fw )
        IOFree((void *)fw, sizeof(struct firmware));
	return;
}




void sysfs_remove_group(struct kobject * kobj,const struct attribute_group * grp){
	return;
}

void print_hex_dump(const char *level, const char *prefix_str, int prefix_type,
                         int rowsize, int groupsize,
                         const void *buf, size_t len, bool ascii)
 {
         const u8 *ptr = (const u8*)buf;
         int i, linelen, remaining = len;
         unsigned char linebuf[200];
 
         if (rowsize != 16 && rowsize != 32)
                 rowsize = 16;
 
         for (i = 0; i < len; i += rowsize) {
                 linelen = min(remaining, rowsize);
                 remaining -= rowsize;
                 hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,
                                 (char*)linebuf, sizeof(linebuf), ascii);
 
                 switch (prefix_type) {
                 case DUMP_PREFIX_ADDRESS:
                         printk("%s%s%*p: %s\n", level, prefix_str,
                                 (int)(2 * sizeof(void *)), ptr + i, linebuf);
                         break;
                 case DUMP_PREFIX_OFFSET:
                         printk("%s%s%.8x: %s\n", level, prefix_str, i, linebuf);
                         break;
                 default:
                         printk("%s%s%s\n", level, prefix_str, linebuf);
                         break;
                 }
		}
}
      

#define hex_asc(x)	"0123456789abcdef"[x]
#define isascii(c) (((unsigned char)(c))<=0x7f)
#define isprint(a) ((a >=' ')&&(a <= '~'))
void hex_dump_to_buffer(const void *buf, size_t len, int rowsize,int groupsize, char *linebuf, size_t linebuflen, bool ascii){

         const u8 *ptr = (const u8 *)buf;
		u8 ch;
		int j, lx = 0;
		int ascii_column;
          if (rowsize != 16 && rowsize != 32)
                  rowsize = 16;
  
          if (!len)
                 goto nil;
          if (len > rowsize)              // limit to one line at a time
                  len = rowsize;
          if ((len % groupsize) != 0)     // no mixed size output
                  groupsize = 1;
  
          switch (groupsize) {
          case 8: {
                  const u64 *ptr8 = (const u64 *)buf;
                  int ngroups = len / groupsize;
  
                  for (j = 0; j < ngroups; j++)
                          lx += snprintf(linebuf + lx, linebuflen - lx,
                                  "%16.16llx ", (unsigned long long)*(ptr8 + j));
                  ascii_column = 17 * ngroups + 2;
                  break;
          }
  
          case 4: {
                  const u32 *ptr4 = (const u32 *)buf;
                 int ngroups = len / groupsize;
  
                  for (j = 0; j < ngroups; j++)
                          lx += snprintf(linebuf + lx, linebuflen - lx,
                                  "%8.8x ", *(ptr4 + j));
                  ascii_column = 9 * ngroups + 2;
                  break;
          }
  
          case 2: {
                  const u16 *ptr2 = (const u16 *)buf;
                  int ngroups = len / groupsize;
  
                  for (j = 0; j < ngroups; j++)
                          lx += snprintf(linebuf + lx, linebuflen - lx,
								"%4.4x ", *(ptr2 + j));
				ascii_column = 5 * ngroups + 2;
				break;
		}
		default:
				for (j = 0; (j < rowsize) && (j < len) && (lx + 4) < linebuflen;
					j++) {
						ch = ptr[j];
						linebuf[lx++] = hex_asc(ch >> 4);
						linebuf[lx++] = hex_asc(ch & 0x0f);
						linebuf[lx++] = ' ';
                  }
                 ascii_column = 3 * rowsize + 2;
                 break;
        }
         if (!ascii)
                 goto nil;
 
         while (lx < (linebuflen - 1) && lx < (ascii_column - 1))
                 linebuf[lx++] = ' ';
         for (j = 0; (j < rowsize) && (j < len) && (lx + 2) < linebuflen; j++)
                 linebuf[lx++] = (isascii(ptr[j]) && isprint(ptr[j])) ? ptr[j]
                                 : '.';
 nil:
         linebuf[lx++] = '\0';
	return;
}

unsigned long simple_strtoul (const char * cp, char ** endp, unsigned int base){
	return 1;
}

int is_zero_ether_addr (	const u8 *  	addr){
	return !(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]);
}




/*
	herre we call the real interuptsHandler from ipw3945
*/
void interuptsHandler(){
	if(!realHandler){
		printf("No Handler defined\n");
		return;
	}
	//printf("Call the IRQ Handler\n");
	(*realHandler)(1,my_hw->priv);
}


bool DMAFilter(OSObject* obj, IOFilterInterruptEventSource * source)
{
    // check if this interrupt belongs to me
	int	interruptIndex = source->getIntIndex();
	if (interruptIndex == 1)
	{
		IOLog("Rx DMA Interrupt Filtered\n");
		return true;// go ahead and invoke completion routine
	}
	
	/*if (interruptIndex == kIntTxDMA)
	{
		IOLog("Tx DMA Interrupt Filtered\n");
		return true;// go ahead and invoke completion routine
	}*/
	
	IOLog("NOT Rx or Tx Interrupt Filtered\n");
	return false;
}

typedef bool ( *Filter)(
    OSObject *,
    IOFilterInterruptEventSource *);
	
/*
	not finish parameter of handler and workqueue
*/
int request_irq(unsigned int irq, irqreturn_t (*handler)(int, void *), unsigned long irqflags, const char *devname, void *dev_id) {
	if(fInterruptSrc)
		return 0;
	if(!workqueue){
		workqueue = IOWorkLoop::workLoop();
		if( workqueue )
			workqueue->init();
        if (!workqueue) {
            IOLog(" ERR: start - getWorkLoop failed\n");
			return -1;
        }
	}
	/*
		set the handler for intterupts
	*/
	realHandler=handler;
	fInterruptSrc = IOInterruptEventSource::interruptEventSource(
						currentController, (IOInterruptEventAction)&interuptsHandler,currentController->getProvider()
						);
	if(!fInterruptSrc || (workqueue->addEventSource(fInterruptSrc) != kIOReturnSuccess)) {
		IOLog(" fInterruptSrc error\n");
	}
		
	fInterruptSrc->enable();
	return 0;
}

//FIXME: test
void enable_int(){
	if(fInterruptSrc)
		fInterruptSrc->enable();
}
void disable_int(){
	if(fInterruptSrc)
		fInterruptSrc->disable();
}



#pragma mark -
#pragma mark mutex and spinlock routines

// Code taken almost verbatim from "Kernel Programming Guide: Locks"
void mutex_init(struct mutex *new_mutex) {
#ifndef NO_MUTEX_LOCKS
    static int first_alloc = 1;
    static lck_grp_attr_t *group_attributes;
    static lck_grp_t *slock_group;
    static lck_attr_t *lock_attributes;

    /* allocate lock group attribute and group */
    if( first_alloc ) {
        /* allocate lock group attribute and group */
        group_attributes = lck_grp_attr_alloc_init();
        
        lck_grp_attr_setstat(group_attributes);
        
        slock_group = lck_grp_alloc_init("80211_mutex_locks", group_attributes);
        
        /* Allocate lock attribute */
        lock_attributes = lck_attr_alloc_init();
        //lck_attr_setdebug(lock_attributes); // set the debug flag
        //lck_attr_setdefault(lock_attributes); // clear the debug flag
        first_alloc = 0;
    }
    
    
    /* Allocate the spin lock */
    new_mutex->mlock = lck_mtx_alloc_init(slock_group, lock_attributes);
#endif
	return;
}

void mutex_lock(struct mutex *new_mtx) {
//#ifndef NO_MUTEX_LOCKS
    //mutexes[current_mutex++] = new_mtx;
	if(new_mtx)
		lck_mtx_lock(new_mtx->mlock);
//#endif
    return;
}

void mutex_unlock(struct mutex *new_mtx) {
//#ifndef NO_MUTEX_LOCKS
    //mutexes[current_mutex--] = NULL;
	if(new_mtx)
		lck_mtx_unlock(new_mtx->mlock);
//#endif
    return;
}



void spin_lock_init(spinlock_t *new_lock) {
#ifndef NO_SPIN_LOCKS
    static int first_alloc = 1;
    static lck_grp_attr_t *group_attributes;
    static lck_grp_t *slock_group;
    static lck_attr_t *lock_attributes;
    
    if( first_alloc ) {
        /* allocate lock group attribute and group */
        group_attributes = lck_grp_attr_alloc_init();
        
        lck_grp_attr_setstat(group_attributes);
        
        slock_group = lck_grp_alloc_init("80211_spin_locks", group_attributes);

        /* Allocate lock attribute */
        lock_attributes = lck_attr_alloc_init();
        //lck_attr_setdebug(lock_attributes); // set the debug flag
        //lck_attr_setdefault(lock_attributes); // clear the debug flag
        first_alloc = 0;
    }
    
    /* Allocate the spin lock */
    new_lock->lock = lck_spin_alloc_init(slock_group, lock_attributes);
    
#endif //NO_SPIN_LOCKS
    return;
}




void spin_lock(spinlock_t *lock) {
#ifndef NO_SPIN_LOCKS
    //lck_spin_lock(lock->lock);
#endif //NO_SPIN_LOCKS
	//lck_mtx_lock(lock->mlock);
    return;
}




void spin_unlock(spinlock_t *lock) {
#ifndef NO_SPIN_LOCKS
    //lck_spin_unlock(lock->lock);
#endif //NO_SPIN_LOCKS
	//lck_mtx_unlock(lock->mlock);
    return;
}




void spin_lock_irqsave(spinlock_t *lock, int fl) {
	//disable_int();
	spin_lock(lock);
	return;
}

#define typecheck(type,x) \
({      type __dummy; \
         typeof(x) __dummy2; \
         (void)(&__dummy == &__dummy2); \
         1; \
})

void spin_unlock_irqrestore(spinlock_t *lock, int fl) {
	spin_unlock(lock);
	//enable_int();
	return;
}


//http://hira.main.jp/wiki/pukiwiki.php?spin_lock_bh()%2Flinux2.6
void spin_lock_bh( spinlock_t *lock ) {
	spin_lock(lock);
    return;
}

void spin_unlock_bh( spinlock_t *lock ) {
	spin_unlock(lock);
    return;
}

void init_timer(struct timer_list *timer) {
//(Doesn't actually work)    return IOPCCardAddTimer(timer);
}

int mod_timer(struct timer_list *timer, int length) {
    return 0;
}

int del_timer_sync(struct timer_list *timer) {
//(Doesn't actually work)    return IOPCCardDeleteTimer(timer);
}

int in_interrupt() {
    return 0;
}

void *dev_get_drvdata(void *p) {
    return p;
}


#pragma mark -
#pragma mark Adapt 80211 functions to OS X

static inline struct sta_info *__sta_info_get(struct sta_info *sta)
{
    return /*kobject_get(&sta->kobj)*/ sta ? sta : NULL;
}

struct sta_info * sta_info_get(struct ieee80211_local *local, u8 *addr)
{
    struct sta_info *sta;
    
    spin_lock_bh(&local->sta_lock);
    sta = local->sta_hash[STA_HASH(addr)];
    while (sta) {
        if (memcmp(sta->addr, addr, ETH_ALEN) == 0) {
            __sta_info_get(sta);
            break;
        }
        sta = sta->hnext;
    }
    spin_unlock_bh(&local->sta_lock);
    
    return sta;
}

void sta_info_put(struct sta_info *sta)
{
//    kobject_put(&sta->kobj);
}

void netif_device_attach(struct net_device *dev) {
#warning Begin network device here
}
void netif_device_detach(struct net_device *dev) {
#warning Stop network device here
}
void netif_start_queue(struct net_device *dev) {
#warning Start queue here
}
void netif_wake_queue(struct net_device *dev) {
#warning Wake queue here
}
void __netif_schedule(struct net_device *dev) {
#warning Schedule queue here
}
bool netif_queue_stopped(struct net_device *dev) {
#warning Check for stopped queue here
    return 0;
}



/* Perform netif operations on all configured interfaces */
int ieee80211_netif_oper(struct ieee80211_hw *hw, Netif_Oper op)
{
    struct ieee80211_local *local = hw_to_local(hw);
    struct net_device *dev = local->mdev;
    
    switch (op) {
        case NETIF_ATTACH:
            netif_device_attach(dev);
            break;
        case NETIF_DETACH:
            netif_device_detach(dev);
            break;
        case NETIF_START:
            netif_start_queue(dev);
            break;
        case NETIF_STOP:
            break;
        case NETIF_WAKE:
            if (local->scan.in_scan == 0) {
                netif_wake_queue(dev);
#if 1
                if (/* FIX: 802.11 qdisc in use */ 1)
                    __netif_schedule(dev);
#endif
            }
            break;
            case NETIF_IS_STOPPED:
            if (netif_queue_stopped(dev))
                return 1;
            break;
            case NETIF_UPDATE_TX_START:
            dev->trans_start = jiffies;
            break;
    }
    
    return 0;
}




int ieee80211_rate_control_register(struct rate_control_ops *ops) {
    return 0;
}

void ieee80211_rate_control_unregister(struct rate_control_ops *ops) {
    return;
}

int ieee80211_get_morefrag(struct ieee80211_hdr *hdr) {
    return (le16_to_cpu(hdr->frame_control) &
            IEEE80211_FCTL_MOREFRAGS) != 0;
}

#pragma mark Rx
typedef enum {
	TXRX_CONTINUE,
	TXRX_DROP,
	TXRX_QUEUED 
};

struct ieee80211_txrx_data {
         struct sk_buff *skb;
         struct net_device *dev;
         struct ieee80211_local *local;
         struct ieee80211_sub_if_data *sdata;
         struct sta_info *sta;
         u16 fc, ethertype;
         struct ieee80211_key *key;
         unsigned int flags;
         union {
                 struct {
                         struct ieee80211_tx_control *control;
                         struct ieee80211_hw_mode *mode;
                         struct ieee80211_rate *rate;
                         /* use this rate (if set) for last fragment; rate can
                          * be set to lower rate for the first fragments, e.g.,
                          * when using CTS protection with IEEE 802.11g. */
                         struct ieee80211_rate *last_frag_rate;
                         int last_frag_hwrate;
 
                         /* Extra fragments (in addition to the first fragment
                          * in skb) */
                         int num_extra_frag;
                         struct sk_buff **extra_frag;
                 } tx;
                 struct {
                         struct ieee80211_rx_status *status;
                         int sent_ps_buffered;
                         int queue;
                         int load;
                         u32 tkip_iv32;
                         u16 tkip_iv16;
                 } rx;
         } u;
 };
 
//static inline ieee80211_txrx_result __ieee80211_invoke_rx_handlers(
static inline int __ieee80211_invoke_rx_handlers(
                                 struct ieee80211_local *local,
                                 void *handlers,
                                 struct ieee80211_txrx_data *rx,
                                 struct sta_info *sta){
		IOLog("TODO __ieee80211_invoke_rx_handlers\n");
		return TXRX_CONTINUE;
}

static inline void ieee80211_invoke_rx_handlers(struct ieee80211_local *local,
                                                 //ieee80211_rx_handler *handlers,
												 void *handlers,
                                                 struct ieee80211_txrx_data *rx,
                                                 struct sta_info *sta)
{
         if (__ieee80211_invoke_rx_handlers(local, handlers, rx, sta) ==
             TXRX_CONTINUE)
                 dev_kfree_skb(rx->skb);
}



static inline void *netdev_priv(const struct net_device *dev)
 {
         return dev->priv;
 }
#define IEEE80211_DEV_TO_SUB_IF(dev) netdev_priv(dev)

u8 *ieee80211_get_bssid(struct ieee80211_hdr *hdr, size_t len)
 {
         u16 fc;
 
         if (len < 24)
                 return NULL;
 
         fc = le16_to_cpu(hdr->frame_control);
 
         switch (fc & IEEE80211_FCTL_FTYPE) {
         case IEEE80211_FTYPE_DATA:
                 switch (fc & (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS)) {
                 case IEEE80211_FCTL_TODS:
                         return hdr->addr1;
                 case (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS):
                         return NULL;
                 case IEEE80211_FCTL_FROMDS:
                         return hdr->addr2;
                 case 0:
                         return hdr->addr3;
                 }
                 break;
         case IEEE80211_FTYPE_MGMT:
                 return hdr->addr3;
         case IEEE80211_FTYPE_CTL:
                 if ((fc & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_PSPOLL)
                         return hdr->addr1;
                 else
                         return NULL;
         }
 
         return NULL;
 }


/*
  * This is the receive path handler. It is called by a low level driver when an
  * 802.11 MPDU is received from the hardware.
  */
 void __ieee80211_rx(struct ieee80211_hw *hw, struct sk_buff *skb,
                     struct ieee80211_rx_status *status)
 {
         struct ieee80211_local *local = hw_to_local(hw);
         struct ieee80211_sub_if_data *sdata;
         struct sta_info *sta;
         struct ieee80211_hdr *hdr;
         struct ieee80211_txrx_data rx;
         u16 type;
         int prepres;
         struct ieee80211_sub_if_data *prev = NULL;
         struct sk_buff *skb_new;
         u8 *bssid;
 
         /*
          * key references and virtual interfaces are protected using RCU
          * and this requires that we are in a read-side RCU section during
          * receive processing
          */
         //rcu_read_lock();
 
         /*
          * Frames with failed FCS/PLCP checksum are not returned,
          * all other frames are returned without radiotap header
          * if it was previously present.
          * Also, frames with less than 16 bytes are dropped.
          */
         /*skb = ieee80211_rx_monitor(local, skb, status);
         if (!skb) {
                 rcu_read_unlock();
                 return;
         }*/
 
         hdr = (struct ieee80211_hdr *) skb_data(skb);
         memset(&rx, 0, sizeof(rx));
         rx.skb = skb;
         rx.local = local;
 
         rx.u.rx.status = status;
         rx.fc = le16_to_cpu(hdr->frame_control);
         type = rx.fc & IEEE80211_FCTL_FTYPE;
 
         if (type == IEEE80211_FTYPE_DATA || type == IEEE80211_FTYPE_MGMT)
                 local->dot11ReceivedFragmentCount++;
 
         sta = rx.sta = sta_info_get(local, hdr->addr2);
         if (sta) {
                 rx.dev = rx.sta->dev;
                 rx.sdata = ( ieee80211_sub_if_data *) IEEE80211_DEV_TO_SUB_IF(rx.dev);
         }
 
        /* if ((status->flag & RX_FLAG_MMIC_ERROR)) {
                 ieee80211_rx_michael_mic_report(local->mdev, hdr, sta, &rx);
                 goto end;
         }*/
#define BIT(nr)                 (1UL << (nr))
#define IEEE80211_TXRXD_RXIN_SCAN BIT(4) 
         if (unlikely(local->sta_scanning))
                 rx.flags |= IEEE80211_TXRXD_RXIN_SCAN;
 
        // if (__ieee80211_invoke_rx_handlers(local, local->rx_pre_handlers, &rx,sta) != TXRX_CONTINUE)
		if (__ieee80211_invoke_rx_handlers(local, NULL, &rx,sta) != TXRX_CONTINUE)
                 goto end;
         skb = rx.skb;
#define WLAN_STA_WDS BIT(27)
#define WLAN_STA_ASSOC_AP BIT(8)
         if (sta && !(sta->flags & (WLAN_STA_WDS | WLAN_STA_ASSOC_AP)) &&
             //!atomic_read(&local->iff_promiscs) &&
             !is_multicast_ether_addr(hdr->addr1)) {
#define IEEE80211_TXRXD_RXRA_MATCH              BIT(5)
                 rx.flags |= IEEE80211_TXRXD_RXRA_MATCH;
                 //ieee80211_invoke_rx_handlers(local, local->rx_handlers, &rx, rx.sta);
					ieee80211_invoke_rx_handlers(local, NULL, &rx,rx.sta);
                 sta_info_put(sta);
                 //rcu_read_unlock();
                 return;
         }
 
         bssid = ieee80211_get_bssid(hdr, skb_len(skb));
#if 0
         list_for_each_entry_rcu(sdata, &local->interfaces, list) {
                 if (!netif_running(sdata->dev))
                         continue;
 
                 if (sdata->type == IEEE80211_IF_TYPE_MNTR)
                         continue;
 
                 rx.flags |= IEEE80211_TXRXD_RXRA_MATCH;
                 prepres = prepare_for_handlers(sdata, bssid, &rx, hdr);
                 /* prepare_for_handlers can change sta */
                 sta = rx.sta;
 
                 if (!prepres)
                         continue;
 
                 /*
                  * frame is destined for this interface, but if it's not
                  * also for the previous one we handle that after the
                  * loop to avoid copying the SKB once too much
                  */
 
                 if (!prev) {
                         prev = sdata;
                         continue;
                 }
 
                 /*
                  * frame was destined for the previous interface
                  * so invoke RX handlers for it
                  */
 
                 skb_new = skb_copy(skb, GFP_ATOMIC);
                 if (!skb_new) {
                         if (net_ratelimit())
                                 printk(KERN_DEBUG "%s: failed to copy "
                                        "multicast frame for %s",
                                        wiphy_name(local->hw.wiphy),
                                        prev->dev->name);
                         continue;
                 }
                 rx.skb = skb_new;
                 rx.dev = prev->dev;
                 rx.sdata = prev;
                 ieee80211_invoke_rx_handlers(local, local->rx_handlers,
                                              &rx, sta);
                 prev = sdata;
         }
         if (prev) {
                 rx.skb = skb;
                 rx.dev = prev->dev;
                 rx.sdata = prev;
                 ieee80211_invoke_rx_handlers(local, local->rx_handlers,
                                              &rx, sta);
         } else
                 dev_kfree_skb(skb);
 #endif
  end:
         //rcu_read_unlock();
 
         if (sta)
                 sta_info_put(sta);
 }
	




#define IEEE80211_RX_MSG 1
#define IEEE80211_TX_STATUS_MSG 2
static void ieee80211_tasklet_handler(void * data)
{
	IOLog("TODO ieee80211_tasklet_handler\n");
	return ;
	struct ieee80211_local *local = (struct ieee80211_local *) data;
	struct sk_buff *skb;
	struct ieee80211_rx_status rx_status;
	struct ieee80211_tx_status *tx_status;

	//get the last packet
	//while ((skb = skb_dequeue(&local->skb_queue)) || (skb = skb_dequeue(&local->skb_queue_unreliable))) {
	//	switch (skb->pkt_type) {
	//	case IEEE80211_RX_MSG:
			/* status is in skb->cb */
	//		memcpy(&rx_status, skb->cb, sizeof(rx_status));
			/* Clear skb->type in order to not confuse kernel
			 * netstack. */
	//		skb->pkt_type = 0;
	//		__ieee80211_rx(local_to_hw(local), skb, &rx_status);
	//		break;
	//	case IEEE80211_TX_STATUS_MSG:
			/* get pointer to saved status out of skb->cb */
	//		memcpy(&tx_status, skb->cb, sizeof(tx_status));
	//		skb->pkt_type = 0;
	//		ieee80211_tx_status(local_to_hw(local),
	//				    skb, tx_status);
	//		kfree(tx_status);
	//		break;
	//	default: /* should never get here! */
			//printk(KERN_ERR "%s: Unknown message type (%d)\n",
			//       local->mdev->name, skb->pkt_type);
	//		dev_kfree_skb(skb);
	//		break;
	//	}
	//}
}





/* This is a version of the rx handler that can be called from hard irq
 * context. Post the skb on the queue and schedule the tasklet */
void ieee80211_rx_irqsafe(struct ieee80211_hw *hw, struct sk_buff *skb, struct ieee80211_rx_status *status)
{
	
    struct ieee80211_local *local = hw_to_local(hw);
    
    BUILD_BUG_ON(sizeof(struct ieee80211_rx_status) > sizeof(skb->cb));
    
    IOLog("todo ieee80211_rx_irqsafe\n");
	
	//PrintPacketHeader(skb->mac_data);
	char    *frame;
    frame = (char*)skb_data(skb);
    for (int i = 0; i < mbuf_len(skb->mac_data); i++)
    {
      IOLog("%02X", (u_int8_t)frame[i]);
    }
	
	//return;
	//skb->dev = local->mdev;
    // copy status into skb->cb for use by tasklet
    memcpy(skb->cb, status, sizeof(*status));
    mbuf_settype(skb->mac_data, MBUF_TYPE_DATA);
    //skb_queue_tail(&local->skb_queue, skb);//how ?
	
	//Start the tasklet
	//IOCreateThread(&ieee80211_tasklet_handler,local);
	
	/*
		RX implementation must be moved after
	*/
	__ieee80211_rx(hw,skb,status);
	

}



void ieee80211_stop_queue(struct ieee80211_hw *hw, int queue) {
    return;
}

void ieee80211_tx_status(struct ieee80211_hw *hw,
                         struct sk_buff *skb,
                         struct ieee80211_tx_status *status) {
    return;
}

void ieee80211_tx_status_irqsafe(struct ieee80211_hw *hw,
                                 struct sk_buff *skb,
                                 struct ieee80211_tx_status *status) {
    return;
}

void ieee80211_wake_queue(struct ieee80211_hw *hw, int queue) {
    return;
}

struct sk_buff *ieee80211_beacon_get(struct ieee80211_hw *hw,int if_id,struct ieee80211_tx_control *control) {
    return NULL;
}


void ieee80211_stop_queues(struct ieee80211_hw *hw) {
    return;
}

#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })
int ieee80211_register_hw (	struct ieee80211_hw *  	hw){
	struct ieee80211_local *local = hw_to_local(hw);
	const char *name;
	int result;

	/*result = wiphy_register(local->hw.wiphy);
	if (result < 0)
		return result;

	name = wiphy_dev(local->hw.wiphy)->driver->name;
	local->hw.workqueue = create_singlethread_workqueue(name);
	if (!local->hw.workqueue) {
		result = -ENOMEM;
		goto fail_workqueue;
	}*/

	/*
	 * The hardware needs headroom for sending the frame,
	 * and we need some headroom for passing the frame to monitor
	 * interfaces, but never both at the same time.
	 */
	//local->tx_headroom = max_t(unsigned int , local->hw.extra_tx_headroom,
	//			   sizeof(struct ieee80211_tx_status_rtap_hdr));

	//debugfs_hw_add(local);

	local->hw.conf.beacon_int = 1000;

	local->wstats_flags |= local->hw.max_rssi ?
			       IW_QUAL_LEVEL_UPDATED : IW_QUAL_LEVEL_INVALID;
	local->wstats_flags |= local->hw.max_signal ?
			       IW_QUAL_QUAL_UPDATED : IW_QUAL_QUAL_INVALID;
	local->wstats_flags |= local->hw.max_noise ?
			       IW_QUAL_NOISE_UPDATED : IW_QUAL_NOISE_INVALID;
	if (local->hw.max_rssi < 0 || local->hw.max_noise < 0)
		local->wstats_flags |= IW_QUAL_DBM;

	/*result = sta_info_start(local);
	if (result < 0)
		goto fail_sta_info;*/

	/*rtnl_lock();
	result = dev_alloc_name(local->mdev, local->mdev->name);
	if (result < 0)
		goto fail_dev;

	memcpy(local->mdev->dev_addr, local->hw.wiphy->perm_addr, ETH_ALEN);
	SET_NETDEV_DEV(local->mdev, wiphy_dev(local->hw.wiphy));*/

	/*result = register_netdevice(local->mdev);
	if (result < 0)
		goto fail_dev;

	ieee80211_debugfs_add_netdev(IEEE80211_DEV_TO_SUB_IF(local->mdev));*/

	/*result = ieee80211_init_rate_ctrl_alg(local, NULL);
	if (result < 0) {
		printk(KERN_DEBUG "%s: Failed to initialize rate control "
		       "algorithm\n", local->mdev->name);
		goto fail_rate;
	}*/
//this one maybe
/*	result = ieee80211_wep_init(local);

	if (result < 0) {
		printk(KERN_DEBUG "%s: Failed to initialize wep\n",
		       local->mdev->name);
		goto fail_wep;
	}*/

	//ieee80211_install_qdisc(local->mdev);

	/* add one default STA interface */
/*	result = ieee80211_if_add(local->mdev, "wlan%d", NULL,
				  IEEE80211_IF_TYPE_STA);
	if (result)
		printk(KERN_WARNING "%s: Failed to add default virtual iface\n",
		       local->mdev->name);

	local->reg_state = IEEE80211_DEV_REGISTERED;
	rtnl_unlock();

	ieee80211_led_init(local);*/

	return 0;

/*fail_wep:
	rate_control_deinitialize(local);
fail_rate:
	ieee80211_debugfs_remove_netdev(IEEE80211_DEV_TO_SUB_IF(local->mdev));
	unregister_netdevice(local->mdev);
fail_dev:
	rtnl_unlock();
	sta_info_stop(local);
fail_sta_info:
	debugfs_hw_del(local);
	destroy_workqueue(local->hw.workqueue);
fail_workqueue:
	wiphy_unregister(local->hw.wiphy);*/
	return result;
}


void ieee80211_unregister_hw(struct ieee80211_hw *  hw){
	return;
}
void ieee80211_start_queues(struct ieee80211_hw *hw){
    struct ieee80211_local *local = hw_to_local(hw);
    int i;
    
    for (i = 0; i < local->hw.queues; i++)
        clear_bit(IEEE80211_LINK_STATE_XOFF, &local->state[i]);
}

void ieee80211_scan_completed (	struct ieee80211_hw *  	hw){
	IOLog("TODO ieee80211_scan_completed\n");
	return ;
	/*struct ieee80211_local *local = hw_to_local(hw);
	struct net_device *dev = local->scan_dev;
	struct ieee80211_sub_if_data *sdata;
	union iwreq_data wrqu;

	local->last_scan_completed = jiffies;
	wmb();
	local->sta_scanning = 0;

	if (ieee80211_hw_config(local))
		printk(KERN_DEBUG "%s: failed to restore operational"
		       "channel after scan\n", dev->name);


	netif_tx_lock_bh(local->mdev);
	local->filter_flags &= ~FIF_BCN_PRBRESP_PROMISC;
	local->ops->configure_filter(local_to_hw(local),
				     FIF_BCN_PRBRESP_PROMISC,
				     &local->filter_flags,
				     local->mdev->mc_count,
				     local->mdev->mc_list);

	netif_tx_unlock_bh(local->mdev);

	memset(&wrqu, 0, sizeof(wrqu));
	wireless_send_event(dev, SIOCGIWSCAN, &wrqu, NULL);

	rcu_read_lock();
	list_for_each_entry_rcu(sdata, &local->interfaces, list) {

		if (sdata->dev == local->mdev)
			continue;

		if (sdata->type == IEEE80211_IF_TYPE_STA) {
			if (sdata->u.sta.flags & IEEE80211_STA_ASSOCIATED)
				ieee80211_send_nullfunc(local, sdata, 0);
			ieee80211_sta_timer((unsigned long)sdata);
		}

		netif_wake_queue(sdata->dev);
	}
	rcu_read_unlock();*/
}


static void ieee80211_if_sdata_init(struct ieee80211_sub_if_data *sdata)
{
	int i;

	/* Default values for sub-interface parameters */
	sdata->drop_unencrypted = 0;
	sdata->eapol = 1;
	for (i = 0; i < IEEE80211_FRAGMENT_MAX; i++)
	{
#warning error herre
		//INIT_LIST_HEAD(&sdata->fragments[i].skb_list);
	//	skb_queue_head_init(&sdata->fragments[i].skb_list);
	}
}

static struct ieee80211_hw* local_to_hw(struct ieee80211_local *local)
{
	return &local->hw;
}

struct ieee80211_hw * ieee80211_alloc_hw (size_t priv_data_len,const struct ieee80211_ops *  ops){
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
	memset(local,0,priv_size);
	local->hw.priv =
	(char*)local +
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

	mdev=(struct net_device*)IOMalloc(sizeof(struct ieee80211_sub_if_data));
	memset(mdev,0,sizeof(struct ieee80211_sub_if_data));
	sdata = (struct ieee80211_sub_if_data*)netdev_priv(mdev);
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
	//INIT_LIST_HEAD(&local->skb_queue);
	//INIT_LIST_HEAD(&local->skb_queue_unreliable);
	
	//printf("ieee80211_alloc_hw [OK]\n");
	my_hw=local_to_hw(local);
	return my_hw;
	//return NULL;
}
void ieee80211_free_hw (	struct ieee80211_hw *  	hw){
	return;
}
int ieee80211_register_hwmode(struct ieee80211_hw *hw,struct ieee80211_hw_mode *mode){
	return 1;
}
//define the whispy for the driver
void SET_IEEE80211_DEV(	struct ieee80211_hw *  	hw,struct device *  	dev){
	return;
}
//Define the addr 
void SET_IEEE80211_PERM_ADDR (	struct ieee80211_hw *  	hw, 	u8 *  	addr){
	my_mac_addr[0] = addr[0];
	my_mac_addr[1] = addr[1];
	my_mac_addr[2] = addr[2];
	my_mac_addr[3] = addr[3];
	my_mac_addr[4] = addr[4];
	my_mac_addr[5] = addr[5];
	return;
}


#pragma mark -
#pragma mark Kernel PCI fiddler adapters


void pci_dma_sync_single_for_cpu(struct pci_dev *hwdev, dma_addr_t dma_handle, size_t size, int direction){
	IOMemoryDescriptor::withPhysicalAddress(dma_handle,size,kIODirectionOutIn)->complete();
	return;
}

int pci_write_config_word(struct pci_dev *dev, int where, u16 val){
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
    fPCIDevice->configWrite16(where,val);
    return 0;
}


int pci_enable_msi  (struct pci_dev * dev){
	return 0;
}

int pci_enable_device (struct pci_dev * dev){
	if(!dev){
		printf("No pci_dev defined\n");
		return 1;
	}
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	//printf("PCI device enabled [OK]\n");
	return 0;
}


//ok but nor realy that on linux kernel
void pci_disable_device (struct pci_dev * dev){
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
}

/*
	put the Iface down
*/
int if_down(){
	if(!my_drv)
		return -6;
	if(!my_pci_dev)
		return -5;
	(my_drv->remove) (my_pci_dev);
	return 0;
}


#define add_timer(x)

/* Maximum number of seconds to wait for the traffic load to get below
 * threshold before forcing a passive scan. */
#define MAX_SCAN_WAIT 60
/* Threshold (pkts/sec TX or RX) for delaying passive scan */
#define SCAN_TXRX_THRESHOLD 75





static void next_chan_same_mode(struct ieee80211_local *local,
                                struct ieee80211_hw_mode **mode,
                                struct ieee80211_channel **chan)
{
    struct ieee80211_hw_mode *m;
    int prev;
    
    list_for_each_entry(m, &local->modes_list, list) {
        *mode = m;
        if (m->mode == local->hw.conf.phymode)
            break;
    }
    local->scan.mode = m;
    
    /* Select next channel - scan only channels marked with W_SCAN flag */
    prev = local->scan.chan_idx;
    do {
        local->scan.chan_idx++;
        if (local->scan.chan_idx >= m->num_channels)
            local->scan.chan_idx = 0;
        *chan = &m->channels[local->scan.chan_idx];
        if ((*chan)->flag & IEEE80211_CHAN_W_SCAN)
            break;
    } while (local->scan.chan_idx != prev);
}



static void get_channel_params(struct ieee80211_local *local, int channel,
                               struct ieee80211_hw_mode **mode,
                               struct ieee80211_channel **chan)
{
    struct ieee80211_hw_mode *m;
    
    list_for_each_entry(m, &local->modes_list, list) {
        *mode = m;
        if (m->mode == local->hw.conf.phymode)
            break;
    }
    local->scan.mode = m;
    local->scan.chan_idx = 0;
    do {
        *chan = &m->channels[local->scan.chan_idx];
        if ((*chan)->chan == channel)
            return;
        local->scan.chan_idx++;
    } while (local->scan.chan_idx < m->num_channels);
    *chan = NULL;
}


static void next_chan_all_modes(struct ieee80211_local *local,
                                struct ieee80211_hw_mode **mode,
                                struct ieee80211_channel **chan)
{
    struct ieee80211_hw_mode *prev_m;
    int prev;
    
    /* Select next channel - scan only channels marked with W_SCAN flag */
    prev = local->scan.chan_idx;
    prev_m = local->scan.mode;
    do {
        *mode = local->scan.mode;
        local->scan.chan_idx++;
        if (local->scan.chan_idx >= (*mode)->num_channels) {
            struct list_head *next;
            
            local->scan.chan_idx = 0;
            next = (*mode)->list.next;
            if (next == &local->modes_list)
                next = next->next;
            *mode = list_entry(next,
                               struct ieee80211_hw_mode,
                               list);
            local->scan.mode = *mode;
        }
        *chan = &(*mode)->channels[local->scan.chan_idx];
        if ((*chan)->flag & IEEE80211_CHAN_W_SCAN)
            break;
    } while (local->scan.chan_idx != prev ||
             local->scan.mode != prev_m);
}



static void ieee80211_scan_start(struct ieee80211_local *local,
                                 struct ieee80211_scan_conf *conf)
{
    struct ieee80211_hw_mode *old_mode = local->scan.mode;
    int old_chan_idx = local->scan.chan_idx;
    struct ieee80211_hw_mode *mode = NULL;
    struct ieee80211_channel *chan = NULL;
    int ret;
    
    if (!local->ops->passive_scan) {
        printk(KERN_DEBUG "%s: Scan handler called, yet the hardware "
               "does not support passive scanning. Disabled.\n",
               local->mdev->name);
        return;
    }
    
    if ((local->scan.tries < MAX_SCAN_WAIT &&
         local->scan.txrx_count > SCAN_TXRX_THRESHOLD)) {
        local->scan.tries++;
        /* Count TX/RX packets during one second interval and allow
         * scan to start only if the number of packets is below the
         * threshold. */
        local->scan.txrx_count = 0;
        local->scan.timer.expires = jiffies + HZ;
        add_timer(&local->scan.timer);
        return;
    }
    
    if (!local->scan.skb) {
        printk(KERN_DEBUG "%s: Scan start called even though scan.skb "
               "is not set\n", local->mdev->name);
    }
    
    if (local->scan.our_mode_only) {
        if (local->scan.channel > 0) {
            get_channel_params(local, local->scan.channel, &mode,
                               &chan);
        } else
            next_chan_same_mode(local, &mode, &chan);
    }
    else
        next_chan_all_modes(local, &mode, &chan);
    
    conf->scan_channel = chan->chan;
    conf->scan_freq = chan->freq;
    conf->scan_channel_val = chan->val;
    conf->scan_phymode = mode->mode;
    conf->scan_power_level = chan->power_level;
    conf->scan_antenna_max = chan->antenna_max;
    conf->scan_time = 2 * local->hw.channel_change_time +
    local->scan.time; /* 10ms scan time+hardware changes */
    conf->skb = local->scan.skb ?
    skb_clone(local->scan.skb, GFP_ATOMIC) : NULL;
    conf->tx_control = &local->scan.tx_control;
#if 0
    printk(KERN_DEBUG "%s: Doing scan on mode: %d freq: %d chan: %d "
           "for %d ms\n",
           local->mdev->name, conf->scan_phymode, conf->scan_freq,
           conf->scan_channel, conf->scan_time);
#endif
    local->scan.rx_packets = 0;
    local->scan.rx_beacon = 0;
    local->scan.freq = chan->freq;
    local->scan.in_scan = 1;
    
    ieee80211_netif_oper(local_to_hw(local), NETIF_STOP);
#define IEEE80211_SCAN_START 1    
    ret = local->ops->passive_scan(local_to_hw(local),
                                   IEEE80211_SCAN_START, conf);
    
    if (ret == 0) {
        long usec = local->hw.channel_change_time +
        local->scan.time;
        usec += 1000000L / HZ - 1;
        usec /= 1000000L / HZ;
        local->scan.timer.expires = jiffies + usec;
    } else {
        local->scan.in_scan = 0;
        if (conf->skb)
            dev_kfree_skb(conf->skb);
        ieee80211_netif_oper(local_to_hw(local), NETIF_WAKE);
        if (ret == -EAGAIN) {
            local->scan.timer.expires = jiffies +
            (local->scan.interval * HZ / 100);
            local->scan.mode = old_mode;
            local->scan.chan_idx = old_chan_idx;
        } else {
            printk(KERN_DEBUG "%s: Got unknown error from "
                   "passive_scan %d\n", local->mdev->name, ret);
            local->scan.timer.expires = jiffies +
            (local->scan.interval * HZ);
        }
        local->scan.in_scan = 0;
    }
    
    add_timer(&local->scan.timer);
}


static void ieee80211_scan_stop(struct ieee80211_local *local,
                                struct ieee80211_scan_conf *conf)
{
    struct ieee80211_hw_mode *mode;
    struct ieee80211_channel *chan;
    int wait;
    
    if (!local->ops->passive_scan)
        return;
    
    mode = local->scan.mode;
    
    if (local->scan.chan_idx >= mode->num_channels)
        local->scan.chan_idx = 0;
    
    chan = &mode->channels[local->scan.chan_idx];
#define IEEE80211_SCAN_END 2     
    local->ops->passive_scan(local_to_hw(local), IEEE80211_SCAN_END,
                             conf);
    
#ifdef CONFIG_MAC80211_VERBOSE_DEBUG
    printk(KERN_DEBUG "%s: Did scan on mode: %d freq: %d chan: %d "
           "GOT: %d Beacon: %d (%d)\n",
           local->mdev->name,
           mode->mode, chan->freq, chan->chan,
           local->scan.rx_packets, local->scan.rx_beacon,
           local->scan.tries);
#endif /* CONFIG_MAC80211_VERBOSE_DEBUG */
    local->scan.num_scans++;
    
    local->scan.in_scan = 0;
    ieee80211_netif_oper(local_to_hw(local), NETIF_WAKE);
    
    local->scan.tries = 0;
    /* Use random interval of scan.interval .. 2 * scan.interval */
    wait = (local->scan.interval * HZ * ((net_random() & 127) + 128)) /
    128;
    local->scan.timer.expires = jiffies + wait;
    
    add_timer(&local->scan.timer);
}




/* Check if running monitor interfaces should go to a "hard monitor" mode
 * and switch them if necessary. */
static void ieee80211_start_hard_monitor(struct ieee80211_local *local)
{
    struct ieee80211_if_init_conf conf;
    
    if (local->open_count && local->open_count == local->monitors &&
        !(local->hw.flags & IEEE80211_HW_MONITOR_DURING_OPER) &&
        local->ops->add_interface) {
        conf.if_id = -1;
        conf.type = IEEE80211_IF_TYPE_MNTR;
        conf.mac_addr = NULL;
        local->ops->add_interface(local_to_hw(local), &conf);
    }
}






static void ieee80211_scan_handler(unsigned long ullocal)
{
    struct ieee80211_local *local = (struct ieee80211_local *) ullocal;
    struct ieee80211_scan_conf conf;
    
    if (local->scan.interval == 0 && !local->scan.in_scan) {
        /* Passive scanning is disabled - keep the timer always
         * running to make code cleaner. */
        local->scan.timer.expires = jiffies + 10 * HZ;
        add_timer(&local->scan.timer);
        return;
    }
    
    memset(&conf, 0, sizeof(struct ieee80211_scan_conf));
    conf.running_freq = local->hw.conf.freq;
    conf.running_channel = local->hw.conf.channel;
    conf.running_phymode = local->hw.conf.phymode;
    conf.running_channel_val = local->hw.conf.channel_val;
    conf.running_power_level = local->hw.conf.power_level;
    conf.running_antenna_max = local->hw.conf.antenna_max;
    
    if (local->scan.in_scan == 0)
        ieee80211_scan_start(local, &conf);
    else
        ieee80211_scan_stop(local, &conf);
}




void ieee80211_init_scan(struct ieee80211_local *local)
{
    struct ieee80211_hdr hdr;
    u16 fc;
    int len = 10;
    struct rate_control_extra extra;
    
    /* Only initialize passive scanning if the hardware supports it */
    if (!local->ops->passive_scan) {
        local->scan.skb = NULL;
        memset(&local->scan.tx_control, 0,
               sizeof(local->scan.tx_control));
        printk(KERN_DEBUG "%s: Does not support passive scan, "
               "disabled\n", local->mdev->name);
        return;
    }
    
    local->scan.interval = 0;
    local->scan.our_mode_only = 1;
    local->scan.time = 10000;
    local->scan.timer.function = ieee80211_scan_handler;
    local->scan.timer.data = (unsigned long) local;
    local->scan.timer.expires = jiffies + local->scan.interval * HZ;
    add_timer(&local->scan.timer);
    
    /* Create a CTS from for broadcasting before
     * the low level changes channels */
    local->scan.skb = alloc_skb(len + local->hw.extra_tx_headroom,
                                GFP_KERNEL);
    if (!local->scan.skb) {
        printk(KERN_WARNING "%s: Failed to allocate CTS packet for "
               "passive scan\n", local->mdev->name);
        return;
    }
    skb_reserve(local->scan.skb, local->hw.extra_tx_headroom);
    
    fc = IEEE80211_FTYPE_CTL | IEEE80211_STYPE_CTS;
    hdr.frame_control = cpu_to_le16(fc);
    hdr.duration_id =
    cpu_to_le16(2 * local->hw.channel_change_time +
                local->scan.time);
    memcpy(hdr.addr1, local->mdev->dev_addr, ETH_ALEN); /* DA */
    hdr.seq_ctrl = 0;
    
    memcpy(skb_put(local->scan.skb, len), &hdr, len);
    
    memset(&local->scan.tx_control, 0, sizeof(local->scan.tx_control));
#define HW_KEY_IDX_INVALID -1
    local->scan.tx_control.key_idx = HW_KEY_IDX_INVALID;
    local->scan.tx_control.flags |= IEEE80211_TXCTL_DO_NOT_ENCRYPT;
    memset(&extra, 0, sizeof(extra));
    extra.endidx = local->num_curr_rates;
    local->scan.tx_control.tx_rate =
    rate_control_get_rate(local, local->mdev,
                          local->scan.skb, &extra)->val;
    local->scan.tx_control.flags |= IEEE80211_TXCTL_NO_ACK;
}








int run_add_interface() {
	struct ieee80211_local *local = hw_to_local(my_hw); 
    struct ieee80211_if_init_conf conf;
    int res;
    
    conf.if_id = IEEE80211_IF_TYPE_IBSS;
    conf.type = 2;
    conf.mac_addr = my_mac_addr;
    res = local->ops->add_interface(local_to_hw(local), &conf);
    if (res) {
        if (conf.type == IEEE80211_IF_TYPE_MNTR)
            ieee80211_start_hard_monitor(local);
    }
    return res;
}    




/*
Adds the driver structure to the list of registered drivers.
Returns a negative value on error, otherwise 0.
If no error occurred, the driver remains registered even if no device was claimed during registration.

Starting of the card will be moved after...
*/
//http://www.promethos.org/lxr/http/source/drivers/pci/pci-driver.c#L376
int pci_register_driver(struct pci_driver * drv){
	if(!thread_lock)
		thread_lock = IOLockAlloc();
	if(!drv)
		return -6;
	my_drv=drv;
	//maybe get the pointer for the good function as iwl3945_pci_probe ...
	struct pci_device_id *test=(struct pci_device_id *)IOMalloc(sizeof(struct pci_device_id));
	struct pci_dev *test_pci=(struct pci_dev *)IOMalloc(sizeof(struct pci_dev));
	my_pci_dev=test_pci;
	
	if(!currentController){
		printf("No currentController set\n");
		return 1;
	}
	//OSDynamicCast(IOPCIDevice, currentController->getProvider());

	test_pci->dev.kobj.ptr=OSDynamicCast(IOPCIDevice, currentController->getProvider());
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)test_pci->dev.kobj.ptr;
	my_pci_device=fPCIDevice;
	fPCIDevice->retain();
	fPCIDevice->open(currentController);
	fPCIDevice->requestPowerDomainState(kIOPMPowerOn, (IOPowerConnection *) currentController->getParentEntry(gIOPowerPlane),IOPMLowestState );
	UInt16 reg16;
	reg16 = fPCIDevice->configRead16(kIOPCIConfigCommand);
	reg16 |= (kIOPCICommandBusMaster      |kIOPCICommandMemorySpace    |kIOPCICommandMemWrInvalidate);

	reg16 &= ~kIOPCICommandIOSpace;  // disable I/O space
	fPCIDevice->configWrite16(kIOPCIConfigCommand,reg16);
		fPCIDevice->configWrite8(kIOPCIConfigLatencyTimer,0x64);
	
	/* We disable the RETRY_TIMEOUT register (0x41) to keep
	 * PCI Tx retries from interfering with C3 CPU state */
	UInt16 reg = fPCIDevice->configRead16(0x40);
	if((reg & 0x0000ff00) != 0)
		fPCIDevice->configWrite16(0x40, reg & 0xffff00ff);

	fPCIDevice->setBusMasterEnable(true);
	fPCIDevice->setMemoryEnable(true);
	int result2 = (drv->probe) (test_pci,test);
	
	//get_eeprom_mac(my_hw->priv,my_mac_addr);
	//Start ...
#warning This assumes the "happy path" and fails miserably when things don't go well
	struct ieee80211_local *local = hw_to_local(my_hw);
	int result3 = run_add_interface();
	if(result3)
		IOLog("Error add_interface\n");
	IOSleep(300);
	//Start mac_open
	result2 = (local->ops->open) (&local->hw);
	

    ieee80211_init_scan(local);
    local->open_count++;
    
	return 0;
}



//http://www.promethos.org/lxr/http/source/drivers/pci/pci-driver.c#L376
void pci_unregister_driver (struct pci_driver * drv){
	return ;
}
/*
	set the device master of the bus
*/
void pci_set_master (struct pci_dev * dev){
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	fPCIDevice->setBusMasterEnable(true);
	return;
}

void free_irq (unsigned int irq, void *dev_id){
	return;
}
void pci_disable_msi(struct pci_dev* dev){
	return;
}

int pci_restore_state (	struct pci_dev *  	dev){
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	fPCIDevice->restoreDeviceState();
	return 0;
}
//ok but no saved_config_space in pci_dev struct
int pci_save_state (struct pci_dev * dev){
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	fPCIDevice->saveDeviceState();
	return 0;
}
int pci_set_dma_mask(struct pci_dev *dev, u64 mask){
	//test if dma support (OK for 3945)
	//dev->dma_mask = mask;
	return 0;
}
/*
	Strange , maybe already do by IOPCIDevice layer ?
*/
//http://www.promethos.org/lxr/http/source/drivers/pci/pci.c#L642
int pci_request_regions (struct pci_dev * pdev, char * res_name){
	return 0;
}
//ok
int pci_write_config_byte(struct pci_dev *dev, int where, u8 val){
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
    fPCIDevice->configWrite8(where,val);
    return 0;
}



void pci_release_regions (struct pci_dev * pdev){
	return;
}
/*
	get the priv...
*/
void *pci_get_drvdata (struct pci_dev *pdev){
	return my_hw->priv;
}
void pci_set_drvdata (struct pci_dev *pdev, void *data){
	return;
}
//ok
#include <IOKit/IOMapper.h>
#define RT_ALIGN_T(u, uAlignment, type) ( ((type)(u) + ((uAlignment) - 1)) & ~(type)((uAlignment) - 1) )
#define RT_ALIGN_Z(cb, uAlignment)              RT_ALIGN_T(cb, uAlignment, size_t)
#define _4G 0x0000000100000000LL
int pci_set_consistent_dma_mask(struct pci_dev *dev, u64 mask){
	//test if dma supported (ok 3945)
	//dev->dev.coherent_dma_mask = mask;
	return 0;
}

void pci_free_consistent(struct pci_dev *hwdev, size_t size,void *vaddr, dma_addr_t dma_handle) {
	size = RT_ALIGN_Z(size, PAGE_SIZE);
    return IOFreeContiguous(vaddr, size);
}




void *pci_alloc_consistent(struct pci_dev *hwdev, size_t size,dma_addr_t *dma_handle,int count) {
	size = RT_ALIGN_Z(size, PAGE_SIZE);
	return IOMallocContiguous(size,PAGE_SIZE, dma_handle);
}

void __iomem * pci_iomap (	struct pci_dev *  	dev,int  	bar,unsigned long  	maxlen){
	IOMemoryMap	*				map;
	IOPhysicalAddress			phys_add;
	UInt16 *					virt_add;
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	map = fPCIDevice->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0, kIOMapInhibitCache);
	if (map == 0) {
			return NULL;
	}
	my_map=map;
	return (void*)map->getVirtualAddress();
}


void pci_iounmap(struct pci_dev *dev, void __iomem * addr){
	return;
}


void pci_unmap_single(struct pci_dev *hwdev, dma_addr_t dma_addr,size_t size, int direction) {
    IODirection mydir = (IODirection) direction;
    IOMemoryDescriptor::withPhysicalAddress(dma_addr, size, mydir)->complete(mydir);
    IOMemoryDescriptor::withPhysicalAddress(dma_addr,size, mydir)->release();
}

addr64_t pci_map_single(struct pci_dev *hwdev, void *ptr, size_t size, int direction) {
	IOMemoryDescriptor::withAddress(ptr,size,kIODirectionOutIn)->complete(kIODirectionOutIn);
	addr64_t tmp = cpu_to_le32(mbuf_data_to_physical( (u8*)ptr));
}


int pci_read_config_byte(struct pci_dev *dev, int where, u8 *val) {
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
    *val = fPCIDevice->configRead8(where);
    return 0;
}

int pci_read_config_word(struct pci_dev *dev, int where, u16 *val) {
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
    *val = fPCIDevice->configRead16(where);
    return 0;
}

int pci_read_config_dword(struct pci_dev *dev, int where, u32 *val) {
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
    *val = fPCIDevice->configRead32(where);
    return 0;
}


#pragma mark -
#pragma mark Adapt sk_buff functions to mbuf for OS X


int skb_tailroom(const struct sk_buff *skb) {
    return mbuf_trailingspace(skb->mac_data);
}

struct sk_buff *skb_clone(const struct sk_buff *skb, unsigned int ignored) {
    struct sk_buff *skb_copy = (struct sk_buff *)IOMalloc(sizeof(struct sk_buff));
    mbuf_copym(skb->mac_data, 0, mbuf_len(skb->mac_data), 1, &skb_copy->mac_data);
    skb_copy->intf = skb->intf;
    return skb_copy;
}

void *skb_data(const struct sk_buff *skb) {
    return mbuf_data(skb->mac_data);
}

int skb_len(const struct sk_buff *skb) {
	return mbuf_pkthdr_len(skb->mac_data);
}

void skb_reserve(struct sk_buff *skb, int len) {
	void *data = (UInt8*)mbuf_data(skb->mac_data) + len;
	mbuf_setdata(skb->mac_data,data, mbuf_len(skb->mac_data));// m_len is not changed.
}

//void skb_queue_tail(&local->skb_queue, skb);

void *skb_put(struct sk_buff *skb, unsigned int len) {
    /*unsigned char *tmp = skb->tail;
     SKB_LINEAR_ASSERT(skb);
     skb->tail += len;
     skb->len  += len;
     return tmp;*/
    void *data = (UInt8*)mbuf_data(skb->mac_data) + mbuf_len(skb->mac_data);
    //mbuf_prepend(&skb,len,1); /* no prepend work */
    //IWI_DUMP_MBUF(1,skb,len);  
    if(mbuf_trailingspace(skb->mac_data) > len ){
        mbuf_setlen(skb->mac_data, mbuf_len(skb->mac_data)+len);
        if(mbuf_flags(skb->mac_data) & MBUF_PKTHDR)
            mbuf_pkthdr_setlen(skb->mac_data, mbuf_pkthdr_len(skb->mac_data)+len);
    }
    //IWI_DUMP_MBUF(2,skb,len);  
    return data;
}


void dev_kfree_skb_any(struct sk_buff *skb) {
    dev_kfree_skb(skb);
}

void dev_kfree_skb(struct sk_buff *skb) {
    IONetworkController *intf = (IONetworkController *)skb->intf;
    if (!(mbuf_type(skb->mac_data) == MBUF_TYPE_FREE))
        intf->freePacket(skb->mac_data);
}

struct sk_buff *__alloc_skb(unsigned int size,gfp_t priority, int fclone, int node) {
    struct sk_buff *skb = (struct sk_buff *)IOMalloc(sizeof(struct sk_buff));
    skb->mac_data = currentController->allocatePacket(size);
    skb->intf = (void *)currentController;
	mbuf_setlen(skb->mac_data, 0);
	mbuf_pkthdr_setlen(skb->mac_data,0);
    return skb;
}


#pragma mark -
#pragma mark Adapt workqueue calls

/*
	wait for the end of all threads ?
*/
void flush_workqueue(struct workqueue_struct *wq){
	return;
}
/*
	Alloc the memory for a workqueue struct
*/
struct workqueue_struct *__create_workqueue(const char *name,int singlethread){
	struct workqueue_struct* tmp_workqueue = (struct workqueue_struct*)IOMalloc(sizeof(struct workqueue_struct));
	if(!tmp_workqueue)
		return NULL;
	return tmp_workqueue;
}

static thread_call_t tlink[256];//for the queue work...

/*
	Cancel a work queue
*/
void queue_td(int num , thread_call_func_t func)
{
	if (tlink[num])
	{
		thread_call_cancel(tlink[num]);
	}
}

void test_function(work_func_t param0,thread_call_param_t param1){
	if(param0 && param1)
		(param0)((work_struct*)param1);
	else
		IOLog("Error while lauch a thread\n");
}
/*
	Add a queue work 
*/
void queue_te(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, bool start)
{
	par=my_hw->priv;
	thread_call_func_t my_func;
	if (tlink[num])
		queue_td(num,NULL);
	if (!tlink[num])
		tlink[num]=thread_call_allocate((thread_call_func_t)test_function,(void*)func);
	uint64_t timei2;
	if (timei)
		clock_interval_to_deadline(timei,kMillisecondScale,&timei2);
	int r;
	if (start==true && tlink[num])
	{
		if (!par && !timei)	
			r=thread_call_enter(tlink[num]);
		if (!par && timei)
			r=thread_call_enter_delayed(tlink[num],timei2);
		if (par && !timei)
			r=thread_call_enter1(tlink[num],par);
		if (par && timei)
			r=thread_call_enter1_delayed(tlink[num],par,timei2);
	}
}


	

//static mutex
struct thread_data{
	work_func_t func;
	void* param;
	int delay;
	int thread_number;
};



/*
	FIXME: Finish IT ;)
	Used only once
	Have be finished...
*/
void tasklet_schedule(struct tasklet_struct *t){
	queue_te(13,(thread_call_func_t)t->func,my_hw->priv,NULL,true);
	return;
}
/*
	Used only once ,
*/
void tasklet_init(struct tasklet_struct *t, void (*func)(unsigned long), unsigned long data){
	t->func=func;
	t->data=data;
	return;
}

int queue_work(struct workqueue_struct *wq, struct work_struct *work) {
#warning Get this to run in a gated manner//
	queue_te(work->number,(thread_call_func_t)work->func,my_hw->priv,NULL,true);
    return 0;
}

int queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *work, unsigned long delay) {
	struct work_struct tmp = work->work;
	struct work_struct *tmp2 = &tmp;
	queue_te(tmp2->number,(thread_call_func_t)tmp2->func,my_hw->priv,delay,true);
    return 0;
}
/**
* __wake_up - wake up threads blocked on a waitqueue.
* @q: the waitqueue
* @mode: which threads
* @nr_exclusive: how many wake-one or wake-many threads to wake up
* @key: is directly passed to the wakeup function
*/
void __wake_up(wait_queue_head_t *q, unsigned int mode, int nr, void *key) {
//wait_queue_wakeup_thread(wait_queue_t wq, event_t  event,
//            thread_t thread, int result);
    return;
}

int cancel_delayed_work(struct delayed_work *work) {
	struct work_struct tmp = work->work;
	struct work_struct *tmp2 = &tmp;
	queue_td(tmp2->number,NULL);
    return 0;
}

//?
int cancel_work_sync(struct work_struct *work){
	queue_td(work->number,NULL);
	return 0;
}

/*
	Unalloc? 
*/
void destroy_workqueue (	struct workqueue_struct *  	wq){
	for(int i=0;i<256;i++)
		queue_td(i,NULL);
	return;
}




void start_undirect_scan(){
	struct ieee80211_local *local;
	local=hw_to_local(my_hw);
	local->ops->hw_scan(my_hw, NULL, 0);
}

void io_write32(u32 ofs, u32 val){
	if(my_pci_device)
		if(my_map)
			my_pci_device->ioWrite32(ofs, val, my_map);
}

u32 io_read32(u32 ofs){
	if(my_pci_device)
		if(my_map)
			return my_pci_device->ioRead32(ofs, my_map);
	return NULL;
}