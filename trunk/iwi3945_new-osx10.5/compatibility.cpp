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
//static IOFilterInterruptEventSource * DMAInterruptSource;
static IOInterruptEventSource *	DMAInterruptSource;
static irqreturn_t (*realHandler)(int, void *);
static pci_driver * my_drv;
struct pci_dev* my_pci_dev;
IOPCIDevice* my_pci_device;
IOMemoryMap	*				my_map;

static int next_thread=0;
static int thread_pos=0;
static IOLock* thread_lock;


#define MAX_MUTEXES 256
static struct mutex *mutexes[MAX_MUTEXES];
unsigned long current_mutex = 0;

/*
	Getters
*/
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
	if(!workqueue){
		workqueue = IOWorkLoop::workLoop();
		/*if(workqueue)
			IOLog("Workloop creation successful!\n");
		else
			IOLog("FAILED!  Couldn't create workloop\n");*/
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
            //break;
		}
		
		/*DMAInterruptSource = IOFilterInterruptEventSource::filterInterruptEventSource(
								currentController, 
								(IOInterruptEventAction)&interuptsHandler,
								(IOFilterInterruptAction)&DMAFilter,
								currentController->getProvider(),
								(int)1 );*/
			
		// This is important. If the interrupt line is shared with other devices,
		// then the interrupt vector will be enabled only if all corresponding
		// interrupt event sources are enabled. To avoid masking interrupts for
		// other devices that are sharing the interrupt line, the event source
		// is enabled immediately.
		//DMAInterruptSource->enable();
		fInterruptSrc->enable();
	//printf("request_irq [OK]\n");
	return 0;
}

//FIXME: test
void enable_int(){
	if(fInterruptSrc)
		fInterruptSrc->enable();
    /*else
        printf("Ignored enable_int(): no fInterruptSrc\n");*/
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
	//lck_mtx_lock(new_mtx->mlock);
//#endif
    return;
}

void mutex_unlock(struct mutex *new_mtx) {
//#ifndef NO_MUTEX_LOCKS
    //mutexes[current_mutex--] = NULL;
	//lck_mtx_unlock(new_mtx->mlock);
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
	//disable_int();
	spin_lock(lock);
    return;
}

void spin_unlock_bh( spinlock_t *lock ) {
	spin_unlock(lock);
	//enable_int();
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


static void ieee80211_tasklet_handler(unsigned long data)
 {

}





/* This is a version of the rx handler that can be called from hard irq
 * context. Post the skb on the queue and schedule the tasklet */
void ieee80211_rx_irqsafe(struct ieee80211_hw *hw, struct sk_buff *skb, struct ieee80211_rx_status *status)
{
	//ieee80211_rx(skb,status);
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
	
	return;
//    skb->dev = local->mdev;
    // copy status into skb->cb for use by tasklet
    memcpy(skb->cb, status, sizeof(*status));
    mbuf_settype(skb->mac_data, MBUF_TYPE_DATA);
    //skb_queue_tail(&local->skb_queue, skb);
    tasklet_schedule(&local->tasklet);
	//IOCreateThread(&ieee80211_tasklet_handler, (long unsigned int)local);

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
	return;
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
void SET_IEEE80211_PERM_ADDR (	struct ieee80211_hw *  	hw, 	u8 *  	addr){
	return;
}


#pragma mark -
#pragma mark Kernel PCI fiddler adapters

//http://www.promethos.org/lxr/http/source/arch/sparc64/kernel/pci_iommu.c#L698
void pci_dma_sync_single_for_cpu(struct pci_dev *hwdev, dma_addr_t dma_handle, size_t size, int direction){
	return;
}

int pci_write_config_word(struct pci_dev *dev, int where, u16 val){
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
    fPCIDevice->extendedConfigWrite16(where,val);
    return 0;
}


int pci_enable_msi  (struct pci_dev * dev){
	return 0;
}

//ok
int pci_restore_state (	struct pci_dev *  	dev){
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	int i;
	for (i = 0; i < 16; i++)
		fPCIDevice->configWrite32(i * 4, dev->saved_config_space[i]);
	//printf("PCI restore state [OK]\n");
	return 0;
}
/*
 IO and memory
 */
 //ok
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
	//printf("if_down\n");
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
    local->scan.tx_control.key_idx = HW_KEY_IDX_INVALID;
    local->scan.tx_control.flags |= IEEE80211_TXCTL_DO_NOT_ENCRYPT;
    memset(&extra, 0, sizeof(extra));
    extra.endidx = local->num_curr_rates;
    local->scan.tx_control.tx_rate =
    rate_control_get_rate(local, local->mdev,
                          local->scan.skb, &extra)->val;
    local->scan.tx_control.flags |= IEEE80211_TXCTL_NO_ACK;
}








int run_add_interface( struct ieee80211_local *local ) {
    struct ieee80211_if_init_conf conf;
    int res;
    
    conf.if_id = IEEE80211_IF_TYPE_IBSS;
    conf.type = 2;
    conf.mac_addr = (void *)"121212"; //dev->dev_addr;
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


	fPCIDevice->setBusMasterEnable(true);

	fPCIDevice->setMemoryEnable(true);
	int result2 = (drv->probe) (test_pci,test);
    
    
	//Start ...
#warning This assumes the "happy path" and fails miserably when things don't go well
	struct ieee80211_local *local = hw_to_local(my_hw);

	result2 = (local->ops->open) (&local->hw);

    int result3 = run_add_interface( local );

    
    
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
	fPCIDevice->setMemoryEnable(true);
	//printf("PCI setMaster [OK]\n");
	return;
}

void free_irq (unsigned int irq, void *dev_id){
	return;
}
void pci_disable_msi(struct pci_dev* dev){
	return;
}

//ok but no saved_config_space in pci_dev struct
int pci_save_state (struct pci_dev * dev){
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	int i;
	for (i = 0; i < 16; i++)
		dev->saved_config_space[i]=fPCIDevice->configRead32(i * 4);
	//printf("PCI save state [OK]\n");
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
    fPCIDevice->extendedConfigWrite8(where,val);
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
int pci_set_consistent_dma_mask(struct pci_dev *dev, u64 mask){
	//test if dma supported (ok 3945)
	//dev->dev.coherent_dma_mask = mask;
	return 0;
}

void pci_free_consistent(struct pci_dev *hwdev, size_t size,void *vaddr, dma_addr_t dma_handle) {
    return IOFreeContiguous(vaddr, size);
}

/*this::IOBufferMemoryDescriptor* MemoryDmaAlloc(UInt32 buf_size, dma_addr_t *phys_add, void *virt_add)
{
	IOBufferMemoryDescriptor *memBuffer;
	void *virt_address;
	dma_addr_t phys_address;
	IOMemoryMap *memMap;

	memBuffer = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task, 
	kIODirectionOutIn | kIOMemoryPhysicallyContiguous | 
	kIOMapInhibitCache | kIOMemoryAutoPrepare , buf_size, 
	PAGE_SIZE); 



	memMap = memBuffer->map();

	if (memMap == NULL) {
		IWI_DEBUG("mapping failed\n");
		memBuffer->release();
		memBuffer = NULL;

		return NULL;	
	}

	if (phys_add!=NULL)
		phys_address = memMap->getPhysicalAddress();

	if (virt_add!=NULL)
	{
		virt_address = (void *)memMap->getVirtualAddress();

		if (virt_address == NULL || phys_address == NULL) {
			memMap->release();
			memBuffer->release();
			memBuffer = NULL;

			return NULL;
		}
	}
	if (phys_add!=NULL) *phys_add = phys_address;
	if (virt_add!=NULL)	*(IOVirtualAddress*)virt_add = (IOVirtualAddress)virt_address;
	memMap->release();

	return memBuffer;
}*/

#include <IOKit/IOMapper.h>
void *pci_alloc_consistent(struct pci_dev *hwdev, size_t size,dma_addr_t *dma_handle,int count) {

	
	//2MB but now I'm sur ;)
    return IOMallocContiguous(size,2*1024*1024, dma_handle);
	/*IOBufferMemoryDescriptor *memBuffer;
	memBuffer = IOBufferMemoryDescriptor::inTaskWithOptions(
						kernel_task,
                        kIOMemoryPhysicallyContiguous,
                        size,
						PAGE_SIZE );

    if ( memBuffer == 0 ||memBuffer->prepare() != kIOReturnSuccess )
    {
        IOLog("pci_alloc_consistent\n");
		void *virtual_ptr = memBuffer->getBytesNoCopy();
		IOByteCount length;
		*dma_handle = memBuffer->getPhysicalSegment( 0, &length );
		return virtual_ptr;
	}
	IOLog("\nError !!!!!\n");
	*dma_handle=NULL;
	return NULL;*/

}

void __iomem * pci_iomap (	struct pci_dev *  	dev,int  	bar,unsigned long  	maxlen){
	IOMemoryMap	*				map;
	//my_map=map;
	IOPhysicalAddress			phys_add;
	UInt16 *					virt_add;
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;

	
  		map = fPCIDevice->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0, kIOMapInhibitCache);
  		if (map == 0) {
			//IOLog("%s map is zero\n", getName());
		//	break;
			return NULL;
		}
		uint16_t reg;
		
				/* We disable the RETRY_TIMEOUT register (0x41) to keep
		 * PCI Tx retries from interfering with C3 CPU state */
		reg = fPCIDevice->configRead16(0x40);
		if((reg & 0x0000ff00) != 0)
			fPCIDevice->configWrite16(0x40, reg & 0xffff00ff);
			
		return (void*)map->getVirtualAddress();

}


void pci_iounmap(struct pci_dev *dev, void __iomem * addr){
	return;
}


void pci_unmap_single(struct pci_dev *hwdev, dma_addr_t dma_addr,
                      size_t size, int direction) {
    IODirection mydir = (IODirection) direction;
    IOMemoryDescriptor::withPhysicalAddress(dma_addr,
                                            size, mydir)->complete(mydir);
    IOMemoryDescriptor::withPhysicalAddress(dma_addr,
                                            size, mydir)->release();
}

addr64_t pci_map_single(struct pci_dev *hwdev, void *ptr, size_t size, int direction) {
    /*unsigned int i;
    if( current_mutex )
        for(i=0; i<current_mutex; i++)
            mutex_unlock(mutexes[i]);*/
		addr64_t tmp = mbuf_data_to_physical( (u8*)ptr);
if(tmp){
    //IOLog("\n\n\n------------------------------------>M_BUF ADDR: %llx\n\n\n",tmp);
	//IOSleep(5000);
	return tmp;
}else{
	//IOLog("\n\n\n---------------------->NULLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL\n\n\n");
	//IOSleep(5000);
	return NULL;
}
	//addr64_t tmp = cpu_to_le32( mbuf_data_to_physical( (u8*)ptr) );
    /*if( current_mutex )
        for(i=0; i<current_mutex; i++)
            mutex_lock(mutexes[i]);*/
}


int pci_read_config_byte(struct pci_dev *dev, int where, u8 *val) {
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
    *val = fPCIDevice->extendedConfigRead8(where);
    return 0;
}

int pci_read_config_word(struct pci_dev *dev, int where, u16 *val) {
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
    *val = fPCIDevice->extendedConfigRead16(where);
    return 0;
}

int pci_read_config_dword(struct pci_dev *dev, int where, u32 *val) {
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
    *val = fPCIDevice->extendedConfigRead32(where);
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
    return mbuf_len(skb->mac_data);
}

void skb_reserve(struct sk_buff *skb, int len) {
    mbuf_setlen(skb->mac_data, len);
}

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

struct sk_buff *__alloc_skb(unsigned int size,
                            gfp_t priority, int fclone, int node) {
    /*unsigned int i;
    if( current_mutex )
        for(i=0; i<current_mutex; i++)
            mutex_unlock(mutexes[i]);*/
    struct sk_buff *skb = (struct sk_buff *)IOMalloc(sizeof(struct sk_buff));
    skb->mac_data = currentController->allocatePacket(size);
    skb->intf = (void *)currentController;
    /*if( current_mutex )
        for(i=0; i<current_mutex; i++)
            mutex_lock(mutexes[i]);*/
    return skb;
}


#pragma mark -
#pragma mark Adapt workqueue calls
/*
	Proposition : lauch a thread at the init of the driver who check every ms if a thread have to be lauch
	
	struct thread_struct{
		...thread,
		microtimestamp starttime,
		boolean started
	}

//Thread lauch at the start of the driver
void threadHandller(){
	foreach ms{
		foreachworkqueue{
				if(thread_struct[0]->started){
					//if finished
						//clean
						//and replace all the thread (1 goes to 0 , 2 goes to 1)
						//start the next thread
				}else{
					if(starttime<=now_time){
						//start
						thrad_struct[0]->started=true;
					}
				}	
		}
	}
}

*/
/*
	wait for the end of all threads ?
*/
void flush_workqueue(struct workqueue_struct *wq){
	//int i
	//for(;;)
		//wq->tlink;
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
/*
	Unalloc? 
*/
void destroy_workqueue (	struct workqueue_struct *  	wq){
	//for ...x in
	//wq->tlink[x]=NULL;
	return;
}
//?
int cancel_work_sync(struct work_struct *work){
	return 1;
}


static thread_call_t tlink[256];//for the queue work...
//static int thread_pos=0;
/*
	Cancel a work queue
*/
void queue_td(int num , thread_call_func_t func)
{
	IOLog("queue_td0 %d\n",tlink[num]);
	if (tlink[num])
	{
		thread_call_cancel(tlink[num]);
		//if (thread_call_cancel(tlink[num])==0)
		//	thread_call_free(tlink[num]);
		//tlink[num]=NULL;
	}
	//IOLog("queue_td1-%d , %d %d\n",num,r,r1);
}

void test_function(work_func_t param0,thread_call_param_t param1){
	//IOLog("Real par0 : %08x\n",param0);
	//IOLog("Real par1 : %08x\n",param1);
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
	//my_func=(thread_call_func_t)test_function;
	if (tlink[num])
		queue_td(num,NULL);
	//IOLog("queue_te0 %d\n",tlink[num]);
	if (!tlink[num])
		tlink[num]=thread_call_allocate((thread_call_func_t)test_function,(void*)func);
	//IOLog("queue_te1 %d\n",tlink[num]);
	uint64_t timei2;
	if (timei)
		clock_interval_to_deadline(timei,kMillisecondScale,&timei2);
	//IOLog("queue_te time %d %d\n",timei,timei2);
	int r;
	if (start==true && tlink[num])
	{
		//IOLog("Normal par : %08x\n",par);
		if (!par && !timei)	
			r=thread_call_enter(tlink[num]);
		if (!par && timei)
			r=thread_call_enter_delayed(tlink[num],timei2);
		if (par && !timei)
			r=thread_call_enter1(tlink[num],par);
		if (par && timei)
			r=thread_call_enter1_delayed(tlink[num],par,timei2);
	}
	//IWI_DEBUG("queue_te result %d\n",r);
}


	

//static mutex
struct thread_data{
	work_func_t func;
	void* param;
	int delay;
	int thread_number;
};

void start_thread(void* data){

	struct thread_data* data_thread=(struct thread_data *)data;
//	if(!thread_lock)
//		thread_lock = IOLockAlloc();
	//do{
		//mutex
	//	IOLockLock(thread_lock);
	//}while(data_thread->thread_number!=next_thread);
	if(data_thread->delay>0){
		IOSleep(data_thread->delay);  
	}
	(data_thread->func)((work_struct*)my_hw->priv);
	//next_thread++;
	//mutex
	//IOLockUnlock(thread_lock);
	IOExitThread();
}

static bool tasklet_enable;

void enable_tasklet(){
	tasklet_enable=true;
	//IOLog("Enabling tasklet............................................\n");
}
/*
	FIXME: Finish IT ;)
	Used only once
	Have be finished...
*/
void tasklet_schedule(struct tasklet_struct *t){
	//if(tasklet_enable){
		IOThread mythread;
		struct thread_data *md = (struct thread_data *)IOMalloc(sizeof(*md));
		md->func =  (void (*)(work_struct*))t->func;
		md->delay = 0;
		//md->thread_number = thread_pos++;
		mythread = IOCreateThread(&start_thread, (void *)md);
	//}else
	//	IOLog("Tasklet not enable");
	//queue_te(13,(thread_call_func_t)t->func,my_hw->priv,NULL,true);
	return;
}
/*
	Used only once ,
*/
void tasklet_init(struct tasklet_struct *t, void (*func)(unsigned long), unsigned long data){
	tasklet_enable=false;
	t->func=func;
	t->data=data;
	return;
}

//FIXME: thread change param adresse
int queue_work(struct workqueue_struct *wq, struct work_struct *work) {
#warning Get this to run in a gated manner//
	//queue_te(work->number,(thread_call_func_t)work->func,my_hw->priv,NULL,true);
	IOThread mythread;
    struct thread_data *md = (struct thread_data *)IOMalloc(sizeof(*md));
    md->func = work->func;
	md->delay = 0;
	md->thread_number = thread_pos++;
    mythread = IOCreateThread(&start_thread, (void *)md);
    return 0;
}
//FIXME: thread change param adresse
int queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *work, unsigned long delay) {
	struct work_struct tmp;
	tmp=work->work;
	struct work_struct *tmp2;
	tmp2=&tmp;
	//queue_te(tmp2->number,(thread_call_func_t)tmp2->func,my_hw->priv,delay,true);
	IOThread mythread;
    struct thread_data *md = (struct thread_data *)IOMalloc(sizeof(*md));
    md->func = tmp2->func;
	md->delay = delay;
	md->thread_number = thread_pos++;
    mythread = IOCreateThread(&start_thread, (void *)md);
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
	//?
    return 0;
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