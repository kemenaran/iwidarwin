/*
 *  compatibility.cpp
 *  iwi3945
 *
 *  Created by Sean Cross on 2/8/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */

#define NO_SPIN_LOCKS 1
#define NO_MUTEX_LOCKS 1

#include <sys/kernel_types.h>
#include <mach/vm_types.h>
#include <sys/kpi_mbuf.h>

#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/network/IONetworkController.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/OSAtomic.h>
#include <IOKit/IOInterruptEventSource.h>

#include "defines.h"
#include "compatibility.h"
#include "firmware/ipw3945.ucode.h"



// Note: This, in itself, makes this very much non-reentrant.  It's used
// primarily when allocating sk_buff entries.
static IONetworkController *currentController;
static ieee80211_hw * my_hw;


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
	//struct class_device *class_dev;
	struct firmware *firmware;
	*firmware_p = firmware =(struct firmware*)IOMalloc(sizeof(struct firmware));
	firmware->size=149652;//crappy
	
	firmware->data=(u8*)ipw3945_ucode_raw;
	//load the file "name" in
	return 0;
}
void release_firmware (	const struct firmware *  fw){
	return;
}




void sysfs_remove_group(struct kobject * kobj,const struct attribute_group * grp){
	return;
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
	not finish parameter of handler and workqueue
*/
int request_irq(unsigned int irq, irqreturn_t (*handler)(int, void *), unsigned long irqflags, const char *devname, void *dev_id) {
        IOInterruptEventSource *	fInterruptSrc;
		fInterruptSrc = IOInterruptEventSource::interruptEventSource(
							currentController, (IOInterruptEventAction)handler,currentController->getProvider());
		/*if(!fInterruptSrc || (workqueue->addEventSource(fInterruptSrc) != kIOReturnSuccess)) {
			IOLog("%s fInterruptSrc error\n", getName());
            return 1;
		}*/
		// This is important. If the interrupt line is shared with other devices,
		// then the interrupt vector will be enabled only if all corresponding
		// interrupt event sources are enabled. To avoid masking interrupts for
		// other devices that are sharing the interrupt line, the event source
		// is enabled immediately.
		//fInterruptSrc->enable();
	printf("request_irq [OK]\n");
	return 0;
}





void mutex_init(struct mutex *){
	return;
}
//end added
void spin_lock_irqsave(spinlock_t *lock, int fl) {
//mask interupts
//local_irq_save(fl) on linux
/*
#define local_irq_save(x) ({ __save_flags(x); __cli(); })
#define __save_flags(x) asm volatile ("movew %%sr,%0":"=d" (x) : :
"memory")
#define __cli() asm volatile ("oriw #0x0700,%%sr": : : "memory")
*/
       spin_lock(lock);
   return;
}

void spin_unlock_irqrestore(spinlock_t *lock, int fl) {
 //unmask interups
/*#define __restore_flags(x) asm volatile ("movew %0,%%sr": :"d" (x) :
"memory")*/
       spin_unlock(lock);
   return;
}

void spin_lock_init(spinlock_t *lock) {
/*#define spin_lock_init(x) do { (x)->slock = 0; } while(0)*/
   return;
}

void spin_lock(spinlock_t *lock) {
#ifndef NO_SPIN_LOCKS
    lck_spin_lock(lock->slock);
#endif //NO_SPIN_LOCKS
    return;
}

void spin_unlock(spinlock_t *lock) {
#ifndef NO_SPIN_LOCKS
    lck_spin_unlock(lock->slock);
#endif //NO_SPIN_LOCKS
    return;
}

//http://hira.main.jp/wiki/pukiwiki.php?spin_lock_bh()%2Flinux2.6
void spin_lock_bh( spinlock_t *lock ) {
    return;
}

void spin_unlock_bh( spinlock_t *lock ) {
    return;
}

void mutex_lock(struct mutex *new_mtx) {
#ifndef NO_MUTEX_LOCKS
	lck_mtx_lock(new_mtx->lock);
#endif
    return;
}

void mutex_unlock(struct mutex *new_mtz) {
#ifndef NO_MUTEX_LOCKS
	lck_mtx_unlock(new_mtx->lock);
#endif
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
    return 1;
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


/* This is a version of the rx handler that can be called from hard irq
 * context. Post the skb on the queue and schedule the tasklet */
void ieee80211_rx_irqsafe(struct ieee80211_hw *hw, struct sk_buff *skb,
                          struct ieee80211_rx_status *status)
{
    struct ieee80211_local *local = hw_to_local(hw);
    
    BUILD_BUG_ON(sizeof(struct ieee80211_rx_status) > sizeof(skb->cb));
    
    IOLog("todo ieee80211_rx_irqsafe\n");
/*
//    skb->dev = local->mdev;
    // copy status into skb->cb for use by tasklet
    memcpy(skb->cb, status, sizeof(*status));
    mbuf_settype(skb->mac_data, MBUF_TYPE_DATA);
    skb_queue_tail(&local->skb_queue, skb);
    tasklet_schedule(&local->tasklet);
*/
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
	return;
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
	
	printf("ieee80211_alloc_hw [OK]\n");
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

//http://www.promethos.org/lxr/http/source/drivers/pci/msi.c#L691
int pci_enable_msi  (struct pci_dev * dev){
	return 0;
}

//ok
int pci_restore_state (	struct pci_dev *  	dev){
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	int i;
	for (i = 0; i < 16; i++)
		fPCIDevice->configWrite32(i * 4, dev->saved_config_space[i]);
	printf("PCI restore state [OK]\n");
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
	fPCIDevice->setIOEnable(true);
	fPCIDevice->setMemoryEnable(true);
	printf("PCI device enabled [OK]\n");
	return 0;
}
//ok but nor realy that on linux kernel
void pci_disable_device (struct pci_dev * dev){
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	fPCIDevice->setIOEnable(false);
	fPCIDevice->setMemoryEnable(false);
	printf("PCI device Disabled [OK]\n");
}

/*
Adds the driver structure to the list of registered drivers.
Returns a negative value on error, otherwise 0.
If no error occurred, the driver remains registered even if no device was claimed during registration.
*/
//http://www.promethos.org/lxr/http/source/drivers/pci/pci-driver.c#L376
int pci_register_driver(struct pci_driver * drv){
	//maybe get the pointer for the good function as iwl3945_pci_probe ...
	struct pci_device_id *test=(struct pci_device_id *)IOMalloc(sizeof(struct pci_device_id));
	struct pci_dev *test_pci=(struct pci_dev *)IOMalloc(sizeof(struct pci_dev));
	
	//struct device *dev=(struct device *)IOMalloc(sizeof(struct device));
	//=test_dev;
	//pci_dev create the os-x kobj
	
	if(!currentController){
		printf("No currentController set\n");
		return 1;
	}
	OSDynamicCast(IOPCIDevice, currentController->getProvider());
	//printf("OK IOPCIDevice");

	test_pci->dev.kobj.ptr=OSDynamicCast(IOPCIDevice, currentController->getProvider());
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)test_pci->dev.kobj.ptr;
	fPCIDevice->retain();
	fPCIDevice->open(currentController);
	printf("PCI device [OK]\n");
	//call of pci_probe
	int result2 = (drv->probe) (test_pci,test);
	//Start ...
	struct ieee80211_local *local = hw_to_local(my_hw);
	//priv->pci_dev=(struct pci_device *)test_pci;
	//local->hw.priv->pci_dev=test_pci;
	result2 = (local->ops->open) (&local->hw);
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
	printf("PCI setMaster [OK]\n");
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
	printf("PCI save state [OK]\n");
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
int pci_set_consistent_dma_mask(struct pci_dev *dev, u64 mask){
	//test if dma supported (ok 3945)
	//dev->dev.coherent_dma_mask = mask;
	return 0;
}

void pci_free_consistent(struct pci_dev *hwdev, size_t size,
                                 void *vaddr, dma_addr_t dma_handle) {
    return IOFreeContiguous(vaddr, size);
}

void *pci_alloc_consistent(struct pci_dev *hwdev, size_t size,
                           dma_addr_t *dma_handle) {
    return IOMallocContiguous(size, 4, dma_handle);
}

void __iomem * pci_iomap (	struct pci_dev *  	dev,int  	bar,unsigned long  	maxlen){
	IOMemoryMap	*				map;
	IOPhysicalAddress			ioBase;
	UInt16 *					memBase;
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	map = fPCIDevice->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0, kIOMapInhibitCache);
	if (map == 0) {
		return NULL;
	}
	ioBase = map->getPhysicalAddress();
	memBase = (UInt16 *)map->getVirtualAddress();
	printf("Iomap [OK]\n");
	return memBase;
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
    return cpu_to_le32( mbuf_data_to_physical( (u8*)ptr) );
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
    struct sk_buff *skb = (struct sk_buff *)IOMalloc(sizeof(struct sk_buff));
    skb->mac_data = currentController->allocatePacket(size);
    skb->intf = (void *)currentController;
    return skb;
}


#pragma mark -
#pragma mark Adapt workqueue calls

void flush_workqueue(struct workqueue_struct *wq){
	return;
}
struct workqueue_struct *__create_workqueue(const char *name,int singlethread){
	return NULL;
}
void destroy_workqueue (	struct workqueue_struct *  	wq){
	//for ...x in
	//wq->tlink[x]=NULL;
	return;
}
int cancel_work_sync(struct work_struct *work){
	return 1;
}
void tasklet_schedule(struct tasklet_struct *t){
	return;
}
/*
*/
void tasklet_init(struct tasklet_struct *t, void (*func)(unsigned long), unsigned long data){
	return;
}


int queue_work(struct workqueue_struct *wq, struct work_struct *work) {
#warning Get this to run in a gated manner
    (work->func)(work);
	//maybe add a counter in workqueue struct
	//queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,work),NULL,NULL,false,wq->tlink);
    return 0;
}
/*void queue_te(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, bool start,thread_call_t tkink)
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

void queue_td(int num , thread_call_func_t func)
{
	//IWI_DEBUG("queue_td0 %d\n",tlink[num]);
	//IWI_DEBUG("queue_td0 %d\n",tlink[num]);
	if (tlink[num])
	{
		thread_call_cancel(tlink[num]);
		//if (thread_call_cancel(tlink[num])==0)
		//	thread_call_free(tlink[num]);
		//tlink[num]=NULL;
	}
	//IWI_DEBUG("queue_td1-%d , %d %d\n",num,r,r1);
}*/

int queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *work, unsigned long delay) {
    IOLog("todo queue_delayed_work\n");
	//queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,work),NULL,delay,false,wq->tlink);
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

/**
* wait_event_interruptible_timeout - sleep until a condition gets true or a timeout elapses
* @wq: the waitqueue to wait on
* @condition: a C expression for the event to wait for
* @timeout: timeout, in jiffies
*
* The process is put to sleep (TASK_INTERRUPTIBLE) until the
* @condition evaluates to true or a signal is received.
* The @condition is checked each time the waitqueue @wq is woken up.
*
* wake_up() has to be called after changing any variable that could
* change the result of the wait condition.
*
* The function returns 0 if the @timeout elapsed, -ERESTARTSYS if it
* was interrupted by a signal, and the remaining jiffies otherwise
* if the condition evaluated to true before the timeout elapsed.
*/
long wait_event_interruptible_timeout(wait_queue_head_t wq, long condition, long timeout) {
    return 0;
}

void setCurController(IONetworkController *tmp){
	currentController=tmp;
	printf("settCurController [OK]\n");
}

struct ieee80211_hw * get_my_hw(){
	return my_hw;
}


