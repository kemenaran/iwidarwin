/*
 *  compatibility.cpp
 *  iwi3945
 *
 *  Created by Sean Cross on 2/8/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */

#include <sys/kernel_types.h>
#include <mach/vm_types.h>
#include <sys/kpi_mbuf.h>

#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/network/IONetworkController.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/OSAtomic.h>

#include "defines.h"
#include "compatibility.h"


// Note: This, in itself, makes this very much non-reentrant.  It's used
// primarily when allocating sk_buff entries.
static IONetworkController *currentController;

//added
int sysfs_create_group(struct kobject * kobj,const struct attribute_group * grp){
	return NULL;
}

int request_firmware  (const struct firmware ** firmware_p, const char * name, struct device * device){
	return 1;
}
void release_firmware (	const struct firmware *  	fw){
	return;
}

void flush_workqueue(struct workqueue_struct *wq){
	return;
}
struct workqueue_struct *__create_workqueue(const char *name,int singlethread){
	return NULL;
}
void destroy_workqueue (	struct workqueue_struct *  	wq){
	return;
}
int cancel_work_sync(struct work_struct *work){
	return 1;
}
void tasklet_schedule(struct tasklet_struct *t){
	return;
}
void tasklet_init(struct tasklet_struct *t, void (*func)(unsigned long), unsigned long data){
	return;
}


void sysfs_remove_group(struct kobject * kobj,const struct attribute_group * grp){
	return;
}


void hex_dump_to_buffer(const void *buf, size_t len, int rowsize,int groupsize, char *linebuf, size_t linebuflen, bool ascii){
	return;
}

unsigned long simple_strtoul (const char * cp, char ** endp, unsigned int base){
	return 1;
}

int is_zero_ether_addr (	const u8 *  	addr){
	return 1;
}





/*int request_irq(unsigned int irq, void (*handler)(int, struct pt_regs *), unsigned long flags, const char *device){
	return 1;
}*/





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
	OSSpinLockLock(lock);
   return;
}

void spin_unlock(spinlock_t *lock) {
	OSSpinLockUnlock(lock);
   return;
}
//http://hira.main.jp/wiki/pukiwiki.php?spin_lock_bh()%2Flinux2.6
void spin_lock_bh( spinlock_t *lock ) {
    return;
}

void spin_unlock_bh( spinlock_t *lock ) {
    return;
}

void mutex_lock(struct mutex *) {
	IOLockLock(mutex->lock);
    return;
}

void mutex_unlock(struct mutex *) {
	IOLockUnlock(mutex->lock);
    return;
}

void msleep(unsigned int msecs) {
	udelay(msecs*100);
    return;
}

void init_timer(struct timer_list *timer) {
    return IOPCCardAddTimer(timer);
}


int del_timer_sync(struct timer_list *timer) {
    return IOPCCardDeleteTimer(timer);
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

struct sk_buff *ieee80211_beacon_get(struct ieee80211_hw *hw,
                                     int if_id,
                                     struct ieee80211_tx_control *control) {
    return NULL;
}


void ieee80211_stop_queues(struct ieee80211_hw *hw) {
    return;
}
int ieee80211_register_hw (	struct ieee80211_hw *  	hw){
	return 1;
}
void ieee80211_unregister_hw (	struct ieee80211_hw *  	hw){
	return;
}
void ieee80211_start_queues(struct ieee80211_hw *hw){
	return;
}
void ieee80211_scan_completed (	struct ieee80211_hw *  	hw){
	return;
}
struct ieee80211_hw * ieee80211_alloc_hw (	size_t  	priv_data_len,const struct ieee80211_ops *  	ops){
	return NULL;
}
void ieee80211_free_hw (	struct ieee80211_hw *  	hw){
	return;
}
int ieee80211_register_hwmode(struct ieee80211_hw *hw,struct ieee80211_hw_mode *mode){
	return 1;
}
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
	return 1;
}

//ok
int pci_restore_state (	struct pci_dev *  	dev){
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj;
	int i;
	//for (i = 0; i < 16; i++)
	//	fPCIDevice->configWrite32(i * 4, dev->saved_config_space[i]);
	return 0;
}
/*
 IO and memory
 */
 //ok
int pci_enable_device (struct pci_dev * dev){
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj;
	fPCIDevice->setIOEnable(true);
	fPCIDevice->setMemoryEnable(true);
	return 0;
}
//ok but nor realy that on linux kernel
void pci_disable_device (struct pci_dev * dev){
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj;
	fPCIDevice->setIOEnable(false);
	fPCIDevice->setMemoryEnable(false);
}
/*
Adds the driver structure to the list of registered drivers.
Returns a negative value on error, otherwise 0.
If no error occurred, the driver remains registered even if no device was claimed during registration.
*/
//http://www.promethos.org/lxr/http/source/drivers/pci/pci-driver.c#L376
int pci_register_driver(struct pci_driver * drv){
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
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj;
	fPCIDevice->setBusMasterEnable(true);
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
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj;
	int i;
/*	for (i = 0; i < 16; i++)
		fPCIDevice->configRead32(i * 4,&dev->saved_config_space[i]);*/
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
	return 1;
}
//ok
int pci_write_config_byte(struct pci_dev *dev, int where, u8 val){
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj;
    fPCIDevice->configWrite8(where,val);
    return 0;
}




void pci_release_regions (struct pci_dev * pdev){
	return;
}
void *pci_get_drvdata (struct pci_dev *pdev){
	return NULL;
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
/* only memory
virtual IOMemoryMap * mapDeviceMemoryWithRegister(
    UInt8 reg, 
    IOOptionBits options = 0 );
*/
	return NULL;
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
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj;
    *val = fPCIDevice->configRead8(where);
    return 0;
}

int pci_read_config_word(struct pci_dev *dev, int where, u16 *val) {
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj;
    *val = fPCIDevice->configRead16(where);
    return 0;
}

int pci_read_config_dword(struct pci_dev *dev, int where, u32 *val) {
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj;
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

int queue_work(struct workqueue_struct *wq, struct work_struct *work) {
#warning Get this to run in a gated manner
    (work->func)(work);
    return 0;
}

int queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *work, unsigned long delay) {
    IOLog("todo queue_delayed_work\n");
    return 0;
}

void __wake_up(wait_queue_head_t *q, unsigned int mode, int nr, void *key) {
    return;
}

int cancel_delayed_work(struct delayed_work *work) {
    return 0;
}

long wait_event_interruptible_timeout(wait_queue_head_t wq, long condition, long timeout) {
    return 0;
}


