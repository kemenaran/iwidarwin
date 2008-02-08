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

#include "defines.h"
#include "compatibility.h"


// Note: This, in itself, makes this very much non-reentrant.  It's used
// primarily when allocating sk_buff entries.
static IONetworkController *currentController;

void spin_lock_irqsave(spinlock_t *lock, int fl) {
    return;
}

void spin_unlock_irqrestore(spinlock_t *lock, int fl) {
    return;
}

void spin_lock_init(spinlock_t *lock) {
    return;
}

void spin_lock(spinlock_t *lock) {
    return;
}

void spin_unlock(spinlock_t *lock) {
    return;
}

void spin_lock_bh( spinlock_t *lock ) {
    return;
}

void spin_unlock_bh( spinlock_t *lock ) {
    return;
}

void mutex_lock(struct mutex *) {
    return;
}

void mutex_unlock(struct mutex *) {
    return;
}

void msleep(unsigned int msecs) {
    return;
}

void init_timer(struct timer_list *timer) {
    return;
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


#pragma mark -
#pragma mark Kernel PCI fiddler adapters

void pci_free_consistent(struct pci_dev *hwdev, size_t size,
                                 void *vaddr, dma_addr_t dma_handle) {
    return IOFreeContiguous(vaddr, size);
}

void *pci_alloc_consistent(struct pci_dev *hwdev, size_t size,
                           dma_addr_t *dma_handle) {
    return IOMallocContiguous(size, 4, dma_handle);
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


