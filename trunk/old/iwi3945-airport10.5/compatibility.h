/*
 *  compatibility.h
 *  iwi3945
 *
 *  Created by Sean Cross on 2/8/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef __COMPATIBILITY_H__
#define __COMPATIBILITY_H__

#ifdef __cplusplus
extern "C" {
#endif


    extern void spin_lock_irqsave(spinlock_t *a, int b);
    extern void spin_unlock_irqrestore(spinlock_t *lock, int fl);
    extern void spin_lock_init(spinlock_t *lock);
    extern void spin_lock(spinlock_t *lock);
    extern void spin_unlock(spinlock_t *lock);
    extern void mutex_lock(struct mutex *);
    extern void mutex_unlock(struct mutex *);
    extern void msleep(unsigned int msecs);
    extern void init_timer(struct timer_list *timer);
    extern int del_timer_sync(struct timer_list *timer);
    extern int in_interrupt();
    extern void *dev_get_drvdata(void *p);

    
    extern struct sta_info * sta_info_get(struct ieee80211_local *local, u8 *addr);
    extern void sta_info_put(struct sta_info *sta);
    
    
    
    extern int ieee80211_rate_control_register(struct rate_control_ops *ops);
    extern void ieee80211_rate_control_unregister(struct rate_control_ops *ops);
    extern void ieee80211_rx_irqsafe(struct ieee80211_hw *hw, struct sk_buff *skb,
                              struct ieee80211_rx_status *status);
    extern int ieee80211_get_morefrag(struct ieee80211_hdr *hdr);
    extern void ieee80211_stop_queue(struct ieee80211_hw *hw, int queue);
    extern void ieee80211_tx_status(struct ieee80211_hw *hw,
                             struct sk_buff *skb,
                             struct ieee80211_tx_status *status);
    extern void ieee80211_tx_status_irqsafe(struct ieee80211_hw *hw,
                                     struct sk_buff *skb,
                                     struct ieee80211_tx_status *status);
    extern void ieee80211_wake_queue(struct ieee80211_hw *hw, int queue);
    extern struct sk_buff *ieee80211_beacon_get(struct ieee80211_hw *hw,
                                         int if_id,
                                         struct ieee80211_tx_control *control);
    
    
    
    
    extern void pci_free_consistent(struct pci_dev *hwdev, size_t size,
                                    void *vaddr, dma_addr_t dma_handle);
    extern void *pci_alloc_consistent(struct pci_dev *hwdev, size_t size,
                         dma_addr_t *dma_handle);
    extern void pci_unmap_single(struct pci_dev *hwdev, dma_addr_t dma_addr,
                            size_t size, int direction);
    extern int pci_read_config_byte(struct pci_dev *dev, int where, u8 *val);
    extern int pci_read_config_word(struct pci_dev *dev, int where, u16 *val);
    extern int pci_read_config_dword(struct pci_dev *dev, int where, u32 *val);
    extern addr64_t pci_map_single(struct pci_dev *hwdev, void *ptr, size_t size, int direction);
    
    extern int skb_tailroom(const struct sk_buff *skb);
    extern void *skb_data(const struct sk_buff *skb);
    extern int skb_len(const struct sk_buff *skb);
    extern void skb_reserve(struct sk_buff *skb, int len);
    extern void *skb_put(struct sk_buff *skb, unsigned int len);
    extern void dev_kfree_skb_any(struct sk_buff *skb);
    extern void dev_kfree_skb(struct sk_buff *skb);
    extern struct sk_buff *__alloc_skb(unsigned int size,
                                       gfp_t priority, int fclone, int node);
    static inline struct sk_buff *alloc_skb(unsigned int size,
                                            gfp_t priority)
    {
        return __alloc_skb(size, priority, 0, -1);
    }
    
    
    
    extern int queue_work(struct workqueue_struct *wq, struct work_struct *work);
    extern int queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *work, unsigned long delay);
#define TASK_RUNNING        0
#define TASK_INTERRUPTIBLE  1
#define TASK_UNINTERRUPTIBLE    2
#define TASK_STOPPED        4
#define TASK_TRACED     8    
#define wake_up_interruptible(x)    __wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
    extern void __wake_up(wait_queue_head_t *q, unsigned int mode, int nr, void *key);
    extern int cancel_delayed_work(struct delayed_work *work);
    extern long wait_event_interruptible_timeout(wait_queue_head_t wq, long condition, long timeout);
    
    
    
    // This has to be one of the most beautiful algorithms I've seen:
    static inline __attribute__((const))
    bool is_power_of_2(unsigned long n)
    {
        return (n != 0 && ((n & (n - 1)) == 0));
    }
    
    
    
    // List-handling routines, from linux/list.h
    static inline void __list_add(struct list_head *new_el,
                                  struct list_head *prev,
                                  struct list_head *next)
    {
        next->prev = new_el;
        new_el->next = next;
        new_el->prev = prev;
        prev->next = new_el;
    }    
    static inline int list_is_last(const struct list_head *list,
                                   const struct list_head *head)
    {
        return list->next == head;
    }
    static inline int list_empty(const struct list_head *head)
    {
        return head->next == head;
    }    
    static inline void list_add(struct list_head *new_el, struct list_head *head)
    {
        __list_add(new_el, head, head->next);
    }
    static inline void list_add_tail(struct list_head *new_el, struct list_head *head)
    {
        __list_add(new_el, head->prev, head);
    }
    static inline void INIT_LIST_HEAD(struct list_head *list)
    {
        list->next = list;
        list->prev = list;
    }
    
#ifdef __cplusplus
}
#endif



#endif //__COMPATIBILITY_H__
