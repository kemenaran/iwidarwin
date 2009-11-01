

#ifndef __COMPATIBILITY_H__
#define __COMPATIBILITY_H__


#define CONFIG_IWLWIFI_DEBUG
//#define CONFIG_MAC80211_DEBUGFS
#define CONFIG_IWL4965
#define CONFIG_IWL5000
#define CONFIG_IWLWIFI_SPECTRUM_MEASUREMENT

#undef add_timer
#undef del_timer
#undef mod_timer

struct ieee80211_hw;
struct rate_control_ops;
struct ieee80211_local;
struct ieee80211_ops;
struct wiphy;
struct ieee80211_vif;
struct ieee80211_bss;
struct cfg80211_bss;
struct net_device;
struct cfg80211_scan_request;
struct ieee80211_tx_rate_control;
struct ieee80211_sta;
struct ieee80211_key_conf;
struct ieee80211_sub_if_data;
struct ieee80211_rx_data;

#include "net/mac80211.h"


#ifdef __cplusplus
extern "C" {
#endif

void *netdev_priv(struct net_device *dev);
void ieee80211_tx_skb(struct ieee80211_sub_if_data *sdata, struct sk_buff *skb,
                       int encrypt);
int ieee80211_open();
void ieee80211_invoke_rx_handlers(struct ieee80211_sub_if_data *sdata,
					 struct ieee80211_rx_data *rx,
					 struct sk_buff *skb);
void drv_stop(struct ieee80211_local *local);
int drv_start(struct ieee80211_local *local);
struct sk_buff *skb_copy( struct sk_buff *skb, gfp_t gfp_mask);
struct sk_buff *skb_dequeue(struct sk_buff_head *list);
dma_addr_t pci_map_page(struct pci_dev *dev, struct sk_buff *page);
int rate_control_send_low(struct ieee80211_sta *sta,
			   void *priv_sta,
			   struct ieee80211_tx_rate_control *txrc);
void ieee80211_rx(struct ieee80211_hw *hw, struct sk_buff *skb);
void kfree_skb(struct sk_buff *skb);
void skb_add_rx_frag(struct sk_buff *skb, int start, void* idata, size_t offset, size_t len);
 void pci_unmap_page(struct pci_dev *dev, dma_addr_t phys_add, size_t size, int p);
struct sk_buff *alloc_pages(size_t size);
int ieee80211_reconfig(struct ieee80211_local *local);
 void print_hex_dump(const char *level, const char *prefix_str, int prefix_type,
                         int rowsize, int groupsize,
                         const void *buf, size_t len, bool ascii);
struct sk_buff *dev_alloc_skb(unsigned int length);
struct sk_buff *__dev_alloc_skb(unsigned int length,
                                               gfp_t gfp_mask);
int skb_set_data(const struct sk_buff *skb, void *data, size_t len);
struct ieee80211_local *hw_to_local(struct ieee80211_hw *hw);
int drv_tx(struct ieee80211_local *local, struct sk_buff *skb);
void netif_tx_wake_all_queues(struct net_device *dev);
void netif_tx_stop_all_queues(struct net_device *dev);
void netif_tx_start_all_queues(struct net_device *dev);
void netif_carrier_off(struct net_device *dev);
void netif_carrier_on(struct net_device *dev);
int skb_len(const struct sk_buff *skb);
void *skb_data(const struct sk_buff *skb);
void ieee80211_queue_work(struct ieee80211_hw *hw, struct work_struct *work);
void ieee80211_queue_delayed_work(struct ieee80211_hw *hw,
				  struct delayed_work *dwork,
				  unsigned long delay);
void cfg80211_scan_done(struct cfg80211_scan_request *request, bool aborted);
void cfg80211_send_assoc_timeout(struct net_device *dev, const u8 *addr);
void cfg80211_send_auth_timeout(struct net_device *dev, const u8 *addr);
void cfg80211_send_rx_assoc(struct net_device *dev, const u8 *buf, size_t len);
void cfg80211_send_disassoc(struct net_device *dev, const u8 *buf, size_t len,
			    void *cookie);
const u8 *ieee80211_bss_get_ie(struct cfg80211_bss *bss, u8 ie);
void cfg80211_send_deauth(struct net_device *dev, const u8 *buf, size_t len,
			  void *cookie);
void cfg80211_unlink_bss(struct wiphy *wiphy, struct cfg80211_bss *pub);
void SET_IEEE80211_PERM_ADDR (	struct ieee80211_hw *  	hw, 	u8 *  	addr);
void ieee80211_wake_queues(struct ieee80211_hw *hw);
void ieee80211_wake_queue(struct ieee80211_hw *hw, int queue);
void ieee80211_unregister_hw(struct ieee80211_hw *hw);
 void ieee80211_tx_status_irqsafe(struct ieee80211_hw *hw,
				 struct sk_buff *skb);
void ieee80211_scan_completed(struct ieee80211_hw *hw, bool aborted);
void ieee80211_rx_irqsafe(struct ieee80211_hw *hw, struct sk_buff *skb);
void ieee80211_stop_tx_ba_cb_irqsafe(struct ieee80211_hw *hw, const u8 *ra,
				     u16 tid);
int ieee80211_start_tx_ba_session(struct ieee80211_hw *hw, u8 *ra, u16 tid);
void ieee80211_start_tx_ba_cb_irqsafe(struct ieee80211_hw *hw, const u8 *ra,
				      u16 tid);
 void ieee80211_restart_hw(struct ieee80211_hw *hw);
void ieee80211_rate_control_unregister(struct rate_control_ops *ops);
int ieee80211_rate_control_register(struct rate_control_ops *ops);
unsigned int ieee80211_hdrlen(__le16 fc);
int ieee80211_register_hw(struct ieee80211_hw *hw);
void ieee80211_stop_queue(struct ieee80211_hw *hw, int queue);
void ieee80211_stop_queues(struct ieee80211_hw *hw);
 void ieee80211_free_hw (	struct ieee80211_hw *  	hw);
struct ieee80211_sta *ieee80211_find_sta(struct ieee80211_hw *hw,
                                          const u8 *addr);
int ieee80211_frequency_to_channel(int freq);
int ieee80211_channel_to_frequency(int chan);
struct sk_buff *ieee80211_beacon_get(struct ieee80211_hw *hw,
                                      struct ieee80211_vif *vif);
void sta_info_init(struct ieee80211_local *local);
struct ieee80211_hw *ieee80211_alloc_hw(size_t priv_data_len,
                                         const struct ieee80211_ops *ops);
int pci_write_config_word(struct pci_dev *dev, int where, u16 val);
int pci_write_config_byte(struct pci_dev *dev, int where, u8 val);
void pci_unregister_driver (struct pci_driver * drv);
void pci_set_master (struct pci_dev * dev);
void pci_set_drvdata (struct pci_dev *pdev, void *data);
int pci_set_dma_mask(struct pci_dev *dev, u64 mask);
int pci_set_consistent_dma_mask(struct pci_dev *dev, u64 mask);
int pci_request_regions (struct pci_dev * pdev, char * res_name);
void pci_release_regions (struct pci_dev * pdev);
int pci_register_driver(struct pci_driver * drv);
int pci_pme_capable(struct pci_dev *dev, u8 where);
void pci_iounmap(struct pci_dev *dev, void  * addr);
void  * pci_iomap (	struct pci_dev *  	dev,int  	bar,unsigned long  	maxlen);
void *pci_get_drvdata (struct pci_dev *pdev);
int pci_find_capability(struct pci_dev *dev, u8 where);
int pci_enable_msi  (struct pci_dev * dev);
int pci_enable_device (struct pci_dev * dev);
void pci_dma_sync_single_for_cpu(struct pci_dev *hwdev, dma_addr_t dma_handle, size_t size, int direction);
void pci_disable_msi(struct pci_dev* dev);
void pci_disable_device (struct pci_dev * dev);
    void pci_free_consistent(struct pci_dev *hwdev, size_t size,
                                    void *vaddr, dma_addr_t dma_handle);
    void *pci_alloc_consistent(struct pci_dev *hwdev, size_t size,
                         dma_addr_t *dma_handle);
    void pci_unmap_single(struct pci_dev *hwdev, dma_addr_t dma_addr,
                            size_t size, int direction);
    int pci_read_config_byte(struct pci_dev *dev, int where, u8 *val);
    int pci_read_config_word(struct pci_dev *dev, int where, u16 *val);
    int pci_read_config_dword(struct pci_dev *dev, int where, u32 *val);
    dma_addr_t pci_map_single(struct pci_dev *hwdev, void *ptr, size_t size, int direction);
void wiphy_rfkill_set_hw_state(struct wiphy *wiphy, int blocked);
void tasklet_schedule(struct tasklet_struct *t);
int tasklet_kill(struct tasklet_struct *t);
void tasklet_init(struct tasklet_struct *t, void (*func)(unsigned long), unsigned long data);
int skb_tailroom(const struct sk_buff *skb);
void skb_reserve(struct sk_buff *skb, int len);
void *skb_put(struct sk_buff *skb, unsigned int len);
ssize_t simple_read_from_buffer(void *to, size_t count, loff_t *ppos, const void *from, size_t available);
int request_irq(unsigned int irq, irqreturn_t (*handler)(int, void *), unsigned long irqflags, const char *devname, void *dev_id);
int request_firmware(const struct firmware ** firmware_p, const char * name, struct device * device);
void release_firmware (	const struct firmware *  fw);
int queue_work(struct workqueue_struct *wq, struct work_struct *work);
int queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *work, unsigned long delay);
void mod_timer(struct timer_list2 *timer, int length);
void init_timer(struct timer_list2 *timer);
void hex_dump_to_buffer(const void *buf, size_t len, int rowsize,int groupsize, char *linebuf, size_t linebuflen, bool ascii);
void dev_kfree_skb_any(struct sk_buff *skb);
void dev_kfree_skb(struct sk_buff *skb);
void *dev_get_drvdata(void *p);
void destroy_workqueue (	struct workqueue_struct *  	wq);
int cancel_work_sync(struct work_struct *work);
void del_timer_sync(struct timer_list2 *timer);
int cancel_work_sync(struct work_struct *work);
int cancel_delayed_work(struct delayed_work *work);
int cancel_delayed_work_sync(struct delayed_work *work);
struct sk_buff *__alloc_skb(unsigned int size,
                                       gfp_t priority, int fclone, int node);
struct workqueue_struct *__create_workqueue(const char *name,int singlethread);
#define create_singlethread_workqueue(name) __create_workqueue((name), 0)									   
static inline struct sk_buff *alloc_skb(unsigned int size, gfp_t priority)
    {
        return __alloc_skb(size, priority, 0, -1);
    }
  static inline int atomic_read(const atomic_t *v)
{
        return v->counter;
}

static inline int atomic_inc_return( atomic_t *v)
{
        v->counter++;
		return v->counter;
}

static inline int atomic_dec_return( atomic_t *v)
{
        v->counter--;
		return v->counter;
}
static inline int in_interrupt() {
    return 0;
}
static inline void flush_workqueue(struct workqueue_struct *wq){
	return;
}
static inline void free_irq (unsigned int irq, void *dev_id){
	return;
}

#define module_init(func) int (*init_routine)(void) = func
#define module_init2(func) int (*init_routine2)(void) = func
static inline u8 *bss_mesh_cfg(struct ieee80211_bss *bss)
 {
 #ifdef CONFIG_MAC80211_MESH
         return bss->mesh_cfg;
 #endif
         return NULL;
 }
 
 static inline u8 *bss_mesh_id(struct ieee80211_bss *bss)
 {
 #ifdef CONFIG_MAC80211_MESH
         return bss->mesh_id;
 #endif
         return NULL;
 }
 
 static inline u8 bss_mesh_id_len(struct ieee80211_bss *bss)
 {
 #ifdef CONFIG_MAC80211_MESH
         return bss->mesh_id_len;
 #endif
         return 0;
 }

static inline void __set_bit(int nr, volatile unsigned long *addr)
  {
          unsigned long mask = BIT_MASK(nr);
          unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
  
          *p  |= mask;
  }
static inline void __clear_bit(int nr, volatile unsigned long *addr)
  {
          unsigned long mask = BIT_MASK(nr);
          unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
  
          *p &= ~mask;
  }

#define BITMAP_LAST_WORD_MASK(nbits)                                    \
 (                                                                       \
         ((nbits) % BITS_PER_LONG) ?                                     \
                 (1UL<<((nbits) % BITS_PER_LONG))-1 : ~0UL               \
 )

#define small_const_nbits(nbits) \
         (__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)

static inline int __bitmap_empty(const unsigned long *bitmap, int bits)
  {
          int k, lim = bits/BITS_PER_LONG;
          for (k = 0; k < lim; ++k)
                  if (bitmap[k])
                          return 0;
  
          if (bits % BITS_PER_LONG)
                  if (bitmap[k] & BITMAP_LAST_WORD_MASK(bits))
                          return 0;
  
          return 1;
  }
 
static inline int bitmap_empty(const unsigned long *src, int nbits)
 {
         if (small_const_nbits(nbits))
                 return ! (*src & BITMAP_LAST_WORD_MASK(nbits));
         else
                 return __bitmap_empty(src, nbits);
 }
 
 static inline int is_zero_ether_addr(const u8 *addr)
  {
          return !(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]);
  }
 






#ifdef __cplusplus
}
#endif





#endif //__COMPATIBILITY_H__
