

#ifndef __COMPATIBILITY_H__
#define __COMPATIBILITY_H__

#undef add_timer
#undef del_timer
#undef mod_timer

#include "net/compat.h"

#ifdef __cplusplus
extern "C" {
#endif

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
int mod_timer(struct timer_list2 *timer, int length);
void init_timer(struct timer_list2 *timer);
void hex_dump_to_buffer(const void *buf, size_t len, int rowsize,int groupsize, char *linebuf, size_t linebuflen, bool ascii);
void dev_kfree_skb_any(struct sk_buff *skb);
void dev_kfree_skb(struct sk_buff *skb);
void *dev_get_drvdata(void *p);
void destroy_workqueue (	struct workqueue_struct *  	wq);
int cancel_work_sync(struct work_struct *work);
int del_timer_sync(struct timer_list2 *timer);
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




#ifdef __cplusplus
}
#endif





#endif //__COMPATIBILITY_H__
