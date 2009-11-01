#ifndef LINUX_26_COMPAT_H
#define LINUX_26_COMPAT_H

#include <IOKit/pccard/k_compat.h>
#include <IOKit/IOLocks.h>


#include <net/if_var.h>
#include <sys/vm.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/dlil.h>
#include <net/bpf.h>
#include <netinet/if_ether.h>
#include <netinet/in_arp.h>
#include <sys/sockio.h>
#include <sys/malloc.h>
#include <sys/queue.h>



typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;
typedef unsigned long long u64;
typedef signed char __s8;
typedef unsigned char __u8;
typedef signed short __s16;
typedef unsigned short __u16;
typedef signed int __s32;
typedef unsigned int __u32;
typedef signed long long __s64;
typedef unsigned long long __u64;
/*#define __bitwise __attribute__((bitwise))
typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;*/
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;

#define __user
#define IFNAMSIZ        16

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
//#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define DIV_ROUND_CLOSEST(x, divisor)(                  \
{                                                       \
        typeof(divisor) __divisor = divisor;            \
        (((x) + ((__divisor) / 2)) / (__divisor));      \
}                                                       \
)
# define BITS_PER_LONG 32
#define BIT(nr)                 (1UL << (nr))
#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE           8
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define ETH_ALEN	6

struct list_head {
	struct list_head *next, *prev;
};
typedef IOPhysicalAddress dma_addr_t;
#define cpu_to_le16(x) le16_to_cpu(x)
#define cpu_to_le32(x) le32_to_cpu(x)
#define __constant_cpu_to_le32(x) cpu_to_le32(x)
#define __constant_cpu_to_le16(x) cpu_to_le16(x)
#define le64_to_cpu(x) OSSwapLittleToHostInt64(x)
#define cpu_to_le64(x) OSSwapHostToLittleInt64(x)
typedef int spinlock_t;
typedef unsigned gfp_t;

struct sk_buff {

	struct sk_buff          *next;
	struct sk_buff          *prev;
	int pkt_type, priority;
    struct net_device *dev;
    mbuf_t mac_data;
    /*
     * This is the control buffer. It is free to use for every
     * layer. Please put your private variables there. If you
     * want to keep them across layers you have to do a skb_clone()
     * first. This is owned by whoever has the skb queued ATM.
     */
    // (We keep this on OS X because it's a handy scratch space.)
    char            cb[48];
    
    void *intf; // A pointer to an IO80211Controller.
};
typedef struct { volatile int counter; } atomic_t;
struct tasklet_struct {
    int padding;
	void (*func)(unsigned long);
	unsigned long data;
};
struct timer_list2 {
        unsigned long expires;
        void (*function)(unsigned long);
        unsigned long data;
		int vv;
		int on;
};


#define __must_check
#define PCI_CAP_ID_EXP 0x10
#define PCI_EXP_LNKCTL	 16
#define KERNEL_VERSION(x,y,z) 999
#define TRACE_EVENT(name, proto, ...)
#define MAX_JIFFY_OFFSET ((~0UL >> 1)-1)
#define MODULE_INFO(tag, info)
#define MODULE_FIRMWARE(_firmware) MODULE_INFO(firmware, _firmware)
struct pci_device_id {
    __u32 vendor, device;       /* Vendor and device ID or PCI_ANY_ID*/
    __u32 subvendor, subdevice; /* Subsystem ID's or PCI_ANY_ID */
    __u32 classtype, class_mask;    /* (class,subclass,prog-if) triplet */
    void *driver_data; /* Data private to the driver */
};
#define __maybe_unused
#define PCI_VENDOR_ID_INTEL	 0x8086
#define PCI_ANY_ID (~0)
typedef unsigned long kernel_ulong_t;
#define PCI_DMA_TODEVICE 0x2 // aka kIODirectionIn. defined in IOMemoryDescriptor
#define PCI_DMA_FROMDEVICE 0x1 // aka kIODirectionOut. defined in IOMemoryDescriptor
#define PCI_REVISION_ID  0x08 //kIOPCIConfigRevisionID
#define PCI_D3hot       3
#define PCI_D3cold       4
#define module_param_named(w, x, y, z)
#define MODULE_PARM_DESC(x, y)
#define container_of(ptr, type, member) ({          \
const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
(type *)( (char *)__mptr - offsetof(type,member) );})

#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

#define MODULE_VERSION(x) 
#define MODULE_LICENSE(x)
#define MODULE_ALIAS(x)
#define list_entry(ptr, type, member) \
container_of(ptr, type, member)

#define GFP_KERNEL 0
#define GFP_ATOMIC 0
#define synchronize_irq(x)
#define DEVICE_ATTR(_name,_mode,_show,_store) 

struct kobject {
    void *ptr;
};

struct device {
	char			name[IFNAMSIZ];
	struct device *parent;
    struct kobject kobj; // Device of type IOPCIDevice.
    void *driver_data;
};

struct pci_dev {
    unsigned long device;
    unsigned long subsystem_device;
    struct device dev;
    unsigned int irq;
	u32 saved_config_space[16];
};
struct firmware {
	size_t size;
	//u8 data[0];
	u8 *data;
};
#define        NETDEV_TX_OK            0
#define KERN_WARNING "warning "
#define KERN_ERR "error "
#define KERN_CRIT "critical "
#define IRQF_SHARED 0
#define PCI_COMMAND_INTX_DISABLE 0x400
#define __devexit
struct pci_driver {
    struct list_head node;
    char *name;
    const struct pci_device_id *id_table;   /* must be non-NULL for probe to be called */
    int  (*probe)  (struct pci_dev *dev, const struct pci_device_id *id);   /* New device inserted */
    void (*remove) (struct pci_dev *dev);   /* Device removed (NULL if not a hot-plug capable driver) */
    int  (*suspend) (struct pci_dev *dev, void *state);  /* Device suspended */
    int  (*suspend_late) (struct pci_dev *dev, void *state);
    int  (*resume_early) (struct pci_dev *dev);
    int  (*resume) (struct pci_dev *dev);                   /* Device woken up */
    int  (*enable_wake) (struct pci_dev *dev, void *state, int enable);   /* Enable wake event */
    void (*shutdown) (struct pci_dev *dev);
    
//    struct pci_error_handlers *err_handler;
//    struct device_driver    driver;
//    struct pci_dynids dynids;
    
    int multithread_probe;
};
#define __devexit_p(x) x
#define IRQ_NONE    (0)
#define IRQ_HANDLED (1)
#define IRQ_RETVAL(x)   ((x) != 0)
#define __user
typedef void loff_t;
 enum iwl_mgmt_stats {
         MANAGEMENT_ASSOC_REQ = 0,
         MANAGEMENT_ASSOC_RESP,
         MANAGEMENT_REASSOC_REQ,
         MANAGEMENT_REASSOC_RESP,
         MANAGEMENT_PROBE_REQ,
         MANAGEMENT_PROBE_RESP,
         MANAGEMENT_BEACON,
         MANAGEMENT_ATIM,
         MANAGEMENT_DISASSOC,
         MANAGEMENT_AUTH,
         MANAGEMENT_DEAUTH,
         MANAGEMENT_ACTION,
         MANAGEMENT_MAX,
 };
 /* control statistics */
 enum iwl_ctrl_stats {
         CONTROL_BACK_REQ =  0,
         CONTROL_BACK,
         CONTROL_PSPOLL,
         CONTROL_RTS,
         CONTROL_CTS,
         CONTROL_ACK,
         CONTROL_CFEND,
         CONTROL_CFENDACK,
         CONTROL_MAX,
 };

#define __builtin_expect(x, expected_value) (x)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x) __builtin_expect(!!(x), 1)
#define __force
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define ETH_ALEN 6
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BUG() do { \
printk("BUG: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __FUNCTION__); \
printk("BUG!"); \
} while (0)
#define BUG_ON(condition) do { if (unlikely((condition)!=0)) BUG(); } while(0)
#define DEBUG(level,...) IOLog(__VA_ARGS__)
#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))

#define PREPARE_WORK(_work, _func)              \
do {                            \
(_work)->func = (_func);            \
} while (0)

#define INIT_WORK(_work, _func,p_number)                 \
do {                            \
PREPARE_WORK((_work), (_func));         \
(_work)->number=p_number;\
} while (0)

#define INIT_DELAYED_WORK(_work, _func, _number)             \
do {                            \
INIT_WORK(&(_work)->work, (_func), _number);     \
} while (0)

# define do_div(n,base) ({                  \
uint32_t __base = (base);               \
uint32_t __rem;                     \
__rem = ((uint64_t)(n)) % __base;           \
(n) = ((uint64_t)(n)) / __base;             \
__rem;                          \
})


#define abs(x) ({               \
int __x = (x);          \
(__x < 0) ? -__x : __x;     \
})



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

#define __WARN() 
#define __WARN_printf(arg...)   do { printk(arg); __WARN(); } while (0)

 #define WARN_ON(condition) ({                                           \
          int __ret_warn_on = !!(condition);                              \
          if (unlikely(__ret_warn_on))                                    \
                  __WARN();                                               \
          unlikely(__ret_warn_on);                                        \
  })
  
  #define WARN(condition, format...) ({                                           \
          int __ret_warn_on = !!(condition);                              \
          if (unlikely(__ret_warn_on))                                    \
                  __WARN_printf(format);                                  \
          unlikely(__ret_warn_on);                                        \
  })

#define WARN_ON_ONCE(condition) ({                              \
         static int __warned;                                    \
         int __ret_warn_once = !!(condition);                    \
                                                                 \
         if (unlikely(__ret_warn_once))                          \
                 if (WARN_ON(!__warned))                         \
                         __warned = 1;                           \
         unlikely(__ret_warn_once);                              \
 })
 
 #define WARN_ONCE(condition, format...) ({                      \
         static int __warned;                                    \
         int __ret_warn_once = !!(condition);                    \
                                                                 \
         if (unlikely(__ret_warn_once))                          \
                 if (WARN(!__warned, format))                    \
                         __warned = 1;                           \
         unlikely(__ret_warn_once);                              \
 })



typedef int irqreturn_t;
typedef irqreturn_t (*irq_handler_t)(int, void *);

struct sk_buff_head {
         /* These two members must be first. */
         struct sk_buff  *next;
         struct sk_buff  *prev;
 
         __u32           qlen;
         spinlock_t      lock;
};


#undef MSEC_PER_SEC		
#undef USEC_PER_SEC		
#undef NSEC_PER_SEC		
#undef NSEC_PER_USEC		

#define MSEC_PER_SEC		1000L
#define USEC_PER_SEC		1000000L
#define NSEC_PER_SEC		1000000000L
#define NSEC_PER_USEC		1000L

static inline unsigned int
__div(unsigned long long n, unsigned int base)
{
	return n / base;
}
#undef jiffies
#define jiffies		\
({		\
	uint64_t m,f;		\
	clock_get_uptime(&m);		\
	absolutetime_to_nanoseconds(m,&f);		\
	((f * HZ) / 1000000000);		\
})

static inline unsigned long usecs_to_jiffies(const unsigned int u)
 {
         //if (u > jiffies_to_usecs(MAX_JIFFY_OFFSET))
           //      return MAX_JIFFY_OFFSET;
 #if HZ <= USEC_PER_SEC && !(USEC_PER_SEC % HZ)
         return (u + (USEC_PER_SEC / HZ) - 1) / (USEC_PER_SEC / HZ);
 #elif HZ > USEC_PER_SEC && !(HZ % USEC_PER_SEC)
         return u * (HZ / USEC_PER_SEC);
 #else
         return (u * HZ + USEC_PER_SEC - 1) / USEC_PER_SEC;
 #endif
 }

static inline void jiffies_to_timespec(unsigned long jiffiess, struct timespec *value)
{
	uint64_t nsec = (uint64_t)jiffies * NSEC_PER_SEC;//TICK_NSEC;
	//value->tv_sec = div_long_long_rem(nsec, NSEC_PER_SEC, &value->tv_nsec);
	// this is wrong
	value->tv_nsec = nsec;
	value->tv_sec = __div(nsec, NSEC_PER_SEC);
}

static inline unsigned int jiffies_to_msecs(const unsigned long j)
{
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
	return (MSEC_PER_SEC / HZ) * j;
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
	return (j + (HZ / MSEC_PER_SEC) - 1)/(HZ / MSEC_PER_SEC);
#else
	return (j * MSEC_PER_SEC) / HZ;
#endif
}

static inline unsigned long msecs_to_jiffies(const unsigned int m)
{
         //if (m > jiffies_to_msecs(MAX_JIFFY_OFFSET)) return MAX_JIFFY_OFFSET;
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
         return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
         return m * (HZ / MSEC_PER_SEC);
#else
         return (m * HZ + MSEC_PER_SEC - 1) / MSEC_PER_SEC;
#endif
}

#define time_after(a,b)	((long)(b) - (long)(a) < 0)

struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);



struct work_struct {
    void* data;
#define WORK_STRUCT_PENDING 0       /* T if work item pending execution */
#define WORK_STRUCT_NOAUTOREL 1     /* F if work item automatically released on 
exec */
#define WORK_STRUCT_FLAG_MASK (3UL)
#define WORK_STRUCT_WQ_DATA_MASK (~WORK_STRUCT_FLAG_MASK)
    struct list_head entry;
    work_func_t func;
	int number;
};


struct delayed_work {
    struct work_struct work;
    struct timer_list2 timer;
};



struct workqueue_struct {
    char data[4];
	thread_call_t tlink[256];
};


struct mutex {
   /* lck_grp_attr_t *slock_grp_attr;
    lck_grp_t *slock_grp;
    lck_attr_t *slock_attr;
    lck_mtx_t *mlock;*/
};

#define NET_SKB_PAD     16

// Bit manipulation, rewritten to use mach routines
#define test_bit(x, y) isset(y, x)
#define clear_bit(x, y) clrbit(y, x)
#define test_and_clear_bit(x,y)		\
({		\
	int r;		\
	r=test_bit(x, y);		\
	clear_bit(x, y);		\
	r;		\
})
#define test_and_set_bit(x,y)		\
({		\
	int r;		\
	r=test_bit(x, y);		\
	set_bit(x, y);		\
	r;		\
})
static inline unsigned compare_ether_addr(const u8 *_a, const u8 *_b)
{
	const u16 *a = (const u16 *) _a;
	const u16 *b = (const u16 *) _b;

	BUILD_BUG_ON(ETH_ALEN != 6);
	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
}
#define copy_from_user(x,y,z) 0

static inline int fls(int x)
  {
          int r = 32;
  
          if (!x)
                  return 0;
          if (!(x & 0xffff0000u)) {
                  x <<= 16;
                  r -= 16;
          }
          if (!(x & 0xff000000u)) {
                  x <<= 8;
                  r -= 8;
          }
          if (!(x & 0xf0000000u)) {
                  x <<= 4;
                  r -= 4;
          }
          if (!(x & 0xc0000000u)) {
                  x <<= 2;
                  r -= 2;
          }
          if (!(x & 0x80000000u)) {
                  x <<= 1;
                  r -= 1;
          }
          return r;
  }


static inline u16 get_unaligned_le16(const u8 *p)
   {
           return p[0] | p[1] << 8;
   }
  
  static inline u32 get_unaligned_le32(const u8 *p)
  {
          return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
  }


static inline int is_multicast_ether_addr(const u8 *addr)
{
       return addr[0] & 0x01;
}

static inline int is_broadcast_ether_addr(const u8 *addr)
{
        return (addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff;
}
static inline  bool is_power_of_2(unsigned long n)
    {
        return (n != 0 && ((n & (n - 1)) == 0));
    }

static inline void *kzalloc(size_t size, unsigned flags)
{
	void *ret = kmalloc(size, flags);
	if (ret)
		memset(ret, 0, size);
	return ret;
}

#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

/**
 * list_entry - get the struct for this entry
 * @ptr:    the &struct list_head pointer.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) \
container_of(ptr, type, member)

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
    next->prev = prev;
    prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->next = (struct list_head *)LIST_POISON1;
    entry->prev = (struct list_head *)LIST_POISON2;
}


/**
 * __list_for_each  -   iterate over a list
 * @pos:    the &struct list_head to use as a loop cursor.
 * @head:   the head for your list.
 *
 * This variant differs from list_for_each() in that it's the
 * simplest possible list iteration code, no prefetching is done.
 * Use this for code that knows the list to be very short (empty
 * or 1 entry) most of the time.
 */
#define __list_for_each(pos, head) \
for (pos = (head)->next; pos != (head); pos = pos->next)


/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:    the &struct list_head to use as a loop cursor.
 * @n:      another &struct list_head to use as temporary storage
 * @head:   the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
for (pos = (head)->next, n = pos->next; pos != (head); \
pos = n, n = pos->next)

static inline void mutex_init(struct mutex *new_mutex) {}

static inline void mutex_lock(struct mutex *new_mtx) {
//#ifndef NO_MUTEX_LOCKS
    //mutexes[current_mutex++] = new_mtx;
	//if(new_mtx)
	//	lck_mtx_lock(new_mtx->mlock);
//#endif
    return;
}

static inline void mutex_unlock(struct mutex *new_mtx) {
//#ifndef NO_MUTEX_LOCKS
    //mutexes[current_mutex--] = NULL;
	//if(new_mtx)
	//	lck_mtx_unlock(new_mtx->mlock);
//#endif
    return;
}

#define net_ratelimit() 0

static inline void put_unaligned_le16(u16 val, u8 *p)
  {
          *p++ = val;
          *p++ = val >> 8;
  }
  
  static inline void put_unaligned_le32(u32 val, u8 *p)
  {
          put_unaligned_le16(val >> 16, p + 2);
          put_unaligned_le16(val, p);
  }

#define rcu_read_lock()
#define rcu_read_unlock()

#define rmb()
#define set_bit(x, y) setbit(y, x)

static inline unsigned long simple_strtoul(const char *cp, char **endp, unsigned int base)
 {
          return strtoul(cp,endp,base);
}

static inline int strict_strtoul(const char *cp, unsigned int base, unsigned long *res)
 {
         char *tail;
         unsigned long val;
         size_t len;
 
         *res = 0;
         len = strlen(cp);
         if (len == 0)
                 return -EINVAL;
 
         val = simple_strtoul(cp, &tail, base);
         if (tail == cp)
                 return -EINVAL;
         if ((*tail == '\0') ||
                 ((len == (size_t)(tail - cp) + 1) && (*tail == '\n'))) {
                 *res = val;
                 return 0;
         }
 
         return -EINVAL;
 }


static inline void spin_lock(spinlock_t *lock) {
#ifndef NO_SPIN_LOCKS
    //lck_spin_lock(lock->lock);
#endif //NO_SPIN_LOCKS
	//lck_mtx_lock(lock->mlock);
    return;
}




static inline void spin_unlock(spinlock_t *lock) {
#ifndef NO_SPIN_LOCKS
    //lck_spin_unlock(lock->lock);
#endif //NO_SPIN_LOCKS
	//lck_mtx_unlock(lock->mlock);
    return;
}




static inline void spin_lock_irqsave(spinlock_t *lock, int fl) {
	//disable_int();
	spin_lock(lock);
	return;
}

static inline void spin_lock_init(spinlock_t *new_lock) {

    return;
}

//FIXME?
#define wait_event_interruptible_timeout(wq, condition, timeout)    \
({                                      \
long __ret = jiffies_to_msecs(timeout);                 \
while(!(condition)) {                   \
    IOSleep(1);                    \
    __ret--;                            \
    if(ret==0)                          \
        break;                          \
}                                       \
__ret;                                  \
})


static inline void __wake_up(wait_queue_head_t *q, unsigned int mode, int nr, void *key) {
//wait_queue_wakeup_thread(wait_queue_t wq, event_t  event,
//            thread_t thread, int result);
    return;
}

#define TASK_RUNNING        0
#define TASK_INTERRUPTIBLE  1
#define TASK_UNINTERRUPTIBLE    2
#define TASK_STOPPED        4
#define TASK_TRACED     8 
#define wake_up_interruptible(x)    __wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)

#define wmb()


static inline void spin_unlock_irqrestore(spinlock_t *lock, int fl) {
	spin_unlock(lock);
	//enable_int();
	return;
}

#define PCI_DMA_BIDIRECTIONAL   0
 #define PCI_DMA_NONE            3
#define pci_unmap_addr(x,y) (dma_addr_t)x
#define pci_unmap_len(x,y) 0
#define pci_unmap_addr_set(x,y,z)
#define pci_unmap_len_set(x,y,z) 

#define	NETDEV_ALIGN		32
#define	NETDEV_ALIGN_CONST	(NETDEV_ALIGN - 1)

#undef ALIGN
#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))
#define ALIGN(x,a)              __ALIGN_MASK(x,(typeof(x))(a)-1)

#define IEEE80211_DEV_TO_SUB_IF(dev) netdev_priv(dev)

static inline void prefetch(const void *x) {;}

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))



struct kref {
         atomic_t refcount;
          void (*release)(struct kref *kref);
  };

#define atomic_set(v,i)     (((v)->counter) = (i))

#define NUM_RX_DATA_QUEUES 17
#define NUM_TX_DATA_QUEUES 6
#define MAX_STA_COUNT 2007
#define STA_TID_NUM 16
#define STA_HASH_SIZE 256


#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#define smp_read_barrier_depends()      do {} while (0)

#define rcu_dereference(p)     ({ \
                                 typeof(p) _________p1 = ACCESS_ONCE(p); \
                                 smp_read_barrier_depends(); \
                                 (_________p1); \
                                 })


#define list_entry_rcu(ptr, type, member) \
         container_of(rcu_dereference(ptr), type, member)

#define list_first_entry_rcu(ptr, type, member) \
         list_entry_rcu((ptr)->next, type, member)
 
 #define __list_for_each_rcu(pos, head) \
         for (pos = rcu_dereference((head)->next); \
                 pos != (head); \
                 pos = rcu_dereference(pos->next))


#define list_for_each_entry_rcu(pos, head, member) \
         for (pos = list_entry_rcu((head)->next, typeof(*pos), member); \
                 prefetch(pos->member.next), &pos->member != (head); \
                 pos = list_entry_rcu(pos->member.next, typeof(*pos), member))


#define rcu_read_lock()
#define rcu_read_unlock()
#define IEEE80211_FRAGMENT_MAX 4
#define MAX_ADDR_LEN	32

struct hlist_node {
         struct hlist_node *next, **pprev;
 };

#define STA_HASH(sta) (sta[5])

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#undef LIST_HEAD
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

#define rtnl_lock()
#define rtnl_unlock()

#define smp_wmb()
#define rcu_assign_pointer(p, v) \
         ({ \
                 if (!__builtin_constant_p(v) || \
                     ((v) != NULL)) \
                         smp_wmb(); \
                 (p) = (v); \
         })

 #define STA_INFO_PIN_STAT_NORMAL        0
 #define STA_INFO_PIN_STAT_PINNED        1
 #define STA_INFO_PIN_STAT_DESTROY       2
 
 static inline void __list_add_rcu(struct list_head *neww,
                  struct list_head *prev, struct list_head *next)
  {
          neww->next = next;
          neww->prev = prev;
          rcu_assign_pointer(prev->next, neww);
          next->prev = neww;
  }
 
 static inline void list_add_tail_rcu(struct list_head *neww,
                                          struct list_head *head)
  {
          __list_add_rcu(neww, head->prev, head);
  }
 
 #define ARPHRD_IEEE80211_RADIOTAP 803  /* IEEE 802.11 + radiotap header */

 enum rx_mgmt_action {
          /* no action required */
          RX_MGMT_NONE,
  
          /* caller must call cfg80211_send_rx_auth() */
          RX_MGMT_CFG80211_AUTH,
  
          /* caller must call cfg80211_send_rx_assoc() */
          RX_MGMT_CFG80211_ASSOC,
  
          /* caller must call cfg80211_send_deauth() */
          RX_MGMT_CFG80211_DEAUTH,
  
          /* caller must call cfg80211_send_disassoc() */
          RX_MGMT_CFG80211_DISASSOC,
  
          /* caller must call cfg80211_auth_timeout() & free work */
          RX_MGMT_CFG80211_AUTH_TO,
  
          /* caller must call cfg80211_assoc_timeout() & free work */
          RX_MGMT_CFG80211_ASSOC_TO,
  };
 
 



#define ASSERT_MGD_MTX(x)
#define smp_mb()

#define IEEE80211_AUTH_TIMEOUT (HZ / 5)
#define IEEE80211_AUTH_MAX_TRIES 3
#define IEEE80211_ASSOC_TIMEOUT (HZ / 5)
#define IEEE80211_ASSOC_MAX_TRIES 3
#define IEEE80211_MONITORING_INTERVAL (2 * HZ)
#define IEEE80211_PROBE_INTERVAL (60 * HZ)
#define IEEE80211_RETRY_AUTH_INTERVAL (1 * HZ)
#define IEEE80211_SCAN_INTERVAL (2 * HZ)
#define IEEE80211_SCAN_INTERVAL_SLOW (15 * HZ)
#define IEEE80211_IBSS_JOIN_TIMEOUT (20 * HZ)

#define IEEE80211_PROBE_DELAY (HZ / 33)
#define IEEE80211_CHANNEL_TIME (HZ / 33)
#define IEEE80211_PASSIVE_CHANNEL_TIME (HZ / 5)
#define IEEE80211_SCAN_RESULT_EXPIRE (10 * HZ)
#define IEEE80211_IBSS_MERGE_INTERVAL (30 * HZ)
#define IEEE80211_IBSS_INACTIVITY_LIMIT (60 * HZ)

#define IEEE80211_IBSS_MAX_STA_ENTRIES 128


#define IEEE80211_FC(type, stype) cpu_to_le16(type | stype)

#define ERP_INFO_USE_PROTECTION BIT(1)


 #define STA_TID_NUM 16
 #define ADDBA_RESP_INTERVAL HZ
 #define HT_AGG_MAX_RETRIES              (0x3)
  
  #define HT_AGG_STATE_INITIATOR_SHIFT    (4)
  
  #define HT_ADDBA_REQUESTED_MSK          BIT(0)
  #define HT_ADDBA_DRV_READY_MSK          BIT(1)
  #define HT_ADDBA_RECEIVED_MSK           BIT(2)
  #define HT_AGG_STATE_REQ_STOP_BA_MSK    BIT(3)
  #define HT_AGG_STATE_INITIATOR_MSK      BIT(HT_AGG_STATE_INITIATOR_SHIFT)
  #define HT_AGG_STATE_IDLE               (0x0)
  #define HT_AGG_STATE_OPERATIONAL        (HT_ADDBA_REQUESTED_MSK |       \
                                           HT_ADDBA_DRV_READY_MSK |       \
                                           HT_ADDBA_RECEIVED_MSK)


#define USHORT_MAX      ((u16)(~0U))

#define WLAN_STA_AUTH            1<<0
#define WLAN_STA_ASSOC           1<<1
#define WLAN_STA_PS              1<<2
#define WLAN_STA_AUTHORIZED      1<<3
#define WLAN_STA_SHORT_PREAMBLE  1<<4
#define WLAN_STA_ASSOC_AP        1<<5
#define WLAN_STA_WME             1<<6
#define WLAN_STA_WDS             1<<7
#define WLAN_STA_CLEAR_PS_FILT   1<<9
#define WLAN_STA_MFP             1<<10
#define WLAN_STA_SUSPEND         1<<11
  
struct ieee80211_radiotap_header {
	u8 it_version;		/* Version 0. Only increases
				 * for drastic changes,
				 * introduction of compatible
				 * new fields does not count.
				 */
	u8 it_pad;
	__le16 it_len;		/* length of the whole
				 * header in bytes, including
				 * it_version, it_pad,
				 * it_len, and data fields.
				 */
	__le32 it_present;	/* A bitmap telling which
				 * fields are present. Set bit 31
				 * (0x80000000) to extend the
				 * bitmap by another 32 bits.
				 * Additional extensions are made
				 * by setting bit 31.
				 */
};

#define might_sleep()
#define msleep(x) IODelay(x)

#define IEEE80211_STA_REQ_SCAN 0
#define IEEE80211_STA_REQ_AUTH 1
#define IEEE80211_STA_REQ_RUN  2

//OLD flags???
#define IEEE80211_STA_PREV_BSSID_SET  BIT(0)
#define IEEE80211_STA_AUTHENTICATED  BIT(1)
#define IEEE80211_STA_ASSOCIATED  BIT(2)
#define IEEE80211_STA_PROBEREQ_POLL  BIT(3)

#define			IEEE80211_STA_BEACON_POLL        BIT(0)
#define         IEEE80211_STA_CONNECTION_POLL    BIT(1)
#define         IEEE80211_STA_CONTROL_PORT       BIT(2)
#define         IEEE80211_STA_WMM_ENABLED        BIT(3)
#define         IEEE80211_STA_DISABLE_11N        BIT(4)
#define         IEEE80211_STA_CSA_RECEIVED       BIT(5)
#define         IEEE80211_STA_MFP_ENABLED        BIT(6)
#define IEEE80211_CONNECTION_IDLE_TIME (2 * HZ) 


#define IEEE80211_SDATA_ALLMULTI  BIT(0)
#define IEEE80211_SDATA_PROMISC  BIT(1)
#define IEEE80211_SDATA_USERSPACE_MLME  BIT(2)
#define IEEE80211_SDATA_OPERATING_GMODE  BIT(3)
#define IEEE80211_SDATA_DONT_BRIDGE_PACKETS  BIT(4)

#define IEEE80211_MAX_PROBE_TRIES 5
#define IEEE80211_PROBE_WAIT (HZ / 5)

#define round_jiffies_up(x) x


#define typecheck(type,x) \
   ({      type __dummy; \
          typeof(x) __dummy2; \
          (void)(&__dummy == &__dummy2); \
          1; \
  })


#define time_before(a,b)        time_after(b,a)
#define time_is_before_jiffies(a) time_after(jiffies, a)
#define time_is_after_jiffies(a) time_before(jiffies, a)
#define TMR_RUNNING_CHANSW      1
#define TMR_RUNNING_TIMER       0
#define round_jiffies_relative(x) 1
#define spin_lock_bh(x)
#define spin_unlock_bh(x)

#define DUMP_PREFIX_OFFSET 0
#define DUMP_PREFIX_ADDRESS 1

#define pci_resource_len(x,y) 0
#define PM_QOS_RESERVED 0
#define PM_QOS_CPU_DMA_LATENCY 1
#define PM_QOS_NETWORK_LATENCY 2
#define PM_QOS_NETWORK_THROUGHPUT 3

#define PM_QOS_NUM_CLASSES 4
#define PM_QOS_DEFAULT_VALUE -1

#define IEEE80211_BEACON_LOSS_TIME	(2 * HZ)

#define DECLARE_PCI_UNMAP_ADDR(mapping)
#define	DECLARE_PCI_UNMAP_LEN(len)

  #define __GFP_WAIT      (0x10u)  /* Can wait and reschedule? */
  #define __GFP_HIGH      (0x20u)  /* Should access emergency pools? */
  #define __GFP_IO        (0x40u)  /* Can start physical IO? */
  #define __GFP_FS        (0x80u)  /* Can call down to low-level FS? */
  #define __GFP_COLD      (0x100u) /* Cache-cold page required */
  #define __GFP_NOWARN    (0x200u) /* Suppress page allocation failure warning */
  #define __GFP_REPEAT    (0x400u) /* See above */
  #define __GFP_NOFAIL    (0x800u) /* See above */
  #define __GFP_NORETRY   (0x1000u)/* See above */
  #define __GFP_COMP      (0x4000u)/* Add compound page metadata */
  #define __GFP_ZERO      (0x8000u)/* Return zeroed page on success */
  #define __GFP_NOMEMALLOC (0x10000u) /* Don't use emergency reserves */
  #define __GFP_HARDWALL   (0x20000u) /* Enforce hardwall cpuset memory allocs */
  #define __GFP_THISNODE  (0x40000u)/* No fallback, no policies */
  #define __GFP_RECLAIMABLE (0x80000u) /* Page is reclaimable */
 
 #define __pskb_pull_tail(a,b) 0 //FIXME
 
 #define sysfs_create_group(a,b) 0
 #define sysfs_remove_group(a,b)
#define module_param(a,b,c)
#define ERESTARTSYS 1
#define uninitialized_var(x) x
#define min_t(a,b,c) (a)min(b,c)

#define trace_iwlwifi_dev_iowrite32(a,b,c)
#define trace_iwlwifi_dev_ioread32(a,b,c)

#define EXPORT_SYMBOL(x)

static inline int get_order(unsigned long size)
  {
          return size;//hack
		  int order;
  
          size = (size - 1) >> (PAGE_SHIFT - 1);
          order = -1;
          do {
                  size >>= 1;
                  order++;
          } while (size);
          return order;
  }
 
#define skb_get_queue_mapping(x) 0 //FIXME
#define pci_dma_sync_single_for_device(a,b,c,d)
#define trace_iwlwifi_dev_tx(q,w,e,r,y,u,i)
#define trace_iwlwifi_dev_hcmd(q,w,e,r)
#define EXPORT_TRACEPOINT_SYMBOL(x)
#define skb_linearize(a) 0
#define free_pages(a,b)
#define le32_to_cpup(x) le32_to_cpu(x)
#define trace_iwlwifi_dev_ucode_event(a,b,c,d)
#define trace_iwlwifi_dev_rx(a,b,c)
#define trace_iwlwifi_dev_ucode_error(q,w,e,r,t,y,u,i,o,p)
#define __free_pages(a,b) dev_kfree_skb(a)

#define ETH_P_AARP	0x80F3		/* Appletalk AARP		*/
#define ETH_P_IPX	0x8137		/* IPX over DIX			*/
#define ETH_P_PAE 0x888E	/* Port Access Entity (IEEE 802.1X) */

#define ETH_HLEN 30//FIXME?
typedef unsigned ieee80211_tx_result;
#define TX_CONTINUE	((ieee80211_tx_result) 0u)
#define TX_DROP		((ieee80211_tx_result) 1u)
#define TX_QUEUED	((ieee80211_tx_result) 2u)
#define IEEE80211_TX_OK		0
#define IEEE80211_TX_AGAIN	1
#define IEEE80211_TX_PENDING	2
#define IEEE80211_TX_FRAGMENTED		BIT(0)
#define IEEE80211_TX_UNICAST		BIT(1)
#define IEEE80211_TX_PS_BUFFERED	BIT(2)
#define TOTAL_MAX_TX_BUFFER 512
#define STA_MAX_TX_BUFFER 128
#define AP_MAX_BC_BUFFER 128













#include "../compatibility.h"
#endif /* LINUX_26_COMPAT_H */
