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
#define true 1
#define false 0
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define DIV_ROUND_CLOSEST(x, divisor)(                  \
{                                                       \
        typeof(divisor) __divisor = divisor;            \
        (((x) + ((__divisor) / 2)) / (__divisor));      \
}                                                       \
)
#define BIT(nr)                 (1UL << (nr))
#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE           8
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define ETH_ALEN	6
struct device{};
struct list_head {
	struct list_head *next, *prev;
};
typedef IOPhysicalAddress dma_addr_t;
#define cpu_to_le16(x) le16_to_cpu(x)
#define cpu_to_le32(x) le32_to_cpu(x)
#define __constant_cpu_to_le32(x) cpu_to_le32(x)
#define __constant_cpu_to_le16(x) cpu_to_le16(x)
struct mutex{};
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
typedef int spinlock_t;
typedef unsigned gfp_t;
#define __iomem
struct sk_buff {

	struct sk_buff          *next;
	struct sk_buff          *prev;
	int pkt_type;
    void *data;
    unsigned int len;
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
struct delayed_work {
    struct work_struct work;
    struct timer_list2 timer;
};
typedef int irqreturn_t;
typedef irqreturn_t (*irq_handler_t)(int, void *);
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

#define __force









#endif /* LINUX_26_COMPAT_H */
