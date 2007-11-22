
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



//includes for fifnet functions
extern "C" {
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
#include <sys/kern_control.h>
#include <libkern/libkern.h>
#include <netinet/ip6.h>
#include <sys/random.h>
#include <sys/mbuf.h>
}

#define IWL 3945
#define CONFIG_IWLWIFI_DEBUG

#include "net/ieee80211.h"
#include "net/ieee80211_radiotap.h"




typedef IOPhysicalAddress dma_addr_t;

#define KERN_ERR
#define KERN_WARNING
#undef KERN_INFO
#define KERN_INFO
#define __builtin_expect(x, expected_value) (x)
#define unlikely(x)	__builtin_expect(!!(x), 0)
#define likely(x) __builtin_expect(!!(x), 1)

#define __must_check
#define spin_lock_irqsave(...)
#define spin_unlock_irqrestore(...)
#define spin_lock_init(...)
#define init_timer(...)
#define del_timer_sync(...)
#define time_after(a,b)	((long)(b) - (long)(a) < 0)
#define queue_work(...)
#define cancel_delayed_work(...)
#define INIT_DELAYED_WORK(...)
#define mutex_unlock(...);
#define mutex_lock(...)
#define queue_delayed_work(...)
#define wake_up_interruptible(...)
#define tasklet_init(...)
#define INIT_WORK(...)
#define flush_workqueue(...)
#define pci_free_consistent(...)
typedef void irqreturn_t;
#define tasklet_schedule(...)
#define spin_unlock(...)
#define spin_lock(...)
#define pci_unmap_single(...)
#define pci_dma_sync_single_for_cpu(...)
#define KERN_CRIT


