/*
 *  compatibility.cpp
 *  iwi3945
 *
 *  Created by Sean Cross on 2/8/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */

#define NO_SPIN_LOCKS 0
#define NO_MUTEX_LOCKS 0
#define IM_HERE_NOW() printf("%s @ %s:%d\n", __FUNCTION__, __FILE__, __LINE__)

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
#ifdef IO80211_VERSION
static IO80211Interface*			my_fNetif;	
#else
static IOEthernetInterface*			my_fNetif;
#endif
static IOBasicOutputQueue *				fTransmitQueue;	
static ieee80211_hw * my_hw;
static IOWorkLoop * workqueue;
static IOInterruptEventSource *	fInterruptSrc;
static IOInterruptEventSource *	DMAInterruptSource;
static irqreturn_t (*realHandler)(int, void *);
static pci_driver * my_drv;
struct pci_dev* my_pci_dev;
IOPCIDevice* my_pci_device;
IOMemoryMap	*				my_map;
u8 my_mac_addr[6];
ifnet_t						my_fifnet;

static int next_thread=0;
static int thread_pos=0;
static IOLock* thread_lock;
static bool is_unloaded=false;

#define MAX_MUTEXES 256
static struct mutex *mutexes[MAX_MUTEXES];
unsigned long current_mutex = 0;

/*
	Getters
*/

u8 * getMyMacAddr(){
	return my_mac_addr;
}

void setCurController(IONetworkController *tmp){
	currentController=tmp;
	printf("settCurController [OK]\n");
}

struct ieee80211_hw * get_my_hw(){
	if(my_hw)
		return my_hw;
	return NULL;
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
IOMemoryMap * getMap(){
	if(my_map)
		return my_map;
	return NULL;
}



/*
	Setters
*/
void setfTransmitQueue(IOBasicOutputQueue* fT){
	fTransmitQueue=fT;
}

void setMyfifnet(ifnet_t fifnet){
	my_fifnet = fifnet;
}

void setUnloaded(){
	is_unloaded=true;
}

void setfNetif(IOEthernetInterface*	Intf){
	my_fNetif=Intf;
}
#pragma mark Various


#pragma mark -
#pragma mark Adapt sk_buff functions to mbuf for OS X

static inline void __skb_queue_tail(struct sk_buff_head *list,struct sk_buff *newsk)
{
	struct sk_buff *prev, *next;

	list->qlen++;
	next = (struct sk_buff *)list;
	prev = next->prev;
	newsk->next = next;
	newsk->prev = prev;
	next->prev  = prev->next = newsk;
}

 /**
1470  *      skb_queue_tail - queue a buffer at the list tail
1471  *      @list: list to use
1472  *      @newsk: buffer to queue
1473  *
1474  *      Queue a buffer at the tail of the list. This function takes the
1475  *      list lock and can be used safely with other locking &sk_buff functions
1476  *      safely.
1477  *
1478  *      A buffer cannot be placed on two lists at the same time.
1479  */
 void skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk)
 {
         unsigned long flags;
 
         spin_lock_irqsave(&list->lock, flags);
         __skb_queue_tail(list, newsk);
         spin_unlock_irqrestore(&list->lock, flags);
 }
  
static inline struct sk_buff *__skb_dequeue(struct sk_buff_head *list)
{
	struct sk_buff *next, *prev, *result;

	prev = (struct sk_buff *) list;
	next = prev->next;
	result = NULL;
	if(next != prev) {
		result       = next;
		next         = next->next;
		list->qlen--;
		next->prev   = prev;
		prev->next   = next;
		result->next = result->prev = NULL;
	}
	return result;
}
struct sk_buff *skb_dequeue(struct sk_buff_head *list)
{
         unsigned long flags;
         struct sk_buff *result;
 
         spin_lock_irqsave(&list->lock, flags);
         result = __skb_dequeue(list);
         spin_unlock_irqrestore(&list->lock, flags);
         return result;
}

 
struct sk_buff *skb_copy( struct sk_buff *skb, gfp_t gfp_mask)
{
	struct sk_buff *skb_copy = (struct sk_buff *)IOMalloc(sizeof(struct sk_buff));
    mbuf_copym(skb->mac_data, 0, mbuf_len(skb->mac_data), 1, &skb_copy->mac_data);
    skb_copy->intf = skb->intf;
    return skb_copy;//need to check for prev, next
}

/**
  *      skb_queue_empty - check if a queue is empty
  *      @list: queue head
  *
  *      Returns true if the queue is empty, false otherwise.
  */
static inline int skb_queue_empty(const struct sk_buff_head *list)
{
	return list->next == (struct sk_buff *)list;
}

/**
  *      skb_trim - remove end from a buffer
  *      @skb: buffer to alter
  *      @len: new length
  *
  *      Cut the length of a buffer down by removing data from the tail. If
  *      the buffer is already under the length specified it is not modified.
  *      The skb must be linear.
  */
static inline void skb_trim(struct sk_buff *skb, signed int len)
{
        //cut from the end of mbuf
	if (len>0)
		mbuf_adj(skb->mac_data, len);
	else
		mbuf_adj(skb->mac_data, -len);
}


static inline void skb_queue_head_init(struct sk_buff_head *list)
{
        spin_lock_init(&list->lock);
        list->prev = list->next = (struct sk_buff *)list;
        list->qlen = 0;
}

static inline void skb_set_mac_header(struct sk_buff *skb, const int offset)
{
	//need to change skb->mac_data
	//skb_reset_mac_header(skb);
        //skb->mac_header += offset;
}

static inline void skb_set_network_header(struct sk_buff *skb, const int offset)
{
        //need to change skb->mac_data
	//skb->network_header = skb->data + offset;
}


void *skb_push(const struct sk_buff *skb, unsigned int len) {
	mbuf_prepend(&(((struct sk_buff*)skb)->mac_data),len,MBUF_WAITOK);
	return mbuf_data(skb->mac_data);
}


int skb_tailroom(const struct sk_buff *skb) {
    return mbuf_trailingspace(skb->mac_data);
}

int skb_headroom(const struct sk_buff *skb){
	return mbuf_leadingspace(skb->mac_data);
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
	return mbuf_pkthdr_len(skb->mac_data);
}

void skb_reserve(struct sk_buff *skb, int len) {
	void *data = (UInt8*)mbuf_data(skb->mac_data) + len;
	mbuf_setdata(skb->mac_data,data, mbuf_len(skb->mac_data));// m_len is not changed.
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
	else
	IOLog("skb_put failded\n");
    //IWI_DUMP_MBUF(2,skb,len);  
    return data;
}



static inline unsigned char *__skb_pull(struct sk_buff *skb, unsigned int len)
{
         //skb->len -= len;
         //return skb->data += len;
		 mbuf_adj(skb->mac_data,len);
		 return (unsigned char*)skb_data(skb);//added
}

/**
953  *      skb_pull - remove data from the start of a buffer
954  *      @skb: buffer to use
955  *      @len: amount of data to remove
956  *
957  *      This function removes data from the start of a buffer, returning
958  *      the memory to the headroom. A pointer to the next data in the buffer
959  *      is returned. Once the data has been pulled future pushes will overwrite
960  *      the old data.
961  */
 static inline unsigned char *skb_pull(struct sk_buff *skb, unsigned int len)
 {
         return unlikely(len > skb_len(skb)) ? NULL : __skb_pull(skb, len);
 }

void dev_kfree_skb_any(struct sk_buff *skb) {
    //need to free prev,next
	dev_kfree_skb(skb);
}

void kfree_skb(struct sk_buff *skb){
    IONetworkController *intf = (IONetworkController *)skb->intf;
    if (skb->mac_data)
	if (!(mbuf_type(skb->mac_data) == MBUF_TYPE_FREE))
        intf->freePacket(skb->mac_data);
}

void dev_kfree_skb(struct sk_buff *skb) {
    IONetworkController *intf = (IONetworkController *)skb->intf;
    if (skb->mac_data)
	if (!(mbuf_type(skb->mac_data) == MBUF_TYPE_FREE))
        intf->freePacket(skb->mac_data);
	skb->mac_data=NULL;
}

struct sk_buff *__alloc_skb(unsigned int size,gfp_t priority, int fclone, int node) {
    struct sk_buff *skb = (struct sk_buff *)IOMalloc(sizeof(struct sk_buff));
    skb->mac_data = currentController->allocatePacket(size);
    skb->intf = (void *)currentController;
	mbuf_setlen(skb->mac_data, 0);
	mbuf_pkthdr_setlen(skb->mac_data,0);
    return skb;
}

#define NET_SKB_PAD     16

static inline struct sk_buff *__dev_alloc_skb(unsigned int length,
                                               gfp_t gfp_mask)
 {
        //check if work
		  struct sk_buff *skb = alloc_skb(length,1);// + NET_SKB_PAD, 1);
        // if (likely(skb))
          //       skb_reserve(skb, NET_SKB_PAD);
         return skb;
 }

struct sk_buff *dev_alloc_skb(unsigned int length)
 {
         return __dev_alloc_skb(length, GFP_ATOMIC);
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
	if(fInterruptSrc)
		return 0;
	if(!workqueue){
		workqueue = IOWorkLoop::workLoop();
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
	}
		
	fInterruptSrc->enable();
	return 0;
}

//FIXME: test
void enable_int(){
	if(fInterruptSrc)
		fInterruptSrc->enable();
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
	//if(new_mtx)
	//	lck_mtx_lock(new_mtx->mlock);
//#endif
    return;
}

void mutex_unlock(struct mutex *new_mtx) {
//#ifndef NO_MUTEX_LOCKS
    //mutexes[current_mutex--] = NULL;
	//if(new_mtx)
	//	lck_mtx_unlock(new_mtx->mlock);
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
	spin_lock(lock);
    return;
}

void spin_unlock_bh( spinlock_t *lock ) {
	spin_unlock(lock);
    return;
}

#pragma mark -
#pragma mark timer adaptation

void
IOPCCardAddTimer(struct timer_list * timer)
{
    uint64_t                    deadline;

    clock_interval_to_deadline(timer->expires, NSEC_PER_SEC / HZ, &deadline);
    //thread_call_func_delayed(timer->function, (void *)timer, deadline);
	thread_call_enter1_delayed((thread_call_t)timer->function,(void*)timer->data,deadline);
}

int
IOPCCardDeleteTimer(struct timer_list * timer)
{
    //return (int)thread_call_func_cancel(timerFunnel, (void *)timer, FALSE);
	return thread_call_cancel((thread_call_t)timer->function);
}


int add_timer(struct timer_list *timer) {
	IOPCCardAddTimer(timer);
	return 0;
}

int del_timer(struct timer_list *timer) {
	return IOPCCardDeleteTimer(timer);
}

void init_timer(struct timer_list *timer) {
	timer=(struct timer_list*)IOMalloc(sizeof(struct timer_list*));
}

int mod_timer(struct timer_list *timer, int length) {
	del_timer(timer);
	timer->expires = length; 
	add_timer(timer);
}

int del_timer_sync(struct timer_list *timer) {
	del_timer(timer);
}

int in_interrupt() {
    return 0;
}

void *dev_get_drvdata(void *p) {
    return p;
}


#pragma mark -
#pragma mark Adapt 80211 functions to OS X
static struct ieee80211_hw* local_to_hw(struct ieee80211_local *local)
{
	return &local->hw;
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
IM_HERE_NOW();
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
IM_HERE_NOW();
    return 0;
}

void ieee80211_rate_control_unregister(struct rate_control_ops *ops) {
IM_HERE_NOW();
    return;
}

int ieee80211_get_morefrag(struct ieee80211_hdr *hdr) {
IM_HERE_NOW();
    return (le16_to_cpu(hdr->frame_control) &
            IEEE80211_FCTL_MOREFRAGS) != 0;
}

#pragma mark Rx

static inline int __ieee80211_invoke_rx_handlers(
                                 struct ieee80211_local *local,
                                 ieee80211_rx_handler *handlers,
                                 struct ieee80211_txrx_data *rx,
                                 struct sta_info *sta){
IM_HERE_NOW();
	ieee80211_rx_handler *handler;
	ieee80211_txrx_result res = TXRX_DROP;

	for (handler = handlers; *handler != NULL; handler++) {
		res = (*handler)(rx);
		if (res != TXRX_CONTINUE) {
			if (res == TXRX_DROP) {
				//I802_DEBUG_INC(local->rx_handlers_drop);
				if (sta)
					sta->rx_dropped++;
			}
			//if (res == TXRX_QUEUED)
			//	I802_DEBUG_INC(local->rx_handlers_queued);
			break;
		}
	}

	if (res == TXRX_DROP) {
		dev_kfree_skb(rx->skb);
	}
	return res;
	//return TXRX_CONTINUE;
}

static inline void ieee80211_invoke_rx_handlers(struct ieee80211_local *local,
                                                ieee80211_rx_handler *handlers,
                                                 struct ieee80211_txrx_data *rx,
                                                 struct sta_info *sta)
{
IM_HERE_NOW();
         if (__ieee80211_invoke_rx_handlers(local, handlers, rx, sta) ==
             TXRX_CONTINUE)
                 dev_kfree_skb(rx->skb);
}



static inline void *netdev_priv(const struct net_device *dev)
 {
 IM_HERE_NOW();
         return dev->priv;
 }
#define IEEE80211_DEV_TO_SUB_IF(dev) netdev_priv(dev)

u8 *ieee80211_get_bssid(struct ieee80211_hdr *hdr, size_t len)
 {
 IM_HERE_NOW();
         u16 fc;
 
         if (len < 24)
                 return NULL;
 
         fc = le16_to_cpu(hdr->frame_control);
 
         switch (fc & IEEE80211_FCTL_FTYPE) {
         case IEEE80211_FTYPE_DATA:
                 switch (fc & (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS)) {
                 case IEEE80211_FCTL_TODS:
                         return hdr->addr1;
                 case (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS):
                         return NULL;
                 case IEEE80211_FCTL_FROMDS:
                         return hdr->addr2;
                 case 0:
                         return hdr->addr3;
                 }
                 break;
         case IEEE80211_FTYPE_MGMT:
                 return hdr->addr3;
         case IEEE80211_FTYPE_CTL:
                 if ((fc & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_PSPOLL)
                         return hdr->addr1;
                 else
                         return NULL;
         }
 
         return NULL;
 }

static int ieee80211_get_radiotap_len(struct sk_buff *skb)
{
IM_HERE_NOW();
	struct ieee80211_radiotap_header *hdr =
		(struct ieee80211_radiotap_header *) skb_data(skb);

	return le16_to_cpu(hdr->it_len);
}


#define WLAN_STA_WDS BIT(27)

int ieee80211_get_hdrlen_from_skb(const struct sk_buff *skb)
{
IM_HERE_NOW();
	const struct ieee80211_hdr *hdr = (const struct ieee80211_hdr *) skb_data(skb);
	int hdrlen;

	if (unlikely(skb_len(skb) < 10))
		return 0;
	hdrlen = ieee80211_get_hdrlen(le16_to_cpu(hdr->frame_control));
	if (unlikely(hdrlen > skb_len(skb)))
		return 0;
	return hdrlen;
}

int ieee80211_wep_get_keyidx(struct sk_buff *skb)
{
IM_HERE_NOW();
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb_data(skb);
	u16 fc;
	int hdrlen;

	fc = le16_to_cpu(hdr->frame_control);
	if (!(fc & IEEE80211_FCTL_PROTECTED))
		return -1;

	hdrlen = ieee80211_get_hdrlen(fc);

	if (skb_len(skb) < 8 + hdrlen)
		return -1;

	return ((u8*)(skb_data(skb)))[hdrlen + 3] >> 6;
}

#define FCS_LEN 4
#define WLAN_STA_ASSOC BIT(1)
enum ieee80211_msg_type {
	ieee80211_msg_normal = 0,
	ieee80211_msg_tx_callback_ack = 1,
	ieee80211_msg_tx_callback_fail = 2,
	/* hole at 3, was ieee80211_msg_passive_scan but unused */
	ieee80211_msg_wep_frame_unknown_key = 4,
	ieee80211_msg_michael_mic_failure = 5,
	/* hole at 6, was monitor but never sent to userspace */
	ieee80211_msg_sta_not_assoc = 7,
	/* 8 was ieee80211_msg_set_aid_for_sta */
	ieee80211_msg_key_threshold_notification = 9,
	ieee80211_msg_radar = 11,
};

static struct ieee80211_rate *
ieee80211_get_rate(struct ieee80211_local *local, int phymode, int hw_rate)
{
IM_HERE_NOW();
	struct ieee80211_hw_mode *mode;
	int r;

	list_for_each_entry(mode, &local->modes_list, list) {
		if (mode->mode != phymode)
			continue;
		for (r = 0; r < mode->num_rates; r++) {
			struct ieee80211_rate *rate = &mode->rates[r];
			if (rate->val == hw_rate ||
			    (rate->flags & IEEE80211_RATE_PREAMBLE2 &&
			     rate->val2 == hw_rate))
				return rate;
		}
	}

	return NULL;
}

static void
ieee80211_fill_frame_info(struct ieee80211_local *local,
			  struct ieee80211_frame_info *fi,
			  struct ieee80211_rx_status *status)
{
IM_HERE_NOW();
	if (status) {
		struct timespec ts;
		struct ieee80211_rate *rate;

		jiffies_to_timespec(jiffies, &ts);
		fi->hosttime = cpu_to_be64((u64) ts.tv_sec * 1000000 +
					   ts.tv_nsec / 1000);
		fi->mactime = cpu_to_be64(status->mactime);
		switch (status->phymode) {
		case MODE_IEEE80211A:
			fi->phytype = htonl(ieee80211_phytype_ofdm_dot11_a);
			break;
		case MODE_IEEE80211B:
			fi->phytype = htonl(ieee80211_phytype_dsss_dot11_b);
			break;
		case MODE_IEEE80211G:
			fi->phytype = htonl(ieee80211_phytype_pbcc_dot11_g);
			break;
		case MODE_ATHEROS_TURBO:
			fi->phytype =
				htonl(ieee80211_phytype_dsss_dot11_turbo);
			break;
		default:
			fi->phytype = htonl(0xAAAAAAAA);
			break;
		}
		fi->channel = htonl(status->channel);
		rate = ieee80211_get_rate(local, status->phymode,
					  status->rate);
		if (rate) {
			fi->datarate = htonl(rate->rate);
			if (rate->flags & IEEE80211_RATE_PREAMBLE2) {
				if (status->rate == rate->val)
					fi->preamble = htonl(2); /* long */
				else if (status->rate == rate->val2)
					fi->preamble = htonl(1); /* short */
			} else
				fi->preamble = htonl(0);
		} else {
			fi->datarate = htonl(0);
			fi->preamble = htonl(0);
		}

		fi->antenna = htonl(status->antenna);
		fi->priority = htonl(0xffffffff); /* no clue */
		fi->ssi_type = htonl(ieee80211_ssi_raw);
		fi->ssi_signal = htonl(status->ssi);
		fi->ssi_noise = 0x00000000;
		fi->encoding = 0;
	} else {
		/* clear everything because we really don't know.
		 * the msg_type field isn't present on monitor frames
		 * so we don't know whether it will be present or not,
		 * but it's ok to not clear it since it'll be assigned
		 * anyway */
		memset(fi, 0, sizeof(*fi) - sizeof(fi->msg_type));

		fi->ssi_type = htonl(ieee80211_ssi_none);
	}
	fi->version = htonl(IEEE80211_FI_VERSION);
	fi->length = cpu_to_be32(sizeof(*fi) - sizeof(fi->msg_type));
}


/* this routine is actually not just for this, but also
 * for pushing fake 'management' frames into userspace.
 * it shall be replaced by a netlink-based system. */
void
ieee80211_rx_mgmt(struct ieee80211_local *local, struct sk_buff *skb,
		  struct ieee80211_rx_status *status, u32 msg_type)
{
IM_HERE_NOW();
	struct ieee80211_frame_info *fi;
	const size_t hlen = sizeof(struct ieee80211_frame_info);
	struct ieee80211_sub_if_data *sdata;

	//skb->dev = local->apdev;

	sdata = (ieee80211_sub_if_data *)IEEE80211_DEV_TO_SUB_IF(local->apdev);

	if (skb_headroom(skb) < hlen) {
		I802_DEBUG_INC(local->rx_expand_skb_head);
		//FIXME: !!
		IOLog("todo pskb_expand_head\n");
		/*if (pskb_expand_head(skb, hlen, 0, GFP_ATOMIC)) {
			dev_kfree_skb(skb);
			return;
		}*/
	}

	fi = (struct ieee80211_frame_info *) skb_push(skb, hlen);

	ieee80211_fill_frame_info(local, fi, status);
	fi->msg_type = htonl(msg_type);

	sdata->stats.rx_packets++;
	sdata->stats.rx_bytes += skb_len(skb);

	//FIXME: Preparation of the mac header and send the packet
	skb_set_mac_header(skb, 0);
	//skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->pkt_type = PACKET_OTHERHOST;
	//skb->protocol = htons(ETH_P_802_2);
	memset(skb->cb, 0, sizeof(skb->cb));
	//netif_rx(skb);
	my_fNetif->inputPacket(skb->mac_data,mbuf_len(skb->mac_data));
}







static void ieee80211_rx_michael_mic_report(struct net_device *dev,
					    struct ieee80211_hdr *hdr,
					    struct sta_info *sta,
					    struct ieee80211_txrx_data *rx)
{
IM_HERE_NOW();
	int keyidx, hdrlen;

	hdrlen = ieee80211_get_hdrlen_from_skb(rx->skb);
	if (skb_len(rx->skb) >= hdrlen + 4){
		//keyidx = rx->skb->data[hdrlen + 3] >> 6;
		u8 * tmp = (u8 *)skb_data(rx->skb);
		keyidx = tmp[hdrlen + 3] >> 6;
	}else
		keyidx = -1;

	/* TODO: verify that this is not triggered by fragmented
	 * frames (hw does not verify MIC for them). */
	printk(KERN_DEBUG "%s: TKIP hwaccel reported Michael MIC "
	       "failure from " MAC_FMT " to " MAC_FMT " keyidx=%d\n",
	       dev->name, MAC_ARG(hdr->addr2), MAC_ARG(hdr->addr1), keyidx);

	if (!sta) {
		/* Some hardware versions seem to generate incorrect
		 * Michael MIC reports; ignore them to avoid triggering
		 * countermeasures. */
		printk(KERN_DEBUG "%s: ignored spurious Michael MIC "
		       "error for unknown address " MAC_FMT "\n",
		       dev->name, MAC_ARG(hdr->addr2));
		goto ignore;
	}

	if (!(rx->fc & IEEE80211_FCTL_PROTECTED)) {
		printk(KERN_DEBUG "%s: ignored spurious Michael MIC "
		       "error for a frame with no ISWEP flag (src "
		       MAC_FMT ")\n", dev->name, MAC_ARG(hdr->addr2));
		goto ignore;
	}

	if ((rx->local->hw.flags & IEEE80211_HW_WEP_INCLUDE_IV) &&
	    rx->sdata->type == IEEE80211_IF_TYPE_AP) {
		keyidx = ieee80211_wep_get_keyidx(rx->skb);
		/* AP with Pairwise keys support should never receive Michael
		 * MIC errors for non-zero keyidx because these are reserved
		 * for group keys and only the AP is sending real multicast
		 * frames in BSS. */
		if (keyidx) {
			printk(KERN_DEBUG "%s: ignored Michael MIC error for "
			       "a frame with non-zero keyidx (%d) (src " MAC_FMT
			       ")\n", dev->name, keyidx, MAC_ARG(hdr->addr2));
			goto ignore;
		}
	}

	if ((rx->fc & IEEE80211_FCTL_FTYPE) != IEEE80211_FTYPE_DATA &&
	    ((rx->fc & IEEE80211_FCTL_FTYPE) != IEEE80211_FTYPE_MGMT ||
	     (rx->fc & IEEE80211_FCTL_STYPE) != IEEE80211_STYPE_AUTH)) {
		printk(KERN_DEBUG "%s: ignored spurious Michael MIC "
		       "error for a frame that cannot be encrypted "
		       "(fc=0x%04x) (src " MAC_FMT ")\n",
		       dev->name, rx->fc, MAC_ARG(hdr->addr2));
		goto ignore;
	}

	do {
		union iwreq_data wrqu;
		char *buf = (char *)kmalloc(128, GFP_ATOMIC);
		if (!buf)
			break;

		/* TODO: needed parameters: count, key type, TSC */
		sprintf(buf, "MLME-MICHAELMICFAILURE.indication("
			"keyid=%d %scast addr=" MAC_FMT ")",
			keyidx, hdr->addr1[0] & 0x01 ? "broad" : "uni",
			MAC_ARG(hdr->addr2));
		memset(&wrqu, 0, sizeof(wrqu));
		//wrqu.data.length = strlen(buf);
		//FIXME: wireless send eve,t!
		//wireless_send_event(rx->dev, IWEVCUSTOM, &wrqu, buf);
		kfree(buf);
	} while (0);

	/* TODO: consider verifying the MIC error report with software
	 * implementation if we get too many spurious reports from the
	 * hardware. */
	if (!rx->local->apdev)
		goto ignore;
	ieee80211_rx_mgmt(rx->local, rx->skb, rx->u.rx.status,
			  ieee80211_msg_michael_mic_failure);
	return;

 ignore:
	dev_kfree_skb(rx->skb);
	rx->skb = NULL;
}

static inline int ieee80211_bssid_match(const u8 *raddr, const u8 *addr)
{
IM_HERE_NOW();
	return compare_ether_addr(raddr, addr) == 0 ||
	       is_broadcast_ether_addr(raddr);
}

static inline void rate_control_rate_init(struct sta_info *sta,
					  struct ieee80211_local *local)
{
IM_HERE_NOW();
	struct rate_control_ref *ref = sta->rate_ctrl;
	ref->ops->rate_init(ref->priv, sta->rate_ctrl_priv, local, sta);
}


/* Caller must hold local->sta_lock */
static void sta_info_hash_add(struct ieee80211_local *local,
			      struct sta_info *sta)
{
IM_HERE_NOW();
	sta->hnext = local->sta_hash[STA_HASH(sta->addr)];
	local->sta_hash[STA_HASH(sta->addr)] = sta;
}

static void kref_init(struct kref *kref, void (*release)(struct kref *kref))
  {
          //WARN_ON(release == NULL);
          atomic_set(&kref->refcount,1);
          kref->release = release;
  }

static  struct kref *kref_get(struct kref *kref)
{
IM_HERE_NOW();
          //WARN_ON(!atomic_read(&kref->refcount));
          atomic_inc(&kref->refcount);
          return kref;
}
 
static inline struct sta_info *__sta_info_get(struct sta_info *sta)
{
IM_HERE_NOW();
    kref_get(&sta->kref);
}
 
struct sta_info * sta_info_get(struct ieee80211_local *local, u8 *addr)
{
IM_HERE_NOW();
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



  /**
   * kref_put - decrement refcount for object.
   * @kref: object.
   *
   * Decrement the refcount, and if 0, call kref->release().
   */
static  void kref_put(struct kref *kref)
{
  IM_HERE_NOW();
		if (atomic_dec_and_test(&kref->refcount)) {
			IOLog("kref cleaning up\n");
			kref->release(kref);
		} 
} 
 
void sta_info_put(struct sta_info *sta)
{
IM_HERE_NOW();
    kref_put(&sta->kref);
}

static struct rate_control_ref *rate_control_get(struct rate_control_ref *ref)
{
IM_HERE_NOW();
	kref_get(&ref->kref);
	return ref;
}

static void rate_control_put(struct rate_control_ref *ref)
{
IM_HERE_NOW();
	kref_put(&ref->kref);//, rate_control_release);
}

static inline void *rate_control_alloc_sta(struct rate_control_ref *ref,
					   gfp_t gfp)
{
IM_HERE_NOW();
	return ref->ops->alloc_sta(ref->priv, gfp);
}

struct sta_info * sta_info_add(struct ieee80211_local *local,
			       struct net_device *dev, u8 *addr, gfp_t gfp)
{
IM_HERE_NOW();
	struct sta_info *sta;

	sta = (sta_info*)kzalloc(sizeof(*sta), gfp);
	if (!sta)
		return NULL;

	kref_init(&sta->kref,NULL);

	sta->rate_ctrl = rate_control_get(local->rate_ctrl);
	sta->rate_ctrl_priv = rate_control_alloc_sta(sta->rate_ctrl, gfp);
	if (!sta->rate_ctrl_priv) {
		rate_control_put(sta->rate_ctrl);
		kref_put(&sta->kref);//, sta_info_release);
		kfree(sta);
		return NULL;
	}

	memcpy(sta->addr, addr, ETH_ALEN);
	sta->local = local;
	sta->dev = dev;
	skb_queue_head_init(&sta->ps_tx_buf);
	skb_queue_head_init(&sta->tx_filtered);
	__sta_info_get(sta);	/* sta used by caller, decremented by
				 * sta_info_put() */
	spin_lock_bh(&local->sta_lock);
	list_add(&sta->list, &local->sta_list);
	local->num_sta++;
	sta_info_hash_add(local, sta);
	spin_unlock_bh(&local->sta_lock);
	if (local->ops->sta_table_notification)
		local->ops->sta_table_notification(local_to_hw(local),
						  local->num_sta);
	sta->key_idx_compression = HW_KEY_IDX_INVALID;

#ifdef CONFIG_MAC80211_VERBOSE_DEBUG
	printk(KERN_DEBUG "%s: Added STA " MAC_FMT "\n",
	       local->mdev->name, MAC_ARG(addr));
#endif /* CONFIG_MAC80211_VERBOSE_DEBUG */

#ifdef CONFIG_MAC80211_DEBUGFS
	if (!in_interrupt()) {
		sta->debugfs_registered = 1;
		ieee80211_sta_debugfs_add(sta);
		rate_control_add_sta_debugfs(sta);
	} else {
		/* debugfs entry adding might sleep, so schedule process
		 * context task for adding entry for STAs that do not yet
		 * have one. */
		queue_work(local->hw.workqueue, &local->sta_debugfs_add);
	}
#endif

	return sta;
}



#define IEEE80211_IBSS_MAX_STA_ENTRIES 128

struct sta_info * ieee80211_ibss_add_sta(struct net_device *dev,
					 struct sk_buff *skb, u8 *bssid,
					 u8 *addr)
{
IM_HERE_NOW();
	struct ieee80211_local *local = (ieee80211_local *)wdev_priv(dev->ieee80211_ptr);
	struct sta_info *sta;
	struct ieee80211_sub_if_data *sdata = (ieee80211_sub_if_data *)IEEE80211_DEV_TO_SUB_IF(dev);

	/* TODO: Could consider removing the least recently used entry and
	 * allow new one to be added. */
	if (local->num_sta >= IEEE80211_IBSS_MAX_STA_ENTRIES) {
		if (net_ratelimit()) {
			printk(KERN_DEBUG "%s: No room for a new IBSS STA "
			       "entry " MAC_FMT "\n", dev->name, MAC_ARG(addr));
		}
		return NULL;
	}

	printk(KERN_DEBUG "%s: Adding new IBSS station " MAC_FMT " (dev=%s)\n",
	       local->mdev->name, MAC_ARG(addr), dev->name);

	sta = sta_info_add(local, dev, addr, GFP_ATOMIC);
	if (!sta)
		return NULL;

	sta->supp_rates = sdata->u.sta.supp_rates_bits;

	rate_control_rate_init(sta, local);

	return sta; /* caller will call sta_info_put() */
}


/*
 * This is the receive path handler. It is called by a low level driver when an
 * 802.11 MPDU is received from the hardware.
 */
void __ieee80211_rx(struct ieee80211_hw *hw, struct sk_buff *skb,
		    struct ieee80211_rx_status *status)
{
IM_HERE_NOW();
	struct ieee80211_local *local = hw_to_local(hw);
	struct ieee80211_sub_if_data *sdata;
	struct sta_info *sta;
	struct ieee80211_hdr *hdr;
	struct ieee80211_txrx_data rx;
	u16 type;
	int multicast;
	int radiotap_len = 0;


	if (status->flag & RX_FLAG_RADIOTAP) {
		radiotap_len = ieee80211_get_radiotap_len(skb);
		skb_pull(skb, radiotap_len);
	}

	hdr = (struct ieee80211_hdr *) skb_data(skb);
	memset(&rx, 0, sizeof(rx));
	rx.skb = skb;
	rx.local = local;

	rx.u.rx.status = status;
	rx.fc = skb_len(skb) >= 2 ? le16_to_cpu(hdr->frame_control) : 0;
	type = rx.fc & IEEE80211_FCTL_FTYPE;
	if (type == IEEE80211_FTYPE_DATA || type == IEEE80211_FTYPE_MGMT)
		local->dot11ReceivedFragmentCount++;
	multicast = is_multicast_ether_addr(hdr->addr1);

	if (skb_len(skb) >= 16)
		sta = rx.sta = sta_info_get(local, hdr->addr2);
	else
		sta = rx.sta = NULL;

	if (sta) {
		rx.dev = sta->dev;
		rx.sdata = (ieee80211_sub_if_data *)IEEE80211_DEV_TO_SUB_IF(rx.dev);
	}

	if ((status->flag & RX_FLAG_MMIC_ERROR)) {
		ieee80211_rx_michael_mic_report(local->mdev, hdr, sta, &rx);
		goto end;
	}

	if (unlikely(local->sta_scanning))
		rx.u.rx.in_scan = 1;

	if (__ieee80211_invoke_rx_handlers(local, local->rx_pre_handlers, &rx,
					   sta) != TXRX_CONTINUE)
		goto end;
	skb = rx.skb;

	skb_push(skb, radiotap_len);
	if (sta && !sta->assoc_ap && !(sta->flags & WLAN_STA_WDS) &&
	    !local->iff_promiscs && !multicast) {
		rx.u.rx.ra_match = 1;
		ieee80211_invoke_rx_handlers(local, local->rx_handlers, &rx,
					     sta);
	} else {
		struct ieee80211_sub_if_data *prev = NULL;
		struct sk_buff *skb_new;
		u8 *bssid = ieee80211_get_bssid(hdr, skb_len(skb) - radiotap_len);
		//FIXME: read_lock
		//read_lock(&local->sub_if_lock);
		list_for_each_entry(sdata, &local->sub_if_list, list) {
			rx.u.rx.ra_match = 1;
			switch (sdata->type) {
			case IEEE80211_IF_TYPE_STA:
				if (!bssid)
					continue;
				if (!ieee80211_bssid_match(bssid,
							sdata->u.sta.bssid)) {
					if (!rx.u.rx.in_scan)
						continue;
					rx.u.rx.ra_match = 0;
				} else if (!multicast &&
					   compare_ether_addr(sdata->dev->dev_addr,
							      hdr->addr1) != 0) {
					if (!sdata->promisc)
						continue;
					rx.u.rx.ra_match = 0;
				}
				break;
			case IEEE80211_IF_TYPE_IBSS:
				if (!bssid)
					continue;
				if (!ieee80211_bssid_match(bssid,
							sdata->u.sta.bssid)) {
					if (!rx.u.rx.in_scan)
						continue;
					rx.u.rx.ra_match = 0;
				} else if (!multicast &&
					   compare_ether_addr(sdata->dev->dev_addr,
							      hdr->addr1) != 0) {
					if (!sdata->promisc)
						continue;
					rx.u.rx.ra_match = 0;
				} else if (!sta)
					sta = rx.sta =
						ieee80211_ibss_add_sta(sdata->dev,
								       skb, bssid,
								       hdr->addr2);
				break;
			case IEEE80211_IF_TYPE_AP:
				if (!bssid) {
					if (compare_ether_addr(sdata->dev->dev_addr,
							       hdr->addr1) != 0)
						continue;
				} else if (!ieee80211_bssid_match(bssid,
							sdata->dev->dev_addr)) {
					if (!rx.u.rx.in_scan)
						continue;
					rx.u.rx.ra_match = 0;
				}
				if (sdata->dev == local->mdev &&
				    !rx.u.rx.in_scan)
					/* do not receive anything via
					 * master device when not scanning */
					continue;
				break;
			case IEEE80211_IF_TYPE_WDS:
				if (bssid ||
				    (rx.fc & IEEE80211_FCTL_FTYPE) != IEEE80211_FTYPE_DATA)
					continue;
				if (compare_ether_addr(sdata->u.wds.remote_addr,
						       hdr->addr2) != 0)
					continue;
				break;
			}

			if (prev) {
				skb_new = skb_copy(skb, GFP_ATOMIC);
				if (!skb_new) {
					if (net_ratelimit())
						printk(KERN_DEBUG "%s: failed to copy "
						       "multicast frame for %s",
						       local->mdev->name, prev->dev->name);
					continue;
				}
				rx.skb = skb_new;
				rx.dev = prev->dev;
				rx.sdata = prev;
				ieee80211_invoke_rx_handlers(local,
							     local->rx_handlers,
							     &rx, sta);
			}
			prev = sdata;
		}
		if (prev) {
			rx.skb = skb;
			rx.dev = prev->dev;
			rx.sdata = prev;
			ieee80211_invoke_rx_handlers(local, local->rx_handlers,
						     &rx, sta);
		} else
			dev_kfree_skb(skb);
		//FIXME: read_unlock
		//read_unlock(&local->sub_if_lock);
	}

  end:
	if (sta)
		sta_info_put(sta);
}





#define IEEE80211_RX_MSG 1
#define IEEE80211_TX_STATUS_MSG 2
static void ieee80211_tasklet_handler(unsigned long data)
{
IM_HERE_NOW();
	struct ieee80211_local *local = (struct ieee80211_local *) data;
	struct sk_buff *skb;
	struct ieee80211_rx_status rx_status;
	struct ieee80211_tx_status *tx_status;
	while ((skb = skb_dequeue(&local->skb_queue)) ||
	       (skb = skb_dequeue(&local->skb_queue_unreliable))) {
		IOLog("Packet Found\n");
		switch (skb->pkt_type) {
		case IEEE80211_RX_MSG:
			/* status is in skb->cb */
			memcpy(&rx_status, skb->cb, sizeof(rx_status));
			/* Clear skb->type in order to not confuse kernel
			 * netstack. */
			skb->pkt_type = 0;
			__ieee80211_rx(local_to_hw(local), skb, &rx_status);
			break;
		case IEEE80211_TX_STATUS_MSG:
			/* get pointer to saved status out of skb->cb */
			memcpy(&tx_status, skb->cb, sizeof(tx_status));
			skb->pkt_type = 0;
			ieee80211_tx_status(local_to_hw(local),
					    skb, tx_status);
			kfree(tx_status);
			break;
		default: /* should never get here! */
			printk(KERN_ERR "%s: Unknown message type (%d)\n",
			       local->mdev->name, skb->pkt_type);
			dev_kfree_skb(skb);
			break;
		}
	}
}






/* This is a version of the rx handler that can be called from hard irq
 * context. Post the skb on the queue and schedule the tasklet */
void ieee80211_rx_irqsafe(struct ieee80211_hw *hw, struct sk_buff *skb, struct ieee80211_rx_status *status)
{
	
    struct ieee80211_local *local = hw_to_local(hw);
    
    BUILD_BUG_ON(sizeof(struct ieee80211_rx_status) > sizeof(skb->cb));
    
    IOLog("todo ieee80211_rx_irqsafe\n");
	
	//PrintPacketHeader(skb->mac_data);
	/*char    *frame;
    frame = (char*)skb_data(skb);
    for (int i = 0; i < mbuf_len(skb->mac_data); i++)
    {
      IOLog("%02X", (u_int8_t)frame[i]);
    }*/
	
	memcpy(skb->cb, status, sizeof(*status));
	skb->pkt_type = IEEE80211_RX_MSG;
	skb_queue_tail(&local->skb_queue, skb);
	//tasklet_schedule(&local->tasklet);
	
	//Start the tasklet
	IOCreateThread((void(*)(void*))&ieee80211_tasklet_handler,local);
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
    fTransmitQueue->service(IOBasicOutputQueue::kServiceAsync);
	return;
}



 int __bitmap_empty(const unsigned long *bitmap, int bits)
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
         if (nbits <= BITS_PER_LONG)
                 return ! (*src & BITMAP_LAST_WORD_MASK(nbits));
         else
                 return __bitmap_empty(src, nbits);
}

static void ieee80211_beacon_add_tim(struct ieee80211_local *local,
				     struct ieee80211_if_ap *bss,
				     struct sk_buff *skb)
{
IM_HERE_NOW();
	u8 *pos, *tim;
	int aid0 = 0;
	int i, have_bits = 0, n1, n2;

	/* Generate bitmap for TIM only if there are any STAs in power save
	 * mode. */
	//spin_lock_bh(&local->sta_lock);
	if (atomic_read(&bss->num_sta_ps) > 0)
		/* in the hope that this is faster than
		 * checking byte-for-byte */
		have_bits = !bitmap_empty((unsigned long*)bss->tim,
					  IEEE80211_MAX_AID+1);

	if (bss->dtim_count == 0)
		bss->dtim_count = bss->dtim_period - 1;
	else
		bss->dtim_count--;

	tim = pos = (u8 *) skb_put(skb, 6);
	*pos++ = WLAN_EID_TIM;
	*pos++ = 4;
	*pos++ = bss->dtim_count;
	*pos++ = bss->dtim_period;

	if (bss->dtim_count == 0 && !skb_queue_empty(&bss->ps_bc_buf))
		aid0 = 1;

	if (have_bits) {
		/* Find largest even number N1 so that bits numbered 1 through
		 * (N1 x 8) - 1 in the bitmap are 0 and number N2 so that bits
		 * (N2 + 1) x 8 through 2007 are 0. */
		n1 = 0;
		for (i = 0; i < IEEE80211_MAX_TIM_LEN; i++) {
			if (bss->tim[i]) {
				n1 = i & 0xfe;
				break;
			}
		}
		n2 = n1;
		for (i = IEEE80211_MAX_TIM_LEN - 1; i >= n1; i--) {
			if (bss->tim[i]) {
				n2 = i;
				break;
			}
		}

		/* Bitmap control */
		*pos++ = n1 | aid0;
		/* Part Virt Bitmap */
		memcpy(pos, bss->tim + n1, n2 - n1 + 1);

		tim[1] = n2 - n1 + 4;
		skb_put(skb, n2 - n1);
	} else {
		*pos++ = aid0; /* Bitmap control */
		*pos++ = 0; /* Part Virt Bitmap */
	}
	spin_unlock_bh(&local->sta_lock);
}

struct sk_buff *ieee80211_beacon_get(struct ieee80211_hw *hw,int if_id,struct ieee80211_tx_control *control) {
IM_HERE_NOW();
	struct ieee80211_local *local = hw_to_local(hw);
	struct sk_buff *skb;
	struct net_device *bdev;
	struct ieee80211_sub_if_data *sdata = NULL;
	struct ieee80211_if_ap *ap = NULL;
	struct ieee80211_rate *rate;
	struct rate_control_extra extra;
	u8 *b_head, *b_tail;
	int bh_len, bt_len;

	bdev = local->mdev;//dev_get_by_index(if_id); //check if work
	if (bdev) {
		sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(bdev);
		ap = &sdata->u.ap;
		//dev_put(bdev);
	}

	if (!ap || sdata->type != IEEE80211_IF_TYPE_AP ||
	    !ap->beacon_head) {
#ifdef CONFIG_MAC80211_VERBOSE_DEBUG
		if (net_ratelimit())
			printk(KERN_DEBUG "no beacon data avail for idx=%d "
			       "(%s)\n", if_id, bdev ? bdev->name : "N/A");
#endif /* CONFIG_MAC80211_VERBOSE_DEBUG */
		return NULL;
	}

	/* Assume we are generating the normal beacon locally */
	b_head = ap->beacon_head;
	b_tail = ap->beacon_tail;
	bh_len = ap->beacon_head_len;
	bt_len = ap->beacon_tail_len;

	skb = dev_alloc_skb(local->tx_headroom +
		bh_len + bt_len + 256 /* maximum TIM len */);
	if (!skb)
		return NULL;

	skb_reserve(skb, local->tx_headroom);
	memcpy(skb_put(skb, bh_len), b_head, bh_len);

	ieee80211_include_sequence(sdata, (struct ieee80211_hdr *)skb->mac_data);

	ieee80211_beacon_add_tim(local, ap, skb);

	if (b_tail) {
		memcpy(skb_put(skb, bt_len), b_tail, bt_len);
	}

	if (control) {
		memset(&extra, 0, sizeof(extra));
		//extra.mode = local->oper_hw_mode;

		rate = rate_control_get_rate(local, local->mdev, skb, &extra);
		if (!rate) {
			if (net_ratelimit()) {
				printk(KERN_DEBUG "%s: ieee80211_beacon_get: no rate "
				       "found\n", local->mdev->name);
			}
			dev_kfree_skb(skb);
			return NULL;
		}

		control->tx_rate = (local->short_preamble &&
				    (rate->flags & IEEE80211_RATE_PREAMBLE2)) ?
			rate->val2 : rate->val;
		control->antenna_sel_tx = local->hw.conf.antenna_sel_tx;
		control->power_level = local->hw.conf.power_level;
		control->flags |= IEEE80211_TXCTL_NO_ACK;
		control->retry_limit = 1;
		control->flags |= IEEE80211_TXCTL_CLEAR_DST_MASK;
	}

	ap->num_beacons++;
	return skb;
}


void ieee80211_stop_queues(struct ieee80211_hw *hw) {
    return;
}

int sta_info_start(struct ieee80211_local *local)
{
	//check this
	//add_timer(&local->sta_cleanup);
	return 0;
}

void ieee80211_if_sdata_init(struct ieee80211_sub_if_data *sdata)
{
	/* Default values for sub-interface parameters */
	sdata->drop_unencrypted = 0;
	sdata->eapol = 1;
	for (int i = 0; i < IEEE80211_FRAGMENT_MAX; i++)
		skb_queue_head_init(&sdata->fragments[i].skb_list);
}

int ieee80211_if_add(struct net_device *dev, const char *name,
		     struct net_device **new_dev, int type)
{
	//full of bugs!!
	struct net_device *ndev;
	struct ieee80211_local *local = (struct ieee80211_local*)dev->ieee80211_ptr;//wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata = NULL;
	int ret;

	//ASSERT_RTNL();
	ndev = local->mdev;//alloc_netdev(sizeof(struct ieee80211_sub_if_data),
			    //name, ieee80211_if_setup);
	if (!ndev)
		return -ENOMEM;

	/*ret = dev_alloc_name(ndev, ndev->name);
	if (ret < 0)
		goto fail;*/

	//memcpy(ndev->dev_addr, local->hw.wiphy->perm_addr, ETH_ALEN);
	ndev->base_addr = dev->base_addr;
	ndev->irq = dev->irq;
	ndev->mem_start = dev->mem_start;
	ndev->mem_end = dev->mem_end;
	//SET_NETDEV_DEV(ndev, wiphy_dev(local->hw.wiphy));

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(ndev);
	ndev->ieee80211_ptr = &sdata->wdev;
	//sdata->wdev.wiphy = local->hw.wiphy;
	sdata->type = IEEE80211_IF_TYPE_AP;
	sdata->dev = ndev;
	sdata->local = local;
	ieee80211_if_sdata_init(sdata);

	/*ret = register_netdevice(ndev);
	if (ret)
		goto fail;*/

	//ieee80211_debugfs_add_netdev(sdata);
	//ieee80211_if_set_type(ndev, type);

	//write_lock_bh(&local->sub_if_lock);
	/*if (unlikely(local->reg_state == IEEE80211_DEV_UNREGISTERED)) {
		write_unlock_bh(&local->sub_if_lock);
		__ieee80211_if_del(local, sdata);
		return -ENODEV;
	}*/
	list_add(&sdata->list, &local->sub_if_list);
	if (new_dev)
		*new_dev = ndev;
	//write_unlock_bh(&local->sub_if_lock);

	//ieee80211_update_default_wep_only(local);

	return 0;

fail:
	//free_netdev(ndev);
	return ret;
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

	name = wiphy_dev(local->hw.wiphy)->driver->name;*/
	local->hw.workqueue = create_workqueue("singlethread_workqueue");//create_singlethread_workqueue(name);
	if (!local->hw.workqueue) {
		result = -ENOMEM;
		return result;
		//goto fail_workqueue;
	}

	/*
	 * The hardware needs headroom for sending the frame,
	 * and we need some headroom for passing the frame to monitor
	 * interfaces, but never both at the same time.
	 */
	local->tx_headroom = max_t(unsigned int , local->hw.extra_tx_headroom,
				   sizeof(struct ieee80211_tx_status_rtap_hdr));

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

	result = sta_info_start(local);
	//if (result < 0)
	//	goto fail_sta_info;

	/*rtnl_lock();
	result = dev_alloc_name(local->mdev, local->mdev->name);
	if (result < 0)
		goto fail_dev;*/

	//memcpy(local->mdev->dev_addr, local->hw.wiphy->perm_addr, ETH_ALEN); //check this
	//SET_NETDEV_DEV(local->mdev, wiphy_dev(local->hw.wiphy));

	/*result = register_netdevice(local->mdev);
	if (result < 0)
		goto fail_dev;

	ieee80211_debugfs_add_netdev(IEEE80211_DEV_TO_SUB_IF(local->mdev));

	result = ieee80211_init_rate_ctrl_alg(local, NULL);
	if (result < 0) {
		printk(KERN_DEBUG "%s: Failed to initialize rate control "
		       "algorithm\n", local->mdev->name);
		//goto fail_rate;
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
	result = ieee80211_if_add(local->mdev, "en%d", NULL,
				  IEEE80211_IF_TYPE_STA);
	if (result)
		printk(KERN_WARNING "%s: Failed to add default virtual iface\n",
		       local->mdev->name);

	(int)local->reg_state = 1;//IEEE80211_DEV_REGISTERED;//check this
	/*rtnl_unlock();

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



typedef enum { ParseOK = 0, ParseUnknown = 1, ParseFailed = -1 } ParseRes;


static ParseRes ieee802_11_parse_elems(u8 *start, size_t len,
				       struct ieee802_11_elems *elems)
{
	size_t left = len;
	u8 *pos = start;
	int unknown = 0;

	memset(elems, 0, sizeof(*elems));

	while (left >= 2) {
		u8 id, elen;

		id = *pos++;
		elen = *pos++;
		left -= 2;

		if (elen > left) {
#if 0
			if (net_ratelimit())
				printk(KERN_DEBUG "IEEE 802.11 element parse "
				       "failed (id=%d elen=%d left=%d)\n",
				       id, elen, left);
#endif
			return ParseFailed;
		}

		switch (id) {
		case WLAN_EID_SSID:
			elems->ssid = pos;
			elems->ssid_len = elen;
			break;
		case WLAN_EID_SUPP_RATES:
			elems->supp_rates = pos;
			elems->supp_rates_len = elen;
			break;
		case WLAN_EID_FH_PARAMS:
			elems->fh_params = pos;
			elems->fh_params_len = elen;
			break;
		case WLAN_EID_DS_PARAMS:
			elems->ds_params = pos;
			elems->ds_params_len = elen;
			break;
		case WLAN_EID_CF_PARAMS:
			elems->cf_params = pos;
			elems->cf_params_len = elen;
			break;
		case WLAN_EID_TIM:
			elems->tim = pos;
			elems->tim_len = elen;
			break;
		case WLAN_EID_IBSS_PARAMS:
			elems->ibss_params = pos;
			elems->ibss_params_len = elen;
			break;
		case WLAN_EID_CHALLENGE:
			elems->challenge = pos;
			elems->challenge_len = elen;
			break;
		case WLAN_EID_WPA:
			if (elen >= 4 && pos[0] == 0x00 && pos[1] == 0x50 &&
			    pos[2] == 0xf2) {
				/* Microsoft OUI (00:50:F2) */
				if (pos[3] == 1) {
					/* OUI Type 1 - WPA IE */
					elems->wpa = pos;
					elems->wpa_len = elen;
				} else if (elen >= 5 && pos[3] == 2) {
					if (pos[4] == 0) {
						elems->wmm_info = pos;
						elems->wmm_info_len = elen;
					} else if (pos[4] == 1) {
						elems->wmm_param = pos;
						elems->wmm_param_len = elen;
					}
				}
			}
			break;
		case WLAN_EID_RSN:
			elems->rsn = pos;
			elems->rsn_len = elen;
			break;
		case WLAN_EID_ERP_INFO:
			elems->erp_info = pos;
			elems->erp_info_len = elen;
			break;
		case WLAN_EID_EXT_SUPP_RATES:
			elems->ext_supp_rates = pos;
			elems->ext_supp_rates_len = elen;
			break;
		default:
#if 0
			printk(KERN_DEBUG "IEEE 802.11 element parse ignored "
				      "unknown element (id=%d elen=%d)\n",
				      id, elen);
#endif
			unknown++;
			break;
		}

		left -= elen;
		pos += elen;
	}

	/* Do not trigger error if left == 1 as Apple Airport base stations
	 * send AssocResps that are one spurious byte too long. */

	return unknown ? ParseUnknown : ParseOK;
}


static struct ieee80211_sta_bss *
ieee80211_rx_bss_get(struct net_device *dev, u8 *bssid)
{
	struct ieee80211_local *local = (ieee80211_local*)wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *bss;

	spin_lock_bh(&local->sta_bss_lock);
	bss = local->sta_bss_hash[STA_HASH(bssid)];
	while (bss) {
		if (memcmp(bss->bssid, bssid, ETH_ALEN) == 0) {
			atomic_inc(&bss->users);
			break;
		}
		bss = bss->hnext;
	}
	spin_unlock_bh(&local->sta_bss_lock);
	return bss;
}

/* Caller must hold local->sta_bss_lock */
static void __ieee80211_rx_bss_hash_add(struct net_device *dev,
					struct ieee80211_sta_bss *bss)
{
	struct ieee80211_local *local = (ieee80211_local *)wdev_priv(dev->ieee80211_ptr);
	bss->hnext = local->sta_bss_hash[STA_HASH(bss->bssid)];
	local->sta_bss_hash[STA_HASH(bss->bssid)] = bss;
}


static struct ieee80211_sta_bss *
ieee80211_rx_bss_add(struct net_device *dev, u8 *bssid)
{
	struct ieee80211_local *local = (ieee80211_local *)wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *bss;

	bss = (ieee80211_sta_bss*)kzalloc(sizeof(*bss), GFP_ATOMIC);
	if (!bss)
		return NULL;
	atomic_inc(&bss->users);
	atomic_inc(&bss->users);
	memcpy(bss->bssid, bssid, ETH_ALEN);

	spin_lock_bh(&local->sta_bss_lock);
	/* TODO: order by RSSI? */
	list_add_tail(&bss->list, &local->sta_bss_list);
	__ieee80211_rx_bss_hash_add(dev, bss);
	spin_unlock_bh(&local->sta_bss_lock);
	return bss;
}

/* Caller must hold local->sta_bss_lock */
static void __ieee80211_rx_bss_hash_del(struct net_device *dev,
					struct ieee80211_sta_bss *bss)
{
	struct ieee80211_local *local = (ieee80211_local *)wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *b, *prev = NULL;
	b = local->sta_bss_hash[STA_HASH(bss->bssid)];
	while (b) {
		if (b == bss) {
			if (!prev)
				local->sta_bss_hash[STA_HASH(bss->bssid)] =
					bss->hnext;
			else
				prev->hnext = bss->hnext;
			break;
		}
		prev = b;
		b = b->hnext;
	}
}

static void ieee80211_rx_bss_free(struct ieee80211_sta_bss *bss)
{
	kfree(bss->wpa_ie);
	kfree(bss->rsn_ie);
	kfree(bss->wmm_ie);
	kfree(bss);
}

static void ieee80211_rx_bss_put(struct net_device *dev,
				 struct ieee80211_sta_bss *bss)
{
	struct ieee80211_local *local = (ieee80211_local *)wdev_priv(dev->ieee80211_ptr);
	if (!atomic_dec_and_test(&bss->users))
		return;

	spin_lock_bh(&local->sta_bss_lock);
	__ieee80211_rx_bss_hash_del(dev, bss);
	list_del(&bss->list);
	spin_unlock_bh(&local->sta_bss_lock);
	ieee80211_rx_bss_free(bss);
}


static void ieee80211_rx_bss_info(struct net_device *dev,
				  struct ieee80211_mgmt *mgmt,
				  size_t len,
				  struct ieee80211_rx_status *rx_status,
				  int beacon)
{
	struct ieee80211_local *local = (ieee80211_local*)wdev_priv(dev->ieee80211_ptr);
	struct ieee802_11_elems elems;
	size_t baselen;
	int channel, invalid = 0, clen;
	struct ieee80211_sta_bss *bss;
	struct sta_info *sta;
	struct ieee80211_sub_if_data *sdata = (ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	u64 timestamp;

	if (!beacon && memcmp(mgmt->da, dev->dev_addr, ETH_ALEN))
		return; /* ignore ProbeResp to foreign address */

#if 1
	printk(KERN_DEBUG "%s: RX %s from " MAC_FMT " to " MAC_FMT "\n",
	       dev->name, beacon ? "Beacon" : "Probe Response",
	       MAC_ARG(mgmt->sa), MAC_ARG(mgmt->da));
#endif

	baselen = (u8 *) mgmt->u.beacon.variable - (u8 *) mgmt;
	if (baselen > len)
		return;

	timestamp = le64_to_cpu(mgmt->u.beacon.timestamp);

	if (sdata->type == IEEE80211_IF_TYPE_IBSS && beacon &&
	    memcmp(mgmt->bssid, sdata->u.sta.bssid, ETH_ALEN) == 0) {
#ifdef CONFIG_MAC80211_IBSS_DEBUG
		static unsigned long last_tsf_debug = 0;
		u64 tsf;
		if (local->ops->get_tsf)
			tsf = local->ops->get_tsf(local_to_hw(local));
		else
			tsf = -1LLU;
		if (time_after(jiffies, last_tsf_debug + 5 * HZ)) {
			printk(KERN_DEBUG "RX beacon SA=" MAC_FMT " BSSID="
			       MAC_FMT " TSF=0x%llx BCN=0x%llx diff=%lld "
			       "@%lu\n",
			       MAC_ARG(mgmt->sa), MAC_ARG(mgmt->bssid),
			       (unsigned long long)tsf,
			       (unsigned long long)timestamp,
			       (unsigned long long)(tsf - timestamp),
			       jiffies);
			last_tsf_debug = jiffies;
		}
#endif /* CONFIG_MAC80211_IBSS_DEBUG */
	}

	if (ieee802_11_parse_elems(mgmt->u.beacon.variable, len - baselen,
				   &elems) == ParseFailed)
		invalid = 1;

	if (sdata->type == IEEE80211_IF_TYPE_IBSS && elems.supp_rates &&
	    memcmp(mgmt->bssid, sdata->u.sta.bssid, ETH_ALEN) == 0 &&
	    (sta = sta_info_get(local, mgmt->sa))) {
		struct ieee80211_hw_mode *mode;
		struct ieee80211_rate *rates;
		size_t num_rates;
		u32 supp_rates, prev_rates;
		int i, j;

		mode = local->sta_scanning ?
		       local->scan_hw_mode : local->oper_hw_mode;
		rates = mode->rates;
		num_rates = mode->num_rates;

		supp_rates = 0;
		for (i = 0; i < elems.supp_rates_len +
			     elems.ext_supp_rates_len; i++) {
			u8 rate = 0;
			int own_rate;
			if (i < elems.supp_rates_len)
				rate = elems.supp_rates[i];
			else if (elems.ext_supp_rates)
				rate = elems.ext_supp_rates
					[i - elems.supp_rates_len];
			own_rate = 5 * (rate & 0x7f);
			if (mode->mode == MODE_ATHEROS_TURBO)
				own_rate *= 2;
			for (j = 0; j < num_rates; j++)
				if (rates[j].rate == own_rate)
					supp_rates |= BIT(j);
		}

		prev_rates = sta->supp_rates;
		sta->supp_rates &= supp_rates;
		if (sta->supp_rates == 0) {
			/* No matching rates - this should not really happen.
			 * Make sure that at least one rate is marked
			 * supported to avoid issues with TX rate ctrl. */
			sta->supp_rates = sdata->u.sta.supp_rates_bits;
		}
		if (sta->supp_rates != prev_rates) {
			printk(KERN_DEBUG "%s: updated supp_rates set for "
			       MAC_FMT " based on beacon info (0x%x & 0x%x -> "
			       "0x%x)\n",
			       dev->name, MAC_ARG(sta->addr), prev_rates,
			       supp_rates, sta->supp_rates);
		}
		sta_info_put(sta);
	}

	if (!elems.ssid)
		return;

	if (elems.ds_params && elems.ds_params_len == 1)
		channel = elems.ds_params[0];
	else
		channel = rx_status->channel;

	bss = ieee80211_rx_bss_get(dev, mgmt->bssid);
	if (!bss) {
		bss = ieee80211_rx_bss_add(dev, mgmt->bssid);
		if (!bss)
			return;
	} else {
#if 0
		/* TODO: order by RSSI? */
		spin_lock_bh(&local->sta_bss_lock);
		list_move_tail(&bss->list, &local->sta_bss_list);
		spin_unlock_bh(&local->sta_bss_lock);
#endif
	}

	if (bss->probe_resp && beacon) {
		/* Do not allow beacon to override data from Probe Response. */
		ieee80211_rx_bss_put(dev, bss);
		return;
	}

	/* save the ERP value so that it is available at association time */
	if (elems.erp_info && elems.erp_info_len >= 1) {
		bss->erp_value = elems.erp_info[0];
		bss->has_erp_value = 1;
	}

	bss->beacon_int = le16_to_cpu(mgmt->u.beacon.beacon_int);
	bss->capability = le16_to_cpu(mgmt->u.beacon.capab_info);
	if (elems.ssid && elems.ssid_len <= IEEE80211_MAX_SSID_LEN) {
		memcpy(bss->ssid, elems.ssid, elems.ssid_len);
		bss->ssid_len = elems.ssid_len;
	}

	bss->supp_rates_len = 0;
	if (elems.supp_rates) {
		clen = IEEE80211_MAX_SUPP_RATES - bss->supp_rates_len;
		if (clen > elems.supp_rates_len)
			clen = elems.supp_rates_len;
		memcpy(&bss->supp_rates[bss->supp_rates_len], elems.supp_rates,
		       clen);
		bss->supp_rates_len += clen;
	}
	if (elems.ext_supp_rates) {
		clen = IEEE80211_MAX_SUPP_RATES - bss->supp_rates_len;
		if (clen > elems.ext_supp_rates_len)
			clen = elems.ext_supp_rates_len;
		memcpy(&bss->supp_rates[bss->supp_rates_len],
		       elems.ext_supp_rates, clen);
		bss->supp_rates_len += clen;
	}

	if (elems.wpa &&
	    (!bss->wpa_ie || bss->wpa_ie_len != elems.wpa_len ||
	     memcmp(bss->wpa_ie, elems.wpa, elems.wpa_len))) {
		kfree(bss->wpa_ie);
		bss->wpa_ie = (u8 *)kmalloc(elems.wpa_len + 2, GFP_ATOMIC);
		if (bss->wpa_ie) {
			memcpy(bss->wpa_ie, elems.wpa - 2, elems.wpa_len + 2);
			bss->wpa_ie_len = elems.wpa_len + 2;
		} else
			bss->wpa_ie_len = 0;
	} else if (!elems.wpa && bss->wpa_ie) {
		kfree(bss->wpa_ie);
		bss->wpa_ie = NULL;
		bss->wpa_ie_len = 0;
	}

	if (elems.rsn &&
	    (!bss->rsn_ie || bss->rsn_ie_len != elems.rsn_len ||
	     memcmp(bss->rsn_ie, elems.rsn, elems.rsn_len))) {
		kfree(bss->rsn_ie);
		bss->rsn_ie = (u8 *)kmalloc(elems.rsn_len + 2, GFP_ATOMIC);
		if (bss->rsn_ie) {
			memcpy(bss->rsn_ie, elems.rsn - 2, elems.rsn_len + 2);
			bss->rsn_ie_len = elems.rsn_len + 2;
		} else
			bss->rsn_ie_len = 0;
	} else if (!elems.rsn && bss->rsn_ie) {
		kfree(bss->rsn_ie);
		bss->rsn_ie = NULL;
		bss->rsn_ie_len = 0;
	}

	if (elems.wmm_param &&
	    (!bss->wmm_ie || bss->wmm_ie_len != elems.wmm_param_len ||
	     memcmp(bss->wmm_ie, elems.wmm_param, elems.wmm_param_len))) {
		kfree(bss->wmm_ie);
		bss->wmm_ie = (u8 *)kmalloc(elems.wmm_param_len + 2, GFP_ATOMIC);
		if (bss->wmm_ie) {
			memcpy(bss->wmm_ie, elems.wmm_param - 2,
			       elems.wmm_param_len + 2);
			bss->wmm_ie_len = elems.wmm_param_len + 2;
		} else
			bss->wmm_ie_len = 0;
	} else if (!elems.wmm_param && bss->wmm_ie) {
		kfree(bss->wmm_ie);
		bss->wmm_ie = NULL;
		bss->wmm_ie_len = 0;
	}


	bss->hw_mode = rx_status->phymode;
	bss->channel = channel;
	bss->freq = rx_status->freq;
	if (channel != rx_status->channel &&
	    (bss->hw_mode == MODE_IEEE80211G ||
	     bss->hw_mode == MODE_IEEE80211B) &&
	    channel >= 1 && channel <= 14) {
		static const int freq_list[] = {
			2412, 2417, 2422, 2427, 2432, 2437, 2442,
			2447, 2452, 2457, 2462, 2467, 2472, 2484
		};
		/* IEEE 802.11g/b mode can receive packets from neighboring
		 * channels, so map the channel into frequency. */
		bss->freq = freq_list[channel - 1];
	}
	bss->timestamp = timestamp;
	bss->last_update = jiffies;
	bss->rssi = rx_status->ssi;
	bss->signal = rx_status->signal;
	bss->noise = rx_status->noise;
	if (!beacon)
		bss->probe_resp++;
	ieee80211_rx_bss_put(dev, bss);
}


static void ieee80211_rx_mgmt_probe_resp(struct net_device *dev,
					 struct ieee80211_mgmt *mgmt,
					 size_t len,
					 struct ieee80211_rx_status *rx_status)
{
	ieee80211_rx_bss_info(dev, mgmt, len, rx_status, 0);
}

static void ieee80211_handle_erp_ie(struct net_device *dev, u8 erp_value)
{
	struct ieee80211_sub_if_data *sdata = (ieee80211_sub_if_data *)IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;
	int use_protection = (erp_value & WLAN_ERP_USE_PROTECTION) != 0;

	if (use_protection != sdata->use_protection) {
		if (net_ratelimit()) {
			printk(KERN_DEBUG "%s: CTS protection %s (BSSID="
			       MAC_FMT ")\n",
			       dev->name,
			       use_protection ? "enabled" : "disabled",
			       MAC_ARG(ifsta->bssid));
		}
		sdata->use_protection = use_protection;
	}
}

//FIXME: !!
enum ieee80211_tx_queue {
	IEEE80211_TX_QUEUE_DATA0,
	IEEE80211_TX_QUEUE_DATA1,
	IEEE80211_TX_QUEUE_DATA2,
	IEEE80211_TX_QUEUE_DATA3,
	IEEE80211_TX_QUEUE_DATA4,
	IEEE80211_TX_QUEUE_SVP,

	//NUM_TX_DATA_QUEUES,

/* due to stupidity in the sub-ioctl userspace interface, the items in
 * this struct need to have fixed values. As soon as it is removed, we can
 * fix these entries. */
	IEEE80211_TX_QUEUE_AFTER_BEACON = 6,
	IEEE80211_TX_QUEUE_BEACON = 7
};

static int ecw2cw(int ecw)
{
	int cw = 1;
	while (ecw > 0) {
		cw <<= 1;
		ecw--;
	}
	return cw - 1;
}

static void ieee80211_sta_wmm_params(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta,
				     u8 *wmm_param, size_t wmm_param_len)
{
	struct ieee80211_local *local = (ieee80211_local *)wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_tx_queue_params params;
	size_t left;
	int count;
	u8 *pos;

	if (wmm_param_len < 8 || wmm_param[5] /* version */ != 1)
		return;
	count = wmm_param[6] & 0x0f;
	if (count == ifsta->wmm_last_param_set)
		return;
	ifsta->wmm_last_param_set = count;

	pos = wmm_param + 8;
	left = wmm_param_len - 8;

	memset(&params, 0, sizeof(params));

	if (!local->ops->conf_tx)
		return;

	local->wmm_acm = 0;
	for (; left >= 4; left -= 4, pos += 4) {
		int aci = (pos[0] >> 5) & 0x03;
		int acm = (pos[0] >> 4) & 0x01;
		int queue;

		switch (aci) {
		case 1:
			queue = IEEE80211_TX_QUEUE_DATA3;
			if (acm) {
				local->wmm_acm |= BIT(0) | BIT(3);
			}
			break;
		case 2:
			queue = IEEE80211_TX_QUEUE_DATA1;
			if (acm) {
				local->wmm_acm |= BIT(4) | BIT(5);
			}
			break;
		case 3:
			queue = IEEE80211_TX_QUEUE_DATA0;
			if (acm) {
				local->wmm_acm |= BIT(6) | BIT(7);
			}
			break;
		case 0:
		default:
			queue = IEEE80211_TX_QUEUE_DATA2;
			if (acm) {
				local->wmm_acm |= BIT(1) | BIT(2);
			}
			break;
		}

		params.aifs = pos[0] & 0x0f;
		params.cw_max = ecw2cw((pos[1] & 0xf0) >> 4);
		params.cw_min = ecw2cw(pos[1] & 0x0f);
		/* TXOP is in units of 32 usec; burst_time in 0.1 ms */
		params.burst_time = (pos[2] | (pos[3] << 8)) * 32 / 100;
		printk(KERN_DEBUG "%s: WMM queue=%d aci=%d acm=%d aifs=%d "
		       "cWmin=%d cWmax=%d burst=%d\n",
		       dev->name, queue, aci, acm, params.aifs, params.cw_min,
		       params.cw_max, params.burst_time);
		/* TODO: handle ACM (block TX, fallback to next lowest allowed
		 * AC for now) */
		if (local->ops->conf_tx(local_to_hw(local), queue, &params)) {
			printk(KERN_DEBUG "%s: failed to set TX queue "
			       "parameters for queue %d\n", dev->name, queue);
		}
	}
}


static void ieee80211_rx_mgmt_beacon(struct net_device *dev,
				     struct ieee80211_mgmt *mgmt,
				     size_t len,
				     struct ieee80211_rx_status *rx_status)
{
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_sta *ifsta;
	size_t baselen;
	struct ieee802_11_elems elems;

	ieee80211_rx_bss_info(dev, mgmt, len, rx_status, 1);

	sdata = (ieee80211_sub_if_data *)IEEE80211_DEV_TO_SUB_IF(dev);
	if (sdata->type != IEEE80211_IF_TYPE_STA)
		return;
	ifsta = &sdata->u.sta;

	if (!ifsta->associated ||
	    memcmp(ifsta->bssid, mgmt->bssid, ETH_ALEN) != 0)
		return;

	/* Process beacon from the current BSS */
	baselen = (u8 *) mgmt->u.beacon.variable - (u8 *) mgmt;
	if (baselen > len)
		return;

	if (ieee802_11_parse_elems(mgmt->u.beacon.variable, len - baselen,
				   &elems) == ParseFailed)
		return;

	if (elems.erp_info && elems.erp_info_len >= 1)
		ieee80211_handle_erp_ie(dev, elems.erp_info[0]);

	if (elems.wmm_param && ifsta->wmm_enabled) {
		ieee80211_sta_wmm_params(dev, ifsta, elems.wmm_param,
					 elems.wmm_param_len);
	}
}

void ieee80211_sta_rx_scan(struct net_device *dev, struct sk_buff *skb,
			   struct ieee80211_rx_status *rx_status)
{
	struct ieee80211_mgmt *mgmt;
	u16 fc;

	if (skb_len(skb) < 24) {
		dev_kfree_skb(skb);
		return;
	}

	mgmt = (struct ieee80211_mgmt *) skb_data(skb);
	fc = le16_to_cpu(mgmt->frame_control);

	if ((fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_MGMT) {
		if ((fc & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_PROBE_RESP) {
			ieee80211_rx_mgmt_probe_resp(dev, mgmt,
						     skb_len(skb), rx_status);
		} else if ((fc & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_BEACON) {
			ieee80211_rx_mgmt_beacon(dev, mgmt, skb_len(skb),
						 rx_status);
		}
	}

	dev_kfree_skb(skb);
}

ieee80211_txrx_result ieee80211_rx_h_parse_qos(struct ieee80211_txrx_data *rx)
{
		return TXRX_CONTINUE;
}


static ieee80211_txrx_result ieee80211_rx_h_load_stats(struct ieee80211_txrx_data *rx)
{
	return TXRX_CONTINUE;
}

/* TODO: implement register/unregister functions for adding TX/RX handlers
 * into ordered list */

/* rx_pre handlers don't have dev and sdata fields available in
 * ieee80211_txrx_data */
static ieee80211_rx_handler ieee80211_rx_pre_handlers[] =
{
	ieee80211_rx_h_parse_qos,
	ieee80211_rx_h_load_stats,
	NULL
};

static ieee80211_txrx_result 
ieee80211_rx_h_if_stats(struct ieee80211_txrx_data *rx)
{
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_monitor(struct ieee80211_txrx_data *rx)
{
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_passive_scan(struct ieee80211_txrx_data *rx)
{
	struct ieee80211_local *local = rx->local;
	struct sk_buff *skb = rx->skb;

	if (unlikely(local->sta_scanning != 0)) {
		ieee80211_sta_rx_scan(rx->dev, skb, rx->u.rx.status);
		return TXRX_QUEUED;
	}

	if (unlikely(rx->u.rx.in_scan)) {
		/* scanning finished during invoking of handlers */
		I802_DEBUG_INC(local->rx_handlers_drop_passive_scan);
		return TXRX_DROP;
	}

	return TXRX_CONTINUE;
}

struct ieee80211_msg_key_notification {
	int tx_rx_count;
	char ifname[IFNAMSIZ];
	u8 addr[ETH_ALEN]; /* ff:ff:ff:ff:ff:ff for broadcast keys */
};

#define NUM_RX_DATA_QUEUES 17

struct ieee80211_key {
	struct kref kref;

	int hw_key_idx; /* filled and used by low-level driver */
	ieee80211_key_alg alg;
	union {
		struct {
			/* last used TSC */
			u32 iv32;
			u16 iv16;
			u16 p1k[5];
			int tx_initialized;

			/* last received RSC */
			u32 iv32_rx[NUM_RX_DATA_QUEUES];
			u16 iv16_rx[NUM_RX_DATA_QUEUES];
			u16 p1k_rx[NUM_RX_DATA_QUEUES][5];
			int rx_initialized[NUM_RX_DATA_QUEUES];
		} tkip;
		struct {
			u8 tx_pn[6];
			u8 rx_pn[NUM_RX_DATA_QUEUES][6];
			struct crypto_cipher *tfm;
			u32 replays; /* dot11RSNAStatsCCMPReplays */
			/* scratch buffers for virt_to_page() (crypto API) */
#ifndef AES_BLOCK_LEN
#define AES_BLOCK_LEN 16
#endif
			u8 tx_crypto_buf[6 * AES_BLOCK_LEN];
			u8 rx_crypto_buf[6 * AES_BLOCK_LEN];
		} ccmp;
	} u;
	int tx_rx_count; /* number of times this key has been used */
	int keylen;

	/* if the low level driver can provide hardware acceleration it should
	 * clear this flag */
	unsigned int force_sw_encrypt:1;
	unsigned int default_tx_key:1; /* This key is the new default TX key
					* (used only for broadcast keys). */
	s8 keyidx; /* WEP key index */

#ifdef CONFIG_MAC80211_DEBUGFS
	struct {
		struct dentry *stalink;
		struct dentry *dir;
		struct dentry *keylen;
		struct dentry *force_sw_encrypt;
		struct dentry *keyidx;
		struct dentry *hw_key_idx;
		struct dentry *tx_rx_count;
		struct dentry *algorithm;
		struct dentry *tx_spec;
		struct dentry *rx_spec;
		struct dentry *replays;
		struct dentry *key;
	} debugfs;
#endif

	u8 key[0];
};


static void ieee80211_key_threshold_notify(struct net_device *dev,
					   struct ieee80211_key *key,
					   struct sta_info *sta)
{
	struct ieee80211_local *local = (ieee80211_local *)wdev_priv(dev->ieee80211_ptr);
	struct sk_buff *skb;
	struct ieee80211_msg_key_notification *msg;

	/* if no one will get it anyway, don't even allocate it.
	 * unlikely because this is only relevant for APs
	 * where the device must be open... */
	if (unlikely(!local->apdev))
		return;

	skb = dev_alloc_skb(sizeof(struct ieee80211_frame_info) +
			    sizeof(struct ieee80211_msg_key_notification));
	if (!skb)
		return;

	skb_reserve(skb, sizeof(struct ieee80211_frame_info));
	msg = (struct ieee80211_msg_key_notification *)
		skb_put(skb, sizeof(struct ieee80211_msg_key_notification));
	msg->tx_rx_count = key->tx_rx_count;
	memcpy(msg->ifname, dev->name, IFNAMSIZ);
	if (sta)
		memcpy(msg->addr, sta->addr, ETH_ALEN);
	else
		memset(msg->addr, 0xff, ETH_ALEN);

	key->tx_rx_count = 0;

	ieee80211_rx_mgmt(local, skb, NULL,
			  ieee80211_msg_key_threshold_notification);
}

static ieee80211_txrx_result
ieee80211_rx_h_check(struct ieee80211_txrx_data *rx)
{
	struct ieee80211_hdr *hdr;
	int always_sta_key;
	hdr = (struct ieee80211_hdr *) skb_data(rx->skb);

	/* Drop duplicate 802.11 retransmissions (IEEE 802.11 Chap. 9.2.9) */
	if (rx->sta && !is_multicast_ether_addr(hdr->addr1)) {
		if (unlikely(rx->fc & IEEE80211_FCTL_RETRY &&
			     rx->sta->last_seq_ctrl[rx->u.rx.queue] ==
			     hdr->seq_ctrl)) {
			if (rx->u.rx.ra_match) {
				rx->local->dot11FrameDuplicateCount++;
				rx->sta->num_duplicates++;
			}
			return TXRX_DROP;
		} else
			rx->sta->last_seq_ctrl[rx->u.rx.queue] = hdr->seq_ctrl;
	}

	if ((rx->local->hw.flags & IEEE80211_HW_RX_INCLUDES_FCS) &&
	    skb_len(rx->skb) > FCS_LEN)
		skb_trim(rx->skb, skb_len(rx->skb) - FCS_LEN);

	if (unlikely(skb_len(rx->skb) < 16)) {
		I802_DEBUG_INC(rx->local->rx_handlers_drop_short);
		return TXRX_DROP;
	}

	if (!rx->u.rx.ra_match)
		rx->skb->pkt_type = PACKET_OTHERHOST;
	else if (compare_ether_addr(rx->dev->dev_addr, hdr->addr1) == 0)
		rx->skb->pkt_type = PACKET_HOST;
	else if (is_multicast_ether_addr(hdr->addr1)) {
		if (is_broadcast_ether_addr(hdr->addr1))
			rx->skb->pkt_type = PACKET_BROADCAST;
		else
			rx->skb->pkt_type = PACKET_MULTICAST;
	} else
		rx->skb->pkt_type = PACKET_OTHERHOST;

	/* Drop disallowed frame classes based on STA auth/assoc state;
	 * IEEE 802.11, Chap 5.5.
	 *
	 * 80211.o does filtering only based on association state, i.e., it
	 * drops Class 3 frames from not associated stations. hostapd sends
	 * deauth/disassoc frames when needed. In addition, hostapd is
	 * responsible for filtering on both auth and assoc states.
	 */
	if (unlikely(((rx->fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA ||
		      ((rx->fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_CTL &&
		       (rx->fc & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_PSPOLL)) &&
		     rx->sdata->type != IEEE80211_IF_TYPE_IBSS &&
		     (!rx->sta || !(rx->sta->flags & WLAN_STA_ASSOC)))) {
		if ((!(rx->fc & IEEE80211_FCTL_FROMDS) &&
		     !(rx->fc & IEEE80211_FCTL_TODS) &&
		     (rx->fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA)
		    || !rx->u.rx.ra_match) {
			/* Drop IBSS frames and frames for other hosts
			 * silently. */
			return TXRX_DROP;
		}

		if (!rx->local->apdev)
			return TXRX_DROP;

		ieee80211_rx_mgmt(rx->local, rx->skb, rx->u.rx.status,
				  ieee80211_msg_sta_not_assoc);
		return TXRX_QUEUED;
	}

	if (rx->sdata->type == IEEE80211_IF_TYPE_STA)
		always_sta_key = 0;
	else
		always_sta_key = 1;

	if (rx->sta && rx->sta->key && always_sta_key) {
		rx->key = rx->sta->key;
	} else {
		if (rx->sta && rx->sta->key)
			rx->key = rx->sta->key;
		else
			rx->key = rx->sdata->default_key;

		if ((rx->local->hw.flags & IEEE80211_HW_WEP_INCLUDE_IV) &&
		    rx->fc & IEEE80211_FCTL_PROTECTED) {
			int keyidx = ieee80211_wep_get_keyidx(rx->skb);

			if (keyidx >= 0 && keyidx < NUM_DEFAULT_KEYS &&
			    (!rx->sta || !rx->sta->key || keyidx > 0))
				rx->key = rx->sdata->keys[keyidx];

			if (!rx->key) {
				if (!rx->u.rx.ra_match)
					return TXRX_DROP;
				printk(KERN_DEBUG "%s: RX WEP frame with "
				       "unknown keyidx %d (A1=" MAC_FMT " A2="
				       MAC_FMT " A3=" MAC_FMT ")\n",
				       rx->dev->name, keyidx,
				       MAC_ARG(hdr->addr1),
				       MAC_ARG(hdr->addr2),
				       MAC_ARG(hdr->addr3));
				if (!rx->local->apdev)
					return TXRX_DROP;
				ieee80211_rx_mgmt(
					rx->local, rx->skb, rx->u.rx.status,
					ieee80211_msg_wep_frame_unknown_key);
				return TXRX_QUEUED;
			}
		}
	}

	if (rx->fc & IEEE80211_FCTL_PROTECTED && rx->key && rx->u.rx.ra_match) {
		rx->key->tx_rx_count++;
		if (unlikely(rx->local->key_tx_rx_threshold &&
			     rx->key->tx_rx_count >
			     rx->local->key_tx_rx_threshold)) {
			ieee80211_key_threshold_notify(rx->dev, rx->key,
						       rx->sta);
		}
	}

	return TXRX_CONTINUE;
}

ieee80211_txrx_result
ieee80211_rx_h_ccmp_decrypt(struct ieee80211_txrx_data *rx)
{
	return TXRX_CONTINUE;
}

#define WLAN_STA_PS BIT(2)

/* Stored in sk_buff->cb */
struct ieee80211_tx_packet_data {
	int ifindex;
	//unsigned long jiffies;
	unsigned int req_tx_status:1;
	unsigned int do_not_encrypt:1;
	unsigned int requeue:1;
	unsigned int mgmt_iface:1;
	unsigned int queue:4;
};

						  
static inline void __bss_tim_clear(struct ieee80211_if_ap *bss, int aid)
{
	/*
	 * This format has ben mandated by the IEEE specifications,
	 * so this line may not be changed to use the __clear_bit() format.
	 */
	bss->tim[(aid)/8] &= !(1<<((aid) % 8));
}

static inline void bss_tim_clear(struct ieee80211_local *local, struct ieee80211_if_ap *bss, u16 aid)
{
	__bss_tim_clear(bss, aid);
}
		
		
#define WLAN_STA_TIM BIT(3) /* TIM bit is on for PS stations */

static int ap_sta_ps_end(struct net_device *dev, struct sta_info *sta)
{
	struct ieee80211_local *local = (ieee80211_local *)wdev_priv(dev->ieee80211_ptr);
	struct sk_buff *skb;
	int sent = 0;
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_tx_packet_data *pkt_data;

	sdata = (ieee80211_sub_if_data *)IEEE80211_DEV_TO_SUB_IF(sta->dev);
	if (sdata->bss)
		atomic_dec((atomic_t *)&sdata->bss->num_sta_ps);
	sta->flags &= ~(WLAN_STA_PS | WLAN_STA_TIM);
	sta->pspoll = 0;
	if (!skb_queue_empty(&sta->ps_tx_buf)) {
		if (local->ops->set_tim)
			local->ops->set_tim(local_to_hw(local), sta->aid, 0);
		if (sdata->bss)
			bss_tim_clear(local, sdata->bss, sta->aid);
	}
#ifdef CONFIG_MAC80211_VERBOSE_PS_DEBUG
	printk(KERN_DEBUG "%s: STA " MAC_FMT " aid %d exits power "
	       "save mode\n", dev->name, MAC_ARG(sta->addr), sta->aid);
#endif /* CONFIG_MAC80211_VERBOSE_PS_DEBUG */
	/* Send all buffered frames to the station */
	while ((skb = skb_dequeue(&sta->tx_filtered)) != NULL) {
		pkt_data = (struct ieee80211_tx_packet_data *) skb->cb;
		sent++;
		pkt_data->requeue = 1;
		//dev_queue_xmit(skb);
		currentController->outputPacket(skb->mac_data,NULL);
	}
	while ((skb = skb_dequeue(&sta->ps_tx_buf)) != NULL) {
		pkt_data = (struct ieee80211_tx_packet_data *) skb->cb;
		local->total_ps_buffered--;
		sent++;
#ifdef CONFIG_MAC80211_VERBOSE_PS_DEBUG
		printk(KERN_DEBUG "%s: STA " MAC_FMT " aid %d send PS frame "
		       "since STA not sleeping anymore\n", dev->name,
		       MAC_ARG(sta->addr), sta->aid);
#endif /* CONFIG_MAC80211_VERBOSE_PS_DEBUG */
		pkt_data->requeue = 1;
		//dev_queue_xmit(skb);
		currentController->outputPacket(skb->mac_data,NULL);
	}

	return sent;
}

static void ap_sta_ps_start(struct net_device *dev, struct sta_info *sta)
{
	struct ieee80211_sub_if_data *sdata;
	sdata = (ieee80211_sub_if_data *)IEEE80211_DEV_TO_SUB_IF(sta->dev);

	if (sdata->bss)
		atomic_inc((atomic_t*)&sdata->bss->num_sta_ps);
	sta->flags |= WLAN_STA_PS;
	sta->pspoll = 0;
#ifdef CONFIG_MAC80211_VERBOSE_PS_DEBUG
	printk(KERN_DEBUG "%s: STA " MAC_FMT " aid %d enters power "
	       "save mode\n", dev->name, MAC_ARG(sta->addr), sta->aid);
#endif /* CONFIG_MAC80211_VERBOSE_PS_DEBUG */
}

static ieee80211_txrx_result
ieee80211_rx_h_sta_process(struct ieee80211_txrx_data *rx)
{
	struct sta_info *sta = rx->sta;
	struct net_device *dev = rx->dev;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb_data(rx->skb);

	if (!sta)
		return TXRX_CONTINUE;

	/* Update last_rx only for IBSS packets which are for the current
	 * BSSID to avoid keeping the current IBSS network alive in cases where
	 * other STAs are using different BSSID. */
	if (rx->sdata->type == IEEE80211_IF_TYPE_IBSS) {
		u8 *bssid = ieee80211_get_bssid(hdr, skb_len(rx->skb));
		if (compare_ether_addr(bssid, rx->sdata->u.sta.bssid) == 0)
			sta->last_rx = jiffies;
	} else
	if (!is_multicast_ether_addr(hdr->addr1) ||
	    rx->sdata->type == IEEE80211_IF_TYPE_STA) {
		/* Update last_rx only for unicast frames in order to prevent
		 * the Probe Request frames (the only broadcast frames from a
		 * STA in infrastructure mode) from keeping a connection alive.
		 */
		sta->last_rx = jiffies;
	}

	if (!rx->u.rx.ra_match)
		return TXRX_CONTINUE;

	sta->rx_fragments++;
	sta->rx_bytes += skb_len(rx->skb);
	sta->last_rssi = (sta->last_rssi * 15 +
			  rx->u.rx.status->ssi) / 16;
	sta->last_signal = (sta->last_signal * 15 +
			    rx->u.rx.status->signal) / 16;
	sta->last_noise = (sta->last_noise * 15 +
			   rx->u.rx.status->noise) / 16;

	if (!(rx->fc & IEEE80211_FCTL_MOREFRAGS)) {
		/* Change STA power saving mode only in the end of a frame
		 * exchange sequence */
		if ((sta->flags & WLAN_STA_PS) && !(rx->fc & IEEE80211_FCTL_PM))
			rx->u.rx.sent_ps_buffered += ap_sta_ps_end(dev, sta);
		else if (!(sta->flags & WLAN_STA_PS) &&
			 (rx->fc & IEEE80211_FCTL_PM))
			ap_sta_ps_start(dev, sta);
	}

	/* Drop data::nullfunc frames silently, since they are used only to
	 * control station power saving mode. */
	if ((rx->fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA &&
	    (rx->fc & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_NULLFUNC) {
		I802_DEBUG_INC(rx->local->rx_handlers_drop_nullfunc);
		/* Update counter and free packet here to avoid counting this
		 * as a dropped packed. */
		sta->rx_packets++;
		dev_kfree_skb(rx->skb);
		return TXRX_QUEUED;
	}

	return TXRX_CONTINUE;
} /* ieee80211_rx_h_sta_process */

void ieee80211_sta_rx_mgmt(struct net_device *dev, struct sk_buff *skb,
			   struct ieee80211_rx_status *rx_status)
{
	struct ieee80211_local *local = (ieee80211_local *)wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_sta *ifsta;
	struct ieee80211_mgmt *mgmt;
	u16 fc;

	if (skb_len(skb) < 24)
		goto fail;

	sdata = (ieee80211_sub_if_data *)IEEE80211_DEV_TO_SUB_IF(dev);
	ifsta = &sdata->u.sta;

	mgmt = (struct ieee80211_mgmt *) skb_data(skb);
	fc = le16_to_cpu(mgmt->frame_control);

	switch (fc & IEEE80211_FCTL_STYPE) {
	case IEEE80211_STYPE_PROBE_REQ:
	case IEEE80211_STYPE_PROBE_RESP:
	case IEEE80211_STYPE_BEACON:
		memcpy(skb->cb, rx_status, sizeof(*rx_status));
	case IEEE80211_STYPE_AUTH:
	case IEEE80211_STYPE_ASSOC_RESP:
	case IEEE80211_STYPE_REASSOC_RESP:
	case IEEE80211_STYPE_DEAUTH:
	case IEEE80211_STYPE_DISASSOC:
		skb_queue_tail(&ifsta->skb_queue, skb);
		queue_work((struct workqueue_struct*)(local->hw.workqueue), (struct work_struct*)&ifsta->work);//check this
		return;
	default:
		printk(KERN_DEBUG "%s: received unknown management frame - "
		       "stype=%d\n", dev->name,
		       (fc & IEEE80211_FCTL_STYPE) >> 4);
		break;
	}

 fail:
	kfree_skb(skb);
}


static ieee80211_txrx_result
ieee80211_rx_h_mgmt(struct ieee80211_txrx_data *rx)
{
	struct ieee80211_sub_if_data *sdata;

	if (!rx->u.rx.ra_match)
		return TXRX_DROP;

	sdata = (ieee80211_sub_if_data *)IEEE80211_DEV_TO_SUB_IF(rx->dev);
	if ((sdata->type == IEEE80211_IF_TYPE_STA ||
	     sdata->type == IEEE80211_IF_TYPE_IBSS) &&
	    !rx->local->user_space_mlme) {
		ieee80211_sta_rx_mgmt(rx->dev, rx->skb, rx->u.rx.status);
	} else {
		/* Management frames are sent to hostapd for processing */
		if (!rx->local->apdev)
			return TXRX_DROP;
		ieee80211_rx_mgmt(rx->local, rx->skb, rx->u.rx.status,
				  ieee80211_msg_normal);
	}
	return TXRX_QUEUED;
}

/* See IEEE 802.1H for LLC/SNAP encapsulation/decapsulation */
/* Ethernet-II snap header (RFC1042 for most EtherTypes) */
static const unsigned char rfc1042_header[] =
	{ 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };
	/* Bridge-Tunnel header (for EtherTypes ETH_P_AARP and ETH_P_IPX) */
static const unsigned char bridge_tunnel_header[] =
	{ 0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8 };
	
#define WLAN_FC_DATA_PRESENT(fc) (((fc) & 0x4c) == 0x08)

/*
 *      This is an Ethernet frame header.
 */
struct ethhdr {
         unsigned char   h_dest[ETH_ALEN];       /* destination eth addr */
         unsigned char   h_source[ETH_ALEN];     /* source ether addr    */
         __be16          h_proto;                /* packet type ID field */
} __attribute__((packed));

static ieee80211_txrx_result
ieee80211_rx_h_data(struct ieee80211_txrx_data *rx)
{
	struct net_device *dev = rx->dev;
	struct ieee80211_local *local = rx->local;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb_data(rx->skb);
	u16 fc, hdrlen, ethertype;
	u8 *payload;
	u8 dst[ETH_ALEN];
	u8 src[ETH_ALEN];
	struct sk_buff *skb = rx->skb, *skb2;
	struct ieee80211_sub_if_data *sdata = (ieee80211_sub_if_data *)IEEE80211_DEV_TO_SUB_IF(dev);

	fc = rx->fc;
	if (unlikely((fc & IEEE80211_FCTL_FTYPE) != IEEE80211_FTYPE_DATA))
		return TXRX_CONTINUE;

	if (unlikely(!WLAN_FC_DATA_PRESENT(fc)))
		return TXRX_DROP;

	hdrlen = ieee80211_get_hdrlen(fc);

	/* convert IEEE 802.11 header + possible LLC headers into Ethernet
	 * header
	 * IEEE 802.11 address fields:
	 * ToDS FromDS Addr1 Addr2 Addr3 Addr4
	 *   0     0   DA    SA    BSSID n/a
	 *   0     1   DA    BSSID SA    n/a
	 *   1     0   BSSID SA    DA    n/a
	 *   1     1   RA    TA    DA    SA
	 */

	switch (fc & (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS)) {
	case IEEE80211_FCTL_TODS:
		/* BSSID SA DA */
		memcpy(dst, hdr->addr3, ETH_ALEN);
		memcpy(src, hdr->addr2, ETH_ALEN);

		if (unlikely(sdata->type != IEEE80211_IF_TYPE_AP &&
			     sdata->type != IEEE80211_IF_TYPE_VLAN)) {
			printk(KERN_DEBUG "%s: dropped ToDS frame (BSSID="
			       MAC_FMT " SA=" MAC_FMT " DA=" MAC_FMT ")\n",
			       dev->name, MAC_ARG(hdr->addr1),
			       MAC_ARG(hdr->addr2), MAC_ARG(hdr->addr3));
			return TXRX_DROP;
		}
		break;
	case (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS):
		/* RA TA DA SA */
		memcpy(dst, hdr->addr3, ETH_ALEN);
		memcpy(src, hdr->addr4, ETH_ALEN);

		if (unlikely(sdata->type != IEEE80211_IF_TYPE_WDS)) {
			printk(KERN_DEBUG "%s: dropped FromDS&ToDS frame (RA="
			       MAC_FMT " TA=" MAC_FMT " DA=" MAC_FMT " SA="
			       MAC_FMT ")\n",
			       rx->dev->name, MAC_ARG(hdr->addr1),
			       MAC_ARG(hdr->addr2), MAC_ARG(hdr->addr3),
			       MAC_ARG(hdr->addr4));
			return TXRX_DROP;
		}
		break;
	case IEEE80211_FCTL_FROMDS:
		/* DA BSSID SA */
		memcpy(dst, hdr->addr1, ETH_ALEN);
		memcpy(src, hdr->addr3, ETH_ALEN);

		if (sdata->type != IEEE80211_IF_TYPE_STA) {
			return TXRX_DROP;
		}
		break;
	case 0:
		/* DA SA BSSID */
		memcpy(dst, hdr->addr1, ETH_ALEN);
		memcpy(src, hdr->addr2, ETH_ALEN);

		if (sdata->type != IEEE80211_IF_TYPE_IBSS) {
			if (net_ratelimit()) {
				printk(KERN_DEBUG "%s: dropped IBSS frame (DA="
				       MAC_FMT " SA=" MAC_FMT " BSSID=" MAC_FMT
				       ")\n",
				       dev->name, MAC_ARG(hdr->addr1),
				       MAC_ARG(hdr->addr2),
				       MAC_ARG(hdr->addr3));
			}
			return TXRX_DROP;
		}
		break;
	}

	payload = ((u8*)skb->mac_data) + hdrlen;
	if (unlikely(skb_len(skb) - hdrlen < 8)) {
		if (net_ratelimit()) {
			printk(KERN_DEBUG "%s: RX too short data frame "
			       "payload\n", dev->name);
		}
		return TXRX_DROP;
	}

	ethertype = (payload[6] << 8) | payload[7];
#define ETH_P_AARP	0x80F3
#define ETH_P_IPX	0x8137		/* IPX over DIX			*/

	if (likely((compare_ether_addr(payload, rfc1042_header) == 0 &&
		    ethertype != ETH_P_AARP && ethertype != ETH_P_IPX) ||
		   compare_ether_addr(payload, bridge_tunnel_header) == 0)) {
		/* remove RFC1042 or Bridge-Tunnel encapsulation and
		 * replace EtherType */
		skb_pull(skb, hdrlen + 6);
		memcpy(skb_push(skb, ETH_ALEN), src, ETH_ALEN);
		memcpy(skb_push(skb, ETH_ALEN), dst, ETH_ALEN);
	} else {
		struct ethhdr *ehdr;
		__be16 len;
		skb_pull(skb, hdrlen);
		len = htons(skb_len(skb));
		ehdr = (struct ethhdr *) skb_push(skb, sizeof(struct ethhdr));
		memcpy(ehdr->h_dest, dst, ETH_ALEN);
		memcpy(ehdr->h_source, src, ETH_ALEN);
		ehdr->h_proto = len;
	}

	//skb->dev = dev;

	skb2 = NULL;

	sdata->stats.rx_packets++;
	sdata->stats.rx_bytes += skb_len(skb);

	if (local->bridge_packets && (sdata->type == IEEE80211_IF_TYPE_AP
	    || sdata->type == IEEE80211_IF_TYPE_VLAN) && rx->u.rx.ra_match) {
		if (is_multicast_ether_addr((u8*)skb_data(skb))) {
			/* send multicast frames both to higher layers in
			 * local net stack and back to the wireless media */
			skb2 = skb_copy(skb, GFP_ATOMIC);
			if (!skb2)
				printk(KERN_DEBUG "%s: failed to clone "
				       "multicast frame\n", dev->name);
		} else {
			struct sta_info *dsta;
			dsta = sta_info_get(local, (u8*)skb_data(skb));
			if (dsta && !dsta->dev) {
				printk(KERN_DEBUG "Station with null dev "
				       "structure!\n");
			} else if (dsta && dsta->dev == dev) {
				/* Destination station is associated to this
				 * AP, so send the frame directly to it and
				 * do not pass the frame to local net stack.
				 */
				skb2 = skb;
				skb = NULL;
			}
			if (dsta)
				sta_info_put(dsta);
		}
	}

	if (skb) {
		/* deliver to local stack */
		//skb->protocol = eth_type_trans(skb, dev);
		memset(skb->cb, 0, sizeof(skb->cb));
		//netif_rx(skb);
		my_fNetif->inputPacket(skb->mac_data,mbuf_len(skb->mac_data));
	}

	if (skb2) {
		/* send to wireless media */
		//FIXME: SEND
		//skb2->protocol = __constant_htons(ETH_P_802_3);
		//skb_set_network_header(skb2, 0);
		//skb_set_mac_header(skb2, 0);
		//dev_queue_xmit(skb2);
		currentController->outputPacket(skb2->mac_data,NULL);
	}

	return TXRX_QUEUED;
}

/* No encapsulation header if EtherType < 0x600 (=length) */
static const unsigned char eapol_header[] =
	{ 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e };
	
static int ieee80211_is_eapol(const struct sk_buff *skb)
{
	const struct ieee80211_hdr *hdr;
	u16 fc;
	int hdrlen;

	if (unlikely(skb_len(skb) < 10))
		return 0;

	hdr = (const struct ieee80211_hdr *) skb_data(skb);
	fc = le16_to_cpu(hdr->frame_control);

	if (unlikely(!WLAN_FC_DATA_PRESENT(fc)))
		return 0;

	hdrlen = ieee80211_get_hdrlen(fc);
	
	UInt32 data_skb = (UInt32) skb_data(skb);
	if (unlikely(skb_len(skb) >= hdrlen + sizeof(eapol_header) &&
		     //memcmp(skb_data(skb) + hdrlen, eapol_header,
			 memcmp((void*)(data_skb + hdrlen), eapol_header,
			    sizeof(eapol_header)) == 0))
		return 1;

	return 0;
}


static ieee80211_txrx_result
ieee80211_rx_h_drop_unencrypted(struct ieee80211_txrx_data *rx)
{
	/*  If the device handles decryption totally, skip this test */
	if (rx->local->hw.flags & IEEE80211_HW_DEVICE_HIDES_WEP)
		return TXRX_CONTINUE;

	/* Drop unencrypted frames if key is set. */
	if (unlikely(!(rx->fc & IEEE80211_FCTL_PROTECTED) &&
		     (rx->fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA &&
		     (rx->fc & IEEE80211_FCTL_STYPE) != IEEE80211_STYPE_NULLFUNC &&
		     (rx->key || rx->sdata->drop_unencrypted) &&
		     (rx->sdata->eapol == 0 ||
		      !ieee80211_is_eapol(rx->skb)))) {
		printk(KERN_DEBUG "%s: RX non-WEP frame, but expected "
		       "encryption\n", rx->dev->name);
		return TXRX_DROP;
	}
	return TXRX_CONTINUE;
}

ieee80211_txrx_result
ieee80211_rx_h_tkip_decrypt(struct ieee80211_txrx_data *rx)
{
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_wep_weak_iv_detection(struct ieee80211_txrx_data *rx)
{
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_wep_decrypt(struct ieee80211_txrx_data *rx)
{
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_defragment(struct ieee80211_txrx_data *rx)
{
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_ps_poll(struct ieee80211_txrx_data *rx)
{
	return TXRX_QUEUED;
}

ieee80211_txrx_result
ieee80211_rx_h_michael_mic_verify(struct ieee80211_txrx_data *rx)
{
	return TXRX_CONTINUE;
}

ieee80211_txrx_result
ieee80211_rx_h_remove_qos_control(struct ieee80211_txrx_data *rx)
{
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_802_1x_pae(struct ieee80211_txrx_data *rx)
{
	return TXRX_CONTINUE;
}


static ieee80211_rx_handler ieee80211_rx_handlers[] =
{
	ieee80211_rx_h_if_stats,
	ieee80211_rx_h_monitor,
	ieee80211_rx_h_passive_scan,
	ieee80211_rx_h_check,
	ieee80211_rx_h_sta_process,
	ieee80211_rx_h_ccmp_decrypt,
	ieee80211_rx_h_tkip_decrypt,
	ieee80211_rx_h_wep_weak_iv_detection,
	ieee80211_rx_h_wep_decrypt,
	ieee80211_rx_h_defragment,
	ieee80211_rx_h_ps_poll,
	ieee80211_rx_h_michael_mic_verify,
	/* this must be after decryption - so header is counted in MPDU mic
	 * must be before pae and data, so QOS_DATA format frames
	 * are not passed to user space by these functions
	 */
	ieee80211_rx_h_remove_qos_control,
	ieee80211_rx_h_802_1x_pae,
	ieee80211_rx_h_drop_unencrypted,
	ieee80211_rx_h_data,
	ieee80211_rx_h_mgmt,
	NULL
};

static ieee80211_tx_handler ieee80211_tx_handlers[] =
{
/*	ieee80211_tx_h_check_assoc,
	ieee80211_tx_h_sequence,
	ieee80211_tx_h_ps_buf,
	ieee80211_tx_h_select_key,
	ieee80211_tx_h_michael_mic_add,
	ieee80211_tx_h_fragment,
	ieee80211_tx_h_tkip_encrypt,
	ieee80211_tx_h_ccmp_encrypt,
	ieee80211_tx_h_wep_encrypt,
	ieee80211_tx_h_rate_ctrl,
	ieee80211_tx_h_misc,
	ieee80211_tx_h_load_stats,*/
	NULL
};

int ieee80211_hw_config(struct ieee80211_local *local)
{
	struct ieee80211_hw_mode *mode;
	struct ieee80211_channel *chan;
	int ret = 0;

	if (local->sta_scanning) {
		chan = local->scan_channel;
		mode = local->scan_hw_mode;
	} else {
		chan = local->oper_channel;
		mode = local->oper_hw_mode;
	}

	local->hw.conf.channel = chan->chan;
	local->hw.conf.channel_val = chan->val;
	local->hw.conf.power_level = chan->power_level;
	local->hw.conf.freq = chan->freq;
	local->hw.conf.phymode = mode->mode;
	local->hw.conf.antenna_max = chan->antenna_max;

#ifdef CONFIG_MAC80211_VERBOSE_DEBUG
	printk(KERN_DEBUG "HW CONFIG: channel=%d freq=%d "
	       "phymode=%d\n", local->hw.conf.channel, local->hw.conf.freq,
	       local->hw.conf.phymode);
#endif /* CONFIG_MAC80211_VERBOSE_DEBUG */

	if (local->ops->config)
		ret = local->ops->config(local_to_hw(local), &local->hw.conf);

	return ret;
}

void ieee80211_scan_completed (	struct ieee80211_hw *  	hw){
	IOLog("ieee80211_scan_completed\n");
	struct ieee80211_local *local = hw_to_local(hw);
	struct net_device *dev = local->scan_dev;
	struct ieee80211_sub_if_data *sdata;
	union iwreq_data wrqu;

	local->last_scan_completed = jiffies;
	//wmb();
	local->sta_scanning = 0;

	if (ieee80211_hw_config(local))
		printk(KERN_DEBUG "%s: failed to restore operational"
		       "channel after scan\n", dev->name);

	/*if (!(local->hw.flags & IEEE80211_HW_NO_PROBE_FILTERING) &&
	    ieee80211_if_config(dev))
		printk(KERN_DEBUG "%s: failed to restore operational"
		       "BSSID after scan\n", dev->name);*/

	//memset(&wrqu, 0, sizeof(wrqu));
	//wireless_send_event(dev, SIOCGIWSCAN, &wrqu, NULL);

	//read_lock(&local->sub_if_lock);
	list_for_each_entry(sdata, &local->sub_if_list, list) {

		/* No need to wake the master device. */
		if (sdata->dev == local->mdev)
			continue;

		/*if (sdata->type == IEEE80211_IF_TYPE_STA) {
			if (sdata->u.sta.associated)
				ieee80211_send_nullfunc(local, sdata, 0);
			ieee80211_sta_timer((unsigned long)sdata);
		}*/

		netif_wake_queue(sdata->dev);
	}
	//read_unlock(&local->sub_if_lock);

	/*sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	if (sdata->type == IEEE80211_IF_TYPE_IBSS) {
		struct ieee80211_if_sta *ifsta = &sdata->u.sta;
		if (!ifsta->bssid_set ||
		    (!ifsta->state == IEEE80211_IBSS_JOINED &&
		    !ieee80211_sta_active_ibss(dev)))
			ieee80211_sta_find_ibss(dev, ifsta);
	}*/
}

static void ieee80211_sta_tx(struct net_device *dev, struct sk_buff *skb,
			     int encrypt)
{
	//FIXME: lot of skb_function
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_tx_packet_data *pkt_data;

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	//skb->dev = sdata->local->mdev;
	skb_set_mac_header(skb, 0);
	skb_set_network_header(skb, 0);
	//skb_set_transport_header(skb, 0);

	pkt_data = (struct ieee80211_tx_packet_data *) skb->cb;
	memset(pkt_data, 0, sizeof(struct ieee80211_tx_packet_data));
	pkt_data->ifindex = sdata->dev->ifindex;
	pkt_data->mgmt_iface = (sdata->type == IEEE80211_IF_TYPE_MGMT);
	pkt_data->do_not_encrypt = !encrypt;

	//dev_queue_xmit(skb);
	currentController->outputPacket(skb->mac_data,NULL);
}

#define IEEE80211_PROBE_DELAY (HZ / 33)
#define IEEE80211_FC(type, stype) cpu_to_le16(type | stype)

static void ieee80211_send_probe_req(struct net_device *dev, u8 *dst,
				     u8 *ssid, size_t ssid_len)
{
	struct ieee80211_local *local = (ieee80211_local *)wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_hw_mode *mode;
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;
	u8 *pos, *supp_rates, *esupp_rates = NULL;
	int i;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + sizeof(*mgmt) + 200);
	if (!skb) {
		printk(KERN_DEBUG "%s: failed to allocate buffer for probe "
		       "request\n", dev->name);
		return;
	}
	skb_reserve(skb, local->hw.extra_tx_headroom);

	mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24);
	memset(mgmt, 0, 24);
	mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
					   IEEE80211_STYPE_PROBE_REQ);
	memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
	if (dst) {
		memcpy(mgmt->da, dst, ETH_ALEN);
		memcpy(mgmt->bssid, dst, ETH_ALEN);
	} else {
		memset(mgmt->da, 0xff, ETH_ALEN);
		memset(mgmt->bssid, 0xff, ETH_ALEN);
	}
	pos = (u8*)skb_put(skb, 2 + ssid_len);
	*pos++ = WLAN_EID_SSID;
	*pos++ = ssid_len;
	memcpy(pos, ssid, ssid_len);

	supp_rates = (u8*)skb_put(skb, 2);
	supp_rates[0] = WLAN_EID_SUPP_RATES;
	supp_rates[1] = 0;
	mode = local->oper_hw_mode;
	for (i = 0; i < mode->num_rates; i++) {
		struct ieee80211_rate *rate = &mode->rates[i];
		if (!(rate->flags & IEEE80211_RATE_SUPPORTED))
			continue;
		if (esupp_rates) {
			pos = (u8*)skb_put(skb, 1);
			esupp_rates[1]++;
		} else if (supp_rates[1] == 8) {
			esupp_rates = (u8*)skb_put(skb, 3);
			esupp_rates[0] = WLAN_EID_EXT_SUPP_RATES;
			esupp_rates[1] = 1;
			pos = &esupp_rates[2];
		} else {
			pos = (u8*)skb_put(skb, 1);
			supp_rates[1]++;
		}
		if (mode->mode == MODE_ATHEROS_TURBO)
			*pos = rate->rate / 10;
		else
			*pos = rate->rate / 5;
	}

	ieee80211_sta_tx(dev, skb, 0);
}

#define IEEE80211_CHANNEL_TIME (HZ / 33)
#define IEEE80211_PASSIVE_CHANNEL_TIME (HZ / 5)


void ieee80211_sta_scan_work(struct work_struct *work)
{
	//FIXME: error in SCAN_SEND_PROBE
	struct ieee80211_local *local = (struct ieee80211_local *)work->data;//check this
		//container_of(work, struct ieee80211_local, scan_work.work);
	struct net_device *dev = local->scan_dev;
	struct ieee80211_sub_if_data *sdata = (ieee80211_sub_if_data *)IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_hw_mode *mode;
	struct ieee80211_channel *chan;
	int skip;
	unsigned long next_delay = 0;

	if (!local->sta_scanning)
		return;

	switch (local->scan_state) {
	case 0://SCAN_SET_CHANNEL:
		mode = local->scan_hw_mode;
		if (local->scan_hw_mode->list.next == &local->modes_list &&
		    local->scan_channel_idx >= mode->num_channels) {
			ieee80211_scan_completed(local_to_hw(local));
			return;
		}
		skip = !(local->enabled_modes & (1 << mode->mode));
		chan = &mode->channels[local->scan_channel_idx];
		if (!(chan->flag & IEEE80211_CHAN_W_SCAN) ||
		    (sdata->type == IEEE80211_IF_TYPE_IBSS &&
		     !(chan->flag & IEEE80211_CHAN_W_IBSS)) ||
		    (local->hw_modes & local->enabled_modes &
		     (1 << MODE_IEEE80211G) && mode->mode == MODE_IEEE80211B))
			skip = 1;

		if (!skip) {

			printk(KERN_DEBUG "%s: scan channel %d (%d MHz)\n",
			       dev->name, chan->chan, chan->freq);


			local->scan_channel = chan;
			if (ieee80211_hw_config(local)) {
				printk(KERN_DEBUG "%s: failed to set channel "
				       "%d (%d MHz) for scan\n", dev->name,
				       chan->chan, chan->freq);
				skip = 1;
			}
		}

		local->scan_channel_idx++;
		if (local->scan_channel_idx >= local->scan_hw_mode->num_channels) {
			if (local->scan_hw_mode->list.next != &local->modes_list) {
				local->scan_hw_mode = list_entry(local->scan_hw_mode->list.next,
								 struct ieee80211_hw_mode,
								 list);
				local->scan_channel_idx = 0;
			}
		}

		if (skip)
			break;

		next_delay = IEEE80211_PROBE_DELAY +
			     usecs_to_jiffies(local->hw.channel_change_time);
		(int)local->scan_state = 1;//SCAN_SEND_PROBE;
		break;
	case 1://SCAN_SEND_PROBE:
		if (local->scan_channel->flag & IEEE80211_CHAN_W_ACTIVE_SCAN) {
			ieee80211_send_probe_req(dev, NULL, local->scan_ssid,
						 local->scan_ssid_len);
			next_delay = IEEE80211_CHANNEL_TIME;
		} else
			next_delay = IEEE80211_PASSIVE_CHANNEL_TIME;
		(int)local->scan_state = 0;//SCAN_SET_CHANNEL;
		break;
	}
	//check this
	if (local->sta_scanning)
		queue_delayed_work((struct workqueue_struct*)local->hw.workqueue, (struct delayed_work*)&local->scan_work,
				   next_delay);
}

/* How often station data is cleaned up (e.g., expiration of buffered frames)
 */
#define STA_INFO_CLEANUP_INTERVAL (10 * HZ)

void sta_info_init(struct ieee80211_local *local)
{
	spin_lock_init(&local->sta_lock);
	INIT_LIST_HEAD(&local->sta_list);
	INIT_LIST_HEAD(&local->deleted_sta_list);

	init_timer(&local->sta_cleanup);
	local->sta_cleanup.expires = jiffies + STA_INFO_CLEANUP_INTERVAL;
	local->sta_cleanup.data = (unsigned long) local;
	//FIXME: sta_info_cleanup
	//local->sta_cleanup.function = sta_info_cleanup;

#ifdef CONFIG_MAC80211_DEBUGFS
	INIT_WORK(&local->sta_debugfs_add, sta_info_debugfs_add_task);
#endif
}

//FIXME: !!
static void ieee80211_tx_pending(unsigned long data)
{
	/*struct ieee80211_local *local = (struct ieee80211_local *)data;
	struct net_device *dev = local->mdev;
	struct ieee80211_tx_stored_packet *store;
	struct ieee80211_txrx_data tx;
	int i, ret, reschedule = 0;

	netif_tx_lock_bh(dev);
	for (i = 0; i < local->hw.queues; i++) {
		if (__ieee80211_queue_stopped(local, i))
			continue;
		if (!__ieee80211_queue_pending(local, i)) {
			reschedule = 1;
			continue;
		}
		store = &local->pending_packet[i];
		tx.u.tx.control = &store->control;
		tx.u.tx.extra_frag = store->extra_frag;
		tx.u.tx.num_extra_frag = store->num_extra_frag;
		tx.u.tx.last_frag_hwrate = store->last_frag_hwrate;
		tx.u.tx.last_frag_rate = store->last_frag_rate;
		tx.u.tx.probe_last_frag = store->last_frag_rate_ctrl_probe;
		ret = __ieee80211_tx(local, store->skb, &tx);
		if (ret) {
			if (ret == IEEE80211_TX_FRAG_AGAIN)
				store->skb = NULL;
		} else {
			clear_bit(IEEE80211_LINK_STATE_PENDING,
				  &local->state[i]);
			reschedule = 1;
		}
	}
	netif_tx_unlock_bh(dev);
	if (reschedule) {
		if (!ieee80211_qdisc_installed(dev)) {
			if (!__ieee80211_queue_stopped(local, 0))
				netif_wake_queue(dev);
		} else
			netif_schedule(dev);
	}*/
}


struct ieee80211_hw * ieee80211_alloc_hw (size_t priv_data_len,const struct ieee80211_ops *  ops){
	struct net_device *mdev;
	struct ieee80211_local *local;
	struct ieee80211_sub_if_data *sdata;
	int priv_size;
	struct wiphy *wiphy;

	/* Ensure 32-byte alignment of our private data and hw private data.
	 * We use the wiphy priv data for both our ieee80211_local and for
	 * the driver's private data
	 *
	 * In memory it'll be like this:
	 *
	 * +-------------------------+
	 * | struct wiphy	    |
	 * +-------------------------+
	 * | struct ieee80211_local  |
	 * +-------------------------+
	 * | driver's private data   |
	 * +-------------------------+
	 *
	 */
	priv_size = ((sizeof(struct ieee80211_local) +
		      NETDEV_ALIGN_CONST) & ~NETDEV_ALIGN_CONST) +
		    priv_data_len;

	/*wiphy = wiphy_new(&mac80211_config_ops, priv_size);

	if (!wiphy)
		return NULL;

	wiphy->privid = mac80211_wiphy_privid;

	local = wiphy_priv(wiphy);
	local->hw.wiphy = wiphy;*/
	local=(struct ieee80211_local*)IOMalloc(priv_size);
	memset(local,0,priv_size);
	
	local->hw.priv = (char *)local +
			 ((sizeof(struct ieee80211_local) +
			   NETDEV_ALIGN_CONST) & ~NETDEV_ALIGN_CONST);

	BUG_ON(!ops->tx);
	BUG_ON(!ops->config);
	BUG_ON(!ops->add_interface);
	local->ops = ops;

	/* for now, mdev needs sub_if_data :/ */
	mdev=(struct net_device*)IOMalloc(sizeof(struct ieee80211_sub_if_data));
	memset(mdev,0,sizeof(struct ieee80211_sub_if_data));
	
	//mdev = alloc_netdev(sizeof(struct ieee80211_sub_if_data),
	//		    "wmaster%d", ether_setup);
	if (!mdev) {
		//wiphy_free(wiphy);
		return NULL;
	}

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(mdev);
	mdev->ieee80211_ptr = &sdata->wdev;
	//sdata->wdev.wiphy = wiphy;

	local->hw.queues = 1; /* default */

	local->mdev = mdev;
	local->rx_pre_handlers = ieee80211_rx_pre_handlers;
	local->rx_handlers = ieee80211_rx_handlers;
	local->tx_handlers = ieee80211_tx_handlers;

	local->bridge_packets = 1;

	local->rts_threshold = IEEE80211_MAX_RTS_THRESHOLD;
	local->fragmentation_threshold = IEEE80211_MAX_FRAG_THRESHOLD;
	local->short_retry_limit = 7;
	local->long_retry_limit = 4;
	local->hw.conf.radio_enabled = 1;

	local->enabled_modes = (unsigned int) -1;

	INIT_LIST_HEAD(&local->modes_list);

	//rwlock_init(&local->sub_if_lock);
	INIT_LIST_HEAD(&local->sub_if_list);

	INIT_DELAYED_WORK(&local->scan_work, ieee80211_sta_scan_work, 100);
	/*init_timer(&local->stat_timer);
	local->stat_timer.function = ieee80211_stat_refresh;
	local->stat_timer.data = (unsigned long) local;*/
	//ieee80211_rx_bss_list_init(mdev);

	sta_info_init(local);

	/*mdev->hard_start_xmit = ieee80211_master_start_xmit;
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

	tasklet_init(&local->tx_pending_tasklet, ieee80211_tx_pending,
		     (unsigned long)local);
	//tasklet_disable(&local->tx_pending_tasklet);

	tasklet_init(&local->tasklet,
		     ieee80211_tasklet_handler,
		     (unsigned long) local);
	//tasklet_disable(&local->tasklet);

	skb_queue_head_init(&local->skb_queue);
	skb_queue_head_init(&local->skb_queue_unreliable);

	printf("ieee80211_alloc_hw [OK]\n");
	my_hw=local_to_hw(local);
	return my_hw;

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
//Define the addr 
void SET_IEEE80211_PERM_ADDR (	struct ieee80211_hw *  	hw, 	u8 *  	addr){
	my_mac_addr[0] = addr[0];
	my_mac_addr[1] = addr[1];
	my_mac_addr[2] = addr[2];
	my_mac_addr[3] = addr[3];
	my_mac_addr[4] = addr[4];
	my_mac_addr[5] = addr[5];
	return;
}


#pragma mark -
#pragma mark Kernel PCI fiddler adapters


void pci_dma_sync_single_for_cpu(struct pci_dev *hwdev, dma_addr_t dma_handle, size_t size, int direction){
	IOMemoryDescriptor::withPhysicalAddress(dma_handle,size,kIODirectionOutIn)->complete();
	return;
}

int pci_write_config_word(struct pci_dev *dev, int where, u16 val){
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
    fPCIDevice->configWrite16(where,val);
    return 0;
}


int pci_enable_msi  (struct pci_dev * dev){
	return 0;
}

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
	(my_drv->remove) (my_pci_dev);
	return 0;
}


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
#define IEEE80211_SCAN_START 1    
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
#define IEEE80211_SCAN_END 2     
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
#define HW_KEY_IDX_INVALID -1
    local->scan.tx_control.key_idx = HW_KEY_IDX_INVALID;
    local->scan.tx_control.flags |= IEEE80211_TXCTL_DO_NOT_ENCRYPT;
    memset(&extra, 0, sizeof(extra));
    extra.endidx = local->num_curr_rates;
    local->scan.tx_control.tx_rate =
    rate_control_get_rate(local, local->mdev,
                          local->scan.skb, &extra)->val;
    local->scan.tx_control.flags |= IEEE80211_TXCTL_NO_ACK;
}








int run_add_interface() {
	struct ieee80211_local *local = hw_to_local(my_hw); 
    struct ieee80211_if_init_conf conf;
    int res;
    
    conf.if_id = IEEE80211_IF_TYPE_IBSS;
    conf.type = 2;
    conf.mac_addr = my_mac_addr;
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
	fPCIDevice->retain();
	fPCIDevice->open(currentController);
	fPCIDevice->requestPowerDomainState(kIOPMPowerOn, (IOPowerConnection *) currentController->getParentEntry(gIOPowerPlane),IOPMLowestState );
	UInt16 reg16;
	reg16 = fPCIDevice->configRead16(kIOPCIConfigCommand);
	reg16 |= (kIOPCICommandBusMaster      |kIOPCICommandMemorySpace    |kIOPCICommandMemWrInvalidate);

	reg16 &= ~kIOPCICommandIOSpace;  // disable I/O space
	fPCIDevice->configWrite16(kIOPCIConfigCommand,reg16);
		fPCIDevice->configWrite8(kIOPCIConfigLatencyTimer,0x64);
	
	/* We disable the RETRY_TIMEOUT register (0x41) to keep
	 * PCI Tx retries from interfering with C3 CPU state */
	UInt16 reg = fPCIDevice->configRead16(0x40);
	if((reg & 0x0000ff00) != 0)
		fPCIDevice->configWrite16(0x40, reg & 0xffff00ff);

	fPCIDevice->setBusMasterEnable(true);
	fPCIDevice->setMemoryEnable(true);
	int result2 = (drv->probe) (test_pci,test);
	
	//get_eeprom_mac(my_hw->priv,my_mac_addr);
	//Start ...
#warning This assumes the "happy path" and fails miserably when things don't go well
	struct ieee80211_local *local = hw_to_local(my_hw);
	int result3 = run_add_interface();
	if(result3)
		IOLog("Error add_interface\n");
	IOSleep(300);
	//Start mac_open
	result2 = (local->ops->open) (&local->hw);
	

    ieee80211_init_scan(local);//is this in the right place??
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
	return;
}

void free_irq (unsigned int irq, void *dev_id){
	return;
}
void pci_disable_msi(struct pci_dev* dev){
	return;
}

int pci_restore_state (	struct pci_dev *  	dev){
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	fPCIDevice->restoreDeviceState();
	return 0;
}
//ok but no saved_config_space in pci_dev struct
int pci_save_state (struct pci_dev * dev){
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	fPCIDevice->saveDeviceState();
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
#include <IOKit/IOMapper.h>
#define RT_ALIGN_T(u, uAlignment, type) ( ((type)(u) + ((uAlignment) - 1)) & ~(type)((uAlignment) - 1) )
#define RT_ALIGN_Z(cb, uAlignment)              RT_ALIGN_T(cb, uAlignment, size_t)
#define _4G 0x0000000100000000LL
int pci_set_consistent_dma_mask(struct pci_dev *dev, u64 mask){
	//test if dma supported (ok 3945)
	//dev->dev.coherent_dma_mask = mask;
	return 0;
}

void pci_free_consistent(struct pci_dev *hwdev, size_t size,void *vaddr, dma_addr_t dma_handle) {
	size = RT_ALIGN_Z(size, PAGE_SIZE);
    return IOFreeContiguous(vaddr, size);
}




void *pci_alloc_consistent(struct pci_dev *hwdev, size_t size,dma_addr_t *dma_handle,int count) {
	size = RT_ALIGN_Z(size, PAGE_SIZE);
	return IOMallocContiguous(size,PAGE_SIZE, dma_handle);
}

void __iomem * pci_iomap (	struct pci_dev *  	dev,int  	bar,unsigned long  	maxlen){
	IOMemoryMap	*				map;
	IOPhysicalAddress			phys_add;
	UInt16 *					virt_add;
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	map = fPCIDevice->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0, kIOMapInhibitCache);
	if (map == 0) {
			return NULL;
	}
	my_map=map;
	return (void*)map->getVirtualAddress();
}


void pci_iounmap(struct pci_dev *dev, void __iomem * addr){
	return;
}


void pci_unmap_single(struct pci_dev *hwdev, dma_addr_t dma_addr,size_t size, int direction) {
    IODirection mydir = (IODirection) direction;
    IOMemoryDescriptor::withPhysicalAddress(dma_addr, size, mydir)->complete(mydir);
    IOMemoryDescriptor::withPhysicalAddress(dma_addr,size, mydir)->release();
}

addr64_t pci_map_single(struct pci_dev *hwdev, void *ptr, size_t size, int direction) {
	IOMemoryDescriptor::withAddress(ptr,size,kIODirectionOutIn)->complete(kIODirectionOutIn);
	addr64_t tmp = cpu_to_le32(mbuf_data_to_physical( (u8*)ptr));
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
#pragma mark Adapt workqueue calls

/*
	wait for the end of all threads ?
*/
void flush_workqueue(struct workqueue_struct *wq){
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

static thread_call_t tlink[256];//for the queue work...

/*
	Cancel a work queue
*/
void queue_td(int num , thread_call_func_t func)
{
	if (tlink[num])
	{
		thread_call_cancel(tlink[num]);
	}
}

void test_function(work_func_t param0,thread_call_param_t param1){
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
	if (tlink[num])
		queue_td(num,NULL);
	if (!tlink[num])
		tlink[num]=thread_call_allocate((thread_call_func_t)test_function,(void*)func);
	uint64_t timei2;
	if (timei)
		clock_interval_to_deadline(timei,kMillisecondScale,&timei2);
	int r;
	if (start==true && tlink[num])
	{
		if (!par && !timei)	
			r=thread_call_enter(tlink[num]);
		if (!par && timei)
			r=thread_call_enter_delayed(tlink[num],timei2);
		if (par && !timei)
			r=thread_call_enter1(tlink[num],par);
		if (par && timei)
			r=thread_call_enter1_delayed(tlink[num],par,timei2);
	}
}


	

//static mutex
struct thread_data{
	work_func_t func;
	void* param;
	int delay;
	int thread_number;
};


void tasklet_schedule(struct tasklet_struct *t){
	queue_te(13,(thread_call_func_t)t->func,my_hw->priv,NULL,true);
	return;
}
/*
	Used only once ,
*/
void tasklet_init(struct tasklet_struct *t, void (*func)(unsigned long), unsigned long data){
	t->func=func;
	t->data=data;
	return;
}

int queue_work(struct workqueue_struct *wq, struct work_struct *work) {
#warning Get this to run in a gated manner//
	queue_te(work->number,(thread_call_func_t)work->func,my_hw->priv,NULL,true);
    return 0;
}

int queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *work, unsigned long delay) {
	struct work_struct tmp = work->work;
	struct work_struct *tmp2 = &tmp;
	queue_te(tmp2->number,(thread_call_func_t)tmp2->func,my_hw->priv,delay,true);
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
	struct work_struct tmp = work->work;
	struct work_struct *tmp2 = &tmp;
	queue_td(tmp2->number,NULL);
    return 0;
}

//?
int cancel_work_sync(struct work_struct *work){
	queue_td(work->number,NULL);
	return 0;
}

/*
	Unalloc? 
*/
void destroy_workqueue (	struct workqueue_struct *  	wq){
	for(int i=0;i<256;i++)
		queue_td(i,NULL);
	return;
}




void start_undirect_scan(){
	struct ieee80211_local *local;
	local=hw_to_local(my_hw);
	local->ops->hw_scan(my_hw, NULL, 0);
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