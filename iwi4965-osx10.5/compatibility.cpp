/*
 *  compatibility.cpp
 *  iwi4965
 *
 *  Created by Sean Cross on 2/8/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 osx 10.4 info.plist
		<key>com.apple.iokit.IONetworkingFamily</key>
        <string>1.1.3</string>
        <key>com.apple.iokit.IOPCIFamily</key>
        <string>1.2</string>
		<key>com.apple.iokit.IO80211Family</key>
		<string>1.0.0</string>
        <key>com.apple.kernel.iokit</key>
        <string>6.0</string>
		<key>com.apple.kpi.bsd</key>
		<string>8.0.0b2</string>
		<key>com.apple.kpi.mach</key>
		<string>8.0.0b2</string>
		<key>com.apple.kpi.unsupported</key>
		<string>8.0.0b2</string>
		<key>com.apple.kpi.libkern</key>
		<string>8.0.0b2</string>
		<key>com.apple.kpi.iokit</key>
		<string>8.0.0b2</string>
 */

#define NO_SPIN_LOCKS 0
#define NO_MUTEX_LOCKS 0
#define IM_HERE_NOW() printf("%s @ %s:%d\n", __FUNCTION__, __FILE__, __LINE__)

/*#include <sys/kernel_types.h>
#include <mach/vm_types.h>
#include <sys/kpi_mbuf.h>
#include <libkern/OSByteOrder.h>
#include <libkern/OSAtomic.h>
*/

#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/network/IONetworkController.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOInterruptEventSource.h>

#include <IOKit/assert.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/network/IONetworkController.h>
#include <IOKit/network/IONetworkInterface.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/network/IOMbufMemoryCursor.h>
#include <IOKit/pccard/IOPCCard.h>
#include <IOKit/apple80211/IO80211Controller.h>
#include <IOKit/apple80211/IO80211Interface.h>
#include <IOKit/network/IOPacketQueue.h>
#include <IOKit/network/IONetworkMedium.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/assert.h>
#include <IOKit/IODataQueue.h>

#include "defines.h"
//#include "compatibility.h"
#include "firmware/ipw4965.ucode.h"




// Note: This, in itself, makes this very much non-reentrant.  It's used
// primarily when allocating sk_buff entries.
static IONetworkController *currentController;
#ifdef IO80211_VERSION
static IO80211Interface*			my_fNetif;	
#else
static IOEthernetInterface*			my_fNetif;
#endif
static IOBasicOutputQueue *				fTransmitQueue;	

static IOWorkLoop * workqueue;
static IOInterruptEventSource *	fInterruptSrc;
static IOInterruptEventSource *	DMAInterruptSource;
static irqreturn_t (*realHandler)(int, void *);
static pci_driver * my_drv;
struct pci_dev* my_pci_dev;
IOPCIDevice* my_pci_device;
IOMemoryMap	*				my_map;

ifnet_t						my_fifnet;

static int next_thread=0;
static int thread_pos=0;
static IOLock* thread_lock;
static bool is_unloaded=false;

#define MAX_MUTEXES 256
static struct mutex *mutexes[MAX_MUTEXES];
unsigned long current_mutex = 0;

extern void (*iwl_scan)(struct iwl4965_priv *);

struct ieee80211_hw* local_to_hw(struct ieee80211_local *local)
{
	return &local->hw;
}
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


void * get_my_priv(){
	if(my_hw)
		return my_hw->priv;
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


int netif_running(struct net_device *dev)
{
	if (!my_fNetif || !dev) return 0;
	if((my_fNetif->getFlags() & IFF_RUNNING)==0) return 0;
	return 1;//running
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

static inline struct sk_buff *skb_peek(struct sk_buff_head *list_)
 {
         struct sk_buff *list = ((struct sk_buff *)list_)->next;
         if (list == (struct sk_buff *)list_)
                 list = NULL;
         return list;
 }

void *skb_push(const struct sk_buff *skb, unsigned int len) {
	mbuf_prepend(&(((struct sk_buff*)skb)->mac_data),len,MBUF_WAITOK);
	return mbuf_data(skb->mac_data);
}

static inline void skb_set_mac_header(struct sk_buff *skb, const int offset)
{
	//need to change skb->mac_data
	//skb_reset_mac_header(skb);
        //skb->mac_header += offset;
		/*u8 et[ETH_ALEN];
		memset(et,0,sizeof(et));
		mbuf_adj(skb->mac_data, ETH_ALEN);
		bcopy(et, skb_push(skb, ETH_ALEN), ETH_ALEN);*/
}

static inline void skb_set_network_header(struct sk_buff *skb, const int offset)
{
        //need to change skb->mac_data
	//skb->network_header = skb->data + offset;
	/*u8 et[ETH_ALEN];
		memset(et,0,sizeof(et));
		mbuf_adj(skb->mac_data, ETH_ALEN);
		bcopy(et, skb_push(skb, ETH_ALEN), ETH_ALEN);*/
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

int skb_set_data(const struct sk_buff *skb, void *data, size_t len) {
   mbuf_setdata(skb->mac_data,data,len);
    mbuf_pkthdr_setlen(skb->mac_data,len);
   mbuf_setlen(skb->mac_data,len);
   return 0;
}

int skb_len(const struct sk_buff *skb) {
	return mbuf_len(skb->mac_data);
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
    void *data = (UInt8*)skb_data(skb) + mbuf_len(skb->mac_data);
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
  *      skb_pull - remove data from the start of a buffer
  *      @skb: buffer to use
  *      @len: amount of data to remove
  *
  *      This function removes data from the start of a buffer, returning
  *      the memory to the headroom. A pointer to the next data in the buffer
  *      is returned. Once the data has been pulled future pushes will overwrite
  *      the old data.
  */
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
	
	firmware->data = (u8*)ipw4965_ucode_raw;
	firmware->size = sizeof(ipw4965_ucode_raw); //149652;//crappy

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
	herre we call the real interuptsHandler from ipw4965
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

static thread_call_t timer_func[99];
int timer_func_count=0;

void
IOPCCardAddTimer(struct timer_list2 * timer)
{
	if (!timer->on)
	{
		IOLog("timer not on\n");
		return;
	}
	thread_call_cancel(timer_func[timer->vv]);
    uint64_t deadline, timei;
	if (timer->expires>0)
	timei=jiffies_to_msecs(timer->expires);
	else timei=0;
	clock_interval_to_deadline(timei,kMillisecondScale,&deadline);
	//IOLog("timer->expires %d timei %d deadline %d\n",timer->expires,timei,deadline);
	thread_call_enter1_delayed(timer_func[timer->vv],(void*)timer->data,deadline);
}

void test_timer(struct timer_list2 * timer,unsigned long data){
	if(timer && data)
	{
		if(timer->on)
		{
		(timer->function)((unsigned long)data);
		IOPCCardAddTimer(timer);
		}
		else
		IOLog("timer is off\n");
	}
	else
		IOLog("Error while launching timer thread\n");
}

int
IOPCCardDeleteTimer(struct timer_list2 * timer)
{
	if (!timer->on) return 0;
	thread_call_cancel(timer_func[timer->vv]);
	timer->on=0;
	return 0;
}

int add_timer(struct timer_list2 *timer) {
	IOPCCardAddTimer(timer);
	return 0;
}

int del_timer(struct timer_list2 *timer) {
	IOPCCardDeleteTimer(timer);
	return 0;
}

void init_timer(struct timer_list2 *timer) {
	//timer=(struct timer_list2*)IOMalloc(sizeof(struct timer_list2*));
	timer_func_count++;
	timer->vv=timer_func_count;
	timer->on=1;
	timer_func[timer->vv]=thread_call_allocate((thread_call_func_t)test_timer,(void*)timer);
}

int mod_timer(struct timer_list2 *timer, int length) {
	del_timer(timer);
	timer->expires = length;
	timer->on=1; 
	add_timer(timer);
}

int del_timer_sync(struct timer_list2 *timer) {
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
	struct rate_control_alg *alg;

	alg = (struct rate_control_alg*)kzalloc(sizeof(*alg), GFP_KERNEL);
	if (alg == NULL) {
		return -ENOMEM;
	}
	alg->ops = ops;

	//mutex_lock(&rate_ctrl_mutex);
	list_add_tail(&alg->list, &rate_ctrl_algs);
	//mutex_unlock(&rate_ctrl_mutex);

    return 0;
}

void ieee80211_rate_control_unregister(struct rate_control_ops *ops) {
IM_HERE_NOW();
struct rate_control_alg *alg;

	//mutex_lock(&rate_ctrl_mutex);
	list_for_each_entry(alg, &rate_ctrl_algs, list) {
		if (alg->ops == ops) {
			list_del(&alg->list);
			break;
		}
	}
	//mutex_unlock(&rate_ctrl_mutex);
	kfree(alg);
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
				I802_DEBUG_INC(local->rx_handlers_drop);
				if (sta)
					sta->rx_dropped++;
			}
			if (res == TXRX_QUEUED)
				I802_DEBUG_INC(local->rx_handlers_queued);
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
		if (pskb_expand_head(skb, hlen, 0)) {
			dev_kfree_skb(skb);
			return;
		}
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

inline int ieee80211_bssid_match(const u8 *raddr, const u8 *addr)
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

static void kref_init(struct kref *kref)
  {
          //WARN_ON(release == NULL);
          atomic_set(&kref->refcount,1);
  }

static  struct kref *kref_get(struct kref *kref)
{
IM_HERE_NOW();
          //WARN_ON(!atomic_read(&kref->refcount));
          atomic_inc(&kref->refcount);
          return kref;
}
 
static inline void __sta_info_get(struct sta_info *sta)
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
static  void kref_put(struct kref *kref, void (*release)(struct kref *kref))
{
  IM_HERE_NOW();
		if (atomic_dec_and_test(&kref->refcount)) {
			IOLog("kref cleaning up\n");
			release(kref);
		} 
} 
 
  static inline void rate_control_free_sta(struct rate_control_ref *ref,
					 void *priv)
{
	ref->ops->free_sta(ref->priv, priv);
}

void ieee80211_debugfs_key_sta_del(struct ieee80211_key *key,
				   struct sta_info *sta)
{
	//debugfs_remove(key->debugfs.stalink);
	//key->debugfs.stalink = NULL;
}

static void rate_control_put(struct rate_control_ref *ref)
{
IM_HERE_NOW();
	kref_put(&ref->kref, rate_control_release);
}

static void sta_info_release(struct kref *kref)
{
IM_HERE_NOW();
	struct sta_info *sta = container_of(kref, struct sta_info, kref);
	struct ieee80211_local *local = sta->local;
	struct sk_buff *skb;
	int i;

	/* free sta structure; it has already been removed from
	 * hash table etc. external structures. Make sure that all
	 * buffered frames are release (one might have been added
	 * after sta_info_free() was called). */
	while ((skb = skb_dequeue(&sta->ps_tx_buf)) != NULL) {
		local->total_ps_buffered--;
		dev_kfree_skb_any(skb);
	}
	while ((skb = skb_dequeue(&sta->tx_filtered)) != NULL) {
		dev_kfree_skb_any(skb);
	}

	/*for (i=0; i< STA_TID_NUM; i++) {
		del_timer_sync(&sta->ht_ba_mlme.tid_agg_info_tx[i].addba_resp_timer);
		del_timer_sync(&sta->ht_ba_mlme.tid_agg_info_rx[i].session_timer);
	}*/

	rate_control_free_sta(sta->rate_ctrl, sta->rate_ctrl_priv);
	rate_control_put(sta->rate_ctrl);
	if (sta->key)
		ieee80211_debugfs_key_sta_del(sta->key, sta);
	kfree(sta);
}

void sta_info_put(struct sta_info *sta)
{
IM_HERE_NOW();
    kref_put(&sta->kref,sta_info_release);
}

static struct rate_control_ref *rate_control_get(struct rate_control_ref *ref)
{
IM_HERE_NOW();
	kref_get(&ref->kref);
	return ref;
}

void rate_control_release(struct kref *kref)
{
IM_HERE_NOW();
	struct rate_control_ref *ctrl_ref;

	ctrl_ref = container_of(kref, struct rate_control_ref, kref);
	ctrl_ref->ops->free(ctrl_ref->priv);
	//ieee80211_rate_control_ops_put(ctrl_ref->ops);
	kfree(ctrl_ref);
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

	kref_init(&sta->kref);

	sta->rate_ctrl = rate_control_get(local->rate_ctrl);
	sta->rate_ctrl_priv = rate_control_alloc_sta(sta->rate_ctrl, gfp);
	if (!sta->rate_ctrl_priv) {
		rate_control_put(sta->rate_ctrl);
		kref_put(&sta->kref, sta_info_release);
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
/*
#ifdef CONFIG_MAC80211_DEBUGFS
	if (!in_interrupt()) {
		sta->debugfs_registered = 1;
		ieee80211_sta_debugfs_add(sta);
		rate_control_add_sta_debugfs(sta);
	} else {
		queue_work(local->hw.workqueue, &local->sta_debugfs_add);
	}
#endif
*/
	return sta;
}



#define IEEE80211_IBSS_MAX_STA_ENTRIES 128

struct sta_info * ieee80211_ibss_add_sta(struct net_device *dev,
					 struct sk_buff *skb, u8 *bssid,
					 u8 *addr)
{
IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
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
	int multicast=0;
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
		printk("rxbssid=" MAC_FMT " ('%s')\n", MAC_ARG(rx.sdata->u.sta.bssid),
		escape_essid((const char*)rx.sdata->u.sta.ssid, rx.sdata->u.sta.ssid_len));	
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
		printk( "bssid=" MAC_FMT " stabssid=" MAC_FMT "\n", MAC_ARG(bssid),MAC_ARG(sdata->u.sta.bssid));
			   
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
				printk( "mul %d dev_addr=" MAC_FMT " addr1=" MAC_FMT "\n", multicast, MAC_ARG(sdata->dev->dev_addr),
		       MAC_ARG(hdr->addr1));
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
		//IOLog("Packet Found\n");
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
IM_HERE_NOW();	
    struct ieee80211_local *local = hw_to_local(hw);
    
    BUILD_BUG_ON(sizeof(struct ieee80211_rx_status) > sizeof(skb->cb));
    
  //  IOLog("ieee80211_rx_irqsafe\n");
	
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
	tasklet_schedule(&local->tasklet);
	//FIXME: tasklet only give the priv as argument must be changed
	//IOCreateThread((void(*)(void*))&ieee80211_tasklet_handler,local);
	//IOExitThread();
}




void ieee80211_stop_queue(struct ieee80211_hw *hw, int queue) {
IM_HERE_NOW();	
	struct ieee80211_local *local = hw_to_local(hw);

	//if (!ieee80211_qdisc_installed(local->mdev) && queue == 0)
	//	netif_stop_queue(local->mdev);
	set_bit(IEEE80211_LINK_STATE_XOFF, &local->state[queue]);

}

static void ieee80211_remove_tx_extra(struct ieee80211_local *local,
				      struct ieee80211_key *key,
				      struct sk_buff *skb,
				      struct ieee80211_tx_control *control)
{
IM_HERE_NOW();
	int hdrlen, iv_len, mic_len;
	struct ieee80211_tx_packet_data *pkt_data;

	pkt_data = (struct ieee80211_tx_packet_data *)skb->cb;
	pkt_data->ifindex = control->ifindex;
	pkt_data->mgmt_iface = (control->type == IEEE80211_IF_TYPE_MGMT);
	pkt_data->req_tx_status = !!(control->flags & IEEE80211_TXCTL_REQ_TX_STATUS);
	pkt_data->do_not_encrypt = !!(control->flags & IEEE80211_TXCTL_DO_NOT_ENCRYPT);
	pkt_data->requeue = !!(control->flags & IEEE80211_TXCTL_REQUEUE);
	pkt_data->queue = control->queue;

	hdrlen = ieee80211_get_hdrlen_from_skb(skb);

	if (!key)
		goto no_key;

	switch (key->alg) {
	case ALG_WEP:
		iv_len = WEP_IV_LEN;
		mic_len = WEP_ICV_LEN;
		break;
	case ALG_TKIP:
		iv_len = TKIP_IV_LEN;
		mic_len = TKIP_ICV_LEN;
		break;
	case ALG_CCMP:
		iv_len = CCMP_HDR_LEN;
		mic_len = CCMP_MIC_LEN;
		break;
	default:
		goto no_key;
	}

	if (skb_len(skb) >= mic_len && key->force_sw_encrypt)
		skb_trim(skb, skb_len(skb) - mic_len);
	if (skb_len(skb) >= iv_len && skb_len(skb) > hdrlen) {
		memmove((u8*)skb_data(skb) + iv_len, skb_data(skb), hdrlen);
		skb_pull(skb, iv_len);
	}

no_key:
	{
		struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb_data(skb);
		u16 fc = le16_to_cpu(hdr->frame_control);
		if ((fc & 0x8C) == 0x88) /* QoS Control Field */ {
			fc &= ~IEEE80211_STYPE_QOS_DATA;
			hdr->frame_control = cpu_to_le16(fc);
			memmove((u8*)skb_data(skb) + 2, (u8*)skb_data(skb), hdrlen - 2);
			skb_pull(skb, 2);
		}
	}
}

static inline void rate_control_tx_status(struct ieee80211_local *local,
					  struct net_device *dev,
					  struct sk_buff *skb,
					  struct ieee80211_tx_status *status)
{
IM_HERE_NOW();
	struct rate_control_ref *ref = local->rate_ctrl;
	ref->ops->tx_status(ref->priv, dev, skb, status);
}

void ieee80211_tx_status(struct ieee80211_hw *hw,
                         struct sk_buff *skb,
                         struct ieee80211_tx_status *status) {
IM_HERE_NOW();
	struct sk_buff *skb2;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb_data(skb);
	struct ieee80211_local *local = hw_to_local(hw);
	u16 frag, type;
	u32 msg_type;
	struct ieee80211_tx_status_rtap_hdr *rthdr;
	struct ieee80211_sub_if_data *sdata;
	int monitors;

	if (!status) {
		printk(KERN_ERR
		       "%s: ieee80211_tx_status called with NULL status\n",
		       local->mdev->name);
		dev_kfree_skb(skb);
		return;
	}

	if (status->excessive_retries) {
		struct sta_info *sta;
		sta = sta_info_get(local, hdr->addr1);
		if (sta) {
			if (sta->flags & WLAN_STA_PS) {
				/* The STA is in power save mode, so assume
				 * that this TX packet failed because of that.
				 */
				status->excessive_retries = 0;
				status->flags |= IEEE80211_TX_STATUS_TX_FILTERED;
			}
			sta_info_put(sta);
		}
	}

	if (status->flags & IEEE80211_TX_STATUS_TX_FILTERED) {
		struct sta_info *sta;
		sta = sta_info_get(local, hdr->addr1);
		if (sta) {
			sta->tx_filtered_count++;

			/* Clear the TX filter mask for this STA when sending
			 * the next packet. If the STA went to power save mode,
			 * this will happen when it is waking up for the next
			 * time. */
			sta->clear_dst_mask = 1;

			/* TODO: Is the WLAN_STA_PS flag always set here or is
			 * the race between RX and TX status causing some
			 * packets to be filtered out before 80211.o gets an
			 * update for PS status? This seems to be the case, so
			 * no changes are likely to be needed. */
			if (sta->flags & WLAN_STA_PS &&
			    skb_queue_len(&sta->tx_filtered) <
			    STA_MAX_TX_BUFFER) {
				ieee80211_remove_tx_extra(local, sta->key,
							  skb,
							  &status->control);
				skb_queue_tail(&sta->tx_filtered, skb);
			} else if (!(sta->flags & WLAN_STA_PS) &&
				   !(status->control.flags & IEEE80211_TXCTL_REQUEUE)) {
				/* Software retry the packet once */
				status->control.flags |= IEEE80211_TXCTL_REQUEUE;
				ieee80211_remove_tx_extra(local, sta->key,
							  skb,
							  &status->control);
				dev_queue_xmit(skb);
			} else {
				if (net_ratelimit()) {
					printk(KERN_DEBUG "%s: dropped TX "
					       "filtered frame queue_len=%d "
					       "PS=%d @%lu\n",
					       local->mdev->name,
					       skb_queue_len(
						       &sta->tx_filtered),
					       !!(sta->flags & WLAN_STA_PS),
					       jiffies);
				}
				dev_kfree_skb(skb);
			}
			sta_info_put(sta);
			return;
		}
	} else {
		/* FIXME: STUPID to call this with both local and local->mdev */
		rate_control_tx_status(local, local->mdev, skb, status);
	}

	//ieee80211_led_tx(local, 0);

	/* SNMP counters
	 * Fragments are passed to low-level drivers as separate skbs, so these
	 * are actually fragments, not frames. Update frame counters only for
	 * the first fragment of the frame. */

	frag = le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_FRAG;
	type = le16_to_cpu(hdr->frame_control) & IEEE80211_FCTL_FTYPE;

	if (status->flags & IEEE80211_TX_STATUS_ACK) {
		if (frag == 0) {
			local->dot11TransmittedFrameCount++;
			if (is_multicast_ether_addr(hdr->addr1))
				local->dot11MulticastTransmittedFrameCount++;
			if (status->retry_count > 0)
				local->dot11RetryCount++;
			if (status->retry_count > 1)
				local->dot11MultipleRetryCount++;
		}

		/* This counter shall be incremented for an acknowledged MPDU
		 * with an individual address in the address 1 field or an MPDU
		 * with a multicast address in the address 1 field of type Data
		 * or Management. */
		if (!is_multicast_ether_addr(hdr->addr1) ||
		    type == IEEE80211_FTYPE_DATA ||
		    type == IEEE80211_FTYPE_MGMT)
			local->dot11TransmittedFragmentCount++;
	} else {
		if (frag == 0)
			local->dot11FailedCount++;
	}

	msg_type = (status->flags & IEEE80211_TX_STATUS_ACK) ?
		ieee80211_msg_tx_callback_ack : ieee80211_msg_tx_callback_fail;

	/* this was a transmitted frame, but now we want to reuse it */
	//skb_orphan(skb);

	if ((status->control.flags & IEEE80211_TXCTL_REQ_TX_STATUS) &&
	    local->apdev) {
		if (local->monitors) {
			skb2 = skb_clone(skb, GFP_ATOMIC);
		} else {
			skb2 = skb;
			skb = NULL;
		}

		if (skb2)
			/* Send frame to hostapd */
			ieee80211_rx_mgmt(local, skb2, NULL, msg_type);

		if (!skb)
			return;
	}

	if (!local->monitors) {
		dev_kfree_skb(skb);
		return;
	}

	/* send frame to monitor interfaces now */

	if (skb_headroom(skb) < sizeof(*rthdr)) {
		printk(KERN_ERR "ieee80211_tx_status: headroom too small\n");
		dev_kfree_skb(skb);
		return;
	}

	rthdr = (struct ieee80211_tx_status_rtap_hdr*)
				skb_push(skb, sizeof(*rthdr));

	memset(rthdr, 0, sizeof(*rthdr));
	rthdr->hdr.it_len = cpu_to_le16(sizeof(*rthdr));
	rthdr->hdr.it_present =
		cpu_to_le32((1 << IEEE80211_RADIOTAP_TX_FLAGS) |
			    (1 << IEEE80211_RADIOTAP_DATA_RETRIES));

	if (!(status->flags & IEEE80211_TX_STATUS_ACK) &&
	    !is_multicast_ether_addr(hdr->addr1))
		rthdr->tx_flags |= cpu_to_le16(IEEE80211_RADIOTAP_F_TX_FAIL);

	if ((status->control.flags & IEEE80211_TXCTL_USE_RTS_CTS) &&
	    (status->control.flags & IEEE80211_TXCTL_USE_CTS_PROTECT))
		rthdr->tx_flags |= cpu_to_le16(IEEE80211_RADIOTAP_F_TX_CTS);
	else if (status->control.flags & IEEE80211_TXCTL_USE_RTS_CTS)
		rthdr->tx_flags |= cpu_to_le16(IEEE80211_RADIOTAP_F_TX_RTS);

	rthdr->data_retries = status->retry_count;

	//read_lock(&local->sub_if_lock);
	monitors = local->monitors;
	list_for_each_entry(sdata, &local->sub_if_list, list) {
		/*
		 * Using the monitors counter is possibly racy, but
		 * if the value is wrong we simply either clone the skb
		 * once too much or forget sending it to one monitor iface
		 * The latter case isn't nice but fixing the race is much
		 * more complicated.
		 */
		if (!monitors || !skb)
			goto out;

		if (sdata->type == IEEE80211_IF_TYPE_MNTR) {
			if (!netif_running(sdata->dev))
				continue;
			monitors--;
			if (monitors)
				skb2 = skb_clone(skb, GFP_KERNEL);
			else
				skb2 = NULL;
			//skb->dev = sdata->dev;
			/* XXX: is this sufficient for BPF? */
			skb_set_mac_header(skb, 0);
			//skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb->pkt_type = PACKET_OTHERHOST;
			//skb->protocol = htons(ETH_P_802_2);
			memset(skb->cb, 0, sizeof(skb->cb));
			//netif_rx(skb);
			my_fNetif->inputPacket(skb->mac_data,mbuf_len(skb->mac_data));
			skb = skb2;
		}
	}
 out:
	//read_unlock(&local->sub_if_lock);
	if (skb)
		dev_kfree_skb(skb);
}

void ieee80211_tx_status_irqsafe(struct ieee80211_hw *hw,
                                 struct sk_buff *skb,
                                 struct ieee80211_tx_status *status) {
IM_HERE_NOW();
	struct ieee80211_local *local = hw_to_local(hw);
	struct ieee80211_tx_status *saved;
	int tmp;

	//skb->dev = local->mdev;
	saved = (struct ieee80211_tx_status*)kmalloc(sizeof(struct ieee80211_tx_status), GFP_ATOMIC);
	if (unlikely(!saved)) {
		if (net_ratelimit())
			printk(KERN_WARNING "%s: Not enough memory, "
			       "dropping tx status", "en1");
		/* should be dev_kfree_skb_irq, but due to this function being
		 * named _irqsafe instead of just _irq we can't be sure that
		 * people won't call it from non-irq contexts */
		dev_kfree_skb_any(skb);
		return;
	}
	memcpy(saved, status, sizeof(struct ieee80211_tx_status));
	/* copy pointer to saved status into skb->cb for use by tasklet */
	memcpy(skb->cb, &saved, sizeof(saved));

	skb->pkt_type = IEEE80211_TX_STATUS_MSG;
	skb_queue_tail(status->control.flags & IEEE80211_TXCTL_REQ_TX_STATUS ?
		       &local->skb_queue : &local->skb_queue_unreliable, skb);
	tmp = skb_queue_len(&local->skb_queue) +
		skb_queue_len(&local->skb_queue_unreliable);
	while (tmp > IEEE80211_IRQSAFE_QUEUE_LIMIT &&
	       (skb = skb_dequeue(&local->skb_queue_unreliable))) {
		memcpy(&saved, skb->cb, sizeof(saved));
		kfree(saved);
		//dev_kfree_skb_irq(skb);
		dev_kfree_skb(skb);
		tmp--;
		I802_DEBUG_INC(local->tx_status_drop);
	}
	tasklet_schedule(&local->tasklet);
}

void ieee80211_wake_queue(struct ieee80211_hw *hw, int queue) {
IM_HERE_NOW();	
   // fTransmitQueue->service(IOBasicOutputQueue::kServiceAsync);
	return;
}



 int __bitmap_empty(const unsigned long *bitmap, int bits)
 {
 IM_HERE_NOW();
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
IM_HERE_NOW();
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

	bdev = dev_get_by_index(if_id);
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

	ieee80211_include_sequence(sdata, (struct ieee80211_hdr *)skb_data(skb));

	ieee80211_beacon_add_tim(local, ap, skb);

	if (b_tail) {
		memcpy(skb_put(skb, bt_len), b_tail, bt_len);
	}

	if (control) {
		memset(&extra, 0, sizeof(extra));
		extra.mode = local->oper_hw_mode;

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
IM_HERE_NOW();	
	int i;

	for (i = 0; i < hw->queues; i++)
		ieee80211_stop_queue(hw, i);

}

int sta_info_start(struct ieee80211_local *local)
{
IM_HERE_NOW();	
	//check this
	add_timer(&local->sta_cleanup);
	return 0;
}

void ieee80211_if_sdata_init(struct ieee80211_sub_if_data *sdata)
{
IM_HERE_NOW();	
	/* Default values for sub-interface parameters */
	sdata->drop_unencrypted = 0;
	sdata->eapol = 1;
	for (int i = 0; i < IEEE80211_FRAGMENT_MAX; i++)
		skb_queue_head_init(&sdata->fragments[i].skb_list);
}

static void ieee80211_sta_tx(struct net_device *dev, struct sk_buff *skb,
			     int encrypt)
{
IM_HERE_NOW();	
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
	sdata->dev->ifindex=2;//hack
	pkt_data->ifindex = sdata->dev->ifindex;
	pkt_data->mgmt_iface = (sdata->type == IEEE80211_IF_TYPE_MGMT);
	pkt_data->do_not_encrypt = !encrypt;

	dev_queue_xmit(skb);
	//currentController->outputPacket(skb->mac_data,NULL);
}

static void ieee80211_rx_mgmt_probe_req(struct net_device *dev,
					struct ieee80211_if_sta *ifsta,
					struct ieee80211_mgmt *mgmt,
					size_t len,
					struct ieee80211_rx_status *rx_status)
{
IM_HERE_NOW();

	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	int tx_last_beacon;
	struct sk_buff *skb;
	struct ieee80211_mgmt *resp;
	u8 *pos, *end;

	if (sdata->type != IEEE80211_IF_TYPE_IBSS ||
	    ifsta->state != IEEE80211_IBSS_JOINED ||
	    len < 24 + 2 || !ifsta->probe_resp)
		return;

	if (local->ops->tx_last_beacon)
		tx_last_beacon = local->ops->tx_last_beacon(local_to_hw(local));
	else
		tx_last_beacon = 1;

#ifdef CONFIG_MAC80211_IBSS_DEBUG
	printk(KERN_DEBUG "%s: RX ProbeReq SA=" MAC_FMT " DA=" MAC_FMT " BSSID="
	       MAC_FMT " (tx_last_beacon=%d)\n",
	       dev->name, MAC_ARG(mgmt->sa), MAC_ARG(mgmt->da),
	       MAC_ARG(mgmt->bssid), tx_last_beacon);
#endif /* CONFIG_MAC80211_IBSS_DEBUG */

	if (!tx_last_beacon)
		return;

	if (memcmp(mgmt->bssid, ifsta->bssid, ETH_ALEN) != 0 &&
	    memcmp(mgmt->bssid, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) != 0)
		return;

	end = ((u8 *) mgmt) + len;
	pos = mgmt->u.probe_req.variable;
	if (pos[0] != WLAN_EID_SSID ||
	    pos + 2 + pos[1] > end) {
		if (net_ratelimit()) {
			printk(KERN_DEBUG "%s: Invalid SSID IE in ProbeReq "
			       "from " MAC_FMT "\n",
			       dev->name, MAC_ARG(mgmt->sa));
		}
		return;
	}
	if (pos[1] != 0 &&
	    (pos[1] != ifsta->ssid_len ||
	     memcmp(pos + 2, ifsta->ssid, ifsta->ssid_len) != 0)) {
		/* Ignore ProbeReq for foreign SSID */
		return;
	}

	/* Reply with ProbeResp */
	skb = skb_copy(ifsta->probe_resp, GFP_ATOMIC);
	if (!skb)
		return;

	resp = (struct ieee80211_mgmt *) skb_data(skb);
	memcpy(resp->da, mgmt->sa, ETH_ALEN);
#ifdef CONFIG_MAC80211_IBSS_DEBUG
	printk(KERN_DEBUG "%s: Sending ProbeResp to " MAC_FMT "\n",
	       dev->name, MAC_ARG(resp->da));
#endif /* CONFIG_MAC80211_IBSS_DEBUG */
	ieee80211_sta_tx(dev, skb, 0);
}

static inline void setup_timer(struct timer_list2 * timer,
                                 void (*function)(unsigned long),
                                 unsigned long data)
 {
		IM_HERE_NOW();
		init_timer(timer);
		timer->function = function;
        timer->data = data;
        //add_timer(timer);//hack
 }

int ieee80211_sta_req_scan(struct net_device *dev, u8 *ssid, size_t ssid_len)
{
	IM_HERE_NOW();
	struct ieee80211_sub_if_data *sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);

	if (sdata->type != IEEE80211_IF_TYPE_STA)
		return ieee80211_sta_start_scan(dev, ssid, ssid_len);

	if (local->sta_scanning) {
		if (local->scan_dev == dev)
			return 0;
		return -EBUSY;
	}

	set_bit(IEEE80211_STA_REQ_SCAN, &ifsta->request);
	queue_te(ifsta->work.number,(thread_call_func_t)ifsta->work.func,sdata,NULL,true);
	//queue_work(local->hw.workqueue, &ifsta->work);
	return 0;
}

void ieee80211_sta_timer(unsigned long data)
{
	IM_HERE_NOW();
	struct ieee80211_sub_if_data *sdata =
		(struct ieee80211_sub_if_data *) data;
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;
	struct ieee80211_local *local = wdev_priv(&sdata->dev);//wdev);

	set_bit(IEEE80211_STA_REQ_RUN, &ifsta->request);
	//queue_work(local->hw.workqueue, &ifsta->work);
	//set_bit(IEEE80211_STA_REQ_SCAN, &ifsta->request);//hack
	queue_te(ifsta->work.number,(thread_call_func_t)ifsta->work.func,sdata,NULL,true);
}

void ieee80211_if_set_type(struct net_device *dev, int type)
{
IM_HERE_NOW();
	struct ieee80211_sub_if_data *sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	int oldtype = sdata->type;

	//dev->hard_start_xmit = ieee80211_subif_start_xmit;

	sdata->type = type;
	switch (type) {
	case IEEE80211_IF_TYPE_WDS:
		sdata->bss = NULL;
		break;
	case IEEE80211_IF_TYPE_VLAN:
		break;
	case IEEE80211_IF_TYPE_AP:
		sdata->u.ap.dtim_period = 2;
		sdata->u.ap.force_unicast_rateidx = -1;
		sdata->u.ap.max_ratectrl_rateidx = -1;
		skb_queue_head_init(&sdata->u.ap.ps_bc_buf);
		sdata->bss = &sdata->u.ap;
		break;
	case IEEE80211_IF_TYPE_STA:
	case IEEE80211_IF_TYPE_IBSS: {
		struct ieee80211_sub_if_data *msdata;
		struct ieee80211_if_sta *ifsta;

		ifsta = &sdata->u.sta;
		INIT_WORK(&ifsta->work, ieee80211_sta_work, 12);
		setup_timer(&ifsta->timer, ieee80211_sta_timer,(unsigned long) sdata);

		skb_queue_head_init(&ifsta->skb_queue);

		ifsta->capab = WLAN_CAPABILITY_ESS;
		ifsta->auth_algs = IEEE80211_AUTH_ALG_OPEN |
			IEEE80211_AUTH_ALG_SHARED_KEY;
		ifsta->create_ibss = 1;
		ifsta->wmm_enabled = 1;
		ifsta->auto_channel_sel = 1;
		ifsta->auto_bssid_sel = 1;

		msdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(sdata->local->mdev);
		sdata->bss = &msdata->u.ap;
		break;
	}
	case IEEE80211_IF_TYPE_MNTR:
		dev->type = ARPHRD_IEEE80211_RADIOTAP;
		//dev->hard_start_xmit = ieee80211_monitor_start_xmit;
		break;
	default:
		printk(KERN_WARNING "%s: %s: Unknown interface type 0x%x",
		       dev->name, __FUNCTION__, type);
	}
	//ieee80211_debugfs_change_if_type(sdata, oldtype);
	//ieee80211_update_default_wep_only(local);
}

int ieee80211_if_add(struct net_device *dev, const char *name,
		     struct net_device **new_dev, int type)
{
IM_HERE_NOW();	

	struct net_device *ndev;
	struct ieee80211_local *local =  wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata = NULL;
	int ret;

	//ASSERT_RTNL();
	ndev = alloc_netdev(sizeof(struct ieee80211_sub_if_data),
			    name, NULL);//ieee80211_if_setup);
	if (!ndev)
		return -ENOMEM;

	//char ii[4]="en1";
	//sprintf(ii,"%s%d" ,my_fNetif->getNamePrefix(), my_fNetif->getUnitNumber());
	//bcopy(ii,ndev->name,sizeof(ii));
	
	/*ret = dev_alloc_name(ndev, ndev->name);
	if (ret < 0)
		goto fail;*/

	memcpy(ndev->dev_addr, my_mac_addr, ETH_ALEN);//local->hw.wiphy->perm_addr, ETH_ALEN);
	ndev->base_addr = dev->base_addr;
	ndev->irq = dev->irq;
	ndev->mem_start = dev->mem_start;
	ndev->mem_end = dev->mem_end;
	ndev->ifindex=2;//hack
	//SET_NETDEV_DEV(ndev, wiphy_dev(local->hw.wiphy));

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(ndev);
	
	ndev->ieee80211_ptr = hw_to_local(my_hw);//&sdata->wdev;
	//sdata->wdev.wiphy = local->hw.wiphy;
	sdata->type = IEEE80211_IF_TYPE_AP;
	sdata->dev = ndev;
	sdata->local = local;
	ieee80211_if_sdata_init(sdata);

	/*ret = register_netdevice(ndev);
	if (ret)
		goto fail;*/

	//ieee80211_debugfs_add_netdev(sdata);
	ieee80211_if_set_type(ndev, type);

	ieee80211_open(ndev);
	//write_lock_bh(&local->sub_if_lock);
	//if (unlikely(local->reg_state == IEEE80211_DEV_UNREGISTERED)) {
	if (unlikely(local->reg_state == 0)) {
		//write_unlock_bh(&local->sub_if_lock);
		//__ieee80211_if_del(local, sdata);
		//return 0;//-ENODEV;
	}
	IOLog("listadd\n");
	list_add(&sdata->list, &local->sub_if_list);
	if (new_dev)
		*new_dev = ndev;
	//write_unlock_bh(&local->sub_if_lock);

	//ieee80211_update_default_wep_only(local);
	local->scan_dev=ndev;
	return 0;

fail:
	//free_netdev(ndev);
	return ret;
}

static struct rate_control_ops *
ieee80211_try_rate_control_ops_get(const char *name)
{
	struct rate_control_alg *alg;
	struct rate_control_ops *ops = NULL;
IM_HERE_NOW();
	//mutex_lock(&rate_ctrl_mutex);
	list_for_each_entry(alg, &rate_ctrl_algs, list) {
		if (!name || !strcmp(alg->ops->name, name))
			/*if (try_module_get(alg->ops->module)) {
				ops = alg->ops;
				break;
			}*/
			ops = alg->ops;
	}
	//mutex_unlock(&rate_ctrl_mutex);
	return ops;
}

static struct rate_control_ops *
ieee80211_rate_control_ops_get(const char *name)
{
	struct rate_control_ops *ops;
IM_HERE_NOW();
	ops = ieee80211_try_rate_control_ops_get(name);
	if (!ops) {
		//request_module("rc80211_%s", name ? name : "default");
		//rate_control_simple_init();
		ops = ieee80211_try_rate_control_ops_get(name);
	}
	return ops;
}

struct rate_control_ref *rate_control_alloc(const char *name,
					    struct ieee80211_local *local)
{
IM_HERE_NOW();
	struct rate_control_ref *ref;

	ref = (struct rate_control_ref*)kmalloc(sizeof(struct rate_control_ref), GFP_KERNEL);
	if (!ref)
		goto fail_ref;
	kref_init(&ref->kref);
	ref->ops = ieee80211_rate_control_ops_get(name);
	if (!ref->ops)
		goto fail_ops;
	ref->priv = ref->ops->alloc(local);
	if (!ref->priv)
		goto fail_priv;
	return ref;

fail_priv:
	//ieee80211_rate_control_ops_put(ref->ops);
fail_ops:
	kfree(ref);
fail_ref:
	return NULL;
}

static void sta_info_hash_del(struct ieee80211_local *local,
			      struct sta_info *sta)
{
IM_HERE_NOW();
	struct sta_info *s;

	s = local->sta_hash[STA_HASH(sta->addr)];
	if (!s)
		return;
	if (memcmp(s->addr, sta->addr, ETH_ALEN) == 0) {
		local->sta_hash[STA_HASH(sta->addr)] = s->hnext;
		return;
	}

	while (s->hnext && memcmp(s->hnext->addr, sta->addr, ETH_ALEN) != 0)
		s = s->hnext;
	if (s->hnext)
		s->hnext = s->hnext->hnext;
	else
		printk(KERN_ERR "%s: could not remove STA " MAC_FMT " from "
		       "hash table\n", local->mdev->name, MAC_ARG(sta->addr));
}


static inline void __bss_tim_clear(struct ieee80211_if_ap *bss, int aid)
{
IM_HERE_NOW();	
	/*
	 * This format has ben mandated by the IEEE specifications,
	 * so this line may not be changed to use the __clear_bit() format.
	 */
	bss->tim[(aid)/8] &= !(1<<((aid) % 8));
}

void sta_info_remove_aid_ptr(struct sta_info *sta)
{
IM_HERE_NOW();
	struct ieee80211_sub_if_data *sdata;

	if (sta->aid <= 0)
		return;

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(sta->dev);

	if (sdata->local->ops->set_tim)
		sdata->local->ops->set_tim(local_to_hw(sdata->local),
					  sta->aid, 0);
	if (sdata->bss)
		__bss_tim_clear(sdata->bss, sta->aid);
}

static void sta_info_remove(struct sta_info *sta)
{
IM_HERE_NOW();
	struct ieee80211_local *local = sta->local;
	struct ieee80211_sub_if_data *sdata;

	sta_info_hash_del(local, sta);
	list_del(&sta->list);
	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(sta->dev);
	if (sta->flags & WLAN_STA_PS) {
		sta->flags &= ~WLAN_STA_PS;
		if (sdata->bss)
			atomic_dec(&sdata->bss->num_sta_ps);
	}
	local->num_sta--;
	sta_info_remove_aid_ptr(sta);
}

static void finish_sta_info_free(struct ieee80211_local *local,
				 struct sta_info *sta)
{
IM_HERE_NOW();
#ifdef CONFIG_MAC80211_VERBOSE_DEBUG
	printk(KERN_DEBUG "%s: Removed STA " MAC_FMT "\n",
	       local->mdev->name, MAC_ARG(sta->addr));
#endif /* CONFIG_MAC80211_VERBOSE_DEBUG */

	/*if (sta->key) {
		ieee80211_debugfs_key_remove(sta->key);
		ieee80211_key_free(sta->key);
		sta->key = NULL;
	}*/

	//rate_control_remove_sta_debugfs(sta);
	//ieee80211_sta_debugfs_remove(sta);

	sta_info_put(sta);
}

void sta_info_free(struct sta_info *sta, int locked)
{
IM_HERE_NOW();
	struct sk_buff *skb;
	struct ieee80211_local *local = sta->local;

	if (!locked) {
		spin_lock_bh(&local->sta_lock);
		sta_info_remove(sta);
		spin_unlock_bh(&local->sta_lock);
	} else {
		sta_info_remove(sta);
	}
	if (local->ops->sta_table_notification)
		local->ops->sta_table_notification(local_to_hw(local),
						  local->num_sta);

	while ((skb = skb_dequeue(&sta->ps_tx_buf)) != NULL) {
		local->total_ps_buffered--;
		dev_kfree_skb_any(skb);
	}
	while ((skb = skb_dequeue(&sta->tx_filtered)) != NULL) {
		dev_kfree_skb_any(skb);
	}

	/*if (sta->key) {
		if (local->ops->set_key) {
			struct ieee80211_key_conf *key;
			key = ieee80211_key_data2conf(local, sta->key);
			if (key) {
				local->ops->set_key(local_to_hw(local),
						   DISABLE_KEY,
						   sta->addr, key, sta->aid);
				kfree(key);
			}
		}
	} else if (sta->key_idx_compression != HW_KEY_IDX_INVALID) {
		struct ieee80211_key_conf conf;
		memset(&conf, 0, sizeof(conf));
		conf.hw_key_idx = sta->key_idx_compression;
		conf.alg = ALG_NULL;
		conf.flags |= IEEE80211_KEY_FORCE_SW_ENCRYPT;
		local->ops->set_key(local_to_hw(local), DISABLE_KEY,
				   sta->addr, &conf, sta->aid);
		sta->key_idx_compression = HW_KEY_IDX_INVALID;
	}*/
/*
#ifdef CONFIG_MAC80211_DEBUGFS
	if (in_atomic()) {
		list_add(&sta->list, &local->deleted_sta_list);
		queue_work(local->hw.workqueue, &local->sta_debugfs_add);
	} else
#endif
*/
		finish_sta_info_free(local, sta);
}

void sta_info_flush(struct ieee80211_local *local, struct net_device *dev)
{
IM_HERE_NOW();
	struct sta_info *sta, *tmp;

	spin_lock_bh(&local->sta_lock);
	list_for_each_entry_safe(sta, tmp, &local->sta_list, list)
		if (!dev || dev == sta->dev)
			sta_info_free(sta, 1);
	spin_unlock_bh(&local->sta_lock);
}

int ieee80211_init_rate_ctrl_alg(struct ieee80211_local *local,
				 const char *name)
{
IM_HERE_NOW();
	struct rate_control_ref *ref, *old;

	//ASSERT_RTNL();
	if (local->open_count || netif_running(local->mdev) ||
	    (local->apdev && netif_running(local->apdev)))
		return -EBUSY;

	ref = rate_control_alloc(name, local);
	if (!ref) {
		printk(KERN_WARNING "%s: Failed to select rate control "
		       "algorithm\n", local->mdev->name);
		return -ENOENT;
	}

	old = local->rate_ctrl;
	local->rate_ctrl = ref;
	if (old) {
		rate_control_put(old);
		sta_info_flush(local, NULL);
	}

	printk(KERN_DEBUG "%s: Selected rate control "
	       "algorithm '%s'\n", local->mdev->name,
	       ref->ops->name);


	return 0;
}

static int ieee80211_regdom = 0x10; /* FCC */
static int ieee80211_japan_5ghz /* = 0 */;
struct ieee80211_channel_range {
	short start_freq;
	short end_freq;
	unsigned char power_level;
	unsigned char antenna_max;
};
static const struct ieee80211_channel_range ieee80211_fcc_channels[] = {
	{ 2412, 2462, 27, 6 } /* IEEE 802.11b/g, channels 1..11 */,
	{ 5180, 5240, 17, 6 } /* IEEE 802.11a, channels 36..48 */,
	{ 5260, 5320, 23, 6 } /* IEEE 802.11a, channels 52..64 */,
	{ 5745, 5825, 30, 6 } /* IEEE 802.11a, channels 149..165, outdoor */,
	{ 0 }
};

static const struct ieee80211_channel_range *channel_range =	ieee80211_fcc_channels;

static void ieee80211_unmask_channel(int mode, struct ieee80211_channel *chan)
{
	int i;

	chan->flag = 0;

	if (ieee80211_regdom == 64 &&
	    (mode == MODE_ATHEROS_TURBO || mode == MODE_ATHEROS_TURBOG)) {
		/* Do not allow Turbo modes in Japan. */
		return;
	}

	for (i = 0; channel_range[i].start_freq; i++) {
		const struct ieee80211_channel_range *r = &channel_range[i];
		if (r->start_freq <= chan->freq && r->end_freq >= chan->freq) {
			if (ieee80211_regdom == 64 && !ieee80211_japan_5ghz &&
			    chan->freq >= 5260 && chan->freq <= 5320) {
				/*
				 * Skip new channels in Japan since the
				 * firmware was not marked having been upgraded
				 * by the vendor.
				 */
				continue;
			}

			if (ieee80211_regdom == 0x10 &&
			    (chan->freq == 5190 || chan->freq == 5210 ||
			     chan->freq == 5230)) {
				    /* Skip MKK channels when in FCC domain. */
				    continue;
			}

			chan->flag |= IEEE80211_CHAN_W_SCAN |
				IEEE80211_CHAN_W_ACTIVE_SCAN |
				IEEE80211_CHAN_W_IBSS;
			chan->power_level = r->power_level;
			chan->antenna_max = r->antenna_max;

			if (ieee80211_regdom == 64 &&
			    (chan->freq == 5170 || chan->freq == 5190 ||
			     chan->freq == 5210 || chan->freq == 5230)) {
				/*
				 * New regulatory rules in Japan have backwards
				 * compatibility with old channels in 5.15-5.25
				 * GHz band, but the station is not allowed to
				 * use active scan on these old channels.
				 */
				chan->flag &= ~IEEE80211_CHAN_W_ACTIVE_SCAN;
			}

			if (ieee80211_regdom == 64 &&
			    (chan->freq == 5260 || chan->freq == 5280 ||
			     chan->freq == 5300 || chan->freq == 5320)) {
				/*
				 * IBSS is not allowed on 5.25-5.35 GHz band
				 * due to radar detection requirements.
				 */
				chan->flag &= ~IEEE80211_CHAN_W_IBSS;
			}

			break;
		}
	}
}


void ieee80211_set_default_regdomain(struct ieee80211_hw_mode *mode)
{
	int c;
	for (c = 0; c < mode->num_channels; c++)
		ieee80211_unmask_channel(mode->mode, &mode->channels[c]);
}

#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })
int ieee80211_register_hw (	struct ieee80211_hw *  	hw){
IM_HERE_NOW();	
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
	if (result < 0) return -1;
	//	goto fail_sta_info;

	//char ii[4]="en1";
	//sprintf(ii,"%s%d" ,my_fNetif->getNamePrefix(), my_fNetif->getUnitNumber());
	//bcopy(ii,local->mdev->name,sizeof(ii));
	/*rtnl_lock();
	result = dev_alloc_name(local->mdev, local->mdev->name);
	if (result < 0)
		goto fail_dev;*/

	memcpy(local->mdev->dev_addr, my_mac_addr, ETH_ALEN);//local->hw.wiphy->perm_addr, ETH_ALEN); //check this
	//SET_NETDEV_DEV(local->mdev, wiphy_dev(local->hw.wiphy));

	/*result = register_netdevice(local->mdev);
	if (result < 0)
		goto fail_dev;

	ieee80211_debugfs_add_netdev(IEEE80211_DEV_TO_SUB_IF(local->mdev));*/


	
	result = ieee80211_init_rate_ctrl_alg(local, NULL);
	if (result < 0) {
		printk(KERN_DEBUG "%s: Failed to initialize rate control "
		       "algorithm\n", local->mdev->name);
		//goto fail_rate;
	}
//this one maybe
/*	result = ieee80211_wep_init(local);

	if (result < 0) {
		printk(KERN_DEBUG "%s: Failed to initialize wep\n",
		       local->mdev->name);
		goto fail_wep;
	}*/

	//ieee80211_install_qdisc(local->mdev);

	/* add one default STA interface */
	result = ieee80211_if_add(local->mdev, local->mdev->name, NULL,
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
IM_HERE_NOW();	
	return;
}
void ieee80211_start_queues(struct ieee80211_hw *hw){
IM_HERE_NOW();	
    struct ieee80211_local *local = hw_to_local(hw);
    int i;
    
    for (i = 0; i < local->hw.queues; i++)
        clear_bit(IEEE80211_LINK_STATE_XOFF, &local->state[i]);
}



typedef enum { ParseOK = 0, ParseUnknown = 1, ParseFailed = -1 } ParseRes;


static ParseRes ieee802_11_parse_elems(u8 *start, size_t len,
				       struct ieee802_11_elems *elems)
{
IM_HERE_NOW();	
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
IM_HERE_NOW();	
	struct ieee80211_local *local =  wdev_priv(dev->ieee80211_ptr);
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
IM_HERE_NOW();	
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	bss->hnext = local->sta_bss_hash[STA_HASH(bss->bssid)];
	local->sta_bss_hash[STA_HASH(bss->bssid)] = bss;
}


static struct ieee80211_sta_bss *
ieee80211_rx_bss_add(struct net_device *dev, u8 *bssid)
{
IM_HERE_NOW();	
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *bss;

	bss = (ieee80211_sta_bss*)kzalloc(sizeof(*bss), GFP_ATOMIC);
	if (!bss)
		return NULL;
	atomic_inc(&bss->users);
	//atomic_inc(&bss->users);//hack
	memcpy(bss->bssid, bssid, ETH_ALEN);

	spin_lock_bh(&local->sta_bss_lock);
	/* TODO: order by RSSI? */
	list_add_tail(&bss->list, &local->sta_bss_list);
	__ieee80211_rx_bss_hash_add(dev, bss);
	spin_unlock_bh(&local->sta_bss_lock);
	
	printk("bss_add= " MAC_FMT " ('%s')\n", MAC_ARG(bss->bssid),
		escape_essid((const char*)bss->ssid, bss->ssid_len));
		
	return bss;
}

/* Caller must hold local->sta_bss_lock */
static void __ieee80211_rx_bss_hash_del(struct net_device *dev,
					struct ieee80211_sta_bss *bss)
{
IM_HERE_NOW();	
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
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
IM_HERE_NOW();	
	kfree(bss->wpa_ie);
	kfree(bss->rsn_ie);
	kfree(bss->wmm_ie);
	kfree(bss);
}

static void ieee80211_rx_bss_put(struct net_device *dev,
				 struct ieee80211_sta_bss *bss)
{
IM_HERE_NOW();	
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
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
IM_HERE_NOW();	
	struct ieee80211_local *local =  wdev_priv(dev->ieee80211_ptr);
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
	/*if (!beacon)
	{
		IOLog("hacking add station\n");
		struct ieee80211_if_sta *ifsta = &sdata->u.sta;
		bcopy(mgmt->sa,sdata->u.sta.bssid,ETH_ALEN);
	}*/
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
	} else if (elems.wmm_info &&
	 (!bss->wmm_ie || bss->wmm_ie_len != elems.wmm_info_len ||
	 memcmp(bss->wmm_ie, elems.wmm_info, elems.wmm_info_len))) {
	 /* As for certain AP's Fifth bit is not set in WMM IE in
	 * beacon frames.So while parsing the beacon frame the
	 * wmm_info structure is used instead of wmm_param.
	 * wmm_info structure was never used to set bss->wmm_ie.
	 * This code fixes this problem by copying the WME
	 * information from wmm_info to bss->wmm_ie and enabling
	 * n-band association.
	 */
	 kfree(bss->wmm_ie);
	 bss->wmm_ie = (u8*)kmalloc(elems.wmm_info_len + 2, GFP_ATOMIC);
	 if (bss->wmm_ie) {
	 memcpy(bss->wmm_ie, elems.wmm_info - 2,
	 elems.wmm_info_len + 2);
	 bss->wmm_ie_len = elems.wmm_info_len + 2;
	 } else
	 bss->wmm_ie_len = 0;
	} else if (!elems.wmm_param && !elems.wmm_info && bss->wmm_ie) {
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
IM_HERE_NOW();	
	ieee80211_rx_bss_info(dev, mgmt, len, rx_status, 0);
	/*struct ieee80211_sub_if_data *sdata = (ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;
	if (ifsta->state != IEEE80211_AUTHENTICATE &&
	    ifsta->state != IEEE80211_ASSOCIATE &&
	    ifsta->state != IEEE80211_ASSOCIATED)
		ieee80211_sta_config_auth(dev, ifsta);*/
}

static void ieee80211_handle_erp_ie(struct net_device *dev, u8 erp_value)
{
IM_HERE_NOW();	
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
IM_HERE_NOW();	
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
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
IM_HERE_NOW();	
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_sta *ifsta;
	size_t baselen;
	struct ieee802_11_elems elems;

	ieee80211_rx_bss_info(dev, mgmt, len, rx_status, 1);

	sdata = (ieee80211_sub_if_data *)IEEE80211_DEV_TO_SUB_IF(dev);
	if (sdata->type != IEEE80211_IF_TYPE_STA) return;
		
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
IM_HERE_NOW();	
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

static void ieee80211_send_auth(struct net_device *dev,
				struct ieee80211_if_sta *ifsta,
				int transaction, u8 *extra, size_t extra_len,
				int encrypt)
{
IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom +
			    sizeof(*mgmt) + 6 + extra_len);
	if (!skb) {
		printk(KERN_DEBUG "%s: failed to allocate buffer for auth "
		       "frame\n", dev->name);
		return;
	}
	skb_reserve(skb, local->hw.extra_tx_headroom);

	mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24 + 6);
	memset(mgmt, 0, 24 + 6);
	mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
					   IEEE80211_STYPE_AUTH);
	if (encrypt)
		mgmt->frame_control |= cpu_to_le16(IEEE80211_FCTL_PROTECTED);
	memcpy(mgmt->da, ifsta->bssid, ETH_ALEN);
	memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
	memcpy(mgmt->bssid, ifsta->bssid, ETH_ALEN);
	mgmt->u.auth.auth_alg = cpu_to_le16(ifsta->auth_alg);
	mgmt->u.auth.auth_transaction = cpu_to_le16(transaction);
	ifsta->auth_transaction = transaction + 1;
	mgmt->u.auth.status_code = cpu_to_le16(0);
	if (extra)
		memcpy(skb_put(skb, extra_len), extra, extra_len);

	ieee80211_sta_tx(dev, skb, encrypt);
}

static int ieee80211_sta_wep_configured(struct net_device *dev)
{
IM_HERE_NOW();
	struct ieee80211_sub_if_data *sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	if (!sdata || !sdata->default_key ||
	    sdata->default_key->alg != ALG_WEP)
		return 0;
	return 1;
}

static int ieee80211_privacy_mismatch(struct net_device *dev,
				      struct ieee80211_if_sta *ifsta)
{
IM_HERE_NOW();
	struct ieee80211_sta_bss *bss;
	int res = 0;

	if (!ifsta || ifsta->mixed_cell ||
	    ifsta->key_mgmt != IEEE80211_KEY_MGMT_NONE)
		return 0;

	bss = ieee80211_rx_bss_get(dev, ifsta->bssid);
	if (!bss)
		return 0;

	if (ieee80211_sta_wep_configured(dev) !=
	    !!(bss->capability & WLAN_CAPABILITY_PRIVACY))
		res = 1;

	ieee80211_rx_bss_put(dev, bss);

	return res;
}

static void ieee80211_send_assoc(struct net_device *dev,
				 struct ieee80211_if_sta *ifsta)
{
IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_hw_mode *mode;
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;
	u8 *pos, *ies;
	int i, len;
	u16 capab;
	struct ieee80211_sta_bss *bss;
	int wmm = 0;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom +
			    sizeof(*mgmt) + 200 + ifsta->extra_ie_len +
			    ifsta->ssid_len);
	if (!skb) {
		printk(KERN_DEBUG "%s: failed to allocate buffer for assoc "
		       "frame\n", dev->name);
		return;
	}
	skb_reserve(skb, local->hw.extra_tx_headroom);

	mode = local->oper_hw_mode;
	capab = ifsta->capab;
	if (mode->mode == MODE_IEEE80211G) {
		capab |= WLAN_CAPABILITY_SHORT_SLOT_TIME |
			WLAN_CAPABILITY_SHORT_PREAMBLE;
	}
	bss = ieee80211_rx_bss_get(dev, ifsta->bssid);
	if (bss) {
		if (bss->capability & WLAN_CAPABILITY_PRIVACY)
			capab |= WLAN_CAPABILITY_PRIVACY;
		if (bss->wmm_ie) {
			wmm = 1;
		}
		ieee80211_rx_bss_put(dev, bss);
	}

	mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24);
	memset(mgmt, 0, 24);
	memcpy(mgmt->da, ifsta->bssid, ETH_ALEN);
	memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
	memcpy(mgmt->bssid, ifsta->bssid, ETH_ALEN);

	if (ifsta->prev_bssid_set) {
		skb_put(skb, 10);
		mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
						   IEEE80211_STYPE_REASSOC_REQ);
		mgmt->u.reassoc_req.capab_info = cpu_to_le16(capab);
		mgmt->u.reassoc_req.listen_interval = cpu_to_le16(1);
		memcpy(mgmt->u.reassoc_req.current_ap, ifsta->prev_bssid,
		       ETH_ALEN);
	} else {
		skb_put(skb, 4);
		mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
						   IEEE80211_STYPE_ASSOC_REQ);
		mgmt->u.assoc_req.capab_info = cpu_to_le16(capab);
		mgmt->u.assoc_req.listen_interval = cpu_to_le16(1);
	}

	/* SSID */
	ies = pos = (u8*)skb_put(skb, 2 + ifsta->ssid_len);
	*pos++ = WLAN_EID_SSID;
	*pos++ = ifsta->ssid_len;
	memcpy(pos, ifsta->ssid, ifsta->ssid_len);

	len = mode->num_rates;
	if (len > 8)
		len = 8;
	pos = (u8*)skb_put(skb, len + 2);
	*pos++ = WLAN_EID_SUPP_RATES;
	*pos++ = len;
	for (i = 0; i < len; i++) {
		int rate = mode->rates[i].rate;
		if (mode->mode == MODE_ATHEROS_TURBO)
			rate /= 2;
		*pos++ = (u8) (rate / 5);
	}

	if (mode->num_rates > len) {
		pos = (u8*)skb_put(skb, mode->num_rates - len + 2);
		*pos++ = WLAN_EID_EXT_SUPP_RATES;
		*pos++ = mode->num_rates - len;
		for (i = len; i < mode->num_rates; i++) {
			int rate = mode->rates[i].rate;
			if (mode->mode == MODE_ATHEROS_TURBO)
				rate /= 2;
			*pos++ = (u8) (rate / 5);
		}
	}

	if (ifsta->extra_ie) {
		pos = (u8*)skb_put(skb, ifsta->extra_ie_len);
		memcpy(pos, ifsta->extra_ie, ifsta->extra_ie_len);
	}

	if (wmm && ifsta->wmm_enabled) {
		pos = (u8*)skb_put(skb, 9);
		*pos++ = WLAN_EID_VENDOR_SPECIFIC;
		*pos++ = 7; /* len */
		*pos++ = 0x00; /* Microsoft OUI 00:50:F2 */
		*pos++ = 0x50;
		*pos++ = 0xf2;
		*pos++ = 2; /* WME */
		*pos++ = 0; /* WME info */
		*pos++ = 1; /* WME ver */
		*pos++ = 0;
	}

	kfree(ifsta->assocreq_ies);
	ifsta->assocreq_ies_len = ((u8*)skb_data(skb) + mbuf_len(skb->mac_data)) - ies;
	ifsta->assocreq_ies = (u8*)kmalloc(ifsta->assocreq_ies_len, GFP_ATOMIC);
	if (ifsta->assocreq_ies)
		memcpy(ifsta->assocreq_ies, ies, ifsta->assocreq_ies_len);

	ieee80211_sta_tx(dev, skb, 0);
}

void ieee80211_associate(struct net_device *dev,
				struct ieee80211_if_sta *ifsta)
{
IM_HERE_NOW();
	ifsta->assoc_tries++;
	if (ifsta->assoc_tries > IEEE80211_ASSOC_MAX_TRIES) {
		printk(KERN_DEBUG "%s: association with AP " MAC_FMT
		       " timed out\n",
		       dev->name, MAC_ARG(ifsta->bssid));
		ifsta->state = IEEE80211_DISABLED;
		//ifsta->assoc_tries=0;//hack
		//del_timer(&ifsta->timer);//hack
		return;
	}

	ifsta->state = IEEE80211_ASSOCIATE;
	printk(KERN_DEBUG "%s: associate with AP " MAC_FMT "\n",
	       dev->name, MAC_ARG(ifsta->bssid));
	if (ieee80211_privacy_mismatch(dev, ifsta)) {
		printk(KERN_DEBUG "%s: mismatch in privacy configuration and "
		       "mixed-cell disabled - abort association\n", dev->name);
		ifsta->state = IEEE80211_DISABLED;
		return;
	}

	ieee80211_send_assoc(dev, ifsta);

	mod_timer(&ifsta->timer, IEEE80211_ASSOC_TIMEOUT);
}

static void ieee80211_auth_completed(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta)
{
IM_HERE_NOW();
	printk(KERN_DEBUG "%s: authenticated\n", dev->name);
	ifsta->authenticated = 1;
	ieee80211_associate(dev, ifsta);
}

static void ieee80211_auth_challenge(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta,
				     struct ieee80211_mgmt *mgmt,
				     size_t len)
{
	IM_HERE_NOW();
	u8 *pos;
	struct ieee802_11_elems elems;

	printk(KERN_DEBUG "%s: replying to auth challenge\n", dev->name);
	pos = mgmt->u.auth.variable;
	if (ieee802_11_parse_elems(pos, len - (pos - (u8 *) mgmt), &elems)
	    == ParseFailed) {
		printk(KERN_DEBUG "%s: failed to parse Auth(challenge)\n",
		       dev->name);
		return;
	}
	if (!elems.challenge) {
		printk(KERN_DEBUG "%s: no challenge IE in shared key auth "
		       "frame\n", dev->name);
		return;
	}
	ieee80211_send_auth(dev, ifsta, 3, elems.challenge - 2,
			    elems.challenge_len + 2, 1);
}

static void ieee80211_rx_mgmt_auth(struct net_device *dev,
				   struct ieee80211_if_sta *ifsta,
				   struct ieee80211_mgmt *mgmt,
				   size_t len)
{
IM_HERE_NOW();
	struct ieee80211_sub_if_data *sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	u16 auth_alg, auth_transaction, status_code;

	if (ifsta->state != IEEE80211_AUTHENTICATE &&
	    sdata->type != IEEE80211_IF_TYPE_IBSS) {
		printk(KERN_DEBUG "%s: authentication frame received from "
		       MAC_FMT ", but not in authenticate state - ignored\n",
		       dev->name, MAC_ARG(mgmt->sa));
		return;
	}

	if (len < 24 + 6) {
		printk(KERN_DEBUG "%s: too short (%zd) authentication frame "
		       "received from " MAC_FMT " - ignored\n",
		       dev->name, len, MAC_ARG(mgmt->sa));
		return;
	}

	if (sdata->type != IEEE80211_IF_TYPE_IBSS &&
	    memcmp(ifsta->bssid, mgmt->sa, ETH_ALEN) != 0) {
		printk(KERN_DEBUG "%s: authentication frame received from "
		       "unknown AP (SA=" MAC_FMT " BSSID=" MAC_FMT ") - "
		       "ignored\n", dev->name, MAC_ARG(mgmt->sa),
		       MAC_ARG(mgmt->bssid));
		return;
	}

	if (sdata->type != IEEE80211_IF_TYPE_IBSS &&
	    memcmp(ifsta->bssid, mgmt->bssid, ETH_ALEN) != 0) {
		printk(KERN_DEBUG "%s: authentication frame received from "
		       "unknown BSSID (SA=" MAC_FMT " BSSID=" MAC_FMT ") - "
		       "ignored\n", dev->name, MAC_ARG(mgmt->sa),
		       MAC_ARG(mgmt->bssid));
		return;
	}

	auth_alg = le16_to_cpu(mgmt->u.auth.auth_alg);
	auth_transaction = le16_to_cpu(mgmt->u.auth.auth_transaction);
	status_code = le16_to_cpu(mgmt->u.auth.status_code);

	printk(KERN_DEBUG "%s: RX authentication from " MAC_FMT " (alg=%d "
	       "transaction=%d status=%d)\n",
	       dev->name, MAC_ARG(mgmt->sa), auth_alg,
	       auth_transaction, status_code);

	if (sdata->type == IEEE80211_IF_TYPE_IBSS) {
		/* IEEE 802.11 standard does not require authentication in IBSS
		 * networks and most implementations do not seem to use it.
		 * However, try to reply to authentication attempts if someone
		 * has actually implemented this.
		 * TODO: Could implement shared key authentication. */
		if (auth_alg != WLAN_AUTH_OPEN || auth_transaction != 1) {
			printk(KERN_DEBUG "%s: unexpected IBSS authentication "
			       "frame (alg=%d transaction=%d)\n",
			       dev->name, auth_alg, auth_transaction);
			return;
		}
		ieee80211_send_auth(dev, ifsta, 2, NULL, 0, 0);
	}

	if (auth_alg != ifsta->auth_alg ||
	    auth_transaction != ifsta->auth_transaction) {
		printk(KERN_DEBUG "%s: unexpected authentication frame "
		       "(alg=%d transaction=%d)\n",
		       dev->name, auth_alg, auth_transaction);
		return;
	}

	if (status_code != WLAN_STATUS_SUCCESS) {
		printk(KERN_DEBUG "%s: AP denied authentication (auth_alg=%d "
		       "code=%d)\n", dev->name, ifsta->auth_alg, status_code);
		if (status_code == WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG) {
			u8 algs[3];
			const int num_algs = ARRAY_SIZE(algs);
			int i, pos;
			algs[0] = algs[1] = algs[2] = 0xff;
			if (ifsta->auth_algs & IEEE80211_AUTH_ALG_OPEN)
				algs[0] = WLAN_AUTH_OPEN;
			if (ifsta->auth_algs & IEEE80211_AUTH_ALG_SHARED_KEY)
				algs[1] = WLAN_AUTH_SHARED_KEY;
			if (ifsta->auth_algs & IEEE80211_AUTH_ALG_LEAP)
				algs[2] = WLAN_AUTH_LEAP;
			if (ifsta->auth_alg == WLAN_AUTH_OPEN)
				pos = 0;
			else if (ifsta->auth_alg == WLAN_AUTH_SHARED_KEY)
				pos = 1;
			else
				pos = 2;
			for (i = 0; i < num_algs; i++) {
				pos++;
				if (pos >= num_algs)
					pos = 0;
				if (algs[pos] == ifsta->auth_alg ||
				    algs[pos] == 0xff)
					continue;
				if (algs[pos] == WLAN_AUTH_SHARED_KEY &&
				    !ieee80211_sta_wep_configured(dev))
					continue;
				ifsta->auth_alg = algs[pos];
				printk(KERN_DEBUG "%s: set auth_alg=%d for "
				       "next try\n",
				       dev->name, ifsta->auth_alg);
				break;
			}
		}
		return;
	}

	switch (ifsta->auth_alg) {
	case WLAN_AUTH_OPEN:
	case WLAN_AUTH_LEAP:
		ieee80211_auth_completed(dev, ifsta);
		break;
	case WLAN_AUTH_SHARED_KEY:
		if (ifsta->auth_transaction == 4)
			ieee80211_auth_completed(dev, ifsta);
		else
			ieee80211_auth_challenge(dev, ifsta, mgmt, len);
		break;
	}
}

static void ieee80211_sta_send_associnfo(struct net_device *dev,
					 struct ieee80211_if_sta *ifsta)
{
IM_HERE_NOW();
	char *buf;
	size_t len;
	int i;
	//union iwreq_data wrqu;

	if (!ifsta->assocreq_ies && !ifsta->assocresp_ies)
		return;

	buf = (char*)kmalloc(50 + 2 * (ifsta->assocreq_ies_len +
				ifsta->assocresp_ies_len), GFP_ATOMIC);
	if (!buf)
		return;

	len = sprintf(buf, "ASSOCINFO(");
	if (ifsta->assocreq_ies) {
		len += sprintf(buf + len, "ReqIEs=");
		for (i = 0; i < ifsta->assocreq_ies_len; i++) {
			len += sprintf(buf + len, "%02x",
				       ifsta->assocreq_ies[i]);
		}
	}
	if (ifsta->assocresp_ies) {
		if (ifsta->assocreq_ies)
			len += sprintf(buf + len, " ");
		len += sprintf(buf + len, "RespIEs=");
		for (i = 0; i < ifsta->assocresp_ies_len; i++) {
			len += sprintf(buf + len, "%02x",
				       ifsta->assocresp_ies[i]);
		}
	}
	len += sprintf(buf + len, ")");

	if (len > IW_CUSTOM_MAX) {
		len = sprintf(buf, "ASSOCRESPIE=");
		for (i = 0; i < ifsta->assocresp_ies_len; i++) {
			len += sprintf(buf + len, "%02x",
				       ifsta->assocresp_ies[i]);
		}
	}

	//memset(&wrqu, 0, sizeof(wrqu));
	//wrqu.data.length = len;
	//wireless_send_event(dev, IWEVCUSTOM, &wrqu, buf);

	kfree(buf);
}

static void ieee80211_set_associated(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta, int assoc)
{
IM_HERE_NOW();
	//union iwreq_data wrqu;
	struct ieee80211_sub_if_data *sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);

	if (ifsta->associated == assoc)
		return;

	ifsta->associated = assoc;

	if (assoc) {
		struct ieee80211_sub_if_data *sdata;
		struct ieee80211_sta_bss *bss;
		sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
		if (sdata->type != IEEE80211_IF_TYPE_STA)
			return;

		bss = ieee80211_rx_bss_get(dev, ifsta->bssid);
		if (bss) {
			if (bss->has_erp_value)
				ieee80211_handle_erp_ie(dev, bss->erp_value);
			ieee80211_rx_bss_put(dev, bss);
		}

		//netif_carrier_on(dev);
		ifsta->prev_bssid_set = 1;
		memcpy(ifsta->prev_bssid, sdata->u.sta.bssid, ETH_ALEN);
		//memcpy(wrqu.ap_addr.sa_data, sdata->u.sta.bssid, ETH_ALEN);
		ieee80211_sta_send_associnfo(dev, ifsta);
	} else {
		//netif_carrier_off(dev);
		sdata->use_protection = 0;
		//memset(wrqu.ap_addr.sa_data, 0, ETH_ALEN);
	}
	//wrqu.ap_addr.sa_family = ARPHRD_ETHER;
	//wireless_send_event(dev, SIOCGIWAP, &wrqu, NULL);
	ifsta->last_probe = jiffies;
}

#define IEEE80211_PROBE_DELAY (HZ / 33)
#define IEEE80211_FC(type, stype) cpu_to_le16(type | stype)

static void ieee80211_send_probe_req(struct net_device *dev, u8 *dst,
				     u8 *ssid, size_t ssid_len)
{
IM_HERE_NOW();	
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
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

static void ieee80211_associated(struct net_device *dev,
				 struct ieee80211_if_sta *ifsta)
{
IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sta_info *sta;
	int disassoc;

	/* TODO: start monitoring current AP signal quality and number of
	 * missed beacons. Scan other channels every now and then and search
	 * for better APs. */
	/* TODO: remove expired BSSes */

	ifsta->state = IEEE80211_ASSOCIATED;

	sta = sta_info_get(local, ifsta->bssid);
	if (!sta) {
		printk(KERN_DEBUG "%s: No STA entry for own AP " MAC_FMT "\n",
		       dev->name, MAC_ARG(ifsta->bssid));
		disassoc = 1;
	} else {
		disassoc = 0;
		if (time_after(jiffies,
			       sta->last_rx + IEEE80211_MONITORING_INTERVAL)) {
			if (ifsta->probereq_poll) {
				printk(KERN_DEBUG "%s: No ProbeResp from "
				       "current AP " MAC_FMT " - assume out of "
				       "range\n",
				       dev->name, MAC_ARG(ifsta->bssid));
				disassoc = 1;
				sta_info_free(sta, 0);
				ifsta->probereq_poll = 0;
			} else {
				ieee80211_send_probe_req(dev, ifsta->bssid,
							 local->scan_ssid,
							 local->scan_ssid_len);
				ifsta->probereq_poll = 1;
			}
		} else {
			ifsta->probereq_poll = 0;
			if (time_after(jiffies, ifsta->last_probe +
				       IEEE80211_PROBE_INTERVAL)) {
				ifsta->last_probe = jiffies;
				ieee80211_send_probe_req(dev, ifsta->bssid,
							 ifsta->ssid,
							 ifsta->ssid_len);
			}
		}
		sta_info_put(sta);
	}
	if (disassoc) {
		/*union iwreq_data wrqu;
		memset(wrqu.ap_addr.sa_data, 0, ETH_ALEN);
		wrqu.ap_addr.sa_family = ARPHRD_ETHER;
		wireless_send_event(dev, SIOCGIWAP, &wrqu, NULL);*/
		mod_timer(&ifsta->timer, IEEE80211_MONITORING_INTERVAL + 30 * HZ);
	} else {
		mod_timer(&ifsta->timer, IEEE80211_MONITORING_INTERVAL);
	}
}

static void ieee80211_rx_mgmt_assoc_resp(struct net_device *dev,
					 struct ieee80211_if_sta *ifsta,
					 struct ieee80211_mgmt *mgmt,
					 size_t len,
					 int reassoc)
{
IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_hw_mode *mode;
	struct sta_info *sta;
	u32 rates;
	u16 capab_info, status_code, aid;
	struct ieee802_11_elems elems;
	u8 *pos;
	int i, j;

	/* AssocResp and ReassocResp have identical structure, so process both
	 * of them in this function. */

	if (ifsta->state != IEEE80211_ASSOCIATE) {
		printk(KERN_DEBUG "%s: association frame received from "
		       MAC_FMT ", but not in associate state - ignored\n",
		       dev->name, MAC_ARG(mgmt->sa));
		return;
	}

	if (len < 24 + 6) {
		printk(KERN_DEBUG "%s: too short (%zd) association frame "
		       "received from " MAC_FMT " - ignored\n",
		       dev->name, len, MAC_ARG(mgmt->sa));
		return;
	}

	if (memcmp(ifsta->bssid, mgmt->sa, ETH_ALEN) != 0) {
		printk(KERN_DEBUG "%s: association frame received from "
		       "unknown AP (SA=" MAC_FMT " BSSID=" MAC_FMT ") - "
		       "ignored\n", dev->name, MAC_ARG(mgmt->sa),
		       MAC_ARG(mgmt->bssid));
		return;
	}

	capab_info = le16_to_cpu(mgmt->u.assoc_resp.capab_info);
	status_code = le16_to_cpu(mgmt->u.assoc_resp.status_code);
	aid = le16_to_cpu(mgmt->u.assoc_resp.aid);
	if ((aid & (BIT(15) | BIT(14))) != (BIT(15) | BIT(14)))
		printk(KERN_DEBUG "%s: invalid aid value %d; bits 15:14 not "
		       "set\n", dev->name, aid);
	aid &= ~(BIT(15) | BIT(14));

	printk(KERN_DEBUG "%s: RX %sssocResp from " MAC_FMT " (capab=0x%x "
	       "status=%d aid=%d)\n",
	       dev->name, reassoc ? "Rea" : "A", MAC_ARG(mgmt->sa),
	       capab_info, status_code, aid);

	if (status_code != WLAN_STATUS_SUCCESS) {
		printk(KERN_DEBUG "%s: AP denied association (code=%d)\n",
		       dev->name, status_code);
		if (status_code == WLAN_STATUS_REASSOC_NO_ASSOC)
			ifsta->prev_bssid_set = 0;
		return;
	}

	pos = mgmt->u.assoc_resp.variable;
	if (ieee802_11_parse_elems(pos, len - (pos - (u8 *) mgmt), &elems)
	    == ParseFailed) {
		printk(KERN_DEBUG "%s: failed to parse AssocResp\n",
		       dev->name);
		return;
	}

	if (!elems.supp_rates) {
		printk(KERN_DEBUG "%s: no SuppRates element in AssocResp\n",
		       dev->name);
		return;
	}

	/* it probably doesn't, but if the frame includes an ERP value then
	 * update our stored copy */
	if (elems.erp_info && elems.erp_info_len >= 1) {
		struct ieee80211_sta_bss *bss
			= ieee80211_rx_bss_get(dev, ifsta->bssid);
		if (bss) {
			bss->erp_value = elems.erp_info[0];
			bss->has_erp_value = 1;
			ieee80211_rx_bss_put(dev, bss);
		}
	}

	printk(KERN_DEBUG "%s: associated\n", dev->name);
	ifsta->aid = aid;
	ifsta->ap_capab = capab_info;

	kfree(ifsta->assocresp_ies);
	ifsta->assocresp_ies_len = len - (pos - (u8 *) mgmt);
	ifsta->assocresp_ies = (u8*)kmalloc(ifsta->assocresp_ies_len, GFP_ATOMIC);
	if (ifsta->assocresp_ies)
		memcpy(ifsta->assocresp_ies, pos, ifsta->assocresp_ies_len);

	ieee80211_set_associated(dev, ifsta, 1);

	/* Add STA entry for the AP */
	sta = sta_info_get(local, ifsta->bssid);
	if (!sta) {
		struct ieee80211_sta_bss *bss;
		sta = sta_info_add(local, dev, ifsta->bssid, GFP_ATOMIC);
		if (!sta) {
			printk(KERN_DEBUG "%s: failed to add STA entry for the"
			       " AP\n", dev->name);
			return;
		}
		bss = ieee80211_rx_bss_get(dev, ifsta->bssid);
		if (bss) {
			sta->last_rssi = bss->rssi;
			sta->last_signal = bss->signal;
			sta->last_noise = bss->noise;
			ieee80211_rx_bss_put(dev, bss);
		}
	}

	sta->dev = dev;
	sta->flags |= WLAN_STA_AUTH | WLAN_STA_ASSOC;
	sta->assoc_ap = 1;

	rates = 0;
	mode = local->oper_hw_mode;
	for (i = 0; i < elems.supp_rates_len; i++) {
		int rate = (elems.supp_rates[i] & 0x7f) * 5;
		if (mode->mode == MODE_ATHEROS_TURBO)
			rate *= 2;
		for (j = 0; j < mode->num_rates; j++)
			if (mode->rates[j].rate == rate)
				rates |= BIT(j);
	}
	for (i = 0; i < elems.ext_supp_rates_len; i++) {
		int rate = (elems.ext_supp_rates[i] & 0x7f) * 5;
		if (mode->mode == MODE_ATHEROS_TURBO)
			rate *= 2;
		for (j = 0; j < mode->num_rates; j++)
			if (mode->rates[j].rate == rate)
				rates |= BIT(j);
	}
	sta->supp_rates = rates;

	rate_control_rate_init(sta, local);

	if (elems.wmm_param && ifsta->wmm_enabled) {
		sta->flags |= WLAN_STA_WME;
		ieee80211_sta_wmm_params(dev, ifsta, elems.wmm_param,
					 elems.wmm_param_len);
	}


	sta_info_put(sta);

	ieee80211_associated(dev, ifsta);
}


ieee80211_txrx_result ieee80211_rx_h_parse_qos(struct ieee80211_txrx_data *rx)
{
IM_HERE_NOW();	
		return TXRX_CONTINUE;
}


static ieee80211_txrx_result ieee80211_rx_h_load_stats(struct ieee80211_txrx_data *rx)
{
IM_HERE_NOW();	
	struct ieee80211_local *local = rx->local;
	struct sk_buff *skb = rx->skb;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb_data(skb);
	u32 load = 0, hdrtime;
	struct ieee80211_rate *rate;
	struct ieee80211_hw_mode *mode = local->hw.conf.mode;
	int i;

	/* Estimate total channel use caused by this frame */

	if (unlikely(mode->num_rates < 0))
		return TXRX_CONTINUE;

	rate = &mode->rates[0];
	for (i = 0; i < mode->num_rates; i++) {
		if (mode->rates[i].val == rx->u.rx.status->rate) {
			rate = &mode->rates[i];
			break;
		}
	}

	/* 1 bit at 1 Mbit/s takes 1 usec; in channel_use values,
	 * 1 usec = 1/8 * (1080 / 10) = 13.5 */

	if (mode->mode == MODE_IEEE80211A ||
	    mode->mode == MODE_ATHEROS_TURBO ||
	    mode->mode == MODE_ATHEROS_TURBOG ||
	    (mode->mode == MODE_IEEE80211G &&
	     rate->flags & IEEE80211_RATE_ERP))
		hdrtime = CHAN_UTIL_HDR_SHORT;
	else
		hdrtime = CHAN_UTIL_HDR_LONG;

	load = hdrtime;
	if (!is_multicast_ether_addr(hdr->addr1))
		load += hdrtime;

	load += skb_len(skb) * rate->rate_inv;

	/* Divide channel_use by 8 to avoid wrapping around the counter */
	load >>= CHAN_UTIL_SHIFT;
	local->channel_use_raw += load;
	if (rx->sta)
		rx->sta->channel_use_raw += load;
	rx->u.rx.load = load;

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
IM_HERE_NOW();	
rx->sdata->channel_use_raw += rx->u.rx.load;
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_monitor(struct ieee80211_txrx_data *rx)
{
IM_HERE_NOW();	
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_passive_scan(struct ieee80211_txrx_data *rx)
{
IM_HERE_NOW();	
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

static void ieee80211_key_threshold_notify(struct net_device *dev,
					   struct ieee80211_key *key,
					   struct sta_info *sta)
{
IM_HERE_NOW();	
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
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
IM_HERE_NOW();	
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

static ieee80211_txrx_result
ieee80211_rx_h_ccmp_decrypt(struct ieee80211_txrx_data *rx)
{
IM_HERE_NOW();	
	return TXRX_CONTINUE;
}

#define WLAN_STA_PS BIT(2)


						  


static inline void bss_tim_clear(struct ieee80211_local *local, struct ieee80211_if_ap *bss, u16 aid)
{
IM_HERE_NOW();	
	__bss_tim_clear(bss, aid);
}
		
		
#define WLAN_STA_TIM BIT(3) /* TIM bit is on for PS stations */

static int ap_sta_ps_end(struct net_device *dev, struct sta_info *sta)
{
IM_HERE_NOW();	
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
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
		dev_queue_xmit(skb);
		//currentController->outputPacket(skb->mac_data,NULL);
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
		dev_queue_xmit(skb);
		//currentController->outputPacket(skb->mac_data,NULL);
	}

	return sent;
}

static void ap_sta_ps_start(struct net_device *dev, struct sta_info *sta)
{
IM_HERE_NOW();	
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
IM_HERE_NOW();	
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
IM_HERE_NOW();	
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
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
		queue_te(ifsta->work.number,(thread_call_func_t)ifsta->work.func,sdata,NULL,true);
		//queue_work(local->hw.workqueue, &ifsta->work);//check this
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
IM_HERE_NOW();	
	struct ieee80211_sub_if_data *sdata;

	if (!rx->u.rx.ra_match)
		return TXRX_DROP;

	sdata = (ieee80211_sub_if_data *)IEEE80211_DEV_TO_SUB_IF(rx->dev);
	if ((sdata->type == IEEE80211_IF_TYPE_STA ||
	     sdata->type == IEEE80211_IF_TYPE_IBSS) /*&&
	    !rx->local->user_space_mlme*/) {
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
IM_HERE_NOW();	
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

	payload = ((u8*)skb_data(skb)) + hdrlen;
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
		skb_set_network_header(skb2, 0);
		skb_set_mac_header(skb2, 0);
		dev_queue_xmit(skb2);
		//currentController->outputPacket(skb2->mac_data,NULL);
	}

	return TXRX_QUEUED;
}

/* No encapsulation header if EtherType < 0x600 (=length) */
static const unsigned char eapol_header[] =
	{ 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e };
	
static int ieee80211_is_eapol(const struct sk_buff *skb)
{
IM_HERE_NOW();	
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
IM_HERE_NOW();	
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

static ieee80211_txrx_result
ieee80211_rx_h_tkip_decrypt(struct ieee80211_txrx_data *rx)
{
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_wep_weak_iv_detection(struct ieee80211_txrx_data *rx)
{
IM_HERE_NOW();	
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_wep_decrypt(struct ieee80211_txrx_data *rx)
{
IM_HERE_NOW();	
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_defragment(struct ieee80211_txrx_data *rx)
{
IM_HERE_NOW();	
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_ps_poll(struct ieee80211_txrx_data *rx)
{
IM_HERE_NOW();	
	struct sk_buff *skb;
	int no_pending_pkts;

	if (likely(!rx->sta ||
		   (rx->fc & IEEE80211_FCTL_FTYPE) != IEEE80211_FTYPE_CTL ||
		   (rx->fc & IEEE80211_FCTL_STYPE) != IEEE80211_STYPE_PSPOLL ||
		   !rx->u.rx.ra_match))
		return TXRX_CONTINUE;

	skb = skb_dequeue(&rx->sta->tx_filtered);
	if (!skb) {
		skb = skb_dequeue(&rx->sta->ps_tx_buf);
		if (skb)
			rx->local->total_ps_buffered--;
	}
	no_pending_pkts = skb_queue_empty(&rx->sta->tx_filtered) &&
		skb_queue_empty(&rx->sta->ps_tx_buf);

	if (skb) {
		struct ieee80211_hdr *hdr =
			(struct ieee80211_hdr *) skb_data(skb);

		/* tell TX path to send one frame even though the STA may
		 * still remain is PS mode after this frame exchange */
		rx->sta->pspoll = 1;

#ifdef CONFIG_MAC80211_VERBOSE_PS_DEBUG
		printk(KERN_DEBUG "STA " MAC_FMT " aid %d: PS Poll (entries "
		       "after %d)\n",
		       MAC_ARG(rx->sta->addr), rx->sta->aid,
		       skb_queue_len(&rx->sta->ps_tx_buf));
#endif /* CONFIG_MAC80211_VERBOSE_PS_DEBUG */

		/* Use MoreData flag to indicate whether there are more
		 * buffered frames for this STA */
		if (no_pending_pkts) {
			hdr->frame_control &= cpu_to_le16(~IEEE80211_FCTL_MOREDATA);
			rx->sta->flags &= ~WLAN_STA_TIM;
		} else
			hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_MOREDATA);

		dev_queue_xmit(skb);
		//currentController->outputPacket(skb->mac_data,NULL);
		
		if (no_pending_pkts) {
			if (rx->local->ops->set_tim)
				rx->local->ops->set_tim(local_to_hw(rx->local),
						       rx->sta->aid, 0);
			if (rx->sdata->bss)
				bss_tim_clear(rx->local, rx->sdata->bss, rx->sta->aid);
		}
#ifdef CONFIG_MAC80211_VERBOSE_PS_DEBUG
	} else if (!rx->u.rx.sent_ps_buffered) {
		printk(KERN_DEBUG "%s: STA " MAC_FMT " sent PS Poll even "
		       "though there is no buffered frames for it\n",
		       rx->dev->name, MAC_ARG(rx->sta->addr));
#endif /* CONFIG_MAC80211_VERBOSE_PS_DEBUG */

	}

	/* Free PS Poll skb here instead of returning TXRX_DROP that would
	 * count as an dropped frame. */
	dev_kfree_skb(rx->skb);

	return TXRX_QUEUED;

}

static ieee80211_txrx_result
ieee80211_rx_h_michael_mic_verify(struct ieee80211_txrx_data *rx)
{
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_remove_qos_control(struct ieee80211_txrx_data *rx)
{
IM_HERE_NOW();	
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_rx_h_802_1x_pae(struct ieee80211_txrx_data *rx)
{
IM_HERE_NOW();	
	if (rx->sdata->eapol && ieee80211_is_eapol(rx->skb) &&
	    rx->sdata->type != IEEE80211_IF_TYPE_STA && rx->u.rx.ra_match) {
		/* Pass both encrypted and unencrypted EAPOL frames to user
		 * space for processing. */
		if (!rx->local->apdev)
			return TXRX_DROP;
		ieee80211_rx_mgmt(rx->local, rx->skb, rx->u.rx.status,
				  ieee80211_msg_normal);
		return TXRX_QUEUED;
	}

	if (unlikely(rx->sdata->ieee802_1x &&
		     (rx->fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA &&
		     (rx->fc & IEEE80211_FCTL_STYPE) != IEEE80211_STYPE_NULLFUNC &&
		     (!rx->sta || !(rx->sta->flags & WLAN_STA_AUTHORIZED)) &&
		     !ieee80211_is_eapol(rx->skb))) {
#ifdef CONFIG_MAC80211_DEBUG
		struct ieee80211_hdr *hdr =
			(struct ieee80211_hdr *) rx->skb->data;
		printk(KERN_DEBUG "%s: dropped frame from " MAC_FMT
		       " (unauthorized port)\n", rx->dev->name,
		       MAC_ARG(hdr->addr2));
#endif /* CONFIG_MAC80211_DEBUG */
		return TXRX_DROP;
	}

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

int ieee80211_hw_config(struct ieee80211_local *local)
{
IM_HERE_NOW();	
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

if (chan)
{
	local->hw.conf.channel = chan->chan;
	local->hw.conf.channel_val = chan->val;
	local->hw.conf.power_level = chan->power_level;
	local->hw.conf.freq = chan->freq;
}
if (mode)
{
	local->hw.conf.phymode = mode->mode;
	local->hw.conf.antenna_max = chan->antenna_max;
}
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

	if (!(local->hw.flags & IEEE80211_HW_NO_PROBE_FILTERING) &&
	    ieee80211_if_config(dev))
		printk(KERN_DEBUG "%s: failed to restore operational"
		       "BSSID after scan\n", dev->name);

	//memset(&wrqu, 0, sizeof(wrqu));
	//wireless_send_event(dev, SIOCGIWSCAN, &wrqu, NULL);

	//read_lock(&local->sub_if_lock);
	list_for_each_entry(sdata, &local->sub_if_list, list) {

		/* No need to wake the master device. */
		if (sdata->dev == local->mdev)
			continue;

		if (sdata->type == IEEE80211_IF_TYPE_STA) {
			if (sdata->u.sta.associated)
				ieee80211_send_nullfunc(local, sdata, 0);
			ieee80211_sta_timer((unsigned long)sdata);
		}

		netif_wake_queue(sdata->dev);
	}
	//read_unlock(&local->sub_if_lock);

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_if_sta *ifsta = &sdata->u.sta;
	if (sdata->type == IEEE80211_IF_TYPE_IBSS) {
		
		if (!ifsta->bssid_set ||
		    (!ifsta->state == IEEE80211_IBSS_JOINED &&
		    !ieee80211_sta_active_ibss(dev)))
			ieee80211_sta_find_ibss(dev, ifsta);
	}
	/*else
	if (!ifsta->associated)
	ieee80211_sta_start_scan(dev, ifsta->ssid, ifsta->ssid_len);*/
}



#define IEEE80211_CHANNEL_TIME (HZ / 33)
#define IEEE80211_PASSIVE_CHANNEL_TIME (HZ / 5)


void ieee80211_sta_scan_work(struct work_struct *work)
{
IM_HERE_NOW();	
	struct ieee80211_local *local = (struct ieee80211_local *)work;//check this
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
		local->scan_state = 1;//SCAN_SEND_PROBE;
		break;
	case 1://SCAN_SEND_PROBE:
		if (local->scan_channel->flag & IEEE80211_CHAN_W_ACTIVE_SCAN) {
			ieee80211_send_probe_req(dev, NULL, local->scan_ssid,
						 local->scan_ssid_len);
			next_delay = IEEE80211_CHANNEL_TIME;
		} else
			next_delay = IEEE80211_PASSIVE_CHANNEL_TIME;
		local->scan_state = 0;//SCAN_SET_CHANNEL;
		break;
	}
	//check this
	if (local->sta_scanning)
	queue_te(local->scan_work.work.number,(thread_call_func_t)local->scan_work.work.func,local,jiffies_to_msecs(next_delay),true);
		//queue_delayed_work(local->hw.workqueue, &local->scan_work,
		//		   next_delay);
}

#define STA_TX_BUFFER_EXPIRE (10 * HZ)
static inline int sta_info_buffer_expired(struct ieee80211_local *local,
					  struct sta_info *sta,
					  struct sk_buff *skb)
{
IM_HERE_NOW();	
	struct ieee80211_tx_packet_data *pkt_data;
	int timeout;

	if (!skb)
		return 0;

	pkt_data = (struct ieee80211_tx_packet_data *) skb->cb;

	/* Timeout: (2 * listen_interval * beacon_int * 1024 / 1000000) sec */
	timeout = (sta->listen_interval * local->hw.conf.beacon_int * 32 /
		   15625) * HZ;
	if (timeout < STA_TX_BUFFER_EXPIRE)
		timeout = STA_TX_BUFFER_EXPIRE;
	return time_after(jiffies, pkt_data->jiffiess + timeout);
	
	return 0;
}


static void sta_info_cleanup_expire_buffered(struct ieee80211_local *local,
					     struct sta_info *sta)
{
IM_HERE_NOW();	
	unsigned long flags;
	struct sk_buff *skb;

	if (skb_queue_empty(&sta->ps_tx_buf))
		return;

	for (;;) {
		spin_lock_irqsave(&sta->ps_tx_buf.lock, flags);
		skb = skb_peek(&sta->ps_tx_buf);
		if (sta_info_buffer_expired(local, sta, skb)) {
			skb = __skb_dequeue(&sta->ps_tx_buf);
			if (skb_queue_empty(&sta->ps_tx_buf))
				sta->flags &= ~WLAN_STA_TIM;
		} else
			skb = NULL;
		spin_unlock_irqrestore(&sta->ps_tx_buf.lock, flags);

		if (skb) {
			local->total_ps_buffered--;
			printk(KERN_DEBUG "Buffered frame expired (STA "
			       MAC_FMT ")\n", MAC_ARG(sta->addr));
			dev_kfree_skb(skb);
		} else
			break;
	}
}

/* How often station data is cleaned up (e.g., expiration of buffered frames)
 */
#define STA_INFO_CLEANUP_INTERVAL (10 * HZ)

static void sta_info_cleanup(unsigned long data)
{
IM_HERE_NOW();	
	struct ieee80211_local *local = (struct ieee80211_local *) data;
	struct sta_info *sta;

	spin_lock_bh(&local->sta_lock);
	list_for_each_entry(sta, &local->sta_list, list) {
		__sta_info_get(sta);
		sta_info_cleanup_expire_buffered(local, sta);
		sta_info_put(sta);
	}
	spin_unlock_bh(&local->sta_lock);

	local->sta_cleanup.expires = STA_INFO_CLEANUP_INTERVAL;
	add_timer(&local->sta_cleanup);
}




void sta_info_init(struct ieee80211_local *local)
{
IM_HERE_NOW();	
	spin_lock_init(&local->sta_lock);
	INIT_LIST_HEAD(&local->sta_list);
	INIT_LIST_HEAD(&local->deleted_sta_list);

	init_timer(&local->sta_cleanup);
	local->sta_cleanup.expires = STA_INFO_CLEANUP_INTERVAL;
	local->sta_cleanup.data = (unsigned long) local;
	local->sta_cleanup.function = sta_info_cleanup;

#ifdef CONFIG_MAC80211_DEBUGFS
	//INIT_WORK(&local->sta_debugfs_add, sta_info_debugfs_add_task);
#endif
}

static inline int __ieee80211_queue_stopped(const struct ieee80211_local *local,
					    int queue)
{
	return test_bit(IEEE80211_LINK_STATE_XOFF, &local->state[queue]);
}

static inline int __ieee80211_queue_pending(const struct ieee80211_local *local,
					    int queue)
{
	return test_bit(IEEE80211_LINK_STATE_PENDING, &local->state[queue]);
}

static inline void ieee80211_dump_frame(const char *ifname, const char *title,
					struct sk_buff *skb)
{
}

int __ieee80211_tx(struct ieee80211_local *local, struct sk_buff *skb,
			  struct ieee80211_txrx_data *tx)
{
IM_HERE_NOW();	
	struct ieee80211_tx_control *control = tx->u.tx.control;
	int ret, i;

	/*if (!ieee80211_qdisc_installed(local->mdev) &&
	    __ieee80211_queue_stopped(local, 0)) {
		netif_stop_queue(local->mdev);
		return IEEE80211_TX_AGAIN;
	}*/
	if (skb) {
		ieee80211_dump_frame(local->mdev->name, "TX to low-level driver", skb);
		ret = local->ops->tx(local_to_hw(local), skb, control);
		if (ret)
			return IEEE80211_TX_AGAIN;
		local->mdev->trans_start = jiffies;
		//ieee80211_led_tx(local, 1);
	}
	if (tx->u.tx.extra_frag) {
		control->flags &= ~(IEEE80211_TXCTL_USE_RTS_CTS |
				    IEEE80211_TXCTL_USE_CTS_PROTECT |
				    IEEE80211_TXCTL_CLEAR_DST_MASK |
				    IEEE80211_TXCTL_FIRST_FRAGMENT);
		for (i = 0; i < tx->u.tx.num_extra_frag; i++) {
			if (!tx->u.tx.extra_frag[i])
				continue;
			if (__ieee80211_queue_stopped(local, control->queue))
				return IEEE80211_TX_FRAG_AGAIN;
			if (i == tx->u.tx.num_extra_frag) {
				control->tx_rate = tx->u.tx.last_frag_hwrate;
				control->rate = tx->u.tx.last_frag_rate;
				if (tx->u.tx.probe_last_frag)
					control->flags |=
						IEEE80211_TXCTL_RATE_CTRL_PROBE;
				else
					control->flags &=
						~IEEE80211_TXCTL_RATE_CTRL_PROBE;
			}

			ieee80211_dump_frame(local->mdev->name,
					     "TX to low-level driver",
					     tx->u.tx.extra_frag[i]);
			ret = local->ops->tx(local_to_hw(local),
					    tx->u.tx.extra_frag[i],
					    control);
			if (ret)
				return IEEE80211_TX_FRAG_AGAIN;
			local->mdev->trans_start = jiffies;
			//ieee80211_led_tx(local, 1);
			tx->u.tx.extra_frag[i] = NULL;
		}
		kfree(tx->u.tx.extra_frag);
		tx->u.tx.extra_frag = NULL;
	}
	return IEEE80211_TX_OK;
}

static void ieee80211_tx_pending(unsigned long data)
{
IM_HERE_NOW();	
	struct ieee80211_local *local = (struct ieee80211_local *)data;
	struct net_device *dev = local->mdev;
	struct ieee80211_tx_stored_packet *store;
	struct ieee80211_txrx_data tx;
	int i, ret, reschedule = 0;

	//netif_tx_lock_bh(dev);
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
	/*netif_tx_unlock_bh(dev);
	if (reschedule) {
		if (!ieee80211_qdisc_installed(dev)) {
			if (!__ieee80211_queue_stopped(local, 0))
				netif_wake_queue(dev);
		} else
			netif_schedule(dev);
	}*/
}

 struct net_device *alloc_netdev(int sizeof_priv, const char *mask,
                                         void (*setup)(struct net_device *))
  {
          void *p;
          struct net_device *dev;
          int alloc_size;
  
          /* ensure 32-byte alignment of both the device and private area */
  
          alloc_size = (sizeof(struct net_device) + 31) & ~31;
          alloc_size += sizeof_priv + 31;
  
          p = kmalloc (alloc_size, GFP_KERNEL);
          if (!p) {
                  printk(KERN_ERR "alloc_dev: Unable to allocate device.\n");
                  return NULL;
          }
  
          memset(p, 0, alloc_size);
  
          dev = (struct net_device *)(((long)p + 31) & ~31);
          dev->padded = (char *)dev - (char *)p;
  
          if (sizeof_priv)
                  dev->priv = netdev_priv(dev);
  
        //  setup(dev);
         strcpy(dev->name, mask);
 
         return dev;
 }


void ieee80211_free_hw (	struct ieee80211_hw *  	hw){
	return;
}

static int rate_list_match(const int *rate_list, int rate)
{
	int i;

	if (!rate_list)
		return 0;

	for (i = 0; rate_list[i] >= 0; i++)
		if (rate_list[i] == rate)
			return 1;

	return 0;
}

static inline int ieee80211_is_erp_rate(int phymode, int rate)
{
	if (phymode == MODE_IEEE80211G) {
		if (rate != 10 && rate != 20 &&
		    rate != 55 && rate != 110)
			return 1;
	}
	return 0;
}

void ieee80211_prepare_rates(struct ieee80211_local *local,
			     struct ieee80211_hw_mode *mode)
{
	int i;

	for (i = 0; i < mode->num_rates; i++) {
		struct ieee80211_rate *rate = &mode->rates[i];

		rate->flags &= ~(IEEE80211_RATE_SUPPORTED |
				 IEEE80211_RATE_BASIC);

		if (local->supp_rates[mode->mode]) {
			if (!rate_list_match(local->supp_rates[mode->mode],
					     rate->rate))
				continue;
		}

		rate->flags |= IEEE80211_RATE_SUPPORTED;

		/* Use configured basic rate set if it is available. If not,
		 * use defaults that are sane for most cases. */
		if (local->basic_rates[mode->mode]) {
			if (rate_list_match(local->basic_rates[mode->mode],
					    rate->rate))
				rate->flags |= IEEE80211_RATE_BASIC;
		} else switch (mode->mode) {
		case MODE_IEEE80211A:
			if (rate->rate == 60 || rate->rate == 120 ||
			    rate->rate == 240)
				rate->flags |= IEEE80211_RATE_BASIC;
			break;
		case MODE_IEEE80211B:
			if (rate->rate == 10 || rate->rate == 20)
				rate->flags |= IEEE80211_RATE_BASIC;
			break;
		case MODE_ATHEROS_TURBO:
			if (rate->rate == 120 || rate->rate == 240 ||
			    rate->rate == 480)
				rate->flags |= IEEE80211_RATE_BASIC;
			break;
		case MODE_IEEE80211G:
			if (rate->rate == 10 || rate->rate == 20 ||
			    rate->rate == 55 || rate->rate == 110)
				rate->flags |= IEEE80211_RATE_BASIC;
			break;
		}

		/* Set ERP and MANDATORY flags based on phymode */
		switch (mode->mode) {
		case MODE_IEEE80211A:
			if (rate->rate == 60 || rate->rate == 120 ||
			    rate->rate == 240)
				rate->flags |= IEEE80211_RATE_MANDATORY;
			break;
		case MODE_IEEE80211B:
			if (rate->rate == 10)
				rate->flags |= IEEE80211_RATE_MANDATORY;
			break;
		case MODE_ATHEROS_TURBO:
			break;
		case MODE_IEEE80211G:
			if (rate->rate == 10 || rate->rate == 20 ||
			    rate->rate == 55 || rate->rate == 110 ||
			    rate->rate == 60 || rate->rate == 120 ||
			    rate->rate == 240)
				rate->flags |= IEEE80211_RATE_MANDATORY;
			break;
		}
		if (ieee80211_is_erp_rate(mode->mode, rate->rate))
			rate->flags |= IEEE80211_RATE_ERP;
	}
}

int ieee80211_register_hwmode(struct ieee80211_hw *hw,
			      struct ieee80211_hw_mode *mode)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct ieee80211_rate *rate;
	int i;

	INIT_LIST_HEAD(&mode->list);
	list_add_tail(&mode->list, &local->modes_list);

	local->hw_modes |= (1 << mode->mode);
	for (i = 0; i < mode->num_rates; i++) {
		rate = &(mode->rates[i]);
		rate->rate_inv = CHAN_UTIL_RATE_LCM / rate->rate;
	}
	ieee80211_prepare_rates(local, mode);

	if (!local->oper_hw_mode) {
		/* Default to this mode */
		local->hw.conf.phymode = mode->mode;
		local->oper_hw_mode = local->scan_hw_mode = mode;
		local->oper_channel = local->scan_channel = &mode->channels[0];
		local->hw.conf.mode = local->oper_hw_mode;
		local->hw.conf.chan = local->oper_channel;
	}

	if (!(hw->flags & IEEE80211_HW_DEFAULT_REG_DOMAIN_CONFIGURED))
		ieee80211_set_default_regdomain(mode);

	return 0;
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

int pci_write_config_dword(struct pci_dev *dev, int where, u32 val){
    IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
    fPCIDevice->configWrite32(where,val);
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
	//IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
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
IM_HERE_NOW();	
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
        local->scan.timer.expires = HZ;
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
#if 1
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
        local->scan.timer.expires = usec;
    } else {
        local->scan.in_scan = 0;
        if (conf->skb)
            dev_kfree_skb(conf->skb);
        ieee80211_netif_oper(local_to_hw(local), NETIF_WAKE);
        if (ret == -EAGAIN) {
            local->scan.timer.expires = (local->scan.interval * HZ / 100);
            local->scan.mode = old_mode;
            local->scan.chan_idx = old_chan_idx;
        } else {
            printk(KERN_DEBUG "%s: Got unknown error from "
                   "passive_scan %d\n", local->mdev->name, ret);
            local->scan.timer.expires = (local->scan.interval * HZ);
        }
        local->scan.in_scan = 0;
    }
    
    add_timer(&local->scan.timer);
}


static void ieee80211_scan_stop(struct ieee80211_local *local,
                                struct ieee80211_scan_conf *conf)
{
IM_HERE_NOW();	
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
    local->scan.timer.expires = wait;
    
    add_timer(&local->scan.timer);
}




/* Check if running monitor interfaces should go to a "hard monitor" mode
 * and switch them if necessary. */
void ieee80211_start_hard_monitor(struct ieee80211_local *local)
{
IM_HERE_NOW();	
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
IM_HERE_NOW();	
    struct ieee80211_local *local = (struct ieee80211_local *) ullocal;
    struct ieee80211_scan_conf conf;
    
    if (local->scan.interval == 0 && !local->scan.in_scan) {
        /* Passive scanning is disabled - keep the timer always
         * running to make code cleaner. */
        local->scan.timer.expires = 10 * HZ;
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
IM_HERE_NOW();	
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
    local->scan.timer.expires = local->scan.interval * HZ;
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
   // extra.endidx = local->num_curr_rates;
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

static int __ieee80211_if_config(struct net_device *dev,
				 struct sk_buff *beacon,
				 struct ieee80211_tx_control *control)
{
IM_HERE_NOW();	

	struct ieee80211_sub_if_data *sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_if_conf conf;
	static u8 scan_bssid[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	if (!local->ops->config_interface || !netif_running(dev))
	{
		IOLog("no netif_running\n");
		return 0;
	}
	memset(&conf, 0, sizeof(conf));
	conf.type = sdata->type;
	if (sdata->type == IEEE80211_IF_TYPE_STA ||
	    sdata->type == IEEE80211_IF_TYPE_IBSS) {
		if (local->sta_scanning &&
		    local->scan_dev == dev)
			conf.bssid = scan_bssid;
		else
			conf.bssid = sdata->u.sta.bssid;
		conf.ssid = sdata->u.sta.ssid;
		conf.ssid_len = sdata->u.sta.ssid_len;
		conf.generic_elem = sdata->u.sta.extra_ie;
		conf.generic_elem_len = sdata->u.sta.extra_ie_len;
	} else if (sdata->type == IEEE80211_IF_TYPE_AP) {
		conf.ssid = sdata->u.ap.ssid;
		conf.ssid_len = sdata->u.ap.ssid_len;
		conf.generic_elem = sdata->u.ap.generic_elem;
		conf.generic_elem_len = sdata->u.ap.generic_elem_len;
		conf.beacon = beacon;
		conf.beacon_control = control;
	}
	return local->ops->config_interface(local_to_hw(local),
					   dev->ifindex, &conf);
}

int ieee80211_if_config(struct net_device *dev)
{
	return __ieee80211_if_config(dev, NULL, NULL);
}







//http://www.promethos.org/lxr/http/source/drivers/pci/pci-driver.c#L376
void pci_unregister_driver (struct pci_driver * drv){
	return ;
}
/*
	set the device master of the bus
*/
void pci_set_master (struct pci_dev * dev){
	//IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	//fPCIDevice->setBusMasterEnable(true);
	return;
}

void free_irq (unsigned int irq, void *dev_id){
	return;
}
void pci_disable_msi(struct pci_dev* dev){
	return;
}

int pci_restore_state (	struct pci_dev *  	dev){
	//IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	//fPCIDevice->restoreDeviceState();
	return 0;
}
//ok but no saved_config_space in pci_dev struct
int pci_save_state (struct pci_dev * dev){
	//IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
	//fPCIDevice->saveDeviceState();
	return 0;
}
int pci_set_dma_mask(struct pci_dev *dev, u64 mask){
	//test if dma support (OK for 4965)
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
	//test if dma supported (ok 4965)
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
	//par=my_hw->priv;
	//thread_call_func_t my_func;
	if (tlink[num])
		queue_td(num,NULL);
	if (!tlink[num])
		tlink[num]=thread_call_allocate((thread_call_func_t)test_function,(void*)func);
	uint64_t timei2;
	if (timei)
	{
		clock_interval_to_deadline(timei,kMillisecondScale,&timei2);
		IOLog("timei %d timei2 %d\n",timei,timei2);
	}
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

void tasklet_enable(struct tasklet_struct *t){
	queue_te(t->padding,(thread_call_func_t)t->func,(void*)t->data,NULL,true);
	return;
}

void tasklet_schedule(struct tasklet_struct *t){
	queue_te(t->padding,(thread_call_func_t)t->func,(void*)t->data,NULL,true);
	return;
}
/*
	Used only once ,
*/

int tasklet_disable(struct tasklet_struct *t){
	queue_td(t->padding,NULL);
	return 0;
}

void tasklet_init(struct tasklet_struct *t, void (*func)(unsigned long), unsigned long data){
	t->padding++;
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
	delay=jiffies_to_msecs(delay);
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

int ieee80211_sta_start_scan(struct net_device *dev,
				    u8 *ssid, size_t ssid_len)
{
IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata;

	if (ssid_len > IEEE80211_MAX_SSID_LEN)
		return -EINVAL;

	/* MLME-SCAN.request (page 118)  page 144 (11.1.3.1)
	 * BSSType: INFRASTRUCTURE, INDEPENDENT, ANY_BSS
	 * BSSID: MACAddress
	 * SSID
	 * ScanType: ACTIVE, PASSIVE
	 * ProbeDelay: delay (in microseconds) to be used prior to transmitting
	 *    a Probe frame during active scanning
	 * ChannelList
	 * MinChannelTime (>= ProbeDelay), in TU
	 * MaxChannelTime: (>= MinChannelTime), in TU
	 */

	 /* MLME-SCAN.confirm
	  * BSSDescriptionSet
	  * ResultCode: SUCCESS, INVALID_PARAMETERS
	 */

	if (local->sta_scanning) {
		if (local->scan_dev == dev)
			return 0;
		return -EBUSY;
	}

	if (local->ops->hw_scan) {
		int rc = local->ops->hw_scan(local_to_hw(local),
					    ssid, ssid_len);
		if (!rc) {
			local->sta_scanning = 1;
			local->scan_dev = dev;
		}
		return rc;
	}
	local->sta_scanning = 1;

	//read_lock(&local->sub_if_lock);
	list_for_each_entry(sdata, &local->sub_if_list, list) {

		/* Don't stop the master interface, otherwise we can't transmit
		 * probes! */
		if (sdata->dev == local->mdev)
			continue;

		//netif_stop_queue(sdata->dev);
		if (sdata->type == IEEE80211_IF_TYPE_STA &&
		    sdata->u.sta.associated)
			ieee80211_send_nullfunc(local, sdata, 1);
	}
	//read_unlock(&local->sub_if_lock);

	if (ssid) {
		local->scan_ssid_len = ssid_len;
		memcpy(local->scan_ssid, ssid, ssid_len);
	} else
		local->scan_ssid_len = 0;
	local->scan_state = 0;//SCAN_SET_CHANNEL;
	local->scan_hw_mode = list_entry(local->modes_list.next,
					 struct ieee80211_hw_mode,
					 list);
	local->scan_channel_idx = 0;
	local->scan_dev = dev;

	if (!(local->hw.flags & IEEE80211_HW_NO_PROBE_FILTERING) &&
	    ieee80211_if_config(dev))
		printk(KERN_DEBUG "%s: failed to set BSSID for scan\n",
		       dev->name);

	/* TODO: start scan as soon as all nullfunc frames are ACKed */
	queue_te(local->scan_work.work.number,(thread_call_func_t)local->scan_work.work.func,local,jiffies_to_msecs(IEEE80211_CHANNEL_TIME),true);
	//queue_delayed_work(local->hw.workqueue, &local->scan_work,
	//		   IEEE80211_CHANNEL_TIME);

	return 0;
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
	//maybe get the pointer for the good function as iwl4965_pci_probe ...
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
	//fPCIDevice->configWrite8(kIOPCIConfigLatencyTimer,0x64);
	
	/* We disable the RETRY_TIMEOUT register (0x41) to keep
	 * PCI Tx retries from interfering with C3 CPU state */
	UInt16 reg = fPCIDevice->configRead16(0x40);
	if((reg & 0x0000ff00) != 0)
		fPCIDevice->configWrite16(0x40, reg & 0xffff00ff);

	//fPCIDevice->setBusMasterEnable(true);
	//fPCIDevice->setMemoryEnable(true);
	int result2 = (drv->probe) (test_pci,test);
	
	/*struct ieee80211_local *local = hw_to_local(my_hw);
	int result3 = ieee80211_open(local);//run_add_interface();
	if(result3)
		IOLog("Error ieee80211_open\n");*/
    //hack
	//ieee80211_sta_start_scan(local->mdev, NULL, 0);
	return 0;
}

static void ieee80211_set_disassoc(struct net_device *dev,
				   struct ieee80211_if_sta *ifsta, int deauth)
{
	IM_HERE_NOW();
	if (deauth)
		ifsta->auth_tries = 0;
	ifsta->assoc_tries = 0;
	ieee80211_set_associated(dev, ifsta, 0);
}

static void ieee80211_rx_mgmt_deauth(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta,
				     struct ieee80211_mgmt *mgmt,
				     size_t len)
{
	u16 reason_code;
IM_HERE_NOW();
	if (len < 24 + 2) {
		printk(KERN_DEBUG "%s: too short (%zd) deauthentication frame "
		       "received from " MAC_FMT " - ignored\n",
		       dev->name, len, MAC_ARG(mgmt->sa));
		return;
	}

	if (memcmp(ifsta->bssid, mgmt->sa, ETH_ALEN) != 0) {
		printk(KERN_DEBUG "%s: deauthentication frame received from "
		       "unknown AP (SA=" MAC_FMT " BSSID=" MAC_FMT ") - "
		       "ignored\n", dev->name, MAC_ARG(mgmt->sa),
		       MAC_ARG(mgmt->bssid));
		return;
	}

	reason_code = le16_to_cpu(mgmt->u.deauth.reason_code);

	printk(KERN_DEBUG "%s: RX deauthentication from " MAC_FMT
	       " (reason=%d)\n",
	       dev->name, MAC_ARG(mgmt->sa), reason_code);

	if (ifsta->authenticated) {
		printk(KERN_DEBUG "%s: deauthenticated\n", dev->name);
	}

	if (ifsta->state == IEEE80211_AUTHENTICATE ||
	    ifsta->state == IEEE80211_ASSOCIATE ||
	    ifsta->state == IEEE80211_ASSOCIATED) {
		ifsta->state = IEEE80211_AUTHENTICATE;
		mod_timer(&ifsta->timer, IEEE80211_RETRY_AUTH_INTERVAL);
	}

	ieee80211_set_disassoc(dev, ifsta, 1);
	ifsta->authenticated = 0;
}

static void ieee80211_rx_mgmt_disassoc(struct net_device *dev,
				       struct ieee80211_if_sta *ifsta,
				       struct ieee80211_mgmt *mgmt,
				       size_t len)
{
	u16 reason_code;
IM_HERE_NOW();
	if (len < 24 + 2) {
		printk(KERN_DEBUG "%s: too short (%zd) disassociation frame "
		       "received from " MAC_FMT " - ignored\n",
		       dev->name, len, MAC_ARG(mgmt->sa));
		return;
	}

	if (memcmp(ifsta->bssid, mgmt->sa, ETH_ALEN) != 0) {
		printk(KERN_DEBUG "%s: disassociation frame received from "
		       "unknown AP (SA=" MAC_FMT " BSSID=" MAC_FMT ") - "
		       "ignored\n", dev->name, MAC_ARG(mgmt->sa),
		       MAC_ARG(mgmt->bssid));
		return;
	}

	reason_code = le16_to_cpu(mgmt->u.disassoc.reason_code);

	printk(KERN_DEBUG "%s: RX disassociation from " MAC_FMT
	       " (reason=%d)\n",
	       dev->name, MAC_ARG(mgmt->sa), reason_code);

	if (ifsta->associated)
		printk(KERN_DEBUG "%s: disassociated\n", dev->name);

	if (ifsta->state == IEEE80211_ASSOCIATED) {
		ifsta->state = IEEE80211_ASSOCIATE;
		mod_timer(&ifsta->timer, IEEE80211_RETRY_AUTH_INTERVAL);
	}

	ieee80211_set_disassoc(dev, ifsta, 0);
}

static void ieee80211_sta_rx_queued_mgmt(struct net_device *dev,
					 struct sk_buff *skb)
{
IM_HERE_NOW();
	struct ieee80211_rx_status *rx_status;
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_sta *ifsta;
	struct ieee80211_mgmt *mgmt;
	u16 fc;

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	ifsta = &sdata->u.sta;

	rx_status = (struct ieee80211_rx_status *) skb->cb;
	mgmt = (struct ieee80211_mgmt *) skb_data(skb);
	fc = le16_to_cpu(mgmt->frame_control);

	switch (fc & IEEE80211_FCTL_STYPE) {
	case IEEE80211_STYPE_PROBE_REQ:
		ieee80211_rx_mgmt_probe_req(dev, ifsta, mgmt, mbuf_len(skb->mac_data),
					    rx_status);
		break;
	case IEEE80211_STYPE_PROBE_RESP:
		ieee80211_rx_mgmt_probe_resp(dev, mgmt, mbuf_len(skb->mac_data), rx_status);
		break;
	case IEEE80211_STYPE_BEACON:
		ieee80211_rx_mgmt_beacon(dev, mgmt, mbuf_len(skb->mac_data), rx_status);
		break;
	case IEEE80211_STYPE_AUTH:
		ieee80211_rx_mgmt_auth(dev, ifsta, mgmt, mbuf_len(skb->mac_data));
		break;
	case IEEE80211_STYPE_ASSOC_RESP:
		ieee80211_rx_mgmt_assoc_resp(dev, ifsta, mgmt, mbuf_len(skb->mac_data), 0);
		break;
	case IEEE80211_STYPE_REASSOC_RESP:
		ieee80211_rx_mgmt_assoc_resp(dev, ifsta, mgmt, mbuf_len(skb->mac_data), 1);
		break;
	case IEEE80211_STYPE_DEAUTH:
		ieee80211_rx_mgmt_deauth(dev, ifsta, mgmt, mbuf_len(skb->mac_data));
		break;
	case IEEE80211_STYPE_DISASSOC:
		ieee80211_rx_mgmt_disassoc(dev, ifsta, mgmt, mbuf_len(skb->mac_data));
		break;
	}

	kfree_skb(skb);
}

void ieee80211_send_nullfunc(struct ieee80211_local *local,
				    struct ieee80211_sub_if_data *sdata,
				    int powersave)
{
IM_HERE_NOW();
	struct sk_buff *skb;
	struct ieee80211_hdr *nullfunc;
	u16 fc;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + 24);
	if (!skb) {
		printk(KERN_DEBUG "%s: failed to allocate buffer for nullfunc "
		       "frame\n", sdata->dev->name);
		return;
	}
	skb_reserve(skb, local->hw.extra_tx_headroom);

	nullfunc = (struct ieee80211_hdr *) skb_put(skb, 24);
	memset(nullfunc, 0, 24);
	fc = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_NULLFUNC |
	     IEEE80211_FCTL_TODS;
	if (powersave)
		fc |= IEEE80211_FCTL_PM;
	nullfunc->frame_control = cpu_to_le16(fc);
	memcpy(nullfunc->addr1, sdata->u.sta.bssid, ETH_ALEN);
	memcpy(nullfunc->addr2, sdata->dev->dev_addr, ETH_ALEN);
	memcpy(nullfunc->addr3, sdata->u.sta.bssid, ETH_ALEN);

	ieee80211_sta_tx(sdata->dev, skb, 0);
}


static void ieee80211_sta_reset_auth(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta)
{
	IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);

	if (local->ops->reset_tsf) {
		/* Reset own TSF to allow time synchronization work. */
		local->ops->reset_tsf(local_to_hw(local));
	}

	ifsta->wmm_last_param_set = -1; /* allow any WMM update */


	if (ifsta->auth_algs & IEEE80211_AUTH_ALG_OPEN)
		ifsta->auth_alg = WLAN_AUTH_OPEN;
	else if (ifsta->auth_algs & IEEE80211_AUTH_ALG_SHARED_KEY)
		ifsta->auth_alg = WLAN_AUTH_SHARED_KEY;
	else if (ifsta->auth_algs & IEEE80211_AUTH_ALG_LEAP)
		ifsta->auth_alg = WLAN_AUTH_LEAP;
	else
		ifsta->auth_alg = WLAN_AUTH_OPEN;
	printk(KERN_DEBUG "%s: Initial auth_alg=%d\n", dev->name,
	       ifsta->auth_alg);
	ifsta->auth_transaction = -1;
	ifsta->associated = ifsta->auth_tries = ifsta->assoc_tries = 0;
	//netif_carrier_off(dev);
}

static int ieee80211_sta_match_ssid(struct ieee80211_if_sta *ifsta,
				    const char *ssid, int ssid_len)
{
	int tmp, hidden_ssid;
IM_HERE_NOW();
	if (!memcmp(ifsta->ssid, ssid, ssid_len))
		return 1;

	if (ifsta->auto_bssid_sel)
		return 0;

	hidden_ssid = 1;
	tmp = ssid_len;
	while (tmp--) {
		if (ssid[tmp] != '\0') {
			hidden_ssid = 0;
			break;
		}
	}

	if (hidden_ssid && ifsta->ssid_len == ssid_len)
		return 1;

	if (ssid_len == 1 && ssid[0] == ' ')
		return 1;

	return 0;
}

static inline void rate_control_clear(struct ieee80211_local *local)
{
	IM_HERE_NOW();
	struct rate_control_ref *ref = local->rate_ctrl;
	ref->ops->clear(ref->priv);
}

int ieee80211_set_channel(struct ieee80211_local *local, int channel, int freq)
{
	struct ieee80211_hw_mode *mode;
	int c, set = 0;
	int ret = -EINVAL;
IM_HERE_NOW();
	list_for_each_entry(mode, &local->modes_list, list) {
		if (!(local->enabled_modes & (1 << mode->mode)))
			continue;
		for (c = 0; c < mode->num_channels; c++) {
			struct ieee80211_channel *chan = &mode->channels[c];
			if (chan->flag & IEEE80211_CHAN_W_SCAN &&
			    ((chan->chan == channel) || (chan->freq == freq))) {
				/* Use next_mode as the mode preference to
				 * resolve non-unique channel numbers. */
				if (set && mode->mode != local->next_mode)
					continue;

				local->oper_channel = chan;
				local->oper_hw_mode = mode;
				set++;
			}
		}
	}

	if (set) {
		if (local->sta_scanning)
			ret = 0;
		else
			ret = ieee80211_hw_config(local);

		rate_control_clear(local);
	}

	return ret;
}

int ieee80211_sta_active_ibss(struct net_device *dev)
{
	IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	int active = 0;
	struct sta_info *sta;

	spin_lock_bh(&local->sta_lock);
	list_for_each_entry(sta, &local->sta_list, list) {
		if (sta->dev == dev &&
		    time_after(sta->last_rx + IEEE80211_IBSS_MERGE_INTERVAL,
			       jiffies)) {
			active++;
			break;
		}
	}
	spin_unlock_bh(&local->sta_lock);

	return active;
}

static int ieee80211_sta_join_ibss(struct net_device *dev,
				   struct ieee80211_if_sta *ifsta,
				   struct ieee80211_sta_bss *bss)
{
	IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	int res, rates, i, j;
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;
	struct ieee80211_tx_control control;
	struct ieee80211_rate *rate;
	struct ieee80211_hw_mode *mode;
	struct rate_control_extra extra;
	u8 *pos;
	struct ieee80211_sub_if_data *sdata;

	/* Remove possible STA entries from other IBSS networks. */
	sta_info_flush(local, NULL);

	if (local->ops->reset_tsf) {
		/* Reset own TSF to allow time synchronization work. */
		local->ops->reset_tsf(local_to_hw(local));
	}
	memcpy(ifsta->bssid, bss->bssid, ETH_ALEN);
	res = ieee80211_if_config(dev);
	if (res)
		return res;

	local->hw.conf.beacon_int = bss->beacon_int >= 10 ? bss->beacon_int : 10;

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	sdata->drop_unencrypted = bss->capability &
		WLAN_CAPABILITY_PRIVACY ? 1 : 0;

	res = ieee80211_set_channel(local, -1, bss->freq);

	if (!(local->oper_channel->flag & IEEE80211_CHAN_W_IBSS)) {
		printk(KERN_DEBUG "%s: IBSS not allowed on channel %d "
		       "(%d MHz)\n", dev->name, local->hw.conf.channel,
		       local->hw.conf.freq);
		return -1;
	}

	/* Set beacon template based on scan results */
	skb = dev_alloc_skb(local->hw.extra_tx_headroom + 400);
	do {
		if (!skb)
			break;

		skb_reserve(skb, local->hw.extra_tx_headroom);

		mgmt = (struct ieee80211_mgmt *)
			skb_put(skb, 24 + sizeof(mgmt->u.beacon));
		memset(mgmt, 0, 24 + sizeof(mgmt->u.beacon));
		mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
						   IEEE80211_STYPE_BEACON);
		memset(mgmt->da, 0xff, ETH_ALEN);
		memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
		memcpy(mgmt->bssid, ifsta->bssid, ETH_ALEN);
		mgmt->u.beacon.beacon_int =
			cpu_to_le16(local->hw.conf.beacon_int);
		mgmt->u.beacon.capab_info = cpu_to_le16(bss->capability);

		pos = (u8*)skb_put(skb, 2 + ifsta->ssid_len);
		*pos++ = WLAN_EID_SSID;
		*pos++ = ifsta->ssid_len;
		memcpy(pos, ifsta->ssid, ifsta->ssid_len);

		rates = bss->supp_rates_len;
		if (rates > 8)
			rates = 8;
		pos = (u8*)skb_put(skb, 2 + rates);
		*pos++ = WLAN_EID_SUPP_RATES;
		*pos++ = rates;
		memcpy(pos, bss->supp_rates, rates);

		pos = (u8*)skb_put(skb, 2 + 1);
		*pos++ = WLAN_EID_DS_PARAMS;
		*pos++ = 1;
		*pos++ = bss->channel;

		pos = (u8*)skb_put(skb, 2 + 2);
		*pos++ = WLAN_EID_IBSS_PARAMS;
		*pos++ = 2;
		/* FIX: set ATIM window based on scan results */
		*pos++ = 0;
		*pos++ = 0;

		if (bss->supp_rates_len > 8) {
			rates = bss->supp_rates_len - 8;
			pos = (u8*)skb_put(skb, 2 + rates);
			*pos++ = WLAN_EID_EXT_SUPP_RATES;
			*pos++ = rates;
			memcpy(pos, &bss->supp_rates[8], rates);
		}

		memset(&control, 0, sizeof(control));
		memset(&extra, 0, sizeof(extra));
		extra.mode = local->oper_hw_mode;
		rate = rate_control_get_rate(local, dev, skb, &extra);
		if (!rate) {
			printk(KERN_DEBUG "%s: Failed to determine TX rate "
			       "for IBSS beacon\n", dev->name);
			break;
		}
		control.tx_rate = (local->short_preamble &&
				   (rate->flags & IEEE80211_RATE_PREAMBLE2)) ?
			rate->val2 : rate->val;
		control.antenna_sel_tx = local->hw.conf.antenna_sel_tx;
		control.power_level = local->hw.conf.power_level;
		control.flags |= IEEE80211_TXCTL_NO_ACK;
		control.retry_limit = 1;

		ifsta->probe_resp = skb_copy(skb, GFP_ATOMIC);
		if (ifsta->probe_resp) {
			mgmt = (struct ieee80211_mgmt *)
				ifsta->probe_resp->mac_data;
			mgmt->frame_control =
				IEEE80211_FC(IEEE80211_FTYPE_MGMT,
					     IEEE80211_STYPE_PROBE_RESP);
		} else {
			printk(KERN_DEBUG "%s: Could not allocate ProbeResp "
			       "template for IBSS\n", dev->name);
		}

		if (local->ops->beacon_update &&
		    local->ops->beacon_update(local_to_hw(local),
					     skb, &control) == 0) {
			printk(KERN_DEBUG "%s: Configured IBSS beacon "
			       "template based on scan results\n", dev->name);
			skb = NULL;
		}

		rates = 0;
		mode = local->oper_hw_mode;
		for (i = 0; i < bss->supp_rates_len; i++) {
			int bitrate = (bss->supp_rates[i] & 0x7f) * 5;
			if (mode->mode == MODE_ATHEROS_TURBO)
				bitrate *= 2;
			for (j = 0; j < mode->num_rates; j++)
				if (mode->rates[j].rate == bitrate)
					rates |= BIT(j);
		}
		ifsta->supp_rates_bits = rates;
	} while (0);

	if (skb) {
		printk(KERN_DEBUG "%s: Failed to configure IBSS beacon "
		       "template\n", dev->name);
		dev_kfree_skb(skb);
	}

	ifsta->state = IEEE80211_IBSS_JOINED;
	mod_timer(&ifsta->timer, IEEE80211_IBSS_MERGE_INTERVAL);

	ieee80211_rx_bss_put(dev, bss);

	return res;
}


static int ieee80211_sta_create_ibss(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta)
{
	IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *bss;
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_hw_mode *mode;
	u8 bssid[ETH_ALEN], *pos;
	int i;

//FIXME was if 0
#if 1
	/* Easier testing, use fixed BSSID. */
	memset(bssid, 0xfe, ETH_ALEN);
#else
	/* Generate random, not broadcast, locally administered BSSID. Mix in
	 * own MAC address to make sure that devices that do not have proper
	 * random number generator get different BSSID. */
	get_random_bytes(bssid, ETH_ALEN);
	for (i = 0; i < ETH_ALEN; i++)
		bssid[i] ^= dev->dev_addr[i];
	bssid[0] &= ~0x01;
	bssid[0] |= 0x02;
#endif

	printk(KERN_DEBUG "%s: Creating new IBSS network, BSSID " MAC_FMT "\n",
	       dev->name, MAC_ARG(bssid));

	bss = ieee80211_rx_bss_add(dev, bssid);
	if (!bss)
		return -ENOMEM;

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	mode = local->oper_hw_mode;

	if (local->hw.conf.beacon_int == 0)
		local->hw.conf.beacon_int = 100;
	bss->beacon_int = local->hw.conf.beacon_int;
	bss->hw_mode = local->hw.conf.phymode;
	bss->channel = local->hw.conf.channel;
	bss->freq = local->hw.conf.freq;
	bss->last_update = jiffies;
	bss->capability = WLAN_CAPABILITY_IBSS;
	if (sdata->default_key) {
		bss->capability |= WLAN_CAPABILITY_PRIVACY;
	} else
		sdata->drop_unencrypted = 0;
	bss->supp_rates_len = mode->num_rates;
	pos = bss->supp_rates;
	for (i = 0; i < mode->num_rates; i++) {
		int rate = mode->rates[i].rate;
		if (mode->mode == MODE_ATHEROS_TURBO)
			rate /= 2;
		*pos++ = (u8) (rate / 5);
	}

	return ieee80211_sta_join_ibss(dev, ifsta, bss);
}

int ieee80211_sta_find_ibss(struct net_device *dev,
				   struct ieee80211_if_sta *ifsta)
{
	IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sta_bss *bss;
	int found = 0;
	u8 bssid[ETH_ALEN];
	int active_ibss;

	if (ifsta->ssid_len == 0)
		return -EINVAL;

	active_ibss = ieee80211_sta_active_ibss(dev);
#ifdef CONFIG_MAC80211_IBSS_DEBUG
	printk(KERN_DEBUG "%s: sta_find_ibss (active_ibss=%d)\n",
	       dev->name, active_ibss);
#endif /* CONFIG_MAC80211_IBSS_DEBUG */
	spin_lock_bh(&local->sta_bss_lock);
	list_for_each_entry(bss, &local->sta_bss_list, list) {
		if (ifsta->ssid_len != bss->ssid_len ||
		    memcmp(ifsta->ssid, bss->ssid, bss->ssid_len) != 0
		    || !(bss->capability & WLAN_CAPABILITY_IBSS))
			continue;
#ifdef CONFIG_MAC80211_IBSS_DEBUG
		printk(KERN_DEBUG "   bssid=" MAC_FMT " found\n",
		       MAC_ARG(bss->bssid));
#endif /* CONFIG_MAC80211_IBSS_DEBUG */
		memcpy(bssid, bss->bssid, ETH_ALEN);
		found = 1;
		if (active_ibss || memcmp(bssid, ifsta->bssid, ETH_ALEN) != 0)
			break;
	}
	spin_unlock_bh(&local->sta_bss_lock);

#ifdef CONFIG_MAC80211_IBSS_DEBUG
	printk(KERN_DEBUG "   sta_find_ibss: selected " MAC_FMT " current "
	       MAC_FMT "\n", MAC_ARG(bssid), MAC_ARG(ifsta->bssid));
#endif /* CONFIG_MAC80211_IBSS_DEBUG */
	if (found && memcmp(ifsta->bssid, bssid, ETH_ALEN) != 0 &&
	    (bss = ieee80211_rx_bss_get(dev, bssid))) {
		printk(KERN_DEBUG "%s: Selected IBSS BSSID " MAC_FMT
		       " based on configured SSID\n",
		       dev->name, MAC_ARG(bssid));
		return ieee80211_sta_join_ibss(dev, ifsta, bss);
	}
#ifdef CONFIG_MAC80211_IBSS_DEBUG
	printk(KERN_DEBUG "   did not try to join ibss\n");
#endif /* CONFIG_MAC80211_IBSS_DEBUG */

	/* Selected IBSS not found in current scan results - try to scan */
	if (ifsta->state == IEEE80211_IBSS_JOINED &&
	    !ieee80211_sta_active_ibss(dev)) {
		mod_timer(&ifsta->timer, IEEE80211_IBSS_MERGE_INTERVAL);
	} else if (time_after(jiffies, local->last_scan_completed +
			      IEEE80211_SCAN_INTERVAL)) {
		printk(KERN_DEBUG "%s: Trigger new scan to find an IBSS to "
		       "join\n", dev->name);
		return ieee80211_sta_req_scan(dev, ifsta->ssid,
					      ifsta->ssid_len);
	} else if (ifsta->state != IEEE80211_IBSS_JOINED) {
		int interval = IEEE80211_SCAN_INTERVAL;

		if (time_after(jiffies, ifsta->ibss_join_req +
			       IEEE80211_IBSS_JOIN_TIMEOUT)) {
			if (ifsta->create_ibss &&
			    local->oper_channel->flag & IEEE80211_CHAN_W_IBSS)
				return ieee80211_sta_create_ibss(dev, ifsta);
			if (ifsta->create_ibss) {
				printk(KERN_DEBUG "%s: IBSS not allowed on the"
				       " configured channel %d (%d MHz)\n",
				       dev->name, local->hw.conf.channel,
				       local->hw.conf.freq);
			}

			/* No IBSS found - decrease scan interval and continue
			 * scanning. */
			interval = IEEE80211_SCAN_INTERVAL_SLOW;
		}

		ifsta->state = IEEE80211_IBSS_SEARCH;
		mod_timer(&ifsta->timer, interval);
		return 0;
	}

	return 0;
}

int ieee80211_sta_set_ssid(struct net_device *dev, char *ssid, size_t len)
{
	IM_HERE_NOW();
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_sta *ifsta;
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);

	if (len > IEEE80211_MAX_SSID_LEN)
		return -EINVAL;

	/* TODO: This should always be done for IBSS, even if IEEE80211_QOS is
	 * not defined. */
	if (local->ops->conf_tx) {
		struct ieee80211_tx_queue_params qparam;
		int i;

		memset(&qparam, 0, sizeof(qparam));
		/* TODO: are these ok defaults for all hw_modes? */
		qparam.aifs = 2;
		qparam.cw_min =
			local->hw.conf.phymode == MODE_IEEE80211B ? 31 : 15;
		qparam.cw_max = 1023;
		qparam.burst_time = 0;
		for (i = IEEE80211_TX_QUEUE_DATA0; i < NUM_TX_DATA_QUEUES; i++)
		{
			local->ops->conf_tx(local_to_hw(local),
					   i + IEEE80211_TX_QUEUE_DATA0,
					   &qparam);
		}
		/* IBSS uses different parameters for Beacon sending */
		qparam.cw_min++;
		qparam.cw_min *= 2;
		qparam.cw_min--;
		local->ops->conf_tx(local_to_hw(local),
				   IEEE80211_TX_QUEUE_BEACON, &qparam);
	}

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	ifsta = &sdata->u.sta;

	if (ifsta->ssid_len != len || memcmp(ifsta->ssid, ssid, len) != 0)
		ifsta->prev_bssid_set = 0;
	memcpy(ifsta->ssid, ssid, len);
	memset(ifsta->ssid + len, 0, IEEE80211_MAX_SSID_LEN - len);
	ifsta->ssid_len = len;

	ifsta->ssid_set = len ? 1 : 0;
	if (sdata->type == IEEE80211_IF_TYPE_IBSS && !ifsta->bssid_set) {
		ifsta->ibss_join_req = jiffies;
		ifsta->state = IEEE80211_IBSS_SEARCH;
		return ieee80211_sta_find_ibss(dev, ifsta);
	}
	return 0;
}

static inline int is_valid_ether_addr(const u8 *addr)
 {
         /* FF:FF:FF:FF:FF:FF is a multicast address so we don't need to
          * explicitly check for it here. */
         return !is_multicast_ether_addr(addr) && !is_zero_ether_addr(addr);
 }
 
int ieee80211_sta_set_bssid(struct net_device *dev, u8 *bssid)
{
	IM_HERE_NOW();
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_if_sta *ifsta;
	int res;

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	ifsta = &sdata->u.sta;

	if (memcmp(ifsta->bssid, bssid, ETH_ALEN) != 0) {
		memcpy(ifsta->bssid, bssid, ETH_ALEN);
		res = ieee80211_if_config(dev);
		if (res) {
			printk(KERN_DEBUG "%s: Failed to config new BSSID to "
			       "the low-level driver\n", dev->name);
			return res;
		}
	}

	if (!is_valid_ether_addr(bssid))
		ifsta->bssid_set = 0;
	else
		ifsta->bssid_set = 1;
	return 0;
}

int ieee80211_sta_config_auth(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta)
{
	IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_sta_bss *bss, *selected = NULL;
	int top_rssi = 0, freq;

	if (!ifsta->auto_channel_sel && !ifsta->auto_bssid_sel &&
	    !ifsta->auto_ssid_sel) {
		ifsta->state = IEEE80211_AUTHENTICATE;
		ieee80211_sta_reset_auth(dev, ifsta);
		return 0;
	}

	spin_lock_bh(&local->sta_bss_lock);
	freq = local->oper_channel->freq;
	list_for_each_entry(bss, &local->sta_bss_list, list) {
		if (!(bss->capability & WLAN_CAPABILITY_ESS))
			continue;

		if (!!(bss->capability & WLAN_CAPABILITY_PRIVACY) ^
		    !!sdata->default_key)
			continue;

		if (!ifsta->auto_channel_sel && bss->freq != freq)
			continue;

		if (!ifsta->auto_bssid_sel &&
		    memcmp(bss->bssid, ifsta->bssid, ETH_ALEN))
			continue;

		if (!ifsta->auto_ssid_sel &&
		    !ieee80211_sta_match_ssid(ifsta, (const char*)bss->ssid, bss->ssid_len))
			continue;

		if (!selected || top_rssi < bss->rssi) {
			selected = bss;
			top_rssi = bss->rssi;
		}
	}
	if (selected)
		atomic_inc(&selected->users);
	spin_unlock_bh(&local->sta_bss_lock);

	if (selected) {
		ieee80211_set_channel(local, -1, selected->freq);
		if (!ifsta->ssid_set)
			ieee80211_sta_set_ssid(dev, (char*)selected->ssid,
					       selected->ssid_len);
		ieee80211_sta_set_bssid(dev, selected->bssid);
		ieee80211_rx_bss_put(dev, selected);
		ifsta->state = IEEE80211_AUTHENTICATE;
		ieee80211_sta_reset_auth(dev, ifsta);
		return 0;
	} else {
		if (ifsta->state != IEEE80211_AUTHENTICATE) {
			if (ifsta->auto_ssid_sel)
				ieee80211_sta_start_scan(dev, NULL, 0);
			else
				ieee80211_sta_start_scan(dev, ifsta->ssid,
							 ifsta->ssid_len);
			ifsta->state = IEEE80211_AUTHENTICATE;
			set_bit(IEEE80211_STA_REQ_AUTH, &ifsta->request);
		} else
			ifsta->state = IEEE80211_DISABLED;
	}
	return -1;
}

void ieee80211_authenticate(struct net_device *dev,
				   struct ieee80211_if_sta *ifsta)
{
	IM_HERE_NOW();
	ifsta->auth_tries++;
	if (ifsta->auth_tries > IEEE80211_AUTH_MAX_TRIES) {
		printk(KERN_DEBUG "%s: authentication with AP " MAC_FMT
		       " timed out\n",
		       dev->name, MAC_ARG(ifsta->bssid));
		ifsta->state = IEEE80211_DISABLED;
		//ifsta->auth_tries=0;//hack
		//del_timer(&ifsta->timer);//hack
		return;
	}

	ifsta->state = IEEE80211_AUTHENTICATE;
	printk(KERN_DEBUG "%s: authenticate with AP " MAC_FMT "\n",
	       dev->name, MAC_ARG(ifsta->bssid));

	ieee80211_send_auth(dev, ifsta, 1, NULL, 0, 0);

	mod_timer(&ifsta->timer, IEEE80211_AUTH_TIMEOUT);
}

static void ieee80211_sta_expire(struct net_device *dev)
{
	IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sta_info *sta, *tmp;

	spin_lock_bh(&local->sta_lock);
	list_for_each_entry_safe(sta, tmp, &local->sta_list, list)
		if (time_after(jiffies, sta->last_rx +
			       IEEE80211_IBSS_INACTIVITY_LIMIT)) {
			printk(KERN_DEBUG "%s: expiring inactive STA " MAC_FMT
			       "\n", dev->name, MAC_ARG(sta->addr));
			sta_info_free(sta, 1);
		}
	spin_unlock_bh(&local->sta_lock);
}

static void ieee80211_sta_merge_ibss(struct net_device *dev,
				     struct ieee80211_if_sta *ifsta)
{
	IM_HERE_NOW();
	mod_timer(&ifsta->timer, IEEE80211_IBSS_MERGE_INTERVAL);

	ieee80211_sta_expire(dev);
	if (ieee80211_sta_active_ibss(dev))
		return;

	printk(KERN_DEBUG "%s: No active IBSS STAs - trying to scan for other "
	       "IBSS networks with same SSID (merge)\n", dev->name);
	ieee80211_sta_req_scan(dev, ifsta->ssid, ifsta->ssid_len);
}

static void ieee80211_send_disassoc(struct net_device *dev,
				    struct ieee80211_if_sta *ifsta, u16 reason)
{
	IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;

	skb = dev_alloc_skb(local->hw.extra_tx_headroom + sizeof(*mgmt));
	if (!skb) {
		printk(KERN_DEBUG "%s: failed to allocate buffer for disassoc "
		       "frame\n", dev->name);
		return;
	}
	skb_reserve(skb, local->hw.extra_tx_headroom);

	mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24);
	memset(mgmt, 0, 24);
	memcpy(mgmt->da, ifsta->bssid, ETH_ALEN);
	memcpy(mgmt->sa, dev->dev_addr, ETH_ALEN);
	memcpy(mgmt->bssid, ifsta->bssid, ETH_ALEN);
	mgmt->frame_control = IEEE80211_FC(IEEE80211_FTYPE_MGMT,
					   IEEE80211_STYPE_DISASSOC);
	skb_put(skb, 2);
	mgmt->u.disassoc.reason_code = cpu_to_le16(reason);

	ieee80211_sta_tx(dev, skb, 0);
}

void ieee80211_sta_work(struct work_struct *work)
{
IM_HERE_NOW();
	struct ieee80211_sub_if_data *sdata = (struct ieee80211_sub_if_data*)work;//check this
	//	container_of(work, struct ieee80211_sub_if_data, u.sta.work);

	struct net_device *dev = sdata->dev;
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_if_sta *ifsta;
	struct sk_buff *skb;

	if (!netif_running(dev))
	{
		IOLog("en1 not running\n");
		return;
	}
	if (local->sta_scanning)
	{
		IOLog("sta_scanning=1\n");
		return;
	}

	if (sdata->type != IEEE80211_IF_TYPE_STA &&
	    sdata->type != IEEE80211_IF_TYPE_IBSS) {
		printk(KERN_DEBUG "%s: ieee80211_sta_work: non-STA interface "
		       "(type=%d)\n", dev->name, sdata->type);
		return;
	}
	ifsta = &sdata->u.sta;

	while ((skb = skb_dequeue(&ifsta->skb_queue)))
		ieee80211_sta_rx_queued_mgmt(dev, skb);



	if (ifsta->state != IEEE80211_AUTHENTICATE &&
	    ifsta->state != IEEE80211_ASSOCIATE &&
	   // test_and_clear_bit(IEEE80211_STA_REQ_SCAN, &ifsta->request)
		test_bit(IEEE80211_STA_REQ_SCAN, &ifsta->request)) {
		clear_bit(IEEE80211_STA_REQ_SCAN, &ifsta->request);
		ieee80211_sta_start_scan(dev, ifsta->ssid, ifsta->ssid_len);//NULL, 0);
		return;
	}


	//if (test_and_clear_bit(IEEE80211_STA_REQ_AUTH, &ifsta->request)) {
	if (test_bit(IEEE80211_STA_REQ_AUTH, &ifsta->request)) {
	clear_bit(IEEE80211_STA_REQ_AUTH, &ifsta->request);
		if (ieee80211_sta_config_auth(dev, ifsta))
			return;
		clear_bit(IEEE80211_STA_REQ_RUN, &ifsta->request);
	} else
	{
	
	// if (!test_and_clear_bit(IEEE80211_STA_REQ_RUN, &ifsta->request))
	 if (!test_bit(IEEE80211_STA_REQ_RUN, &ifsta->request))
	 clear_bit(IEEE80211_STA_REQ_RUN, &ifsta->request);
		return;
	}
IOLog("ifsta->state %d\n",ifsta->state);
	switch (ifsta->state) {
	case IEEE80211_DISABLED:
		break;
	case IEEE80211_AUTHENTICATE:
		ieee80211_authenticate(dev, ifsta);
		break;
	case IEEE80211_ASSOCIATE:
		ieee80211_associate(dev, ifsta);
		break;
	case IEEE80211_ASSOCIATED:
		ieee80211_associated(dev, ifsta);
		break;
	case IEEE80211_IBSS_SEARCH:
		ieee80211_sta_find_ibss(dev, ifsta);
		break;
	case IEEE80211_IBSS_JOINED:
		ieee80211_sta_merge_ibss(dev, ifsta);
		break;
	default:
		printk(KERN_DEBUG "ieee80211_sta_work: Unknown state %d\n",
		       ifsta->state);
		break;
	}

	if (ieee80211_privacy_mismatch(dev, ifsta)) {
		printk(KERN_DEBUG "%s: privacy configuration mismatch and "
		       "mixed-cell disabled - disassociate\n", dev->name);

		ieee80211_send_disassoc(dev, ifsta, WLAN_REASON_UNSPECIFIED);
		ieee80211_set_disassoc(dev, ifsta, 0);
	}
	
}

static inline void ieee80211_start_soft_monitor(struct ieee80211_local *local)
{
IM_HERE_NOW();
	struct ieee80211_if_init_conf conf;

	if (local->open_count && local->open_count == local->monitors &&
	    !(local->hw.flags & IEEE80211_HW_MONITOR_DURING_OPER) &&
	    local->ops->remove_interface) {
		conf.if_id = -1;
		conf.type = IEEE80211_IF_TYPE_MNTR;
		conf.mac_addr = NULL;
		local->ops->remove_interface(local_to_hw(local), &conf);
	}
}

int ieee80211_open(struct net_device *dev)
{
IM_HERE_NOW();
	struct ieee80211_local *local =  wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata, *nsdata;
	struct ieee80211_if_init_conf conf;
	int res;

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	/*read_lock(&local->sub_if_lock);
	list_for_each_entry(nsdata, &local->sub_if_list, list) {
		struct net_device *ndev = nsdata->dev;

		if (ndev != dev && ndev != local->mdev && netif_running(ndev) &&
		    compare_ether_addr(dev->dev_addr, ndev->dev_addr) == 0 &&
		    !identical_mac_addr_allowed(sdata->type, nsdata->type)) {
			read_unlock(&local->sub_if_lock);
			return -ENOTUNIQ;
		}
	}
	read_unlock(&local->sub_if_lock);*/

	if (sdata->type == IEEE80211_IF_TYPE_WDS &&
	    is_zero_ether_addr(sdata->u.wds.remote_addr))
		return -ENOLINK;

	if (sdata->type == IEEE80211_IF_TYPE_MNTR && local->open_count &&
	    !(local->hw.flags & IEEE80211_HW_MONITOR_DURING_OPER)) {
		/* run the interface in a "soft monitor" mode */
		local->monitors++;
		local->open_count++;
		//local->hw.conf.flags |= IEEE80211_CONF_RADIOTAP;
		return 0;
	}
	ieee80211_start_soft_monitor(local);

	conf.if_id = dev->ifindex;
	conf.type = sdata->type;
	conf.mac_addr = dev->dev_addr;
	res = local->ops->add_interface(local_to_hw(local), &conf);
	if (res) {
		if (sdata->type == IEEE80211_IF_TYPE_MNTR)
			ieee80211_start_hard_monitor(local);
		return res;
	}

	if (local->open_count == 0) {
		if (local->ops->open)
			res = local->ops->open(local_to_hw(local));
		if (res == 0) {
			//res = dev_open(local->mdev);
			if (res) {
				if (local->ops->stop)
					local->ops->stop(local_to_hw(local));
			} else {
				res = ieee80211_hw_config(local);
				if (res && local->ops->stop)
					local->ops->stop(local_to_hw(local));
				else
				ieee80211_if_add_mgmt(local);	
				//else if (!res && local->apdev)
				//	dev_open(local->apdev);
			}
		}
		if (res) {
			if (local->ops->remove_interface)
				local->ops->remove_interface(local_to_hw(local),
							    &conf);
			return res;
		}
		/* enable tasklets only if all callbacks return correctly */
		tasklet_enable(&local->tx_pending_tasklet);
		tasklet_enable(&local->tasklet);
	}
	local->open_count++;

	if (sdata->type == IEEE80211_IF_TYPE_MNTR) {
		local->monitors++;
		//local->hw.conf.flags |= IEEE80211_CONF_RADIOTAP;
	} else
		ieee80211_if_config(dev);

	//if (!res) ieee80211_sta_req_scan(dev,NULL,0);
	/*if (sdata->type == IEEE80211_IF_TYPE_STA &&
	    !local->user_space_mlme)
		netif_carrier_off(dev);
	else
		netif_carrier_on(dev);*/

	netif_start_queue(dev);
	return res;
}

static ieee80211_txrx_result inline
__ieee80211_tx_prepare(struct ieee80211_txrx_data *tx,
		       struct sk_buff *skb,
		       struct net_device *dev,
		       struct ieee80211_tx_control *control)
{
IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb_data(skb);
	struct ieee80211_sub_if_data *sdata;
	ieee80211_txrx_result res = TXRX_CONTINUE;

	int hdrlen;

	memset(tx, 0, sizeof(*tx));
	tx->skb = skb;
	tx->dev = dev; /* use original interface */
	tx->local = local;
	tx->sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	tx->sta = sta_info_get(local, hdr->addr1);
	tx->fc = le16_to_cpu(hdr->frame_control);

	/*
	 * set defaults for things that can be set by
	 * injected radiotap headers
	 */
	control->power_level = local->hw.conf.power_level;
	control->antenna_sel_tx = local->hw.conf.antenna_sel_tx;
	if (local->sta_antenna_sel != 0 && tx->sta)
		control->antenna_sel_tx = tx->sta->antenna_sel_tx;

	/* process and remove the injection radiotap header */
	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	if (unlikely(sdata->type == IEEE80211_IF_TYPE_MNTR)) {
		/*if (__ieee80211_parse_tx_radiotap(tx, skb, control) ==
								TXRX_DROP) {
			return TXRX_DROP;
		}*/
		/*
		 * we removed the radiotap header after this point,
		 * we filled control with what we could use
		 * set to the actual ieee header now
		 */
		hdr = (struct ieee80211_hdr *) skb_data(skb);
		res = TXRX_QUEUED; /* indication it was monitor packet */
	}

	tx->u.tx.control = control;
	tx->u.tx.unicast = !is_multicast_ether_addr(hdr->addr1);
	if (is_multicast_ether_addr(hdr->addr1))
		control->flags |= IEEE80211_TXCTL_NO_ACK;
	else
		control->flags &= ~IEEE80211_TXCTL_NO_ACK;
	tx->fragmented = local->fragmentation_threshold <
		IEEE80211_MAX_FRAG_THRESHOLD && tx->u.tx.unicast &&
		skb_len(skb) + FCS_LEN > local->fragmentation_threshold &&
		(!local->ops->set_frag_threshold);
	if (!tx->sta)
		control->flags |= IEEE80211_TXCTL_CLEAR_DST_MASK;
	else if (tx->sta->clear_dst_mask) {
		control->flags |= IEEE80211_TXCTL_CLEAR_DST_MASK;
		tx->sta->clear_dst_mask = 0;
	}
	hdrlen = ieee80211_get_hdrlen(tx->fc);
	if (skb_len(skb) > hdrlen + sizeof(rfc1042_header) + 2) {
		//u8 *pos = &skb->data[hdrlen + sizeof(rfc1042_header)];
		u8 *pos = (u8*)skb_data(skb)+hdrlen + sizeof(rfc1042_header);
		tx->ethertype = (pos[0] << 8) | pos[1];
	}
	control->flags |= IEEE80211_TXCTL_FIRST_FRAGMENT;

	return res;
}

static int ieee80211_frame_duration(struct ieee80211_local *local, size_t len,
				    int rate, int erp, int short_preamble)
{
IM_HERE_NOW();
	int dur;

	/* calculate duration (in microseconds, rounded up to next higher
	 * integer if it includes a fractional microsecond) to send frame of
	 * len bytes (does not include FCS) at the given rate. Duration will
	 * also include SIFS.
	 *
	 * rate is in 100 kbps, so divident is multiplied by 10 in the
	 * DIV_ROUND_UP() operations.
	 */

	if (local->hw.conf.phymode == MODE_IEEE80211A || erp ||
	    local->hw.conf.phymode == MODE_ATHEROS_TURBO) {
		/*
		 * OFDM:
		 *
		 * N_DBPS = DATARATE x 4
		 * N_SYM = Ceiling((16+8xLENGTH+6) / N_DBPS)
		 *	(16 = SIGNAL time, 6 = tail bits)
		 * TXTIME = T_PREAMBLE + T_SIGNAL + T_SYM x N_SYM + Signal Ext
		 *
		 * T_SYM = 4 usec
		 * 802.11a - 17.5.2: aSIFSTime = 16 usec
		 * 802.11g - 19.8.4: aSIFSTime = 10 usec +
		 *	signal ext = 6 usec
		 */
		/* FIX: Atheros Turbo may have different (shorter) duration? */
		dur = 16; /* SIFS + signal ext */
		dur += 16; /* 17.3.2.3: T_PREAMBLE = 16 usec */
		dur += 4; /* 17.3.2.3: T_SIGNAL = 4 usec */
		dur += 4 * DIV_ROUND_UP((16 + 8 * (len + 4) + 6) * 10,
					4 * rate); /* T_SYM x N_SYM */
	} else {
		/*
		 * 802.11b or 802.11g with 802.11b compatibility:
		 * 18.3.4: TXTIME = PreambleLength + PLCPHeaderTime +
		 * Ceiling(((LENGTH+PBCC)x8)/DATARATE). PBCC=0.
		 *
		 * 802.11 (DS): 15.3.3, 802.11b: 18.3.4
		 * aSIFSTime = 10 usec
		 * aPreambleLength = 144 usec or 72 usec with short preamble
		 * aPLCPHeaderLength = 48 usec or 24 usec with short preamble
		 */
		dur = 10; /* aSIFSTime = 10 usec */
		dur += short_preamble ? (72 + 24) : (144 + 48);

		dur += DIV_ROUND_UP(8 * (len + 4) * 10, rate);
	}

	return dur;
}

static u16 ieee80211_duration(struct ieee80211_txrx_data *tx, int group_addr,
			      int next_frag_len)
{
IM_HERE_NOW();
	int rate, mrate, erp, dur, i;
	struct ieee80211_rate *txrate = tx->u.tx.rate;
	struct ieee80211_local *local = tx->local;
	struct ieee80211_hw_mode *mode = tx->u.tx.mode;

	erp = txrate->flags & IEEE80211_RATE_ERP;

	/*
	 * data and mgmt (except PS Poll):
	 * - during CFP: 32768
	 * - during contention period:
	 *   if addr1 is group address: 0
	 *   if more fragments = 0 and addr1 is individual address: time to
	 *      transmit one ACK plus SIFS
	 *   if more fragments = 1 and addr1 is individual address: time to
	 *      transmit next fragment plus 2 x ACK plus 3 x SIFS
	 *
	 * IEEE 802.11, 9.6:
	 * - control response frame (CTS or ACK) shall be transmitted using the
	 *   same rate as the immediately previous frame in the frame exchange
	 *   sequence, if this rate belongs to the PHY mandatory rates, or else
	 *   at the highest possible rate belonging to the PHY rates in the
	 *   BSSBasicRateSet
	 */

	if ((tx->fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_CTL) {
		/* TODO: These control frames are not currently sent by
		 * 80211.o, but should they be implemented, this function
		 * needs to be updated to support duration field calculation.
		 *
		 * RTS: time needed to transmit pending data/mgmt frame plus
		 *    one CTS frame plus one ACK frame plus 3 x SIFS
		 * CTS: duration of immediately previous RTS minus time
		 *    required to transmit CTS and its SIFS
		 * ACK: 0 if immediately previous directed data/mgmt had
		 *    more=0, with more=1 duration in ACK frame is duration
		 *    from previous frame minus time needed to transmit ACK
		 *    and its SIFS
		 * PS Poll: BIT(15) | BIT(14) | aid
		 */
		return 0;
	}

	/* data/mgmt */
	if (0 /* FIX: data/mgmt during CFP */)
		return 32768;

	if (group_addr) /* Group address as the destination - no ACK */
		return 0;

	/* Individual destination address:
	 * IEEE 802.11, Ch. 9.6 (after IEEE 802.11g changes)
	 * CTS and ACK frames shall be transmitted using the highest rate in
	 * basic rate set that is less than or equal to the rate of the
	 * immediately previous frame and that is using the same modulation
	 * (CCK or OFDM). If no basic rate set matches with these requirements,
	 * the highest mandatory rate of the PHY that is less than or equal to
	 * the rate of the previous frame is used.
	 * Mandatory rates for IEEE 802.11g PHY: 1, 2, 5.5, 11, 6, 12, 24 Mbps
	 */
	rate = -1;
	mrate = 10; /* use 1 Mbps if everything fails */
	for (i = 0; i < mode->num_rates; i++) {
		struct ieee80211_rate *r = &mode->rates[i];
		if (r->rate > txrate->rate)
			break;

		if (IEEE80211_RATE_MODULATION(txrate->flags) !=
		    IEEE80211_RATE_MODULATION(r->flags))
			continue;

		if (r->flags & IEEE80211_RATE_BASIC)
			rate = r->rate;
		else if (r->flags & IEEE80211_RATE_MANDATORY)
			mrate = r->rate;
	}
	if (rate == -1) {
		/* No matching basic rate found; use highest suitable mandatory
		 * PHY rate */
		rate = mrate;
	}

	/* Time needed to transmit ACK
	 * (10 bytes + 4-byte FCS = 112 bits) plus SIFS; rounded up
	 * to closest integer */

	dur = ieee80211_frame_duration(local, 10, rate, erp,
				       local->short_preamble);

	if (next_frag_len) {
		/* Frame is fragmented: duration increases with time needed to
		 * transmit next fragment plus ACK and 2 x SIFS. */
		dur *= 2; /* ACK + SIFS */
		/* next fragment */
		dur += ieee80211_frame_duration(local, next_frag_len,
						txrate->rate, erp,
						local->short_preamble);
	}

	return dur;
}

static ieee80211_txrx_result
ieee80211_tx_h_load_stats(struct ieee80211_txrx_data *tx)
{
IM_HERE_NOW();
	struct ieee80211_local *local = tx->local;
	struct ieee80211_hw_mode *mode = tx->u.tx.mode;
	struct sk_buff *skb = tx->skb;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb_data(skb);
	u32 load = 0, hdrtime;

	/* TODO: this could be part of tx_status handling, so that the number
	 * of retries would be known; TX rate should in that case be stored
	 * somewhere with the packet */

	/* Estimate total channel use caused by this frame */

	/* 1 bit at 1 Mbit/s takes 1 usec; in channel_use values,
	 * 1 usec = 1/8 * (1080 / 10) = 13.5 */

	if (mode->mode == MODE_IEEE80211A ||
	    mode->mode == MODE_ATHEROS_TURBO ||
	    mode->mode == MODE_ATHEROS_TURBOG ||
	    (mode->mode == MODE_IEEE80211G &&
	     tx->u.tx.rate->flags & IEEE80211_RATE_ERP))
		hdrtime = CHAN_UTIL_HDR_SHORT;
	else
		hdrtime = CHAN_UTIL_HDR_LONG;

	load = hdrtime;
	if (!is_multicast_ether_addr(hdr->addr1))
		load += hdrtime;

	if (tx->u.tx.control->flags & IEEE80211_TXCTL_USE_RTS_CTS)
		load += 2 * hdrtime;
	else if (tx->u.tx.control->flags & IEEE80211_TXCTL_USE_CTS_PROTECT)
		load += hdrtime;

	load += skb_len(skb) * tx->u.tx.rate->rate_inv;

	if (tx->u.tx.extra_frag) {
		int i;
		for (i = 0; i < tx->u.tx.num_extra_frag; i++) {
			load += 2 * hdrtime;
			load += skb_len(tx->u.tx.extra_frag[i]) *
				tx->u.tx.rate->rate;
		}
	}

	/* Divide channel_use by 8 to avoid wrapping around the counter */
	load >>= CHAN_UTIL_SHIFT;
	local->channel_use_raw += load;
	if (tx->sta)
		tx->sta->channel_use_raw += load;
	tx->sdata->channel_use_raw += load;

	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_tx_h_misc(struct ieee80211_txrx_data *tx)
{
IM_HERE_NOW();
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb_data(tx->skb);
	u16 dur;
	struct ieee80211_tx_control *control = tx->u.tx.control;
	struct ieee80211_hw_mode *mode = tx->u.tx.mode;

	if (!is_multicast_ether_addr(hdr->addr1)) {
		if (skb_len(tx->skb) + FCS_LEN > tx->local->rts_threshold &&
		    tx->local->rts_threshold < IEEE80211_MAX_RTS_THRESHOLD) {
			control->flags |= IEEE80211_TXCTL_USE_RTS_CTS;
			control->retry_limit =
				tx->local->long_retry_limit;
		} else {
			control->retry_limit =
				tx->local->short_retry_limit;
		}
	} else {
		control->retry_limit = 1;
	}

	if (tx->fragmented) {
		/* Do not use multiple retry rates when sending fragmented
		 * frames.
		 * TODO: The last fragment could still use multiple retry
		 * rates. */
		control->alt_retry_rate = -1;
	}

	/* Use CTS protection for unicast frames sent using extended rates if
	 * there are associated non-ERP stations and RTS/CTS is not configured
	 * for the frame. */
	if (mode->mode == MODE_IEEE80211G &&
	    (tx->u.tx.rate->flags & IEEE80211_RATE_ERP) &&
	    tx->u.tx.unicast && tx->sdata->use_protection &&
	    !(control->flags & IEEE80211_TXCTL_USE_RTS_CTS))
		control->flags |= IEEE80211_TXCTL_USE_CTS_PROTECT;

	/* Setup duration field for the first fragment of the frame. Duration
	 * for remaining fragments will be updated when they are being sent
	 * to low-level driver in ieee80211_tx(). */
	dur = ieee80211_duration(tx, is_multicast_ether_addr(hdr->addr1),
				 tx->fragmented ? skb_len(tx->u.tx.extra_frag[0]) :
				 0);
	hdr->duration_id = cpu_to_le16(dur);

	if ((control->flags & IEEE80211_TXCTL_USE_RTS_CTS) ||
	    (control->flags & IEEE80211_TXCTL_USE_CTS_PROTECT)) {
		struct ieee80211_rate *rate;

		/* Do not use multiple retry rates when using RTS/CTS */
		control->alt_retry_rate = -1;

		/* Use min(data rate, max base rate) as CTS/RTS rate */
		rate = tx->u.tx.rate;
		while (rate > mode->rates &&
		       !(rate->flags & IEEE80211_RATE_BASIC))
			rate--;

		control->rts_cts_rate = rate->val;
		control->rts_rate = rate;
	}

	if (tx->sta) {
		tx->sta->tx_packets++;
		tx->sta->tx_fragments++;
		tx->sta->tx_bytes += skb_len(tx->skb);
		if (tx->u.tx.extra_frag) {
			int i;
			tx->sta->tx_fragments += tx->u.tx.num_extra_frag;
			for (i = 0; i < tx->u.tx.num_extra_frag; i++) {
				tx->sta->tx_bytes +=
					skb_len(tx->u.tx.extra_frag[i]);
			}
		}
	}

	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_tx_h_rate_ctrl(struct ieee80211_txrx_data *tx)
{
IM_HERE_NOW();
if (unlikely(!tx->sta))
		return TXRX_DROP;
		
	struct rate_control_extra extra;

	memset(&extra, 0, sizeof(extra));
	extra.mode = tx->u.tx.mode;
	extra.mgmt_data = tx->sdata &&
		tx->sdata->type == IEEE80211_IF_TYPE_MGMT;
	extra.ethertype = tx->ethertype;

	tx->u.tx.rate = rate_control_get_rate(tx->local, tx->dev, tx->skb,
					      &extra);
	if (unlikely(extra.probe != NULL)) {
		tx->u.tx.control->flags |= IEEE80211_TXCTL_RATE_CTRL_PROBE;
		tx->u.tx.probe_last_frag = 1;
		tx->u.tx.control->alt_retry_rate = tx->u.tx.rate->val;
		tx->u.tx.rate = extra.probe;
	} else {
		tx->u.tx.control->alt_retry_rate = -1;
	}
	if (!tx->u.tx.rate)
		return TXRX_DROP;
	if (tx->u.tx.mode->mode == MODE_IEEE80211G &&
	    tx->sdata->use_protection && tx->fragmented &&
	    extra.nonerp) {
		tx->u.tx.last_frag_rate = tx->u.tx.rate;
		tx->u.tx.probe_last_frag = extra.probe ? 1 : 0;

		tx->u.tx.rate = extra.nonerp;
		tx->u.tx.control->rate = extra.nonerp;
		tx->u.tx.control->flags &= ~IEEE80211_TXCTL_RATE_CTRL_PROBE;
	} else {
		tx->u.tx.last_frag_rate = tx->u.tx.rate;
		tx->u.tx.control->rate = tx->u.tx.rate;
	}
	tx->u.tx.control->tx_rate = tx->u.tx.rate->val;
	if ((tx->u.tx.rate->flags & IEEE80211_RATE_PREAMBLE2) &&
	    tx->local->short_preamble &&
	    (!tx->sta || (tx->sta->flags & WLAN_STA_SHORT_PREAMBLE))) {
		tx->u.tx.short_preamble = 1;
		tx->u.tx.control->tx_rate = tx->u.tx.rate->val2;
	}

	/* only data unicast frame */
	if ((tx->u.tx.rate) && tx->skb && tx->sdata && tx->u.tx.unicast &&
	    (tx->sdata->type == IEEE80211_IF_TYPE_STA ||
	     tx->sdata->type == IEEE80211_IF_TYPE_IBSS )&& !extra.mgmt_data) {
		struct ieee80211_hdr *hdr;
		u16 fc;

		hdr = (struct ieee80211_hdr *) skb_data(tx->skb);
		fc = le16_to_cpu(hdr->frame_control);

		if ((fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA)
			tx->sdata->u.sta.last_rate = tx->u.tx.rate->rate *
								     100000;
	}

	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_tx_h_wep_encrypt(struct ieee80211_txrx_data *tx)
{
/*	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) tx->skb->data;
	u16 fc;

	fc = le16_to_cpu(hdr->frame_control);

	if (!tx->key || tx->key->alg != ALG_WEP ||
	    ((fc & IEEE80211_FCTL_FTYPE) != IEEE80211_FTYPE_DATA &&
	     ((fc & IEEE80211_FCTL_FTYPE) != IEEE80211_FTYPE_MGMT ||
	      (fc & IEEE80211_FCTL_STYPE) != IEEE80211_STYPE_AUTH)))
		return TXRX_CONTINUE;

	tx->u.tx.control->iv_len = WEP_IV_LEN;
	tx->u.tx.control->icv_len = WEP_ICV_LEN;
	ieee80211_tx_set_iswep(tx);

	if (wep_encrypt_skb(tx, tx->skb) < 0) {
		I802_DEBUG_INC(tx->local->tx_handlers_drop_wep);
		return TXRX_DROP;
	}

	if (tx->u.tx.extra_frag) {
		int i;
		for (i = 0; i < tx->u.tx.num_extra_frag; i++) {
			if (wep_encrypt_skb(tx, tx->u.tx.extra_frag[i]) < 0) {
				I802_DEBUG_INC(tx->local->
					       tx_handlers_drop_wep);
				return TXRX_DROP;
			}
		}
	}*/

	return TXRX_CONTINUE;
}

ieee80211_txrx_result
ieee80211_tx_h_ccmp_encrypt(struct ieee80211_txrx_data *tx)
{
/*	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) tx->skb->data;
	struct ieee80211_key *key = tx->key;
	u16 fc;
	struct sk_buff *skb = tx->skb;
	int test = 0;

	fc = le16_to_cpu(hdr->frame_control);

	if (!key || key->alg != ALG_CCMP || !WLAN_FC_DATA_PRESENT(fc))
		return TXRX_CONTINUE;

	tx->u.tx.control->icv_len = CCMP_MIC_LEN;
	tx->u.tx.control->iv_len = CCMP_HDR_LEN;
	ieee80211_tx_set_iswep(tx);

	if (!tx->key->force_sw_encrypt &&
	    !(tx->local->hw.flags & IEEE80211_HW_WEP_INCLUDE_IV)) {
		tx->u.tx.control->key_idx = tx->key->hw_key_idx;
		return TXRX_CONTINUE;
	}

	if (ccmp_encrypt_skb(tx, skb, test) < 0)
		return TXRX_DROP;

	if (tx->u.tx.extra_frag) {
		int i;

		for (i = 0; i < tx->u.tx.num_extra_frag; i++) {
			if (ccmp_encrypt_skb(tx, tx->u.tx.extra_frag[i], test)
			    < 0)
				return TXRX_DROP;
		}
	}*/

	return TXRX_CONTINUE;
}

ieee80211_txrx_result
ieee80211_tx_h_tkip_encrypt(struct ieee80211_txrx_data *tx)
{
/*	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) tx->skb->data;
	u16 fc;
	struct ieee80211_key *key = tx->key;
	struct sk_buff *skb = tx->skb;
	int wpa_test = 0, test = 0;

	fc = le16_to_cpu(hdr->frame_control);

	if (!key || key->alg != ALG_TKIP || !WLAN_FC_DATA_PRESENT(fc))
		return TXRX_CONTINUE;

	tx->u.tx.control->icv_len = TKIP_ICV_LEN;
	tx->u.tx.control->iv_len = TKIP_IV_LEN;
	ieee80211_tx_set_iswep(tx);

	if (!tx->key->force_sw_encrypt &&
	    !(tx->local->hw.flags & IEEE80211_HW_WEP_INCLUDE_IV) &&
	    !wpa_test) {
		tx->u.tx.control->key_idx = tx->key->hw_key_idx;
		return TXRX_CONTINUE;
	}

	if (tkip_encrypt_skb(tx, skb, test) < 0)
		return TXRX_DROP;

	if (tx->u.tx.extra_frag) {
		int i;
		for (i = 0; i < tx->u.tx.num_extra_frag; i++) {
			if (tkip_encrypt_skb(tx, tx->u.tx.extra_frag[i], test)
			    < 0)
				return TXRX_DROP;
		}
	}
*/
	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_tx_h_fragment(struct ieee80211_txrx_data *tx)
{
IM_HERE_NOW();
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb_data(tx->skb);
	size_t hdrlen, per_fragm, num_fragm, payload_len, left;
	struct sk_buff **frags, *first, *frag;
	int i;
	u16 seq;
	u8 *pos;
	int frag_threshold = tx->local->fragmentation_threshold;

	if (!tx->fragmented)
		return TXRX_CONTINUE;

	first = tx->skb;

	hdrlen = ieee80211_get_hdrlen(tx->fc);
	payload_len = skb_len(first) - hdrlen;
	per_fragm = frag_threshold - hdrlen - FCS_LEN;
	num_fragm = (payload_len + per_fragm - 1) / per_fragm;

	frags = (struct sk_buff**)kzalloc(num_fragm * sizeof(struct sk_buff *), GFP_ATOMIC);
	if (!frags)
		goto fail;

	hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_MOREFRAGS);
	seq = le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_SEQ;
	pos = (u8*)first->mac_data + hdrlen + per_fragm;
	left = payload_len - per_fragm;
	for (i = 0; i < num_fragm - 1; i++) {
		struct ieee80211_hdr *fhdr;
		size_t copylen;

		if (left <= 0)
			goto fail;

		/* reserve enough extra head and tail room for possible
		 * encryption */
		frag = frags[i] =
			dev_alloc_skb(tx->local->tx_headroom +
				      frag_threshold +
				      IEEE80211_ENCRYPT_HEADROOM +
				      IEEE80211_ENCRYPT_TAILROOM);
		if (!frag)
			goto fail;
		/* Make sure that all fragments use the same priority so
		 * that they end up using the same TX queue */
		//frag->priority = first->priority;
		skb_reserve(frag, tx->local->tx_headroom +
				  IEEE80211_ENCRYPT_HEADROOM);
		fhdr = (struct ieee80211_hdr *) skb_put(frag, hdrlen);
		memcpy(fhdr, first->mac_data, hdrlen);
		if (i == num_fragm - 2)
			fhdr->frame_control &= cpu_to_le16(~IEEE80211_FCTL_MOREFRAGS);
		fhdr->seq_ctrl = cpu_to_le16(seq | ((i + 1) & IEEE80211_SCTL_FRAG));
		copylen = left > per_fragm ? per_fragm : left;
		memcpy(skb_put(frag, copylen), pos, copylen);

		pos += copylen;
		left -= copylen;
	}
	skb_trim(first, hdrlen + per_fragm);

	tx->u.tx.num_extra_frag = num_fragm - 1;
	tx->u.tx.extra_frag = frags;

	return TXRX_CONTINUE;

 fail:
	printk(KERN_DEBUG "%s: failed to fragment frame\n", tx->dev->name);
	if (frags) {
		for (i = 0; i < num_fragm - 1; i++)
			if (frags[i])
				dev_kfree_skb(frags[i]);
		kfree(frags);
	}
	I802_DEBUG_INC(tx->local->tx_handlers_drop_fragment);
	return TXRX_DROP;
}

ieee80211_txrx_result
ieee80211_tx_h_michael_mic_add(struct ieee80211_txrx_data *tx)
{
/*	u8 *data, *sa, *da, *key, *mic, qos_tid;
	size_t data_len;
	u16 fc;
	struct sk_buff *skb = tx->skb;
	int authenticator;
	int wpa_test = 0;

	fc = tx->fc;

	if (!tx->key || tx->key->alg != ALG_TKIP || skb->len < 24 ||
	    !WLAN_FC_DATA_PRESENT(fc))
		return TXRX_CONTINUE;

	if (ieee80211_get_hdr_info(skb, &sa, &da, &qos_tid, &data, &data_len))
		return TXRX_DROP;

	if (!tx->key->force_sw_encrypt &&
	    !tx->fragmented &&
	    !(tx->local->hw.flags & IEEE80211_HW_TKIP_INCLUDE_MMIC) &&
	    !wpa_test) {
		return TXRX_CONTINUE;
	}

	if (skb_tailroom(skb) < MICHAEL_MIC_LEN) {
		I802_DEBUG_INC(tx->local->tx_expand_skb_head);
		if (unlikely(pskb_expand_head(skb, TKIP_IV_LEN,
					      MICHAEL_MIC_LEN + TKIP_ICV_LEN,
					      GFP_ATOMIC))) {
			printk(KERN_DEBUG "%s: failed to allocate more memory "
			       "for Michael MIC\n", tx->dev->name);
			return TXRX_DROP;
		}
	}

#if 0
	authenticator = fc & IEEE80211_FCTL_FROMDS; 
#else
	authenticator = 1;
#endif
	key = &tx->key->key[authenticator ? ALG_TKIP_TEMP_AUTH_TX_MIC_KEY :
			    ALG_TKIP_TEMP_AUTH_RX_MIC_KEY];
	mic = skb_put(skb, MICHAEL_MIC_LEN);
	michael_mic(key, da, sa, qos_tid & 0x0f, data, data_len, mic);*/

	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_tx_h_select_key(struct ieee80211_txrx_data *tx)
{
IM_HERE_NOW();
	if (tx->sta)
		tx->u.tx.control->key_idx = tx->sta->key_idx_compression;
	else
		tx->u.tx.control->key_idx = HW_KEY_IDX_INVALID;

	if (unlikely(tx->u.tx.control->flags & IEEE80211_TXCTL_DO_NOT_ENCRYPT))
		tx->key = NULL;
	else if (tx->sta && tx->sta->key)
		tx->key = tx->sta->key;
	else if (tx->sdata->default_key)
		tx->key = tx->sdata->default_key;
	else if (tx->sdata->drop_unencrypted &&
		 !(tx->sdata->eapol && ieee80211_is_eapol(tx->skb))) {
		I802_DEBUG_INC(tx->local->tx_handlers_drop_unencrypted);
		return TXRX_DROP;
	} else
		tx->key = NULL;

	if (tx->key) {
		tx->key->tx_rx_count++;
		if (unlikely(tx->local->key_tx_rx_threshold &&
			     tx->key->tx_rx_count >
			     tx->local->key_tx_rx_threshold)) {
			ieee80211_key_threshold_notify(tx->dev, tx->key,
						       tx->sta);
		}
	}

	return TXRX_CONTINUE;
}

static void purge_old_ps_buffers(struct ieee80211_local *local)
{
IM_HERE_NOW();
	int total = 0, purged = 0;
	struct sk_buff *skb;
	struct ieee80211_sub_if_data *sdata;
	struct sta_info *sta;

	//read_lock(&local->sub_if_lock);
	list_for_each_entry(sdata, &local->sub_if_list, list) {
		struct ieee80211_if_ap *ap;
		if (sdata->dev == local->mdev ||
		    sdata->type != IEEE80211_IF_TYPE_AP)
			continue;
		ap = &sdata->u.ap;
		skb = skb_dequeue(&ap->ps_bc_buf);
		if (skb) {
			purged++;
			dev_kfree_skb(skb);
		}
		total += skb_queue_len(&ap->ps_bc_buf);
	}
	//read_unlock(&local->sub_if_lock);

	spin_lock_bh(&local->sta_lock);
	list_for_each_entry(sta, &local->sta_list, list) {
		skb = skb_dequeue(&sta->ps_tx_buf);
		if (skb) {
			purged++;
			dev_kfree_skb(skb);
		}
		total += skb_queue_len(&sta->ps_tx_buf);
	}
	spin_unlock_bh(&local->sta_lock);

	local->total_ps_buffered = total;
	printk(KERN_DEBUG "%s: PS buffers full - purged %d frames\n",
	       local->mdev->name, purged);
}

static inline void __bss_tim_set(struct ieee80211_if_ap *bss, int aid)
{
	/*
	 * This format has ben mandated by the IEEE specifications,
	 * so this line may not be changed to use the __set_bit() format.
	 */
	bss->tim[(aid)/8] |= 1<<((aid) % 8);
}

static inline void bss_tim_set(struct ieee80211_local *local,
			       struct ieee80211_if_ap *bss, int aid)
{
	spin_lock_bh(&local->sta_lock);
	__bss_tim_set(bss, aid);
	spin_unlock_bh(&local->sta_lock);
}

inline __u32 skb_queue_len(const struct sk_buff_head *list_)
{
         return list_->qlen;
 }

static inline ieee80211_txrx_result
ieee80211_tx_h_unicast_ps_buf(struct ieee80211_txrx_data *tx)
{
IM_HERE_NOW();
	struct sta_info *sta = tx->sta;

	if (unlikely(!sta ||
		     ((tx->fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_MGMT &&
		      (tx->fc & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_PROBE_RESP)))
		return TXRX_CONTINUE;

	if (unlikely((sta->flags & WLAN_STA_PS) && !sta->pspoll)) {
		struct ieee80211_tx_packet_data *pkt_data;
#ifdef CONFIG_MAC80211_VERBOSE_PS_DEBUG
		printk(KERN_DEBUG "STA " MAC_FMT " aid %d: PS buffer (entries "
		       "before %d)\n",
		       MAC_ARG(sta->addr), sta->aid,
		       skb_queue_len(&sta->ps_tx_buf));
#endif /* CONFIG_MAC80211_VERBOSE_PS_DEBUG */
		sta->flags |= WLAN_STA_TIM;
		if (tx->local->total_ps_buffered >= TOTAL_MAX_TX_BUFFER)
			purge_old_ps_buffers(tx->local);
		if (skb_queue_len(&sta->ps_tx_buf) >= STA_MAX_TX_BUFFER) {
			struct sk_buff *old = skb_dequeue(&sta->ps_tx_buf);
			if (net_ratelimit()) {
				printk(KERN_DEBUG "%s: STA " MAC_FMT " TX "
				       "buffer full - dropping oldest frame\n",
				       tx->dev->name, MAC_ARG(sta->addr));
			}
			dev_kfree_skb(old);
		} else
			tx->local->total_ps_buffered++;
		/* Queue frame to be sent after STA sends an PS Poll frame */
		if (skb_queue_empty(&sta->ps_tx_buf)) {
			if (tx->local->ops->set_tim)
				tx->local->ops->set_tim(local_to_hw(tx->local),
						       sta->aid, 1);
			if (tx->sdata->bss)
				bss_tim_set(tx->local, tx->sdata->bss, sta->aid);
		}
		pkt_data = (struct ieee80211_tx_packet_data *)tx->skb->cb;
		pkt_data->jiffiess = jiffies;
		skb_queue_tail(&sta->ps_tx_buf, tx->skb);
		return TXRX_QUEUED;
	}
#ifdef CONFIG_MAC80211_VERBOSE_PS_DEBUG
	else if (unlikely(sta->flags & WLAN_STA_PS)) {
		printk(KERN_DEBUG "%s: STA " MAC_FMT " in PS mode, but pspoll "
		       "set -> send frame\n", tx->dev->name,
		       MAC_ARG(sta->addr));
	}
#endif /* CONFIG_MAC80211_VERBOSE_PS_DEBUG */
	sta->pspoll = 0;

	return TXRX_CONTINUE;
}

static inline ieee80211_txrx_result
ieee80211_tx_h_multicast_ps_buf(struct ieee80211_txrx_data *tx)
{
IM_HERE_NOW();
	/* broadcast/multicast frame */
	/* If any of the associated stations is in power save mode,
	 * the frame is buffered to be sent after DTIM beacon frame */
	if ((tx->local->hw.flags & IEEE80211_HW_HOST_BROADCAST_PS_BUFFERING) &&
	    tx->sdata->type != IEEE80211_IF_TYPE_WDS &&
	    tx->sdata->bss && atomic_read(&tx->sdata->bss->num_sta_ps) &&
	    !(tx->fc & IEEE80211_FCTL_ORDER)) {
		if (tx->local->total_ps_buffered >= TOTAL_MAX_TX_BUFFER)
			purge_old_ps_buffers(tx->local);
		if (skb_queue_len(&tx->sdata->bss->ps_bc_buf) >=
		    AP_MAX_BC_BUFFER) {
			if (net_ratelimit()) {
				printk(KERN_DEBUG "%s: BC TX buffer full - "
				       "dropping the oldest frame\n",
				       tx->dev->name);
			}
			dev_kfree_skb(skb_dequeue(&tx->sdata->bss->ps_bc_buf));
		} else
			tx->local->total_ps_buffered++;
		skb_queue_tail(&tx->sdata->bss->ps_bc_buf, tx->skb);
		return TXRX_QUEUED;
	}

	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_tx_h_ps_buf(struct ieee80211_txrx_data *tx)
{
IM_HERE_NOW();
	if (unlikely(tx->u.tx.ps_buffered))
		return TXRX_CONTINUE;

	if (tx->u.tx.unicast)
		return ieee80211_tx_h_unicast_ps_buf(tx);
	else
		return ieee80211_tx_h_multicast_ps_buf(tx);
}

static ieee80211_txrx_result
ieee80211_tx_h_sequence(struct ieee80211_txrx_data *tx)
{
IM_HERE_NOW();
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb_data(tx->skb);

	if (ieee80211_get_hdrlen(le16_to_cpu(hdr->frame_control)) >= 24)
		ieee80211_include_sequence(tx->sdata, hdr);

	return TXRX_CONTINUE;
}

static ieee80211_txrx_result
ieee80211_tx_h_check_assoc(struct ieee80211_txrx_data *tx)
{
IM_HERE_NOW();
#ifdef CONFIG_MAC80211_VERBOSE_DEBUG
	struct sk_buff *skb = tx->skb;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
#endif /* CONFIG_MAC80211_VERBOSE_DEBUG */
	u32 sta_flags;

	if (unlikely(tx->local->sta_scanning != 0) &&
	    ((tx->fc & IEEE80211_FCTL_FTYPE) != IEEE80211_FTYPE_MGMT ||
	     (tx->fc & IEEE80211_FCTL_STYPE) != IEEE80211_STYPE_PROBE_REQ))
		return TXRX_DROP;

	if (tx->u.tx.ps_buffered)
		return TXRX_CONTINUE;

	sta_flags = tx->sta ? tx->sta->flags : 0;

	if (likely(tx->u.tx.unicast)) {
		if (unlikely(!(sta_flags & WLAN_STA_ASSOC) &&
			     tx->sdata->type != IEEE80211_IF_TYPE_IBSS &&
			     (tx->fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA)) {
#ifdef CONFIG_MAC80211_VERBOSE_DEBUG
			printk(KERN_DEBUG "%s: dropped data frame to not "
			       "associated station " MAC_FMT "\n",
			       tx->dev->name, MAC_ARG(hdr->addr1));
#endif /* CONFIG_MAC80211_VERBOSE_DEBUG */
			I802_DEBUG_INC(tx->local->tx_handlers_drop_not_assoc);
			return TXRX_DROP;
		}
	} else {
		if (unlikely((tx->fc & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_DATA &&
			     tx->local->num_sta == 0 &&
			     !tx->local->allow_broadcast_always &&
			     tx->sdata->type != IEEE80211_IF_TYPE_IBSS)) {
			/*
			 * No associated STAs - no need to send multicast
			 * frames.
			 */
			return TXRX_DROP;
		}
		return TXRX_CONTINUE;
	}

	if (unlikely(!tx->u.tx.mgmt_interface && tx->sdata->ieee802_1x &&
		     !(sta_flags & WLAN_STA_AUTHORIZED))) {
#ifdef CONFIG_MAC80211_VERBOSE_DEBUG
		printk(KERN_DEBUG "%s: dropped frame to " MAC_FMT
		       " (unauthorized port)\n", tx->dev->name,
		       MAC_ARG(hdr->addr1));
#endif
		I802_DEBUG_INC(tx->local->tx_handlers_drop_unauth_port);
		return TXRX_DROP;
	}

	return TXRX_CONTINUE;
}

static int ieee80211_tx(struct net_device *dev, struct sk_buff *skb,
			struct ieee80211_tx_control *control, int mgmt)
{
IM_HERE_NOW();
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct sta_info *sta;
	ieee80211_tx_handler *handler;
	struct ieee80211_txrx_data tx;
	ieee80211_txrx_result res = TXRX_DROP, res_prepare;
	int ret, i;

	//WARN_ON(__ieee80211_queue_pending(local, control->queue));

	if (unlikely(skb_len(skb) < 10)) {
		dev_kfree_skb(skb);
		return 0;
	}

	res_prepare = __ieee80211_tx_prepare(&tx, skb, dev, control);

	if (res_prepare == TXRX_DROP) {
		dev_kfree_skb(skb);
		return 0;
	}

	sta = tx.sta;
	tx.u.tx.mgmt_interface = mgmt;
	tx.u.tx.mode = local->hw.conf.mode;

	if (res_prepare == TXRX_QUEUED) { /* if it was an injected packet */
		res = TXRX_CONTINUE;
	} else {
		for (handler = local->tx_handlers; *handler != NULL;
		     handler++) {
			res = (*handler)(&tx);
			if (res != TXRX_CONTINUE)
				break;
		}
	}

	skb = tx.skb; /* handlers are allowed to change skb */

	if (sta)
		sta_info_put(sta);

	if (unlikely(res == TXRX_DROP)) {
		I802_DEBUG_INC(local->tx_handlers_drop);
		goto drop;
	}

	if (unlikely(res == TXRX_QUEUED)) {
		I802_DEBUG_INC(local->tx_handlers_queued);
		return 0;
	}

	if (tx.u.tx.extra_frag) {
		for (i = 0; i < tx.u.tx.num_extra_frag; i++) {
			int next_len, dur;
			struct ieee80211_hdr *hdr =
				(struct ieee80211_hdr *)
				tx.u.tx.extra_frag[i]->mac_data;

			if (i + 1 < tx.u.tx.num_extra_frag) {
				next_len = skb_len(tx.u.tx.extra_frag[i + 1]);
			} else {
				next_len = 0;
				tx.u.tx.rate = tx.u.tx.last_frag_rate;
				tx.u.tx.last_frag_hwrate = tx.u.tx.rate->val;
			}
			dur = ieee80211_duration(&tx, 0, next_len);
			hdr->duration_id = cpu_to_le16(dur);
		}
	}

retry:
	ret = __ieee80211_tx(local, skb, &tx);
	if (ret) {
		struct ieee80211_tx_stored_packet *store =
			&local->pending_packet[control->queue];

		if (ret == IEEE80211_TX_FRAG_AGAIN)
			skb = NULL;
		set_bit(IEEE80211_LINK_STATE_PENDING,
			&local->state[control->queue]);
		//smp_mb();
		/* When the driver gets out of buffers during sending of
		 * fragments and calls ieee80211_stop_queue, there is
		 * a small window between IEEE80211_LINK_STATE_XOFF and
		 * IEEE80211_LINK_STATE_PENDING flags are set. If a buffer
		 * gets available in that window (i.e. driver calls
		 * ieee80211_wake_queue), we would end up with ieee80211_tx
		 * called with IEEE80211_LINK_STATE_PENDING. Prevent this by
		 * continuing transmitting here when that situation is
		 * possible to have happened. */
		if (!__ieee80211_queue_stopped(local, control->queue)) {
			clear_bit(IEEE80211_LINK_STATE_PENDING,
				  &local->state[control->queue]);
			goto retry;
		}
		memcpy(&store->control, control,
		       sizeof(struct ieee80211_tx_control));
		store->skb = skb;
		store->extra_frag = tx.u.tx.extra_frag;
		store->num_extra_frag = tx.u.tx.num_extra_frag;
		store->last_frag_hwrate = tx.u.tx.last_frag_hwrate;
		store->last_frag_rate = tx.u.tx.last_frag_rate;
		store->last_frag_rate_ctrl_probe = tx.u.tx.probe_last_frag;
	}
	return 0;

 drop:
	if (skb)
		dev_kfree_skb(skb);
	for (i = 0; i < tx.u.tx.num_extra_frag; i++)
		if (tx.u.tx.extra_frag[i])
			dev_kfree_skb(tx.u.tx.extra_frag[i]);
	kfree(tx.u.tx.extra_frag);
	return 0;
}

int ieee80211_master_start_xmit(struct sk_buff *skb,
				       struct net_device *dev)
{
IM_HERE_NOW();
	struct ieee80211_tx_control control;
	struct ieee80211_tx_packet_data *pkt_data;
	struct net_device *odev = NULL;
	struct ieee80211_sub_if_data *osdata;
	int headroom;
	int ret;

	/*
	 * copy control out of the skb so other people can use skb->cb
	 */
	pkt_data = (struct ieee80211_tx_packet_data *)skb->cb;
	memset(&control, 0, sizeof(struct ieee80211_tx_control));
IOLog("pkt_data->ifindex %d\n",pkt_data->ifindex);
	if (pkt_data->ifindex)
	{
		odev = dev_get_by_index(pkt_data->ifindex);
	}
//	if (unlikely(odev) /*&& !is_ieee80211_device(odev, dev))*/) {
		//dev_put(odev);
//		odev = NULL;
//	}
	if (unlikely(!odev)) {
//#ifdef CONFIG_MAC80211_VERBOSE_DEBUG
		printk(KERN_DEBUG "%s: Discarded packet with nonexistent "
		       "originating device\n", dev->name);
//#endif
		dev_kfree_skb(skb);
		return 0;
	}
	osdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(odev);

	headroom = osdata->local->tx_headroom + IEEE80211_ENCRYPT_HEADROOM;
	if (skb_headroom(skb) < headroom) {
		if (pskb_expand_head(skb, headroom, 0)) {
			dev_kfree_skb(skb);
			IOLog("pskb_expand_head failed\n");
			//dev_put(odev);
			return 0;
		}
	}

	control.ifindex = odev->ifindex;
	control.type = osdata->type;
	if (pkt_data->req_tx_status)
		control.flags |= IEEE80211_TXCTL_REQ_TX_STATUS;
	if (pkt_data->do_not_encrypt)
		control.flags |= IEEE80211_TXCTL_DO_NOT_ENCRYPT;
	if (pkt_data->requeue)
		control.flags |= IEEE80211_TXCTL_REQUEUE;
	if (pkt_data->ht_queue)
		control.flags |= IEEE80211_TXCTL_HT_MPDU_AGG;

	control.queue = pkt_data->queue;

	ret = ieee80211_tx(odev, skb, &control,
			   control.type == IEEE80211_IF_TYPE_MGMT);
	//dev_put(odev);

	return ret;
}

static ieee80211_tx_handler ieee80211_tx_handlers[] =
{
	ieee80211_tx_h_check_assoc,
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
	ieee80211_tx_h_load_stats,
	NULL
};

struct ieee80211_hw * ieee80211_alloc_hw (size_t priv_data_len,const struct ieee80211_ops *  ops){
IM_HERE_NOW();	
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
	//mdev=(struct net_device*)IOMalloc(sizeof(struct ieee80211_sub_if_data));
	//memset(mdev,0,sizeof(struct ieee80211_sub_if_data));
	
	mdev = alloc_netdev(sizeof(struct ieee80211_sub_if_data),
			    "wmaster1",NULL);//%d", ether_setup);
	if (!mdev) {
		//wiphy_free(wiphy);
		return NULL;
	}

	mdev->ifindex=1;//hack
	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(mdev);
	mdev->ieee80211_ptr = hw_to_local(my_hw);//sdata->wdev;
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

	INIT_DELAYED_WORK(&local->scan_work, ieee80211_sta_scan_work, 11);
	/*init_timer(&local->stat_timer);
	local->stat_timer.function = ieee80211_stat_refresh;
	local->stat_timer.data = (unsigned long) local;*/
	//ieee80211_rx_bss_list_init(mdev);
	spin_lock_init(&local->sta_bss_lock);
	INIT_LIST_HEAD(&local->sta_bss_list);
	
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

	local->tx_pending_tasklet.padding=125;//reserve space in tlink for tx_pending_tasklet
	tasklet_init(&local->tx_pending_tasklet, ieee80211_tx_pending,
		     (unsigned long)local);
	tasklet_disable(&local->tx_pending_tasklet);

	skb_queue_head_init(&local->skb_queue);
	skb_queue_head_init(&local->skb_queue_unreliable);

	local->tasklet.padding=126;//reserve space in tlink for tasklet
	tasklet_init(&local->tasklet,
		     ieee80211_tasklet_handler,
		     (unsigned long) local);
	tasklet_disable(&local->tasklet);
	
	my_hw=local_to_hw(local);

	printf("ieee80211_alloc_hw [OK]\n");
	
	return my_hw;

}

struct sta_info *dls_info_get(struct ieee80211_local *local, u8 *addr)
{
	struct sta_info *sta;

	spin_lock_bh(&local->sta_lock);
	sta = local->sta_hash[STA_HASH(addr)];
	while (sta) {
		if (memcmp(sta->addr, addr, ETH_ALEN) == 0) {
			/*if (!sta->dls_sta) {
				sta = NULL;
				break;
			}*/
			__sta_info_get(sta);
			break;
		}
		sta = sta->hnext;
	}
	spin_unlock_bh(&local->sta_lock);

	return sta;
}

int dls_link_status(struct ieee80211_local *local, u8 *addr)
{
	struct sta_info *dls;
	int ret = 1;//DLS_STATUS_NOLINK;

	if ((dls = dls_info_get(local, addr)) != NULL) {
		ret = 0;//dls->dls_status;
		sta_info_put(dls);
	}
	return ret;
}

int ieee80211_subif_start_xmit(struct sk_buff *skb,
			       struct net_device *dev)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_tx_packet_data *pkt_data;
	struct ieee80211_sub_if_data *sdata;
	int ret = 1, head_need;
	u16 ethertype, hdrlen, fc;
	struct ieee80211_hdr hdr;
	const u8 *encaps_data;
	int encaps_len, skip_header_bytes;
	int nh_pos, h_pos, no_encrypt = 0;
	struct sta_info *sta;

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);
	if (unlikely(skb_len(skb) < ETH_HLEN)) {
		printk(KERN_DEBUG "%s: short skb (len=%d)\n",
		       dev->name, skb_len(skb));
		ret = 0;
		goto fail;
	}

	nh_pos = 0;//skb_network_header(skb) - (u8*)skb_data(skb);
	h_pos = 0;//skb_transport_header(skb) - (u8*)skb_data(skb);

	/* convert Ethernet header to proper 802.11 header (based on
	 * operation mode) */
	//ethertype = (skb->data[12] << 8) | skb->data[13];
	u8 *p0,*p1;
	p0=(u8*)skb_data(skb) +12;
	p1=(u8*)skb_data(skb)+13;
	ethertype = (*p0 << 8) | *p1;
	/* TODO: handling for 802.1x authorized/unauthorized port */
	fc = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA;

	if (likely(sdata->type == IEEE80211_IF_TYPE_AP ||
		   sdata->type == IEEE80211_IF_TYPE_VLAN)) {
		fc |= IEEE80211_FCTL_FROMDS;
		/* DA BSSID SA */
		memcpy(hdr.addr1, skb_data(skb), ETH_ALEN);
		memcpy(hdr.addr2, dev->dev_addr, ETH_ALEN);
		memcpy(hdr.addr3, (u8*)skb_data(skb) + ETH_ALEN, ETH_ALEN);
		hdrlen = 24;
	} else if (sdata->type == IEEE80211_IF_TYPE_WDS) {
		fc |= IEEE80211_FCTL_FROMDS | IEEE80211_FCTL_TODS;
		/* RA TA DA SA */
		memcpy(hdr.addr1, sdata->u.wds.remote_addr, ETH_ALEN);
		memcpy(hdr.addr2, dev->dev_addr, ETH_ALEN);
		memcpy(hdr.addr3, skb_data(skb), ETH_ALEN);
		memcpy(hdr.addr4, (u8*)skb_data(skb) + ETH_ALEN, ETH_ALEN);
		hdrlen = 30;
	} else if (sdata->type == IEEE80211_IF_TYPE_STA) {
		if (dls_link_status(local, (u8*)skb_data(skb)) == 0) {
			/* DA SA BSSID */
			memcpy(hdr.addr1, skb_data(skb), ETH_ALEN);
			memcpy(hdr.addr2, (u8*)skb_data(skb) + ETH_ALEN, ETH_ALEN);
			memcpy(hdr.addr3, sdata->u.sta.bssid, ETH_ALEN);
		} else {
			fc |= IEEE80211_FCTL_TODS;
			/* BSSID SA DA */
			memcpy(hdr.addr1, sdata->u.sta.bssid, ETH_ALEN);
			memcpy(hdr.addr2, (u8*)skb_data(skb) + ETH_ALEN, ETH_ALEN);
			memcpy(hdr.addr3, skb_data(skb), ETH_ALEN);
		}
		hdrlen = 24;
	} else if (sdata->type == IEEE80211_IF_TYPE_IBSS) {
		/* DA SA BSSID */
		memcpy(hdr.addr1, skb_data(skb), ETH_ALEN);
		memcpy(hdr.addr2, (u8*)skb_data(skb) + ETH_ALEN, ETH_ALEN);
		memcpy(hdr.addr3, sdata->u.sta.bssid, ETH_ALEN);
		hdrlen = 24;
	} else {
		ret = 0;
		goto fail;
	}

	/* receiver is QoS enabled, use a QoS type frame */
	sta = sta_info_get(local, hdr.addr1);
	if (sta) {
		if (sta->flags & WLAN_STA_WME) {
			fc |= IEEE80211_STYPE_QOS_DATA;
			hdrlen += 2;
		}
		sta_info_put(sta);
	}

	hdr.frame_control = cpu_to_le16(fc);
	hdr.duration_id = 0;
	hdr.seq_ctrl = 0;

	skip_header_bytes = ETH_HLEN;
	if (ethertype == ETH_P_AARP || ethertype == ETH_P_IPX) {
		encaps_data = bridge_tunnel_header;
		encaps_len = sizeof(bridge_tunnel_header);
		skip_header_bytes -= 2;
	} else if (ethertype >= 0x600) {
		encaps_data = rfc1042_header;
		encaps_len = sizeof(rfc1042_header);
		skip_header_bytes -= 2;
	} else {
		encaps_data = NULL;
		encaps_len = 0;
	}

	skb_pull(skb, skip_header_bytes);
	nh_pos -= skip_header_bytes;
	h_pos -= skip_header_bytes;

	/* TODO: implement support for fragments so that there is no need to
	 * reallocate and copy payload; it might be enough to support one
	 * extra fragment that would be copied in the beginning of the frame
	 * data.. anyway, it would be nice to include this into skb structure
	 * somehow
	 *
	 * There are few options for this:
	 * use skb->cb as an extra space for 802.11 header
	 * allocate new buffer if not enough headroom
	 * make sure that there is enough headroom in every skb by increasing
	 * build in headroom in __dev_alloc_skb() (linux/skbuff.h) and
	 * alloc_skb() (net/core/skbuff.c)
	 */
	head_need = hdrlen + encaps_len + local->tx_headroom;
	head_need -= skb_headroom(skb);

	/* We are going to modify skb data, so make a copy of it if happens to
	 * be cloned. This could happen, e.g., with Linux bridge code passing
	 * us broadcast frames. */

	if (head_need > 0 /*|| skb_cloned(skb)*/) {
#if 1
		printk(KERN_DEBUG "%s: need to reallocate buffer for %d bytes "
		       "of headroom\n", dev->name, head_need);
#endif

		if (1)//skb_cloned(skb))
			I802_DEBUG_INC(local->tx_expand_skb_head_cloned);
		else
			I802_DEBUG_INC(local->tx_expand_skb_head);
		/* Since we have to reallocate the buffer, make sure that there
		 * is enough room for possible WEP IV/ICV and TKIP (8 bytes
		 * before payload and 12 after). */
		if (pskb_expand_head(skb, (head_need > 0 ? head_need + 8 : 8),
				     12)) {
			printk(KERN_DEBUG "%s: failed to reallocate TX buffer"
			       "\n", dev->name);
			goto fail;
		}
	}

	if (encaps_data) {
		memcpy(skb_push(skb, encaps_len), encaps_data, encaps_len);
		nh_pos += encaps_len;
		h_pos += encaps_len;
	}
	memcpy(skb_push(skb, hdrlen), &hdr, hdrlen);
	nh_pos += hdrlen;
	h_pos += hdrlen;

	pkt_data = (struct ieee80211_tx_packet_data *)skb->cb;
	memset(pkt_data, 0, sizeof(struct ieee80211_tx_packet_data));
	sdata->dev->ifindex=2;//hack
	pkt_data->ifindex = dev->ifindex;
	pkt_data->mgmt_iface = (sdata->type == IEEE80211_IF_TYPE_MGMT);
	pkt_data->do_not_encrypt = no_encrypt;

	//skb->dev = local->mdev;
	sdata->stats.tx_packets++;
	sdata->stats.tx_bytes += skb_len(skb);

	/* Update skb pointers to various headers since this modified frame
	 * is going to go through Linux networking code that may potentially
	 * need things like pointer to IP header. */
	//skb_set_mac_header(skb, 0);
	//skb_set_network_header(skb, nh_pos);
	//skb_set_transport_header(skb, h_pos);

	dev->trans_start = jiffies;
	//dev_queue_xmit(skb);
	ieee80211_master_start_xmit(skb,local->mdev);
	return 0;

 fail:
	if (!ret)
		dev_kfree_skb(skb);

	return ret;
}

struct net_device * dev_get_by_index(int index)
{
	struct ieee80211_local *local=hw_to_local(get_my_hw());
	if (!local) return NULL;
	struct net_device *dev=NULL;
	if (index==1) dev=local->mdev;
	if (index==2) dev=local->scan_dev;
	if (index==3) dev=local->apdev;
	return dev;
}

int dev_queue_xmit(struct sk_buff *skb)
{
IM_HERE_NOW();	
	int ret=0;
	struct ieee80211_tx_packet_data *pkt_data = (struct ieee80211_tx_packet_data *)skb->cb;
	struct net_device *dev=dev_get_by_index(pkt_data->ifindex);
	if (!dev) 
	{
		IOLog("no dev\n");
		struct ieee80211_local *local=hw_to_local(get_my_hw());
		//memset(pkt_data, 0, sizeof(struct ieee80211_tx_packet_data));
		pkt_data->ifindex=2;
		dev=local->scan_dev;
	}
	if (pkt_data->ifindex==1) ret=ieee80211_master_start_xmit(skb,dev);
	if (pkt_data->ifindex==2) ret=ieee80211_subif_start_xmit(skb,dev);
	if (pkt_data->ifindex==3) ret=ieee80211_mgmt_start_xmit(skb,dev);
	return ret;
}


int
ieee80211_mgmt_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ieee80211_local *local = wdev_priv(dev->ieee80211_ptr);
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_tx_packet_data *pkt_data;
	struct ieee80211_hdr *hdr;
	u16 fc;

	sdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(dev);

	if (skb_len(skb) < 10) {
		dev_kfree_skb(skb);
		return 0;
	}

	if (skb_headroom(skb) < sdata->local->tx_headroom) {
		if (pskb_expand_head(skb, sdata->local->tx_headroom,
				     0)) {
			dev_kfree_skb(skb);
			return 0;
		}
	}

	hdr = (struct ieee80211_hdr *) skb_data(skb);
	fc = le16_to_cpu(hdr->frame_control);

	pkt_data = (struct ieee80211_tx_packet_data *) skb->cb;
	memset(pkt_data, 0, sizeof(struct ieee80211_tx_packet_data));
	sdata->dev->ifindex=3;//hack
	pkt_data->ifindex = sdata->dev->ifindex;
	pkt_data->mgmt_iface = (sdata->type == IEEE80211_IF_TYPE_MGMT);

	//skb->priority = 20; /* use hardcoded priority for mgmt TX queue */
	//skb->dev = sdata->local->mdev;

	/*
	 * We're using the protocol field of the the frame control header
	 * to request TX callback for hostapd. BIT(1) is checked.
	 */
	if ((fc & BIT(1)) == BIT(1)) {
		pkt_data->req_tx_status = 1;
		fc &= ~BIT(1);
		hdr->frame_control = cpu_to_le16(fc);
	}

	pkt_data->do_not_encrypt = !(fc & IEEE80211_FCTL_PROTECTED);

	sdata->stats.tx_packets++;
	sdata->stats.tx_bytes += skb_len(skb);

	//dev_queue_xmit(skb);
	ieee80211_master_start_xmit(skb,local->mdev);
	
	return 0;
}

int ieee80211_if_add_mgmt(struct ieee80211_local *local)
{
IM_HERE_NOW();
	struct net_device *ndev;
	struct ieee80211_sub_if_data *nsdata;
	int ret;

	//ASSERT_RTNL();

	ndev = alloc_netdev(sizeof(struct ieee80211_sub_if_data), "wmgmt%d",NULL);//,ieee80211_if_mgmt_setup);
	if (!ndev)
		return -ENOMEM;
	/*ret = dev_alloc_name(ndev, ndev->name);
	if (ret < 0)
		goto fail;*/
	
	//memcpy(ndev->dev_addr, local->hw.wiphy->perm_addr, ETH_ALEN);
	memcpy(ndev->dev_addr, my_mac_addr, ETH_ALEN);
	//SET_NETDEV_DEV(ndev, wiphy_dev(local->hw.wiphy));

	ndev->ifindex=3;//hack
	nsdata = (struct ieee80211_sub_if_data*)IEEE80211_DEV_TO_SUB_IF(ndev);
	//ndev->ieee80211_ptr = &nsdata->wdev;
	ndev->ieee80211_ptr = hw_to_local(my_hw);
	//nsdata->wdev.wiphy = local->hw.wiphy;
	nsdata->type = IEEE80211_IF_TYPE_MGMT;
	nsdata->dev = ndev;
	nsdata->local = local;
	ieee80211_if_sdata_init(nsdata);

	/*ret = register_netdevice(ndev);
	if (ret)
		goto fail;*/

	//ieee80211_debugfs_add_netdev(nsdata);

	//if (local->open_count > 0)
	//	dev_open(ndev);
	local->apdev = ndev;
	return 0;

fail:
	//free_netdev(ndev);
	return ret;
}

int pskb_expand_head(struct sk_buff *skb, int size, int reserve)
{
IM_HERE_NOW();
	return 0;
	if (size==0) return 1;
	int ret=mbuf_prepend(&skb->mac_data, size, MBUF_WAITOK);
	IOLog("mbuf_prepend =%d\n",ret);
	if (ret!=0) return 1;
	if (reserve>0) skb_reserve(skb,reserve);
	return 0;
}