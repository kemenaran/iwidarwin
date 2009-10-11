
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

#include "compatibility.h"
#include "net/mac80211.h"

#include "firmware/iwlwifi-1000-3.ucode.h"
#include "firmware/iwlwifi-3945-2.ucode.h"
#include "firmware/iwlwifi-4965-2.ucode.h"
#include "firmware/iwlwifi-5000-2.ucode.h"
#include "firmware/iwlwifi-5150-2.ucode.h"

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
UInt16 my_deviceID;
IOMemoryMap	*				my_map;

ifnet_t						my_fifnet;

static int next_thread=0;
static int thread_pos=0;
static IOLock* thread_lock;
static bool is_unloaded=false;

#define MAX_MUTEXES 256
static struct mutex *mutexes[MAX_MUTEXES];
unsigned long current_mutex = 0;

static u8 my_mac_addr[6];
static struct ieee80211_hw * my_hw;

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

void * get_my_priv(){
	//if(my_hw)
	//	return my_hw->priv;
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
static inline  void skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk)
 {
         unsigned long flags;
 
       //  spin_lock_irqsave(&list->lock, flags);
         __skb_queue_tail(list, newsk);
      //   spin_unlock_irqrestore(&list->lock, flags);
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
static inline struct sk_buff *skb_dequeue(struct sk_buff_head *list)
{
         unsigned long flags;
         struct sk_buff *result;
 
     //    spin_lock_irqsave(&list->lock, flags);
         result = __skb_dequeue(list);
      //   spin_unlock_irqrestore(&list->lock, flags);
         return result;
}

 
static inline struct sk_buff *skb_copy( struct sk_buff *skb, gfp_t gfp_mask)
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
      //  spin_lock_init(&list->lock);
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




static inline void *skb_push(const struct sk_buff *skb, unsigned int len) {
	if (len)
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

static inline int skb_headroom(const struct sk_buff *skb){
	return mbuf_leadingspace(skb->mac_data);
}

static inline struct sk_buff *skb_clone(const struct sk_buff *skb, unsigned int ignored) {
    struct sk_buff *skb_copy = (struct sk_buff *)IOMalloc(sizeof(struct sk_buff));
    mbuf_copym(skb->mac_data, 0, mbuf_len(skb->mac_data), 1, &skb_copy->mac_data);
    skb_copy->intf = skb->intf;
    return skb_copy;
}

static inline void *skb_data(const struct sk_buff *skb) {
    return mbuf_data(skb->mac_data);
}

static inline int skb_set_data(const struct sk_buff *skb, void *data, size_t len) {
   mbuf_setdata(skb->mac_data,data,len);
   mbuf_pkthdr_setlen(skb->mac_data,len);
   mbuf_setlen(skb->mac_data,len);
   return 0;
}

static inline int skb_len(const struct sk_buff *skb) {
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
		 if (len)
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

void dev_kfree_skb(struct sk_buff *skb) {
    IONetworkController *intf = (IONetworkController *)skb->intf;
    if (skb->mac_data)
	if (!(mbuf_type(skb->mac_data) == MBUF_TYPE_FREE))
        intf->freePacket(skb->mac_data);
	skb->mac_data=NULL;
}

void dev_kfree_skb_any(struct sk_buff *skb) {
    //need to free prev,next
	dev_kfree_skb(skb);
}

static inline void kfree_skb(struct sk_buff *skb){
    IONetworkController *intf = (IONetworkController *)skb->intf;
    if (skb->mac_data)
	if (!(mbuf_type(skb->mac_data) == MBUF_TYPE_FREE))
        intf->freePacket(skb->mac_data);
}



struct sk_buff *__alloc_skb(unsigned int size,gfp_t priority, int fclone, int node) {
    struct sk_buff *skb = (struct sk_buff *)IOMalloc(sizeof(struct sk_buff));
    skb->mac_data = currentController->allocatePacket(size);
    skb->intf = (void *)currentController;
	mbuf_setlen(skb->mac_data, 0);
	mbuf_pkthdr_setlen(skb->mac_data,0);
    return skb;
}



	
	
static inline struct sk_buff *__dev_alloc_skb(unsigned int length,
                                               gfp_t gfp_mask)
 {
        //check if work
		  struct sk_buff *skb = alloc_skb(length,1);// + NET_SKB_PAD, 1);
        // if (likely(skb))
          //       skb_reserve(skb, NET_SKB_PAD);
         return skb;
 }

static inline struct sk_buff *dev_alloc_skb(unsigned int length)
 {
         return __dev_alloc_skb(length, GFP_ATOMIC);
 }
 
 


static inline void atomic_inc( atomic_t *v)
{
        v->counter++;
}



static inline bool atomic_dec_and_test( atomic_t *v)
{
        v->counter--;
		if(v->counter <= 0)
			return false;
		return true;
}

static inline void atomic_dec( atomic_t *v)
{
        v->counter--;
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
		//IOLog("timei %d timei2 %d\n",timei,timei2);
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

struct ieee80211_hw * get_my_hw(){
	if(my_hw)
		return my_hw;
	return NULL;
}
	

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

int tasklet_kill(struct tasklet_struct *t){
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

int cancel_delayed_work(struct delayed_work *work) {
	struct work_struct tmp = work->work;
	struct work_struct *tmp2 = &tmp;
	queue_td(tmp2->number,NULL);
    return 0;
}

int cancel_delayed_work_sync(struct delayed_work *work) {
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
		if (timer->on)
		{
		(timer->function)((unsigned long)data);
		IOPCCardAddTimer(timer);
		}
		else
		IOLog("timer is off\n");
	}
	else
		IOLog("Error while lauch timer thread\n");
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



void *dev_get_drvdata(void *p) {
    return p;
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

void release_firmware (	const struct firmware *  fw){
    if( fw )
        IOFree((void *)fw, sizeof(struct firmware));
	return;
}

int request_firmware(const struct firmware ** firmware_p, const char * name, struct device * device){
	struct firmware *firmware;
	*firmware_p = firmware =(struct firmware*) IOMalloc(sizeof(struct firmware));
	
	switch (my_deviceID) {
	case 0x4222:
	case 0x4227:
		firmware->data = (u8*)i3945;
		firmware->size = sizeof(i3945);
		break;
	case 0x4229:
	case 0x4230:
		firmware->data = (u8*)i4965;
		firmware->size = sizeof(i4965);
		break;
	case 0x4232:
	case 0x4235:
	case 0x4236:
	case 0x4237:
	case 0x423A:
	case 0x423B:
		firmware->data = (u8*)i5000;
		firmware->size = sizeof(i5000);
		break;
	case 0x423C:
	case 0x423D:
		firmware->data = (u8*)i5150;
		firmware->size = sizeof(i5150);
		break;
	case 0x0083:
	case 0x0084:
		firmware->data = (u8*)i1000;
		firmware->size = sizeof(i1000);
		break;
	default:
		IOLog("Invalid firmware\n");
		break;
	}
			
	return 0;
}

void interuptsHandler(){
	if(!realHandler){
		printf("No Handler defined\n");
		return;
	}
	//printf("Call the IRQ Handler\n");
	(*realHandler)(1,my_hw->priv);
}
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

ssize_t simple_read_from_buffer(void *to, size_t count, loff_t *ppos, const void *from, size_t available)
{
return 0;//FIXME
}


void wiphy_rfkill_set_hw_state(struct wiphy *wiphy, int blocked)
{
IOLog("TODO: rfkill status\n");	
}


