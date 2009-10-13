
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/network/IONetworkController.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOMapper.h>

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
//#include "net/mac80211.h"

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
//static IOInterruptEventSource *	DMAInterruptSource;
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
static LIST_HEAD(rate_ctrl_algs);




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

void *skb_data(const struct sk_buff *skb) {
    return mbuf_data(skb->mac_data);
}

static inline int skb_set_data(const struct sk_buff *skb, void *data, size_t len) {
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

void mod_timer(struct timer_list2 *timer, int length) {
	del_timer(timer);
	timer->expires = length; 
	timer->on=1;
	add_timer(timer);

}

void del_timer_sync(struct timer_list2 *timer) {
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
    IOPCIDevice *fPCIDevice = my_pci_device;//(IOPCIDevice *)dev->dev.kobj.ptr;
    fPCIDevice->configWrite8(where,val);
    return 0;
}


void SET_IEEE80211_PERM_ADDR (	struct ieee80211_hw *  	hw, 	u8 *  	addr){
	my_mac_addr[0] = addr[0];
	my_mac_addr[1] = addr[1];
	my_mac_addr[2] = addr[2];
	my_mac_addr[3] = addr[3];
	my_mac_addr[4] = addr[4];
	my_mac_addr[5] = addr[5];
	//memcpy(hw->wiphy->perm_addr, addr, ETH_ALEN);
}

void pci_release_regions (struct pci_dev * pdev){
	return;
}
/*
	get the priv...
*/

static inline void *dev_get_drvdata(struct device *dev)
 {
         return dev->driver_data;
 }

void *pci_get_drvdata (struct pci_dev *pdev){
	//return my_hw->priv;
	return dev_get_drvdata(&pdev->dev);
}

static inline void dev_set_drvdata(struct device *dev, void *data)
 {
         dev->driver_data = data;
 }

void pci_set_drvdata (struct pci_dev *pdev, void *data){
	dev_set_drvdata(&pdev->dev, data);
}
//ok
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




void *pci_alloc_consistent(struct pci_dev *hwdev, size_t size,dma_addr_t *dma_handle) {
	size = RT_ALIGN_Z(size, PAGE_SIZE);
	return IOMallocContiguous(size,PAGE_SIZE, dma_handle);
}

void __iomem * pci_iomap (	struct pci_dev *  	dev,int  	bar,unsigned long  	maxlen){
	IOMemoryMap	*				map;
	IOPCIDevice *fPCIDevice = my_pci_device;//(IOPCIDevice *)dev->dev.kobj.ptr;
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
    //IODirection mydir = (IODirection) direction;
    //IOMemoryDescriptor::withPhysicalAddress(dma_addr, size, mydir)->complete(mydir);
    //IOMemoryDescriptor::withPhysicalAddress(dma_addr,size, mydir)->release();
	dma_addr=NULL;
}

addr64_t pci_map_single(struct pci_dev *hwdev, void *ptr, size_t size, int direction) {
	//IOMemoryDescriptor::withAddress(ptr,size,kIODirectionOutIn)->complete(kIODirectionOutIn);
	addr64_t tmp = mbuf_data_to_physical( (u8*)ptr)+size;
	return tmp;
}


int pci_read_config_byte(struct pci_dev *dev, int where, u8 *val) {
    IOPCIDevice *fPCIDevice = my_pci_device;//(IOPCIDevice *)dev->dev.kobj.ptr;
    *val = fPCIDevice->configRead8(where);
    return 0;
}

int pci_read_config_word(struct pci_dev *dev, int where, u16 *val) {
    IOPCIDevice *fPCIDevice = my_pci_device;//(IOPCIDevice *)dev->dev.kobj.ptr;
    *val = fPCIDevice->configRead16(where);
    return 0;
}

int pci_read_config_dword(struct pci_dev *dev, int where, u32 *val) {
    IOPCIDevice *fPCIDevice = my_pci_device;//(IOPCIDevice *)dev->dev.kobj.ptr;
    *val = fPCIDevice->configRead32(where);
    return 0;
}



int pci_pme_capable(struct pci_dev *dev, u8 where) {
    IOPCIDevice *fPCIDevice = my_pci_device;//(IOPCIDevice *)dev->dev.kobj.ptr;
    u8 *val;
	int ret=fPCIDevice->findPCICapability(where,val);
    return ret;
}

int pci_find_capability(struct pci_dev *dev, u8 where) {
    IOPCIDevice *fPCIDevice = my_pci_device;//(IOPCIDevice *)dev->dev.kobj.ptr;
    u8 *val;
	fPCIDevice->findPCICapability(where,val);
    return *val;
}



void pci_dma_sync_single_for_cpu(struct pci_dev *hwdev, dma_addr_t dma_handle, size_t size, int direction){
	//IOMemoryDescriptor::withPhysicalAddress(dma_handle,size,kIODirectionOutIn)->complete();
	return;
}

int pci_write_config_word(struct pci_dev *dev, int where, u16 val){
    IOPCIDevice *fPCIDevice = my_pci_device;//(IOPCIDevice *)dev->dev.kobj.ptr;
    fPCIDevice->configWrite16(where,val);
    return 0;
}


int pci_enable_msi  (struct pci_dev * dev){
	return 0;
}

int pci_enable_device (struct pci_dev * dev){
	/*if(!dev){
		printf("No pci_dev defined\n");
		return 1;
	}
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;*/
	printf("PCI device enabled [OK]\n");
	return 0;
}

void pci_disable_device (struct pci_dev * dev){
	//IOPCIDevice *fPCIDevice = (IOPCIDevice *)dev->dev.kobj.ptr;
}


int pci_register_driver(struct pci_driver * drv){
	if(!thread_lock)
		thread_lock = IOLockAlloc();
	if(!drv)
		return -6;
	my_drv=drv;
	//maybe get the pointer for the good function as iwl3945_pci_probe ...
	struct pci_device_id *test=(struct pci_device_id*)drv->id_table;//(struct pci_device_id *)IOMalloc(sizeof(struct pci_device_id));
	struct pci_dev *test_pci=(struct pci_dev *)IOMalloc(sizeof(struct pci_dev));
	
	if(!currentController){
		printf("No currentController set\n");
		return 1;
	}

	test_pci->dev.kobj.ptr=OSDynamicCast(IOPCIDevice, currentController->getProvider());
	IOPCIDevice *fPCIDevice = (IOPCIDevice *)test_pci->dev.kobj.ptr;

//	fPCIDevice->retain();
//	fPCIDevice->open(currentController);
//	fPCIDevice->requestPowerDomainState(kIOPMPowerOn, (IOPowerConnection *) currentController->getParentEntry(gIOPowerPlane),IOPMLowestState );
	UInt16 reg16;
	reg16 = fPCIDevice->configRead16(kIOPCIConfigCommand);
	reg16 |= (kIOPCICommandBusMaster      |kIOPCICommandMemorySpace    |kIOPCICommandMemWrInvalidate);

	reg16 &= ~kIOPCICommandIOSpace;  // disable I/O space
	fPCIDevice->configWrite16(kIOPCIConfigCommand,reg16);
		
	//fPCIDevice->configWrite8(kIOPCIConfigLatencyTimer,0x64);
	
	/* We disable the RETRY_TIMEOUT register (0x41) to keep
	 * PCI Tx retries from interfering with C3 CPU state */
//	UInt16 reg = fPCIDevice->configRead16(0x40);
//	if((reg & 0x0000ff00) != 0)
//		fPCIDevice->configWrite16(0x40, reg & 0xffff00ff);

	//fPCIDevice->setBusMasterEnable(true);
	//fPCIDevice->setMemoryEnable(true);

	int r = (drv->probe) (test_pci,test);

	if(r)
		IOLog("Error drv->probe\n");

	/*if (r) return r;
	
	struct ieee80211_local *local =hw_to_local(my_hw);
	r=ieee80211_open(local->scan_dev);*/

	return r;
}

static inline void setup_timer(struct timer_list2 * timer,
                                 void (*function)(unsigned long),
                                 unsigned long data)
 {
	init_timer(timer);
	timer->function = function;
    timer->data = data;
    add_timer(timer);//hack
 }

#define STA_INFO_CLEANUP_INTERVAL (10 * HZ)


static void kref_init(struct kref *kref)
  {
          //WARN_ON(release == NULL);
          atomic_set(&kref->refcount,1);
  }

static  struct kref *kref_get(struct kref *kref)
{
          //WARN_ON(!atomic_read(&kref->refcount));
          atomic_inc(&kref->refcount);
          return kref;
}
 
 
 static inline struct ieee80211_local *hw_to_local(struct ieee80211_hw *hw)
{
	 return container_of(hw, struct ieee80211_local, hw);
}
struct ieee80211_sub_if_data *vif_to_sdata(struct ieee80211_vif *p)
 {
         return container_of(p, struct ieee80211_sub_if_data, vif);
 }
 
int sta_info_start(struct ieee80211_local *local)
 {
         add_timer(&local->sta_cleanup);
         return 0;
 }

static struct rate_control_ops *
ieee80211_try_rate_control_ops_get(const char *name)
{
	struct rate_control_alg *alg;
	struct rate_control_ops *ops = NULL;

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
         struct dentry *debugfsdir = NULL;
         struct rate_control_ref *ref;
 
         ref = (struct rate_control_ref*)kmalloc(sizeof(struct rate_control_ref), GFP_KERNEL);
         if (!ref)
                 goto fail_ref;
         kref_init(&ref->kref);
         ref->local = local;
         ref->ops = ieee80211_rate_control_ops_get(name);
         if (!ref->ops)
                 goto fail_ops;
 
 #ifdef CONFIG_MAC80211_DEBUGFS
         debugfsdir = debugfs_create_dir("rc", local->hw.wiphy->debugfsdir);
         local->debugfs.rcdir = debugfsdir;
         local->debugfs.rcname = debugfs_create_file("name", 0400, debugfsdir,
                                                     ref, &rcname_ops);
 #endif
 
         ref->priv = ref->ops->alloc(&local->hw, debugfsdir);
         if (!ref->priv)
                 goto fail_priv;
         return ref;
 
 fail_priv:
        // ieee80211_rate_control_ops_put(ref->ops);
 fail_ops:
         kfree(ref);
 fail_ref:
     return NULL;
}

static  void kref_put(struct kref *kref, void (*release)(struct kref *kref))
{
		if (atomic_dec_and_test(&kref->refcount)) {
			//IOLog("kref cleaning up\n");
			kref=NULL;
			//release(kref);
		} 
} 

static void rate_control_release(struct kref *kref)
 {
         struct rate_control_ref *ctrl_ref;
 
         ctrl_ref = container_of(kref, struct rate_control_ref, kref);
         ctrl_ref->ops->free(ctrl_ref->priv);
 
 #ifdef CONFIG_MAC80211_DEBUGFS
         debugfs_remove(ctrl_ref->local->debugfs.rcname);
         ctrl_ref->local->debugfs.rcname = NULL;
         debugfs_remove(ctrl_ref->local->debugfs.rcdir);
         ctrl_ref->local->debugfs.rcdir = NULL;
 #endif
 
         //ieee80211_rate_control_ops_put(ctrl_ref->ops);
         kfree(ctrl_ref);
 }

void rate_control_put(struct rate_control_ref *ref)
 {
         kref_put(&ref->kref, rate_control_release);
 }

static int sta_info_hash_del(struct ieee80211_local *local,
                               struct sta_info *sta)
  {
          struct sta_info *s;
  
          s = local->sta_hash[STA_HASH(sta->sta.addr)];
          if (!s)
                  return -ENOENT;
          if (s == sta) {
                  rcu_assign_pointer(local->sta_hash[STA_HASH(sta->sta.addr)],
                                     s->hnext);
                  return 0;
          }
  
          while (s->hnext && s->hnext != sta)
                  s = s->hnext;
          if (s->hnext) {
                  rcu_assign_pointer(s->hnext, sta->hnext);
                  return 0;
         }
 
         return -ENOENT;
 }

static inline u32 test_and_clear_sta_flags(struct sta_info *sta,
                                            const u32 flags)
 {
         u32 ret;
         unsigned long irqfl;
 
         spin_lock_irqsave(&sta->flaglock, irqfl);
         ret = sta->flags & flags;
         sta->flags &= ~flags;
         spin_unlock_irqrestore(&sta->flaglock, irqfl);
 
         return ret;
 }

static void __sta_info_unlink(struct sta_info **sta)
 {
         struct ieee80211_local *local = (*sta)->local;
         struct ieee80211_sub_if_data *sdata = (*sta)->sdata;
         /*
          * pull caller's reference if we're already gone.
          */
         if (sta_info_hash_del(local, *sta)) {
                 *sta = NULL;
                 return;
         }
 
       /*  if ((*sta)->key) {
                 ieee80211_key_free((*sta)->key);
                 WARN_ON((*sta)->key);
         }*/
 
         list_del(&(*sta)->list);
 
         if (test_and_clear_sta_flags(*sta, WLAN_STA_PS)) {
                 BUG_ON(!sdata->bss);
 
                 atomic_dec(&sdata->bss->num_sta_ps);
         //        __sta_info_clear_tim_bit(sdata->bss, *sta);
         }
 
         local->num_sta--;
         local->sta_generation++;
 
         if (local->ops->sta_notify) {
                 if (sdata->vif.type == NL80211_IFTYPE_AP_VLAN)
                         sdata = container_of(sdata->bss,
                                              struct ieee80211_sub_if_data,
                                              u.ap);
 
    //             drv_sta_notify(local, &sdata->vif, STA_NOTIFY_REMOVE,
      //                          &(*sta)->sta);
         }
 
     //    if (ieee80211_vif_is_mesh(&sdata->vif)) {
       //          mesh_accept_plinks_update(sdata);
 #ifdef CONFIG_MAC80211_MESH
                 del_timer(&(*sta)->plink_timer);
 #endif
        // }
 
 #ifdef CONFIG_MAC80211_VERBOSE_DEBUG
         printk(KERN_DEBUG "%s: Removed STA %pM\n",
                wiphy_name(local->hw.wiphy), (*sta)->sta.addr);
 #endif /* CONFIG_MAC80211_VERBOSE_DEBUG */
 
         /*
          * Finally, pull caller's reference if the STA is pinned by the
          * task that is adding the debugfs entries. In that case, we
          * leave the STA "to be freed".
          *
          * The rules are not trivial, but not too complex either:
          *  (1) pin_status is only modified under the sta_lock
          *  (2) STAs may only be pinned under the RTNL so that
          *      sta_info_flush() is guaranteed to actually destroy
          *      all STAs that are active for a given interface, this
          *      is required for correctness because otherwise we
          *      could notify a driver that an interface is going
          *      away and only after that (!) notify it about a STA
          *      on that interface going away.
          *  (3) sta_info_debugfs_add_work() will set the status
          *      to PINNED when it found an item that needs a new
          *      debugfs directory created. In that case, that item
          *      must not be freed although all *RCU* users are done
          *      with it. Hence, we tell the caller of _unlink()
          *      that the item is already gone (as can happen when
          *      two tasks try to unlink/destroy at the same time)
          *  (4) We set the pin_status to DESTROY here when we
          *      find such an item.
          *  (5) sta_info_debugfs_add_work() will reset the pin_status
          *      from PINNED to NORMAL when it is done with the item,
*      but will check for DESTROY before resetting it in
          *      which case it will free the item.
          */
         if ((*sta)->pin_status == STA_INFO_PIN_STAT_PINNED) {
                 (*sta)->pin_status = STA_INFO_PIN_STAT_DESTROY;
                 *sta = NULL;
                 return;
         }
 }

static inline void rate_control_free_sta(struct sta_info *sta)
  {
          struct rate_control_ref *ref = sta->rate_ctrl;
          struct ieee80211_sta *ista = &sta->sta;
          void *priv_sta = sta->rate_ctrl_priv;
  
          ref->ops->free_sta(ref->priv, ista, priv_sta);
  }
 

static void __sta_info_free(struct ieee80211_local *local,
                             struct sta_info *sta)
 {
         rate_control_free_sta(sta);
         rate_control_put(sta->rate_ctrl);
 
 #ifdef CONFIG_MAC80211_VERBOSE_DEBUG
         printk(KERN_DEBUG "%s: Destroyed STA %pM\n",
                wiphy_name(local->hw.wiphy), sta->sta.addr);
 #endif /* CONFIG_MAC80211_VERBOSE_DEBUG */
 
         kfree(sta);
 }

 void sta_info_destroy(struct sta_info *sta)
 {
         struct ieee80211_local *local;
         struct sk_buff *skb;
         int i;
 
       //  might_sleep();
 
         if (!sta)
                 return;
 
        local = sta->local;
 
  //       rate_control_remove_sta_debugfs(sta);
    //     ieee80211_sta_debugfs_remove(sta);
 
 #ifdef CONFIG_MAC80211_MESH
         if (ieee80211_vif_is_mesh(&sta->sdata->vif))
                 mesh_plink_deactivate(sta);
 #endif
 
         /*
          * We have only unlinked the key, and actually destroying it
          * may mean it is removed from hardware which requires that
          * the key->sta pointer is still valid, so flush the key todo
          * list here.
          *
          * ieee80211_key_todo() will synchronize_rcu() so after this
          * nothing can reference this sta struct any more.
          */
    //     ieee80211_key_todo();
 
 #ifdef CONFIG_MAC80211_MESH
         if (ieee80211_vif_is_mesh(&sta->sdata->vif))
                 del_timer_sync(&sta->plink_timer);
 #endif
 
         while ((skb = skb_dequeue(&sta->ps_tx_buf)) != NULL) {
                 local->total_ps_buffered--;
                 dev_kfree_skb_any(skb);
         }
 
         while ((skb = skb_dequeue(&sta->tx_filtered)) != NULL)
                 dev_kfree_skb_any(skb);
 
         for (i = 0; i <  STA_TID_NUM; i++) {
                 struct tid_ampdu_rx *tid_rx;
                 struct tid_ampdu_tx *tid_tx;
 
             //    spin_lock_bh(&sta->lock);
                 tid_rx = NULL;//sta->ampdu_mlme.tid_rx[i];
                 /* Make sure timer won't free the tid_rx struct, see below */
                 if (tid_rx)
                         tid_rx->shutdown = true;
 
              //   spin_unlock_bh(&sta->lock);
 
                 /*
                  * Outside spinlock - shutdown is true now so that the timer
                  * won't free tid_rx, we have to do that now. Can't let the
                  * timer do it because we have to sync the timer outside the
                  * lock that it takes itself.
                  */
                 if (tid_rx) {
                         del_timer_sync(&tid_rx->session_timer);
                         kfree(tid_rx);
                 }
 
                 /*
                  * No need to do such complications for TX agg sessions, the
                  * path leading to freeing the tid_tx struct goes via a call
                  * from the driver, and thus needs to look up the sta struct
                  * again, which cannot be found when we get here. Hence, we
                  * just need to delete the timer and free the aggregation
                  * info; we won't be telling the peer about it then but that
                  * doesn't matter if we're not talking to it again anyway.
                  */
                 tid_tx = NULL;//sta->ampdu_mlme.tid_tx[i];
                 if (tid_tx) {
                         del_timer_sync(&tid_tx->addba_resp_timer);
                         /*
                          * STA removed while aggregation session being
                          * started? Bit odd, but purge frames anyway.
                          */
                      //   skb_queue_purge(&tid_tx->pending);
                         kfree(tid_tx);
                 }
         }
 
         __sta_info_free(local, sta);
 }

int sta_info_flush(struct ieee80211_local *local,
                    struct ieee80211_sub_if_data *sdata)
 {
         struct sta_info *sta, *tmp;
         LIST_HEAD(tmp_list);
         int ret = 0;
         unsigned long flags;
 
        // might_sleep();
 
         spin_lock_irqsave(&local->sta_lock, flags);
         list_for_each_entry_safe(sta, tmp, &local->sta_list, list) {
                 if (!sdata || sdata == sta->sdata) {
                         __sta_info_unlink(&sta);
                         if (sta) {
                                 list_add_tail(&sta->list, &tmp_list);
                                 ret++;
                         }
                 }
         }
         spin_unlock_irqrestore(&local->sta_lock, flags);
 
         list_for_each_entry_safe(sta, tmp, &tmp_list, list)
                 sta_info_destroy(sta);
 
         return ret;
 }
 
int ieee80211_init_rate_ctrl_alg(struct ieee80211_local *local,
                                  const char *name)
 {
         struct rate_control_ref *ref, *old;
 
       //  ASSERT_RTNL();
         if (local->open_count)
                 return -EBUSY;
 
         ref = rate_control_alloc(name, local);
         if (!ref) {
                 printk(KERN_WARNING "%s: Failed to select rate control "
                        "algorithm\n", wiphy_name(local->hw.wiphy));
                 return -ENOENT;
         }
 
         old = local->rate_ctrl;
         local->rate_ctrl = ref;
         if (old) {
                 rate_control_put(old);
                 sta_info_flush(local, NULL);
         }
 
         printk(KERN_DEBUG "%s: Selected rate control "
                "algorithm '%s'\n", wiphy_name(local->hw.wiphy),
                ref->ops->name);
 
 
         return 0;
 }

static void ieee80211_if_setup(struct net_device *dev)
 {
        // ether_setup(dev);
       //  dev->netdev_ops = &ieee80211_dataif_ops;
        // dev->destructor = free_netdev;
 }

static void *netdev_priv(struct net_device *dev)
{
	return (char *)dev + ((sizeof(struct net_device*)+ NETDEV_ALIGN_CONST)& ~NETDEV_ALIGN_CONST);
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
 
 #define CRCPOLY_BE 0x04c11db7
 u32 crc32_be(u32 crc, unsigned char const *p, size_t len)
 {
         int i;
         while (len--) {
                 crc ^= *p++ << 24;
                 for (i = 0; i < 8; i++)
                         crc =
                             (crc << 1) ^ ((crc & 0x80000000) ? CRCPOLY_BE :
                                           0);
         }
         return crc;
 }

static const u64 care_about_ies =
         (1ULL << WLAN_EID_COUNTRY) |
         (1ULL << WLAN_EID_ERP_INFO) |
         (1ULL << WLAN_EID_CHANNEL_SWITCH) |
         (1ULL << WLAN_EID_PWR_CONSTRAINT) |
         (1ULL << WLAN_EID_HT_CAPABILITY) |
         (1ULL << WLAN_EID_HT_INFORMATION);


u32 ieee802_11_parse_elems_crc(u8 *start, size_t len,
                                struct ieee802_11_elems *elems,
                                u64 filter, u32 crc)
 {
         size_t left = len;
         u8 *pos = start;
         bool calc_crc = filter != 0;
 
         memset(elems, 0, sizeof(*elems));
         elems->ie_start = start;
         elems->total_len = len;
 
         while (left >= 2) {
                 u8 id, elen;
 
                 id = *pos++;
                 elen = *pos++;
                 left -= 2;
 
                 if (elen > left)
                         break;
 
                 if (calc_crc && id < 64 && (filter & BIT(id)))
                         crc = crc32_be(crc, pos - 2, elen + 2);
 
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
                         if (elen >= sizeof(struct ieee80211_tim_ie)) {
                                 elems->tim = (struct ieee80211_tim_ie *)pos;
                                 elems->tim_len = elen;
                         }
                         break;
                 case WLAN_EID_IBSS_PARAMS:
                         elems->ibss_params = pos;
                         elems->ibss_params_len = elen;
                         break;
                 case WLAN_EID_CHALLENGE:
                         elems->challenge = pos;
                         elems->challenge_len = elen;
                         break;
                 case WLAN_EID_VENDOR_SPECIFIC:
                         if (elen >= 4 && pos[0] == 0x00 && pos[1] == 0x50 &&
                             pos[2] == 0xf2) {
                                 /* Microsoft OUI (00:50:F2) */
 
                                 if (calc_crc)
                                         crc = crc32_be(crc, pos - 2, elen + 2);
 
                                 if (pos[3] == 1) {
                                         /* OUI Type 1 - WPA IE */
                                         elems->wpa = pos;
                                         elems->wpa_len = elen;
                                 } else if (elen >= 5 && pos[3] == 2) {
                                         /* OUI Type 2 - WMM IE */
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
                 case WLAN_EID_HT_CAPABILITY:
                         if (elen >= sizeof(struct ieee80211_ht_cap))
                                 elems->ht_cap_elem = (struct ieee80211_ht_cap *)pos;
                         break;
                 case WLAN_EID_HT_INFORMATION:
                         if (elen >= sizeof(struct ieee80211_ht_info))
                                 elems->ht_info_elem = (struct ieee80211_ht_info *)pos;
                         break;
                 case WLAN_EID_MESH_ID:
                         elems->mesh_id = pos;
                         elems->mesh_id_len = elen;
                         break;
                 case WLAN_EID_MESH_CONFIG:
                         elems->mesh_config = pos;
                         elems->mesh_config_len = elen;
                         break;
                 case WLAN_EID_PEER_LINK:
                         elems->peer_link = pos;
                         elems->peer_link_len = elen;
                         break;
                 case WLAN_EID_PREQ:
                         elems->preq = pos;
                         elems->preq_len = elen;
                         break;
                case WLAN_EID_PREP:
                         elems->prep = pos;
                         elems->prep_len = elen;
                         break;
                 case WLAN_EID_PERR:
                         elems->perr = pos;
                         elems->perr_len = elen;
                         break;
                 case WLAN_EID_CHANNEL_SWITCH:
                         elems->ch_switch_elem = pos;
                        elems->ch_switch_elem_len = elen;
                         break;
                 case WLAN_EID_QUIET:
                         if (!elems->quiet_elem) {
                                 elems->quiet_elem = pos;
                                 elems->quiet_elem_len = elen;
                         }
                         elems->num_of_quiet_elem++;
                         break;
                 case WLAN_EID_COUNTRY:
                         elems->country_elem = pos;
                         elems->country_elem_len = elen;
                         break;
                 case WLAN_EID_PWR_CONSTRAINT:
                         elems->pwr_constr_elem = pos;
                         elems->pwr_constr_elem_len = elen;
                         break;
                 case WLAN_EID_TIMEOUT_INTERVAL:
                         elems->timeout_int = pos;
                         elems->timeout_int_len = elen;
                         break;
                 default:
                        break;
                 }
 
                 left -= elen;
                 pos += elen;
         }
 
         return crc;
 }

static void ieee80211_rx_bss_free(struct cfg80211_bss *cbss)
  {
          struct ieee80211_bss *bss = (struct ieee80211_bss *)cbss;
  
          kfree(bss_mesh_id(bss));
          kfree(bss_mesh_cfg(bss));
  }
 
struct ieee80211_bss *
  ieee80211_bss_info_update(struct ieee80211_local *local,
                            struct ieee80211_rx_status *rx_status,
                            struct ieee80211_mgmt *mgmt,
                            size_t len,
                            struct ieee802_11_elems *elems,
                            struct ieee80211_channel *channel,
                            bool beacon)
  {
          struct ieee80211_bss *bss;
          int clen;
          s32 signal = 0;
  
          if (local->hw.flags & IEEE80211_HW_SIGNAL_DBM)
                  signal = rx_status->signal * 100;
          else if (local->hw.flags & IEEE80211_HW_SIGNAL_UNSPEC)
                  signal = (rx_status->signal * 100) / local->hw.max_signal;
  
         // bss = (struct ieee80211_bss *)cfg80211_inform_bss_frame(local->hw.wiphy, channel,
            //                                      mgmt, len, signal, GFP_ATOMIC);
  
          if (!bss)
                  return NULL;
  
          bss->cbss.free_priv = ieee80211_rx_bss_free;
  
          /* save the ERP value so that it is available at association time */
          if (elems->erp_info && elems->erp_info_len >= 1) {
                  bss->erp_value = elems->erp_info[0];
                  bss->has_erp_value = 1;
          }
  
          if (elems->tim) {
                 struct ieee80211_tim_ie *tim_ie =
                          (struct ieee80211_tim_ie *)elems->tim;
                  bss->dtim_period = tim_ie->dtim_period;
          }
  
          /* set default value for buggy AP/no TIM element */
          if (bss->dtim_period == 0)
                  bss->dtim_period = 1;
  
          bss->supp_rates_len = 0;
          if (elems->supp_rates) {
                  clen = IEEE80211_MAX_SUPP_RATES - bss->supp_rates_len;
                 if (clen > elems->supp_rates_len)
                         clen = elems->supp_rates_len;
                 memcpy(&bss->supp_rates[bss->supp_rates_len], elems->supp_rates,
                        clen);
                 bss->supp_rates_len += clen;
         }
         if (elems->ext_supp_rates) {
                 clen = IEEE80211_MAX_SUPP_RATES - bss->supp_rates_len;
                 if (clen > elems->ext_supp_rates_len)
                         clen = elems->ext_supp_rates_len;
                 memcpy(&bss->supp_rates[bss->supp_rates_len],
                        elems->ext_supp_rates, clen);
                 bss->supp_rates_len += clen;
         }
 
         bss->wmm_used = elems->wmm_param || elems->wmm_info;
 
         if (!beacon)
                 bss->last_probe_resp = jiffies;
 
         return bss;
 }

static void bss_release(struct kref *ref)
  {
          struct cfg80211_internal_bss *bss;
  
          bss = container_of(ref, struct cfg80211_internal_bss, ref);
        if (bss->pub.free_priv)
                 bss->pub.free_priv(&bss->pub);
 
         if (bss->ies_allocated)
                 kfree(bss->pub.information_elements);
 
         BUG_ON(atomic_read(&bss->hold));
 
         kfree(bss);
 }

void cfg80211_put_bss(struct cfg80211_bss *pub)
 {
         struct cfg80211_internal_bss *bss;
 
         if (!pub)
                 return;
 
         bss = container_of(pub, struct cfg80211_internal_bss, pub);
         kref_put(&bss->ref, bss_release);
 }

void ieee80211_rx_bss_put(struct ieee80211_local *local,
                           struct ieee80211_bss *bss)
 {
          cfg80211_put_bss((struct cfg80211_bss *)bss);
  }
 
 
 void ieee80211_sta_process_chanswitch(struct ieee80211_sub_if_data *sdata,
                                       struct ieee80211_channel_sw_ie *sw_elem,
                                       struct ieee80211_bss *bss)
 {
         struct ieee80211_channel *new_ch;
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         int new_freq = ieee80211_channel_to_frequency(sw_elem->new_ch_num);
 
       //  ASSERT_MGD_MTX(ifmgd);
 
         if (!ifmgd->associated)
                 return;
 
         if (sdata->local->scanning)
                 return;
 
         /* Disregard subsequent beacons if we are already running a timer
            processing a CSA */
 
         if (ifmgd->flags & IEEE80211_STA_CSA_RECEIVED)
                return;
 
        // new_ch = ieee80211_get_channel(sdata->local->hw.wiphy, new_freq);
         if (!new_ch || new_ch->flags & IEEE80211_CHAN_DISABLED)
                 return;
 
         sdata->local->csa_channel = new_ch;
 
        if (sw_elem->count <= 1) {
                // ieee80211_queue_work(&sdata->local->hw, &ifmgd->chswitch_work);
         } else {
               //  ieee80211_stop_queues_by_reason(&sdata->local->hw,
                 //                        IEEE80211_QUEUE_STOP_REASON_CSA);
                 //ifmgd->flags |= IEEE80211_STA_CSA_RECEIVED;
                 mod_timer(&ifmgd->chswitch_timer, msecs_to_jiffies(sw_elem->count *bss->cbss.beacon_interval));
         }
 }

static void ieee80211_rx_bss_info(struct ieee80211_sub_if_data *sdata,
                                   struct ieee80211_mgmt *mgmt,
                                   size_t len,
                                   struct ieee80211_rx_status *rx_status,
                                   struct ieee802_11_elems *elems,
                                   bool beacon)
 {
         struct ieee80211_local *local = sdata->local;
         int freq;
         struct ieee80211_bss *bss;
         struct ieee80211_channel *channel;
 
         if (elems->ds_params && elems->ds_params_len == 1)
                 freq = ieee80211_channel_to_frequency(elems->ds_params[0]);
         else
                 freq = rx_status->freq;
 
        // channel = ieee80211_get_channel(local->hw.wiphy, freq);
 
         if (!channel || channel->flags & IEEE80211_CHAN_DISABLED)
                 return;
 
         bss = ieee80211_bss_info_update(local, rx_status, mgmt, len, elems,
                                         channel, beacon);
         if (bss)
                 ieee80211_rx_bss_put(local, bss);
 
         if (!sdata->u.mgd.associated)
                 return;
 
         if (elems->ch_switch_elem && (elems->ch_switch_elem_len == 3) &&
             (memcmp(mgmt->bssid, sdata->u.mgd.associated->cbss.bssid,
                                                         ETH_ALEN) == 0)) {
                 struct ieee80211_channel_sw_ie *sw_elem =
                         (struct ieee80211_channel_sw_ie *)elems->ch_switch_elem;
                 ieee80211_sta_process_chanswitch(sdata, sw_elem, bss);
         }
 }

static int ecw2cw(int ecw)
 {
         return (1 << ecw) - 1;
 }

static inline int drv_conf_tx(struct ieee80211_local *local, u16 queue,
                               const struct ieee80211_tx_queue_params *params)
 {
         int ret = -EOPNOTSUPP;
         if (local->ops->conf_tx)
                 ret = local->ops->conf_tx(&local->hw, queue, params);
       //  trace_drv_conf_tx(local, queue, params, ret);
         return ret;
 }

static void ieee80211_sta_wmm_params(struct ieee80211_local *local,
                                      struct ieee80211_if_managed *ifmgd,
                                      u8 *wmm_param, size_t wmm_param_len)
 {
         struct ieee80211_tx_queue_params params;
         size_t left;
         int count;
         u8 *pos;
 
        if (!(ifmgd->flags & IEEE80211_STA_WMM_ENABLED))
                return;
 
         if (!wmm_param)
                 return;
 
         if (wmm_param_len < 8 || wmm_param[5] /* version */ != 1)
                 return;
         count = wmm_param[6] & 0x0f;
         if (count == ifmgd->wmm_last_param_set)
                 return;
         ifmgd->wmm_last_param_set = count;
 
         pos = wmm_param + 8;
         left = wmm_param_len - 8;
 
         memset(&params, 0, sizeof(params));
 
         local->wmm_acm = 0;
         for (; left >= 4; left -= 4, pos += 4) {
                 int aci = (pos[0] >> 5) & 0x03;
                 int acm = (pos[0] >> 4) & 0x01;
                 int queue;
 
                 switch (aci) {
                 case 1: /* AC_BK */
                         queue = 3;
                         if (acm)
                                 local->wmm_acm |= BIT(1) | BIT(2); /* BK/- */
                         break;
                 case 2: /* AC_VI */
                         queue = 1;
                         if (acm)
                                 local->wmm_acm |= BIT(4) | BIT(5); /* CL/VI */
                         break;
                 case 3: /* AC_VO */
                         queue = 0;
                         if (acm)
                                 local->wmm_acm |= BIT(6) | BIT(7); /* VO/NC */
                         break;
                 case 0: /* AC_BE */
                 default:
                         queue = 2;
                         if (acm)
                                 local->wmm_acm |= BIT(0) | BIT(3); /* BE/EE */
                         break;
                 }
 
                 params.aifs = pos[0] & 0x0f;
                 params.cw_max = ecw2cw((pos[1] & 0xf0) >> 4);
                 params.cw_min = ecw2cw(pos[1] & 0x0f);
                 params.txop = get_unaligned_le16(pos + 2);
 #ifdef CONFIG_MAC80211_VERBOSE_DEBUG
                 printk(KERN_DEBUG "%s: WMM queue=%d aci=%d acm=%d aifs=%d "
                        "cWmin=%d cWmax=%d txop=%d\n",
                        wiphy_name(local->hw.wiphy), queue, aci, acm,
                        params.aifs, params.cw_min, params.cw_max, params.txop);
 #endif
                 if (drv_conf_tx(local, queue, &params) && local->ops->conf_tx)
                         printk(KERN_DEBUG "%s: failed to set TX queue "
                                "parameters for queue %d\n",
                                wiphy_name(local->hw.wiphy), queue);
         }
 }


void ieee80211_send_nullfunc(struct ieee80211_local *local,
                              struct ieee80211_sub_if_data *sdata,
                              int powersave)
{
	/*   struct sk_buff *skb;
         struct ieee80211_hdr *nullfunc;
         __le16 fc;
 
         if (WARN_ON(sdata->vif.type != NL80211_IFTYPE_STATION))
                 return;
 
         skb = dev_alloc_skb(local->hw.extra_tx_headroom + 24);
         if (!skb) {
                 printk(KERN_DEBUG "%s: failed to allocate buffer for nullfunc "
                        "frame\n", sdata->dev->name);
                 return;
         }
         skb_reserve(skb, local->hw.extra_tx_headroom);
 
         nullfunc = (struct ieee80211_hdr *) skb_put(skb, 24);
         memset(nullfunc, 0, 24);
         fc = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_NULLFUNC |
                          IEEE80211_FCTL_TODS);
         if (powersave)
                 fc |= cpu_to_le16(IEEE80211_FCTL_PM);
         nullfunc->frame_control = fc;
         memcpy(nullfunc->addr1, sdata->u.mgd.bssid, ETH_ALEN);
         memcpy(nullfunc->addr2, sdata->dev->dev_addr, ETH_ALEN);
         memcpy(nullfunc->addr3, sdata->u.mgd.bssid, ETH_ALEN);
 
         ieee80211_tx_skb(sdata, skb, 0);*/
}

void ieee80211_send_pspoll(struct ieee80211_local *local,
                            struct ieee80211_sub_if_data *sdata)
 {
        /* struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         struct ieee80211_pspoll *pspoll;
         struct sk_buff *skb;
         u16 fc;
 
         skb = dev_alloc_skb(local->hw.extra_tx_headroom + sizeof(*pspoll));
         if (!skb) {
                 printk(KERN_DEBUG "%s: failed to allocate buffer for "
                        "pspoll frame\n", sdata->dev->name);
                 return;
         }
         skb_reserve(skb, local->hw.extra_tx_headroom);
 
         pspoll = (struct ieee80211_pspoll *) skb_put(skb, sizeof(*pspoll));
         memset(pspoll, 0, sizeof(*pspoll));
         fc = IEEE80211_FTYPE_CTL | IEEE80211_STYPE_PSPOLL | IEEE80211_FCTL_PM;
        pspoll->frame_control = cpu_to_le16(fc);
        pspoll->aid = cpu_to_le16(ifmgd->aid);
 
         pspoll->aid |= cpu_to_le16(1 << 15 | 1 << 14);
 
         memcpy(pspoll->bssid, ifmgd->bssid, ETH_ALEN);
         memcpy(pspoll->ta, sdata->dev->dev_addr, ETH_ALEN);
 
         ieee80211_tx_skb(sdata, skb, 0);*/
 }

static inline int drv_config(struct ieee80211_local *local, u32 changed)
  {
          int ret = local->ops->config(&local->hw, changed);
         // trace_drv_config(local, changed, ret);
          return ret;
  }
 
int ieee80211_hw_config(struct ieee80211_local *local, u32 changed)
 {
         struct ieee80211_channel *chan, *scan_chan;
         int ret = 0;
         int power;
        enum nl80211_channel_type channel_type;
 
         might_sleep();
 
         scan_chan = local->scan_channel;
 
         if (scan_chan) {
                 chan = scan_chan;
                 channel_type = NL80211_CHAN_NO_HT;
         } else {
                 chan = local->oper_channel;
                 channel_type = local->oper_channel_type;
         }
 
         if (chan != local->hw.conf.channel ||
             channel_type != local->hw.conf.channel_type) {
                 local->hw.conf.channel = chan;
                 local->hw.conf.channel_type = channel_type;
                 changed |= IEEE80211_CONF_CHANGE_CHANNEL;
         }
 
         if (scan_chan)
                 power = chan->max_power;
         else
                 power = local->power_constr_level ?
                         (chan->max_power - local->power_constr_level) :
                         chan->max_power;
 
         if (local->user_power_level >= 0)
                 power = min(power, local->user_power_level);
 
         if (local->hw.conf.power_level != power) {
                 changed |= IEEE80211_CONF_CHANGE_POWER;
                 local->hw.conf.power_level = power;
         }
 
         if (changed && local->open_count) {
                 ret = drv_config(local, changed);

         }
 
         return ret;
 }

static u32 ieee80211_handle_bss_capability(struct ieee80211_sub_if_data *sdata,
                                            u16 capab, bool erp_valid, u8 erp)
 {
         struct ieee80211_bss_conf *bss_conf = &sdata->vif.bss_conf;
         u32 changed = 0;
     /*    bool use_protection;
         bool use_short_preamble;
         bool use_short_slot;
 
         if (erp_valid) {
                 use_protection = (erp & WLAN_ERP_USE_PROTECTION) != 0;
                 use_short_preamble = (erp & WLAN_ERP_BARKER_PREAMBLE) == 0;
         } else {
                 use_protection = false;
                 use_short_preamble = !!(capab & WLAN_CAPABILITY_SHORT_PREAMBLE);
         }
 
         use_short_slot = !!(capab & WLAN_CAPABILITY_SHORT_SLOT_TIME);
 
         if (use_protection != bss_conf->use_cts_prot) {
                 bss_conf->use_cts_prot = use_protection;
                 changed |= BSS_CHANGED_ERP_CTS_PROT;
         }
 
         if (use_short_preamble != bss_conf->use_short_preamble) {
                 bss_conf->use_short_preamble = use_short_preamble;
                 changed |= BSS_CHANGED_ERP_PREAMBLE;
         }
 
         if (use_short_slot != bss_conf->use_short_slot) {
                 bss_conf->use_short_slot = use_short_slot;
                 changed |= BSS_CHANGED_ERP_SLOT;
         }*/
 
         return changed;
 }

struct sta_info *sta_info_get(struct ieee80211_local *local, const u8 *addr)
 {
         struct sta_info *sta;
 
         sta = rcu_dereference(local->sta_hash[STA_HASH(addr)]);
         while (sta) {
                 if (memcmp(sta->sta.addr, addr, ETH_ALEN) == 0)
                         break;
                sta = rcu_dereference(sta->hnext);
         }
         return sta;
 }
 
 static inline void drv_bss_info_changed(struct ieee80211_local *local,
                                          struct ieee80211_vif *vif,
                                         struct ieee80211_bss_conf *info,
                                          u32 changed)
  {
          if (local->ops->bss_info_changed)
                  local->ops->bss_info_changed(&local->hw, vif, info, changed);
        //  trace_drv_bss_info_changed(local, vif, info, changed);
  }
 
 void ieee80211_bss_info_change_notify(struct ieee80211_sub_if_data *sdata,
                                       u32 changed)
 {
         struct ieee80211_local *local = sdata->local;
         static const u8 zero[ETH_ALEN] = { 0 };
 
         if (!changed)
                 return;
 
         if (sdata->vif.type == NL80211_IFTYPE_STATION) {
                 /*
                  * While not associated, claim a BSSID of all-zeroes
                  * so that drivers don't do any weird things with the
                  * BSSID at that time.
                  */
                 if (sdata->vif.bss_conf.assoc)
                         sdata->vif.bss_conf.bssid = sdata->u.mgd.bssid;
                 else
                         sdata->vif.bss_conf.bssid = zero;
         } else if (sdata->vif.type == NL80211_IFTYPE_ADHOC)
                 sdata->vif.bss_conf.bssid = sdata->u.ibss.bssid;
         else if (sdata->vif.type == NL80211_IFTYPE_AP)
                 sdata->vif.bss_conf.bssid = sdata->dev->dev_addr;
         else if (ieee80211_vif_is_mesh(&sdata->vif)) {
                 sdata->vif.bss_conf.bssid = zero;
         } else {
                 WARN_ON(1);
                 return;
         }
 
         switch (sdata->vif.type) {
         case NL80211_IFTYPE_AP:
         case NL80211_IFTYPE_ADHOC:
         case NL80211_IFTYPE_MESH_POINT:
                 break;
         default:
                 /* do not warn to simplify caller in scan.c */
                 changed &= ~BSS_CHANGED_BEACON_ENABLED;
                 if (WARN_ON(changed & BSS_CHANGED_BEACON))
                         return;
                 break;
         }
 
         if (changed & BSS_CHANGED_BEACON_ENABLED) {
                 if (local->quiescing || !netif_running(sdata->dev) ||
                     test_bit(SCAN_SW_SCANNING, &local->scanning)) {
                         sdata->vif.bss_conf.enable_beacon = false;
                 } else {
                         /*
                          * Beacon should be enabled, but AP mode must
                          * check whether there is a beacon configured.
                          */
                         switch (sdata->vif.type) {
                         case NL80211_IFTYPE_AP:
                                 sdata->vif.bss_conf.enable_beacon =
                                         !!rcu_dereference(sdata->u.ap.beacon);
                                 break;
                         case NL80211_IFTYPE_ADHOC:
                                 sdata->vif.bss_conf.enable_beacon =
                                         !!rcu_dereference(sdata->u.ibss.presp);
                                 break;
                         case NL80211_IFTYPE_MESH_POINT:
                                 sdata->vif.bss_conf.enable_beacon = true;
                                 break;
                         default:
                                 /* not reached */
                                 WARN_ON(1);
                                 break;
                         }
                 }
         }
 
         drv_bss_info_changed(local, &sdata->vif,
                              &sdata->vif.bss_conf, changed);
 }

 static void ieee80211_rx_mgmt_beacon(struct ieee80211_sub_if_data *sdata,
                                      struct ieee80211_mgmt *mgmt,
                                      size_t len,
                                      struct ieee80211_rx_status *rx_status)
 {
        struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         size_t baselen;
         struct ieee802_11_elems elems;
         struct ieee80211_local *local = sdata->local;
         u32 changed = 0;
         bool erp_valid, directed_tim = false;
         u8 erp_value = 0;
         u32 ncrc;
         u8 *bssid;
 
       //  ASSERT_MGD_MTX(ifmgd);
 
         /* Process beacon from the current BSS */
         baselen = (u8 *) mgmt->u.beacon.variable - (u8 *) mgmt;
         if (baselen > len)
                 return;
 
         if (rx_status->freq != local->hw.conf.channel->center_freq)
                 return;
 
         /*
          * We might have received a number of frames, among them a
          * disassoc frame and a beacon...
          */
         if (!ifmgd->associated)
                 return;
 
         bssid = ifmgd->associated->cbss.bssid;
 
         /*
          * And in theory even frames from a different AP we were just
         * associated to a split-second ago!
          */
         if (memcmp(bssid, mgmt->bssid, ETH_ALEN) != 0)
                 return;
 
        if (ifmgd->flags & IEEE80211_STA_BEACON_POLL) {
 #ifdef CONFIG_MAC80211_VERBOSE_DEBUG
                 if (net_ratelimit()) {
                         printk(KERN_DEBUG "%s: cancelling probereq poll due "
                                "to a received beacon\n", sdata->dev->name);
                 }
 #endif
                 ifmgd->flags &= ~IEEE80211_STA_BEACON_POLL;
                 mutex_lock(&local->iflist_mtx);
               //  ieee80211_recalc_ps(local, -1);
                 mutex_unlock(&local->iflist_mtx);
         }
 
         /*
          * Push the beacon loss detection into the future since
          * we are processing a beacon from the AP just now.
          */
        // mod_beacon_timer(sdata);
 
         ncrc = crc32_be(0, (const unsigned char *)&mgmt->u.beacon.beacon_int, 4);
         ncrc = ieee802_11_parse_elems_crc(mgmt->u.beacon.variable,
                                           len - baselen, &elems,
                                           care_about_ies, ncrc);
 
         if (local->hw.flags & IEEE80211_HW_PS_NULLFUNC_STACK)
                 directed_tim = ieee80211_check_tim(elems.tim, elems.tim_len,
                                                    ifmgd->aid);
 
         if (ncrc != ifmgd->beacon_crc) {
                 ieee80211_rx_bss_info(sdata, mgmt, len, rx_status, &elems,
                                       true);
 
                 ieee80211_sta_wmm_params(local, ifmgd, elems.wmm_param,
                                          elems.wmm_param_len);
         }
 
         if (local->hw.flags & IEEE80211_HW_PS_NULLFUNC_STACK) {
                 if (directed_tim) {
                         if (local->hw.conf.dynamic_ps_timeout > 0) {
                                 local->hw.conf.flags &= ~IEEE80211_CONF_PS;
                                 ieee80211_hw_config(local,
                                                     IEEE80211_CONF_CHANGE_PS);
                                 ieee80211_send_nullfunc(local, sdata, 0);
                         } else {
                                 local->pspolling = true;
 
                                /*
                                  * Here is assumed that the driver will be
                                  * able to send ps-poll frame and receive a
                                  * response even though power save mode is
                                  * enabled, but some drivers might require
                                  * to disable power save here. This needs
                                  * to be investigated.
                                  */
                                 ieee80211_send_pspoll(local, sdata);
                         }
                 }
         }
 
         if (ncrc == ifmgd->beacon_crc)
                 return;
         ifmgd->beacon_crc = ncrc;
 
         if (elems.erp_info && elems.erp_info_len >= 1) {
                 erp_valid = true;
                 erp_value = elems.erp_info[0];
         } else {
                 erp_valid = false;
         }
         changed |= ieee80211_handle_bss_capability(sdata,
                         le16_to_cpu(mgmt->u.beacon.capab_info),
                         erp_valid, erp_value);
 
 
        if (elems.ht_cap_elem && elems.ht_info_elem && elems.wmm_param &&
             !(ifmgd->flags & IEEE80211_STA_DISABLE_11N)) {
                 struct sta_info *sta;
                 struct ieee80211_supported_band *sband;
                 u16 ap_ht_cap_flags;
 
                 rcu_read_lock();
 
                 sta = sta_info_get(local, bssid);
                 if (WARN_ON(!sta)) {
                         rcu_read_unlock();
                         return;
                 }
 
                 sband = local->hw.wiphy->bands[local->hw.conf.channel->band];
 
               //  ieee80211_ht_cap_ie_to_sta_ht_cap(sband, elems.ht_cap_elem, &sta->sta.ht_cap);
 
                 ap_ht_cap_flags = sta->sta.ht_cap.cap;
 
                 rcu_read_unlock();
 
                // changed |= ieee80211_enable_ht(sdata, elems.ht_info_elem,                           bssid, ap_ht_cap_flags);
         }
 
         /* Note: country IE parsing is done for us by cfg80211 */
         /*if (elems.country_elem) {
                 if (elems.pwr_constr_elem)
                         ieee80211_handle_pwr_constr(sdata,
                                 le16_to_cpu(mgmt->u.probe_resp.capab_info),
                                 elems.pwr_constr_elem,
                                 elems.pwr_constr_elem_len);
         }*/
 
         ieee80211_bss_info_change_notify(sdata, changed);
}

void ieee802_11_parse_elems(u8 *start, size_t len,
                             struct ieee802_11_elems *elems)
 {
         ieee802_11_parse_elems_crc(start, len, elems, 0, 0);
 }

static void ieee80211_rx_mgmt_probe_resp(struct ieee80211_sub_if_data *sdata,
                                          struct ieee80211_mgd_work *wk,
                                          struct ieee80211_mgmt *mgmt, size_t len,
                                          struct ieee80211_rx_status *rx_status)
 {
         struct ieee80211_if_managed *ifmgd;
         size_t baselen;
         struct ieee802_11_elems elems;
 
         ifmgd = &sdata->u.mgd;
 
         ASSERT_MGD_MTX(ifmgd);
 
         if (memcmp(mgmt->da, sdata->dev->dev_addr, ETH_ALEN))
                 return; /* ignore ProbeResp to foreign address */
 
         baselen = (u8 *) mgmt->u.probe_resp.variable - (u8 *) mgmt;
         if (baselen > len)
                 return;
 
         ieee802_11_parse_elems(mgmt->u.probe_resp.variable, len - baselen,
                                 &elems);
 
         ieee80211_rx_bss_info(sdata, mgmt, len, rx_status, &elems, false);
 
         /* direct probe may be part of the association flow */
         if (wk && wk->state == IEEE80211_MGD_STATE_PROBE) {
               printk(KERN_DEBUG "%s: direct probe responded\n",
                        sdata->dev->name);
                 wk->tries = 0;
                 wk->state = IEEE80211_MGD_STATE_AUTH;
      //           WARN_ON(ieee80211_authenticate(sdata, wk) != RX_MGMT_NONE);
         }
 
         if (ifmgd->associated &&
             memcmp(mgmt->bssid, ifmgd->associated->cbss.bssid, ETH_ALEN) == 0 &&
             ifmgd->flags & (IEEE80211_STA_BEACON_POLL |
                             IEEE80211_STA_CONNECTION_POLL)) {
                 ifmgd->flags &= ~(IEEE80211_STA_CONNECTION_POLL |
                                   IEEE80211_STA_BEACON_POLL);
                 mutex_lock(&sdata->local->iflist_mtx);
             //    ieee80211_recalc_ps(sdata->local, -1);
                 mutex_unlock(&sdata->local->iflist_mtx);

        //         mod_beacon_timer(sdata);
                 mod_timer(&ifmgd->conn_mon_timer,
                           round_jiffies_up(IEEE80211_CONNECTION_IDLE_TIME));
         }
 }

u32 ieee80211_reset_erp_info(struct ieee80211_sub_if_data *sdata)
 {
         sdata->vif.bss_conf.use_cts_prot = false;
         sdata->vif.bss_conf.use_short_preamble = false;
         sdata->vif.bss_conf.use_short_slot = false;
         return BSS_CHANGED_ERP_CTS_PROT |
                BSS_CHANGED_ERP_PREAMBLE |
                BSS_CHANGED_ERP_SLOT;
 }

static inline struct ieee80211_hw *local_to_hw(
         struct ieee80211_local *local)
 {
         return &local->hw;
 }

void ieee80211_set_wmm_default(struct ieee80211_sub_if_data *sdata)
 {
         struct ieee80211_local *local = sdata->local;
         struct ieee80211_tx_queue_params qparam;
         int queue;
         bool use_11b;
         int aCWmin, aCWmax;
 
         if (!local->ops->conf_tx)
                 return;
 
         memset(&qparam, 0, sizeof(qparam));
 
         use_11b = 0;//(local->hw.conf.channel->band == IEEE80211_BAND_2GHZ) &&
                  //!(sdata->flags & IEEE80211_SDATA_OPERATING_GMODE);
 
         for (queue = 0; queue < local_to_hw(local)->queues; queue++) {
                 /* Set defaults according to 802.11-2007 Table 7-37 */
                 aCWmax = 1023;
                 if (use_11b)
                         aCWmin = 31;
                 else
                         aCWmin = 15;
 
                 switch (queue) {
                 case 3: /* AC_BK */
                         qparam.cw_max = aCWmax;
                         qparam.cw_min = aCWmin;
                         qparam.txop = 0;
                         qparam.aifs = 7;
                         break;
                 default: /* never happens but let's not leave undefined */
                 case 2: /* AC_BE */
                         qparam.cw_max = aCWmax;
                         qparam.cw_min = aCWmin;
                         qparam.txop = 0;
                         qparam.aifs = 3;
                         break;
                 case 1: /* AC_VI */
                         qparam.cw_max = aCWmin;
                         qparam.cw_min = (aCWmin + 1) / 2 - 1;
                         if (use_11b)
                                 qparam.txop = 6016/32;
                         else
                                 qparam.txop = 3008/32;
                         qparam.aifs = 2;
                         break;
                 case 0: /* AC_VO */
                         qparam.cw_max = (aCWmin + 1) / 2 - 1;
                         qparam.cw_min = (aCWmin + 1) / 4 - 1;
                         if (use_11b)
                                 qparam.txop = 3264/32;
                         else
                                 qparam.txop = 1504/32;
                         qparam.aifs = 2;
                        break;
                 }
 
                 drv_conf_tx(local, queue, &qparam);
         }
 }


static void ieee80211_set_disassoc(struct ieee80211_sub_if_data *sdata,
                                    bool deauth)
{
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         struct ieee80211_local *local = sdata->local;
         struct sta_info *sta;
         u32 changed = 0, config_changed = 0;
         u8 bssid[ETH_ALEN];
 
         ASSERT_MGD_MTX(ifmgd);
 
         if (WARN_ON(!ifmgd->associated))
                 return;
 
         memcpy(bssid, ifmgd->associated->cbss.bssid, ETH_ALEN);
 
         ifmgd->associated = NULL;
         memset(ifmgd->bssid, 0, ETH_ALEN);
 
         if (deauth) {
                 kfree(ifmgd->old_associate_work);
                 ifmgd->old_associate_work = NULL;
         } else {
                 struct ieee80211_mgd_work *wk = ifmgd->old_associate_work;
 
                 wk->state = IEEE80211_MGD_STATE_IDLE;
                 list_add(&wk->list, &ifmgd->work_list);
         }
 
         /*
          * we need to commit the associated = NULL change because the
          * scan code uses that to determine whether this iface should
          * go to/wake up from powersave or not -- and could otherwise
          * wake the queues erroneously.
          */
         smp_mb();
 
         /*
          * Thus, we can only afterwards stop the queues -- to account
          * for the case where another CPU is finishing a scan at this
          * time -- we don't want the scan code to enable queues.
          */
 
      //   netif_tx_stop_all_queues(sdata->dev);
        // netif_carrier_off(sdata->dev);
 
         rcu_read_lock();
         sta = sta_info_get(local, bssid);
        // if (sta)
          //       ieee80211_sta_tear_down_BA_sessions(sta);
         rcu_read_unlock();
 
         changed |= ieee80211_reset_erp_info(sdata);
 
//         ieee80211_led_assoc(local, 0);
         changed |= BSS_CHANGED_ASSOC;
         sdata->vif.bss_conf.assoc = false;
 
         ieee80211_set_wmm_default(sdata);
    //    ieee80211_recalc_idle(local);
 
         /* channel(_type) changes are handled by ieee80211_hw_config */
         local->oper_channel_type = NL80211_CHAN_NO_HT;
 
         /* on the next assoc, re-program HT parameters */
         sdata->ht_opmode_valid = false;

         local->power_constr_level = 0;
 
         del_timer_sync(&local->dynamic_ps_timer);
         cancel_work_sync(&local->dynamic_ps_enable_work);
 
         if (local->hw.conf.flags & IEEE80211_CONF_PS) {
                 local->hw.conf.flags &= ~IEEE80211_CONF_PS;
                 config_changed |= IEEE80211_CONF_CHANGE_PS;
         }
 
         ieee80211_hw_config(local, config_changed);
 
         /* And the BSSID changed -- not very interesting here */
         changed |= BSS_CHANGED_BSSID;
         ieee80211_bss_info_change_notify(sdata, changed);
 
         rcu_read_lock();
 
         sta = sta_info_get(local, bssid);
         if (!sta) {
                 rcu_read_unlock();
                 return;
         }
 
         __sta_info_unlink(&sta);
 
         rcu_read_unlock();
 
         sta_info_destroy(sta);
 }

rx_mgmt_action ieee80211_rx_mgmt_deauth(struct ieee80211_sub_if_data *sdata,
                          struct ieee80211_mgd_work *wk,
                          struct ieee80211_mgmt *mgmt, size_t len)
 {
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         const u8 *bssid = NULL;
         u16 reason_code;
 
         if (len < 24 + 2)
                 return RX_MGMT_NONE;
 
         ASSERT_MGD_MTX(ifmgd);
 
         if (wk)
                 bssid = wk->bss->cbss.bssid;
         else
                 bssid = ifmgd->associated->cbss.bssid;
 
         reason_code = le16_to_cpu(mgmt->u.deauth.reason_code);
 
         printk(KERN_DEBUG "%s: deauthenticated from %pM (Reason: %u)\n",
                         sdata->dev->name, bssid, reason_code);
 
         if (!wk) {
                 ieee80211_set_disassoc(sdata, true);
         } else {
                 list_del(&wk->list);
                 kfree(wk);
         }
 
         return RX_MGMT_CFG80211_DEAUTH;
 }

rx_mgmt_action ieee80211_rx_mgmt_disassoc(struct ieee80211_sub_if_data *sdata,
                            struct ieee80211_mgmt *mgmt, size_t len)
 {
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         u16 reason_code;
 
         if (len < 24 + 2)
                return RX_MGMT_NONE;
 
         ASSERT_MGD_MTX(ifmgd);
 
         if (WARN_ON(!ifmgd->associated))
                 return RX_MGMT_NONE;
 
         if (WARN_ON(memcmp(ifmgd->associated->cbss.bssid, mgmt->sa, ETH_ALEN)))
                return RX_MGMT_NONE;
 
         reason_code = le16_to_cpu(mgmt->u.disassoc.reason_code);
 
         printk(KERN_DEBUG "%s: disassociated from %pM (Reason: %u)\n",
                         sdata->dev->name, mgmt->sa, reason_code);
 
         ieee80211_set_disassoc(sdata, false);
         return RX_MGMT_CFG80211_DISASSOC;
 }

static void ieee80211_auth_completed(struct ieee80211_sub_if_data *sdata,
                                      struct ieee80211_mgd_work *wk)
 {
         wk->state = IEEE80211_MGD_STATE_IDLE;
         printk(KERN_DEBUG "%s: authenticated\n", sdata->dev->name);
 }

void ieee80211_send_auth(struct ieee80211_sub_if_data *sdata,
                          u16 transaction, u16 auth_alg,
                         u8 *extra, size_t extra_len, const u8 *bssid,
                          const u8 *key, u8 key_len, u8 key_idx)
 {
     /*    struct ieee80211_local *local = sdata->local;
         struct sk_buff *skb;
         struct ieee80211_mgmt *mgmt;
         int err;
 
         skb = dev_alloc_skb(local->hw.extra_tx_headroom +
                             sizeof(*mgmt) + 6 + extra_len);
         if (!skb) {
                 printk(KERN_DEBUG "%s: failed to allocate buffer for auth "
                        "frame\n", sdata->dev->name);
                 return;
         }
         skb_reserve(skb, local->hw.extra_tx_headroom);
 
         mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24 + 6);
         memset(mgmt, 0, 24 + 6);
         mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
                                           IEEE80211_STYPE_AUTH);
         memcpy(mgmt->da, bssid, ETH_ALEN);
         memcpy(mgmt->sa, sdata->dev->dev_addr, ETH_ALEN);
         memcpy(mgmt->bssid, bssid, ETH_ALEN);
         mgmt->u.auth.auth_alg = cpu_to_le16(auth_alg);
         mgmt->u.auth.auth_transaction = cpu_to_le16(transaction);
         mgmt->u.auth.status_code = cpu_to_le16(0);
         if (extra)
                 memcpy(skb_put(skb, extra_len), extra, extra_len);
 
         if (auth_alg == WLAN_AUTH_SHARED_KEY && transaction == 3) {
                 mgmt->frame_control |= cpu_to_le16(IEEE80211_FCTL_PROTECTED);
                 err = ieee80211_wep_encrypt(local, skb, key, key_len, key_idx);
                 WARN_ON(err);
        }
 
         ieee80211_tx_skb(sdata, skb, 0);*/
 }

static void ieee80211_auth_challenge(struct ieee80211_sub_if_data *sdata,
                                      struct ieee80211_mgd_work *wk,
                                      struct ieee80211_mgmt *mgmt,
                                      size_t len)
 {
         u8 *pos;
         struct ieee802_11_elems elems;
 
         pos = mgmt->u.auth.variable;
         ieee802_11_parse_elems(pos, len - (pos - (u8 *) mgmt), &elems);
         if (!elems.challenge)
                 return;
         ieee80211_send_auth(sdata, 3, wk->auth_alg,
                             elems.challenge - 2, elems.challenge_len + 2,
                             wk->bss->cbss.bssid,
                             wk->key, wk->key_len, wk->key_idx);
         wk->auth_transaction = 4;
 }

rx_mgmt_action ieee80211_rx_mgmt_auth(struct ieee80211_sub_if_data *sdata,
                        struct ieee80211_mgd_work *wk,
                        struct ieee80211_mgmt *mgmt, size_t len)
 {
         u16 auth_alg, auth_transaction, status_code;
 
         if (wk->state != IEEE80211_MGD_STATE_AUTH)
                 return RX_MGMT_NONE;
 
         if (len < 24 + 6)
                 return RX_MGMT_NONE;
 
         if (memcmp(wk->bss->cbss.bssid, mgmt->sa, ETH_ALEN) != 0)
                 return RX_MGMT_NONE;
 
         if (memcmp(wk->bss->cbss.bssid, mgmt->bssid, ETH_ALEN) != 0)
                 return RX_MGMT_NONE;
 
         auth_alg = le16_to_cpu(mgmt->u.auth.auth_alg);
         auth_transaction = le16_to_cpu(mgmt->u.auth.auth_transaction);
         status_code = le16_to_cpu(mgmt->u.auth.status_code);
 
         if (auth_alg != wk->auth_alg ||
             auth_transaction != wk->auth_transaction)
                 return RX_MGMT_NONE;
 
         if (status_code != WLAN_STATUS_SUCCESS) {
                 list_del(&wk->list);
                 kfree(wk);
                 return RX_MGMT_CFG80211_AUTH;
         }
 
         switch (wk->auth_alg) {
         case WLAN_AUTH_OPEN:
         case WLAN_AUTH_LEAP:
         case WLAN_AUTH_FT:
                 ieee80211_auth_completed(sdata, wk);
                 return RX_MGMT_CFG80211_AUTH;
         case WLAN_AUTH_SHARED_KEY:
                if (wk->auth_transaction == 4) {
                         ieee80211_auth_completed(sdata, wk);
                         return RX_MGMT_CFG80211_AUTH;
                } else
                         ieee80211_auth_challenge(sdata, wk, mgmt, len);
                 break;
         }
 
         return RX_MGMT_NONE;
 }

static void run_again(struct ieee80211_if_managed *ifmgd,
                              unsigned long timeout)
 {
         ASSERT_MGD_MTX(ifmgd);
 
        // if (!timer_pending(&ifmgd->timer) ||
          //   time_before(timeout, ifmgd->timer.expires))
                 mod_timer(&ifmgd->timer, timeout);
 }

struct rate_control_ref *rate_control_get(struct rate_control_ref *ref)
 {
         kref_get(&ref->kref);
         return ref;
 }

static inline void *rate_control_alloc_sta(struct rate_control_ref *ref,
                                             struct ieee80211_sta *sta,
                                            gfp_t gfp)
 {
         return ref->ops->alloc_sta(ref->priv, sta, gfp);
 }
 
struct sta_info *sta_info_alloc(struct ieee80211_sub_if_data *sdata,
                               u8 *addr, gfp_t gfp)
 {
         struct ieee80211_local *local = sdata->local;
         struct sta_info *sta;
         int i;
 
         sta = (struct sta_info*)kzalloc(sizeof(*sta) + local->hw.sta_data_size, gfp);
         if (!sta)
                 return NULL;
 
         spin_lock_init(&sta->lock);
         spin_lock_init(&sta->flaglock);
 
         memcpy(sta->sta.addr, addr, ETH_ALEN);
         sta->local = local;
         sta->sdata = sdata;
 
         sta->rate_ctrl = rate_control_get(local->rate_ctrl);
         sta->rate_ctrl_priv = rate_control_alloc_sta(sta->rate_ctrl,
                                                      &sta->sta, gfp);
         if (!sta->rate_ctrl_priv) {
                 rate_control_put(sta->rate_ctrl);
                 kfree(sta);
                 return NULL;
         }
 
         for (i = 0; i < STA_TID_NUM; i++) {
                 /* timer_to_tid must be initialized with identity mapping to
                  * enable session_timer's data differentiation. refer to
                  * sta_rx_agg_session_timer_expired for useage */
                 sta->timer_to_tid[i] = i;
                 /* rx */
                 sta->ampdu_mlme.tid_state_rx[i] = HT_AGG_STATE_IDLE;
                 sta->ampdu_mlme.tid_rx[i] = NULL;
                 /* tx */
                 sta->ampdu_mlme.tid_state_tx[i] = HT_AGG_STATE_IDLE;
                 sta->ampdu_mlme.tid_tx[i] = NULL;
                 sta->ampdu_mlme.addba_req_num[i] = 0;
         }
         skb_queue_head_init(&sta->ps_tx_buf);
         skb_queue_head_init(&sta->tx_filtered);

         for (i = 0; i < NUM_RX_DATA_QUEUES; i++)
                 sta->last_seq_ctrl[i] = cpu_to_le16(USHORT_MAX);
 
 #ifdef CONFIG_MAC80211_VERBOSE_DEBUG
         printk(KERN_DEBUG "%s: Allocated STA %pM\n",
                wiphy_name(local->hw.wiphy), sta->sta.addr);
 #endif /* CONFIG_MAC80211_VERBOSE_DEBUG */
 
 #ifdef CONFIG_MAC80211_MESH
        sta->plink_state = PLINK_LISTEN;
         init_timer(&sta->plink_timer);
 #endif
 
         return sta;
 }

static inline void set_sta_flags(struct sta_info *sta, const u32 flags)
 {
         unsigned long irqfl;
 
         spin_lock_irqsave(&sta->flaglock, irqfl);
         sta->flags |= flags;
         spin_unlock_irqrestore(&sta->flaglock, irqfl);
 }

static inline void rate_control_rate_init(struct sta_info *sta)
  {
          struct ieee80211_local *local = sta->sdata->local;
          struct rate_control_ref *ref = sta->rate_ctrl;
          struct ieee80211_sta *ista = &sta->sta;
          void *priv_sta = sta->rate_ctrl_priv;
          struct ieee80211_supported_band *sband;
  
          sband = local->hw.wiphy->bands[local->hw.conf.channel->band];
  
          ref->ops->rate_init(ref->priv, sband, ista, priv_sta);
  }
  
  static void sta_info_hash_add(struct ieee80211_local *local,
                               struct sta_info *sta)
 {
         sta->hnext = local->sta_hash[STA_HASH(sta->sta.addr)];
         rcu_assign_pointer(local->sta_hash[STA_HASH(sta->sta.addr)], sta);
 }

static inline void drv_sta_notify(struct ieee80211_local *local,
                                   struct ieee80211_vif *vif,
                                   enum sta_notify_cmd cmd,
                                   struct ieee80211_sta *sta)
 {
         if (local->ops->sta_notify)
                 local->ops->sta_notify(&local->hw, vif, cmd, sta);
      //   trace_drv_sta_notify(local, vif, cmd, sta);
 }

int sta_info_insert(struct sta_info *sta)
 {
         struct ieee80211_local *local = sta->local;
         struct ieee80211_sub_if_data *sdata = sta->sdata;
         unsigned long flags;
         int err = 0;
 
         /*
          * Can't be a WARN_ON because it can be triggered through a race:
          * something inserts a STA (on one CPU) without holding the RTNL
          * and another CPU turns off the net device.
          */
         if (unlikely(!netif_running(sdata->dev))) {
                 err = -ENETDOWN;
                 goto out_free;
         }
 
         if (WARN_ON(compare_ether_addr(sta->sta.addr, sdata->dev->dev_addr) == 0 ||
                     is_multicast_ether_addr(sta->sta.addr))) {
                 err = -EINVAL;
                 goto out_free;
         }
 
         spin_lock_irqsave(&local->sta_lock, flags);
         /* check if STA exists already */
        if (sta_info_get(local, sta->sta.addr)) {
                 spin_unlock_irqrestore(&local->sta_lock, flags);
                 err = -EEXIST;
                 goto out_free;
         }
         list_add(&sta->list, &local->sta_list);
         local->sta_generation++;
         local->num_sta++;
         sta_info_hash_add(local, sta);
 
         /* notify driver */
         if (local->ops->sta_notify) {
                 if (sdata->vif.type == NL80211_IFTYPE_AP_VLAN)
                         sdata = container_of(sdata->bss,
                                              struct ieee80211_sub_if_data,
                                              u.ap);
 
                 drv_sta_notify(local, &sdata->vif, STA_NOTIFY_ADD, &sta->sta);
         }
 
 #ifdef CONFIG_MAC80211_VERBOSE_DEBUG
         printk(KERN_DEBUG "%s: Inserted STA %pM\n",
                wiphy_name(local->hw.wiphy), sta->sta.addr);
 #endif /* CONFIG_MAC80211_VERBOSE_DEBUG */
 
         spin_unlock_irqrestore(&local->sta_lock, flags);
 
 #ifdef CONFIG_MAC80211_DEBUGFS
        /*
          * Debugfs entry adding might sleep, so schedule process
          * context task for adding entry for STAs that do not yet
          * have one.
         * NOTE: due to auto-freeing semantics this may only be done
          *       if the insertion is successful!
          */
        // schedule_work(&local->sta_debugfs_add);
 #endif
 
    //     if (ieee80211_vif_is_mesh(&sdata->vif))
      //           mesh_accept_plinks_update(sdata);
 
         return 0;
  out_free:
         BUG_ON(!err);
         __sta_info_free(local, sta);
         return err;
 }

static void ieee80211_set_associated(struct ieee80211_sub_if_data *sdata,
                                      struct ieee80211_mgd_work *wk,
                                      u32 bss_info_changed)
 {
         struct ieee80211_local *local = sdata->local;
         struct ieee80211_bss *bss = wk->bss;
 
         bss_info_changed |= BSS_CHANGED_ASSOC;
         /* set timing information */
         sdata->vif.bss_conf.beacon_int = bss->cbss.beacon_interval;
         sdata->vif.bss_conf.timestamp = bss->cbss.tsf;
         sdata->vif.bss_conf.dtim_period = bss->dtim_period;
 
         bss_info_changed |= BSS_CHANGED_BEACON_INT;
         bss_info_changed |= ieee80211_handle_bss_capability(sdata,
                 bss->cbss.capability, bss->has_erp_value, bss->erp_value);
 
         sdata->u.mgd.associated = bss;
         sdata->u.mgd.old_associate_work = wk;
         memcpy(sdata->u.mgd.bssid, bss->cbss.bssid, ETH_ALEN);
 
         /* just to be sure */
         sdata->u.mgd.flags &= ~(IEEE80211_STA_CONNECTION_POLL |
                                 IEEE80211_STA_BEACON_POLL);
 
//         ieee80211_led_assoc(local, 1);
 
         sdata->vif.bss_conf.assoc = 1;
         /*
          * For now just always ask the driver to update the basic rateset
          * when we have associated, we aren't checking whether it actually
          * changed or not.
          */
        bss_info_changed |= BSS_CHANGED_BASIC_RATES;
 
         /* And the BSSID changed - we're associated now */
        bss_info_changed |= BSS_CHANGED_BSSID;
 
         ieee80211_bss_info_change_notify(sdata, bss_info_changed);

         mutex_lock(&local->iflist_mtx);
     //    ieee80211_recalc_ps(local, -1);
         mutex_unlock(&local->iflist_mtx);
 
		//netif_tx_start_all_queues(sdata->dev);
         //netif_carrier_on(sdata->dev);
 }

rx_mgmt_action ieee80211_rx_mgmt_assoc_resp(struct ieee80211_sub_if_data *sdata,
                              struct ieee80211_mgd_work *wk,
                              struct ieee80211_mgmt *mgmt, size_t len,
                              bool reassoc)
 {
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         struct ieee80211_local *local = sdata->local;
         struct ieee80211_supported_band *sband;
         struct sta_info *sta;
         u32 rates, basic_rates;
         u16 capab_info, status_code, aid;
        struct ieee802_11_elems elems;
         struct ieee80211_bss_conf *bss_conf = &sdata->vif.bss_conf;
         u8 *pos;
         u32 changed = 0;
         int i, j;
         bool have_higher_than_11mbit = false, newsta = false;
         u16 ap_ht_cap_flags;
 
         /*
          * AssocResp and ReassocResp have identical structure, so process both
          * of them in this function.
          */

         if (len < 24 + 6)
                 return RX_MGMT_NONE;
 
         if (memcmp(wk->bss->cbss.bssid, mgmt->sa, ETH_ALEN) != 0)
                 return RX_MGMT_NONE;
 
         capab_info = le16_to_cpu(mgmt->u.assoc_resp.capab_info);
         status_code = le16_to_cpu(mgmt->u.assoc_resp.status_code);
         aid = le16_to_cpu(mgmt->u.assoc_resp.aid);
 
         printk(KERN_DEBUG "%s: RX %sssocResp from %pM (capab=0x%x "
                "status=%d aid=%d)\n",
                sdata->dev->name, reassoc ? "Rea" : "A", mgmt->sa,
                capab_info, status_code, (u16)(aid & ~(BIT(15) | BIT(14))));
 
         pos = mgmt->u.assoc_resp.variable;
         ieee802_11_parse_elems(pos, len - (pos - (u8 *) mgmt), &elems);
 
         if (status_code == WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY &&
             elems.timeout_int && elems.timeout_int_len == 5 &&
             elems.timeout_int[0] == WLAN_TIMEOUT_ASSOC_COMEBACK) {
                 u32 tu, ms;
                 tu = get_unaligned_le32(elems.timeout_int + 1);
                 ms = tu * 1024 / 1000;
                 printk(KERN_DEBUG "%s: AP rejected association temporarily; "
                        "comeback duration %u TU (%u ms)\n",
                        sdata->dev->name, tu, ms);
                 wk->timeout =  msecs_to_jiffies(ms);
                 if (ms > IEEE80211_ASSOC_TIMEOUT)
                         run_again(ifmgd,  msecs_to_jiffies(ms));
                 return RX_MGMT_NONE;
         }
 
         if (status_code != WLAN_STATUS_SUCCESS) {
                 printk(KERN_DEBUG "%s: AP denied association (code=%d)\n",
                        sdata->dev->name, status_code);
                 list_del(&wk->list);
                 kfree(wk);
                 return RX_MGMT_CFG80211_ASSOC;
         }
 
         if ((aid & (BIT(15) | BIT(14))) != (BIT(15) | BIT(14)))
                 printk(KERN_DEBUG "%s: invalid aid value %d; bits 15:14 not "
                        "set\n", sdata->dev->name, aid);
         aid &= ~(BIT(15) | BIT(14));
 
         if (!elems.supp_rates) {
                 printk(KERN_DEBUG "%s: no SuppRates element in AssocResp\n",
                        sdata->dev->name);
                 return RX_MGMT_NONE;
         }
 
         printk(KERN_DEBUG "%s: associated\n", sdata->dev->name);
         ifmgd->aid = aid;
 
         rcu_read_lock();
 
         /* Add STA entry for the AP */
         sta = sta_info_get(local, wk->bss->cbss.bssid);
         if (!sta) {
                 newsta = true;
 
                 rcu_read_unlock();
 
                 sta = sta_info_alloc(sdata, wk->bss->cbss.bssid, GFP_KERNEL);
                 if (!sta) {
                         printk(KERN_DEBUG "%s: failed to alloc STA entry for"
                                " the AP\n", sdata->dev->name);
                         return RX_MGMT_NONE;
                 }
 
                 set_sta_flags(sta, WLAN_STA_AUTH | WLAN_STA_ASSOC |
                                    WLAN_STA_ASSOC_AP);
                 if (!(ifmgd->flags & IEEE80211_STA_CONTROL_PORT))
                         set_sta_flags(sta, WLAN_STA_AUTHORIZED);
 
                 rcu_read_lock();
         }
 
         rates = 0;
         basic_rates = 0;
         sband = local->hw.wiphy->bands[local->hw.conf.channel->band];
 
        for (i = 0; i < elems.supp_rates_len; i++) {
                 int rate = (elems.supp_rates[i] & 0x7f) * 5;
                 bool is_basic = !!(elems.supp_rates[i] & 0x80);
 
                 if (rate > 110)
                         have_higher_than_11mbit = true;
 
                 for (j = 0; j < sband->n_bitrates; j++) {
                         if (sband->bitrates[j].bitrate == rate) {
                                 rates |= BIT(j);
                                 if (is_basic)
                                         basic_rates |= BIT(j);
                                 break;
                         }
                 }
         }
 
         for (i = 0; i < elems.ext_supp_rates_len; i++) {
                 int rate = (elems.ext_supp_rates[i] & 0x7f) * 5;
                 bool is_basic = !!(elems.ext_supp_rates[i] & 0x80);
 
                 if (rate > 110)
                         have_higher_than_11mbit = true;
 
                 for (j = 0; j < sband->n_bitrates; j++) {
                         if (sband->bitrates[j].bitrate == rate) {
                                 rates |= BIT(j);
                                 if (is_basic)
                                         basic_rates |= BIT(j);
                                 break;
                         }
                 }
         }
 
        sta->sta.supp_rates[local->hw.conf.channel->band] = rates;
         sdata->vif.bss_conf.basic_rates = basic_rates;
 
         /* cf. IEEE 802.11 9.2.12 */
         if (local->hw.conf.channel->band == IEEE80211_BAND_2GHZ &&
             have_higher_than_11mbit)
                 sdata->flags |= IEEE80211_SDATA_OPERATING_GMODE;
         else
                 sdata->flags &= ~IEEE80211_SDATA_OPERATING_GMODE;
 
     //    if (elems.ht_cap_elem && !(ifmgd->flags & IEEE80211_STA_DISABLE_11N))
       //          ieee80211_ht_cap_ie_to_sta_ht_cap(sband,             elems.ht_cap_elem, &sta->sta.ht_cap);
 
         ap_ht_cap_flags = sta->sta.ht_cap.cap;
 
         rate_control_rate_init(sta);
 
         if (ifmgd->flags & IEEE80211_STA_MFP_ENABLED)
                 set_sta_flags(sta, WLAN_STA_MFP);
 
         if (elems.wmm_param)
                 set_sta_flags(sta, WLAN_STA_WME);
 
         if (newsta) {
               int err = sta_info_insert(sta);
                 if (err) {
                         printk(KERN_DEBUG "%s: failed to insert STA entry for"
                                " the AP (error %d)\n", sdata->dev->name, err);
                         rcu_read_unlock();
                         return RX_MGMT_NONE;
                 }
         }
 
         rcu_read_unlock();
 
         if (elems.wmm_param)
                 ieee80211_sta_wmm_params(local, ifmgd, elems.wmm_param,
                                          elems.wmm_param_len);
         else
                 ieee80211_set_wmm_default(sdata);
 
 //       if (elems.ht_info_elem && elems.wmm_param &&
   //          (ifmgd->flags & IEEE80211_STA_WMM_ENABLED) &&
     //        !(ifmgd->flags & IEEE80211_STA_DISABLE_11N))
       //          changed |= ieee80211_enable_ht(sdata, elems.ht_info_elem,                                                wk->bss->cbss.bssid,                                                ap_ht_cap_flags);
 
         /* delete work item -- must be before set_associated for PS */
         list_del(&wk->list);
 
        /* set AID and assoc capability,
          * ieee80211_set_associated() will tell the driver */
         bss_conf->aid = aid;
         bss_conf->assoc_capability = capab_info;
         /* this will take ownership of wk */
         ieee80211_set_associated(sdata, wk, changed);
 
         /*
          * Start timer to probe the connection to the AP now.
          * Also start the timer that will detect beacon loss.
          */
      //   ieee80211_sta_rx_notify(sdata, (struct ieee80211_hdr *)mgmt);
        // mod_beacon_timer(sdata);
 
         return RX_MGMT_CFG80211_ASSOC;
 }

void cfg80211_send_deauth(struct net_device *dev, const u8 *buf, size_t len,
			  void *cookie)
{

}

void cfg80211_send_rx_auth(struct net_device *dev, const u8 *buf, size_t len)
{}

void cfg80211_send_disassoc(struct net_device *dev, const u8 *buf, size_t len,
			    void *cookie)
{}

void cfg80211_send_rx_assoc(struct net_device *dev, const u8 *buf, size_t len)
{}

 static void ieee80211_sta_rx_queued_mgmt(struct ieee80211_sub_if_data *sdata,
                                          struct sk_buff *skb)
 {
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         struct ieee80211_rx_status *rx_status;
         struct ieee80211_mgmt *mgmt;
         struct ieee80211_mgd_work *wk;
         enum rx_mgmt_action rma = RX_MGMT_NONE;
         u16 fc;
 
         rx_status = (struct ieee80211_rx_status *) skb->cb;
         mgmt = (struct ieee80211_mgmt *) skb_data(skb);
         fc = le16_to_cpu(mgmt->frame_control);
 
         mutex_lock(&ifmgd->mtx);
 
         if (ifmgd->associated &&
             memcmp(ifmgd->associated->cbss.bssid, mgmt->bssid,
                                                         ETH_ALEN) == 0) {
                 switch (fc & IEEE80211_FCTL_STYPE) {
                 case IEEE80211_STYPE_BEACON:
                         ieee80211_rx_mgmt_beacon(sdata, mgmt, skb_len(skb),
                                                  rx_status);
                         break;
                 case IEEE80211_STYPE_PROBE_RESP:
                         ieee80211_rx_mgmt_probe_resp(sdata, NULL, mgmt,
                                                      skb_len(skb), rx_status);
                         break;
                 case IEEE80211_STYPE_DEAUTH:
                         rma = ieee80211_rx_mgmt_deauth(sdata, NULL,
                                                        mgmt, skb_len(skb));
                         break;
                 case IEEE80211_STYPE_DISASSOC:
                         rma = ieee80211_rx_mgmt_disassoc(sdata, mgmt, skb_len(skb));
                         break;
                 case IEEE80211_STYPE_ACTION:
                         /* XXX: differentiate, can only happen for CSA now! */
                         ieee80211_sta_process_chanswitch(sdata,
                                         &mgmt->u.action.u.chan_switch.sw_elem,
                                         ifmgd->associated);
                         break;
                 }
                 mutex_unlock(&ifmgd->mtx);
 
                 switch (rma) {
                 case RX_MGMT_NONE:
                         /* no action */
                         break;
                 case RX_MGMT_CFG80211_DEAUTH:
                         cfg80211_send_deauth(sdata->dev, (u8 *)mgmt, skb_len(skb),
                                              NULL);
                         break;
                 case RX_MGMT_CFG80211_DISASSOC:
                         cfg80211_send_disassoc(sdata->dev, (u8 *)mgmt, skb_len(skb),
                                                NULL);
                         break;
                 default:
                         WARN(1, "unexpected: %d", rma);
                 }
                 goto out;
         }
 
         list_for_each_entry(wk, &ifmgd->work_list, list) {
                 if (memcmp(wk->bss->cbss.bssid, mgmt->bssid, ETH_ALEN) != 0)
                         continue;
 
                 switch (fc & IEEE80211_FCTL_STYPE) {
                 case IEEE80211_STYPE_PROBE_RESP:
                         ieee80211_rx_mgmt_probe_resp(sdata, wk, mgmt, skb_len(skb),
                                                      rx_status);
                        break;
                 case IEEE80211_STYPE_AUTH:
                         rma = ieee80211_rx_mgmt_auth(sdata, wk, mgmt, skb_len(skb));
                         break;
                 case IEEE80211_STYPE_ASSOC_RESP:
                         rma = ieee80211_rx_mgmt_assoc_resp(sdata, wk, mgmt,
                                                            skb_len(skb), false);
                         break;
                 case IEEE80211_STYPE_REASSOC_RESP:
                         rma = ieee80211_rx_mgmt_assoc_resp(sdata, wk, mgmt,
                                                            skb_len(skb), true);
                         break;
                 case IEEE80211_STYPE_DEAUTH:
                         rma = ieee80211_rx_mgmt_deauth(sdata, wk, mgmt,
                                                        skb_len(skb));
                         break;
                 }
                 /*
                  * We've processed this frame for that work, so it can't
                  * belong to another work struct.
                  * NB: this is also required for correctness because the
                  * called functions can free 'wk', and for 'rma'!
                  */
                 break;
         }
 
         mutex_unlock(&ifmgd->mtx);

         switch (rma) {
         case RX_MGMT_NONE:
                 /* no action */
                 break;
         case RX_MGMT_CFG80211_AUTH:
                 cfg80211_send_rx_auth(sdata->dev, (u8 *) mgmt, skb_len(skb));
                 break;
         case RX_MGMT_CFG80211_ASSOC:
                 cfg80211_send_rx_assoc(sdata->dev, (u8 *) mgmt, skb_len(skb));
                 break;
         case RX_MGMT_CFG80211_DEAUTH:
                 cfg80211_send_deauth(sdata->dev, (u8 *)mgmt, skb_len(skb), NULL);
                 break;
         default:
                 WARN(1, "unexpected: %d", rma);
      }
 
  out:
         kfree_skb(skb);
 }

void ieee80211_send_probe_req(struct ieee80211_sub_if_data *sdata, u8 *dst,
                               const u8 *ssid, size_t ssid_len,
                               const u8 *ie, size_t ie_len)
 {
       /*  struct ieee80211_local *local = sdata->local;
         struct sk_buff *skb;
         struct ieee80211_mgmt *mgmt;
         u8 *pos;
 
         skb = dev_alloc_skb(local->hw.extra_tx_headroom + sizeof(*mgmt) + 200 +
                             ie_len);
         if (!skb) {
                 printk(KERN_DEBUG "%s: failed to allocate buffer for probe "
                        "request\n", sdata->dev->name);
                 return;
         }
        skb_reserve(skb, local->hw.extra_tx_headroom);
 
         mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24);
         memset(mgmt, 0, 24);
         mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
                                           IEEE80211_STYPE_PROBE_REQ);
         memcpy(mgmt->sa, sdata->dev->dev_addr, ETH_ALEN);
         if (dst) {
               memcpy(mgmt->da, dst, ETH_ALEN);
                 memcpy(mgmt->bssid, dst, ETH_ALEN);
         } else {
                 memset(mgmt->da, 0xff, ETH_ALEN);
                 memset(mgmt->bssid, 0xff, ETH_ALEN);
         }
         pos = skb_put(skb, 2 + ssid_len);
         *pos++ = WLAN_EID_SSID;
         *pos++ = ssid_len;
         memcpy(pos, ssid, ssid_len);
         pos += ssid_len;
 
         skb_put(skb, ieee80211_build_preq_ies(local, pos, ie, ie_len));
 
         ieee80211_tx_skb(sdata, skb, 0);*/
 }

const u8 *ieee80211_bss_get_ie(struct cfg80211_bss *bss, u8 ie)
 {
         u8 *end, *pos;
 
         pos = bss->information_elements;
         if (pos == NULL)
                 return NULL;
         end = pos + bss->len_information_elements;
 
         while (pos + 1 < end) {
                 if (pos + 2 + pos[1] > end)
                         break;
                 if (pos[0] == ie)
                         return pos;
                 pos += 2 + pos[1];
         }
 
         return NULL;
 }

static void ieee80211_mgd_probe_ap_send(struct ieee80211_sub_if_data *sdata)
 {
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         const u8 *ssid;
 
         ssid = ieee80211_bss_get_ie(&ifmgd->associated->cbss, WLAN_EID_SSID);
         ieee80211_send_probe_req(sdata, ifmgd->associated->cbss.bssid,
                                  ssid + 2, ssid[1], NULL, 0);
 
         ifmgd->probe_send_count++;
         ifmgd->probe_timeout =  IEEE80211_PROBE_WAIT;
         run_again(ifmgd, ifmgd->probe_timeout);
 }

static void ieee80211_send_deauth_disassoc(struct ieee80211_sub_if_data *sdata,
                                            const u8 *bssid, u16 stype, u16 reason,
                                            void *cookie)
 {
       /*  struct ieee80211_local *local = sdata->local;
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         struct sk_buff *skb;
         struct ieee80211_mgmt *mgmt;
 
         skb = dev_alloc_skb(local->hw.extra_tx_headroom + sizeof(*mgmt));
         if (!skb) {
                 printk(KERN_DEBUG "%s: failed to allocate buffer for "
                        "deauth/disassoc frame\n", sdata->dev->name);
                 return;
         }
         skb_reserve(skb, local->hw.extra_tx_headroom);
 
         mgmt = (struct ieee80211_mgmt *) skb_put(skb, 24);
         memset(mgmt, 0, 24);
         memcpy(mgmt->da, bssid, ETH_ALEN);
         memcpy(mgmt->sa, sdata->dev->dev_addr, ETH_ALEN);
         memcpy(mgmt->bssid, bssid, ETH_ALEN);
         mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | stype);
         skb_put(skb, 2);

         mgmt->u.deauth.reason_code = cpu_to_le16(reason);
 
         if (stype == IEEE80211_STYPE_DEAUTH)
                 cfg80211_send_deauth(sdata->dev, (u8 *)mgmt, skb->len, cookie);
         else
                 cfg80211_send_disassoc(sdata->dev, (u8 *)mgmt, skb->len, cookie);
         ieee80211_tx_skb(sdata, skb, ifmgd->flags & IEEE80211_STA_MFP_ENABLED);*/
 }

void cfg80211_unlink_bss(struct wiphy *wiphy, struct cfg80211_bss *pub)
 {
       /*  struct cfg80211_registered_device *dev = wiphy_to_dev(wiphy);
         struct cfg80211_internal_bss *bss;
 
         if (WARN_ON(!pub))
                 return;
 
         bss = container_of(pub, struct cfg80211_internal_bss, pub);
 
         spin_lock_bh(&dev->bss_lock);
 
         list_del(&bss->list);
         dev->bss_generation++;
         rb_erase(&bss->rbn, &dev->bss_tree);
 
         spin_unlock_bh(&dev->bss_lock);
 
         kref_put(&bss->ref, bss_release);*/
 }

rx_mgmt_action ieee80211_direct_probe(struct ieee80211_sub_if_data *sdata,
                        struct ieee80211_mgd_work *wk)
 {
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         struct ieee80211_local *local = sdata->local;
 
         wk->tries++;
         if (wk->tries > IEEE80211_AUTH_MAX_TRIES) {
                 printk(KERN_DEBUG "%s: direct probe to AP %pM timed out\n",
                        sdata->dev->name, wk->bss->cbss.bssid);
 
                 /*
                  * Most likely AP is not in the range so remove the
                  * bss struct for that AP.
                  */
                 cfg80211_unlink_bss(local->hw.wiphy, &wk->bss->cbss);
 
                 /*
                  * We might have a pending scan which had no chance to run yet
                  * due to work needing to be done. Hence, queue the STAs work
                  * again for that.
                  */
                 ieee80211_queue_work(&local->hw, &ifmgd->work);
                 return RX_MGMT_CFG80211_AUTH_TO;
         }
 
         printk(KERN_DEBUG "%s: direct probe to AP %pM (try %d)\n",
                         sdata->dev->name, wk->bss->cbss.bssid,
                         wk->tries);
 
         /*
          * Direct probe is sent to broadcast address as some APs
          * will not answer to direct packet in unassociated state.
          */
         ieee80211_send_probe_req(sdata, NULL, wk->ssid, wk->ssid_len, NULL, 0);
 
         wk->timeout = jiffies + IEEE80211_AUTH_TIMEOUT;
         run_again(ifmgd, wk->timeout);
 
         return RX_MGMT_NONE;
 }

rx_mgmt_action ieee80211_authenticate(struct ieee80211_sub_if_data *sdata,
                        struct ieee80211_mgd_work *wk)
 {
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         struct ieee80211_local *local = sdata->local;
 
         wk->tries++;
         if (wk->tries > IEEE80211_AUTH_MAX_TRIES) {
                 printk(KERN_DEBUG "%s: authentication with AP %pM"
                        " timed out\n",
                        sdata->dev->name, wk->bss->cbss.bssid);
 
                 /*
                  * Most likely AP is not in the range so remove the
                  * bss struct for that AP.
                  */
                cfg80211_unlink_bss(local->hw.wiphy, &wk->bss->cbss);
 
                 /*
                  * We might have a pending scan which had no chance to run yet
                  * due to work needing to be done. Hence, queue the STAs work
                  * again for that.
                  */
                 ieee80211_queue_work(&local->hw, &ifmgd->work);
                 return RX_MGMT_CFG80211_AUTH_TO;
         }
 
         printk(KERN_DEBUG "%s: authenticate with AP %pM (try %d)\n",
                sdata->dev->name, wk->bss->cbss.bssid, wk->tries);
 
         ieee80211_send_auth(sdata, 1, wk->auth_alg, wk->ie, wk->ie_len,
                             wk->bss->cbss.bssid, NULL, 0, 0);
         wk->auth_transaction = 2;
 
         wk->timeout = jiffies + IEEE80211_AUTH_TIMEOUT;
         run_again(ifmgd, wk->timeout);
 
         return RX_MGMT_NONE;
 }

rx_mgmt_action ieee80211_associate(struct ieee80211_sub_if_data *sdata,
                     struct ieee80211_mgd_work *wk)
{
        struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         struct ieee80211_local *local = sdata->local;
 
         wk->tries++;
         if (wk->tries > IEEE80211_ASSOC_MAX_TRIES) {
                 printk(KERN_DEBUG "%s: association with AP %pM"
                        " timed out\n",
                        sdata->dev->name, wk->bss->cbss.bssid);
 
                 /*
                  * Most likely AP is not in the range so remove the
                  * bss struct for that AP.
                  */
                 cfg80211_unlink_bss(local->hw.wiphy, &wk->bss->cbss);
 
                 /*
                  * We might have a pending scan which had no chance to run yet
                  * due to work needing to be done. Hence, queue the STAs work
                  * again for that.
                  */
                 ieee80211_queue_work(&local->hw, &ifmgd->work);
                 return RX_MGMT_CFG80211_ASSOC_TO;
         }
 
         printk(KERN_DEBUG "%s: associate with AP %pM (try %d)\n",
                sdata->dev->name, wk->bss->cbss.bssid, wk->tries);
       //  ieee80211_send_assoc(sdata, wk);
 
         wk->timeout = jiffies + IEEE80211_ASSOC_TIMEOUT;
         run_again(ifmgd, wk->timeout);
 
         return RX_MGMT_NONE;
 }

void cfg80211_send_auth_timeout(struct net_device *dev, const u8 *addr)
{}

void cfg80211_send_assoc_timeout(struct net_device *dev, const u8 *addr)
{}


 static void ieee80211_sta_work(struct work_struct *work)
 {
         struct ieee80211_sub_if_data *sdata =
                 container_of(work, struct ieee80211_sub_if_data, u.mgd.work);
         struct ieee80211_local *local = sdata->local;
         struct ieee80211_if_managed *ifmgd;
         struct sk_buff *skb;
         struct ieee80211_mgd_work *wk, *tmp;
         LIST_HEAD(free_work);
         enum rx_mgmt_action rma;
         bool anybusy = false;
 
         if (!netif_running(sdata->dev))
                 return;
 
         if (local->scanning)
                 return;
 
         if (WARN_ON(sdata->vif.type != NL80211_IFTYPE_STATION))
                 return;
 
         /*
          * ieee80211_queue_work() should have picked up most cases,
          * here we'll pick the the rest.
          */
         if (WARN(local->suspended, "STA MLME work scheduled while "
                  "going to suspend\n"))
                 return;
 
         ifmgd = &sdata->u.mgd;
 
         /* first process frames to avoid timing out while a frame is pending */
         while ((skb = skb_dequeue(&ifmgd->skb_queue)))
                 ieee80211_sta_rx_queued_mgmt(sdata, skb);
 
         /* then process the rest of the work */
         mutex_lock(&ifmgd->mtx);
 
         if (ifmgd->flags & (IEEE80211_STA_BEACON_POLL |
                             IEEE80211_STA_CONNECTION_POLL) &&
             ifmgd->associated) {
                 u8 bssid[ETH_ALEN];
 
                 memcpy(bssid, ifmgd->associated->cbss.bssid, ETH_ALEN);
                 if (time_is_after_jiffies(ifmgd->probe_timeout))
                         run_again(ifmgd, ifmgd->probe_timeout);
 
                 else if (ifmgd->probe_send_count < IEEE80211_MAX_PROBE_TRIES) {
 #ifdef CONFIG_MAC80211_VERBOSE_DEBUG
                       printk(KERN_DEBUG "No probe response from AP %pM"
                                 " after %dms, try %d\n", bssid,
                                 (1000 * IEEE80211_PROBE_WAIT)/HZ,
                                 ifmgd->probe_send_count);
 #endif
                         ieee80211_mgd_probe_ap_send(sdata);
                 } else {


                         ifmgd->flags &= ~(IEEE80211_STA_CONNECTION_POLL |
                                           IEEE80211_STA_BEACON_POLL);
                         printk(KERN_DEBUG "No probe response from AP %pM"
                                 " after %dms, disconnecting.\n",
                                 bssid, (1000 * IEEE80211_PROBE_WAIT)/HZ);
                         ieee80211_set_disassoc(sdata, true);
                         mutex_unlock(&ifmgd->mtx);


                         ieee80211_send_deauth_disassoc(sdata, bssid,
                                         IEEE80211_STYPE_DEAUTH,
                                         WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY,
                                         NULL);
                         mutex_lock(&ifmgd->mtx);
                 }
         }
 
 
     //    ieee80211_recalc_idle(local);
 
         list_for_each_entry_safe(wk, tmp, &ifmgd->work_list, list) {
                 if (time_is_after_jiffies(wk->timeout)) {


                         run_again(ifmgd, wk->timeout);
                         continue;
                 }
 
                 switch (wk->state) {
                 default:
                         WARN_ON(1);

                 case IEEE80211_MGD_STATE_IDLE:

                         rma = RX_MGMT_NONE;
                         break;
                 case IEEE80211_MGD_STATE_PROBE:
                         rma = ieee80211_direct_probe(sdata, wk);
                         break;
                 case IEEE80211_MGD_STATE_AUTH:
                         rma = ieee80211_authenticate(sdata, wk);
                         break;
                 case IEEE80211_MGD_STATE_ASSOC:
                         rma = ieee80211_associate(sdata, wk);
                         break;
                 }
 
                 switch (rma) {
                 case RX_MGMT_NONE:

                         break;
                 case RX_MGMT_CFG80211_AUTH_TO:
                 case RX_MGMT_CFG80211_ASSOC_TO:
                         list_del(&wk->list);
                         list_add(&wk->list, &free_work);
                         wk->tries = rma; 
                         break;
                 default:
                         WARN(1, "unexpected: %d", rma);
                 }
         }
 
         list_for_each_entry(wk, &ifmgd->work_list, list) {
                 if (wk->state != IEEE80211_MGD_STATE_IDLE) {
                         anybusy = true;
                         break;
                 }
         }
         if (!anybusy &&
             test_and_clear_bit(IEEE80211_STA_REQ_SCAN, &ifmgd->request))
                 ieee80211_queue_delayed_work(&local->hw,
                                              &local->scan_work,
                                              round_jiffies_relative(0));
 
         mutex_unlock(&ifmgd->mtx);
 
         list_for_each_entry_safe(wk, tmp, &free_work, list) {
                 switch (wk->tries) {
                 case RX_MGMT_CFG80211_AUTH_TO:
                         cfg80211_send_auth_timeout(sdata->dev,
                                                    wk->bss->cbss.bssid);
                         break;
                 case RX_MGMT_CFG80211_ASSOC_TO:
                         cfg80211_send_assoc_timeout(sdata->dev,
                                                     wk->bss->cbss.bssid);
                         break;
                 default:
                         WARN(1, "unexpected: %d", wk->tries);
                 }
 
                 list_del(&wk->list);
                 kfree(wk);
         }
 
     //    ieee80211_recalc_idle(local);
 }

void ieee80211_queue_work(struct ieee80211_hw *hw, struct work_struct *work)
 {
         struct ieee80211_local *local = hw_to_local(hw);
 
       //  if (!ieee80211_can_queue_work(local))
         //        return;
 
         queue_work(local->workqueue, work);
 }

void ieee80211_queue_delayed_work(struct ieee80211_hw *hw,
				  struct delayed_work *dwork,
				  unsigned long delay)
{
	struct ieee80211_local *local = hw_to_local(hw);
	queue_delayed_work(local->workqueue, dwork,delay);
}

static void ieee80211_sta_timer(unsigned long data)
 {
         struct ieee80211_sub_if_data *sdata =
                 (struct ieee80211_sub_if_data *) data;
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
         struct ieee80211_local *local = sdata->local;
 
         if (local->quiescing) {
                 set_bit(TMR_RUNNING_TIMER, &ifmgd->timers_running);
                 return;
         }
 
         ieee80211_queue_work(&local->hw, &ifmgd->work);
 }

static void ieee80211_chswitch_timer(unsigned long data)
 {
         struct ieee80211_sub_if_data *sdata =
                 (struct ieee80211_sub_if_data *) data;
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
 
         if (sdata->local->quiescing) {
                 set_bit(TMR_RUNNING_CHANSW, &ifmgd->timers_running);
                 return;
         }
 
         ieee80211_queue_work(&sdata->local->hw, &ifmgd->chswitch_work);
 }

static void ieee80211_chswitch_work(struct work_struct *work)
 {
         struct ieee80211_sub_if_data *sdata =
                 container_of(work, struct ieee80211_sub_if_data, u.mgd.chswitch_work);
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
 
         if (!netif_running(sdata->dev))
                 return;
 
         mutex_lock(&ifmgd->mtx);
         if (!ifmgd->associated)
                 goto out;
 
         sdata->local->oper_channel = sdata->local->csa_channel;
         ieee80211_hw_config(sdata->local, IEEE80211_CONF_CHANGE_CHANNEL);
 
         /* XXX: shouldn't really modify cfg80211-owned data! */
         ifmgd->associated->cbss.channel = sdata->local->oper_channel;
 
     //    ieee80211_wake_queues_by_reason(&sdata->local->hw,
       //                                  IEEE80211_QUEUE_STOP_REASON_CSA);
  out:
         ifmgd->flags &= ~IEEE80211_STA_CSA_RECEIVED;
         mutex_unlock(&ifmgd->mtx);
 }

 void ieee80211_sta_setup_sdata(struct ieee80211_sub_if_data *sdata)
 {
         struct ieee80211_if_managed *ifmgd;
 
         ifmgd = &sdata->u.mgd;
        INIT_WORK(&ifmgd->work, ieee80211_sta_work,32);
        // INIT_WORK(&ifmgd->monitor_work, ieee80211_sta_monitor_work,33);
         INIT_WORK(&ifmgd->chswitch_work, ieee80211_chswitch_work,34);
       //  INIT_WORK(&ifmgd->beacon_loss_work, ieee80211_beacon_loss_work,35);
         setup_timer(&ifmgd->timer, ieee80211_sta_timer,
                     (unsigned long) sdata);
     //    setup_timer(&ifmgd->bcn_mon_timer, ieee80211_sta_bcn_mon_timer,
       //              (unsigned long) sdata);
        // setup_timer(&ifmgd->conn_mon_timer, ieee80211_sta_conn_mon_timer,
          //           (unsigned long) sdata);
         setup_timer(&ifmgd->chswitch_timer, ieee80211_chswitch_timer,
                     (unsigned long) sdata);
         skb_queue_head_init(&ifmgd->skb_queue);
 
         INIT_LIST_HEAD(&ifmgd->work_list);
 
         ifmgd->capab = WLAN_CAPABILITY_ESS;
         ifmgd->flags = 0;
        if (sdata->local->hw.queues >= 4)
                 ifmgd->flags |= IEEE80211_STA_WMM_ENABLED;
 
         mutex_init(&ifmgd->mtx);
 }

 static void ieee80211_setup_sdata(struct ieee80211_sub_if_data *sdata,
                                   enum nl80211_iftype type)
 {
         /* clear type-dependent union */
         memset(&sdata->u, 0, sizeof(sdata->u));
 
         /* and set some type-dependent values */
         sdata->vif.type = type;
       //  sdata->dev->netdev_ops = &ieee80211_dataif_ops;
         sdata->wdev.iftype = type;
 
         /* only monitor differs */
         sdata->dev->type = ARPHRD_ETHER;
 
         switch (type) {
         case NL80211_IFTYPE_AP:
                 skb_queue_head_init(&sdata->u.ap.ps_bc_buf);
                 INIT_LIST_HEAD(&sdata->u.ap.vlans);
                 break;
         case NL80211_IFTYPE_STATION:
                 ieee80211_sta_setup_sdata(sdata);
                 break;
         case NL80211_IFTYPE_ADHOC:
               //  ieee80211_ibss_setup_sdata(sdata);
                 break;
         case NL80211_IFTYPE_MESH_POINT:
                // if (ieee80211_vif_is_mesh(&sdata->vif))
                  //       ieee80211_mesh_init_sdata(sdata);
                 break;
         case NL80211_IFTYPE_MONITOR:
                 sdata->dev->type = ARPHRD_IEEE80211_RADIOTAP;
                // sdata->dev->netdev_ops = &ieee80211_monitorif_ops;
                 sdata->u.mntr_flags = MONITOR_FLAG_CONTROL |
                                       MONITOR_FLAG_OTHER_BSS;
                 break;
         case NL80211_IFTYPE_WDS:
         case NL80211_IFTYPE_AP_VLAN:
                 break;
         case NL80211_IFTYPE_UNSPECIFIED:
         case __NL80211_IFTYPE_AFTER_LAST:
                 BUG();
                 break;
         }
 
      //   ieee80211_debugfs_add_netdev(sdata);
 }

int ieee80211_if_add(struct ieee80211_local *local, const char *name,
                      struct net_device **new_dev, enum nl80211_iftype type,
                      struct vif_params *params)
 {
         struct net_device *ndev;
         struct ieee80211_sub_if_data *sdata = NULL;
         int ret, i;
 
        // ASSERT_RTNL();
 
         ndev = alloc_netdev(sizeof(*sdata) + local->hw.vif_data_size,
                             name, NULL);//ieee80211_if_setup);
         if (!ndev)
                 return -ENOMEM;
        // dev_net_set(ndev, wiphy_net(local->hw.wiphy));
 
       //  ndev->needed_headroom = local->tx_headroom +
         //                        4*6 /* four MAC addresses */
           //                      + 2 + 2 + 2 + 2 /* ctl, dur, seq, qos */
             //                    + 6 /* mesh */
               //                  + 8 /* rfc1042/bridge tunnel */
                 //                - ETH_HLEN /* ethernet hard_header_len */
                   //              + IEEE80211_ENCRYPT_HEADROOM;
         //ndev->needed_tailroom = IEEE80211_ENCRYPT_TAILROOM;
 
        /* ret = dev_alloc_name(ndev, ndev->name);
         if (ret < 0)
                 goto fail;*/
 
       //  memcpy(ndev->dev_addr, local->hw.wiphy->perm_addr, ETH_ALEN);
		 memcpy(ndev->dev_addr, my_mac_addr, ETH_ALEN);
		 
   //      SET_NETDEV_DEV(ndev, wiphy_dev(local->hw.wiphy));
  //       SET_NETDEV_DEVTYPE(ndev, &wiphy_type);
 
         /* don't use IEEE80211_DEV_TO_SUB_IF because it checks too much */
         sdata = (struct ieee80211_sub_if_data*)netdev_priv(ndev);
         ndev->ieee80211_ptr = &sdata->wdev;
 
         /* initialise type-independent data */
         sdata->wdev.wiphy = local->hw.wiphy;
         sdata->local = local;
         sdata->dev = ndev;
 
         for (i = 0; i < IEEE80211_FRAGMENT_MAX; i++)
                 skb_queue_head_init(&sdata->fragments[i].skb_list);
 
         INIT_LIST_HEAD(&sdata->key_list);
 
         sdata->force_unicast_rateidx = -1;
         sdata->max_ratectrl_rateidx = -1;
 
         /* setup type-dependent data */
         ieee80211_setup_sdata(sdata, type);
 
      /*   ret = register_netdevice(ndev);
         if (ret)
                 goto fail;
 
       if (ieee80211_vif_is_mesh(&sdata->vif) &&
             params && params->mesh_id_len)
                 ieee80211_sdata_set_mesh_id(sdata,
                                             params->mesh_id_len,
                                             params->mesh_id);
 */
         mutex_lock(&local->iflist_mtx);
         list_add_tail_rcu(&sdata->list, &local->interfaces);
         mutex_unlock(&local->iflist_mtx);
 
         if (new_dev)
                 *new_dev = ndev;
 
         return 0;
 
  fail:
      //   free_netdev(ndev);
         return ret;
 }

int ieee80211_register_hw(struct ieee80211_hw *hw)
 {
         struct ieee80211_local *local = hw_to_local(hw);
         int result;
         //enum ieee80211_band 
		 int band;
         int channels, i, j, max_bitrates;
         bool supp_ht;
         static const u32 cipher_suites[] = {
                 WLAN_CIPHER_SUITE_WEP40,
                 WLAN_CIPHER_SUITE_WEP104,
                 WLAN_CIPHER_SUITE_TKIP,
                 WLAN_CIPHER_SUITE_CCMP,
 
                 /* keep last -- depends on hw flags! */
                 WLAN_CIPHER_SUITE_AES_CMAC
         };
 
         /*
          * generic code guarantees at least one band,
          * set this very early because much code assumes
          * that hw.conf.channel is assigned
          */
         channels = 0;
         max_bitrates = 0;
         supp_ht = false;
         for (band = 0; band < IEEE80211_NUM_BANDS; band++) {
                 struct ieee80211_supported_band *sband;
 
                 sband = local->hw.wiphy->bands[band];
                 if (!sband)
                         continue;
                 if (!local->oper_channel) {
                         /* init channel we're on */
                         local->hw.conf.channel =
                         local->oper_channel = &sband->channels[0];
                         local->hw.conf.channel_type = NL80211_CHAN_NO_HT;
                 }
                 channels += sband->n_channels;
 
                 if (max_bitrates < sband->n_bitrates)
                         max_bitrates = sband->n_bitrates;
                 supp_ht = supp_ht || sband->ht_cap.ht_supported;
         }
 
         local->int_scan_req = (struct cfg80211_scan_request*)kzalloc(sizeof(*local->int_scan_req) +
                                       sizeof(void *) * channels, GFP_KERNEL);
         if (!local->int_scan_req)
                 return -ENOMEM;
 
         /* if low-level driver supports AP, we also support VLAN */
         if (local->hw.wiphy->interface_modes & BIT(NL80211_IFTYPE_AP))
                 local->hw.wiphy->interface_modes |= BIT(NL80211_IFTYPE_AP_VLAN);
 
         /* mac80211 always supports monitor */
         local->hw.wiphy->interface_modes |= BIT(NL80211_IFTYPE_MONITOR);
 
         if (local->hw.flags & IEEE80211_HW_SIGNAL_DBM)
                 local->hw.wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;
         else if (local->hw.flags & IEEE80211_HW_SIGNAL_UNSPEC)
                 local->hw.wiphy->signal_type = CFG80211_SIGNAL_TYPE_UNSPEC;
 
         /*
          * Calculate scan IE length -- we need this to alloc
          * memory and to subtract from the driver limit. It
          * includes the (extended) supported rates and HT
          * information -- SSID is the driver's responsibility.
          */
         local->scan_ies_len = 4 + max_bitrates; /* (ext) supp rates */
         if (supp_ht)
                 local->scan_ies_len += 2 + sizeof(struct ieee80211_ht_cap);
 
         if (!local->ops->hw_scan) {
                 /* For hw_scan, driver needs to set these up. */
                local->hw.wiphy->max_scan_ssids = 4;
                 local->hw.wiphy->max_scan_ie_len = IEEE80211_MAX_DATA_LEN;
         }
 
         /*
          * If the driver supports any scan IEs, then assume the
          * limit includes the IEs mac80211 will add, otherwise
          * leave it at zero and let the driver sort it out; we
          * still pass our IEs to the driver but userspace will
          * not be allowed to in that case.
          */
         if (local->hw.wiphy->max_scan_ie_len)
                 local->hw.wiphy->max_scan_ie_len -= local->scan_ies_len;
 
         local->hw.wiphy->cipher_suites = cipher_suites;
         local->hw.wiphy->n_cipher_suites = ARRAY_SIZE(cipher_suites);
         if (!(local->hw.flags & IEEE80211_HW_MFP_CAPABLE))
                 local->hw.wiphy->n_cipher_suites--;
 
        /* result = wiphy_register(local->hw.wiphy);
         if (result < 0)
                 goto fail_wiphy_register;
 
         
          * We use the number of queues for feature tests (QoS, HT) internally
          * so restrict them appropriately.
          */
         if (hw->queues > IEEE80211_MAX_QUEUES)
                 hw->queues = IEEE80211_MAX_QUEUES;
 
         local->workqueue =
                 create_singlethread_workqueue(wiphy_name(local->hw.wiphy));
         if (!local->workqueue) {
                 result = -ENOMEM;
                 goto fail_workqueue;
         }
 
         /*
          * The hardware needs headroom for sending the frame,
          * and we need some headroom for passing the frame to monitor
          * interfaces, but never both at the same time.
          */
         local->tx_headroom = max_t(unsigned int , local->hw.extra_tx_headroom,
                                    sizeof(struct ieee80211_tx_status_rtap_hdr));
 
        // debugfs_hw_add(local);
 
         if (local->hw.max_listen_interval == 0)
                 local->hw.max_listen_interval = 1;
 
         local->hw.conf.listen_interval = local->hw.max_listen_interval;
 
         result = sta_info_start(local);
         if (result < 0)
                 goto fail_sta_info;
 
    //     result = ieee80211_wep_init(local);
         if (result < 0) {
                 printk(KERN_DEBUG "%s: Failed to initialize wep: %d\n",
                        wiphy_name(local->hw.wiphy), result);
                 goto fail_wep;
         }
 
         rtnl_lock();
 
         result = ieee80211_init_rate_ctrl_alg(local,
                                               hw->rate_control_algorithm);
         if (result < 0) {
                 printk(KERN_DEBUG "%s: Failed to initialize rate control "
                        "algorithm\n", wiphy_name(local->hw.wiphy));
                 goto fail_rate;
         }
 
         /* add one default STA interface if supported */
         if (local->hw.wiphy->interface_modes & BIT(NL80211_IFTYPE_STATION)) {
                 result = ieee80211_if_add(local, "wlan%d", NULL,
                                           NL80211_IFTYPE_STATION, NULL);
                 if (result)
                         printk(KERN_WARNING "%s: Failed to add default virtual iface\n",
                                wiphy_name(local->hw.wiphy));
         }
 
         rtnl_unlock();
 
     //    ieee80211_led_init(local);
 
         /* alloc internal scan request */
         i = 0;
         local->int_scan_req->ssids = &local->scan_ssid;
         local->int_scan_req->n_ssids = 1;
         for (band = 0; band < IEEE80211_NUM_BANDS; band++) {
                 if (!hw->wiphy->bands[band])
                         continue;
                 for (j = 0; j < hw->wiphy->bands[band]->n_channels; j++) {
                         local->int_scan_req->channels[i] =
                                 &hw->wiphy->bands[band]->channels[j];
                         i++;
                 }
         }
 
        /* local->network_latency_notifier.notifier_call =
                 ieee80211_max_network_latency;
         result = pm_qos_add_notifier(PM_QOS_NETWORK_LATENCY,
                                      &local->network_latency_notifier);
 
         if (result) {
                 rtnl_lock();
                 goto fail_pm_qos;
         }*/
 
         return 0;
 
  fail_pm_qos:
       //  ieee80211_led_exit(local);
         //ieee80211_remove_interfaces(local);
  fail_rate:
         rtnl_unlock();
         //ieee80211_wep_free(local);
  fail_wep:
         //sta_info_stop(local);
  fail_sta_info:
        // debugfs_hw_del(local);
         //destroy_workqueue(local->workqueue);
  fail_workqueue:
         //wiphy_unregister(local->hw.wiphy);
  fail_wiphy_register:
         kfree(local->int_scan_req);
         return result;
 }


void ieee80211_rate_control_unregister(struct rate_control_ops *ops)
  {
          struct rate_control_alg *alg;
  
          //mutex_lock(&rate_ctrl_mutex);
          list_for_each_entry(alg, &rate_ctrl_algs, list) {
                  if (alg->ops == ops) {
                          list_del(&alg->list);
                          kfree(alg);
                          break;
                  }
          }
         // mutex_unlock(&rate_ctrl_mutex);
  }

int ieee80211_rate_control_register(struct rate_control_ops *ops)
  {
          struct rate_control_alg *alg;
  
          if (!ops->name)
                  return -EINVAL;
  
         // mutex_lock(&rate_ctrl_mutex);
        list_for_each_entry(alg, &rate_ctrl_algs, list) {
                 if (!strcmp(alg->ops->name, ops->name)) {

                          WARN_ON(1);
                        //  mutex_unlock(&rate_ctrl_mutex);
                          return -EALREADY;
                  }
          }
  
          alg = (struct rate_control_alg*)kzalloc(sizeof(*alg), GFP_KERNEL);
          if (alg == NULL) {
                  //mutex_unlock(&rate_ctrl_mutex);
                  return -ENOMEM;
          }
          alg->ops = ops;
 
         list_add_tail(&alg->list, &rate_ctrl_algs);
        //  mutex_unlock(&rate_ctrl_mutex);
 
          return 0;
  }
 
 
unsigned int ieee80211_hdrlen(__le16 fc)
 {
         unsigned int hdrlen = 24;
 
         if (ieee80211_is_data(fc)) {
                 if (ieee80211_has_a4(fc))
                         hdrlen = 30;
                 if (ieee80211_is_data_qos(fc))
                         hdrlen += IEEE80211_QOS_CTL_LEN;
                 goto out;
         }
 
         if (ieee80211_is_ctl(fc)) {
                 /*
                  * ACK and CTS are 10 bytes, all others 16. To see how
                  * to get this condition consider
                  *   subtype mask:   0b0000000011110000 (0x00F0)
                  *   ACK subtype:    0b0000000011010000 (0x00D0)
                  *   CTS subtype:    0b0000000011000000 (0x00C0)
                  *   bits that matter:         ^^^      (0x00E0)
                  *   value of those: 0b0000000011000000 (0x00C0)
                  */
                 if ((fc & cpu_to_le16(0x00E0)) == cpu_to_le16(0x00C0))
                         hdrlen = 10;
                 else
                         hdrlen = 16;
         }
 out:
         return hdrlen;
 }

void ieee80211_stop_queue(struct ieee80211_hw *hw, int queue) {
	struct ieee80211_local *local = hw_to_local(hw);

	//if (!ieee80211_qdisc_installed(local->mdev) && queue == 0)
	//	netif_stop_queue(local->mdev);
	//set_bit(IEEE80211_LINK_STATE_XOFF, &local->state[queue]);

}

void ieee80211_stop_queues(struct ieee80211_hw *hw) {
	int i;

	for (i = 0; i < hw->queues; i++)
		ieee80211_stop_queue(hw, i);

}
 
 void ieee80211_free_hw (	struct ieee80211_hw *  	hw){
	return;
}

 
 int ieee80211_channel_to_frequency(int chan)
  {
          if (chan < 14)
                  return 2407 + chan * 5;
  
          if (chan == 14)
                  return 2484;
  
          /* FIXME: 802.11j 17.3.8.3.2 */
          return (chan + 1000) * 5;
  }




struct ieee80211_sta *ieee80211_find_sta(struct ieee80211_hw *hw,
                                          const u8 *addr)
 {
         struct sta_info *sta = sta_info_get(hw_to_local(hw), addr);
 
         if (!sta)
                 return NULL;
         return &sta->sta;
 }


  
  int ieee80211_frequency_to_channel(int freq)
  {
          if (freq == 2484)
                  return 14;
  
          if (freq < 2484)
                  return (freq - 2407) / 5;
  
          /* FIXME: 802.11j 17.3.8.3.2 */
          return freq/5 - 1000;
  }
 
 void mesh_mgmt_ies_add(struct sk_buff *skb, struct ieee80211_sub_if_data *sdata)
 {
     /*    struct ieee80211_local *local = sdata->local;
         struct ieee80211_supported_band *sband;
         u8 *pos;
         int len, i, rate;
 
         sband = local->hw.wiphy->bands[local->hw.conf.channel->band];
         len = sband->n_bitrates;
         if (len > 8)
                 len = 8;
         pos = (u8*)skb_put(skb, len + 2);
         *pos++ = WLAN_EID_SUPP_RATES;
         *pos++ = len;
         for (i = 0; i < len; i++) {
                 rate = sband->bitrates[i].bitrate;
                 *pos++ = (u8) (rate / 5);
         }
 
         if (sband->n_bitrates > len) {
                 pos = (u8*)skb_put(skb, sband->n_bitrates - len + 2);
                 *pos++ = WLAN_EID_EXT_SUPP_RATES;
                 *pos++ = sband->n_bitrates - len;
                 for (i = len; i < sband->n_bitrates; i++) {
                         rate = sband->bitrates[i].bitrate;
                         *pos++ = (u8) (rate / 5);
                 }
         }
 
         pos = (u8*)skb_put(skb, 2 + sdata->u.mesh.mesh_id_len);
         *pos++ = WLAN_EID_MESH_ID;
         *pos++ = sdata->u.mesh.mesh_id_len;
         if (sdata->u.mesh.mesh_id_len)
                 memcpy(pos, sdata->u.mesh.mesh_id, sdata->u.mesh.mesh_id_len);
 
         pos = (u8*)skb_put(skb, 2 + IEEE80211_MESH_CONFIG_LEN);
         *pos++ = WLAN_EID_MESH_CONFIG;
         *pos++ = IEEE80211_MESH_CONFIG_LEN;

         *pos++ = 1;
 

        memcpy(pos, sdata->u.mesh.mesh_pp_id, 4);
         pos += 4;
 

         memcpy(pos, sdata->u.mesh.mesh_pm_id, 4);
         pos += 4;
 

         memcpy(pos, sdata->u.mesh.mesh_cc_id, 4);
         pos += 4;
 

         memcpy(pos, sdata->u.mesh.mesh_sp_id, 4);
         pos += 4;
 

         memcpy(pos, sdata->u.mesh.mesh_auth_id, 4);
         pos += 4;
 

         memset(pos, 0x00, 1);
         pos += 1;
 

         sdata->u.mesh.accepting_plinks = mesh_plink_availables(sdata);
         *pos = CAPAB_FORWARDING;
         *pos++ |= sdata->u.mesh.accepting_plinks ? CAPAB_ACCEPT_PLINKS : 0x00;
         *pos++ = 0x00;
 
         return;*/
 }

 struct sk_buff *ieee80211_beacon_get(struct ieee80211_hw *hw,
                                      struct ieee80211_vif *vif)
 {
         struct ieee80211_local *local = hw_to_local(hw);
         struct sk_buff *skb = NULL;
         struct ieee80211_tx_info *info;
         struct ieee80211_sub_if_data *sdata = NULL;
         struct ieee80211_if_ap *ap = NULL;
         struct beacon_data *beacon;
         struct ieee80211_supported_band *sband;
         enum ieee80211_band band = local->hw.conf.channel->band;
 
         sband = local->hw.wiphy->bands[band];
 
         rcu_read_lock();
 
         sdata = vif_to_sdata(vif);
 
         if (sdata->vif.type == NL80211_IFTYPE_AP) {
                 ap = &sdata->u.ap;
                 beacon = rcu_dereference(ap->beacon);
                 if (ap && beacon) {
                         /*
                          * headroom, head length,
                          * tail length and maximum TIM length
                          */
                         skb = dev_alloc_skb(local->tx_headroom +
                                             beacon->head_len +
                                             beacon->tail_len + 256);
                         if (!skb)
                                 goto out;
 
                         skb_reserve(skb, local->tx_headroom);
                         memcpy(skb_put(skb, beacon->head_len), beacon->head,
                                beacon->head_len);
 
                         /*
                          * Not very nice, but we want to allow the driver to call
                          * ieee80211_beacon_get() as a response to the set_tim()
                          * callback. That, however, is already invoked under the
                          * sta_lock to guarantee consistent and race-free update
                          * of the tim bitmap in mac80211 and the driver.
                          */
                         if (local->tim_in_locked_section) {
                             //    ieee80211_beacon_add_tim(ap, skb, beacon);
                       } else {
                                 unsigned long flags;
 
                                 spin_lock_irqsave(&local->sta_lock, flags);
                              //   ieee80211_beacon_add_tim(ap, skb, beacon);
                                 spin_unlock_irqrestore(&local->sta_lock, flags);
                         }
 
                         if (beacon->tail)
                                 memcpy(skb_put(skb, beacon->tail_len),
                                        beacon->tail, beacon->tail_len);
                 } else
                         goto out;
         } else if (sdata->vif.type == NL80211_IFTYPE_ADHOC) {
                 struct ieee80211_if_ibss *ifibss = &sdata->u.ibss;
                 struct ieee80211_hdr *hdr;
                 struct sk_buff *presp = rcu_dereference(ifibss->presp);
 
                 if (!presp)
                         goto out;
 
                 skb = skb_copy(presp, GFP_ATOMIC);
                 if (!skb)
                         goto out;
 
                 hdr = (struct ieee80211_hdr *) skb_data(skb);
                 hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
                                                  IEEE80211_STYPE_BEACON);
         } else if (ieee80211_vif_is_mesh(&sdata->vif)) {
                 struct ieee80211_mgmt *mgmt;
                 u8 *pos;
 
                 /* headroom, head length, tail length and maximum TIM length */
                 skb = dev_alloc_skb(local->tx_headroom + 400);
                 if (!skb)
                         goto out;
 
                 skb_reserve(skb, local->hw.extra_tx_headroom);
                 mgmt = (struct ieee80211_mgmt *)
                         skb_put(skb, 24 + sizeof(mgmt->u.beacon));
                 memset(mgmt, 0, 24 + sizeof(mgmt->u.beacon));
                 mgmt->frame_control =
                     cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_BEACON);
                 memset(mgmt->da, 0xff, ETH_ALEN);
                 memcpy(mgmt->sa, sdata->dev->dev_addr, ETH_ALEN);
                 /* BSSID is left zeroed, wildcard value */
                 mgmt->u.beacon.beacon_int =
                         cpu_to_le16(sdata->vif.bss_conf.beacon_int);
                 mgmt->u.beacon.capab_info = 0x0; /* 0x0 for MPs */
 
                 pos = (u8*)skb_put(skb, 2);
                 *pos++ = WLAN_EID_SSID;
                 *pos++ = 0x0;
 
                 mesh_mgmt_ies_add(skb, sdata);
         } else {
                 WARN_ON(1);
                 goto out;
         }
 
         info = IEEE80211_SKB_CB(skb);
 
         info->flags |= IEEE80211_TX_INTFL_DONT_ENCRYPT;
         info->band = band;
         /*
          * XXX: For now, always use the lowest rate
          */
         info->control.rates[0].idx = 0;
         info->control.rates[0].count = 1;
         info->control.rates[1].idx = -1;
         info->control.rates[2].idx = -1;
         info->control.rates[3].idx = -1;
         info->control.rates[4].idx = -1;
         BUILD_BUG_ON(IEEE80211_TX_MAX_RATES != 5);
 
         info->control.vif = vif;
 
         info->flags |= IEEE80211_TX_CTL_NO_ACK;
         info->flags |= IEEE80211_TX_CTL_CLEAR_PS_FILT;
         info->flags |= IEEE80211_TX_CTL_ASSIGN_SEQ;
  out:
         rcu_read_unlock();
         return skb;
 }


#define STA_TX_BUFFER_EXPIRE (10 * HZ)

static int sta_info_buffer_expired(struct sta_info *sta,
                                    struct sk_buff *skb)
 {
         struct ieee80211_tx_info *info;
         int timeout;
 
         if (!skb)
                 return 0;
 
         info = IEEE80211_SKB_CB(skb);
 
         /* Timeout: (2 * listen_interval * beacon_int * 1024 / 1000000) sec */
         timeout = (sta->listen_interval *
                    sta->sdata->vif.bss_conf.beacon_int *
                    32 / 15625) * HZ;
         if (timeout < STA_TX_BUFFER_EXPIRE)
                 timeout = STA_TX_BUFFER_EXPIRE;
         return time_after(jiffies, info->control.jiffiess + timeout);
 }

static void sta_info_cleanup_expire_buffered(struct ieee80211_local *local,
                                              struct sta_info *sta)
 {
         unsigned long flags;
         struct sk_buff *skb;
         struct ieee80211_sub_if_data *sdata;
 
         if (skb_queue_empty(&sta->ps_tx_buf))
                 return;
 
         for (;;) {
                 spin_lock_irqsave(&sta->ps_tx_buf.lock, flags);
                 skb = skb_peek(&sta->ps_tx_buf);
                 if (sta_info_buffer_expired(sta, skb))
                         skb = __skb_dequeue(&sta->ps_tx_buf);
                 else
                         skb = NULL;
                 spin_unlock_irqrestore(&sta->ps_tx_buf.lock, flags);
 
                 if (!skb)
                         break;
 
                 sdata = sta->sdata;
                 local->total_ps_buffered--;
 #ifdef CONFIG_MAC80211_VERBOSE_PS_DEBUG
                 printk(KERN_DEBUG "Buffered frame expired (STA %pM)\n",
                        sta->sta.addr);
 #endif
                 dev_kfree_skb(skb);
 
                // if (skb_queue_empty(&sta->ps_tx_buf))
                  //       sta_info_clear_tim_bit(sta);
         }
 }

static void sta_info_cleanup(unsigned long data)
{

	struct ieee80211_local *local = (struct ieee80211_local *) data;
         struct sta_info *sta;
 
         rcu_read_lock();
         list_for_each_entry_rcu(sta, &local->sta_list, list)
                 sta_info_cleanup_expire_buffered(local, sta);
         rcu_read_unlock();
 
         if (local->quiescing)
                 return;
 
         local->sta_cleanup.expires =
                 ( STA_INFO_CLEANUP_INTERVAL);
         add_timer(&local->sta_cleanup);
}

void sta_info_init(struct ieee80211_local *local)
{
	spin_lock_init(&local->sta_lock);
	INIT_LIST_HEAD(&local->sta_list);

	init_timer(&local->sta_cleanup);
	local->sta_cleanup.expires = /*jiffies +*/ STA_INFO_CLEANUP_INTERVAL;
	local->sta_cleanup.data = (unsigned long) local;
	local->sta_cleanup.function = sta_info_cleanup;

#ifdef CONFIG_MAC80211_DEBUGFS
	//INIT_WORK(&local->sta_debugfs_add, sta_info_debugfs_add_task);
#endif
}

bool wiphy_idx_valid(int wiphy_idx)
 {
         return (wiphy_idx >= 0);
 }

void ieee80211_dynamic_ps_enable_work(struct work_struct *work)
 {
         struct ieee80211_local *local =
                 container_of(work, struct ieee80211_local,
                              dynamic_ps_enable_work);
         struct ieee80211_sub_if_data *sdata = local->ps_sdata;
 
         /* can only happen when PS was just disabled anyway */
         if (!sdata)
                 return;
 
         if (local->hw.conf.flags & IEEE80211_CONF_PS)
                 return;
 
         if (local->hw.flags & IEEE80211_HW_PS_NULLFUNC_STACK)
                 ieee80211_send_nullfunc(local, sdata, 1);
 
         local->hw.conf.flags |= IEEE80211_CONF_PS;
         ieee80211_hw_config(local, IEEE80211_CONF_CHANGE_PS);
 }
 
 void ieee80211_dynamic_ps_timer(unsigned long data)
 {
         struct ieee80211_local *local = (struct ieee80211_local *) data;
 
         if (local->quiescing || local->suspended)
                 return;
 
         ieee80211_queue_work(&local->hw, &local->dynamic_ps_enable_work);
 }

void ieee80211_dynamic_ps_disable_work(struct work_struct *work)
 {
         struct ieee80211_local *local =
                 container_of(work, struct ieee80211_local,
                              dynamic_ps_disable_work);
 
         if (local->hw.conf.flags & IEEE80211_CONF_PS) {
                 local->hw.conf.flags &= ~IEEE80211_CONF_PS;
                 ieee80211_hw_config(local, IEEE80211_CONF_CHANGE_PS);
         }
 
     //    ieee80211_wake_queues_by_reason(&local->hw,
       //                                  IEEE80211_QUEUE_STOP_REASON_PS);
 }

static inline u64 drv_prepare_multicast(struct ieee80211_local *local,
                                          int mc_count,
                                          struct dev_addr_list *mc_list)
  {
          u64 ret = 0;
  
          if (local->ops->prepare_multicast)
                  ret = local->ops->prepare_multicast(&local->hw, mc_count,
                                                      mc_list);
  
       //   trace_drv_prepare_multicast(local, mc_count, ret);
  
          return ret;
  }
 
 static inline void drv_configure_filter(struct ieee80211_local *local,
                                          unsigned int changed_flags,
                                          unsigned int *total_flags,
                                          u64 multicast)
  {
          might_sleep();
  
          local->ops->configure_filter(&local->hw, changed_flags, total_flags,
                                       multicast);
        //  trace_drv_configure_filter(local, changed_flags, total_flags,
          //                           multicast);
  }
 
void ieee80211_configure_filter(struct ieee80211_local *local)
  {
          u64 mc;
          unsigned int changed_flags;
          unsigned int new_flags = 0;
  
          if (atomic_read(&local->iff_promiscs))
                  new_flags |= FIF_PROMISC_IN_BSS;
  
          if (atomic_read(&local->iff_allmultis))
                  new_flags |= FIF_ALLMULTI;
  
          if (local->monitors || local->scanning)
                  new_flags |= FIF_BCN_PRBRESP_PROMISC;
  
          if (local->fif_fcsfail)
                  new_flags |= FIF_FCSFAIL;
  
          if (local->fif_plcpfail)
                  new_flags |= FIF_PLCPFAIL;
  
          if (local->fif_control)
                  new_flags |= FIF_CONTROL;
  
          if (local->fif_other_bss)
                  new_flags |= FIF_OTHER_BSS;
  
          if (local->fif_pspoll)
                  new_flags |= FIF_PSPOLL;
  
          spin_lock_bh(&local->filter_lock);
          changed_flags = local->filter_flags ^ new_flags;
  
          mc = drv_prepare_multicast(local, local->mc_count, local->mc_list);
          spin_unlock_bh(&local->filter_lock);
  
          /* be a bit nasty */
          new_flags |= (1<<31);
  
          drv_configure_filter(local, changed_flags, &new_flags, mc);
  
          WARN_ON(new_flags & (1<<31));
  
          local->filter_flags = new_flags & ~(1<<31);
  }
 
static void ieee80211_reconfig_filter(struct work_struct *work)
 {
         struct ieee80211_local *local =
                 container_of(work, struct ieee80211_local, reconfig_filter);
 
         ieee80211_configure_filter(local);
 }

static inline int drv_start(struct ieee80211_local *local)
  {
          int ret;
  
         local->started = true;
         smp_mb();
         ret = local->ops->start(&local->hw);
      //    trace_drv_start(local, ret);
         return ret;
  }
 
 static inline int drv_add_interface(struct ieee80211_local *local,
                                      struct ieee80211_if_init_conf *conf)
  {
          int ret = local->ops->add_interface(&local->hw, conf);
        //  trace_drv_add_interface(local, conf->mac_addr, conf->vif, ret);
          return ret;
  }
 
 static inline void clear_sta_flags(struct sta_info *sta, const u32 flags)
 {
         unsigned long irqfl;
 
         spin_lock_irqsave(&sta->flaglock, irqfl);
         sta->flags &= ~flags;
        spin_unlock_irqrestore(&sta->flaglock, irqfl);
 }

 static inline int drv_set_rts_threshold(struct ieee80211_local *local,
                                         u32 value)
 {
         int ret = 0;
         if (local->ops->set_rts_threshold)
                 ret = local->ops->set_rts_threshold(&local->hw, value);
       //  trace_drv_set_rts_threshold(local, value, ret);
         return ret;
 }

int ieee80211_reconfig(struct ieee80211_local *local)
 {
         struct ieee80211_hw *hw = &local->hw;
         struct ieee80211_sub_if_data *sdata;
         struct ieee80211_if_init_conf conf;
         struct sta_info *sta;
         unsigned long flags;
         int res;
         bool from_suspend = local->suspended;
 
         /*
          * We're going to start the hardware, at that point
          * we are no longer suspended and can RX frames.
          */
         local->suspended = false;
 
         /* restart hardware */
         if (local->open_count) {
                 res = drv_start(local);
 
       //          ieee80211_led_radio(local, true);
         }
 
         /* add interfaces */
         list_for_each_entry(sdata, &local->interfaces, list) {
                 if (sdata->vif.type != NL80211_IFTYPE_AP_VLAN &&
                     sdata->vif.type != NL80211_IFTYPE_MONITOR &&
                     netif_running(sdata->dev)) {
                         conf.vif = &sdata->vif;
                         conf.type = sdata->vif.type;
                         conf.mac_addr = sdata->dev->dev_addr;
                         res = drv_add_interface(local, &conf);
                 }
         }
 
         /* add STAs back */
         if (local->ops->sta_notify) {
                 spin_lock_irqsave(&local->sta_lock, flags);
                 list_for_each_entry(sta, &local->sta_list, list) {
                         sdata = sta->sdata;
                         if (sdata->vif.type == NL80211_IFTYPE_AP_VLAN)
                                 sdata = container_of(sdata->bss,
                                              struct ieee80211_sub_if_data,
                                              u.ap);
 
                         drv_sta_notify(local, &sdata->vif, STA_NOTIFY_ADD,
                                        &sta->sta);
                 }
                 spin_unlock_irqrestore(&local->sta_lock, flags);
         }
 
         /* Clear Suspend state so that ADDBA requests can be processed */
 
         rcu_read_lock();
 
         if (hw->flags & IEEE80211_HW_AMPDU_AGGREGATION) {
                 list_for_each_entry_rcu(sta, &local->sta_list, list) {
                         clear_sta_flags(sta, WLAN_STA_SUSPEND);
                 }
         }
 
         rcu_read_unlock();
 
         /* setup RTS threshold */
         drv_set_rts_threshold(local, hw->wiphy->rts_threshold);
 
         /* reconfigure hardware */
         ieee80211_hw_config(local, ~0);
 
         ieee80211_configure_filter(local);
 
         /* Finally also reconfigure all the BSS information */
         list_for_each_entry(sdata, &local->interfaces, list) {
                 u32 changed = ~0;
                 if (!netif_running(sdata->dev))
                         continue;
                 switch (sdata->vif.type) {
                 case NL80211_IFTYPE_STATION:
                         /* disable beacon change bits */
                         changed &= ~(BSS_CHANGED_BEACON |
                                      BSS_CHANGED_BEACON_ENABLED);
                         /* fall through */
                 case NL80211_IFTYPE_ADHOC:
                 case NL80211_IFTYPE_AP:
                 case NL80211_IFTYPE_MESH_POINT:
                         ieee80211_bss_info_change_notify(sdata, changed);
                         break;
                 case NL80211_IFTYPE_WDS:
                         break;
                 case NL80211_IFTYPE_AP_VLAN:
                 case NL80211_IFTYPE_MONITOR:
                         /* ignore virtual */
                         break;
                 case NL80211_IFTYPE_UNSPECIFIED:
                 case __NL80211_IFTYPE_AFTER_LAST:
                         WARN_ON(1);
                         break;
                }
         }
 
         /* add back keys
         list_for_each_entry(sdata, &local->interfaces, list)
                 if (netif_running(sdata->dev))
                         ieee80211_enable_keys(sdata);
 
         ieee80211_wake_queues_by_reason(hw,
                        IEEE80211_QUEUE_STOP_REASON_SUSPEND);
 */
         /*
          * If this is for hw restart things are still running.
          * We may want to change that later, however.
          */
         if (!from_suspend)
                 return 0;
 
#ifdef CONFIG_PM
         local->suspended = false;
 
         list_for_each_entry(sdata, &local->interfaces, list) {
                 switch(sdata->vif.type) {
                 case NL80211_IFTYPE_STATION:
                         ieee80211_sta_restart(sdata);
                         break;
                 case NL80211_IFTYPE_ADHOC:
                         ieee80211_ibss_restart(sdata);
                         break;
                 case NL80211_IFTYPE_MESH_POINT:
                         ieee80211_mesh_restart(sdata);
                         break;
                 default:
                         break;
                 }
         }
 
         add_timer(&local->sta_cleanup);
 
         spin_lock_irqsave(&local->sta_lock, flags);
         list_for_each_entry(sta, &local->sta_list, list)
                 mesh_plink_restart(sta);
         spin_unlock_irqrestore(&local->sta_lock, flags);
 #else
         WARN_ON(1);
 #endif
         return 0;
 }

static void ieee80211_restart_work(struct work_struct *work)
 {
         struct ieee80211_local *local =
                 container_of(work, struct ieee80211_local, restart_work);
 
         rtnl_lock();
         ieee80211_reconfig(local);
         rtnl_unlock();
 }

int ieee80211_build_preq_ies(struct ieee80211_local *local, u8 *buffer,
                              const u8 *ie, size_t ie_len)
 {
         struct ieee80211_supported_band *sband;
         u8 *pos, *supp_rates_len, *esupp_rates_len = NULL;
         int i;
 
         sband = local->hw.wiphy->bands[local->hw.conf.channel->band];
 
         pos = buffer;
 
         *pos++ = WLAN_EID_SUPP_RATES;
         supp_rates_len = pos;
         *pos++ = 0;
 
         for (i = 0; i < sband->n_bitrates; i++) {
                 struct ieee80211_rate *rate = &sband->bitrates[i];
 
                 if (esupp_rates_len) {
                         *esupp_rates_len += 1;
                 } else if (*supp_rates_len == 8) {
                         *pos++ = WLAN_EID_EXT_SUPP_RATES;
                         esupp_rates_len = pos;
                         *pos++ = 1;
                 } else
                         *supp_rates_len += 1;
 
                 *pos++ = rate->bitrate / 5;
         }
 
         if (sband->ht_cap.ht_supported) {
                 __le16 tmp = cpu_to_le16(sband->ht_cap.cap);
 
                 *pos++ = WLAN_EID_HT_CAPABILITY;
                 *pos++ = sizeof(struct ieee80211_ht_cap);
                 memset(pos, 0, sizeof(struct ieee80211_ht_cap));
                 memcpy(pos, &tmp, sizeof(u16));
                 pos += sizeof(u16);
                 /* TODO: needs a define here for << 2 */
                 *pos++ = sband->ht_cap.ampdu_factor |
                          (sband->ht_cap.ampdu_density << 2);
                 memcpy(pos, &sband->ht_cap.mcs, sizeof(sband->ht_cap.mcs));
                 pos += sizeof(sband->ht_cap.mcs);
                 pos += 2 + 4 + 1; /* ext info, BF cap, antsel */
         }
 
         /*
          * If adding more here, adjust code in main.c
          * that calculates local->scan_ies_len.
          */
 
         if (ie) {
                 memcpy(pos, ie, ie_len);
                 pos += ie_len;
         }
 
         return pos - buffer;
 }

static inline int drv_hw_scan(struct ieee80211_local *local,
                               struct cfg80211_scan_request *req)
 {
         int ret = local->ops->hw_scan(&local->hw, req);
       //  trace_drv_hw_scan(local, req, ret);
         return ret;
 }

static inline void drv_sw_scan_start(struct ieee80211_local *local)
 {
         if (local->ops->sw_scan_start)
                 local->ops->sw_scan_start(&local->hw);
       //  trace_drv_sw_scan_start(local);
 }

static int ieee80211_start_sw_scan(struct ieee80211_local *local)
 {
         struct ieee80211_sub_if_data *sdata;
 
         /*
          * Hardware/driver doesn't support hw_scan, so use software
          * scanning instead. First send a nullfunc frame with power save
          * bit on so that AP will buffer the frames for us while we are not
          * listening, then send probe requests to each channel and wait for
          * the responses. After all channels are scanned, tune back to the
          * original channel and send a nullfunc frame with power save bit
          * off to trigger the AP to send us all the buffered frames.
          *
          * Note that while local->sw_scanning is true everything else but
          * nullfunc frames and probe requests will be dropped in
          * ieee80211_tx_h_check_assoc().
          */
         drv_sw_scan_start(local);
 
         mutex_lock(&local->iflist_mtx);
         list_for_each_entry(sdata, &local->interfaces, list) {
                 if (!netif_running(sdata->dev))
                         continue;
 
                 /* disable beaconing */
                 if (sdata->vif.type == NL80211_IFTYPE_AP ||
                     sdata->vif.type == NL80211_IFTYPE_ADHOC ||
                     sdata->vif.type == NL80211_IFTYPE_MESH_POINT)
                         ieee80211_bss_info_change_notify(
                                sdata, BSS_CHANGED_BEACON_ENABLED);
 
                 /*
                  * only handle non-STA interfaces here, STA interfaces
                  * are handled in the scan state machine
                  */
         //        if (sdata->vif.type != NL80211_IFTYPE_STATION)
           //              netif_tx_stop_all_queues(sdata->dev);
         }
         mutex_unlock(&local->iflist_mtx);
 
         local->next_scan_state = SCAN_DECISION;
         local->scan_channel_idx = 0;
 
         ieee80211_configure_filter(local);
 
         /* TODO: start scan as soon as all nullfunc frames are ACKed */
         ieee80211_queue_delayed_work(&local->hw,
                                      &local->scan_work,
                                      IEEE80211_CHANNEL_TIME);
 
         return 0;
 }

static void ieee80211_restore_scan_ies(struct ieee80211_local *local)
 {
         kfree((void*)local->scan_req->ie);
         local->scan_req->ie = local->orig_ies;
         local->scan_req->ie_len = local->orig_ies_len;
 }

static int __ieee80211_start_scan(struct ieee80211_sub_if_data *sdata,
                                   struct cfg80211_scan_request *req)
 {
         struct ieee80211_local *local = sdata->local;
         struct ieee80211_if_managed *ifmgd = &sdata->u.mgd;
        int rc;

         if (local->scan_req)
                 return -EBUSY;
 
         if (local->ops->hw_scan) {
                 u8 *ies;
                 int ielen;
 
                 ies = (u8*)kmalloc(2 + IEEE80211_MAX_SSID_LEN +
                               local->scan_ies_len + req->ie_len, GFP_KERNEL);
                 if (!ies)
                         return -ENOMEM;
 
                 ielen = ieee80211_build_preq_ies(local, ies,
                                                  req->ie, req->ie_len);
                 local->orig_ies = req->ie;
                 local->orig_ies_len = req->ie_len;
                 req->ie = ies;
                 req->ie_len = ielen;
         }
 
         local->scan_req = req;
         local->scan_sdata = sdata;
 
         if (req != local->int_scan_req &&
             sdata->vif.type == NL80211_IFTYPE_STATION &&
             !list_empty(&ifmgd->work_list)) {
                 /* actually wait for the work it's doing to finish/time out */
                 set_bit(IEEE80211_STA_REQ_SCAN, &ifmgd->request);
                 return 0;
         }
 
         if (local->ops->hw_scan)
                 __set_bit(SCAN_HW_SCANNING, &local->scanning);
         else
                 __set_bit(SCAN_SW_SCANNING, &local->scanning);
         /*
          * Kicking off the scan need not be protected,
          * only the scan variable stuff, since now
          * local->scan_req is assigned and other callers
          * will abort their scan attempts.
          *
          * This avoids getting a scan_mtx -> iflist_mtx
          * dependency, so that the scan completed calls
          * have more locking freedom.
          */
 
     //    ieee80211_recalc_idle(local);
         mutex_unlock(&local->scan_mtx);
 
         if (local->ops->hw_scan)
                 rc = drv_hw_scan(local, local->scan_req);
         else
                 rc = ieee80211_start_sw_scan(local);
 
         mutex_lock(&local->scan_mtx);
 
         if (rc) {
                 if (local->ops->hw_scan)
                         ieee80211_restore_scan_ies(local);
                 local->scanning = 0;
 
     //            ieee80211_recalc_idle(local);
 
                 local->scan_req = NULL;
                 local->scan_sdata = NULL;
         }
 
         return rc;
 }

static int ieee80211_scan_state_decision(struct ieee80211_local *local,
                                          unsigned long *next_delay)
 {
         bool associated = false;
         struct ieee80211_sub_if_data *sdata;
 
         /* if no more bands/channels left, complete scan and advance to the idle state */
         if (local->scan_channel_idx >= local->scan_req->n_channels) {
                 ieee80211_scan_completed(&local->hw, false);
                 return 1;
         }
 
         /* check if at least one STA interface is associated */
         mutex_lock(&local->iflist_mtx);
         list_for_each_entry(sdata, &local->interfaces, list) {
                 if (!netif_running(sdata->dev))
                         continue;
 
                 if (sdata->vif.type == NL80211_IFTYPE_STATION) {
                         if (sdata->u.mgd.associated) {
                                 associated = true;
                                 break;
                         }
                 }
         }
         mutex_unlock(&local->iflist_mtx);
 
         if (local->scan_channel) {
                 /*
                * we're currently scanning a different channel, let's
                  * switch back to the operating channel now if at least
                  * one interface is associated. Otherwise just scan the
                  * next channel
                  */
                 if (associated)
                         local->next_scan_state = SCAN_ENTER_OPER_CHANNEL;
                 else
                         local->next_scan_state = SCAN_SET_CHANNEL;
         } else {
                 /*
                  * we're on the operating channel currently, let's
                  * leave that channel now to scan another one
                  */
                 local->next_scan_state = SCAN_LEAVE_OPER_CHANNEL;
         }
 
         *next_delay = 0;
         return 0;
 }

static void ieee80211_scan_state_set_channel(struct ieee80211_local *local,
                                              unsigned long *next_delay)
 {
         int skip;
         struct ieee80211_channel *chan;
         struct ieee80211_sub_if_data *sdata = local->scan_sdata;
 
         skip = 0;
         chan = local->scan_req->channels[local->scan_channel_idx];
 
         if (chan->flags & IEEE80211_CHAN_DISABLED ||
             (sdata->vif.type == NL80211_IFTYPE_ADHOC &&
              chan->flags & IEEE80211_CHAN_NO_IBSS))
                 skip = 1;
 
         if (!skip) {
                 local->scan_channel = chan;
                 if (ieee80211_hw_config(local,
                                         IEEE80211_CONF_CHANGE_CHANNEL))
                         skip = 1;
         }
 
         /* advance state machine to next channel/band */
         local->scan_channel_idx++;
 
         if (skip) {
                 /* if we skip this channel return to the decision state */
                 local->next_scan_state = SCAN_DECISION;
                 return;
         }
 
         /*
          * Probe delay is used to update the NAV, cf. 11.1.3.2.2
          * (which unfortunately doesn't say _why_ step a) is done,
          * but it waits for the probe delay or until a frame is
          * received - and the received frame would update the NAV).
          * For now, we do not support waiting until a frame is
          * received.
          *
          * In any case, it is not necessary for a passive scan.
          */
         if (chan->flags & IEEE80211_CHAN_PASSIVE_SCAN ||
             !local->scan_req->n_ssids) {
                 *next_delay = IEEE80211_PASSIVE_CHANNEL_TIME;
                 local->next_scan_state = SCAN_DECISION;
                 return;
         }
 
         /* active scan, send probes */
         *next_delay = IEEE80211_PROBE_DELAY;
         local->next_scan_state = SCAN_SEND_PROBE;
 }

static void ieee80211_scan_state_send_probe(struct ieee80211_local *local,
                                             unsigned long *next_delay)
 {
         int i;
         struct ieee80211_sub_if_data *sdata = local->scan_sdata;
 
         for (i = 0; i < local->scan_req->n_ssids; i++)
                 ieee80211_send_probe_req(
                         sdata, NULL,
                         local->scan_req->ssids[i].ssid,
                         local->scan_req->ssids[i].ssid_len,
                         local->scan_req->ie, local->scan_req->ie_len);
 
         /*
          * After sending probe requests, wait for probe responses
          * on the channel.
          */
         *next_delay = IEEE80211_CHANNEL_TIME;
         local->next_scan_state = SCAN_DECISION;
 }

static void ieee80211_scan_ps_enable(struct ieee80211_sub_if_data *sdata)
 {
         struct ieee80211_local *local = sdata->local;
         bool ps = false;
 
         /* FIXME: what to do when local->pspolling is true? */
 
         del_timer_sync(&local->dynamic_ps_timer);
         cancel_work_sync(&local->dynamic_ps_enable_work);
 
         if (local->hw.conf.flags & IEEE80211_CONF_PS) {
                 ps = true;
                 local->hw.conf.flags &= ~IEEE80211_CONF_PS;
                 ieee80211_hw_config(local, IEEE80211_CONF_CHANGE_PS);
         }
 
         if (!ps || !(local->hw.flags & IEEE80211_HW_PS_NULLFUNC_STACK))
                 /*
                  * If power save was enabled, no need to send a nullfunc
                  * frame because AP knows that we are sleeping. But if the
                  * hardware is creating the nullfunc frame for power save
                  * status (ie. IEEE80211_HW_PS_NULLFUNC_STACK is not
                  * enabled) and power save was enabled, the firmware just
                  * sent a null frame with power save disabled. So we need
                  * to send a new nullfunc frame to inform the AP that we
                  * are again sleeping.
                  */
                 ieee80211_send_nullfunc(local, sdata, 1);
 }

static void ieee80211_scan_state_leave_oper_channel(struct ieee80211_local *local,
                                                     unsigned long *next_delay)
 {
         struct ieee80211_sub_if_data *sdata;
 
         /*
          * notify the AP about us leaving the channel and stop all STA interfaces
          */
         mutex_lock(&local->iflist_mtx);
         list_for_each_entry(sdata, &local->interfaces, list) {
                 if (!netif_running(sdata->dev))
                         continue;
 
                 if (sdata->vif.type == NL80211_IFTYPE_STATION) {
                        // netif_tx_stop_all_queues(sdata->dev);
                         if (sdata->u.mgd.associated)
                                 ieee80211_scan_ps_enable(sdata);
                 }
         }
         mutex_unlock(&local->iflist_mtx);
 
         __set_bit(SCAN_OFF_CHANNEL, &local->scanning);
 
         /* advance to the next channel to be scanned */
         *next_delay = HZ / 10;
         local->next_scan_state = SCAN_SET_CHANNEL;
 }
 
 static void ieee80211_scan_ps_disable(struct ieee80211_sub_if_data *sdata)
 {
         struct ieee80211_local *local = sdata->local;
 
         if (!local->ps_sdata)
                 ieee80211_send_nullfunc(local, sdata, 0);
         else {
                 /*
                  * In !IEEE80211_HW_PS_NULLFUNC_STACK case the hardware
                  * will send a nullfunc frame with the powersave bit set
                  * even though the AP already knows that we are sleeping.
                  * This could be avoided by sending a null frame with power
                  * save bit disabled before enabling the power save, but
                  * this doesn't gain anything.
                  *
                  * When IEEE80211_HW_PS_NULLFUNC_STACK is enabled, no need
                  * to send a nullfunc frame because AP already knows that
                  * we are sleeping, let's just enable power save mode in
                  * hardware.
                  */
                 local->hw.conf.flags |= IEEE80211_CONF_PS;
                 ieee80211_hw_config(local, IEEE80211_CONF_CHANGE_PS);
         }
 }

 static void ieee80211_scan_state_enter_oper_channel(struct ieee80211_local *local,
                                                     unsigned long *next_delay)
 {
         struct ieee80211_sub_if_data *sdata = local->scan_sdata;
 
         /* switch back to the operating channel */
         local->scan_channel = NULL;
         ieee80211_hw_config(local, IEEE80211_CONF_CHANGE_CHANNEL);
 
         /*
          * notify the AP about us being back and restart all STA interfaces
          */
         mutex_lock(&local->iflist_mtx);
         list_for_each_entry(sdata, &local->interfaces, list) {
                 if (!netif_running(sdata->dev))
                         continue;
 
                 /* Tell AP we're back */
                 if (sdata->vif.type == NL80211_IFTYPE_STATION) {
                         if (sdata->u.mgd.associated)
                                 ieee80211_scan_ps_disable(sdata);
                   //      netif_tx_wake_all_queues(sdata->dev);
                 }
         }
         mutex_unlock(&local->iflist_mtx);
 
         __clear_bit(SCAN_OFF_CHANNEL, &local->scanning);
 
         *next_delay = HZ / 5;
         local->next_scan_state = SCAN_DECISION;
 }

void ieee80211_scan_work(struct work_struct *work)
 {
         struct ieee80211_local *local =
                 container_of(work, struct ieee80211_local, scan_work.work);
         struct ieee80211_sub_if_data *sdata = local->scan_sdata;
         unsigned long next_delay = 0;
 
         mutex_lock(&local->scan_mtx);
         if (!sdata || !local->scan_req) {
                 mutex_unlock(&local->scan_mtx);
                 return;
         }
 
         if (local->scan_req && !local->scanning) {
                 struct cfg80211_scan_request *req = local->scan_req;
                 int rc;
 
                 local->scan_req = NULL;
                 local->scan_sdata = NULL;
 
                 rc = __ieee80211_start_scan(sdata, req);
                 mutex_unlock(&local->scan_mtx);

                 if (rc)
                         ieee80211_scan_completed(&local->hw, true);
                 return;
         }
 
         mutex_unlock(&local->scan_mtx);

         /*
          * Avoid re-scheduling when the sdata is going away.
          */
         if (!netif_running(sdata->dev)) {
                 ieee80211_scan_completed(&local->hw, true);
                 return;
         }
 
         /*
          * as long as no delay is required advance immediately
          * without scheduling a new work
          */
         do {
                 switch (local->next_scan_state) {
                 case SCAN_DECISION:
                         if (ieee80211_scan_state_decision(local, &next_delay))
                                 return;
                         break;
                 case SCAN_SET_CHANNEL:
                         ieee80211_scan_state_set_channel(local, &next_delay);
                         break;
                 case SCAN_SEND_PROBE:
                         ieee80211_scan_state_send_probe(local, &next_delay);
                         break;
                 case SCAN_LEAVE_OPER_CHANNEL:
                         ieee80211_scan_state_leave_oper_channel(local, &next_delay);
                         break;
                 case SCAN_ENTER_OPER_CHANNEL:
                         ieee80211_scan_state_enter_oper_channel(local, &next_delay);
                         break;
                 }
         } while (next_delay == 0);
 
         ieee80211_queue_delayed_work(&local->hw, &local->scan_work, next_delay);
 }

struct ieee80211_hw *ieee80211_alloc_hw(size_t priv_data_len,
                                         const struct ieee80211_ops *ops)
 {
         struct ieee80211_local *local;
         int priv_size, i;
         struct wiphy *wiphy;
 
         /* Ensure 32-byte alignment of our private data and hw private data.
          * We use the wiphy priv data for both our ieee80211_local and for
          * the driver's private data
         *
          * In memory it'll be like this:
          *
          * +-------------------------+
          * | struct wiphy           |
          * +-------------------------+
          * | struct ieee80211_local  |
          * +-------------------------+
          * | driver's private data   |
          * +-------------------------+
          *
          */
         priv_size = ALIGN(sizeof(*local), NETDEV_ALIGN) + priv_data_len;
 
       /* wiphy = wiphy_new(&mac80211_config_ops, priv_size);
 
         if (!wiphy)
                 return NULL;
 
         wiphy->netnsok = true;
         wiphy->privid = mac80211_wiphy_privid;
 
         wiphy->bss_priv_size = sizeof(struct ieee80211_bss) -
                                sizeof(struct cfg80211_bss);
 
         local = wiphy_priv(wiphy);
 
        local->hw.wiphy = wiphy;*/
 
		wiphy=(struct wiphy*)IOMalloc(priv_size);
		memset(wiphy,0,priv_size);
		
		 local = (struct ieee80211_local*)wiphy_priv(wiphy);
		  local->hw.wiphy = wiphy;
		  
		//local=(struct ieee80211_local*)IOMalloc(priv_size);

		//memset(local,0,priv_size);
	
         local->hw.priv = (char *)local + ALIGN(sizeof(*local), NETDEV_ALIGN);

		
         BUG_ON(!ops->tx);
         BUG_ON(!ops->start);
         BUG_ON(!ops->stop);
         BUG_ON(!ops->config);
         BUG_ON(!ops->add_interface);
         BUG_ON(!ops->remove_interface);
         BUG_ON(!ops->configure_filter);
         local->ops = ops;
 
         /* set up some defaults */
         local->hw.queues = 1;
         local->hw.max_rates = 1;
         local->hw.conf.long_frame_max_tx_count = wiphy->retry_long;
         local->hw.conf.short_frame_max_tx_count = wiphy->retry_short;
         local->user_power_level = -1;
 
         INIT_LIST_HEAD(&local->interfaces);
         mutex_init(&local->iflist_mtx);
         mutex_init(&local->scan_mtx);
 
         spin_lock_init(&local->key_lock);
         spin_lock_init(&local->filter_lock);
         spin_lock_init(&local->queue_stop_reason_lock);
 
         INIT_DELAYED_WORK(&local->scan_work, ieee80211_scan_work,27);
 
         INIT_WORK(&local->restart_work, ieee80211_restart_work,28);
 
         INIT_WORK(&local->reconfig_filter, ieee80211_reconfig_filter,29);
 
         INIT_WORK(&local->dynamic_ps_enable_work,
                   ieee80211_dynamic_ps_enable_work,30);
         INIT_WORK(&local->dynamic_ps_disable_work,
                   ieee80211_dynamic_ps_disable_work,31);
         setup_timer(&local->dynamic_ps_timer,
                     ieee80211_dynamic_ps_timer, (unsigned long) local);
 
         sta_info_init(local);
 
         for (i = 0; i < IEEE80211_MAX_QUEUES; i++)
                 skb_queue_head_init(&local->pending[i]);
   /*      tasklet_init(&local->tx_pending_tasklet, ieee80211_tx_pending,
                      (unsigned long)local);
 
         tasklet_init(&local->tasklet,
                      ieee80211_tasklet_handler,
                      (unsigned long) local);*/
 
         skb_queue_head_init(&local->skb_queue);
         skb_queue_head_init(&local->skb_queue_unreliable);
 
         spin_lock_init(&local->ampdu_lock);
 
		my_hw=&local->hw;//local_to_hw(local);

		printf("ieee80211_alloc_hw [OK]\n");
	
		return my_hw;

 }
 
 
 void ieee80211_restart_hw(struct ieee80211_hw *hw)
 {
         struct ieee80211_local *local = hw_to_local(hw);
 
         /* use this reason, __ieee80211_resume will unblock it */
//         ieee80211_stop_queues_by_reason(hw,
  //               IEEE80211_QUEUE_STOP_REASON_SUSPEND);
 
        // schedule_work(&local->restart_work);
 }
 
 void ieee80211_start_tx_ba_cb_irqsafe(struct ieee80211_hw *hw, const u8 *ra,
				      u16 tid)
{}

int ieee80211_start_tx_ba_session(struct ieee80211_hw *hw, u8 *ra, u16 tid)
{
return 0;
}

void ieee80211_stop_tx_ba_cb_irqsafe(struct ieee80211_hw *hw, const u8 *ra,
				     u16 tid)
{}


void ieee80211_rx_irqsafe(struct ieee80211_hw *hw, struct sk_buff *skb)
{

    struct ieee80211_local *local = hw_to_local(hw);
    
    
  //  IOLog("ieee80211_rx_irqsafe\n");
	
	//PrintPacketHeader(skb->mac_data);
	/*char    *frame;
    frame = (char*)skb_data(skb);
    for (int i = 0; i < mbuf_len(skb->mac_data); i++)
    {
      IOLog("%02X", (u_int8_t)frame[i]);
    }*/
	
	//memcpy(skb->cb, status, sizeof(*status));
	//skb->pkt_type = IEEE80211_RX_MSG;
	skb_queue_tail(&local->skb_queue, skb);
	tasklet_schedule(&local->tasklet);
	//FIXME: tasklet only give the priv as argument must be changed
	//IOCreateThread((void(*)(void*))&ieee80211_tasklet_handler,local);
	//IOExitThread();
}

void ieee80211_scan_completed(struct ieee80211_hw *hw, int aborted)
{}

 void ieee80211_tx_status_irqsafe(struct ieee80211_hw *hw,
				 struct sk_buff *skb)
{}
 
 
 void ieee80211_unregister_hw(struct ieee80211_hw *hw)
 {}
 
 void ieee80211_wake_queues(struct ieee80211_hw *hw)
  {}
void ieee80211_wake_queue(struct ieee80211_hw *hw, int queue)
 {}
 
 
 
 