typedef unsigned char	u_char;
#include <libkern/OSByteOrder.h>
#include <iostream>
#include <stdlib.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_event.h>
#include <sys/errno.h>
#include <sys/ioctl.h>

//darwin_iwi NetworkSelector (rename to Space Port ?)
//created by asaf algawi AKA moseschrist for the insanelymac.com community.
//this file is free, the code is free, you are more than wellcome to manipulate
//the code, and do whatever you wish with it.
//
//disclaimer:
//i am not resposible for your computer, i don't promise anything.
//so if your laptop/desktop explodes due to the use of this software,
//it is your own damn problem. (but between us, it shouldn't :) )
//
//version 0.01:
//currently the software will print out the list of networks available
//in your area. (i hope)

//#include "defines.h" 
#include <IOKit/IOTypes.h>

struct list_head {
	struct list_head *next, *prev;
};

#define container_of(ptr, type, member)					\
({									\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);		\
	(type *)( (char *)__mptr - offsetof(type,member) );		\
})

#define __list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)
	
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

static inline void prefetch(const void *x) {;}

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
		 
struct ieee80211_sta_bss {
	struct list_head list;
	struct ieee80211_sta_bss *hnext;
	int users;

	UInt8 bssid[6];
	UInt8 ssid[32];
	size_t ssid_len;
	UInt16 capability; /* host byte order */
	int hw_mode;
	int channel;
	int freq;
	int rssi, signal, noise;
	UInt8 *wpa_ie;
	size_t wpa_ie_len;
	UInt8 *rsn_ie;
	size_t rsn_ie_len;
	UInt8 *wmm_ie;
	size_t wmm_ie_len;
#define IEEE80211_MAX_SUPP_RATES 32
	UInt8 supp_rates[IEEE80211_MAX_SUPP_RATES];
	size_t supp_rates_len;
	int beacon_int;
	UInt64 timestamp;

	int probe_resp;
	unsigned long last_update;

	/* during assocation, we save an ERP value from a probe response so
	 * that we can feed ERP info to the driver when handling the
	 * association completes. these fields probably won't be up-to-date
	 * otherwise, you probably don't want to use them. */
	int has_erp_value;
	UInt8 erp_value;
};

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((UInt8*)(x))[0],((UInt8*)(x))[1],((UInt8*)(x))[2],((UInt8*)(x))[3],((UInt8*)(x))[4],((UInt8*)(x))[5]

static inline int ieee80211_is_empty_essid(const char *essid, int essid_len)
{
	/* Single white space is for Linksys APs */
	if (essid_len == 1 && essid[0] == ' ')
		return 1;

	/* Otherwise, if the entire essid is 0, we assume it is hidden */
	while (essid_len) {
		essid_len--;
		if (essid[essid_len] != '\0')
			return 0;
	}

	return 1;
}

/* escape_essid() is intended to be used in debug (and possibly error)
 * messages. It should never be used for passing essid to user space. */
static inline const char *escape_essid(const char *essid, UInt8 essid_len)
{
	static char escaped[32 * 2 + 1];
	const char *s = essid;
	char *d = escaped;

	if (ieee80211_is_empty_essid(essid, essid_len)) {
		memcpy(escaped, "<hidden>", sizeof("<hidden>"));
		return escaped;
	}
	if (essid_len>32)
	essid_len = 32;//min(essid_len, (UInt8) 32);
	while (essid_len--) {
		if (*s == '\0') {
			*d++ = '\\';
			*d++ = '0';
			s++;
		} else {
			*d++ = *s++;
		}
	}
	*d = '\0';
	return escaped;
}

static inline void INIT_LIST_HEAD(struct list_head *list)
    {
        list->next = list;
        list->prev = list;
    }
	
using namespace std;
int main (int argc, char * const argv[]) {
	// insert code here...
	struct sockaddr_ctl       addr;
	int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd) {
        bzero(&addr, sizeof(addr)); // sets the sc_unit field to 0
        addr.sc_len = sizeof(addr);
        addr.sc_family = AF_SYSTEM;
        addr.ss_sysaddr = AF_SYS_CONTROL;
		}
    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    assert (strlen("insanelymac.iwidarwin.control") < MAX_KCTL_NAME);
    strcpy(info.ctl_name, "insanelymac.iwidarwin.control");
    int err;
    if (ioctl(fd, CTLIOCGINFO,&info)) {
        err = errno;
        printf("Could not get ID for kernel control. %d\n", err);
        return(-1);
    }
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;
	
	int result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	socklen_t b,sp;

																			
	int sel0,sel=-1;
	while (sel!=5)
	{
		cout<<"\nWelcome to the insanelyMac SpacePort 0.1\n";

		cout<<"\n1) Turn card on/off ";
		cout<<"\n2) Start scan ";
		cout<<"\n5) Close Program \n0) Refresh";
		cout<<"\n\nEnter Option:  ";
		cin>>sel;
		cout<<"\n";

		
		switch (sel)
		{
			case 5:
			default:
				break;
			case 3:
				break;
			case 4:

				break;
			case (1):
				setsockopt(fd,SYSPROTO_CONTROL,1,NULL,0);
				break;
			case (2):
				struct ieee80211_sta_bss bss[99];
				socklen_t sp=sizeof(bss);
				bss[0].ssid_len=0;
				int result = getsockopt( fd, SYSPROTO_CONTROL, 2, bss, &sp);
				printf("\nnetworks found:\n");
				if (result) break;
				int i=0;
				for (int ci=1;ci<=bss[0].ssid_len;ci++) {
					i++;
					printf("%d) " MAC_FMT " ('%s') cap %x hw %d ch %d\n", i,MAC_ARG(bss[ci].bssid),
					escape_essid((const char*)bss[ci].ssid, bss[ci].ssid_len),bss[ci].capability,bss[ci].hw_mode,bss[ci].channel);
				}
				if (i>0)
				{
					printf("\ntype unsecure network number to associate or 0 to return\n");
					cin>>sel0;
					if (sel0>0 && sel0<=i)
					{
					b=6;
					printf("trying to associate\n");
					setsockopt(fd,SYSPROTO_CONTROL,3,bss[sel0].bssid,b);
					}
				}
				break;
		}
	}
	
	close(fd);
}
