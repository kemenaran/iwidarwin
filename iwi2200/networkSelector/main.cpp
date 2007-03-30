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

#include "2200/defines.h" 
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

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)
inline void __list_add(struct list_head *new2,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new2;
	new2->next = next;
	new2->prev = prev;
	prev->next = new2;
}

inline void list_add_tail(struct list_head *new2, struct list_head *head)
{
	__list_add(new2, head->prev, head);
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

	struct ipw_priv priv0,priv;
	//struct net_device net_dev;
	struct ieee80211_device ieee;
	struct ieee80211_network nets;
																			
	int sel0,sel=-1;
	while (sel!=5)
	{
		priv=priv0;
		sp=sizeof(priv);
		result = getsockopt( fd, SYSPROTO_CONTROL, 0, &priv, &sp);
		priv.ieee = &ieee;			
		sp=sizeof(*priv.ieee);
		result = getsockopt( fd, SYSPROTO_CONTROL, 1, priv.ieee, &sp);
		priv.ieee->networks = (struct ieee80211_network*)malloc(MAX_NETWORK_COUNT * sizeof(struct ieee80211_network));
		memset(priv.ieee->networks, 0, MAX_NETWORK_COUNT * sizeof(struct ieee80211_network));		
		sp=sizeof(*priv.ieee->networks);
		result = getsockopt( fd, SYSPROTO_CONTROL, 2, priv.ieee->networks, &sp);
		if (priv.status & STATUS_ASSOCIATED)
		{
			priv.assoc_network=&nets;
			sp=sizeof(*priv.assoc_network);
			result = getsockopt( fd, SYSPROTO_CONTROL, 3, priv.assoc_network, &sp);
		}
		cout<<"\nWellcome to the insanelyMac SpacePort 0.1\n";
		printf("Adapter [mode: %d led: %s]\n",priv.ieee->iw_mode, priv.config & CFG_NO_LED ? "off" :	"on");
		if ((priv.status & STATUS_ASSOCIATED) && priv.assoc_network)
		{
			printf("Associated: '%s (%02x:%02x:%02x:%02x:%02x:%02x)' \n",
						escape_essid((const char*)priv.assoc_network->ssid, priv.assoc_network->ssid_len),
						MAC_ARG(priv.assoc_network->bssid));
		}
		cout<<"\n1) Turn card ";
		if (priv.status & (STATUS_RF_KILL_HW | STATUS_RF_KILL_SW)) cout<<"on"; else cout<<"off"; 
		cout<<"\n2) Network List \n3) Switch led \n4) Change mode"<<"\n5) Close Program \n0) Refresh";
		cout<<"\n\nEnter Option:  ";
		cin>>sel;
		cout<<"\n";

		
		switch (sel)
		{
			case 5:
			default:
				break;
			case 3:
				setsockopt(fd,SYSPROTO_CONTROL,3,NULL,0);
				break;
			case 4:
				if (!(priv.status & (STATUS_RF_KILL_HW | STATUS_RF_KILL_SW))) break;
				printf("type new mode or 0 to return\n 1=bss 2=ibss(adhoc) 3=monitor\n");
				cin>>sel0;
				if (sel0>0 && sel0<4)
				{
					int *i = (int*) malloc(sizeof (int));
					*i=(int)sel0;
					b=sizeof(int);
					setsockopt(fd,SYSPROTO_CONTROL,4,i,b);
				}
				break;
			case (1):
				//int *i = (int*) malloc(sizeof (int));
				//*i=1;
				//b=sizeof(int);
				setsockopt(fd,SYSPROTO_CONTROL,1,NULL,0);
				break;
			case (2):
				//TODO: use ipw_bestnetwork...
				if (priv.status & (STATUS_RF_KILL_HW | STATUS_RF_KILL_SW)) break;
				printf("hello world: send network list\n");
				if (priv.ieee->networks)
				{
					int ii,cn=0,vi=0;
					for (ii=0; ii<MAX_NETWORK_COUNT ;ii++)
					{
						if (priv.ieee->networks[ii].ssid_len>0)
						{
							cn++;
							printf("[%0d] '%s (%02x:%02x:%02x:%02x:%02x:%02x)' \n",cn,
							escape_essid((const char*)priv.ieee->networks[ii].ssid, priv.ieee->networks[ii].ssid_len),
							MAC_ARG(priv.ieee->networks[ii].bssid));
						}
					}
					if (cn>0)
					{
						printf("select network or type 0 to return\n");
						cin>>sel0;
						if (sel0>0 && sel0 <=cn)
						{
							for (ii=0; ii<MAX_NETWORK_COUNT ;ii++)
							if (priv.ieee->networks[ii].ssid_len>0)
							{
								vi++;
								if (vi==cn) break;
							}
							printf("connecting to '%s (%02x:%02x:%02x:%02x:%02x:%02x)'...\n",
							escape_essid((const char*)priv.ieee->networks[ii].ssid, priv.ieee->networks[ii].ssid_len),
							MAC_ARG(priv.ieee->networks[ii].bssid));
							setsockopt(fd,SYSPROTO_CONTROL,2,&priv.ieee->networks[ii], sizeof(priv.ieee->networks[ii]));
						}
					}
				}
				else
				if (priv.assoc_network)
				{
					printf("associated to network:\n");
					printf(" '%s (%02x:%02x:%02x:%02x:%02x:%02x)' \n",
						escape_essid((const char*)priv.assoc_network->ssid, priv.assoc_network->ssid_len),
						MAC_ARG(priv.assoc_network->bssid));
				}
				break;
		}
		
	}
	
	close(fd);
}
