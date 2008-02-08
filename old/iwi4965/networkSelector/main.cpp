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
				break;
		}
	}
	
	close(fd);
}
