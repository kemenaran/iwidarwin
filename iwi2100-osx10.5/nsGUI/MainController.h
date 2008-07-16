/* MainController */

#import <Cocoa/Cocoa.h>

#include <iostream>
#include <stdlib.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_event.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include "2100/defines.h"

#define	STD_OPN		0x0001
#define	STD_WEP		0x0002
#define	STD_WPA		0x0004
#define	STD_WPA2	0x0008
#define	ENC_WEP		0x0010
#define	ENC_TKIP	0x0020
#define	ENC_WRAP	0x0040
#define	ENC_CCMP	0x0080
#define ENC_WEP40	0x1000
#define	ENC_WEP104	0x0100

#define	AUTH_OPN	0x0200
#define	AUTH_PSK	0x0400
#define	AUTH_MGT	0x0800

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

/* ip address formatting macros */
#define IP_FORMAT	"%d.%d.%d.%d"
#define IP_CH(ip)	((u_char *)ip)
#define IP_LIST(ip)	IP_CH(ip)[2],IP_CH(ip)[3],IP_CH(ip)[4],IP_CH(ip)[5]



@interface MainController : NSObject
{
    IBOutlet NSButton *CancelButton;
    IBOutlet NSButton *ConnectButton;
	IBOutlet NSWindow *about;
	IBOutlet NSButton *cancelChangeButton;
    IBOutlet NSButton *changeModeButton;
	IBOutlet NSButton *PowerButton;
	IBOutlet NSButton *Createibss;
	IBOutlet NSButton *NetButton;
	IBOutlet NSButton *LedButton;
	IBOutlet NSButton *ModeButton;
	IBOutlet NSButton *createButton;
	IBOutlet NSMatrix *selectedMode;
    IBOutlet NSTableView *dataOutlet;
    IBOutlet NSTextField *textOutlet;
	IBOutlet NSTextField *createNetworkTitle;
	IBOutlet NSPanel *cr_networkDialog;
	IBOutlet NSProgressIndicator *ProgressAnim;
	IBOutlet id listWindow;
	IBOutlet NSWindow* mainWindow;
	IBOutlet id appcontrol;
	IBOutlet NSTextField *modeChangeTitle;
	IBOutlet NSMenu *DockMenu;
	IBOutlet NSMenu *networksMenu;
	IBOutlet NSTextField *networkName;
	IBOutlet NSPanel *cr_passwordDialog;
	IBOutlet NSTextField *passwordName;
	IBOutlet NSPanel *cr_hiddenDialog;
	IBOutlet NSTextField *hiddenessid;
	IBOutlet NSButton *hexapassw;
	
	NSTimer *timecheck;
	NSTimeInterval tinterval;
	NSStatusItem *statusItem;
	NSImage *statusImage;
	NSImage *statusAltImage;

	socklen_t b,sp;
	struct ipw2100_priv priv0,priv;
	struct net_device net_dev;
	struct ieee80211_device ieee;
	struct ieee80211_network nets;
	struct sockaddr_ctl       addr;
	struct ctl_info info;
	int fd;
	NSMutableArray *networksData;
	bool wait_conect;
	NSImage *originalIcon;
	NSImage *iconImageBuffer;
	
}

- (IBAction)Cancelhidden:(id)sender;
- (IBAction)CancelConnect:(id)sender;
- (IBAction)Connect:(id)sender;
- (void)ConnectFromMenu:(id)sender;
- (IBAction)LEDAction:(id)sender;
- (IBAction)ModeAction:(id)sender;
- (IBAction)NetworkAction:(id)sender;
- (IBAction)PowerAction:(id)sender;
- (IBAction)quit:(id)sender;
- (IBAction)cancelModeChange:(id)sender;
- (IBAction)ModeChange:(id)sender;
- (IBAction)openAboutWindow:(id)sender;
- (IBAction)openMainWindow:(id)sender;
- (IBAction)createAdHoc:(id)sender;
- (IBAction)createAdHocSelected:(id)sender;
- (IBAction)createPassword:(id)sender;
- (IBAction)createPasswordSelected:(id)sender;
- (IBAction)createhidden:(id)sender;

- (void)tableView:(NSTableView *)aTableView
    setObjectValue:anObject
    forTableColumn:(NSTableColumn *)aTableColumn
	row:(int)rowIndex;
- (void)preAction;
//- (void)tableView:(NSTableView *)tableView sortDescriptorsDidChange:(NSArray *)oldDescriptors;
- (NSMenu *)applicationDockMenu:(NSApplication *)sender;
- (void)alertDidEnd:(NSAlert *)alert returnCode:(int)returnCode contextInfo:(void *)contextInfo;
@end
