
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

}


#include "iwi3945.h"
#include "ipw3945.h"
#include "net/ieee80211.h"
#include "net/ieee80211_radiotap.h"


#define le16_to_cpu(x)	OSSwapLittleToHostInt16(x)
#define le32_to_cpu(x)	OSSwapLittleToHostInt32(x)
#define cpu_to_le16(x)	OSSwapLittleToHostInt16(x)
#define cpu_to_le32(x)	OSSwapLittleToHostInt32(x)
typedef unsigned long long u64;
typedef signed short	s16;
typedef signed int	s32;


#pragma mark -
#pragma mark еее Misc Macros еее
#pragma mark -

/* macro to handle unaligned little endian data in firmware image */
#define GETLE32(p) ((p)[0] | (p)[1] << 8 | (p)[2] << 16 | (p)[3] << 24)

#define RELEASE(x) do { if(x) { (x)->release(); (x) = 0; } } while(0)

#define IWI_EEPROM_CTL(sc, val) do {							\
	MEM_WRITE_4((sc), IWI_MEM_EEPROM_CTL, (val));				\
	IOSleep(IWI_EEPROM_DELAY);									\
} while (/* CONSTCOND */0)

#pragma mark -
#pragma mark еее CSR_READ Macros еее
#pragma mark -

#define CSR_READ_1(mem, off)	\
	(UInt8)*((UInt8 *)mem + off)
	
#define CSR_READ_2(mem, off)											\
	OSReadLittleInt16((void *) mem, off)
	
#define CSR_READ_4(mem, off)											\
	OSReadLittleInt32((void *) mem, off)

#pragma mark -
#pragma mark еее CSR_WRITE Macros еее
#pragma mark -

#define CSR_WRITE_1(mem, off, reg)										\
	*((UInt8 *)mem + off) = (UInt8)reg

#define CSR_WRITE_2(mem, off, reg)										\
	OSWriteLittleInt16((void *) mem, off, reg)

#define CSR_WRITE_4(mem, off, reg)										\
	OSWriteLittleInt32((void *) mem, off, reg)
	
	
#pragma mark -
#pragma mark еее MEM_WRITE Macros еее
#pragma mark -

#define MEM_WRITE_1(mem, addr, val) do {                            \
	CSR_WRITE_4(mem, IWI_CSR_INDIRECT_ADDR, addr);				\
	CSR_WRITE_1(mem, IWI_CSR_INDIRECT_DATA, val);				\
} while (/* CONSTCOND */0)

#define MEM_WRITE_2(mem, addr, val) do {                            \
	CSR_WRITE_4(mem, IWI_CSR_INDIRECT_ADDR, addr);				\
	CSR_WRITE_2(mem, IWI_CSR_INDIRECT_DATA, val);				\
} while (/* CONSTCOND */0)

#define MEM_WRITE_4(mem, addr, val) do {                            \
	CSR_WRITE_4(mem, IWI_CSR_INDIRECT_ADDR, addr);				\
	CSR_WRITE_4(mem, IWI_CSR_INDIRECT_DATA, val);				\
} while (/* CONSTCOND */0)

/* not implemented
#define MEM_WRITE_MULTI_1(mem, addr, buf, len) do {                 \
	CSR_WRITE_4((mem), IWI_CSR_INDIRECT_ADDR, (addr));				\
	CSR_WRITE_MULTI_1((mem), IWI_CSR_INDIRECT_DATA, (buf), (len));	\
} while (0)
*/

#pragma mark -
#pragma mark еее Description #defines еее
#pragma mark -


#pragma mark -
#pragma mark еее Queue #defines еее
#pragma mark -

#define IWI_CMD_RING_COUNT			16
#define IWI_TX_RING_COUNT			64
#define IWI_RX_RING_COUNT			32

#define IWI_TX_DESC_SIZE	(sizeof (struct iwi_tx_desc))
#define IWI_CMD_DESC_SIZE	(sizeof (struct iwi_cmd_desc))

#pragma mark -
#pragma mark еее CSR Register Addresses еее
#pragma mark -

#define IWI_CSR_INTR					0x0008
#define IWI_CSR_INTR_MASK				0x000c
#define IWI_CSR_INDIRECT_ADDR			0x0010
#define IWI_CSR_INDIRECT_DATA			0x0014
#define IWI_CSR_AUTOINC_ADDR			0x0018
#define IWI_CSR_AUTOINC_DATA			0x001c
#define IWI_CSR_RST						0x0020
#define IWI_CSR_CTL						0x0024
#define IWI_CSR_IO						0x0030
#define IWI_CSR_CMD_BASE				0x0200
#define IWI_CSR_CMD_SIZE				0x0204
#define IWI_CSR_TX1_BASE				0x0208
#define IWI_CSR_TX1_SIZE				0x020c
#define IWI_CSR_TX2_BASE				0x0210
#define IWI_CSR_TX2_SIZE				0x0214
#define IWI_CSR_TX3_BASE				0x0218
#define IWI_CSR_TX3_SIZE				0x021c
#define IWI_CSR_TX4_BASE				0x0220
#define IWI_CSR_TX4_SIZE				0x0224
#define IWI_CSR_CMD_RIDX				0x0280
#define IWI_CSR_TX1_RIDX				0x0284
#define IWI_CSR_TX2_RIDX				0x0288
#define IWI_CSR_TX3_RIDX				0x028c
#define IWI_CSR_TX4_RIDX				0x0290
#define IWI_CSR_RX_RIDX					0x02a0
#define IWI_CSR_RX_BASE					0x0500
#define IWI_CSR_TABLE0_SIZE				0x0700
#define IWI_CSR_TABLE0_BASE				0x0704
#define IWI_CSR_CMD_WIDX				0x0f80
#define IWI_CSR_TX1_WIDX				0x0f84
#define IWI_CSR_TX2_WIDX				0x0f88
#define IWI_CSR_TX3_WIDX				0x0f8c
#define IWI_CSR_TX4_WIDX				0x0f90
#define IWI_CSR_RX_WIDX					0x0fa0
#define IWI_CSR_READ_INT				0x0ff4

#pragma mark -
#pragma mark еее Aliases еее
#pragma mark -

#define IWI_CSR_CURRENT_TX_RATE	IWI_CSR_TABLE0_BASE

#pragma mark -
#pragma mark еее Interrupt #defines for IWI_CSR_INTR еее
#pragma mark -

#define IWI_INTR_RX_DONE				0x00000002
#define IWI_INTR_CMD_DONE				0x00000800
#define IWI_INTR_TX1_DONE				0x00001000
#define IWI_INTR_TX2_DONE				0x00002000
#define IWI_INTR_TX3_DONE				0x00004000
#define IWI_INTR_TX4_DONE				0x00008000
#define IWI_INTR_FW_INITED				0x01000000
#define IWI_INTR_RADIO_OFF				0x04000000
#define IWI_INTR_FATAL_ERROR			0x40000000
#define IWI_INTR_PARITY_ERROR			0x80000000

#define IWI_INTR_MASK												\
	(IWI_INTR_RX_DONE | IWI_INTR_CMD_DONE |	IWI_INTR_TX1_DONE | 	\
	 IWI_INTR_TX2_DONE | IWI_INTR_TX3_DONE | IWI_INTR_TX4_DONE |	\
	 IWI_INTR_FW_INITED | IWI_INTR_RADIO_OFF |						\
	 IWI_INTR_FATAL_ERROR | IWI_INTR_PARITY_ERROR)

#pragma mark -
#pragma mark еее Reset #defines for IWI_CSR_RST еее
#pragma mark -

#define IWI_RST_PRINCETON_RESET			0x00000001
#define IWI_RST_SOFT_RESET				0x00000080
#define IWI_RST_MASTER_DISABLED			0x00000100
#define IWI_RST_STOP_MASTER				0x00000200

#pragma mark -
#pragma mark еее Some #defines for IWI_CSR_CTL еее
#pragma mark -

#define IWI_CTL_CLOCK_READY				0x00000001
#define IWI_CTL_ALLOW_STANDBY			0x00000002
#define IWI_CTL_INIT					0x00000004

#pragma mark -
#pragma mark еее Radio #defines for IWI_CSR_IO еее
#pragma mark -

#define IWI_IO_RADIO_ENABLED			0x00010000

#pragma mark -
#pragma mark еее Some #defines for IWI_CSR_READ_INT еее
#pragma mark -

#define IWI_READ_INT_INIT_HOST			0x20000000

#pragma mark -
#pragma mark еее Constants for command blocks (Firmware) еее
#pragma mark -

#define IWI_CB_DEFAULT_CTL				0x8cea0000
#define IWI_CB_MAXDATALEN				8191

#pragma mark -
#pragma mark еее Supported Rates еее
#pragma mark -

#define IWI_RATE_DS1					10
#define IWI_RATE_DS2					20
#define IWI_RATE_DS5					55
#define IWI_RATE_DS11					110
#define IWI_RATE_OFDM6					13
#define IWI_RATE_OFDM9					15
#define IWI_RATE_OFDM12					5
#define IWI_RATE_OFDM18					7
#define IWI_RATE_OFDM24					9
#define IWI_RATE_OFDM36					11
#define IWI_RATE_OFDM48					1
#define IWI_RATE_OFDM54					3

#pragma mark -
#pragma mark еее Header data types еее
#pragma mark -

#define IWI_HDR_TYPE_DATA				0
#define IWI_HDR_TYPE_COMMAND			1
#define IWI_HDR_TYPE_NOTIF				3
#define IWI_HDR_TYPE_FRAME				9

#define IWI_HDR_FLAG_IRQ				0x04


#define IWI_NOTIF_TYPE_ASSOCIATION		10
#define IWI_NOTIF_TYPE_AUTHENTICATION	11
#define IWI_NOTIF_TYPE_SCAN_CHANNEL		12
#define IWI_NOTIF_TYPE_SCAN_COMPLETE	13
#define IWI_NOTIF_TYPE_BEACON			17
#define IWI_NOTIF_TYPE_CALIBRATION		20
#define IWI_NOTIF_TYPE_NOISE			25

#define IWI_DEAUTHENTICATED				0
#define IWI_AUTHENTICATED				9

#define IWI_DEASSOCIATED				0
#define IWI_ASSOCIATED					12


#pragma mark -
#pragma mark еее Header for Transmittion еее
#pragma mark -

#define IWI_DATA_CMD_TX					0x0b

#define IWI_DATA_FLAG_SHPREAMBLE		0x04
#define IWI_DATA_FLAG_NO_WEP			0x20
#define IWI_DATA_FLAG_NEED_ACK			0x80

#define IWI_DATA_XFLAG_QOS				0x10

#define IWI_MAX_NSEG					6

#define IWI_CMD_ENABLE					2
#define IWI_CMD_SET_CONFIG				6
#define IWI_CMD_SET_ESSID				8
#define IWI_CMD_SET_MAC_ADDRESS			11
#define IWI_CMD_SET_RTS_THRESHOLD		15
#define IWI_CMD_SET_FRAG_THRESHOLD		16
#define IWI_CMD_SET_POWER_MODE			17
#define IWI_CMD_SET_WEP_KEY				18
#define IWI_CMD_SCAN					20
#define IWI_CMD_SCAN_REQUEST_EXT		26
#define IWI_CMD_ASSOCIATE				21
#define IWI_CMD_SET_RATES				22
#define IWI_CMD_ABORT_SCAN				23
#define IWI_CMD_SET_WME_PARAMS			25
#define IWI_CMD_SET_OPTIE				31
#define IWI_CMD_DISABLE					33
#define IWI_CMD_SET_IV					34
#define IWI_CMD_SET_TX_POWER			35
#define IWI_CMD_SET_SENSITIVITY			42
#define IWI_CMD_SET_WMEIE				84


#pragma mark -
#pragma mark еее Constants for Mode fields еее
#pragma mark -
#define IWI_MODE_11A					0
#define IWI_MODE_11B					1
#define IWI_MODE_11G					2

#pragma mark -
#pragma mark еее Possible values for command IWI_CMD_SET_POWER_MODE еее
#pragma mark -


#pragma mark -
#pragma mark еее ieee stuff еее
#pragma mark -

typedef IOPhysicalAddress dma_addr_t;

typedef signed char s8;
typedef unsigned char UInt8;


/*
 * EEPROM Related Definitions
 */


#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

# define __builtin_expect(x, expected_value) (x)
#define unlikely(x)	__builtin_expect(!!(x), 0)


#define IEEE_A            (1<<0)
#define IEEE_B            (1<<1)
#define IEEE_G            (1<<2)
#define IEEE_MODE_MASK    (IEEE_A|IEEE_B|IEEE_G)







#define IW_ESSID_MAX_SIZE 32

	
#define ETH_ALEN	6			

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((u8*)(x))[0],((u8*)(x))[1],((u8*)(x))[2],((u8*)(x))[3],((u8*)(x))[4],((u8*)(x))[5]

#define DEFAULT_RTS_THRESHOLD     2304U
#define BEACON_THRESHOLD 5



//#define _ipw_write8(ipw, ofs, val) writeb((val), (ipw) + (ofs))
#define _ipw_read8(mem, ofs) (UInt8)*((UInt8 *)mem + ofs)

#define _ipw_write8(mem, off, reg) *((UInt8 *)mem + off) = (UInt8)reg
#define _ipw_write32(ipw, ofs, val) OSWriteLittleInt32((void*)ipw, ofs, val)
// writel((val), (ipw) + (ofs))
#define _ipw_read32(ipw, ofs) OSReadLittleInt32((void*)ipw, ofs)
//readl((ipw) + (ofs))
#define _ipw_write16(ipw, ofs, val) OSWriteLittleInt16((void*)ipw ,ofs, val)

#define IPW_STATS_INTERVAL (2 * HZ)





#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})

#define local_irq_restore(x) 	do { typecheck(unsigned long,x); __asm__ __volatile__("pushl %0 ; popfl": /* no output */ :"g" (x):"memory", "cc"); } while (0)
#define local_irq_save(x)	__asm__ __volatile__("pushfl ; popl %0 ; cli":"=g" (x): /* no input */ :"memory")

#define	NETDEV_ALIGN		32
#define	NETDEV_ALIGN_CONST	(NETDEV_ALIGN - 1)

#define IPW_FW_MAJOR_VERSION 2
#define IPW_FW_MINOR_VERSION 3

#define IPW_FW_MINOR(x) ((x & 0xff) >> 8)
#define IPW_FW_MAJOR(x) (x & 0xff)

#define IPW_FW_VERSION ((IPW_FW_MINOR_VERSION << 8) | IPW_FW_MAJOR_VERSION)

#define IW_MODE_MONITOR 2
#define IW_MODE_ADHOC 1
#define IW_MODE_INFRA 0

#define LD_TIME_LINK_ON 300
#define LD_TIME_LINK_OFF 2700
#define LD_TIME_ACT_ON 250


#define DEFAULT_RTS_THRESHOLD     2304U
#define MIN_RTS_THRESHOLD         1U
#define MAX_RTS_THRESHOLD         2304U
#define DEFAULT_BEACON_INTERVAL   100U
#define	DEFAULT_SHORT_RETRY_LIMIT 7U
#define	DEFAULT_LONG_RETRY_LIMIT  4U

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

#define ARPHRD_IEEE80211_RADIOTAP 803
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)
		

/* ip address formatting macros */
#define IP_FORMAT	"%d.%d.%d.%d"
#define IP_CH(ip)	((u_char *)ip)
#define IP_LIST(ip)	IP_CH(ip)[0],IP_CH(ip)[1],IP_CH(ip)[2],IP_CH(ip)[3]

#define IPW_RATE_SCALE_MAX_WINDOW 62
#define IPW_INVALID_VALUE  -1

#define IPW_PLCP_QUIET_THRESH       (1)	/* packets */
#define IPW_ACTIVE_QUIET_TIME       (5)	/* msec */
#define PROBE_OPTION_MAX        0x4
#define WLAN_EID_SSID 0
#define PROBE_OPTION_MAX        0x4
//#define TX_CMD_FLG_SEQ_CTL_MSK  0x2000
#define TX_CMD_LIFE_TIME_INFINITE       0xFFFFFFFF
#define IPW_GOOD_CRC_TH             (1)

#define IPW_MAX_SCAN_SIZE 1024

#define ieee80211_is_probe_response(fc) \
   ((WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) && \
    ( WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_PROBE_RESP ))

#define ieee80211_is_management(fc) \
   (WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT)

#define ieee80211_is_control(fc) \
   (WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_CTL)

#define ieee80211_is_data(fc) \
   (WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_DATA)

#define ieee80211_is_assoc_request(fc) \
   (WLAN_FC_GET_STYPE(fc) == IEEE80211__STYPE_ASSOC_REQ)

#define ieee80211_is_reassoc_request(fc) \
   (WLAN_FC_GET_STYPE(fc) == IEEE80211__STYPE_REASSOC_REQ)

#define ETH_P_AARP	0x80F3		/* Appletalk AARP		*/
#define ETH_P_IPX	0x8137		/* IPX over DIX			*/

#define IW_QUAL_QUAL_UPDATED    0x01    /* Value was updated since last read */
#define IW_QUAL_LEVEL_UPDATED   0x02
#define IW_QUAL_NOISE_UPDATED   0x04
#define IW_QUAL_ALL_UPDATED     0x07
#define IW_QUAL_QUAL_INVALID    0x10    /* Driver doesn't provide value */
#define IW_QUAL_LEVEL_INVALID   0x20
#define IW_QUAL_NOISE_INVALID   0x40
#define IW_QUAL_ALL_INVALID     0x70
#define IW_QUAL_DBM             0x08    /* Level + Noise are dBm */
#define CHAN_UTIL_RATE_LCM 95040

#define IPW_ACTIVE_DWELL_TIME_24    (20)	/* all times in msec */
#define IPW_ACTIVE_DWELL_TIME_52    (10)
#define IPW_PASSIVE_DWELL_TIME_24   (20)	/* all times in msec */
#define IPW_PASSIVE_DWELL_TIME_52   (10)
#define IPW_PASSIVE_DWELL_BASE      (100)
#define IPW_CHANNEL_TUNE_TIME       5


#define IPW3945_CMD_QUEUE_NUM         4
#define IPW3945_NUM_OF_STATIONS 25
#define AP_ID           0
#define MULTICAST_ID    1
#define STA_ID          2
#define IPW3945_BROADCAST_ID    24
#define IPW3945_RX_BUF_SIZE 3000
#define IPW_INVALID_CHANNEL                   0xFF
#define IPW_INVALID_TX_CHANNEL                0xFE
#define CHECK_AND_PRINT(x) ((eeprom_ch_info[c].flags & IPW_CHANNEL_##x) ? # x " " : "")
#define IPW_RX_HDR(x) ((struct ipw_rx_frame_hdr *)(\
                       x->u.rx_frame.stats.payload + \
                       x->u.rx_frame.stats.mib_count))
#define IPW_RX_END(x) ((struct ipw_rx_frame_end *)(\
                       IPW_RX_HDR(x)->payload + \
                       le16_to_cpu(IPW_RX_HDR(x)->len)))
#define IPW_RX_STATS(x) (&x->u.rx_frame.stats)
#define IPW_RX_DATA(x) (IPW_RX_HDR(x)->payload)

#define ieee80211chan2mhz(x) \
        (((x) <= 14) ? \
        (((x) == 14) ? 2484 : ((x) * 5) + 2407) : \
        ((x) + 1000) * 5)
#define IEEE80211_FCTL_FTYPE		0x000c
#define IEEE80211_FCTL_STYPE		0x00f0		
	
#define NUM_RATES 12
#define IPW_MAX_GAIN_ENTRIES 78
#define IPW_CCK_FROM_OFDM_POWER_DIFF  -5
#define IPW_CCK_FROM_OFDM_INDEX_DIFF (10)
#define IPW_CCK_RATES  4
#define IPW_OFDM_RATES 8
#define IPW_MAX_RATES  (IPW_CCK_RATES + IPW_OFDM_RATES)

#define REPLY_RXON  0x10
#define	REPLY_RXON_ASSOC  0x11
#define REPLY_RXON_TIMING  0x14
#define REPLY_SCAN_CMD  0x80
#define REPLY_TX_PWR_TABLE_CMD  0x97
#define REPLY_TX_LINK_QUALITY_CMD  0x4e

#define IPW_CMD(x) case x : return #x
#define IPW_CMD3945(x) case REPLY_ ## x : return #x
#define IPW_INVALID_RATE     0xFF
#define IPW_RX_HDR(x) ((struct ipw_rx_frame_hdr *)(\
                       x->u.rx_frame.stats.payload + \
                       x->u.rx_frame.stats.mib_count))
#define IPW_RX_END(x) ((struct ipw_rx_frame_end *)(\
                       IPW_RX_HDR(x)->payload + \
                       le16_to_cpu(IPW_RX_HDR(x)->len)))
#define IPW_RX_STATS(x) (&x->u.rx_frame.stats)
#define IPW_RX_DATA(x) (IPW_RX_HDR(x)->payload)
#define IPW_TEMPERATURE_LIMIT_TIMER   6
#define PCI_LINK_CTRL      0x0F0

// OFDM rates mask values
#define RATE_SCALE_6M_INDEX  0
#define RATE_SCALE_9M_INDEX  1
#define RATE_SCALE_12M_INDEX 2
#define RATE_SCALE_18M_INDEX 3
#define RATE_SCALE_24M_INDEX 4
#define RATE_SCALE_36M_INDEX 5
#define RATE_SCALE_48M_INDEX 6
#define RATE_SCALE_54M_INDEX 7

// CCK rate mask values
#define RATE_SCALE_1M_INDEX   8
#define RATE_SCALE_2M_INDEX   9
#define RATE_SCALE_5_5M_INDEX 10
#define RATE_SCALE_11M_INDEX  11

// OFDM rates  plcp values
#define RATE_SCALE_6M_PLCP  13
#define RATE_SCALE_9M_PLCP  15
#define RATE_SCALE_12M_PLCP 5
#define RATE_SCALE_18M_PLCP 7
#define RATE_SCALE_24M_PLCP 9
#define RATE_SCALE_36M_PLCP 11
#define RATE_SCALE_48M_PLCP 1
#define RATE_SCALE_54M_PLCP 3

// CCK rate plcp values
#define RATE_SCALE_1M_PLCP    10
#define RATE_SCALE_2M_PLCP    20
#define RATE_SCALE_5_5M_PLCP  55
#define RATE_SCALE_11M_PLCP   110
#define TX_STATUS_ENTRY(x) case TX_STATUS_FAIL_ ## x: return #x

#define CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW          (0x08000000)



#define IWL_CMD_FAILED_MSK 0x40


/* #define vs. enum to keep from defaulting to 'large integer' */
#define	IWL_RATE_6M_MASK   (1<<IWL_RATE_6M_INDEX)
#define	IWL_RATE_9M_MASK   (1<<IWL_RATE_9M_INDEX)
#define	IWL_RATE_12M_MASK  (1<<IWL_RATE_12M_INDEX)
#define	IWL_RATE_18M_MASK  (1<<IWL_RATE_18M_INDEX)
#define	IWL_RATE_24M_MASK  (1<<IWL_RATE_24M_INDEX)
#define	IWL_RATE_36M_MASK  (1<<IWL_RATE_36M_INDEX)
#define	IWL_RATE_48M_MASK  (1<<IWL_RATE_48M_INDEX)
#define	IWL_RATE_54M_MASK  (1<<IWL_RATE_54M_INDEX)
#define	IWL_RATE_1M_MASK   (1<<IWL_RATE_1M_INDEX)
#define	IWL_RATE_2M_MASK   (1<<IWL_RATE_2M_INDEX)
#define	IWL_RATE_5M_MASK   (1<<IWL_RATE_5M_INDEX)
#define	IWL_RATE_11M_MASK  (1<<IWL_RATE_11M_INDEX)

#define IWL_CMD_QUEUE_NUM       4
#define IWL_MAX_SCAN_SIZE 1024


/* interrupt flags in INTA, set by uCode or hardware (e.g. dma),
 * acknowledged (reset) by host writing "1" to flagged bits. */


/* interrupt flags in FH (flow handler) (PCI busmaster DMA) */
#define BIT_FH_INT_ERR       (1<<31) /* Error */
#define BIT_FH_INT_HI_PRIOR  (1<<30) /* High priority Rx, bypass coalescing */
#define BIT_FH_INT_RX_CHNL2  (1<<18) /* Rx channel 2 (3945 only) */
#define BIT_FH_INT_RX_CHNL1  (1<<17) /* Rx channel 1 */
#define BIT_FH_INT_RX_CHNL0  (1<<16) /* Rx channel 0 */
#define BIT_FH_INT_TX_CHNL6  (1<<6)  /* Tx channel 6 (3945 only) */
#define BIT_FH_INT_TX_CHNL1  (1<<1)  /* Tx channel 1 */
#define BIT_FH_INT_TX_CHNL0  (1<<0)  /* Tx channel 0 */

#define FH_INT_RX_MASK        ( BIT_FH_INT_HI_PRIOR |  \
				BIT_FH_INT_RX_CHNL2 |  \
				BIT_FH_INT_RX_CHNL1 |  \
				BIT_FH_INT_RX_CHNL0 )

#define FH_INT_TX_MASK        ( BIT_FH_INT_TX_CHNL6 |  \
				BIT_FH_INT_TX_CHNL1 |  \
				BIT_FH_INT_TX_CHNL0 )

#define CMD_VAR_MAGIC 0xA987

#define IEEE80211_MAX_FRAG_THRESHOLD	2346
#define IEEE80211_MAX_RTS_THRESHOLD	2347
#define IEEE80211_MAX_AID		2007
#define IEEE80211_MAX_TIM_LEN		251
#define IEEE80211_MAX_DATA_LEN		2304
#define RATE_CONTROL_NUM_DOWN 20
#define RATE_CONTROL_NUM_UP   15
#define IWL_IBSS_MAC_HASH_SIZE 31
#define IWL_MAX_NUM_QUEUES   16
#define IWL_RX_BUF_SIZE 3000
#define IWL_DEFAULT_TX_POWER 0x0F
#define HOST_COMPLETE_TIMEOUT (HZ / 2)


