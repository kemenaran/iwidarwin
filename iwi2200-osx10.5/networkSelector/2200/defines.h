typedef unsigned char	u_char;
#include <libkern/OSByteOrder.h>
#include <IOKit/IOTypes.h>
#include "net/ieee80211.h"
#include "net/ieee80211_crypt.h"
#include "ipw2200.h"
		 
#define        __iomem
typedef unsigned int mbuf_t;
typedef unsigned char	u8;
typedef unsigned short	u16;
typedef unsigned int	u32;
#define le16_to_cpu(x)	OSSwapLittleToHostInt16(x)
#define le32_to_cpu(x)	OSSwapLittleToHostInt32(x)
#define cpu_to_le16(x)	OSSwapLittleToHostInt16(x)
#define cpu_to_le32(x)	OSSwapLittleToHostInt32(x)
typedef unsigned long long u64;
typedef signed short s16;
typedef signed int s32;


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

#define IWI_POWER_MODE_CAM           0x00	//(always on)
#define IWI_POWER_INDEX_1            0x01
#define IWI_POWER_INDEX_2            0x02
#define IWI_POWER_INDEX_3            0x03
#define IWI_POWER_INDEX_4            0x04
#define IWI_POWER_INDEX_5            0x05
#define IWI_POWER_AC                 0x06
#define IWI_POWER_BATTERY            0x07
#define IWI_POWER_LIMIT              0x07
#define IWI_POWER_MASK               0x0F
#define IWI_POWER_ENABLED            0x10

#define IWI_RATESET_TYPE_NEGOCIATED		0
#define IWI_RATESET_TYPE_SUPPORTED		1


#define IWI_TXPOWER_MAX					20
#define IWI_TXPOWER_RATIO		(IEEE80211_TXPOWER_MAX / IWI_TXPOWER_MAX)

#define IWI_AUTH_OPEN					0
#define IWI_AUTH_SHARED					1
#define IWI_AUTH_NONE					3

#define IWI_POLICY_WME					1
#define IWI_POLICY_WPA					2


#define IWI_SCAN_TYPE_PASSIVE			1
#define IWI_SCAN_TYPE_BROADCAST			3

#define IWI_CHAN_5GHZ					(0 << 6)
#define IWI_CHAN_2GHZ					(1 << 6)



#define IWI_MEM_EEPROM_CTL				0x00300040

#define IWI_EEPROM_MAC					0x21

#define IWI_EEPROM_DELAY				1	/* minimum hold time (microsecond) */

#define IWI_EEPROM_C					(1 << 0)	/* Serial Clock */
#define IWI_EEPROM_S					(1 << 1)	/* Chip Select */
#define IWI_EEPROM_D					(1 << 2)	/* Serial data input */
#define IWI_EEPROM_Q					(1 << 4)	/* Serial data output */

#define IWI_EEPROM_SHIFT_D				2
#define IWI_EEPROM_SHIFT_Q				4


#pragma mark -
#pragma mark еее #defines added by tuxx еее
#pragma mark -

#define IWI_INDIRECT_ADDR_MASK			(~0x3ul)




#pragma mark -
#pragma mark еее ieee stuff еее
#pragma mark -

typedef IOPhysicalAddress dma_addr_t;


#define IPW_RESET_REG     0x00000020
#define IPW_RESET_REG_SW_RESET        (1<<7)
#define IPW_RESET_REG_MASTER_DISABLED (1<<8)
#define IPW_RESET_REG_STOP_MASTER     (1<<9)
#define CBD_RESET_REG_PRINCETON_RESET (1<<0)
#define IPW_GP_CNTRL_RW   0x00000024

#define IPW_READ_INT_REGISTER 0xFF4

#define IPW_GP_CNTRL_BIT_INIT_DONE	0x00000004

#define IPW_GP_CNTRL_BIT_HOST_ALLOWS_STANDBY 0x00000002


#define MAX_A_CHANNELS  37
#define MAX_B_CHANNELS  14
typedef signed char s8;
typedef unsigned char UInt8;


#define IPW_A_MODE                         0
#define IPW_B_MODE                         1
#define IPW_G_MODE                         2

#define IPW_CMD_TX_POWER                     35
#define IPW_CMD_SEED_NUMBER                  34
#define IPW_CMD_HOST_COMPLETE                 2


/*
 * EEPROM Related Definitions
 */

#define IPW_EEPROM_DATA_SRAM_ADDRESS (IPW_SHARED_LOWER_BOUND + 0x814)
#define IPW_EEPROM_DATA_SRAM_SIZE    (IPW_SHARED_LOWER_BOUND + 0x818)
#define IPW_EEPROM_LOAD_DISABLE      (IPW_SHARED_LOWER_BOUND + 0x81C)
#define IPW_EEPROM_DATA              (IPW_SHARED_LOWER_BOUND + 0x820)
#define IPW_EEPROM_UPPER_ADDRESS     (IPW_SHARED_LOWER_BOUND + 0x9E0)

#define IPW_STATION_TABLE_LOWER      (IPW_SHARED_LOWER_BOUND + 0xA0C)
#define IPW_STATION_TABLE_UPPER      (IPW_SHARED_LOWER_BOUND + 0xB0C)
#define IPW_REQUEST_ATIM             (IPW_SHARED_LOWER_BOUND + 0xB0C)
#define IPW_ATIM_SENT                (IPW_SHARED_LOWER_BOUND + 0xB10)
#define IPW_WHO_IS_AWAKE             (IPW_SHARED_LOWER_BOUND + 0xB14)
#define IPW_DURING_ATIM_WINDOW       (IPW_SHARED_LOWER_BOUND + 0xB18)

#define MSB                             1
#define LSB                             0

#define GET_EEPROM_ADDR(_wordoffset,_byteoffset) \
    ( WORD_TO_BYTE(_wordoffset) + (_byteoffset) )

/* EEPROM access by BYTE */
#define EEPROM_PME_CAPABILITY   (GET_EEPROM_ADDR(0x09,MSB))	/* 1 byte   */
#define EEPROM_MAC_ADDRESS      (GET_EEPROM_ADDR(0x21,LSB))	/* 6 byte   */
#define EEPROM_VERSION          (GET_EEPROM_ADDR(0x24,MSB))	/* 1 byte   */
#define EEPROM_NIC_TYPE         (GET_EEPROM_ADDR(0x25,LSB))	/* 1 byte   */
#define EEPROM_SKU_CAPABILITY   (GET_EEPROM_ADDR(0x25,MSB))	/* 1 byte   */
#define EEPROM_COUNTRY_CODE     (GET_EEPROM_ADDR(0x26,LSB))	/* 3 bytes  */
#define EEPROM_IBSS_CHANNELS_BG (GET_EEPROM_ADDR(0x28,LSB))	/* 2 bytes  */
#define EEPROM_IBSS_CHANNELS_A  (GET_EEPROM_ADDR(0x29,MSB))	/* 5 bytes  */
#define EEPROM_BSS_CHANNELS_BG  (GET_EEPROM_ADDR(0x2c,LSB))	/* 2 bytes  */
#define EEPROM_HW_VERSION       (GET_EEPROM_ADDR(0x72,LSB))	/* 2 bytes  */

/* NIC type as found in the one byte EEPROM_NIC_TYPE offset */
#define EEPROM_NIC_TYPE_0 0
#define EEPROM_NIC_TYPE_1 1
#define EEPROM_NIC_TYPE_2 2
#define EEPROM_NIC_TYPE_3 3
#define EEPROM_NIC_TYPE_4 4

/* Bluetooth Coexistence capabilities as found in EEPROM_SKU_CAPABILITY */
#define EEPROM_SKU_CAP_BT_CHANNEL_SIG  0x01	/* we can tell BT our channel # */
#define EEPROM_SKU_CAP_BT_PRIORITY     0x02	/* BT can take priority over us */
#define EEPROM_SKU_CAP_BT_OOB          0x04	/* we can signal BT out-of-band */

#define FW_MEM_REG_LOWER_BOUND          0x00300000
#define FW_MEM_REG_EEPROM_ACCESS        (FW_MEM_REG_LOWER_BOUND + 0x40)
#define IPW_EVENT_REG                   (FW_MEM_REG_LOWER_BOUND + 0x04)
#define EEPROM_BIT_SK                   (1<<0)
#define EEPROM_BIT_CS                   (1<<1)
#define EEPROM_BIT_DI                   (1<<2)
#define EEPROM_BIT_DO                   (1<<4)

#define EEPROM_CMD_READ                 0x2
#define IPW_INDIRECT_ADDR 0x00000010
#define IPW_INDIRECT_DATA 0x00000014
#define IPW_SHARED_LOWER_BOUND          0x00000200
#define IPW_EEPROM_IMAGE_SIZE          0x100
#define IPW_EEPROM_LOAD_DISABLE      (IPW_SHARED_LOWER_BOUND + 0x81C)


#define IPW_INTA_RW       0x00000008
#define IPW_INTA_MASK_R   0x0000000C
#define IPW_INDIRECT_ADDR 0x00000010
#define IPW_INDIRECT_DATA 0x00000014
#define IPW_AUTOINC_ADDR  0x00000018
#define IPW_AUTOINC_DATA  0x0000001C
#define IPW_RESET_REG     0x00000020
#define IPW_GP_CNTRL_RW   0x00000024

#define IPW_INTA_BIT_FW_INITIALIZATION_DONE        0x01000000
#define IPW_BIT_INT_HOST_SRAM_READ_INT_REGISTER (1 << 29)
#define IPW_GP_CNTRL_BIT_CLOCK_READY    0x00000001
#define IPW_GP_CNTRL_BIT_HOST_ALLOWS_STANDBY 0x00000002

/* Interrupts masks */
#define IPW_INTA_NONE   0x00000000

#define IPW_INTA_BIT_RX_TRANSFER                   0x00000002
#define IPW_INTA_BIT_STATUS_CHANGE                 0x00000010
#define IPW_INTA_BIT_BEACON_PERIOD_EXPIRED         0x00000020

//Inta Bits for CF
#define IPW_INTA_BIT_TX_CMD_QUEUE                  0x00000800
#define IPW_INTA_BIT_TX_QUEUE_1                    0x00001000
#define IPW_INTA_BIT_TX_QUEUE_2                    0x00002000
#define IPW_INTA_BIT_TX_QUEUE_3                    0x00004000
#define IPW_INTA_BIT_TX_QUEUE_4                    0x00008000

#define IPW_INTA_BIT_SLAVE_MODE_HOST_CMD_DONE      0x00010000

#define IPW_INTA_BIT_PREPARE_FOR_POWER_DOWN        0x00100000
#define IPW_INTA_BIT_POWER_DOWN                    0x00200000

#define IPW_INTA_BIT_FW_INITIALIZATION_DONE        0x01000000
#define IPW_INTA_BIT_FW_CARD_DISABLE_PHY_OFF_DONE  0x02000000
#define IPW_INTA_BIT_RF_KILL_DONE                  0x04000000
#define IPW_INTA_BIT_FATAL_ERROR             0x40000000
#define IPW_INTA_BIT_PARITY_ERROR            0x80000000

/* Interrupts enabled at init time. */
#define IPW_INTA_MASK_ALL                        \
        (IPW_INTA_BIT_TX_QUEUE_1               | \
	 IPW_INTA_BIT_TX_QUEUE_2               | \
	 IPW_INTA_BIT_TX_QUEUE_3               | \
	 IPW_INTA_BIT_TX_QUEUE_4               | \
	 IPW_INTA_BIT_TX_CMD_QUEUE             | \
	 IPW_INTA_BIT_RX_TRANSFER              | \
	 IPW_INTA_BIT_FATAL_ERROR              | \
	 IPW_INTA_BIT_PARITY_ERROR             | \
	 IPW_INTA_BIT_STATUS_CHANGE            | \
	 IPW_INTA_BIT_FW_INITIALIZATION_DONE   | \
	 IPW_INTA_BIT_BEACON_PERIOD_EXPIRED    | \
	 IPW_INTA_BIT_SLAVE_MODE_HOST_CMD_DONE | \
	 IPW_INTA_BIT_PREPARE_FOR_POWER_DOWN   | \
	 IPW_INTA_BIT_POWER_DOWN               | \
         IPW_INTA_BIT_RF_KILL_DONE )



#define IPW_NIC_SRAM_LOWER_BOUND        0x00000000
#define IPW_NIC_SRAM_UPPER_BOUND        0x00030000

#define CBD_RESET_REG_PRINCETON_RESET (1<<0)
#define IPW_START_STANDBY             (1<<2)
#define IPW_ACTIVITY_LED              (1<<4)
#define IPW_ASSOCIATED_LED            (1<<5)
#define IPW_OFDM_LED                  (1<<6)
#define IPW_RESET_REG_SW_RESET        (1<<7)
#define IPW_RESET_REG_MASTER_DISABLED (1<<8)
#define IPW_RESET_REG_STOP_MASTER     (1<<9)
#define IPW_GATE_ODMA                 (1<<25)
#define IPW_GATE_IDMA                 (1<<26)
#define IPW_ARC_KESHET_CONFIG         (1<<27)
#define IPW_GATE_ADMA                 (1<<29)


#define IPW_CMD_HOST_COMPLETE                 2
#define IPW_CMD_POWER_DOWN                    4
#define IPW_CMD_SYSTEM_CONFIG                 6
#define IPW_CMD_MULTICAST_ADDRESS             7
#define IPW_CMD_SSID                          8
#define IPW_CMD_ADAPTER_ADDRESS              11
#define IPW_CMD_PORT_TYPE                    12
#define IPW_CMD_RTS_THRESHOLD                15
#define IPW_CMD_FRAG_THRESHOLD               16
#define IPW_CMD_POWER_MODE                   17
#define IPW_CMD_WEP_KEY                      18
#define IPW_CMD_TGI_TX_KEY                   19
#define IPW_CMD_SCAN_REQUEST                 20
#define IPW_CMD_ASSOCIATE                    21
#define IPW_CMD_SUPPORTED_RATES              22
#define IPW_CMD_SCAN_ABORT                   23
#define IPW_CMD_TX_FLUSH                     24
#define IPW_CMD_QOS_PARAMETERS               25
#define IPW_CMD_SCAN_REQUEST_EXT             26
#define IPW_CMD_DINO_CONFIG                  30
#define IPW_CMD_RSN_CAPABILITIES             31
#define IPW_CMD_RX_KEY                       32
#define IPW_CMD_CARD_DISABLE                 33
#define IPW_CMD_SEED_NUMBER                  34
#define IPW_CMD_TX_POWER                     35
#define IPW_CMD_COUNTRY_INFO                 36
#define IPW_CMD_AIRONET_INFO                 37
#define IPW_CMD_AP_TX_POWER                  38
#define IPW_CMD_CCKM_INFO                    39
#define IPW_CMD_CCX_VER_INFO                 40
#define IPW_CMD_SET_CALIBRATION              41
#define IPW_CMD_SENSITIVITY_CALIB            42
#define IPW_CMD_RETRY_LIMIT                  51
#define IPW_CMD_IPW_PRE_POWER_DOWN           58
#define IPW_CMD_VAP_BEACON_TEMPLATE          60
#define IPW_CMD_VAP_DTIM_PERIOD              61
#define IPW_CMD_EXT_SUPPORTED_RATES          62
#define IPW_CMD_VAP_LOCAL_TX_PWR_CONSTRAINT  63
#define IPW_CMD_VAP_QUIET_INTERVALS          64
#define IPW_CMD_VAP_CHANNEL_SWITCH           65
#define IPW_CMD_VAP_MANDATORY_CHANNELS       66
#define IPW_CMD_VAP_CELL_PWR_LIMIT           67
#define IPW_CMD_VAP_CF_PARAM_SET             68
#define IPW_CMD_VAP_SET_BEACONING_STATE      69
#define IPW_CMD_MEASUREMENT                  80
#define IPW_CMD_POWER_CAPABILITY             81
#define IPW_CMD_SUPPORTED_CHANNELS           82
#define IPW_CMD_TPC_REPORT                   83
#define IPW_CMD_WME_INFO                     84
#define IPW_CMD_PRODUCTION_COMMAND	     85
#define IPW_CMD_LINKSYS_EOU_INFO             90


#define IPW_MAX_RATES 12

#define IPW_RX_READ_INDEX               (0x000002A0)

#define IPW_RATE_CAPABILITIES 1
#define IPW_RATE_CONNECT      0


#define IEEE80211_CCK_MODULATION    (1<<0)
#define IEEE80211_OFDM_MODULATION   (1<<1)

#define IEEE80211_24GHZ_BAND     (1<<0)
#define IEEE80211_52GHZ_BAND     (1<<1)

#define IEEE80211_CCK_RATE_1MB		        0x02
#define IEEE80211_CCK_RATE_2MB		        0x04
#define IEEE80211_CCK_RATE_5MB		        0x0B
#define IEEE80211_CCK_RATE_11MB		        0x16
#define IEEE80211_OFDM_RATE_6MB		        0x0C
#define IEEE80211_OFDM_RATE_9MB		        0x12
#define IEEE80211_OFDM_RATE_12MB		0x18
#define IEEE80211_OFDM_RATE_18MB		0x24
#define IEEE80211_OFDM_RATE_24MB		0x30
#define IEEE80211_OFDM_RATE_36MB		0x48
#define IEEE80211_OFDM_RATE_48MB		0x60
#define IEEE80211_OFDM_RATE_54MB		0x6C
#define IEEE80211_BASIC_RATE_MASK		0x80

#define IEEE80211_CCK_RATE_1MB_MASK		(1<<0)
#define IEEE80211_CCK_RATE_2MB_MASK		(1<<1)
#define IEEE80211_CCK_RATE_5MB_MASK		(1<<2)
#define IEEE80211_CCK_RATE_11MB_MASK		(1<<3)
#define IEEE80211_OFDM_RATE_6MB_MASK		(1<<4)
#define IEEE80211_OFDM_RATE_9MB_MASK		(1<<5)
#define IEEE80211_OFDM_RATE_12MB_MASK		(1<<6)
#define IEEE80211_OFDM_RATE_18MB_MASK		(1<<7)
#define IEEE80211_OFDM_RATE_24MB_MASK		(1<<8)
#define IEEE80211_OFDM_RATE_36MB_MASK		(1<<9)
#define IEEE80211_OFDM_RATE_48MB_MASK		(1<<10)
#define IEEE80211_OFDM_RATE_54MB_MASK		(1<<11)

#define IEEE80211_CCK_RATES_MASK	        0x0000000F
#define IEEE80211_CCK_BASIC_RATES_MASK	(IEEE80211_CCK_RATE_1MB_MASK | \
	IEEE80211_CCK_RATE_2MB_MASK)
#define IEEE80211_CCK_DEFAULT_RATES_MASK	(IEEE80211_CCK_BASIC_RATES_MASK | \
        IEEE80211_CCK_RATE_5MB_MASK | \
        IEEE80211_CCK_RATE_11MB_MASK)

#define IEEE80211_OFDM_RATES_MASK		0x00000FF0
#define IEEE80211_OFDM_BASIC_RATES_MASK	(IEEE80211_OFDM_RATE_6MB_MASK | \
	IEEE80211_OFDM_RATE_12MB_MASK | \
	IEEE80211_OFDM_RATE_24MB_MASK)
#define IEEE80211_OFDM_DEFAULT_RATES_MASK	(IEEE80211_OFDM_BASIC_RATES_MASK | \
	IEEE80211_OFDM_RATE_9MB_MASK  | \
	IEEE80211_OFDM_RATE_18MB_MASK | \
	IEEE80211_OFDM_RATE_36MB_MASK | \
	IEEE80211_OFDM_RATE_48MB_MASK | \
	IEEE80211_OFDM_RATE_54MB_MASK)
#define IEEE80211_DEFAULT_RATES_MASK (IEEE80211_OFDM_DEFAULT_RATES_MASK | \
                                IEEE80211_CCK_DEFAULT_RATES_MASK)

#define IEEE80211_NUM_OFDM_RATES	    8
#define IEEE80211_NUM_CCK_RATES	            4
#define IEEE80211_OFDM_SHIFT_MASK_A         4


#define CB_LAST_VALID     0x20000000
#define CB_INT_ENABLED    0x40000000
#define CB_VALID          0x80000000
#define CB_SRC_LE         0x08000000
#define CB_DEST_LE        0x04000000
#define CB_SRC_AUTOINC    0x00800000
#define CB_SRC_IO_GATED   0x00400000
#define CB_DEST_AUTOINC   0x00080000
#define CB_SRC_SIZE_LONG  0x00200000
#define CB_DEST_SIZE_LONG 0x00020000

#define IPW_SHARED_SRAM_SIZE               0x00030000
#define IPW_SHARED_SRAM_DMA_CONTROL        0x00027000
#define CB_MAX_LENGTH                      0x1FFF

#define IPW_DMA_I_CURRENT_CB  0x003000D0
#define IPW_DMA_O_CURRENT_CB  0x003000D4
#define IPW_DMA_I_DMA_CONTROL 0x003000A4
#define IPW_DMA_I_CB_BASE     0x003000A0



#define DMA_CONTROL_SMALL_CB_CONST_VALUE 0x00540000
#define DMA_CB_STOP_AND_ABORT            0x00000C00
#define DMA_CB_START                     0x00000100
#define IPW_INDIRECT_ADDR_MASK (~0x3ul)


#define IPW_REGISTER_DOMAIN1_END        0x00001000


#define IPW_INTERNAL_CMD_EVENT 	0X00300004
#define IPW_BASEBAND_POWER_DOWN 0x00000001

#define IPW_MEM_HALT_AND_RESET  0x003000e0

/* defgroup bits_halt_reset MEM_HALT_AND_RESET register bits */
#define IPW_BIT_HALT_RESET_ON	0x80000000
#define IPW_BIT_HALT_RESET_OFF 	0x00000000

#define DINO_ENABLE_SYSTEM 0x80	/* 1 = baseband processor on, 0 = reset */
#define DINO_ENABLE_CS     0x40	/* 1 = enable ucode load */
#define DINO_RXFIFO_DATA   0x01	/* 1 = data available */
#define IPW_BASEBAND_CONTROL_STATUS	0X00200000
#define IPW_BASEBAND_TX_FIFO_WRITE	0X00200004
#define IPW_BASEBAND_RX_FIFO_READ	0X00200004
#define IPW_BASEBAND_CONTROL_STORE	0X00200010

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define __builtin_expect(x, expected_value) (x)
#define unlikely(x)	__builtin_expect(!!(x), 0)
#define likely(x) __builtin_expect(!!(x), 1)

#define STATUS_HCMD_ACTIVE      (1<<0)	/**< host command in progress */

#define STATUS_INT_ENABLED      (1<<1)
#define STATUS_RF_KILL_HW       (1<<2)
#define STATUS_RF_KILL_SW       (1<<3)
#define STATUS_RF_KILL_MASK     (STATUS_RF_KILL_HW | STATUS_RF_KILL_SW)

#define STATUS_INIT             (1<<5)
#define STATUS_AUTH             (1<<6)
#define STATUS_ASSOCIATED       (1<<7)
#define STATUS_STATE_MASK       (STATUS_INIT | STATUS_AUTH | STATUS_ASSOCIATED)

#define STATUS_ASSOCIATING      (1<<8)
#define STATUS_DISASSOCIATING   (1<<9)
#define STATUS_ROAMING          (1<<10)
#define STATUS_EXIT_PENDING     (1<<11)
#define STATUS_DISASSOC_PENDING (1<<12)
#define STATUS_STATE_PENDING    (1<<13)

#define STATUS_SCAN_PENDING     (1<<20)
#define STATUS_SCANNING         (1<<21)
#define STATUS_SCAN_ABORTING    (1<<22)
#define STATUS_SCAN_FORCED      (1<<23)

#define STATUS_LED_LINK_ON      (1<<24)
#define STATUS_LED_ACT_ON       (1<<25)

#define STATUS_INDIRECT_BYTE    (1<<28)	/* sysfs entry configured for access */
#define STATUS_INDIRECT_DWORD   (1<<29)	/* sysfs entry configured for access */
#define STATUS_DIRECT_DWORD     (1<<30)	/* sysfs entry configured for access */

#define STATUS_SECURITY_UPDATED (1<<31)	/* Security sync needed */

#define CFG_STATIC_CHANNEL      (1<<0)	/* Restrict assoc. to single channel */
#define CFG_STATIC_ESSID        (1<<1)	/* Restrict assoc. to single SSID */
#define CFG_STATIC_BSSID        (1<<2)	/* Restrict assoc. to single BSSID */
#define CFG_CUSTOM_MAC          (1<<3)
#define CFG_PREAMBLE_LONG       (1<<4)
#define CFG_ADHOC_PERSIST       (1<<5)
#define CFG_ASSOCIATE           (1<<6)
#define CFG_FIXED_RATE          (1<<7)
#define CFG_ADHOC_CREATE        (1<<8)
#define CFG_NO_LED              (1<<9)
#define CFG_BACKGROUND_SCAN     (1<<10)
#define CFG_SPEED_SCAN          (1<<11)
#define CFG_NET_STATS           (1<<12)

#define IEEE_A            (1<<0)
#define IEEE_B            (1<<1)
#define IEEE_G            (1<<2)
#define IEEE_MODE_MASK    (IEEE_A|IEEE_B|IEEE_G)







#define CFG_BT_COEXISTENCE_SIGNAL_CHNL  0x01	/* tell BT our chnl # */
#define CFG_BT_COEXISTENCE_DEFER        0x02	/* defer our Tx if BT traffic */
#define CFG_BT_COEXISTENCE_KILL         0x04	/* kill our Tx if BT traffic */
#define CFG_BT_COEXISTENCE_WME_OVER_BT  0x08	/* multimedia extensions */
#define CFG_BT_COEXISTENCE_OOB          0x10	/* signal BT via out-of-band */

#define IPW_SCAN_CHANNELS 54


#define IW_SCAN_TYPE_ACTIVE 0
#define IW_SCAN_TYPE_PASSIVE 1
#define MAX_SPEED_SCAN 100

#define IW_ESSID_MAX_SIZE 32

	
#define ETH_ALEN	6			
#define IPW_RX_WRITE_INDEX              (0x00000FA0)
#define RX_FRAME_TYPE                      0x09
#define RX_HOST_NOTIFICATION_TYPE          0x03
#define RX_HOST_CMD_RESPONSE_TYPE          0x04
#define RX_TX_FRAME_RESPONSE_TYPE          0x05


#define IEEE80211_STATMASK_SIGNAL (1<<0)
#define IEEE80211_STATMASK_RSSI (1<<1)
#define IEEE80211_STATMASK_NOISE (1<<2)
#define IEEE80211_STATMASK_RATE (1<<3)
#define IEEE80211_STATMASK_WEMASK 0x7
#define IPW_RSSI_TO_DBM 112


#define IPW_RX_NOTIFICATION_SIZE sizeof(struct ipw_rx_header) + 12
#define IPW_RX_FRAME_SIZE        (unsigned int)(sizeof(struct ipw_rx_header) + \
                                 sizeof(struct ipw_rx_frame))

#define DEPTH_RSSI 8
#define DEPTH_NOISE 16
#define IEEE80211_FTYPE_MGMT		0x0000
#define IEEE80211_FTYPE_CTL		0x0004
#define IEEE80211_FTYPE_DATA		0x0008
#define IEEE80211_FCTL_FTYPE	0x000c
#define WLAN_FC_GET_TYPE(fc) ((fc) & IEEE80211_FCTL_FTYPE)
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((u8*)(x))[0],((u8*)(x))[1],((u8*)(x))[2],((u8*)(x))[3],((u8*)(x))[4],((u8*)(x))[5]


#define HOST_NOTIFICATION_STATUS_ASSOCIATED             10
#define HOST_NOTIFICATION_STATUS_AUTHENTICATE           11
#define HOST_NOTIFICATION_STATUS_SCAN_CHANNEL_RESULT    12
#define HOST_NOTIFICATION_STATUS_SCAN_COMPLETED         13
#define HOST_NOTIFICATION_STATUS_FRAG_LENGTH            14
#define HOST_NOTIFICATION_STATUS_LINK_DETERIORATION     15
#define HOST_NOTIFICATION_DINO_CONFIG_RESPONSE          16
#define HOST_NOTIFICATION_STATUS_BEACON_STATE           17
#define HOST_NOTIFICATION_STATUS_TGI_TX_KEY             18
#define HOST_NOTIFICATION_TX_STATUS                     19
#define HOST_NOTIFICATION_CALIB_KEEP_RESULTS            20
#define HOST_NOTIFICATION_MEASUREMENT_STARTED           21
#define HOST_NOTIFICATION_MEASUREMENT_ENDED             22
#define HOST_NOTIFICATION_CHANNEL_SWITCHED              23
#define HOST_NOTIFICATION_RX_DURING_QUIET_PERIOD        24
#define HOST_NOTIFICATION_NOISE_STATS			25
#define HOST_NOTIFICATION_S36_MEASUREMENT_ACCEPTED      30
#define HOST_NOTIFICATION_S36_MEASUREMENT_REFUSED       31

#define HOST_NOTIFICATION_STATUS_BEACON_MISSING         1
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

#undef LIST_HEAD
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
#define IP_LIST(ip)	IP_CH(ip)[2],IP_CH(ip)[3],IP_CH(ip)[4],IP_CH(ip)[5]

#define IPW_RX_BUF_SIZE (1600)
//#define IPW_RX_BUF_SIZE (2048)

#define memcpy_toio(a,b,c)	memcpy((void *)(a),(b),(c))

#define IPW_GET_PACKET_STYPE(x) WLAN_FC_GET_STYPE( \
			 le16_to_cpu(((struct ieee80211_hdr *)(x))->frame_ctl))

#undef MSEC_PER_SEC		
#undef USEC_PER_SEC		
#undef NSEC_PER_SEC		
#undef NSEC_PER_USEC		

#define MSEC_PER_SEC		1000L
#define USEC_PER_SEC		1000000L
#define NSEC_PER_SEC		1000000000L
#define NSEC_PER_USEC		1000L

 #define IPW_PACKET_RETRY_TIME HZ
 
 #define SCAN_ITEM_SIZE 128
 
#define ETH_P_AARP	0x80F3		/* Appletalk AARP		*/
#define ETH_P_IPX	0x8137		/* IPX over DIX			*/

 #define FREE_FRAME_THRESHOLD 5
#define IEEE80211_ERP_PRESENT                  (0x01)
#define IEEE80211_ERP_USE_PROTECTION           (0x02)
#define IEEE80211_ERP_BARKER_PREAMBLE_MODE     (0x04)
#define IPW_SUPPORTED_RATES_IE_LEN         8







 
			 

