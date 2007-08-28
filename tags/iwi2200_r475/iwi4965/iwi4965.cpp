//iwlwifi-4965-ucode-4.44.15
#include "firmware/ipw4965.ucode.h"
#include "defines.h"


// Define my superclass
#define super IOEthernetController
//IO80211Controller
// REQUIRED! This macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires. Do NOT use super as the
// second parameter. You must use the literal name of the superclass.
OSDefineMetaClassAndStructors(darwin_iwi4965, IOEthernetController);//IO80211Controller);

//clone of the driver class, used in all the kext control functions.

static darwin_iwi4965 *clone;

static struct ipw_tx_power power_gain_table[2][IPW_MAX_GAIN_ENTRIES] = {
	{
	 {251, 127},		/* 2.4 GHz, highest power */
	 {251, 127},
	 {251, 127},
	 {251, 127},
	 {251, 125},
	 {251, 110},
	 {251, 105},
	 {251, 98},
	 {187, 125},
	 {187, 115},
	 {187, 108},
	 {187, 99},
	 {243, 119},
	 {243, 111},
	 {243, 105},
	 {243, 97},
	 {243, 92},
	 {211, 106},
	 {211, 100},
	 {179, 120},
	 {179, 113},
	 {179, 107},
	 {147, 125},
	 {147, 119},
	 {147, 112},
	 {147, 106},
	 {147, 101},
	 {147, 97},
	 {147, 91},
	 {115, 107},
	 {235, 121},
	 {235, 115},
	 {235, 109},
	 {203, 127},
	 {203, 121},
	 {203, 115},
	 {203, 108},
	 {203, 102},
	 {203, 96},
	 {203, 92},
	 {171, 110},
	 {171, 104},
	 {171, 98},
	 {139, 116},
	 {227, 125},
	 {227, 119},
	 {227, 113},
	 {227, 107},
	 {227, 101},
	 {227, 96},
	 {195, 113},
	 {195, 106},
	 {195, 102},
	 {195, 95},
	 {163, 113},
	 {163, 106},
	 {163, 102},
	 {163, 95},
	 {131, 113},
	 {131, 106},
	 {131, 102},
	 {131, 95},
	 {99, 113},
	 {99, 106},
	 {99, 102},
	 {99, 95},
	 {67, 113},
	 {67, 106},
	 {67, 102},
	 {67, 95},
	 {35, 113},
	 {35, 106},
	 {35, 102},
	 {35, 95},
	 {3, 113},
	 {3, 106},
	 {3, 102},
	 {3, 95}},		/* 2.4 GHz, lowest power */
	{
	 {251, 127},		/* 5.x GHz, highest power */
	 {251, 120},
	 {251, 114},
	 {219, 119},
	 {219, 101},
	 {187, 113},
	 {187, 102},
	 {155, 114},
	 {155, 103},
	 {123, 117},
	 {123, 107},
	 {123, 99},
	 {123, 92},
	 {91, 108},
	 {59, 125},
	 {59, 118},
	 {59, 109},
	 {59, 102},
	 {59, 96},
	 {59, 90},
	 {27, 104},
	 {27, 98},
	 {27, 92},
	 {115, 118},
	 {115, 111},
	 {115, 104},
	 {83, 126},
	 {83, 121},
	 {83, 113},
	 {83, 105},
	 {83, 99},
	 {51, 118},
	 {51, 111},
	 {51, 104},
	 {51, 98},
	 {19, 116},
	 {19, 109},
	 {19, 102},
	 {19, 98},
	 {19, 93},
	 {171, 113},
	 {171, 107},
	 {171, 99},
	 {139, 120},
	 {139, 113},
	 {139, 107},
	 {139, 99},
	 {107, 120},
	 {107, 113},
	 {107, 107},
	 {107, 99},
	 {75, 120},
	 {75, 113},
	 {75, 107},
	 {75, 99},
	 {43, 120},
	 {43, 113},
	 {43, 107},
	 {43, 99},
	 {11, 120},
	 {11, 113},
	 {11, 107},
	 {11, 99},
	 {131, 107},
	 {131, 99},
	 {99, 120},
	 {99, 113},
	 {99, 107},
	 {99, 99},
	 {67, 120},
	 {67, 113},
	 {67, 107},
	 {67, 99},
	 {35, 120},
	 {35, 113},
	 {35, 107},
	 {35, 99},
	 {3, 120}}		/* 5.x GHz, lowest power */
};

enum {
	TX_CMD_FLG_RTS_MSK = (1 << 1),
	TX_CMD_FLG_CTS_MSK = (1 << 2),
	TX_CMD_FLG_ACK_MSK = (1 << 3),
	TX_CMD_FLG_FULL_TXOP_PROT_MSK = (1 << 7),
	TX_CMD_FLG_ANT_SEL_MSK = 0xf00,
	TX_CMD_FLG_ANT_A_MSK = (1 << 8),
	TX_CMD_FLG_ANT_B_MSK = (1 << 9),

	/* ucode ignores BT priority for this frame */
	TX_CMD_FLG_BT_DIS_MSK = (1 << 12),

	/* ucode overides sequence control */
	TX_CMD_FLG_SEQ_CTL_MSK = (1 << 13),

	/* signal that this frame is non-last MPDU */
	TX_CMD_FLG_MORE_FRAG_MSK = (1 << 14),

	/* calculate TSF in outgoing frame */
	TX_CMD_FLG_TSF_MSK = (1 << 16),

	/* activate TX calibration. */
	TX_CMD_FLG_CALIB_MSK = (1 << 17),

	/* HCCA-AP - disable duration overwriting. */
	TX_CMD_FLG_DUR_MSK = (1 << 25),
};

enum {
	TX_STATUS_MSK = 0x000000ff,          /* bits 0:7 */
	TX_PACKET_MODE_MSK = 0x0000ff00,     /* bits 8:15 */
	TX_FIFO_NUMBER_MSK = 0x00070000,     /* bits 16:18 */
	TX_RESERVED = 0x00780000,            /* bits 19:22 */
	TX_POWER_PA_DETECT_MSK = 0x7f800000, /* bits 23:30 */
	TX_ABORT_REQUIRED_MSK = 0x80000000,  /* bits 31:31 */
};

enum {
	TX_STATUS_SUCCESS = 0x1,
	TX_STATUS_FAIL_SHORT_LIMIT = 0x82,
	TX_STATUS_FAIL_LONG_LIMIT = 0x83,
	TX_STATUS_FAIL_FIFO_UNDERRUN = 0x84,
	TX_STATUS_FAIL_MGMNT_ABORT = 0x85,
	TX_STATUS_FAIL_NEXT_FRAG = 0x86,
	TX_STATUS_FAIL_LIFE_EXPIRE = 0x87,
	TX_STATUS_FAIL_DEST_PS = 0x88,
	TX_STATUS_FAIL_ABORTED = 0x89,
	TX_STATUS_FAIL_BT_RETRY = 0x8a,
	TX_STATUS_FAIL_STA_INVALID = 0x8b,
	TX_STATUS_FAIL_FRAG_DROPPED = 0x8c,
	TX_STATUS_FAIL_TID_DISABLE = 0x8d,
	TX_STATUS_FAIL_FRAME_FLUSHED = 0x8e,
	TX_STATUS_FAIL_INSUFFICIENT_CF_POLL = 0x8f,
	TX_STATUS_FAIL_TX_LOCKED = 0x90,
	TX_STATUS_FAIL_NO_BEACON_ON_RADAR = 0x91,
};



static const char *get_tx_fail_reason(u32 status)
{
	switch (status & TX_STATUS_MSK) {
	case TX_STATUS_SUCCESS:
		return "SUCCESS";
		TX_STATUS_ENTRY(SHORT_LIMIT);
		TX_STATUS_ENTRY(LONG_LIMIT);
		TX_STATUS_ENTRY(FIFO_UNDERRUN);
		TX_STATUS_ENTRY(MGMNT_ABORT);
		TX_STATUS_ENTRY(NEXT_FRAG);
		TX_STATUS_ENTRY(LIFE_EXPIRE);
		TX_STATUS_ENTRY(DEST_PS);
		TX_STATUS_ENTRY(ABORTED);
		TX_STATUS_ENTRY(BT_RETRY);
		TX_STATUS_ENTRY(STA_INVALID);
		TX_STATUS_ENTRY(FRAG_DROPPED);
		TX_STATUS_ENTRY(TID_DISABLE);
		TX_STATUS_ENTRY(FRAME_FLUSHED);
		TX_STATUS_ENTRY(INSUFFICIENT_CF_POLL);
		TX_STATUS_ENTRY(TX_LOCKED);
		TX_STATUS_ENTRY(NO_BEACON_ON_RADAR);
	}

	return "UNKNOWN";
}



static const char *get_cmd_string(u8 cmd)
{
	switch (cmd) {
		IPW_CMD(SCAN_START_NOTIFICATION);
		IPW_CMD(SCAN_RESULTS_NOTIFICATION);
		IPW_CMD(SCAN_COMPLETE_NOTIFICATION);
		IPW_CMD(STATISTICS_NOTIFICATION);
		IPW_CMD3945(ALIVE);
		IPW_CMD3945(ERROR);
		IPW_CMD3945(RXON_ASSOC);
		IPW_CMD3945(RXON);
		IPW_CMD3945(QOS_PARAM);
		IPW_CMD3945(RXON_TIMING);
		IPW_CMD3945(ADD_STA);
		IPW_CMD3945(RX);
		IPW_CMD3945(TX);
		IPW_CMD3945(BCON);
		IPW_CMD3945(RATE_SCALE);
		IPW_CMD3945(LEDS_CMD);
		IPW_CMD3945(SCAN_ABORT_CMD);
		IPW_CMD3945(TX_BEACON);
		IPW_CMD3945(BT_CONFIG);
		IPW_CMD3945(SCAN_CMD);
		IPW_CMD3945(TX_PWR_TABLE_CMD);
		IPW_CMD3945(STATISTICS_CMD);
		IPW_CMD3945(CARD_STATE_CMD);
		IPW_CMD3945(TX_LINK_QUALITY_CMD);
	case POWER_TABLE_CMD:
		return "POWER_TABLE_CMD";
	default:
		return "UNKNOWN";

	}
}

static const struct ipw_status_code ipw_status_codes[] = {
	{0x00, "Successful"},
	{0x01, "Unspecified failure"},
	{0x0A, "Cannot support all requested capabilities in the "
	 "Capability information field"},
	{0x0B, "Reassociation denied due to inability to confirm that "
	 "association exists"},
	{0x0C, "Association denied due to reason outside the scope of this "
	 "standard"},
	{0x0D,
	 "Responding station does not support the specified authentication "
	 "algorithm"},
	{0x0E,
	 "Received an Authentication frame with authentication sequence "
	 "transaction sequence number out of expected sequence"},
	{0x0F, "Authentication rejected because of challenge failure"},
	{0x10, "Authentication rejected due to timeout waiting for next "
	 "frame in sequence"},
	{0x11, "Association denied because AP is unable to handle additional "
	 "associated stations"},
	{0x12,
	 "Association denied due to requesting station not supporting all "
	 "of the datarates in the BSSBasicServiceSet Parameter"},
	{0x13,
	 "Association denied due to requesting station not supporting "
	 "short preamble operation"},
	{0x14,
	 "Association denied due to requesting station not supporting "
	 "PBCC encoding"},
	{0x15,
	 "Association denied due to requesting station not supporting "
	 "channel agility"},
	{0x19,
	 "Association denied due to requesting station not supporting "
	 "short slot operation"},
	{0x1A,
	 "Association denied due to requesting station not supporting "
	 "DSSS-OFDM operation"},
	{0x28, "Invalid Information Element"},
	{0x29, "Group Cipher is not valid"},
	{0x2A, "Pairwise Cipher is not valid"},
	{0x2B, "AKMP is not valid"},
	{0x2C, "Unsupported RSN IE version"},
	{0x2D, "Invalid RSN IE Capabilities"},
	{0x2E, "Cipher suite is rejected per security policy"},
};

static const struct ieee80211_geo ipw_geos[] = {
	{			/* Restricted */
	 "---",
	 11,
	 NULL,
	{{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11}},
	NULL
	 },

	{			/* Custom US/Canada */
	 "ZZF",
	 11,
	 8,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11}},
	 {{5180, 36},
	       {5200, 40},
	       {5220, 44},
	       {5240, 48},
	       {5260, 52, IEEE80211_CH_PASSIVE_ONLY},
	       {5280, 56, IEEE80211_CH_PASSIVE_ONLY},
	       {5300, 60, IEEE80211_CH_PASSIVE_ONLY},
	       {5320, 64, IEEE80211_CH_PASSIVE_ONLY}}
	 },

	{			/* Rest of World */
	 "ZZD",
	 13,
	 NULL,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11}, {2467, 12},
		{2472, 13}},
	NULL
	 },

	{			/* Custom USA & Europe & High */
	 "ZZA",
	 11,
	 NULL,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11}},
	 {{5180, 36},
	       {5200, 40},
	       {5220, 44},
	       {5240, 48},
	       {5260, 52, IEEE80211_CH_PASSIVE_ONLY},
	       {5280, 56, IEEE80211_CH_PASSIVE_ONLY},
	       {5300, 60, IEEE80211_CH_PASSIVE_ONLY},
	       {5320, 64, IEEE80211_CH_PASSIVE_ONLY},
	       {5745, 149},
	       {5765, 153},
	       {5785, 157},
	       {5805, 161},
	       {5825, 165}}
	 },

	{			/* Custom NA & Europe */
	 "ZZB",
	 11,
	 13,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11}},
	 {{5180, 36},
	       {5200, 40},
	       {5220, 44},
	       {5240, 48},
	       {5260, 52, IEEE80211_CH_PASSIVE_ONLY},
	       {5280, 56, IEEE80211_CH_PASSIVE_ONLY},
	       {5300, 60, IEEE80211_CH_PASSIVE_ONLY},
	       {5320, 64, IEEE80211_CH_PASSIVE_ONLY},
	       {5745, 149, IEEE80211_CH_PASSIVE_ONLY},
	       {5765, 153, IEEE80211_CH_PASSIVE_ONLY},
	       {5785, 157, IEEE80211_CH_PASSIVE_ONLY},
	       {5805, 161, IEEE80211_CH_PASSIVE_ONLY},
	       {5825, 165, IEEE80211_CH_PASSIVE_ONLY}}
	 },

	{			/* Custom Japan */
	 "ZZC",
	 11,
	 4,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11}},
	 {{5170, 34}, {5190, 38},
	       {5210, 42}, {5230, 46}}
	 },

	{			/* Custom */
	 "ZZM",
	 11,
	 NULL,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11}},
	NULL
	 },

	{			/* Europe */
	 "ZZE",
	 13,
	 19,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11}, {2467, 12},
		{2472, 13}},
	 {{5180, 36},
	       {5200, 40},
	       {5220, 44},
	       {5240, 48},
	       {5260, 52, IEEE80211_CH_PASSIVE_ONLY},
	       {5280, 56, IEEE80211_CH_PASSIVE_ONLY},
	       {5300, 60, IEEE80211_CH_PASSIVE_ONLY},
	       {5320, 64, IEEE80211_CH_PASSIVE_ONLY},
	       {5500, 100, IEEE80211_CH_PASSIVE_ONLY},
	       {5520, 104, IEEE80211_CH_PASSIVE_ONLY},
	       {5540, 108, IEEE80211_CH_PASSIVE_ONLY},
	       {5560, 112, IEEE80211_CH_PASSIVE_ONLY},
	       {5580, 116, IEEE80211_CH_PASSIVE_ONLY},
	       {5600, 120, IEEE80211_CH_PASSIVE_ONLY},
	       {5620, 124, IEEE80211_CH_PASSIVE_ONLY},
	       {5640, 128, IEEE80211_CH_PASSIVE_ONLY},
	       {5660, 132, IEEE80211_CH_PASSIVE_ONLY},
	       {5680, 136, IEEE80211_CH_PASSIVE_ONLY},
	       {5700, 140, IEEE80211_CH_PASSIVE_ONLY}}
	 },

	{			/* Custom Japan */
	 "ZZJ",
	 14,
	 4,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11}, {2467, 12},
		{2472, 13}, {2484, 14, IEEE80211_CH_B_ONLY}},
	 {{5170, 34}, {5190, 38},
	       {5210, 42}, {5230, 46}}
	 },

	{			/* Rest of World */
	 "ZZR",
	 14,
	 NULL,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11}, {2467, 12},
		{2472, 13}, {2484, 14, IEEE80211_CH_B_ONLY |
			     IEEE80211_CH_PASSIVE_ONLY}},
	NULL
	 },

	{			/* High Band */
	 "ZZH",
	 13,
	 4,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11},
		{2467, 12, IEEE80211_CH_PASSIVE_ONLY},
		{2472, 13, IEEE80211_CH_PASSIVE_ONLY}},
	 {{5745, 149}, {5765, 153},
	       {5785, 157}, {5805, 161}}
	 },

	{			/* Custom Europe */
	 "ZZG",
	 13,
	 4,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11},
		{2467, 12}, {2472, 13}},
	 {{5180, 36}, {5200, 40},
	       {5220, 44}, {5240, 48}}
	 },

	{			/* Europe */
	 "ZZK",
	 13,
	 24,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11},
		{2467, 12, IEEE80211_CH_PASSIVE_ONLY},
		{2472, 13, IEEE80211_CH_PASSIVE_ONLY}},
	 {{5180, 36, IEEE80211_CH_PASSIVE_ONLY},
	       {5200, 40, IEEE80211_CH_PASSIVE_ONLY},
	       {5220, 44, IEEE80211_CH_PASSIVE_ONLY},
	       {5240, 48, IEEE80211_CH_PASSIVE_ONLY},
	       {5260, 52, IEEE80211_CH_PASSIVE_ONLY},
	       {5280, 56, IEEE80211_CH_PASSIVE_ONLY},
	       {5300, 60, IEEE80211_CH_PASSIVE_ONLY},
	       {5320, 64, IEEE80211_CH_PASSIVE_ONLY},
	       {5500, 100, IEEE80211_CH_PASSIVE_ONLY},
	       {5520, 104, IEEE80211_CH_PASSIVE_ONLY},
	       {5540, 108, IEEE80211_CH_PASSIVE_ONLY},
	       {5560, 112, IEEE80211_CH_PASSIVE_ONLY},
	       {5580, 116, IEEE80211_CH_PASSIVE_ONLY},
	       {5600, 120, IEEE80211_CH_PASSIVE_ONLY},
	       {5620, 124, IEEE80211_CH_PASSIVE_ONLY},
	       {5640, 128, IEEE80211_CH_PASSIVE_ONLY},
	       {5660, 132, IEEE80211_CH_PASSIVE_ONLY},
	       {5680, 136, IEEE80211_CH_PASSIVE_ONLY},
	       {5700, 140, IEEE80211_CH_PASSIVE_ONLY},
	       {5745, 149, IEEE80211_CH_PASSIVE_ONLY},
	       {5765, 153, IEEE80211_CH_PASSIVE_ONLY},
	       {5785, 157, IEEE80211_CH_PASSIVE_ONLY},
	       {5805, 161, IEEE80211_CH_PASSIVE_ONLY},
	       {5825, 165, IEEE80211_CH_PASSIVE_ONLY}}
	 },

	{			/* Europe */
	 "ZZL",
	 11,
	 13,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11}},
	 {{5180, 36, IEEE80211_CH_PASSIVE_ONLY},
	       {5200, 40, IEEE80211_CH_PASSIVE_ONLY},
	       {5220, 44, IEEE80211_CH_PASSIVE_ONLY},
	       {5240, 48, IEEE80211_CH_PASSIVE_ONLY},
	       {5260, 52, IEEE80211_CH_PASSIVE_ONLY},
	       {5280, 56, IEEE80211_CH_PASSIVE_ONLY},
	       {5300, 60, IEEE80211_CH_PASSIVE_ONLY},
	       {5320, 64, IEEE80211_CH_PASSIVE_ONLY},
	       {5745, 149, IEEE80211_CH_PASSIVE_ONLY},
	       {5765, 153, IEEE80211_CH_PASSIVE_ONLY},
	       {5785, 157, IEEE80211_CH_PASSIVE_ONLY},
	       {5805, 161, IEEE80211_CH_PASSIVE_ONLY},
	       {5825, 165, IEEE80211_CH_PASSIVE_ONLY}}
	 }
};

	 
bool darwin_iwi4965::init(OSDictionary *dict)
{

	
/* Initialize module parameter values here */
qos_enable = 0;
qos_burst_enable = 1;
qos_no_ack_mask = 0;
burst_duration_CCK = 0;
burst_duration_OFDM = 0;
config = 0;
 cmdlog = 0;
  debug = 0;
  channel = 0;
  mode = 0;
  disable2=1;
  associate = 0;
  auto_create = 1;
  led = 1;
  bt_coexist = 1;
  hwcrypto = 0;
  roaming = 1;
 antenna = 0;//CFG_SYS_ANTENNA_BOTH;
 
  disable2=OSDynamicCast(OSNumber,dict->getObject("p_disable"))->unsigned32BitValue();
  led=OSDynamicCast(OSNumber,dict->getObject("p_led"))->unsigned32BitValue();
  mode=OSDynamicCast(OSNumber,dict->getObject("p_mode"))->unsigned32BitValue();

 IOLog("disable %d led %d mode %d\n",disable2, led, mode);

 return super::init(dict);
}


int darwin_iwi4965::ipw_sw_reset(int option)
{

	int err = 0;
	struct net_device *net_dev;
	void __iomem *base;
	u32 length, val;
	int i;
	struct ieee80211_hw *ieee;
	struct ieee80211_local *local;
	
	//net_dev=(struct net_device*)fifnet;
	net_dev=&net_dev2;
	//memset(&net_dev,0,sizeof(struct ieee80211_device) + sizeof(struct ipw_priv));
	if (!net_dev) {
		IOLog("Unable to network device.\n");
		return -1;
	}
	
	//ieee = (struct ieee80211_device*)netdev_priv(net_dev);
	ieee=&ieee2;
	ieee->max_rssi = 60;
	ieee->flags = IEEE80211_HW_WEP_INCLUDE_IV;
	ieee->queues = 4;
	
	local = hw_to_local(ieee);
	local->hw.queues = 1;
	local->bridge_packets = 1;

	//local->rts_threshold = IEEE80211_MAX_RTS_THRESHOLD;
	//local->fragmentation_threshold = IEEE80211_MAX_FRAG_THRESHOLD;
	local->short_retry_limit = 7;
	local->long_retry_limit = 4;
	local->hw.conf.radio_enabled = 1;
	//local->rate_ctrl_num_up = RATE_CONTROL_NUM_UP;
	//local->rate_ctrl_num_down = RATE_CONTROL_NUM_DOWN;

	//local->scan.in_scan = 0;
	local->enabled_modes = (unsigned int) -1;
	INIT_LIST_HEAD(&local->modes_list);
	/*INIT_LIST_HEAD(&local->sta_list);
	INIT_LIST_HEAD(&local->deleted_sta_list);*/
	
	priv = &priv2;
	//priv=(struct ipw_priv*)ieee80211_priv(net_dev);
	priv->ieee = ieee;
	//local->scan_flags |= IEEE80211_SCAN_EXTRA_INFO;
	priv->ieee_channels = NULL;
	priv->ieee_rates = NULL;
 
	priv->net_dev = net_dev;
		
	priv->rxq = NULL;
	priv->antenna = antenna;
#ifdef CONFIG_IPW3945_DEBUG
	ipw_debug_level = debug;
#endif
	priv->retry_rate = 1;

	for (i = 0; i < IPW_IBSS_MAC_HASH_SIZE; i++)
		INIT_LIST_HEAD(&priv->ibss_mac_hash[i]);

	INIT_LIST_HEAD(&priv->free_frames);

	ipw_clear_stations_table(priv);
	
	memset(&(priv->txq[0]), 0, sizeof(struct ipw_tx_queue) * 6);
	memset(&priv->card_alive, 0, sizeof(struct ipw_alive_resp));
	priv->data_retry_limit = -1;
	priv->auth_state = AUTH_INIT;
	priv->ieee_channels = NULL;
	priv->ieee_rates = NULL;
	//priv->hw_base = memBase;


	/* Initialize module parameter values here */

	if (!led)
		priv->config |= CFG_NO_LED;
	if (associate)
		priv->config |= CFG_ASSOCIATE;
	else
		IOLog("Auto associate disabled.\n");
	if (auto_create)
		priv->config |= CFG_ADHOC_CREATE;
	else
		IOLog("Auto adhoc creation disabled.\n");
	if (disable2) {
		priv->status |= STATUS_RF_KILL_SW;
		IOLog("Radio disabled.\n");
	}

	/*************************************/
	switch (mode) {
	case 1:
		priv->iw_mode = IW_MODE_ADHOC;
		break;
	case 2:
		priv->iw_mode = IW_MODE_MONITOR;
		break;
	default:
	case 0:
		priv->iw_mode = IW_MODE_INFRA;
		break;
	}

	priv->freq_band = IEEE80211_24GHZ_BAND;
	
	u32 pci_id;//(priv->pci_dev->device << 16) | priv->pci_dev->subsystem_device;
	priv->is_3945 = 1;
	pci_id= (fPCIDevice->configRead16(kIOPCIConfigDeviceID) << 16) | fPCIDevice->configRead16(kIOPCIConfigSubSystemID);
	IWI_LOG("PCI_ID 0x%08x\n",pci_id);
	
	IOLog(": Detected Intel PRO/Wireless 4965%s Network Connection\n",
	       priv->is_abg ? "ABG" : "BG");

	if (channel != 0) {
		priv->config |= CFG_STATIC_CHANNEL;
		priv->active_conf.channel = channel;
		IOLog("Bind to static channel %d\n", channel);
		/* TODO: Validate that provided channel is in range */
	} else
		priv->active_conf.channel = 1;


	priv->rates_mask = IEEE80211_DEFAULT_RATES_MASK;
	priv->missed_beacon_threshold = IPW_MB_DISASSOCIATE_THRESHOLD_DEFAULT;
	priv->rts_threshold = DEFAULT_RTS_THRESHOLD;
	/* If power management is turned on, default to AC mode */
	priv->power_mode = IPW_POWER_AC;


	//priv->perfect_rssi = -20;
	//priv->worst_rssi = -95;
	//memset(&priv->qos_data, 0, sizeof(struct ipw_qos_info));
	//if (qos_enable)
	//	priv->qos_data.qos_enable = 1;
	//priv->qos_data.qos_active = 0;
	//priv->qos_data.qos_cap.val = 0;
	//priv->actual_txpower_limit = IPW_DEFAULT_TX_POWER;	
	
	

	MemoryDmaAlloc(sizeof(struct ipw_shared_t), &priv->hw_setting.shared_phys, &priv->hw_setting.shared_virt);

	



	priv->hw_setting.eeprom_size = sizeof(struct ipw_eeprom);
	priv->hw_setting.cmd_queue_no = IPW3945_CMD_QUEUE_NUM;
	priv->hw_setting.number_of_stations = IPW3945_NUM_OF_STATIONS;
	priv->hw_setting.broadcast_id = IPW3945_BROADCAST_ID;
	priv->hw_setting.max_num_rate = IPW_MAX_RATES;
	priv->hw_setting.max_queue_number = TFD_QUEUE_MAX;
	priv->hw_setting.ac_queue_count = AC_NUM;
	priv->hw_setting.rx_buffer_size = IPW3945_RX_BUF_SIZE;
	priv->hw_setting.max_inst_size = ALM_RTC_INST_SIZE;
	priv->hw_setting.max_data_size = ALM_RTC_DATA_SIZE;
	priv->hw_setting.start_cmd_queue = 0;
	priv->hw_setting.tx_cmd_len = sizeof(struct ipw_tx_cmd);
	priv->hw_setting.statistics_size = sizeof(struct ipw_notif_statistics);
	priv->hw_setting.rate_scale_size =
		sizeof(struct ipw_rate_scaling_cmd_specifics);
	priv->hw_setting.add_station_size = sizeof(struct ipw_addsta_cmd);
	priv->hw_setting.max_rxq_size = RX_QUEUE_SIZE;
	priv->hw_setting.max_rxq_log = RX_QUEUE_SIZE_LOG;
	priv->hw_setting.cck_flag = 0;

	ipw_read_ucode(priv);


	return 0;
	
}

int darwin_iwi4965::ipw_read_ucode(struct ipw_priv *priv)
{
	struct ipw_ucode *ucode;
	int rc = 0;
	struct firmware *ucode_raw;
	const char *name = "iwlwifi-4965.ucode";	/* firmware file name */
	u8 *src;
	size_t len;

	/* data from ucode file:  header followed by uCode images */
	(void*)ucode = (void*)ipw;

	IOLog("f/w package hdr ucode version = 0x%x\n", ucode->ver);
	IOLog("f/w package hdr runtime inst size = %u\n",
		       ucode->inst_size);
	IOLog("f/w package hdr runtime data size = %u\n",
		       ucode->data_size);
	IOLog("f/w package hdr boot inst size = %u\n",
		       ucode->boot_size);
	IOLog("f/w package hdr boot data size = %u\n",
		       ucode->boot_data_size);

	/* verify size of file vs. image size info in file's header */
	/*if (ucode_raw->size < sizeof(*ucode) +
	    ucode->inst_size + ucode->data_size +
	    ucode->boot_size + ucode->boot_data_size) {
		IOLog("uCode file size %d too small\n",
			       (int)ucode_raw->size);
		rc = -EINVAL;
		//goto err_release;
	}*/

	/* verify that uCode images will fit in card's SRAM */
	if (ucode->inst_size > ALM_RTC_INST_SIZE) {
		 IOLog("uCode instr len %d too large to fit in card\n",
			       (int)ucode->inst_size);
		rc = -EINVAL;
		//goto err_release;
	}

	if (ucode->data_size > ALM_RTC_DATA_SIZE) {
		IOLog("uCode data len %d too large to fit in card\n",
			       (int)ucode->data_size);
		rc = -EINVAL;
		//goto err_release;
	}

	if (ucode->boot_size > ALM_RTC_INST_SIZE) {
		IOLog
		    ("uCode boot instr len %d too large to fit in card\n",
		     (int)ucode->boot_size);
		rc = -EINVAL;
		//goto err_release;
	}

	if (ucode->boot_data_size > ALM_RTC_DATA_SIZE) {
		IOLog
		    ("uCode boot data len %d too large to fit in card\n",
		     (int)ucode->boot_data_size);
		rc = -EINVAL;
		//goto err_release;
	}

	/* allocate ucode buffers for card's bus-master loading */
	priv->ucode_code.len = ucode->inst_size;
	MemoryDmaAlloc(priv->ucode_code.len, &(priv->ucode_code.p_addr), &(priv->ucode_code.v_addr));
	
	priv->ucode_data.len = ucode->data_size;
	MemoryDmaAlloc(priv->ucode_data.len, &(priv->ucode_data.p_addr), &(priv->ucode_data.v_addr));
	

	priv->ucode_boot.len = ucode->boot_size;
	MemoryDmaAlloc(priv->ucode_boot.len, &(priv->ucode_boot.p_addr), &(priv->ucode_boot.v_addr));


	priv->ucode_boot_data.len = ucode->boot_data_size;
	MemoryDmaAlloc(priv->ucode_boot_data.len, &(priv->ucode_boot_data.p_addr), &(priv->ucode_boot_data.v_addr));


	if (!priv->ucode_code.v_addr || !priv->ucode_data.v_addr
	    || !priv->ucode_boot.v_addr || !priv->ucode_boot_data.v_addr) {
		IOLog("failed to allocate pci memory\n");
		rc = -ENOMEM;
		goto err_pci_alloc;
	}

	/* Copy images into buffers for card's bus-master reads ... */

	/* runtime instructions (first block of data in file) */
	src = &ucode->data[0];
	len = priv->ucode_code.len;
	IOLog("Copying (but not loading) uCode instr len %d\n",
		       (int)len);
	memcpy(priv->ucode_code.v_addr, src, len);

	/* runtime data (2nd block) */
	src = &ucode->data[ucode->inst_size];
	len = priv->ucode_data.len;
	IOLog("Copying (but not loading) uCode data len %d\n",
		       (int)len);
	memcpy(priv->ucode_data.v_addr, src, len);

	/* bootstrap instructions (3rd block) */
	src = &ucode->data[ucode->inst_size + ucode->data_size];
	len = priv->ucode_boot.len;
	IOLog("Copying (but not loading) boot instr len %d\n",
		       (int)len);
	memcpy(priv->ucode_boot.v_addr, src, len);

	/* bootstrap data (4th block) */
	src = &ucode->data[ucode->inst_size + ucode->data_size
			   + ucode->boot_size];
	len = priv->ucode_boot_data.len;
	IOLog("Copying (but not loading) boot data len %d\n",
		       (int)len);
	memcpy(priv->ucode_boot_data.v_addr, src, len);

	//release_firmware(ucode_raw);
	return 0;

      err_pci_alloc:
	//ipw_dealloc_ucode_pci(priv);

      err_release:
//	release_firmware(ucode_raw);

      error:
	return rc;
}

IOOptionBits darwin_iwi4965::getState( void ) const
{
	IOOptionBits r=super::getState();
	IOLog("getState = %x\n",r);
	return r;
}

bool darwin_iwi4965::start(IOService *provider)
{
	UInt16	reg;
//linking the kext control clone to the driver:
		clone=this;
		
	do {
				
		if ( super::start(provider) == 0) {
			IOLog("%s ERR: super::start failed\n", getName());
			break;
		}
			
		if ( (fPCIDevice = OSDynamicCast(IOPCIDevice, provider)) == 0) {
			IOLog("%s ERR: fPCIDevice == 0 :(\n", getName());
			break;
		}

		fPCIDevice->retain();
		
		if (fPCIDevice->open(this) == 0) {
			IOLog("%s ERR: fPCIDevice->open(this) failed\n", getName());
			break;
		}
		
		// Request domain power.
        	// Without this, the PCIDevice may be in state 0, and the
        	// PCI config space may be invalid if the machine has been
       		// sleeping.
		if (fPCIDevice->requestPowerDomainState(kIOPMPowerOn, 
			(IOPowerConnection *) getParentEntry(gIOPowerPlane),
			IOPMLowestState ) != IOPMNoErr) {
				IOLog("%s Power thingi failed\n", getName());
				break;
       		}

		fPCIDevice->setBusMasterEnable(true);
		fPCIDevice->setMemoryEnable(true);
		//fPCIDevice->setIOEnable(true);
		
		irqNumber = fPCIDevice->configRead8(kIOPCIConfigInterruptLine);
		vendorID = fPCIDevice->configRead16(kIOPCIConfigVendorID);
		deviceID = fPCIDevice->configRead16(kIOPCIConfigDeviceID);		
		pciReg = fPCIDevice->configRead16(kIOPCIConfigRevisionID);

  		map = fPCIDevice->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0, kIOMapInhibitCache);
  		if (map == 0) {
			IOLog("%s map is zero\n", getName());
			break;
		}
		ioBase = map->getPhysicalAddress();
		memBase = (UInt16 *)map->getVirtualAddress();
		memDes = map->getMemoryDescriptor();
		mem = fPCIDevice->getDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0);
		
		memDes->initWithPhysicalAddress(ioBase, map->getLength(), kIODirectionOutIn);
					 
		/* We disable the RETRY_TIMEOUT register (0x41) to keep
		 * PCI Tx retries from interfering with C3 CPU state */
		reg = fPCIDevice->configRead16(0x40);
		if((reg & 0x0000ff00) != 0)
			fPCIDevice->configWrite16(0x40, reg & 0xffff00ff);
			

		IOLog("%s iomemory length: 0x%x @ 0x%x\n", getName(), map->getLength(), ioBase);
		IOLog("%s virt: 0x%x physical: 0x%x\n", getName(), memBase, ioBase);
		IOLog("%s IRQ: %d, Vendor ID: %04x, Product ID: %04x\n", getName(), irqNumber, vendorID, deviceID);
		
		fWorkLoop = (IOWorkLoop *) getWorkLoop();
		if (!fWorkLoop) {
			IOLog("%s ERR: start - getWorkLoop failed\n", getName());
			break;
		}
		fInterruptSrc = IOInterruptEventSource::interruptEventSource(
			this, (IOInterruptEventAction) &darwin_iwi4965::interruptOccurred,
			provider);
		if(!fInterruptSrc || (fWorkLoop->addEventSource(fInterruptSrc) != kIOReturnSuccess)) {
			IOLog("%s fInterruptSrc error\n", getName());
			break;;
		}
		// This is important. If the interrupt line is shared with other devices,
		// then the interrupt vector will be enabled only if all corresponding
		// interrupt event sources are enabled. To avoid masking interrupts for
		// other devices that are sharing the interrupt line, the event source
		// is enabled immediately.
		fInterruptSrc->enable();
		mutex=IOLockAlloc();
		
		fTransmitQueue = createOutputQueue();
		if (fTransmitQueue == NULL)
		{
			IWI_ERR("ERR: getOutputQueue()\n");
			break;
		}
		fTransmitQueue->setCapacity(1024);
		
		ipw_sw_reset(1);
		//resetDevice((UInt16 *)memBase); //iwi2200 code to fix
		ipw_nic_init(priv);
		ipw_nic_reset(priv);
		ipw_bg_resume_work();
		
		if (attachInterface((IONetworkInterface **) &fNetif, false) == false) {
			IOLog("%s attach failed\n", getName());
			break;
		}
		fNetif->registerService();

		
		mediumDict = OSDictionary::withCapacity(MEDIUM_TYPE_INVALID + 1);
		addMediumType(kIOMediumIEEE80211None,  0,  MEDIUM_TYPE_NONE);
		addMediumType(kIOMediumIEEE80211Auto,  0,  MEDIUM_TYPE_AUTO);
		addMediumType(kIOMediumIEEE80211DS1,   1000000, MEDIUM_TYPE_1MBIT);
		addMediumType(kIOMediumIEEE80211DS2,   2000000, MEDIUM_TYPE_2MBIT);
		addMediumType(kIOMediumIEEE80211DS5,   5500000, MEDIUM_TYPE_5MBIT);
		addMediumType(kIOMediumIEEE80211DS11, 11000000, MEDIUM_TYPE_11MBIT);
		addMediumType(kIOMediumIEEE80211,     54000000, MEDIUM_TYPE_54MBIT, "OFDM54");
		addMediumType(kIOMediumIEEE80211OptionAdhoc, 0, MEDIUM_TYPE_ADHOC,"ADHOC");

		publishMediumDictionary(mediumDict);
		setCurrentMedium(mediumTable[MEDIUM_TYPE_AUTO]);
		setSelectedMedium(mediumTable[MEDIUM_TYPE_AUTO]);
		setLinkStatus(kIONetworkLinkValid, mediumTable[MEDIUM_TYPE_AUTO]);
		
		registerService();
	
		/*lck_grp_attr_t	*ga=lck_grp_attr_alloc_init();
		lck_grp_t		*gr=lck_grp_alloc_init("mut",ga);
		lck_attr_t		*lca=lck_attr_alloc_init();
		mutex=lck_mtx_alloc_init(gr,lca);
	
		lck_grp_attr_t	*ga2=lck_grp_attr_alloc_init();
		lck_grp_t		*gr2=lck_grp_alloc_init("spn",ga2);
		lck_attr_t		*lca2=lck_attr_alloc_init();
		//spin= lck_spin_alloc_init(gr2,lca2);
		spin=IOSimpleLockAlloc();
		
		if (!spin) return false;
		if (!mutex) return false;*/
		
		//kext control registration:
		//these functions registers the control which enables
		//the user to interact with the driver
		
		struct kern_ctl_reg		ep_ctl; // Initialize control
		kern_ctl_ref	kctlref;
		bzero(&ep_ctl, sizeof(ep_ctl));
		ep_ctl.ctl_id = 0; /* OLD STYLE: ep_ctl.ctl_id = kEPCommID; */
		ep_ctl.ctl_unit = 0;
		strcpy(ep_ctl.ctl_name,"insanelymac.iwidarwin.control");
		ep_ctl.ctl_flags = 0;
		ep_ctl.ctl_connect = ConnectClient;
		ep_ctl.ctl_disconnect = disconnectClient;
		ep_ctl.ctl_send = setSelectedNetwork;
		ep_ctl.ctl_setopt = configureConnection;
		ep_ctl.ctl_getopt = sendNetworkList;
		errno_t error = ctl_register(&ep_ctl, &kctlref);
		
		//IW_SCAN_TYPE_ACTIVE
		queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan),NULL,NULL,false);
		queue_te(1,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_adapter_restart),NULL,NULL,false);
		queue_te(2,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_led_link_on),NULL,NULL,false);
		queue_te(3,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_rf_kill),NULL,NULL,false);
		queue_te(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan_check),NULL,NULL,false);
		queue_te(5,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_associate),NULL,NULL,false);
		queue_te(6,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_gather_stats),NULL,NULL,false);
		queue_te(7,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_rx_queue_replenish),NULL,NULL,false);
		queue_te(8,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_led_activity_off),NULL,NULL,false);
		queue_te(9,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_bg_alive_start),NULL,NULL,false);
		queue_te(10,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::reg_txpower_periodic),NULL,NULL,false);
		queue_te(11,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_bg_post_associate),NULL,NULL,false);
		queue_te(12,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_down),NULL,NULL,false);
		pl=1;
		ipw_up(priv);
		return true;			// end start successfully
	} while (false);
		
	//stop(provider);
	free();
	return false;			// end start insuccessfully
}

void darwin_iwi4965::ipw_bg_resume_work()
{
	unsigned long flags;

	//mutex_lock(&priv->mutex);
	//IOLockLock(mutex);
	
	/* The following it a temporary work around due to the
	 * suspend / resume not fully initializing the NIC correctly.
	 * Without all of the following, resume will not attempt to take
	 * down the NIC (it shouldn't really need to) and will just try
	 * and bring the NIC back up.  However that fails during the
	 * ucode verification process.  This then causes ipw_down to be
	 * called *after* ipw_nic_init() has succeedded -- which
	 * then lets the next init sequence succeed.  So, we've
	 * replicated all of that NIC init code here... */

	ipw_write32( CSR_INT, 0xFFFFFFFF);

	ipw_nic_init(priv);

	ipw_write32( CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	ipw_write32( CSR_UCODE_DRV_GP1_CLR,
		    CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);
	ipw_write32( CSR_INT, 0xFFFFFFFF);
	ipw_write32( CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	ipw_write32( CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);

	/* tell the device to stop sending interrupts */
	ipw_disable_interrupts(priv);

	//spin_lock_irqsave(&priv->lock, flags);
	ipw_clear_bit( CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
	//spin_unlock_irqrestore(&priv->lock, flags);

	//spin_lock_irqsave(&priv->lock, flags);
	if (!ipw_grab_restricted_access(priv)) {
		_ipw_write_restricted_reg(priv, ALM_APMG_CLK_DIS,
					 APMG_CLK_REG_VAL_DMA_CLK_RQT);
		_ipw_release_restricted_access(priv);
	}
	//spin_unlock_irqrestore(&priv->lock, flags);

	udelay(5);

	ipw_nic_reset(priv);

	/* Bring the device back up */
	priv->status &= ~STATUS_IN_SUSPEND;

	//mutex_unlock(&priv->mutex);
	//IOLockUnlock(mutex);
}

IOReturn darwin_iwi4965::selectMedium(const IONetworkMedium * medium)
{
	bool  r;

	if ( OSDynamicCast(IONetworkMedium, medium) == 0 )
    {
        // Defaults to Auto.
		medium = mediumTable[MEDIUM_TYPE_AUTO];
        if ( medium == 0 ) {
		IOLog("selectMedium failed\n");
		return kIOReturnError;
	}
    }

	// Program PHY to select the desired medium.
	//r = _phySetMedium( (mediumType_t) medium->getIndex() );

	if ( r && !setCurrentMedium(medium) )
		IOLog("%s: setCurrentMedium error\n", getName());

	IOLog("Medium is set to: %s\n", medium->getName()->getCStringNoCopy());
	return ( r ? kIOReturnSuccess : kIOReturnIOError );
}

bool darwin_iwi4965::addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name) {	
    IONetworkMedium	* medium;
    bool              ret = false;
    
    medium = IONetworkMedium::medium(type, speed, 0, code, name);
    if (medium) {
        ret = IONetworkMedium::addMedium(mediumDict, medium);
        if (ret)
            mediumTable[code] = medium;
        medium->release();
    }
    return ret;
}

IOOutputQueue * darwin_iwi4965::createOutputQueue( void )
{
	// An IOGatedOutputQueue will serialize all calls to the driver's
    // outputPacket() function with its work loop. This essentially
    // serializes all access to the driver and the hardware through
    // the driver's work loop, which simplifies the driver but also
    // carries a small performance cost (relatively for 10/100 Mb).

    return IOGatedOutputQueue::withTarget( this, getWorkLoop() );
}

bool darwin_iwi4965::createWorkLoop( void )
{
    fWorkLoop = IOWorkLoop::workLoop();
	
    return ( fWorkLoop != 0 );
}

IOWorkLoop * darwin_iwi4965::getWorkLoop( void ) const
{
    // Override IOService::getWorkLoop() method to return the work loop
    // we allocated in createWorkLoop().

	return fWorkLoop;
}

const OSString * darwin_iwi4965::newVendorString( void ) const
{
    return OSString::withCString("Intel");
}

const OSString * darwin_iwi4965::newModelString( void ) const
{
    const char * model = "4965";

    return OSString::withCString(model);
}

int darwin_iwi4965::ipw_stop_nic()
{

}

int darwin_iwi4965::ipw_init_nic()
{

}

int darwin_iwi4965::ipw_reset_nic(struct ipw_priv *priv)
{
	int rc = 0;
	unsigned long flags;


	rc = ipw_init_nic();

	/* Clear the 'host command active' bit... */
	priv->status &= ~STATUS_HCMD_ACTIVE;
	//wake_up_interruptible(&priv->wait_command_queue);
	priv->status &= ~(STATUS_SCANNING | STATUS_SCAN_ABORTING);
	//wake_up_interruptible(&priv->wait_state);

	return rc;
}


void darwin_iwi4965::ipw_start_nic()
{

	/* prvHwStartNic  release ARC */
	ipw_clear_bit(IPW_RESET_REG,
		      IPW_RESET_REG_MASTER_DISABLED |
		      IPW_RESET_REG_STOP_MASTER |
		      CBD_RESET_REG_PRINCETON_RESET);

	/* enable power management */
	ipw_set_bit(IPW_GP_CNTRL_RW,
		    IPW_GP_CNTRL_BIT_HOST_ALLOWS_STANDBY);

}

inline void darwin_iwi4965::ipw_enable_interrupts(struct ipw_priv *priv)
{
	if (priv->status & STATUS_INT_ENABLED)
		return;
	priv->status |= STATUS_INT_ENABLED;
	ipw_write32(CSR_INT_MASK, CSR_INI_SET_MASK);}

int darwin_iwi4965::ipw_load(struct ipw_priv *priv)
{
	
}

int darwin_iwi4965::rf_kill_active(struct ipw_priv *priv)
{

}

void darwin_iwi4965::ipw_adapter_restart(ipw_priv *adapter)
{
	struct ipw_priv *priv = adapter;
	if (priv->status & STATUS_RF_KILL_MASK)
		return;

	IOLog("ipw_adapter_restart\n");
	//queue_td(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan));
	//queue_td(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan_check));
	//priv->status |= STATUS_RF_KILL_HW;
	//queue_td(2,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_led_link_on));
	//priv->status  &= ~(STATUS_RF_KILL_HW);
	queue_te(12,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_down),priv,NULL,true);
	
	if (priv->assoc_network &&
	    (priv->assoc_network->capability & WLAN_CAPABILITY_IBSS))
		ipw_remove_current_network(priv);

	
	pl=1;
	if (ipw_up(priv)) {
		IOLog("Failed to up device\n");
		return;
	}
}

void darwin_iwi4965::ipw_remove_current_network(struct ipw_priv *priv)
{
}

void darwin_iwi4965::ipw_rf_kill(ipw_priv *priv)
{
	//struct ipw_priv *priv = container_of(work, struct ipw_priv, rf_kill);

	//wake_up_interruptible(&priv->wait_command_queue);

	if (priv->status & STATUS_EXIT_PENDING)
		return;

	//mutex_lock(&priv->mutex);

	if (!(priv->status & STATUS_RF_KILL_MASK)) {
			IOLog("HW RF Kill no longer active, restarting "
			  "device\n");
		if (!(priv->status & STATUS_EXIT_PENDING))
			queue_te(12,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_down),priv,NULL,true);
	} else {
		priv->led_state = IPW_LED_LINK_RADIOOFF;

		if (!(priv->status & STATUS_RF_KILL_HW))
			IOLog
			    ("Can not turn radio back on - "
			     "disabled by SW switch\n");
		else
		{	IOLog
			    ("Radio Frequency Kill Switch is On:\n"
			     "Kill switch must be turned off for "
			     "wireless networking to work. Press wireless button if you have it\n");
				 //queue_te(3,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_rf_kill),priv,2,true);
		}
	}
	//mutex_unlock(&priv->mutex);
}

int darwin_iwi4965::ipw_set_geo(struct ieee80211_device *ieee,
		       const struct ieee80211_geo *geo)
{
	memcpy(ieee->geo.name, geo->name, 3);
	ieee->geo.name[3] = '\0';
	ieee->geo.bg_channels = geo->bg_channels;
	ieee->geo.a_channels = geo->a_channels;
	memcpy(ieee->geo.bg, geo->bg, geo->bg_channels *
	       sizeof(struct ieee80211_channel));
	memcpy(ieee->geo.a, geo->a, ieee->geo.a_channels *
	       sizeof(struct ieee80211_channel));
	return 0;
}

/*IOReturn darwin_iwi4965::setPowerState ( unsigned long powerStateOrdinal, IOService* whatDevice )
{
	IOLog("setPowerState to %d\n",powerStateOrdinal);
	power=powerStateOrdinal;
	return super::setPowerState(powerStateOrdinal,whatDevice);
}*/

void darwin_iwi4965::ipw_init_ordinals(struct ipw_priv *priv)
{

}

int darwin_iwi4965::ipw_grab_restricted_access(struct ipw_priv *priv)
{
	//if (priv->is_3945) {
		int rc;
		ipw_set_bit( CSR_GP_CNTRL,
			    CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
		rc = ipw_poll_bit( priv,CSR_GP_CNTRL,
				  CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN,
				  (CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY |
				   CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP), 50);
		if (rc < 0) {
			//IOLog("MAC is in deep sleep!\n");
			return -EIO;
		}
	//}

	priv->status |= STATUS_RESTRICTED;

	return 0;

}

void darwin_iwi4965::_ipw_write_restricted(struct ipw_priv *priv,
					 u32 reg, u32 value)
{
//      _ipw_grab_restricted_access(priv);
	_ipw_write32(memBase, reg, value);
//      _ipw_release_restricted_access(priv);
}

void darwin_iwi4965::_ipw_write_restricted_reg(struct ipw_priv *priv,
					     u32 addr, u32 val)
{
	_ipw_write_restricted(priv, HBUS_TARG_PRPH_WADDR,
			      ((addr & 0x0000FFFF) | (3 << 24)));
	_ipw_write_restricted(priv, HBUS_TARG_PRPH_WDAT, val);
}

int darwin_iwi4965::ipw_copy_ucode_images(struct ipw_priv *priv,
				 u8 * image_code,
				 size_t image_len_code,
				 u8 * image_data, size_t image_len_data)
{
/*	int rc;

	if ((image_len_code > priv->ucode_code.actual_len) ||
	    (image_len_data > priv->ucode_data.actual_len)) {
		IOLog("uCode size is too large to fit\n");
		return -EINVAL;
	}

	memcpy(priv->ucode_code.v_addr, image_code, image_len_code);
	priv->ucode_code.len = (u32) image_len_code;
	memcpy(priv->ucode_data.v_addr, image_data, image_len_data);
	priv->ucode_data.len = (u32) image_len_data;

	rc = ipw_grab_restricted_access(priv);
	if (rc)
		return rc;

	_ipw_write_restricted_reg(priv, BSM_DRAM_INST_PTR_REG,
				 priv->ucode_code.p_addr);
	_ipw_write_restricted_reg(priv, BSM_DRAM_DATA_PTR_REG,
				 priv->ucode_data.p_addr);
	_ipw_write_restricted_reg(priv, BSM_DRAM_INST_BYTECOUNT_REG,
				 priv->ucode_code.len);
	_ipw_write_restricted_reg(priv, BSM_DRAM_DATA_BYTECOUNT_REG,
				 priv->ucode_data.len);
	_ipw_release_restricted_access(priv);

	return 0;*/
}

void darwin_iwi4965::_ipw_release_restricted_access(struct ipw_priv
						  *priv)
{
	ipw_clear_bit(CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);

	priv->status &= ~STATUS_RESTRICTED;
}

void darwin_iwi4965::ipw_write_restricted_reg_buffer(struct ipw_priv
						   *priv, u32 reg,
						   u32 len, u8 * values)
{
	u32 reg_offset = reg;
	u32 aligment = reg & 0x3;

	if (len < sizeof(u32)) {
		if ((aligment + len) <= sizeof(u32)) {
			u8 size;
			u32 value = 0;
			size = len - 1;
			memcpy(&value, values, len);
			reg_offset = (reg_offset & 0x0000FFFF);

			_ipw_write_restricted(priv,
					      HBUS_TARG_PRPH_WADDR,
					      (reg_offset | (size << 24)));
			_ipw_write_restricted(priv, HBUS_TARG_PRPH_WDAT, value);
		}

		return;
	}

	for (; reg_offset < (reg + len);
	     reg_offset += sizeof(u32), values += sizeof(u32))
		_ipw_write_restricted_reg(priv, reg_offset, *((u32 *) values));
}


int darwin_iwi4965::ipw_download_ucode_base(struct ipw_priv *priv, u8 * image, u32 len)
{
	u32 reg;
	u32 val;
	int rc;

	rc = ipw_grab_restricted_access(priv);
	if (rc)
		return rc;

	ipw_write_restricted_reg_buffer(priv, BSM_SRAM_LOWER_BOUND, len, image);
	_ipw_write_restricted_reg(priv, BSM_WR_MEM_SRC_REG, 0x0);
	_ipw_write_restricted_reg(priv, BSM_WR_MEM_DST_REG,
				 RTC_INST_LOWER_BOUND);
	_ipw_write_restricted_reg(priv, BSM_WR_DWCOUNT_REG, len / sizeof(u32));
	_ipw_write_restricted_reg(priv, BSM_WR_CTRL_REG,
				 BSM_WR_CTRL_REG_BIT_START_EN);

	val = _ipw_read_restricted_reg(priv, BSM_WR_DWCOUNT_REG);
	for (reg = BSM_SRAM_LOWER_BOUND;
	     reg < BSM_SRAM_LOWER_BOUND + len;
	     reg += sizeof(u32), image += sizeof(u32)) {
		val = _ipw_read_restricted_reg(priv, reg);
		if (val != *(u32 *) image) {
			IOLog("uCode verification failed at "
				  "addr 0x%08X+%u (of %u)\n",
				  BSM_SRAM_LOWER_BOUND,
				  reg - BSM_SRAM_LOWER_BOUND, len);
			_ipw_release_restricted_access(priv);
			return -EIO;
		}
	}

	_ipw_release_restricted_access(priv);
	return 0;
}

u32 darwin_iwi4965::_ipw_read_restricted_reg(struct ipw_priv *priv, u32 reg)
{
	_ipw_write_restricted(priv, HBUS_TARG_PRPH_RADDR, reg | (3 << 24));
	return _ipw_read_restricted(priv, HBUS_TARG_PRPH_RDAT);
}

u32 darwin_iwi4965::_ipw_read_restricted(struct ipw_priv *priv, u32 reg)
{
	u32 val;
//      _ipw_grab_restricted_access(priv);
	val = _ipw_read32(memBase, reg);
//      _ipw_release_restricted_access(priv);
	return val;
}

int darwin_iwi4965::attach_buffer_to_tfd_frame(void *ptr,
				      dma_addr_t addr, u16 len)
{
	int count = 0;
	u32 pad;
	struct tfd_frame *tfd = (struct tfd_frame *)ptr;

	count = TFD_CTL_COUNT_GET(tfd->control_flags);
	pad = TFD_CTL_PAD_GET(tfd->control_flags);

	if ((count >= NUM_TFD_CHUNKS) || (count < 0)) {
		IOLog("Error can not send more than %d chunks\n",
			  NUM_TFD_CHUNKS);
		return -EINVAL;
	}

	tfd->pa[count].addr = (u32) addr;
	tfd->pa[count].len = len;

	count++;

	tfd->control_flags = TFD_CTL_COUNT_SET(count) | TFD_CTL_PAD_SET(pad);

	return 0;

}

void darwin_iwi4965::ipw_write_buffer_restricted(struct ipw_priv *priv,
					u32 reg, u32 len, u32 * values)
{
	u32 count = sizeof(u32);
	if ((priv != NULL) && (values != NULL)) {
		for (; 0 < len; len -= count, reg += count, values++)
			_ipw_write_restricted(priv, reg, *values);
	}
}

int darwin_iwi4965::ipw_download_ucode(struct ipw_priv *priv,
			      struct fw_image_desc *desc,
			      u32 mem_size, dma_addr_t dst_addr)
{
	dma_addr_t phy_addr = 0;
	u32 len = 0;
	u32 count = 0;
	u32 pad;
	struct tfd_frame tfd;
	u32 tx_config = 0;
	int rc;

	memset(&tfd, 0, sizeof(struct tfd_frame));

	phy_addr = desc->p_addr;
	len = desc->len;

	if (mem_size < len) {
		IOLog("invalid image size, too big %d %d\n", mem_size, len);
		return -EINVAL;
	}

	while (len > 0) {
		if (ALM_TB_MAX_BYTES_COUNT < len) {
			attach_buffer_to_tfd_frame(&tfd, phy_addr,
						   ALM_TB_MAX_BYTES_COUNT);
			len -= ALM_TB_MAX_BYTES_COUNT;
			phy_addr += ALM_TB_MAX_BYTES_COUNT;
		} else {
			attach_buffer_to_tfd_frame(&tfd, phy_addr, len);
			break;
		}
	}

	pad = U32_PAD(len);
	count = TFD_CTL_COUNT_GET(tfd.control_flags);
	tfd.control_flags = TFD_CTL_COUNT_SET(count) | TFD_CTL_PAD_SET(pad);

	rc = ipw_grab_restricted_access(priv);
	if (rc)
		return rc;

	_ipw_write_restricted(priv, FH_TCSR_CONFIG(ALM_FH_SRVC_CHNL),
			     ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE);
	ipw_write_buffer_restricted(priv,
				    ALM_FH_TFDB_CHNL_BUF_CTRL_REG
				    (ALM_FH_SRVC_CHNL),
				    sizeof(struct tfd_frame), (u32 *) & tfd);
	_ipw_write_restricted(priv, HBUS_TARG_MEM_WADDR, dst_addr);
	_ipw_write_restricted(priv, FH_TCSR_CREDIT(ALM_FH_SRVC_CHNL),
			     0x000FFFFF);
	_ipw_write_restricted(priv,
			     FH_TCSR_BUFF_STTS(ALM_FH_SRVC_CHNL),
			     ALM_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID
			     | ALM_FH_TCSR_CHNL_TX_BUF_STS_REG_BIT_TFDB_WPTR);

	tx_config = ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
	    ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE_VAL |
	    ALM_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_DRIVER;

	_ipw_write_restricted(priv, FH_TCSR_CONFIG(ALM_FH_SRVC_CHNL), tx_config);

	rc = ipw_poll_restricted_bit(priv, FH_TSSR_TX_STATUS,
				     ALM_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE
				     (ALM_FH_SRVC_CHNL), 1000);
	if (rc < 0) {
		IOLog("4965 card ucode DOWNLOAD FAILED \n");
		goto done;
	}

	rc = 0;

	IOLog("4965 card ucode download is good \n");

	_ipw_write_restricted(priv, FH_TCSR_CREDIT(ALM_FH_SRVC_CHNL), 0x0);

      done:
	_ipw_release_restricted_access(priv);
	return rc;
}

int darwin_iwi4965::ipw_poll_restricted_bit(struct ipw_priv *priv,
					  u32 addr, u32 mask, int timeout)
{
	int i = 0;

	do {
		if ((_ipw_read_restricted(priv, addr) & mask) == mask)
			return i;
		mdelay(10);
		i += 10;
	} while (i < timeout);

	return -ETIMEDOUT;
}

int darwin_iwi4965::ipw_load_ucode(struct ipw_priv *priv,
			  struct fw_image_desc *desc,
			  u32 mem_size, dma_addr_t dst_addr)
{
	dma_addr_t phy_addr = 0;
	u32 len = 0;
	u32 count = 0;
	u32 pad;
	struct tfd_frame tfd;
	u32 tx_config = 0;
	int rc;

	memset(&tfd, 0, sizeof(struct tfd_frame));

	phy_addr = desc->p_addr;
	len = desc->len;

	if (mem_size < len) {
		IOLog("invalid image size, too big %d %d\n", mem_size, len);
		//return -EINVAL;
	}

	while (len > 0) {
		if (ALM_TB_MAX_BYTES_COUNT < len) {
			attach_buffer_to_tfd_frame( &tfd, phy_addr,
						   ALM_TB_MAX_BYTES_COUNT);
			len -= ALM_TB_MAX_BYTES_COUNT;
			phy_addr += ALM_TB_MAX_BYTES_COUNT;
		} else {
			attach_buffer_to_tfd_frame( &tfd, phy_addr, len);
			break;
		}
	}

	pad = U32_PAD(len);
	count = TFD_CTL_COUNT_GET(tfd.control_flags);
	tfd.control_flags = TFD_CTL_COUNT_SET(count) | TFD_CTL_PAD_SET(pad);

	rc = ipw_grab_restricted_access(priv);
	if (rc)
		return rc;

	_ipw_write_restricted(priv, FH_TCSR_CONFIG(ALM_FH_SRVC_CHNL),
			     ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE);
	ipw_write_buffer_restricted(priv,
				    ALM_FH_TFDB_CHNL_BUF_CTRL_REG
				    (ALM_FH_SRVC_CHNL),
				    sizeof(struct tfd_frame), (u32 *) & tfd);
	_ipw_write_restricted(priv, HBUS_TARG_MEM_WADDR, dst_addr);
	_ipw_write_restricted(priv, FH_TCSR_CREDIT(ALM_FH_SRVC_CHNL),
			     0x000FFFFF);
	_ipw_write_restricted(priv,
			     FH_TCSR_BUFF_STTS(ALM_FH_SRVC_CHNL),
			     ALM_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID
			     | ALM_FH_TCSR_CHNL_TX_BUF_STS_REG_BIT_TFDB_WPTR);

	tx_config = ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
	    ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE_VAL |
	    ALM_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_DRIVER;

	_ipw_write_restricted(priv, FH_TCSR_CONFIG(ALM_FH_SRVC_CHNL), tx_config);

	rc = ipw_poll_restricted_bit(priv, FH_TSSR_TX_STATUS,
				     ALM_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE
				     (ALM_FH_SRVC_CHNL), 1000);
	if (rc < 0) {
		IOLog("4965 card ucode DOWNLOAD FAILED \n");
		//goto done;
	}

	rc = 0;

	IOLog("4965 card ucode download is good \n");

	_ipw_write_restricted(priv, FH_TCSR_CREDIT(ALM_FH_SRVC_CHNL), 0x0);

      done:
	_ipw_release_restricted_access(priv);
	return rc;

}

void darwin_iwi4965::ipw_clear_stations_table(struct ipw_priv *priv)
{

	priv->num_stations = 0;
	memset(priv->stations, 0,
	       NUM_OF_STATIONS * sizeof(struct ipw_station_entry));
}

void darwin_iwi4965::ipw_nic_start(struct ipw_priv *priv)
{
	unsigned long flags;

	//spin_lock_irqsave(&priv->lock, flags);
	ipw_clear_bit( CSR_RESET,
		      CSR_RESET_REG_FLAG_MASTER_DISABLED |
		      CSR_RESET_REG_FLAG_STOP_MASTER |
		      CSR_RESET_REG_FLAG_NEVO_RESET);
	//spin_unlock_irqrestore(&priv->lock, flags);
}

int darwin_iwi4965::ipw_query_eeprom(struct ipw_priv *priv, u32 offset,
			    u32 len, u8 * buf)
{
/*	if (EEPROM_IMAGE_SIZE < (offset + len))
		return -1;

	memcpy(buf, &(priv->eeprom[offset]), len);

	return 0;*/
}

int darwin_iwi4965::ipw_card_show_info(struct ipw_priv *priv)
{
	IOLog("4965 HW Version %u.%u.%u\n",
		       ((priv->eeprom.board_revision >> 8) & 0x0F),
		       ((priv->eeprom.board_revision >> 8) >> 4),
		       (priv->eeprom.board_revision & 0x00FF));

	IOLog("4965 PBA Number %.*s\n",
		       (int)sizeof(priv->eeprom.board_pba_number),
		       priv->eeprom.board_pba_number);

	IOLog("EEPROM_ANTENNA_SWITCH_TYPE is 0x%02X\n",
		       priv->eeprom.antenna_switch_type);


}



int darwin_iwi4965::ipw_power_init_handle(struct ipw_priv *priv)
{
	int rc = 0, i;
	struct ipw_power_mgr *pow_data;
	int size = sizeof(struct ipw_power_vec_entry) * IPW_POWER_AC;
	u16 pci_pm;

	IOLog("Intialize power \n");

	pow_data = &(priv->power_data);

	memset(pow_data, 0, sizeof(*pow_data));

	pow_data->active_index = IPW_POWER_RANGE_0;
	pow_data->dtim_val = 0xffff;

	//memcpy(&pow_data->pwr_range_0[0], &range_0[0], size);
	//memcpy(&pow_data->pwr_range_1[0], &range_1[0], size);
	pci_pm= fPCIDevice->configRead32(PCI_LINK_CTRL);
	 rc=0;
	//rc = pci_read_config_word(priv->pci_dev, PCI_LINK_CTRL, &pci_pm);
	if (rc != 0)
		return 0;
	else {
		struct ipw_powertable_cmd *cmd;

		IOLog("adjust power command flags\n");

		for (i = 0; i < IPW_POWER_AC; i++) {
			cmd = &pow_data->pwr_range_0[i].cmd;

			if (pci_pm & 0x1)
				cmd->flags &= ~0x8;
			else
				cmd->flags |= 0x8;
		}
	}

	return rc;
}

void darwin_iwi4965::__ipw_set_bits_restricted_reg(u32 line, struct ipw_priv
						 *priv, u32 reg, u32 mask)
{
	if (!(priv->status & STATUS_RESTRICTED))
		IOLog("Unrestricted access from line %d\n", line);
	_ipw_set_bits_restricted_reg(priv, reg, mask);
}

int darwin_iwi4965::ipw_eeprom_init_sram(struct ipw_priv *priv)
{
	u16 *e = (u16 *) & priv->eeprom;
	u32 r;
	int to;
	u32 gp = ipw_read32( CSR_EEPROM_GP);
	u16 sz = sizeof(priv->eeprom);
	int rc;
	u16 addr;

	if (sizeof(priv->eeprom) != 1024) {
		IOLog("EEPROM structure size incorrect!\n");
		//return -EINVAL;
	}

	if ((gp & 0x00000007) == 0x00000000) {
		IOLog("EEPROM not found, EEPROM_GP=0x%08x", gp);
		//return -ENOENT;
	}

	ipw_clear_bit( CSR_EEPROM_GP, 0x00000180);
	for (addr = 0, r = 0; addr < sz; addr += 2) {
		ipw_write32( CSR_EEPROM_REG, addr << 1);
		ipw_clear_bit( CSR_EEPROM_REG, 0x00000002);
		ipw_grab_restricted_access(priv);
		//if (rc)
		//	return rc;

		for (to = 0; to < 10; to++) {
			r = _ipw_read_restricted(priv, CSR_EEPROM_REG);
			if (r & 1)
				break;
			udelay(5);
		}

		_ipw_release_restricted_access(priv);

		if (!(r & 1)) {
			IOLog("Time out reading EEPROM[%d]", addr);
			//return -ETIMEDOUT;
		}

		e[addr / 2] = r >> 16;
	}

	return 0;
}

int darwin_iwi4965::ipw_rate_scale_clear_window(struct ipw_rate_scale_data
				       *window)
{

	window->data = 0;
	window->success_counter = 0;
	window->success_ratio = IPW_INVALID_VALUE;
	window->counter = 0;
	window->average_tpt = IPW_INVALID_VALUE;
	window->stamp = 0;
	return 0;
}

int darwin_iwi4965::ipw_rate_scale_init_handle(struct ipw_priv *priv, s32 window_size)
{
	int rc = 0;
	int i;
	unsigned long flags;
	struct RateScalingCmdSpecifics *cmd;
	struct rate_scaling_info *table;

	cmd = &priv->rate_scale_mgr.scale_rate_cmd;
	memset(cmd, 0, sizeof(cmd));
	table = &cmd->rate_scale_table[0];

	IOLog("initialize rate scale window to %d\n", window_size);

	if ((window_size > IPW_RATE_SCALE_MAX_WINDOW)
	    || (window_size < 0))
		window_size = IPW_RATE_SCALE_MAX_WINDOW;

	//spin_lock_irqsave(&priv->rate_scale_mgr.lock, flags);

	priv->rate_scale_mgr.expected_tpt = NULL;
	priv->rate_scale_mgr.next_higher_rate = NULL;
	priv->rate_scale_mgr.next_lower_rate = NULL;

	priv->rate_scale_mgr.stamp = jiffies;
	priv->rate_scale_mgr.stamp_last = jiffies;
	priv->rate_scale_mgr.flush_time = IPW_RATE_SCALE_FLUSH;
	priv->rate_scale_mgr.tx_packets = 0;

	priv->rate_scale_mgr.max_window_size = window_size;

	for (i = 0; i < NUM_RATES; i++)
		ipw_rate_scale_clear_window(&priv->rate_scale_mgr.window[i]);

	table[RATE_SCALE_6M_INDEX].tx_rate = R_6M;
	table[RATE_SCALE_6M_INDEX].try_cnt = priv->retry_rate;
	table[RATE_SCALE_6M_INDEX].next_rate_index = RATE_SCALE_11M_INDEX;

	table[RATE_SCALE_9M_INDEX].tx_rate = R_9M;
	table[RATE_SCALE_9M_INDEX].try_cnt = priv->retry_rate;
	table[RATE_SCALE_9M_INDEX].next_rate_index = RATE_SCALE_6M_INDEX;

	table[RATE_SCALE_12M_INDEX].tx_rate = R_12M;
	table[RATE_SCALE_12M_INDEX].try_cnt = priv->retry_rate;
	table[RATE_SCALE_12M_INDEX].next_rate_index = RATE_SCALE_9M_INDEX;

	table[RATE_SCALE_18M_INDEX].tx_rate = R_18M;
	table[RATE_SCALE_18M_INDEX].try_cnt = priv->retry_rate;
	table[RATE_SCALE_18M_INDEX].next_rate_index = RATE_SCALE_12M_INDEX;

	table[RATE_SCALE_24M_INDEX].tx_rate = R_24M;
	table[RATE_SCALE_24M_INDEX].try_cnt = priv->retry_rate;
	table[RATE_SCALE_24M_INDEX].next_rate_index = RATE_SCALE_18M_INDEX;

	table[RATE_SCALE_36M_INDEX].tx_rate = R_36M;
	table[RATE_SCALE_36M_INDEX].try_cnt = priv->retry_rate;
	table[RATE_SCALE_36M_INDEX].next_rate_index = RATE_SCALE_24M_INDEX;

	table[RATE_SCALE_48M_INDEX].tx_rate = R_48M;
	table[RATE_SCALE_48M_INDEX].try_cnt = priv->retry_rate;
	table[RATE_SCALE_48M_INDEX].next_rate_index = RATE_SCALE_36M_INDEX;

	table[RATE_SCALE_54M_INDEX].tx_rate = R_54M;
	table[RATE_SCALE_54M_INDEX].try_cnt = priv->retry_rate;
	table[RATE_SCALE_54M_INDEX].next_rate_index = RATE_SCALE_48M_INDEX;

	table[RATE_SCALE_1M_INDEX].tx_rate = R_1M;
	table[RATE_SCALE_1M_INDEX].try_cnt = priv->retry_rate;
	table[RATE_SCALE_1M_INDEX].next_rate_index = RATE_SCALE_1M_INDEX;

	table[RATE_SCALE_2M_INDEX].tx_rate = R_2M;
	table[RATE_SCALE_2M_INDEX].try_cnt = priv->retry_rate;
	table[RATE_SCALE_2M_INDEX].next_rate_index = RATE_SCALE_1M_INDEX;

	table[RATE_SCALE_5_5M_INDEX].tx_rate = R_5_5M;
	table[RATE_SCALE_5_5M_INDEX].try_cnt = priv->retry_rate;
	table[RATE_SCALE_5_5M_INDEX].next_rate_index = RATE_SCALE_2M_INDEX;

	table[RATE_SCALE_11M_INDEX].tx_rate = R_11M;
	table[RATE_SCALE_11M_INDEX].try_cnt = priv->retry_rate;
	table[RATE_SCALE_11M_INDEX].next_rate_index = RATE_SCALE_5_5M_INDEX;

//	spin_unlock_irqrestore(&priv->rate_scale_mgr.lock, flags);

	return rc;
}

int darwin_iwi4965::ipw_nic_set_pwr_src(struct ipw_priv *priv, int pwr_max)
{

}

void darwin_iwi4965::__ipw_set_bits_mask_restricted_reg(u32 line, struct ipw_priv
						      *priv, u32 reg,
						      u32 bits, u32 mask)
{
	if (!(priv->status & STATUS_RESTRICTED))
		IOLog("Unrestricted access from line %d\n", line);
	_ipw_set_bits_mask_restricted_reg(priv, reg, bits, mask);
}

int darwin_iwi4965::ipw3945_nic_set_pwr_src(struct ipw_priv *priv, int pwr_max)
{
	int rc = 0;
	unsigned long flags;

	//return 0;
	//spin_lock_irqsave(&priv->lock, flags);
	rc = ipw_grab_restricted_access(priv);
	/*if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}*/

	if (!pwr_max) {
		u32 val;
		//rc = pci_read_config_dword(priv->pci_dev, 0x0C8, &val);
		val=fPCIDevice->configRead32(0x0C8);
		if (val & PCI_CFG_PMC_PME_FROM_D3COLD_SUPPORT) {
			ipw_set_bits_mask_restricted_reg(priv,
							 ALM_APMG_PS_CTL,
							 APMG_PS_CTRL_REG_VAL_POWER_SRC_VAUX,
							 ~APMG_PS_CTRL_REG_MSK_POWER_SRC);
			_ipw_release_restricted_access(priv);

			ipw_poll_bit( priv,CSR_GPIO_IN,
				     CSR_GPIO_IN_VAL_VAUX_PWR_SRC,
				     CSR_GPIO_IN_BIT_AUX_POWER, 5000);
		} else
			_ipw_release_restricted_access(priv);

	} else {
		ipw_set_bits_mask_restricted_reg(priv,
						 ALM_APMG_PS_CTL,
						 APMG_PS_CTRL_REG_VAL_POWER_SRC_VMAIN,
						 ~APMG_PS_CTRL_REG_MSK_POWER_SRC);

		_ipw_release_restricted_access(priv);
		ipw_poll_bit(priv, CSR_GPIO_IN, CSR_GPIO_IN_VAL_VMAIN_PWR_SRC, CSR_GPIO_IN_BIT_AUX_POWER, 5000);	//uS
	}
	//spin_unlock_irqrestore(&priv->lock, flags);

	return rc;
}

int darwin_iwi4965::ipw_nic_stop_master(struct ipw_priv *priv)
{
	int rc = 0;
	u32 reg_val;
	unsigned long flags;

	//spin_lock_irqsave(&priv->lock, flags);

	/* set stop master bit */
	ipw_set_bit( CSR_RESET, CSR_RESET_REG_FLAG_STOP_MASTER);

	reg_val = ipw_read32(CSR_GP_CNTRL);

	if (CSR_GP_CNTRL_REG_FLAG_MAC_POWER_SAVE ==
	    (reg_val & CSR_GP_CNTRL_REG_MSK_POWER_SAVE_TYPE)) {
		IOLog
		    ("Card in power save, master is already stopped\n");
	} else {
		rc = ipw_poll_bit(priv,
				  CSR_RESET,
				  CSR_RESET_REG_FLAG_MASTER_DISABLED,
				  CSR_RESET_REG_FLAG_MASTER_DISABLED, 100);
		/*if (rc < 0) {
			spin_unlock_irqrestore(&priv->lock, flags);
			return rc;
		}*/
	}

	//spin_unlock_irqrestore(&priv->lock, flags);
	IOLog("stop master\n");

	return rc;
}

int darwin_iwi4965::ipw_nic_reset(struct ipw_priv *priv)
{
	int rc = 0;
	unsigned long flags;

	ipw_nic_stop_master(priv);

	//spin_lock_irqsave(&priv->lock, flags);
	ipw_set_bit( CSR_RESET, CSR_RESET_REG_FLAG_SW_RESET);

	rc = ipw_poll_bit(priv, CSR_GP_CNTRL,
			  CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
			  CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY, 25000);

	rc = ipw_grab_restricted_access(priv);
	/*if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}*/

	_ipw_write_restricted_reg(priv, APMG_CLK_CTRL_REG,
				 APMG_CLK_REG_VAL_BSM_CLK_RQT);

	udelay(10);

	ipw_set_bit(CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_INIT_DONE);

	_ipw_write_restricted_reg(priv, ALM_APMG_LARC_INT_MSK, 0x0);
	_ipw_write_restricted_reg(priv, ALM_APMG_LARC_INT, 0xFFFFFFFF);

	/* enable DMA */
	_ipw_write_restricted_reg(priv, ALM_APMG_CLK_EN,
				 APMG_CLK_REG_VAL_DMA_CLK_RQT |
				 APMG_CLK_REG_VAL_BSM_CLK_RQT);
	udelay(10);

	ipw_set_bits_restricted_reg(priv, ALM_APMG_PS_CTL,
				    APMG_PS_CTRL_REG_VAL_ALM_R_RESET_REQ);
	udelay(5);
	ipw_clear_bits_restricted_reg(priv, ALM_APMG_PS_CTL,
				      APMG_PS_CTRL_REG_VAL_ALM_R_RESET_REQ);
	_ipw_release_restricted_access(priv);

	/* Clear the 'host command active' bit... */
	priv->status &= ~STATUS_HCMD_ACTIVE;

	//wake_up_interruptible(&priv->wait_command_queue);
	//spin_unlock_irqrestore(&priv->lock, flags);

	return rc;
}

void darwin_iwi4965::ipw_clear_bits_restricted_reg(struct ipw_priv
					  *priv, u32 reg, u32 mask)
{
	u32 val = _ipw_read_restricted_reg(priv, reg);
	_ipw_write_restricted_reg(priv, reg, (val & ~mask));
}

int darwin_iwi4965::ipw_nic_init(struct ipw_priv *priv)
{
	u8 rev_id;
	int rc;
	unsigned long flags;

	ipw_power_init_handle(priv);
	
	ipw_rate_scale_init_handle(priv, IPW_RATE_SCALE_MAX_WINDOW);

	//spin_lock_irqsave(&priv->lock, flags);
	ipw_set_bit( CSR_ANA_PLL_CFG, (1 << 24));
	ipw_set_bit( CSR_GIO_CHICKEN_BITS,
		    CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX);

	ipw_set_bit( CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_INIT_DONE);
	rc = ipw_poll_bit( priv,CSR_GP_CNTRL,
			  CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
			  CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY, 25000);
	if (rc < 0) {
		//spin_unlock_irqrestore(&priv->lock, flags);
		IOLog("Failed to init the card\n");
		//return rc;
	}

	rc = ipw_grab_restricted_access(priv);
	/*if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}*/
	_ipw_write_restricted_reg(priv, ALM_APMG_CLK_EN,
				 APMG_CLK_REG_VAL_DMA_CLK_RQT |
				 APMG_CLK_REG_VAL_BSM_CLK_RQT);
	udelay(20);
	ipw_set_bits_restricted_reg(priv, ALM_APMG_PCIDEV_STT,
				    APMG_DEV_STATE_REG_VAL_L1_ACTIVE_DISABLE);
	_ipw_release_restricted_access(priv);
	//spin_unlock_irqrestore(&priv->lock, flags);

	/* Determine HW type */
	rev_id= fPCIDevice->configRead8(kIOPCIConfigRevisionID);
	IOLog("HW Revision ID = 0x%X\n", rev_id);

	ipw3945_nic_set_pwr_src(priv, 1);
	//spin_lock_irqsave(&priv->lock, flags);

	if (rev_id & PCI_CFG_REV_ID_BIT_RTP)
		IOLog("RTP type \n");
	else if (rev_id & PCI_CFG_REV_ID_BIT_BASIC_SKU) {
		IOLog("ALM-MB type\n");
		ipw_set_bit( CSR_HW_IF_CONFIG_REG,
			    CSR_HW_IF_CONFIG_REG_BIT_ALMAGOR_MB);
	} else {
		IOLog("ALM-MM type\n");
		ipw_set_bit( CSR_HW_IF_CONFIG_REG,
			    CSR_HW_IF_CONFIG_REG_BIT_ALMAGOR_MM);
	}

	//spin_unlock_irqrestore(&priv->lock, flags);

	/* Initialize the EEPROM */
	rc = ipw_eeprom_init_sram(priv);
	if (rc)
		return rc;

	//spin_lock_irqsave(&priv->lock, flags);
	if (EEPROM_SKU_CAP_OP_MODE_MRC == priv->eeprom.sku_cap) {
		IOLog("SKU OP mode is mrc\n");
		ipw_set_bit( CSR_HW_IF_CONFIG_REG,
			    CSR_HW_IF_CONFIG_REG_BIT_SKU_MRC);
	} else {
		IOLog("SKU OP mode is basic\n");
	}

	if ((priv->eeprom.board_revision & 0xF0) == 0xD0) {
		IOLog("4965 revision is 0x%X\n",
			       priv->eeprom.board_revision);
		ipw_set_bit( CSR_HW_IF_CONFIG_REG,
			    CSR_HW_IF_CONFIG_REG_BIT_BOARD_TYPE);
	} else {
		IOLog("4965 revision is 0x%X\n",
			       priv->eeprom.board_revision);
		ipw_clear_bit( CSR_HW_IF_CONFIG_REG,
			      CSR_HW_IF_CONFIG_REG_BIT_BOARD_TYPE);
	}

	if (priv->eeprom.almgor_m_version <= 1) {
		ipw_set_bit( CSR_HW_IF_CONFIG_REG,
			    CSR_HW_IF_CONFIG_REG_BITS_SILICON_TYPE_A);
		IOLog("Card M type A version is 0x%X\n",
			       priv->eeprom.almgor_m_version);
	} else {
		IOLog("Card M type B version is 0x%X\n",
			       priv->eeprom.almgor_m_version);
		ipw_set_bit( CSR_HW_IF_CONFIG_REG,
			    CSR_HW_IF_CONFIG_REG_BITS_SILICON_TYPE_B);
	}
	//spin_unlock_irqrestore(&priv->lock, flags);

	if (priv->eeprom.sku_cap & EEPROM_SKU_CAP_SW_RF_KILL_ENABLE)
		priv->capability |= CAP_RF_SW_KILL;
	else
		priv->capability &= ~CAP_RF_SW_KILL;

	if (priv->eeprom.sku_cap & EEPROM_SKU_CAP_HW_RF_KILL_ENABLE)
		priv->capability |= CAP_RF_HW_KILL;
	else
		priv->capability &= ~CAP_RF_HW_KILL;

	switch (priv->capability & (CAP_RF_HW_KILL | CAP_RF_SW_KILL)) {
	case CAP_RF_HW_KILL:
		IOLog("HW RF KILL supported in EEPROM.\n");
		break;
	case CAP_RF_SW_KILL:
		IOLog("SW RF KILL supported in EEPROM.\n");
		break;
	case (CAP_RF_HW_KILL | CAP_RF_SW_KILL):
		IOLog("HW & HW RF KILL supported in EEPROM.\n");
		break;
	default:
		IOLog("NO RF KILL supported in EEPROM.\n");
		break;
	}
	

	/* Allocate the RX queue, or reset if it is already allocated */
	IOLog("Allocate the RX queue\n");
	if (!priv->rxq)
		priv->rxq = ipw_rx_queue_alloc(priv);
	else
		ipw_rx_queue_reset(priv, priv->rxq);

	if (!priv->rxq) {
		IOLog("Unable to initialize Rx queue\n");
		//return -ENOMEM;
	}
	IOLog("ipw_rx_queue_replenish\n");
	ipw_rx_queue_replenish(priv);
	IOLog("ipw_rx_init\n");
	ipw_rx_init(priv, priv->rxq);

//	spin_lock_irqsave(&priv->lock, flags);

	rc = ipw_grab_restricted_access(priv);
	/*if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}*/
	_ipw_write_restricted(priv, FH_RCSR_WPTR(0), priv->rxq->write & ~7);
	_ipw_release_restricted_access(priv);

	//spin_unlock_irqrestore(&priv->lock, flags);
	IOLog("ipw_queue_reset\n");
	rc = ipw_queue_reset(priv);
	//if (rc)
	//	return rc;

	priv->status |= STATUS_INIT;

	return 0;

}

int darwin_iwi4965::ipw_queue_inc_wrap(int index, int n_bd)
{
	return (++index == n_bd) ? 0 : index;
}

void darwin_iwi4965::ipw_queue_tx_free_tfd(struct ipw_priv *priv,
				  struct ipw_tx_queue *txq)
{
	struct tfd_frame *bd_tmp = (struct tfd_frame *)&txq->bd[0];
	struct tfd_frame *bd = &bd_tmp[txq->q.last_used];
	//struct pci_dev *dev = priv->pci_dev;
	int i;
	int counter = 0;
	/* classify bd */
	if (txq->q.id == priv->hw_setting.cmd_queue_no)
		/* nothing to cleanup after for host commands */
		return;

	/* sanity check */
	counter = TFD_CTL_COUNT_GET(le32_to_cpu(bd->control_flags));
	if (counter > NUM_TFD_CHUNKS) {
		IOLog("Too many chunks: %d\n", counter);
		/** @todo issue fatal error, it is quite serious situation */
		return;
	}

	/* unmap chunks if any */

	for (i = 1; i < counter; i++) {
		//pci_unmap_single(dev, le32_to_cpu(bd->pa[i].addr),
		//		 le16_to_cpu(bd->pa[i].len), PCI_DMA_TODEVICE);
				 bd->pa[i].addr=NULL;
		if (txq->txb[txq->q.last_used].skb[0]) {
			mbuf_t skb = txq->txb[txq->q.last_used].skb[0];
			priv->tx_bytes += mbuf_len(skb) - mbuf_pkthdr_len(skb);
			   // ieee80211_get_hdrlen_from_skb(skb);

			/*do we still own skb, then released */
			if (txq->txb[txq->q.last_used].skb[0]) {
				if (!(mbuf_type(skb) == MBUF_TYPE_FREE) ) freePacket(skb);
				txq->txb[txq->q.last_used].skb[0] = NULL;
			}
		}
	}
	return;

}

void darwin_iwi4965::ieee80211_txb_free(struct ieee80211_txb *txb)
{
	int i;
	if (unlikely(!txb))
		return;
	for (i = 0; i < txb->nr_frags; i++)
		if (txb->fragments[i]) 
		{
			mbuf_freem_list(txb->fragments[i]);
			if (!(mbuf_type(txb->fragments[i]) == MBUF_TYPE_FREE) ) freePacket(txb->fragments[i]);
			txb->fragments[i]=NULL;
			
		}
	kfree(txb);
	txb=NULL;
}

void darwin_iwi4965::ipw_queue_tx_free(struct ipw_priv *priv, struct ipw_tx_queue *txq)
{
	struct ipw_queue *q = &txq->q;
	//struct pci_dev *dev = priv->pci_dev;
	int len;

	if (q->n_bd == 0)
		return;

	/* first, empty all BD's */
	for (; q->first_empty != q->last_used;
	     q->last_used = ipw_queue_inc_wrap(q->last_used, q->n_bd)) {
		ipw_queue_tx_free_tfd(priv, txq);
	}

	len = (sizeof(txq->cmd[0]) * q->n_window) + IPW_MAX_SCAN_SIZE;
	//pci_free_consistent(dev, len, txq->cmd, txq->dma_addr_cmd);

	txq->dma_addr_cmd=NULL;
	/* free buffers belonging to queue itself */
	ipw3945_queue_tx_free(priv, txq);

	if (txq->txb) {
		kfree(txq->txb);
		txq->txb = NULL;
	}

	/* 0 fill whole structure */
	memset(txq, 0, sizeof(*txq));

}

int darwin_iwi4965::ipw3945_queue_tx_free(struct ipw_priv *priv,
				 struct ipw_tx_queue *txq)
{
	struct ipw_queue *q = &txq->q;
	//struct pci_dev *dev = priv->pci_dev;

	if (q->n_bd == 0)
		return 0;

	/* free buffers belonging to queue itself */
	//pci_free_consistent(dev, sizeof(struct tfd_frame) * q->n_bd,
	//		    txq->bd, q->dma_addr);
	q->dma_addr=NULL;
	return 0;
}

/**
 * Destroy all DMA queues and structures
 *
 * @param priv
 */
void darwin_iwi4965::ipw_tx_queue_free(struct ipw_priv *priv)
{

	/* Tx queues */
	ipw_queue_tx_free(priv, &priv->txq[0]);
	ipw_queue_tx_free(priv, &priv->txq[1]);
	ipw_queue_tx_free(priv, &priv->txq[2]);
	ipw_queue_tx_free(priv, &priv->txq[3]);
	ipw_queue_tx_free(priv, &priv->txq[4]);
	ipw_queue_tx_free(priv, &priv->txq[5]);
}

int darwin_iwi4965::ipw_tx_reset(struct ipw_priv *priv)
{
	int rc;
	unsigned long flags;

	//spin_lock_irqsave(&priv->lock, flags);
	rc = ipw_grab_restricted_access(priv);
	/*if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}*/

	_ipw_write_restricted_reg(priv, SCD_MODE_REG, 0x2);	// bypass mode
	_ipw_write_restricted_reg(priv, SCD_ARASTAT_REG, 0x01);	// RA 0 is active
	_ipw_write_restricted_reg(priv, SCD_TXFACT_REG, 0x3f);	// all 6 fifo are active
	_ipw_write_restricted_reg(priv, SCD_SBYP_MODE_1_REG, 0x010000);
	_ipw_write_restricted_reg(priv, SCD_SBYP_MODE_2_REG, 0x030002);
	_ipw_write_restricted_reg(priv, SCD_TXF4MF_REG, 0x000004);
	_ipw_write_restricted_reg(priv, SCD_TXF5MF_REG, 0x000005);

	_ipw_write_restricted(priv, FH_TSSR_CBB_BASE, priv->hw_setting.shared_phys);

	_ipw_write_restricted(priv,
			     FH_TSSR_MSG_CONFIG,
			     ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TXPD_ON
			     |
			     ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_TXPD_ON
			     |
			     ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_MAX_FRAG_SIZE_128B
			     |
			     ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_SNOOP_RD_TFD_ON
			     |
			     ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RD_CBB_ON
			     |
			     ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_ORDER_RSP_WAIT_TH
			     | ALM_FH_TSSR_TX_MSG_CONFIG_REG_VAL_RSP_WAIT_TH);

	_ipw_release_restricted_access(priv);

	//spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

int darwin_iwi4965::ipw_queue_tx_init(struct ipw_priv *priv,
			     struct ipw_tx_queue *q, int count, u32 id)
{
	//struct pci_dev *dev = priv->pci_dev;
	int len;
	int rc = 0;

	/* alocate command space + one big command for scan since scan
	 * command is very huge the system will not have two scan at the
	 * same time */
	len = (sizeof(struct ipw_cmd) * count) + IPW_MAX_SCAN_SIZE;
	//q->cmd = pci_alloc_consistent(dev, len, &q->dma_addr_cmd);
	MemoryDmaAlloc(len, &(q->q.dma_addr), &(q->cmd));
	if (!q->cmd)
		return -ENOMEM;

	rc = ipw3945_queue_tx_init(priv, q, count, id);
	if (rc) {
		//pci_free_consistent(dev, len, q->cmd, q->dma_addr_cmd);
		q->dma_addr_cmd=NULL;
		return -ENOMEM;
	}

	q->need_update = 0;
	ipw_queue_init(priv, &q->q, TFD_QUEUE_SIZE_MAX, count, id);
	return 0;
}

int darwin_iwi4965::ipw3945_queue_tx_init(struct ipw_priv *priv,
				 struct ipw_tx_queue *q, int count, u32 id)
{
	//struct pci_dev *dev = priv->pci_dev;

	if (id != priv->hw_setting.cmd_queue_no) {
		q->txb = (struct ipw_tx_info*)kmalloc(sizeof(q->txb[0]) *
				 TFD_QUEUE_SIZE_MAX, GFP_ATOMIC);
		if (!q->txb) {
			IOLog("kmalloc for auxilary BD "
				  "structures failed\n");
			return -ENOMEM;
		}
	} else
		q->txb = NULL;

	/*q->bd = (u8 *)
	    pci_alloc_consistent(dev,
				 sizeof(struct tfd_frame) *
				 TFD_QUEUE_SIZE_MAX, &q->q.dma_addr);*/

	MemoryDmaAlloc(sizeof(struct tfd_frame) *
				 TFD_QUEUE_SIZE_MAX, &(q->q.dma_addr), &(q->bd));
	
	q->q.element_size = sizeof(struct tfd_frame);
	if (!q->bd) {
		IOLog("pci_alloc_consistent(%zd) failed\n",
			  sizeof(q->bd[0]) * count);
		if (q->txb) {
			kfree(q->txb);
			q->txb = NULL;
		}
		return -ENOMEM;
	}

	return 0;
}

int darwin_iwi4965::ipw_queue_init(struct ipw_priv *priv, struct ipw_queue *q,
			  int count, int size, u32 id)
{
	int rc;
	unsigned long flags;

	q->n_bd = count;
	q->n_window = size;
	q->id = id;

	q->low_mark = q->n_window / 4;
	if (q->low_mark < 4)
		q->low_mark = 4;

	q->high_mark = q->n_window / 8;
	if (q->high_mark < 2)
		q->high_mark = 2;

	q->first_empty = q->last_used = 0;
	
	
	struct ipw_shared_t *shared_data =
	    (struct ipw_shared_t *)priv->hw_setting.shared_virt;

	shared_data->tx_base_ptr[id] = (u32) q->dma_addr;

	q->element_size = sizeof(struct tfd_frame);

	//spin_lock_irqsave(&priv->lock, flags);
	rc = ipw_grab_restricted_access(priv);
	if (rc) {
		//spin_unlock_irqrestore(&priv->lock, flags);
		//return rc;
	}
	_ipw_write_restricted(priv, FH_CBCC_CTRL(id), 0);
	_ipw_write_restricted(priv, FH_CBCC_BASE(id), 0);

	_ipw_write_restricted(priv, FH_TCSR_CONFIG(id),
			     ALM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_RTC_NOINT
			     |
			     ALM_FH_TCSR_TX_CONFIG_REG_VAL_MSG_MODE_TXF
			     |
			     ALM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_IFTFD
			     |
			     ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL
			     | ALM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE);
	_ipw_release_restricted_access(priv);

	ipw_read32(FH_TSSR_CBB_BASE);	/* fake read to flush all prev. writes */

	//spin_unlock_irqrestore(&priv->lock, flags);
	return 0;

}

int darwin_iwi4965::ipw_queue_reset(struct ipw_priv *priv)
{
	int rc = 0;

	ipw_tx_queue_free(priv);

	/* Tx CMD queue */
	ipw_tx_reset(priv);

	/* Tx queue(s) */
	rc = ipw_queue_tx_init(priv, &priv->txq[0], TFD_TX_CMD_SLOTS, 0);
	if (rc) {
		IOLog("Tx 0 queue init failed\n");
		goto error;
	}

	rc = ipw_queue_tx_init(priv, &priv->txq[1], TFD_TX_CMD_SLOTS, 1);
	if (rc) {
		IOLog("Tx 1 queue init failed\n");
		goto error;
	}
	rc = ipw_queue_tx_init(priv, &priv->txq[2], TFD_TX_CMD_SLOTS, 2);
	if (rc) {
		IOLog("Tx 2 queue init failed\n");
		goto error;
	}
	rc = ipw_queue_tx_init(priv, &priv->txq[3], TFD_TX_CMD_SLOTS, 3);
	if (rc) {
		IOLog("Tx 3 queue init failed\n");
		goto error;
	}

	rc = ipw_queue_tx_init(priv, &priv->txq[4], TFD_CMD_SLOTS,
			       CMD_QUEUE_NUM);
	if (rc) {
		IOLog("Tx Cmd queue init failed\n");
		goto error;
	}

	rc = ipw_queue_tx_init(priv, &priv->txq[5], TFD_TX_CMD_SLOTS, 5);
	if (rc) {
		IOLog("Tx service queue init failed\n");
		goto error;
	}

	return rc;

      error:
	ipw_tx_queue_free(priv);
	return rc;
}

int darwin_iwi4965::ipw_rx_init(struct ipw_priv *priv, struct ipw_rx_queue *rxq)
{
	int rc;
	unsigned long flags;

	//spin_lock_irqsave(&priv->lock, flags);
	rc = ipw_grab_restricted_access(priv);
	if (rc) {
		//spin_unlock_irqrestore(&priv->lock, flags);
		//return rc;
	}

	_ipw_write_restricted(priv, FH_RCSR_RBD_BASE(0), rxq->dma_addr);
	_ipw_write_restricted(priv, FH_RCSR_RPTR_ADDR(0),
			     priv->hw_setting.shared_phys +
			     offsetof(struct ipw_shared_t, rx_read_ptr[0]));
	_ipw_write_restricted(priv, FH_RCSR_WPTR(0), 0);
	_ipw_write_restricted(priv, FH_RCSR_CONFIG(0),
			     ALM_FH_RCSR_RX_CONFIG_REG_VAL_DMA_CHNL_EN_ENABLE
			     |
			     ALM_FH_RCSR_RX_CONFIG_REG_VAL_RDRBD_EN_ENABLE
			     |
			     ALM_FH_RCSR_RX_CONFIG_REG_BIT_WR_STTS_EN
			     |
			     ALM_FH_RCSR_RX_CONFIG_REG_VAL_MAX_FRAG_SIZE_128
			     | (RX_QUEUE_SIZE_LOG <<
				ALM_FH_RCSR_RX_CONFIG_REG_POS_RBDC_SIZE)
			     |
			     ALM_FH_RCSR_RX_CONFIG_REG_VAL_IRQ_DEST_INT_HOST
			     | (1 << ALM_FH_RCSR_RX_CONFIG_REG_POS_IRQ_RBTH)
			     | ALM_FH_RCSR_RX_CONFIG_REG_VAL_MSG_MODE_FH);

	/* fake read to flush all prev I/O */
	_ipw_read_restricted(priv, FH_RSSR_CTRL);

	_ipw_release_restricted_access(priv);

	//spin_unlock_irqrestore(&priv->lock, flags);

	return 0;

}

int darwin_iwi4965::ipw_rx_queue_space(struct ipw_rx_queue *q)
{
	int s = q->read - q->write;
	if (s <= 0)
		s += RX_QUEUE_SIZE;
	s -= 2;			// keep some buffer to not confuse full and empty queue
	if (s < 0)
		s = 0;
	return s;
}

int darwin_iwi4965::ipw_rx_queue_update_write_ptr(struct ipw_priv *priv,
					 struct ipw_rx_queue *q)
{
	u32 reg = 0;
	int rc = 0;
	unsigned long flags;

	//spin_lock_irqsave(&q->lock, flags);

	if (q->need_update == 0)
		goto exit_unlock;

	if (priv->status & STATUS_POWER_PMI) {
		reg = ipw_read32(CSR_UCODE_DRV_GP1);

		if (reg & CSR_UCODE_DRV_GP1_BIT_MAC_SLEEP) {
			ipw_set_bit( CSR_GP_CNTRL,
				    CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
			goto exit_unlock;
		}

		rc = ipw_grab_restricted_access(priv);
		if (rc)
			goto exit_unlock;

		_ipw_write_restricted(priv, FH_RCSR_WPTR(0), q->write & ~0x7);
		_ipw_release_restricted_access(priv);
	} else {
		ipw_write32( FH_RCSR_WPTR(0), q->write & ~0x7);
	}

	q->need_update = 0;

      exit_unlock:
	//spin_unlock_irqrestore(&q->lock, flags);
	return rc;
}

int darwin_iwi4965::ipw_rx_queue_restock(struct ipw_priv *priv)
{
		
	struct ipw_rx_queue *rxq = priv->rxq;
	struct list_head *element;
	struct ipw_rx_mem_buffer *rxb;
	unsigned long flags;
	int write;
	int counter = 0;

	//spin_lock_irqsave(&rxq->lock, flags);
	write = rxq->write & ~0x7;
	while ((ipw_rx_queue_space(rxq) > 0) && (rxq->free_count)) {
		element = rxq->rx_free.next;
		rxb = list_entry(element, struct ipw_rx_mem_buffer, list);
		list_del(element);
		((u32 *) rxq->bd)[rxq->write] = rxb->dma_addr;
		rxq->queue[rxq->write] = rxb;
		rxq->write = (rxq->write + 1) % RX_QUEUE_SIZE;
		rxq->free_count--;
		counter++;
	}
	//spin_unlock_irqrestore(&rxq->lock, flags);
	/* If the pre-allocated buffer pool is dropping low, schedule to
	 * refill it */
	if (rxq->free_count <= RX_LOW_WATERMARK) {
		queue_te(7,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_rx_queue_replenish),priv,NULL,true);
	}

	counter = ipw_rx_queue_space(rxq);
	/* If we've added more space for the firmware to place data, tell it */
	if ((write != (rxq->write & ~0x7))
	    || (rxq->write - rxq->read > 7)
		|| (-rxq->write + rxq->read > 7)) {
		//spin_lock_irqsave(&rxq->lock, flags);
		rxq->need_update = 1;
		//spin_unlock_irqrestore(&rxq->lock, flags);
		ipw_rx_queue_update_write_ptr(priv, rxq);
	}

	return 0;

}

void darwin_iwi4965::ipw_rx_queue_replenish(struct ipw_priv *priv)
{
	struct ipw_rx_queue *rxq = priv->rxq;
	struct list_head *element;
	struct ipw_rx_mem_buffer *rxb;
	unsigned long flags;
	//spin_lock_irqsave(&rxq->lock, flags);
	while (!list_empty(&rxq->rx_used)) {
		element = rxq->rx_used.next;
		rxb = list_entry(element, struct ipw_rx_mem_buffer, list);
		//rxb->skb = alloc_skb(IPW_RX_BUF_SIZE, GFP_ATOMIC);
		rxb->skb=allocatePacket(IPW_RX_BUF_SIZE);
		if (!rxb->skb) {
			IOLog(
			       "%s: Can not allocate SKB buffers.\n",
			       priv->net_dev->name);
			/* We don't reschedule replenish work here -- we will
			 * call the restock method and if it still needs
			 * more buffers it will schedule replenish */
			break;
		}
		list_del(element);
		rxb->dma_addr = mbuf_data_to_physical(mbuf_data(rxb->skb));
		list_add_tail(&rxb->list, &rxq->rx_free);
		rxq->free_count++;
	}
	//spin_unlock_irqrestore(&rxq->lock, flags);

	//spin_lock_irqsave(&priv->lock, flags);
	ipw_rx_queue_restock(priv);
	//spin_unlock_irqrestore(&priv->lock, flags);
}

void darwin_iwi4965::ipw_rx_queue_reset(struct ipw_priv *priv,
				      struct ipw_rx_queue *rxq)
{
	unsigned long flags;
	int i;
	//spin_lock_irqsave(&rxq->lock, flags);
	INIT_LIST_HEAD(&rxq->rx_free);
	INIT_LIST_HEAD(&rxq->rx_used);
	/* Fill the rx_used queue with _all_ of the Rx buffers */
	for (i = 0; i < RX_FREE_BUFFERS + RX_QUEUE_SIZE; i++) {
		/* In the reset function, these buffers may have been allocated
		 * to an SKB, so we need to unmap and free potential storage */
		if (rxq->pool[i].skb != NULL) {
			rxq->pool[i].dma_addr=NULL;
			if (!(mbuf_type(rxq->pool[i].skb) == MBUF_TYPE_FREE) ) freePacket(rxq->pool[i].skb);
			rxq->pool[i].skb = NULL;
		}
		list_add_tail(&rxq->pool[i].list, &rxq->rx_used);
	}

	/* Set us so that we have processed and used all buffers, but have
	 * not restocked the Rx queue with fresh buffers */
	rxq->read = rxq->write = 0;
	rxq->free_count = 0;
	//spin_unlock_irqrestore(&rxq->lock, flags);
}

struct ipw_rx_queue *darwin_iwi4965::ipw_rx_queue_alloc(struct ipw_priv *priv)
{
	struct ipw_rx_queue *rxq;
	//struct pci_dev *dev = priv->pci_dev;
	int i;
	rxq = (struct ipw_rx_queue*)kmalloc(sizeof(*rxq), GFP_ATOMIC);
	memset(rxq, 0, sizeof(*rxq));

	//spin_lock_init(&rxq->lock);
	INIT_LIST_HEAD(&rxq->rx_free);
	INIT_LIST_HEAD(&rxq->rx_used);
	//rxq->bd = pci_alloc_consistent(dev, 4 * RX_QUEUE_SIZE, &rxq->dma_addr);
	MemoryDmaAlloc(4 * RX_QUEUE_SIZE, &rxq->dma_addr, &rxq->bd);
	/* Fill the rx_used queue with _all_ of the Rx buffers */
	for (i = 0; i < RX_FREE_BUFFERS + RX_QUEUE_SIZE; i++)
		list_add_tail(&rxq->pool[i].list, &rxq->rx_used);
	/* Set us so that we have processed and used all buffers, but have
	 * not restocked the Rx queue with fresh buffers */
	rxq->read = rxq->write = 0;
	rxq->free_count = 0;
	rxq->need_update = 0;
	return rxq;
}

int darwin_iwi4965::ipw_rf_eeprom_ready(struct ipw_priv *priv)
{
	u8 sku_cap;
	int rc;

	rc = ipw_query_eeprom(priv, EEPROM_SKU_CAP, sizeof(u8),
			      (u8 *) & sku_cap);
	if (rc) {
		IOLog("failed to read EEPROM_SKU_CAP\n");
		return rc;
	}

	if (sku_cap & EEPROM_SKU_CAP_SW_RF_KILL_ENABLE)
		priv->capability |= CAP_RF_SW_KILL;
	else
		priv->capability &= ~CAP_RF_SW_KILL;

	if (sku_cap & EEPROM_SKU_CAP_HW_RF_KILL_ENABLE)
		priv->capability |= CAP_RF_HW_KILL;
	else
		priv->capability &= ~CAP_RF_HW_KILL;

	switch (priv->capability & (CAP_RF_HW_KILL | CAP_RF_SW_KILL)) {
	case CAP_RF_HW_KILL:
		IOLog("HW RF KILL supported in EEPROM.\n");
		break;
	case CAP_RF_SW_KILL:
		IOLog("SW RF KILL supported in EEPROM.\n");
		break;
	case (CAP_RF_HW_KILL | CAP_RF_SW_KILL):
		IOLog("HW & HW RF KILL supported in EEPROM.\n");
		break;
	default:
		IOLog("NO RF KILL supported in EEPROM.\n");
		break;
	}

	return 0;
}

int darwin_iwi4965::ipw_verify_bootstrap(struct ipw_priv *priv)
{
	u32 *image;
	u32 len, val;
	int rc1;
	int rc2 = 0;
	u32 errcnt;

	len = priv->ucode_boot_data.len;
	image = (u32 *) priv->ucode_boot_data.v_addr;

	IOLog("bootstrap data image size is %u\n", len);

	rc1 = ipw_grab_restricted_access(priv);
	//if (rc1)
	//	return rc1;

	/* read from card's data memory to verify */
	_ipw_write_restricted(priv, HBUS_TARG_MEM_RADDR, RTC_DATA_LOWER_BOUND);

	for (errcnt = 0; len > 0; len -= sizeof(u32), image++) {
		/* read data comes through single port, auto-incr addr */
		val = _ipw_read_restricted(priv, HBUS_TARG_MEM_RDAT);
		if (val != *image) {
			IOLog("bootstrap DATA section is invalid at offset "
				  "0x%x\n", priv->ucode_boot_data.len - len);
			rc2 = -EIO;
			errcnt++;
			if (errcnt >= 20)
				break;
		}
	}

	_ipw_release_restricted_access(priv);
	errcnt=0;
	if (!errcnt)
		IOLog("bootstrap image in DATA memory is good\n");

	/* check instruction image */
	len = priv->ucode_boot.len;
	image = (u32 *) priv->ucode_boot.v_addr;

	IOLog("bootstrap instruction image size is %u\n", len);

	rc1 = ipw_grab_restricted_access(priv);
	//if (rc1)
	//	return rc1;

	/* read from card's instruction memory to verify */
	_ipw_write_restricted(priv, HBUS_TARG_MEM_RADDR, RTC_INST_LOWER_BOUND);

	for (errcnt = 0; len > 0; len -= sizeof(u32), image++) {
		/* read data comes through single port, auto-incr addr */
		val = _ipw_read_restricted(priv, HBUS_TARG_MEM_RDAT);
		if (val != *image) {
			IOLog("bootstrap INST section is invalid at offset "
				  "0x%x\n", priv->ucode_boot.len - len);
			rc2 = -EIO;
			errcnt++;
			if (errcnt >= 20)
				break;
		}
	}

	_ipw_release_restricted_access(priv);
	errcnt=0;
	if (!errcnt)
		IOLog
		    ("bootstrap image in INSTRUCTION memory is good\n");

	return rc2;
}

int darwin_iwi4965::ipw_verify_ucode(struct ipw_priv *priv)
{
	u32 *image;
	u32 len, val;
	int rc = 0;
	u32 errcnt;

	/* Since data memory has already been modified by running uCode,
	 * we can't really verify the data image, but we'll show its size. */
	IOLog("ucode data image size is %u\n", priv->ucode_data.len);

	/* read from instruction memory to verify instruction image */
	image = (u32*)priv->ucode_code.v_addr;
	len = priv->ucode_code.len;

	IOLog("ucode inst image size is %u\n", len);

	rc = ipw_grab_restricted_access(priv);
	if (rc)
		return rc;

	_ipw_write_restricted(priv, HBUS_TARG_MEM_RADDR, RTC_INST_LOWER_BOUND);

	errcnt = 0;
	for (; len > 0; len -= sizeof(u32), image++) {
		/* read data comes through single port, auto-incr addr */
		val = _ipw_read_restricted(priv, HBUS_TARG_MEM_RDAT);
		if (val != *image) {
			IOLog("uCode INST section is invalid at "
				  "offset 0x%x, is 0x%x, s/b 0x%x\n",
				  priv->ucode_code.len - len, val, *image);
			rc = -EIO;
			errcnt++;
			if (errcnt >= 20)
				break;
		}
	}

	_ipw_release_restricted_access(priv);

	if (!errcnt)
		IOLog
		    ("runtime ucode image in INSTRUCTION memory is good\n");

	return rc;

}

int darwin_iwi4965::ipw_setup_bootstrap(struct ipw_priv *priv)
{
	int rc = 0;

	/* Load bootstrap uCode data into card via card's TFD DMA channel */
	rc = ipw_load_ucode(priv, &(priv->ucode_boot_data),
			    ALM_RTC_DATA_SIZE, RTC_DATA_LOWER_BOUND);
	if (rc)
		goto error;

	/* Load bootstrap uCode instructions, same way */
	rc = ipw_load_ucode(priv, &(priv->ucode_boot),
			    ALM_RTC_INST_SIZE, RTC_INST_LOWER_BOUND);
	if (rc)
		goto error;

	/* verify bootstrap in-place in DATA and INSTRUCTION SRAM */
	ipw_verify_bootstrap(priv);

	/* tell bootstrap uCode where to find the runtime uCode in host DRAM */
	rc = ipw_grab_restricted_access(priv);
	if (rc)
		goto error;

	_ipw_write_restricted_reg(priv, BSM_DRAM_INST_PTR_REG,
				 priv->ucode_code.p_addr);
	_ipw_write_restricted_reg(priv, BSM_DRAM_DATA_PTR_REG,
				 priv->ucode_data.p_addr);
	_ipw_write_restricted_reg(priv, BSM_DRAM_INST_BYTECOUNT_REG,
				 priv->ucode_code.len);
	_ipw_write_restricted_reg(priv, BSM_DRAM_DATA_BYTECOUNT_REG,
				 priv->ucode_data.len);
	_ipw_release_restricted_access(priv);

	return 0;

      error:
	return rc;
}

#define MAX_HW_RESTARTS 2

int darwin_iwi4965::ipw_up(struct ipw_priv *priv)
{
	pl++;
	if (pl>MAX_HW_RESTARTS)	return 0;
	int rc, i;

	if (priv->status & STATUS_EXIT_PENDING) {
		IOLog("Exit pending will not bring the NIC up\n");
		//return -EIO;
	}

	if (priv->status & STATUS_RF_KILL_SW) {
		IOLog("Radio disabled by module parameter.\n");
		//return 0;
	};// else if (priv->status & STATUS_RF_KILL_HW)
		//return 0;

	ipw_write32( CSR_INT, 0xFFFFFFFF);

	rc = ipw_nic_init(priv);
	if (rc) {
		IOLog("Unable to init nic\n");
		//return rc;
	}

	ipw_write32( CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	ipw_write32( CSR_UCODE_DRV_GP1_CLR,
		    CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);
	ipw_write32( CSR_INT, 0xFFFFFFFF);

	ipw_enable_interrupts(priv);

	ipw_write32( CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	ipw_write32( CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);

	for (i = 1; i < MAX_HW_RESTARTS; i++) {

		ipw_clear_stations_table(priv);

		rc = ipw_setup_bootstrap(priv);
		if (rc) {
			IOLog("Unable to set up bootstrap uCode: %d\n", rc);
			continue;
		}

		/* start card; bootstrap will load runtime ucode */
		ipw_nic_start(priv);

		ipw_card_show_info(priv);

		//if (!(priv->config & CFG_CUSTOM_MAC)) {
			//eeprom_parse_mac(priv, priv->mac_addr);
			memcpy(priv->mac_addr, priv->eeprom.mac_address, 6);
			IOLog("MAC address: " MAC_FMT "\n",
				       MAC_ARG(priv->mac_addr));
			
			// TODO removed by patatester, maybe the cause of the incorrect 
			// mac address association
			// ifnet_set_lladdr(fifnet, priv->eeprom.mac_address, ETH_ALEN);
		//}

		memcpy(priv->net_dev->dev_addr, priv->mac_addr, ETH_ALEN);
		//memcpy(priv->ieee->perm_addr, priv->mac_addr, ETH_ALEN);

		return 0;
	}

	priv->status |= STATUS_EXIT_PENDING;
	queue_te(12,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_down),priv,NULL,true);

	/* tried to restart and config the device for as long as our
	 * patience could withstand */
	IOLog("Unable to initialize device after %d attempts.\n", i);
	return -EIO;

}

IOReturn darwin_iwi4965::enable( IONetworkInterface * netif ) 
{
	if (!fifnet)
	{
		char ii[4];
		sprintf(ii,"%s%d" ,fNetif->getNamePrefix(), fNetif->getUnitNumber());
		ifnet_find_by_name(ii,&fifnet);
		memcpy(&priv->net_dev->name,ii,sizeof(ii));
		IWI_DEBUG("ifnet_t %s%d = %x\n",ifnet_name(fifnet),ifnet_unit(fifnet),fifnet);
	}
	if ((priv->status & STATUS_RF_KILL_HW)) return -1;
	IWI_DEBUG("ifconfig up\n");
	switch ((fNetif->getFlags() & IFF_UP) && (fNetif->getFlags() & IFF_RUNNING))
	{
	case false:
		IWI_DEBUG("ifconfig going up\n ");
		
		//super::enable(fNetif);
		//fNetif->setPoweredOnByUser(true);
		//fNetif->setLinkState(kIO80211NetworkLinkUp);

		//(if_flags & ~mask) | (new_flags & mask) if mask has IFF_UP if_updown fires up (kpi_interface.c in xnu)	
		ifnet_set_flags(fifnet, IFF_UP|IFF_RUNNING|IFF_BROADCAST|IFF_SIMPLEX|IFF_MULTICAST|IFF_NOTRAILERS 		, IFF_UP | IFF_RUNNING );
		//fNetif->inputEvent(kIONetworkEventTypeLinkUp,NULL);
		fTransmitQueue->setCapacity(1024);
		fTransmitQueue->start();
		return kIOReturnSuccess;
		break;
	default:
		IWI_DEBUG("ifconfig already up\n");
		return kIOReturnExclusiveAccess;
		break;
	}

}

inline int darwin_iwi4965::ipw_is_init(struct ipw_priv *priv)
{
	return (priv->status & STATUS_INIT) ? 1 : 0;
}

u32 darwin_iwi4965::ipw_register_toggle(u32 reg)
{
	reg &= ~IPW_START_STANDBY;
	if (reg & IPW_GATE_ODMA)
		reg &= ~IPW_GATE_ODMA;
	if (reg & IPW_GATE_IDMA)
		reg &= ~IPW_GATE_IDMA;
	if (reg & IPW_GATE_ADMA)
		reg &= ~IPW_GATE_ADMA;
	return reg;
}

void darwin_iwi4965::ipw_led_activity_off(struct ipw_priv *priv)
{

}

void darwin_iwi4965::ipw_led_link_down(struct ipw_priv *priv)
{
	ipw_led_activity_off(priv);
	ipw_led_link_off(priv);

	if (priv->status & STATUS_RF_KILL_MASK)
		ipw_led_radio_off(priv);
}

void darwin_iwi4965::ipw_led_link_off(struct ipw_priv *priv)
{

}

void darwin_iwi4965::ipw_led_band_off(struct ipw_priv *priv)
{
	
}

void darwin_iwi4965::ipw_led_shutdown(struct ipw_priv *priv)
{
	ipw_led_activity_off(priv);
	ipw_led_link_off(priv);
	ipw_led_band_off(priv);
	queue_td(2,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_led_link_on));
	//cancel_delayed_work(&priv->led_link_off);
	//cancel_delayed_work(&priv->led_act_off);
}

void darwin_iwi4965::ipw_abort_scan(struct ipw_priv *priv)
{
	int err;

	if (priv->status & STATUS_SCAN_ABORTING) {
		IOLog("Ignoring concurrent scan abort request.\n");
		return;
	}
	priv->status |= STATUS_SCAN_ABORTING;
	queue_td(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan));
	queue_td(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan_check));
	err = sendCommand(IPW_CMD_SCAN_ABORT, NULL,0, 0);
	if (err)
		IOLog("Request to abort scan failed.\n");
}

void darwin_iwi4965::ipw_send_disassociate(struct ipw_priv *priv, int quiet)
{
	int err;

	if (priv->status & STATUS_ASSOCIATING) {
		IOLog("Disassociating while associating.\n");
		//queue_work(priv->workqueue, &priv->disassociate);
		return;
	}

	if (!(priv->status & STATUS_ASSOCIATED)) {
		IOLog("Disassociating while not associated.\n");
		return;
	}

	IOLog("Disassocation attempt from %02x:%02x:%02x:%02x:%02x:%02x "
			"on channel %d.\n",
			MAC_ARG(priv->assoc_request.bssid),
			priv->assoc_request.channel);

	priv->status &= ~(STATUS_ASSOCIATING | STATUS_ASSOCIATED);
	priv->status |= STATUS_DISASSOCIATING;

	if (quiet)
		priv->assoc_request.assoc_type = HC_DISASSOC_QUIET;
	else
		priv->assoc_request.assoc_type = HC_DISASSOCIATE;

	err = ipw_send_associate(priv, &priv->assoc_request);
	if (err) {
		IOLog("Attempt to send [dis]associate command "
			     "failed.\n");
		return;
	}

}

int darwin_iwi4965::ipw_send_associate(struct ipw_priv *priv,
			      struct ipw_associate *associate)
{
	struct ipw_associate tmp_associate;

	if (!priv || !associate) {
		IOLog("Invalid args\n");
		return -1;
	}

	memcpy(&tmp_associate, associate, sizeof(*associate));
	tmp_associate.policy_support =
	    cpu_to_le16(tmp_associate.policy_support);
	tmp_associate.assoc_tsf_msw = cpu_to_le32(tmp_associate.assoc_tsf_msw);
	tmp_associate.assoc_tsf_lsw = cpu_to_le32(tmp_associate.assoc_tsf_lsw);
	tmp_associate.capability = cpu_to_le16(tmp_associate.capability);
	tmp_associate.listen_interval =
	    cpu_to_le16(tmp_associate.listen_interval);
	tmp_associate.beacon_interval =
	    cpu_to_le16(tmp_associate.beacon_interval);
	tmp_associate.atim_window = cpu_to_le16(tmp_associate.atim_window);

	return sendCommand(IPW_CMD_ASSOCIATE, &tmp_associate,sizeof(tmp_associate), 1);
}

int darwin_iwi4965::ipw_disassociate(struct ipw_priv *data)
{
	struct ipw_priv *priv = data;
	if (!(priv->status & (STATUS_ASSOCIATED | STATUS_ASSOCIATING)))
		return 0;
	ipw_send_disassociate(data, 0);
	return 1;
}

void darwin_iwi4965::ipw_deinit(struct ipw_priv *priv)
{
	int i;

	if (priv->status & STATUS_SCANNING) {
		IOLog("Aborting scan during shutdown.\n");
		ipw_abort_scan(priv);
	}

	if (priv->status & STATUS_ASSOCIATED) {
		IOLog("Disassociating during shutdown.\n");
		ipw_disassociate(priv);
	}

	ipw_led_shutdown(priv);

	/* Wait up to 1s for status to change to not scanning and not
	 * associated (disassociation can take a while for a ful 802.11
	 * exchange */
	for (i = 1000; i && (priv->status &
			     (STATUS_DISASSOCIATING |
			      STATUS_ASSOCIATED | STATUS_SCANNING)); i--)
		udelay(10);

	if (priv->status & (STATUS_DISASSOCIATING |
			    STATUS_ASSOCIATED | STATUS_SCANNING))
		IOLog("Still associated or scanning...\n");
	else
		IOLog("Took %dms to de-init\n", 1000 - i);

	/* Attempt to disable the card */
	u32 phy_off = cpu_to_le32(0);
	sendCommand(IPW_CMD_CARD_DISABLE, &phy_off,sizeof(phy_off), 1);

	priv->status &= ~STATUS_INIT;
}


inline void darwin_iwi4965::ipw_disable_interrupts(struct ipw_priv *priv)
{
	if (!(priv->status & STATUS_INT_ENABLED))
		return;
	priv->status &= ~STATUS_INT_ENABLED;
	ipw_write32(CSR_INT_MASK, 0x00000000);
	ipw_write32(CSR_INT, CSR_INI_SET_MASK);
	ipw_write32( CSR_FH_INT_STATUS, 0xff);
	ipw_write32( CSR_FH_INT_STATUS, 0x00070000);

}

void darwin_iwi4965::ipw_down(struct ipw_priv *priv)
{
	unsigned long flags;
	int exit_pending = priv->status & STATUS_EXIT_PENDING;
	struct ieee80211_conf *conf = NULL;

	IOLog("ipw going down \n");

	conf = ieee80211_get_hw_conf(priv->ieee);

	priv->status |= STATUS_EXIT_PENDING;

	/* If we are coming down due to a microcode error, then
	 * don't bother trying to do anything that results in sending
	 * host commands... */
	if (!(priv->status & STATUS_FW_ERROR) && ipw_is_alive(priv)) {

		/*ipw_update_link_led(priv);
		ipw_update_activity_led(priv);
		ipw_update_tech_led(priv);*/
	}

	ipw_clear_stations_table(priv);

	/* Cancel any pending scheduled work */
	//ipw_cancel_deferred_work(priv);

	/* Unblock any waiting calls */
	//wake_up_interruptible_all(&priv->wait_command_queue);

	/* Wipe out the EXIT_PENDING status bit if we are not actually
	 * exiting the module */
	if (!exit_pending)
		priv->status &= ~STATUS_EXIT_PENDING;

	/* tell the device to stop sending interrupts */
	ipw_write32(CSR_RESET, CSR_RESET_REG_FLAG_NEVO_RESET);
	ipw_disable_interrupts(priv);

	if (priv->netdev_registered) {
		setLinkStatus(kIONetworkLinkValid);
		fTransmitQueue->stop();
		fTransmitQueue->setCapacity(0);
		fTransmitQueue->flush();
		//netif_carrier_off(priv->net_dev);
		//ieee80211_stop_queues(priv->ieee);
	}

	/* If we have not previously called ipw_init() then
	 * clear all bits but the RF Kill and SUSPEND bits and return */
	if (!ipw_is_init(priv)) {
		priv->status &= (STATUS_RF_KILL_MASK | STATUS_IN_SUSPEND);
		goto exit;
	}

	/* ...otherwise clear out all the status bits but the RF Kill and
	 * SUSPEND bits and continue taking the NIC down. */
	priv->status &= (STATUS_RF_KILL_MASK | STATUS_IN_SUSPEND);

	//spin_lock_irqsave(&priv->lock, flags);
	ipw_clear_bit( CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
	//spin_unlock_irqrestore(&priv->lock, flags);

	//ipw_stop_tx_queue(priv);
	ipw_tx_queue_free(priv);
	//ipw_rxq_stop(priv);
	ipw3945_rxq_stop(priv);

	//spin_lock_irqsave(&priv->lock, flags);
	if (!ipw_grab_restricted_access(priv)) {
		_ipw_write_restricted_reg(priv, ALM_APMG_CLK_DIS,
					 APMG_CLK_REG_VAL_DMA_CLK_RQT);
		_ipw_release_restricted_access(priv);
	}
	//spin_unlock_irqrestore(&priv->lock, flags);

	udelay(5);

	ipw_nic_stop_master(priv);

	//spin_lock_irqsave(&priv->lock, flags);
	ipw_set_bit( CSR_RESET, CSR_RESET_REG_FLAG_SW_RESET);
	//spin_unlock_irqrestore(&priv->lock, flags);

	ipw_nic_reset(priv);

      exit:
	memset(&priv->card_alive, 0, sizeof(struct ipw_alive_resp));

	//if (priv->ibss_beacon)
	//	//freePacket(priv->ibss_beacon);
	//priv->ibss_beacon = NULL;

	if (priv->scan) {
		kfree(priv->scan);
		priv->scan = NULL;
	}

	/* clear out any free frames */
	ipw_clear_free_frames(priv);
}

void darwin_iwi4965::ipw_clear_free_frames(struct ipw_priv *priv)
{
	struct list_head *element;

	IOLog("%d frames on pre-allocated heap on clear.\n",
		       priv->frames_count);

	while (!list_empty(&priv->free_frames)) {
		element = priv->free_frames.next;
		list_del(element);
		kfree(list_entry(element, struct ipw_frame, list));
		priv->frames_count--;
	}

	if (priv->frames_count) {
		IOLog
		    ("%d frames still in use.  Did we lose one?\n",
		     priv->frames_count);
		priv->frames_count = 0;
	}
}

int darwin_iwi4965::ipw3945_rxq_stop(struct ipw_priv *priv)
{
	int rc;
	unsigned long flags;

	//spin_lock_irqsave(&priv->lock, flags);
	rc = ipw_grab_restricted_access(priv);
	if (rc) {
		//spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}

	_ipw_write_restricted(priv, FH_RCSR_CONFIG(0), 0);
	rc = ipw_poll_restricted_bit(priv, FH_RSSR_STATUS, (1 << 24), 1000);
	if (rc < 0)
		IOLog("Can't stop Rx DMA.\n");

	_ipw_release_restricted_access(priv);
	//spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

void darwin_iwi4965::ipw_led_radio_off(struct ipw_priv *priv)
{
	ipw_led_activity_off(priv);
	ipw_led_link_off(priv);
}

void darwin_iwi4965::interruptOccurred(OSObject * owner, 
	//IOInterruptEventSource * src, int /*count*/) 
	void		*src,  IOService *nub, int source)
{
	darwin_iwi4965 *self = OSDynamicCast(darwin_iwi4965, owner); //(darwin_iwi4965 *)owner;
	self->handleInterrupt();
}

void darwin_iwi4965::ipw_irq_handle_error(struct ipw_priv *priv)
{
	/* Set the FW error flag -- cleared on ipw_down */
	priv->status |= STATUS_FW_ERROR;

	/* Cancel currently queued command. */
	priv->status &= ~STATUS_HCMD_ACTIVE;

	/*if (ipw_debug_level & IPW_DL_FW_ERRORS) {
		ipw_dump_nic_error_log(priv);
		ipw_dump_nic_event_log(priv);
		ipw_print_rx_config_cmd(&priv->active_rxon);
	}*/

	//wake_up_interruptible(&priv->wait_command_queue);

	/* Keep the restart process from trying to send host
	 * commands by clearing the INIT status bit */
	priv->status &= ~STATUS_READY;
	if (!(priv->status & STATUS_EXIT_PENDING)) {
		IOLog( "Restarting adapter due to uCode error.\n");
		queue_te(12,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_down),priv,NULL,true);
		//queue_work(priv->workqueue, &priv->down);
	}
}

int darwin_iwi4965::ipw3945_rx_queue_update_wr_ptr(struct ipw_priv *priv,
					  struct ipw_rx_queue *q)
{
	u32 reg = 0;
	int rc = 0;
	unsigned long flags;

	//spin_lock_irqsave(&q->lock, flags);

	if (q->need_update == 0)
		goto exit_unlock;

	if (priv->status & STATUS_POWER_PMI) {
		reg = ipw_read32(CSR_UCODE_DRV_GP1);

		if (reg & CSR_UCODE_DRV_GP1_BIT_MAC_SLEEP) {
			ipw_set_bit( CSR_GP_CNTRL,
				    CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
			goto exit_unlock;
		}

		rc = ipw_grab_restricted_access(priv);
		if (rc)
			goto exit_unlock;

		_ipw_write_restricted(priv, FH_RCSR_WPTR(0), q->write & ~0x7);
		_ipw_release_restricted_access(priv);
	} else {
		ipw_write32( FH_RCSR_WPTR(0), q->write & ~0x7);
	}

	q->need_update = 0;

      exit_unlock:
	//spin_unlock_irqrestore(&q->lock, flags);
	return rc;
}

int darwin_iwi4965::ipw_tx_queue_update_write_ptr(struct ipw_priv *priv,
					 struct ipw_tx_queue *txq, int tx_id)
{
	u32 reg = 0;
	int rc = 0;

	if (txq->need_update == 0)
		return rc;

	if (priv->status & STATUS_POWER_PMI) {
		reg = ipw_read32( CSR_UCODE_DRV_GP1);

		if (reg & CSR_UCODE_DRV_GP1_BIT_MAC_SLEEP) {
			ipw_set_bit( CSR_GP_CNTRL,
				    CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
			return rc;
		}

		rc = ipw_grab_restricted_access(priv);
		if (rc)
			return rc;
		_ipw_write_restricted(priv, HBUS_TARG_WRPTR,
				     txq->q.first_empty | (tx_id << 8));
		_ipw_release_restricted_access(priv);
	} else {
		ipw_write32( HBUS_TARG_WRPTR,
			    txq->q.first_empty | (tx_id << 8));
	}

	txq->need_update = 0;

	return rc;
}

UInt32 darwin_iwi4965::handleInterrupt(void)
{
	u32 inta, inta_mask;
	if (!priv)
		return false;

	//spin_lock(&priv->lock);
	if (!(priv->status & STATUS_INT_ENABLED)) {
		/* Shared IRQ */
		return false;
	}

	inta = ipw_read32( CSR_INT);
	inta_mask = ipw_read32( CSR_INT_MASK);
	if (inta == 0xFFFFFFFF) {
		/* Hardware disappeared */
		//IOLog("IRQ INTA == 0xFFFFFFFF\n");
		return false;
	}

	if (!(inta & (CSR_INI_SET_MASK & inta_mask))) {
		if (inta)
			ipw_write32( CSR_INT, inta);
		/* Shared interrupt */
		return false;
	}

	/* tell the device to stop sending interrupts */

	IOLog
	    ("interrupt recieved 0x%08x masked 0x%08x card mask 0x%08x\n",
	     inta, inta_mask, CSR_INI_SET_MASK);

	priv->status &= ~STATUS_INT_ENABLED;
	ipw_write32( CSR_INT_MASK, 0x00000000);
	/* ack current interrupts */
	ipw_write32( CSR_INT, inta);
	inta &= (CSR_INI_SET_MASK & inta_mask);
	/* Cache INTA value for our tasklet */
	priv->isr_inta = inta;
	
	UInt32  handled = 0;
	//unsigned long flags;

	//spin_lock_irqsave(&priv->lock, flags);

	inta = ipw_read32( CSR_INT);
	inta_mask = ipw_read32( CSR_INT_MASK);
	ipw_write32( CSR_INT, inta);
	inta &= (CSR_INI_SET_MASK & inta_mask);

	/* Add any cached INTA values that need to be handled */
	inta |= priv->isr_inta;

	if (inta & BIT_INT_ERR) {
		IOLog("Microcode HW error detected.  Restarting.\n");

		/* tell the device to stop sending interrupts */
		ipw_disable_interrupts(priv);

		ipw_irq_handle_error(priv);

		handled |= BIT_INT_ERR;

		//spin_unlock_irqrestore(&priv->lock, flags);

		return 0;
	}

	if (inta & BIT_INT_SWERROR) {
		IOLog("Microcode SW error detected.  Restarting 0x%X.\n",
			  inta);
		ipw_irq_handle_error(priv);
		handled |= BIT_INT_SWERROR;
	}

	if (inta & BIT_INT_WAKEUP) {
		IOLog("Wakeup interrupt\n");
		ipw_rx_queue_update_write_ptr(priv, priv->rxq);
		ipw_tx_queue_update_write_ptr(priv, &priv->txq[0], 0);
		ipw_tx_queue_update_write_ptr(priv, &priv->txq[1], 1);
		ipw_tx_queue_update_write_ptr(priv, &priv->txq[2], 2);
		ipw_tx_queue_update_write_ptr(priv, &priv->txq[3], 3);
		ipw_tx_queue_update_write_ptr(priv, &priv->txq[4], 4);
		ipw_tx_queue_update_write_ptr(priv, &priv->txq[5], 5);


		handled |= BIT_INT_WAKEUP;
	}

	if (inta & BIT_INT_ALIVE) {
		IOLog("Alive interrupt\n");
		handled |= BIT_INT_ALIVE;
	}

	/* handle all the justifications for the interrupt */
	if (inta & BIT_INT_RX) {
		IOLog("Rx interrupt\n");
		//ipw_rx_handle(priv);
		RxQueueIntr();
		handled |= BIT_INT_RX;
	}

	if (inta & BIT_INT_TX) {
		IOLog("Command completed.\n");
		ipw_write32( CSR_FH_INT_STATUS, (1 << 6));
		if (!ipw_grab_restricted_access(priv)) {
			_ipw_write_restricted(priv,
					     FH_TCSR_CREDIT
					     (ALM_FH_SRVC_CHNL), 0x0);
			_ipw_release_restricted_access(priv);
		}

		handled |= BIT_INT_TX;
	}

	if (handled != inta) {
		IOLog("Unhandled INTA bits 0x%08x\n", inta & ~handled);
	}

	/* enable all interrupts */
	ipw_enable_interrupts(priv);

	//spin_unlock_irqrestore(&priv->lock, flags);
}


UInt16 darwin_iwi4965::readPromWord(UInt16 *base, UInt8 addr)
{
	UInt32 tmp;
	UInt16 val;
	int n;
	
	/* clock C once before the first command */
	IWI_EEPROM_CTL(base, 0);
	IWI_EEPROM_CTL(base, IWI_EEPROM_S);
	IWI_EEPROM_CTL(base, IWI_EEPROM_S | IWI_EEPROM_C);
	IWI_EEPROM_CTL(base, IWI_EEPROM_S);

	/* write start bit (1) */
	IWI_EEPROM_CTL(base, IWI_EEPROM_S | IWI_EEPROM_D);
	IWI_EEPROM_CTL(base, IWI_EEPROM_S | IWI_EEPROM_D | IWI_EEPROM_C);

	/* write READ opcode (10) */
	IWI_EEPROM_CTL(base, IWI_EEPROM_S | IWI_EEPROM_D);
	IWI_EEPROM_CTL(base, IWI_EEPROM_S | IWI_EEPROM_D | IWI_EEPROM_C);
	IWI_EEPROM_CTL(base, IWI_EEPROM_S);
	IWI_EEPROM_CTL(base, IWI_EEPROM_S | IWI_EEPROM_C);


	for (n = 7; n >= 0; n--) {
		IWI_EEPROM_CTL(base, IWI_EEPROM_S |
		    (((addr >> n) & 1) << IWI_EEPROM_SHIFT_D));
		IWI_EEPROM_CTL(base, IWI_EEPROM_S |
		    (((addr >> n) & 1) << IWI_EEPROM_SHIFT_D) | IWI_EEPROM_C);
	}

	IWI_EEPROM_CTL(base, IWI_EEPROM_S);
	
	/* read data Q15-Q0 */
	val = 0;
	for (n = 15; n >= 0; n--) {
		IWI_EEPROM_CTL(base, IWI_EEPROM_S | IWI_EEPROM_C);
		IWI_EEPROM_CTL(base, IWI_EEPROM_S);
		tmp = MEM_READ_4(base, IWI_MEM_EEPROM_CTL);
		val |= ((tmp & IWI_EEPROM_Q) >> IWI_EEPROM_SHIFT_Q) << n;
	}

	IWI_EEPROM_CTL(base, 0);

	/* clear Chip Select and clock C */
	IWI_EEPROM_CTL(base, IWI_EEPROM_S);
	IWI_EEPROM_CTL(base, 0);
	IWI_EEPROM_CTL(base, IWI_EEPROM_C);

#if defined(__BIG_ENDIAN__)
	return (val);
#else
	return OSSwapInt16(val);
#endif
}


IOReturn darwin_iwi4965::getHardwareAddress( IOEthernetAddress * addr )
{
	UInt16 val;
	if (fEnetAddr.bytes[0]==0 && fEnetAddr.bytes[1]==0 && fEnetAddr.bytes[2]==0
	&& fEnetAddr.bytes[3]==0 && fEnetAddr.bytes[4]==0 && fEnetAddr.bytes[5]==0)
	{
		if (priv) memcpy(fEnetAddr.bytes, priv->eeprom.mac_address, ETH_ALEN);	
		IOLog("getHardwareAddress " MAC_FMT "\n",MAC_ARG(fEnetAddr.bytes));	
	}
	memcpy(addr, &fEnetAddr, sizeof(*addr));
	if (priv)
	{
		memcpy(priv->mac_addr, &fEnetAddr.bytes, ETH_ALEN);
		memcpy(priv->net_dev->dev_addr, &fEnetAddr.bytes, ETH_ALEN);
		//memcpy(priv->ieee->dev->dev_addr, &fEnetAddr.bytes, ETH_ALEN);
		//IOLog("getHardwareAddress " MAC_FMT "\n",MAC_ARG(priv->mac_addr));
	}
	
	return kIOReturnSuccess;
}


void darwin_iwi4965::stopMaster(UInt16 *base) {
	UInt32 tmp;
	int ntries;

	CSR_WRITE_4(base, IWI_CSR_INTR_MASK, 0);

	CSR_WRITE_4(base, IWI_CSR_RST, IWI_RST_STOP_MASTER);
	for (ntries = 0; ntries < 5; ntries++) {
		if (CSR_READ_4(base, IWI_CSR_RST) & IWI_RST_MASTER_DISABLED)
			break;
		IODelay(100);
	}
	if(ntries == 5)
		IOLog("%s timeout waiting for master\n", getName());

	tmp = CSR_READ_4(base, IWI_CSR_RST);
	CSR_WRITE_4(base, IWI_CSR_RST, tmp | IWI_RST_PRINCETON_RESET);
}

void darwin_iwi4965::stopDevice(UInt16 *base)
{
	stopMaster(base);
	
	CSR_WRITE_4(base, IWI_CSR_RST, IWI_RST_SOFT_RESET);
}

bool darwin_iwi4965::resetDevice(UInt16 *base) 
{
	int i;
	UInt32 tmp;

	stopMaster(base);
	
	tmp = CSR_READ_4(base, IWI_CSR_CTL);

	CSR_WRITE_4(base, IWI_CSR_CTL, tmp | IWI_CTL_INIT);

	CSR_WRITE_4(base, IWI_CSR_READ_INT, IWI_READ_INT_INIT_HOST);
	
	for(i=0; i<100; i++) {
		if (CSR_READ_4(base, IWI_CSR_CTL) & IWI_CTL_CLOCK_READY)
			break;
		IODelay(10);
	}

	if(i==100) {
		IOLog("%s timeout waiting for clock stabilization\n", getName());
		//return false;
	}


	tmp = CSR_READ_4(base, IWI_CSR_RST);
	CSR_WRITE_4(base, IWI_CSR_RST, tmp | IWI_RST_SOFT_RESET);
	
	IODelay(10);

	tmp = CSR_READ_4(base, IWI_CSR_CTL);
	CSR_WRITE_4(base, IWI_CSR_CTL, tmp | IWI_CTL_INIT);

	for(i = 0; i < 0xc000; i++)
		CSR_WRITE_4(base, IWI_CSR_AUTOINC_DATA, 0);

	return true;
}


void darwin_iwi4965::ipw_write_reg8(UInt32 reg, UInt8 value)
{
	UInt32 aligned_addr = reg & IPW_INDIRECT_ADDR_MASK;	/* dword align */
	UInt32 dif_len = reg - aligned_addr;

	_ipw_write32(memBase, IPW_INDIRECT_ADDR, aligned_addr);
	_ipw_write8(memBase, IPW_INDIRECT_DATA + dif_len, value);
}

UInt8 darwin_iwi4965::ipw_read_reg8(UInt32 reg)
{
	UInt32 word;
	_ipw_write32(memBase, IPW_INDIRECT_ADDR, reg & IPW_INDIRECT_ADDR_MASK);
	word = _ipw_read32(memBase, IPW_INDIRECT_DATA);
	return (word >> ((reg & 0x3) * 8)) & 0xff;
}

void darwin_iwi4965::ipw_write_reg16(UInt32 reg, UInt16 value)
{
	UInt32 aligned_addr = reg & IPW_INDIRECT_ADDR_MASK;	/* dword align */
	UInt32 dif_len = (reg - aligned_addr) & (~0x1ul);

	_ipw_write32(memBase, IPW_INDIRECT_ADDR, aligned_addr);
	_ipw_write16(memBase, IPW_INDIRECT_DATA + dif_len, value);
	
}

int darwin_iwi4965::ipw_stop_master()
{
}

void darwin_iwi4965::ipw_arc_release()
{
	mdelay(5);

	ipw_clear_bit( IPW_RESET_REG, CBD_RESET_REG_PRINCETON_RESET);

	/* no one knows timing, for safety add some delay */
	mdelay(5);
}

bool darwin_iwi4965::uploadUCode(const unsigned char * data, UInt16 len)
{
	
}



void inline darwin_iwi4965::ipw_write32(UInt32 offset, UInt32 data)
{
	//OSWriteLittleInt32((void*)memBase, offset, data);
	_ipw_write32(memBase, offset, data);
}

UInt32 inline darwin_iwi4965::ipw_read32(UInt32 offset)
{
	//return OSReadLittleInt32((void*)memBase, offset);
	return _ipw_read32(memBase,offset);
}

void inline darwin_iwi4965::ipw_clear_bit(UInt32 reg, UInt32 mask)
{
	ipw_write32(reg, ipw_read32(reg) & ~mask);
}

void inline darwin_iwi4965::ipw_set_bit(UInt32 reg, UInt32 mask)
{
	ipw_write32(reg, ipw_read32(reg) | mask);
}

int darwin_iwi4965::ipw_fw_dma_add_command_block(
					UInt32 src_address,
					UInt32 dest_address,
					UInt32 length,
					int interrupt_enabled, int is_last)
{

	return 0;
}

void darwin_iwi4965::ipw_zero_memory(UInt32 start, UInt32 count)
{
	count >>= 2;
	if (!count)
		return;
	_ipw_write32(memBase,IPW_AUTOINC_ADDR, start);
	while (count--)
		_ipw_write32(memBase,IPW_AUTOINC_DATA, 0);
}

void darwin_iwi4965::ipw_fw_dma_reset_command_blocks()
{

}

void darwin_iwi4965::ipw_write_reg32( UInt32 reg, UInt32 value)
{
	_ipw_write32(memBase,IPW_INDIRECT_ADDR, reg);
	_ipw_write32(memBase,IPW_INDIRECT_DATA, value);
}

int darwin_iwi4965::ipw_fw_dma_enable()
{				/* start dma engine but no transfers yet */

	ipw_fw_dma_reset_command_blocks();
	ipw_write_reg32(IPW_DMA_I_CB_BASE, IPW_SHARED_SRAM_DMA_CONTROL);
	return 0;
}

void darwin_iwi4965::ipw_write_indirect(UInt32 addr, UInt8 * buf,
				int num)
{
	UInt32 aligned_addr = addr & IPW_INDIRECT_ADDR_MASK;	/* dword align */
	UInt32 dif_len = addr - aligned_addr;
	UInt32 i;


	if (num <= 0) {
		return;
	}

	/* Write the first dword (or portion) byte by byte */
	if (unlikely(dif_len)) {
		_ipw_write32(memBase,IPW_INDIRECT_ADDR, aligned_addr);
		/* Start writing at aligned_addr + dif_len */
		for (i = dif_len; ((i < 4) && (num > 0)); i++, num--, buf++)
			_ipw_write8(memBase, IPW_INDIRECT_DATA + i, *buf);
		aligned_addr += 4;
	}

	/* Write all of the middle dwords as dwords, with auto-increment */
	_ipw_write32(memBase, IPW_AUTOINC_ADDR, aligned_addr);
	for (; num >= 4; buf += 4, aligned_addr += 4, num -= 4)
		_ipw_write32(memBase, IPW_AUTOINC_DATA, *(UInt32 *) buf);

	/* Write the last dword (or portion) byte by byte */
	if (unlikely(num)) {
		_ipw_write32(memBase,IPW_INDIRECT_ADDR, aligned_addr);
		for (i = 0; num > 0; i++, num--, buf++)
			_ipw_write8(memBase, IPW_INDIRECT_DATA + i, *buf);
	}
}


int darwin_iwi4965::ipw_fw_dma_add_buffer(UInt32 src_phys, UInt32 dest_address, UInt32 length)
{
	UInt32 bytes_left = length;
	UInt32 src_offset = 0;
	UInt32 dest_offset = 0;
	int status = 0;

	while (bytes_left > CB_MAX_LENGTH) {
		status = ipw_fw_dma_add_command_block(
						      src_phys + src_offset,
						      dest_address +
						      dest_offset,
						      CB_MAX_LENGTH, 0, 0);
		if (status) {
			return -1;
		};

		src_offset += CB_MAX_LENGTH;
		dest_offset += CB_MAX_LENGTH;
		bytes_left -= CB_MAX_LENGTH;
	}

	/* add the buffer tail */
	if (bytes_left > 0) {
		status =
		    ipw_fw_dma_add_command_block( src_phys + src_offset,
						 dest_address + dest_offset,
						 bytes_left, 0, 0);
		if (status) {
			return -1;
		};
	}

	return 0;
}

int darwin_iwi4965::ipw_fw_dma_write_command_block(int index,
					  struct command_block *cb)
{
		return 0;

}

int darwin_iwi4965::ipw_fw_dma_kick()
{
	
	return 0;
}

UInt32 darwin_iwi4965::ipw_read_reg32( UInt32 reg)
{
	UInt32 value;


	_ipw_write32(memBase, IPW_INDIRECT_ADDR, reg);
	value = _ipw_read32(memBase, IPW_INDIRECT_DATA);
	return value;
}

int darwin_iwi4965::ipw_fw_dma_command_block_index()
{

}

void darwin_iwi4965::ipw_fw_dma_dump_command_block()
{
	UInt32 address;
	UInt32 register_value = 0;
	UInt32 cb_fields_address = 0;

	address = ipw_read_reg32(IPW_DMA_I_CURRENT_CB);

	/* Read the DMA Controlor register */
	register_value = ipw_read_reg32(IPW_DMA_I_DMA_CONTROL);

	/* Print the CB values */
	cb_fields_address = address;
	register_value = ipw_read_reg32( cb_fields_address);

	cb_fields_address += sizeof(UInt32);
	register_value = ipw_read_reg32( cb_fields_address);

	cb_fields_address += sizeof(UInt32);
	register_value = ipw_read_reg32( cb_fields_address);

	cb_fields_address += sizeof(UInt32);
	register_value = ipw_read_reg32( cb_fields_address);

}

void darwin_iwi4965::ipw_fw_dma_abort()
{

}

int darwin_iwi4965::ipw_fw_dma_wait()
{
	
}


bool darwin_iwi4965::uploadFirmware(u8 * data, size_t len)
{	
	
}

bool darwin_iwi4965::uploadUCode2(UInt16 *base, const unsigned char *uc, UInt16 size, int offset)
{
	
}


bool darwin_iwi4965::uploadFirmware2(UInt16 *base, const unsigned char *fw, UInt32 size, int offset)
{	
	dma_addr_t physAddr, src;
	UInt8 *virtAddr, *p, *end;
	UInt32 dst, len, mlen, ctl, sum, sentinel, tmp, ntries;
	IOBufferMemoryDescriptor *memD;
	size -= offset;
	fw += offset;
	
	memD = MemoryDmaAlloc(size, &physAddr, &virtAddr);
	if(!memD) 
		IOLog("%s: dma_mem_alloc failer\n", getName());
//	XXX	bus_dmamap_sync(dmat, map, BUS_DMASYNC_PREWRITE); 
	memcpy(virtAddr, fw, size);
	
	// tell the adapter where the command blocks are stored 
	MEM_WRITE_4(base, 0x3000a0, 0x27000);

	/*
	 * Store command blocks into adapter's internal memory using register
	 * indirections. The adapter will read the firmware image through DMA
	 * using information stored in command blocks.
	 */
	src = physAddr;
	p = virtAddr;
	end = p + size;

	CSR_WRITE_4(base, IWI_CSR_AUTOINC_ADDR, 0x27000);

	while (p < end)
	{
		dst = GETLE32(p); p += 4; src += 4;
		len = GETLE32(p); p += 4; src += 4;
		p += len;

	//	IOLog("dst: 0x%8x    len: 0x%8x\n",dst,len);
		while (len > 0)
		{
			mlen = min(len, IWI_CB_MAXDATALEN);

			ctl = IWI_CB_DEFAULT_CTL | mlen;
			sum = ctl ^ src ^ dst;

			// write a command block
			CSR_WRITE_4(base, IWI_CSR_AUTOINC_DATA, ctl);
			CSR_WRITE_4(base, IWI_CSR_AUTOINC_DATA, src);
			CSR_WRITE_4(base, IWI_CSR_AUTOINC_DATA, dst);
			CSR_WRITE_4(base, IWI_CSR_AUTOINC_DATA, sum);

			src += mlen;
			dst += mlen;
			len -= mlen;
		}
	}

	// write a fictive final command block (sentinel)
	sentinel = CSR_READ_4(base, IWI_CSR_AUTOINC_ADDR);
	CSR_WRITE_4(base, IWI_CSR_AUTOINC_DATA, 0);


	tmp = CSR_READ_4(base, IWI_CSR_RST);
	tmp &= ~(IWI_RST_MASTER_DISABLED | IWI_RST_STOP_MASTER);
	CSR_WRITE_4(base, IWI_CSR_RST, tmp);

	// tell the adapter to start processing command blocks
	MEM_WRITE_4(base, 0x3000a4, 0x540100);

	// wait until the adapter reach the sentinel 
	for (ntries = 0; ntries < 400; ntries++) {
		if (MEM_READ_4(base, 0x3000d0) >= sentinel)
			break;
		IODelay(100*100);
	}
	
	if (ntries == 400) {
		IOLog("timeout processing command blocks\n");
		return false;
	}
	
	// we're done with command blocks processing 
	MEM_WRITE_4(base, 0x3000a4, 0x540c00);
  
  
/*
	// allow interrupts so we know when the firmware is inited 
	CSR_WRITE_4(base, IWI_CSR_INTR_MASK, IWI_INTR_MASK);

	// tell the adapter to initialize the firmware
	CSR_WRITE_4(base, IWI_CSR_RST, 0);

	tmp = CSR_READ_4(base, IWI_CSR_CTL);
	CSR_WRITE_4(base, IWI_CSR_CTL, tmp | IWI_CTL_ALLOW_STANDBY);
	for(ntries = 0; ntries < 50; ntries++) {
		if(handleInterrupt() == IWI_INTR_FW_INITED)
			break;  
		IODelay(1000);
	}       
	if(ntries == 50) {
		memD->release();
		return false;
	}*/
	memD->release();
	return true;
}


int darwin_iwi4965::ipw_get_fw(const struct firmware **fw, const char *name)
{
		
}

IOBufferMemoryDescriptor*
darwin_iwi4965::MemoryDmaAlloc(UInt32 buf_size, dma_addr_t *phys_add, void *virt_add)
{
	IOBufferMemoryDescriptor *memBuffer;
	void *virt_address;
	dma_addr_t phys_address;
	IOMemoryMap *memMap;
	
	memBuffer = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
						kIODirectionOutIn | kIOMemoryPhysicallyContiguous | \
						kIOMemoryAutoPrepare | kIOMapInhibitCache, buf_size, \
						PAGE_SIZE);

	if (memBuffer == NULL) {
		IOLog("Memory Allocation failed - RLC");

		return NULL;
	}

	memMap = memBuffer->map();

	if (memMap == NULL) {
		IOLog("mapping failed\n");
		memBuffer->release();
		memBuffer = NULL;
		
		return NULL;	
	}

	phys_address = memMap->getPhysicalAddress();

	virt_address = (void *)memMap->getVirtualAddress();

	if (virt_address == NULL || phys_address == NULL) {
		memMap->release();
		memBuffer->release();
		memBuffer = NULL;
		
		return NULL;
	}

	*phys_add = phys_address;
	*(IOVirtualAddress*)virt_add = (IOVirtualAddress)virt_address;
	memMap->release();

	return memBuffer;
}


int darwin_iwi4965::sendCommand(UInt8 type,void *data,UInt8 len,bool async)
{

	
	struct iwi_cmd_desc *desc;
	priv->status |= STATUS_HCMD_ACTIVE;
	
	desc = &this->cmdq.desc[cmdq.cur];
	desc->hdr.type = IWI_HDR_TYPE_COMMAND;
	desc->hdr.flags = IWI_HDR_FLAG_IRQ;
	desc->type = type;
	desc->len = len;
	memcpy(desc->data, data, len);
	
//	bus_dmamap_sync(sc->cmdq.desc_dmat, sc->cmdq.desc_map,
//	    BUS_DMASYNC_PREWRITE);

//	IOLog("sending command idx=%u type=%u len=%u\n", cmdq.cur, type, len);

	cmdq.cur = (cmdq.cur + 1) % IWI_CMD_RING_COUNT;
	CSR_WRITE_4(memBase, IWI_CSR_CMD_WIDX, cmdq.cur);
	
	int r=0;
	if (async) 
	while (priv->status & STATUS_HCMD_ACTIVE) 
	{
		r++;
		IODelay(HZ);
		if (r==HZ) break;
	}	
//	return async ? 0 : msleep(sc, &sc->sc_mtx, 0, "iwicmd", hz);
	return 0;
}

const struct ieee80211_geo* darwin_iwi4965::ipw_get_geo(struct ieee80211_device *ieee)
{
	return &ieee->geo;
}

int darwin_iwi4965::ipw_set_tx_power(struct ipw_priv *priv)
{

}

void darwin_iwi4965::init_sys_config(struct ipw_sys_config *sys_config)
{
	
}

void darwin_iwi4965::ipw_add_cck_scan_rates(struct ipw_supported_rates *rates,
				   u8 modulation, u32 rate_mask)
{
	u8 basic_mask = (IEEE80211_OFDM_MODULATION == modulation) ?
	    IEEE80211_BASIC_RATE_MASK : 0;

	if (rate_mask & IEEE80211_CCK_RATE_1MB_MASK)
		rates->supported_rates[rates->num_rates++] =
		    IEEE80211_BASIC_RATE_MASK | IEEE80211_CCK_RATE_1MB;

	if (rate_mask & IEEE80211_CCK_RATE_2MB_MASK)
		rates->supported_rates[rates->num_rates++] =
		    IEEE80211_BASIC_RATE_MASK | IEEE80211_CCK_RATE_2MB;

	if (rate_mask & IEEE80211_CCK_RATE_5MB_MASK)
		rates->supported_rates[rates->num_rates++] = basic_mask |
		    IEEE80211_CCK_RATE_5MB;

	if (rate_mask & IEEE80211_CCK_RATE_11MB_MASK)
		rates->supported_rates[rates->num_rates++] = basic_mask |
		    IEEE80211_CCK_RATE_11MB;
}

void darwin_iwi4965::ipw_add_ofdm_scan_rates(struct ipw_supported_rates *rates,
				    u8 modulation, u32 rate_mask)
{
	u8 basic_mask = (IEEE80211_OFDM_MODULATION == modulation) ?
	    IEEE80211_BASIC_RATE_MASK : 0;

	if (rate_mask & IEEE80211_OFDM_RATE_6MB_MASK)
		rates->supported_rates[rates->num_rates++] = basic_mask |
		    IEEE80211_OFDM_RATE_6MB;

	if (rate_mask & IEEE80211_OFDM_RATE_9MB_MASK)
		rates->supported_rates[rates->num_rates++] =
		    IEEE80211_OFDM_RATE_9MB;

	if (rate_mask & IEEE80211_OFDM_RATE_12MB_MASK)
		rates->supported_rates[rates->num_rates++] = basic_mask |
		    IEEE80211_OFDM_RATE_12MB;

	if (rate_mask & IEEE80211_OFDM_RATE_18MB_MASK)
		rates->supported_rates[rates->num_rates++] =
		    IEEE80211_OFDM_RATE_18MB;

	if (rate_mask & IEEE80211_OFDM_RATE_24MB_MASK)
		rates->supported_rates[rates->num_rates++] = basic_mask |
		    IEEE80211_OFDM_RATE_24MB;

	if (rate_mask & IEEE80211_OFDM_RATE_36MB_MASK)
		rates->supported_rates[rates->num_rates++] =
		    IEEE80211_OFDM_RATE_36MB;

	if (rate_mask & IEEE80211_OFDM_RATE_48MB_MASK)
		rates->supported_rates[rates->num_rates++] =
		    IEEE80211_OFDM_RATE_48MB;

	if (rate_mask & IEEE80211_OFDM_RATE_54MB_MASK)
		rates->supported_rates[rates->num_rates++] =
		    IEEE80211_OFDM_RATE_54MB;
}

int darwin_iwi4965::init_supported_rates(struct ipw_priv *priv,
				struct ipw_supported_rates *rates)
{

}

void darwin_iwi4965::ipw_send_tgi_tx_key(struct ipw_priv *priv, int type, int index)
{
}

void darwin_iwi4965::ipw_send_wep_keys(struct ipw_priv *priv, int type)
{
	
}

void darwin_iwi4965::ipw_set_hw_decrypt_unicast(struct ipw_priv *priv, int level)
{
	
}

void darwin_iwi4965::ipw_set_hw_decrypt_multicast(struct ipw_priv *priv, int level)
{
	
}

void darwin_iwi4965::ipw_set_hwcrypto_keys(struct ipw_priv *priv)
{
	
}

bool darwin_iwi4965::configureInterface(IONetworkInterface * netif)
 {
    IONetworkData * data;
    IWI_DEBUG("configureInterface\n");
    if (super::configureInterface(netif) == false)
            return false;
    
    // Get the generic network statistics structure.

   data = netif->getParameter(kIONetworkStatsKey);
    if (!data || !(netStats = (IONetworkStats *)data->getBuffer())) {
            return false;
    }

    // Get the Ethernet statistics structure.

    data = netif->getParameter(kIOEthernetStatsKey);
    if (!data || !(etherStats = (IOEthernetStats *)data->getBuffer())) {
            return false;
    }
    return true;

}

int darwin_iwi4965::configu(struct ipw_priv *priv)
{
	
}

u8 darwin_iwi4965::ipw_qos_current_mode(struct ipw_priv *priv)
{

}

u32 darwin_iwi4965::ipw_qos_get_burst_duration(struct ipw_priv *priv)
{
	
}

int darwin_iwi4965::ipw_qos_activate(struct ipw_priv *priv,
			    struct ieee80211_qos_data *qos_network_data)
{
	
}

void darwin_iwi4965::ipw_led_link_on(struct ipw_priv *priv)
{
	
}

void darwin_iwi4965::ipw_led_init(struct ipw_priv *priv)
{
	
}


void darwin_iwi4965::ipw_led_band_on(struct ipw_priv *priv)
{
	
}

int darwin_iwi4965::ipw_channel_to_index(struct ieee80211_device *ieee, u8 channel)
{

}

void darwin_iwi4965::ipw_add_scan_channels(struct ipw_priv *priv,
				  struct ipw_scan_request_ext *scan,
				  int scan_type)
{
	
}

int darwin_iwi4965::ipw_is_ready(struct ipw_priv *priv)
{
	/* The adapter is 'ready' if READY and GEO_CONFIGURED bits are
	 * set but EXIT_PENDING is not */
	return ((priv->status & (STATUS_READY |
				 STATUS_GEO_CONFIGURED |
				 STATUS_EXIT_PENDING)) ==
		(STATUS_READY | STATUS_GEO_CONFIGURED)) ? 1 : 0;
}

int darwin_iwi4965::ipw_is_associated(struct ipw_priv *priv)
{
	return (priv->active_rxon.filter_flags & RXON_FILTER_ASSOC_MSK) ?
		1 : 0;
}

static struct ipw_rate_info rate_table_info[] = {
/*  OFDM rate info   */
	{13, 6 * 2, 0, 24, 44, 52, 44, 228},	/*   6mbps */
	{15, 9 * 2, 1, 36, 36, 44, 36, 160},	/*   9mbps */
	{5, 12 * 2, 2, 48, 32, 36, 32, 124},	/*  12mbps */
	{7, 18 * 2, 3, 72, 28, 32, 28, 92},	/*  18mbps */
	{9, 24 * 2, 4, 96, 28, 32, 28, 72},	/*  24mbps */
	{11, 36 * 2, 5, 144, 24, 28, 24, 56},	/*  36mbps */
	{1, 48 * 2, 6, 192, 24, 24, 24, 48},	/*  48mbps */
	{3, 54 * 2, 7, 216, 24, 24, 24, 44},	/*  54mbps */
/*  CCK rate info   */
	{10, 2, 8, 0, 112, 160, 112, 1216},	/*   1mbps */
	{20, 4, 9, 0, 56, 80, 56, 608},	/*   2mbps */
	{55, 11, 10, 0, 21, 29, 21, 222},	/* 5.5mbps */
	{110, 22, 11, 0, 11, 15, 11, 111},	/*  11mbps */
};



u8 darwin_iwi4965::ipw_rate_index2ieee(int x)
{

	if (x < ARRAY_SIZE(rate_table_info))
		return rate_table_info[x].rate_ieee;

	return IPW_INVALID_RATE;
}

u16 darwin_iwi4965::ipw_supported_rate_to_ie(u8 * ie,
				    u16 supported_rate,
				    u16 basic_rate, int max_count)
{
	u16 ret_rates = 0, bit;
	int i;
	u8 *rates;

	rates = &(ie[1]);

	for (bit = 1, i = 0; i < IPW_MAX_RATES; i++, bit <<= 1) {
		if (bit & supported_rate) {
			ret_rates |= bit;
			rates[*ie] = ipw_rate_index2ieee(i) |
			    ((bit & basic_rate) ? 0x80 : 0x00);
			*ie = *ie + 1;
			if (*ie >= max_count)
				break;
		}
	}

	return ret_rates;
}

static u8 BROADCAST_ADDR[ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

int darwin_iwi4965::ipw_fill_probe_req(struct ipw_priv *priv,
			      struct ieee80211_mgmt *frame,
			      int left, int is_direct)
{
	int len = 0;
	u8 *pos = NULL;
	u16 ret_rates;

	/* Make sure there is enough space for the probe request,
	 * two mandatory IEs and the data */
	left -= 24;
	if (left < 0)
		return 0;
	len += 24;

	frame->frame_control = IEEE80211_STYPE_PROBE_REQ;
	memcpy(frame->da, BROADCAST_ADDR, ETH_ALEN);
	memcpy(frame->sa, priv->mac_addr, ETH_ALEN);
	memcpy(frame->bssid, BROADCAST_ADDR, ETH_ALEN);
	frame->seq_ctrl = 0;

	/* fill in our indirect SSID IE */
	/* ...next IE... */

	left -= 2;
	if (left < 0)
		return 0;
	len += 2;
	pos = &(frame->u.probe_req.variable[0]);
	*pos++ = WLAN_EID_SSID;
	*pos++ = 0;

	/* fill in our direct SSID IE... */
	if (is_direct) {
		/* ...next IE... */
		left -= 2 + priv->essid_len;
		if (left < 0)
			return 0;
		/* ... fill it in... */
		*pos++ = WLAN_EID_SSID;
		*pos++ = priv->essid_len;
		memcpy(pos, priv->essid, priv->essid_len);
		pos += priv->essid_len;
		len += 2 + priv->essid_len;
	}

	/* fill in supported rate */
	/* ...next IE... */
	left -= 2;
	if (left < 0)
		return 0;
	/* ... fill it in... */
	*pos++ = WLAN_EID_SUPP_RATES;
	*pos = 0;
	ret_rates =
	    ipw_supported_rate_to_ie(pos, priv->active_rate,
				     priv->active_rate_basic, left);
	len += 2 + *pos;
	pos += (*pos) + 1;
	ret_rates = ~ret_rates & priv->active_rate;

	if (ret_rates == 0)
		goto fill_end;

	/* fill in supported extended rate */
	/* ...next IE... */
	left -= 2;
	if (left < 0)
		return 0;
	/* ... fill it in... */
	*pos++ = WLAN_EID_EXT_SUPP_RATES;
	*pos = 0;
	ipw_supported_rate_to_ie(pos, ret_rates, priv->active_rate_basic, left);
	if (*pos > 0)
		len += 2 + *pos;
      fill_end:
	return len;
}

struct ieee80211_hw_mode *darwin_iwi4965::ipw_get_hw_mode(struct ipw_priv *priv,
						  int mode)
{
	struct ieee80211_hw_mode *hw_mode;
	struct ieee80211_local *local = hw_to_local(priv->ieee);

	list_for_each_entry(hw_mode, &local->modes_list, list) {
		if (hw_mode->mode == mode)
			return hw_mode;
	}

	return NULL;
}

int darwin_iwi4965::ipw_get_antenna_flags(struct ipw_priv *priv)
{
	switch (priv->antenna) {
	case 0:		/* "diversity", NIC selects best antenna by itself */
		return 0;

	case 1:		/* force Main antenna */
		if (priv->eeprom.antenna_switch_type)
			return RXON_FLG_DIS_DIV_MSK | RXON_FLG_ANT_B_MSK;
		return RXON_FLG_DIS_DIV_MSK | RXON_FLG_ANT_A_MSK;

	case 2:		/* force Aux antenna */
		if (priv->eeprom.antenna_switch_type)
			return RXON_FLG_DIS_DIV_MSK | RXON_FLG_ANT_A_MSK;
		return RXON_FLG_DIS_DIV_MSK | RXON_FLG_ANT_B_MSK;
	}

	/* bad antenna selector value */
	IOLog("Bad antenna selector value (0x%x)\n", priv->antenna);
	return 0;		/* "diversity" is default if error */
}

int darwin_iwi4965::ipw_scan(struct ipw_priv *priv, int type)
{

	struct ipw_host_cmd cmd;// = {
		cmd.id = REPLY_SCAN_CMD;
		cmd.len = sizeof(struct ipw_scan_cmd);
		cmd.meta.flags = CMD_SIZE_HUGE;
	//};
	int rc = 0;
	struct ipw_scan_cmd *scan;
	struct ieee80211_hw_mode *hw_mode = NULL;
	struct ieee80211_conf *conf = NULL;
	u8 direct_mask;
	int phymode;

	conf = ieee80211_get_hw_conf(priv->ieee);

	if (!ipw_is_ready(priv)) {
		IOLog("request scan called when driver not ready.\n");
		//return -1;
	}

	//mutex_lock(&priv->mutex);

	/* This should never be called or scheduled if there is currently
	 * a scan active in the hardware. */
	if (priv->status & STATUS_SCAN_HW) {
		IOLog
		    ("Multiple concurrent scan requests in parallel. "
		     "Ignoring second request.\n");
		//rc = -EIO;
		//goto done;
	}

	if (priv->status & STATUS_EXIT_PENDING) {
		IOLog("Aborting scan due to device shutdown\n");
		priv->status |= STATUS_SCAN_PENDING;
		//goto done;
	}

	if (priv->status & STATUS_SCAN_ABORTING) {
		IOLog("Scan request while abort pending.  Queuing.\n");
		priv->status |= STATUS_SCAN_PENDING;
		//goto done;
	}

	if (priv->status & STATUS_RF_KILL_MASK) {
		IOLog("Aborting scan due to RF Kill activation\n");
		priv->status |= STATUS_SCAN_PENDING;
		//goto done;
	}

	if (!(priv->status & STATUS_READY)) {
		IOLog("Scan request while uninitialized.  Queuing.\n");
		priv->status |= STATUS_SCAN_PENDING;
		goto done;
	}

	if (!priv->scan_bands) {
		IOLog("Aborting scan due to no requested bands.\n");
		//goto done;
	}

	if (!priv->scan) {
		priv->scan = (struct ipw_scan_cmd*)kmalloc(sizeof(struct ipw_scan_cmd) +
				     IPW_MAX_SCAN_SIZE, GFP_ATOMIC);
		if (!priv->scan) {
			rc = -ENOMEM;
			goto done;
		}
	}
	scan = priv->scan;
	memset(scan, 0, sizeof(struct ipw_scan_cmd) + IPW_MAX_SCAN_SIZE);

	scan->quiet_plcp_th = IPW_PLCP_QUIET_THRESH;
	scan->quiet_time = IPW_ACTIVE_QUIET_TIME;

	if (ipw_is_associated(priv)) {
		u16 interval = 1000U;//conf->beacon_int;
		u32 extra;

		IOLog("Scanning while associated...\n");
		scan->suspend_time = 100;
		scan->max_out_time = 600 * 1024;
		if (interval) {
			/*
			 * suspend time format:
			 *  0-19: beacon interval in usec (time before exec.)
			 * 20-23: 0
			 * 24-31: number of beacons (suspend between channels)
			 */

			extra = (scan->suspend_time / interval) << 24;
			scan->suspend_time = 0xFF0FFFFF & (extra |
							   ((scan->
							     suspend_time
							     % interval)
							    * 1024));
		}
	}

	/* We should add the ability for user to lock to PASSIVE ONLY */
	if (priv->one_direct_scan) {
		IOLog
		    ("Kicking off one direct scan for '%s'\n",
		     escape_essid((const char*)priv->direct_ssid, priv->direct_ssid_len));
		scan->direct_scan[0].id = WLAN_EID_SSID;
		scan->direct_scan[0].len = priv->direct_ssid_len;
		memcpy(scan->direct_scan[0].ssid,
		       priv->direct_ssid, priv->direct_ssid_len);
		direct_mask = 1;
	} else if (!ipw_is_associated(priv)) {
		scan->direct_scan[0].id = WLAN_EID_SSID;
		scan->direct_scan[0].len = priv->essid_len;
		memcpy(scan->direct_scan[0].ssid, priv->essid, priv->essid_len);
		direct_mask = 1;
	} else {
		direct_mask = 0;
	}

	/* We don't build a direct scan probe request; the uCode will do
	 * that based on the direct_mask added to each channel entry */
	scan->tx_cmd.len = ipw_fill_probe_req(
		priv,
		(struct ieee80211_mgmt *)scan->data,
		IPW_MAX_SCAN_SIZE - sizeof(scan), 0);
	scan->tx_cmd.tx_flags = TX_CMD_FLG_SEQ_CTL_MSK;
	scan->tx_cmd.sta_id = priv->hw_setting.broadcast_id;
	scan->tx_cmd.u.life_time = TX_CMD_LIFE_TIME_INFINITE;

	/* flags + rate selection */

	switch (priv->scan_bands) {
	case 2: scan->flags = RXON_FLG_BAND_24G_MSK | RXON_FLG_AUTO_DETECT_MSK;
		scan->tx_cmd.rate = R_1M;
		scan->good_CRC_th = 0;
		hw_mode = ipw_get_hw_mode(priv, MODE_IEEE80211G);
		phymode = MODE_IEEE80211G;
		break;

	case 1: scan->tx_cmd.rate = R_6M;
		scan->good_CRC_th = IPW_GOOD_CRC_TH;
		hw_mode = ipw_get_hw_mode(priv, MODE_IEEE80211A);
		phymode = MODE_IEEE80211A;
		break;

	default:
		IOLog("Invalid scan band count\n");
		goto done;
	}

	if (!hw_mode) {
		IOLog("Could not obtain hw_mode in scan.  Aborting.\n");
		goto done;
	}

	scan->flags |= ipw_get_antenna_flags(priv);

	if (priv->iw_mode == IEEE80211_IF_TYPE_MNTR)
		scan->filter_flags = RXON_FILTER_PROMISC_MSK;

	if (direct_mask)
		IOLog
		    ("Initiating direct scan for %s.\n",
		     escape_essid((const char*)priv->essid, priv->essid_len));
	else
		IOLog("Initiating indirect scan.\n");

	scan->channel_count = ipw_get_channels_for_scan(
		priv, phymode, 1 /* active */ , direct_mask,
		(struct ipw_scan_channel*)&scan->data[scan->tx_cmd.len]);

	cmd.len += scan->tx_cmd.len +
	    scan->channel_count * sizeof(struct ipw_scan_channel);
	cmd.data = scan;
	scan->len = cmd.len;

	priv->status |= STATUS_SCAN_HW;

	rc = ipw_send_cmd(priv, &cmd);
	if (rc)
		goto done;

	//queue_delayed_work(priv->workqueue, &priv->scan_check,  IPW_SCAN_CHECK_WATCHDOG);
	queue_te(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan_check),priv,5,false);
	
	priv->status &= ~STATUS_SCAN_PENDING;

	goto done;

      done:
	//if (!rc) ipw_update_link_led(priv);

	return 0;
	//mutex_unlock(&priv->mutex);
		
}

int darwin_iwi4965::is_cmd_sync(struct ipw_host_cmd *cmd)
{
	return !(cmd->meta.flags & CMD_ASYNC);
}

int darwin_iwi4965::is_cmd_small(struct ipw_host_cmd *cmd)
{
	return !(cmd->meta.flags & CMD_SIZE_HUGE);
}

int darwin_iwi4965::ipw_queue_tx_hcmd(struct ipw_priv *priv, struct ipw_host_cmd *cmd)
{
	struct ipw_tx_queue *txq = &priv->txq[priv->hw_setting.cmd_queue_no];
	struct ipw_queue *q = &txq->q;
	u8 *tfd;
	u32 *control_flags;
	struct ipw_cmd *out_cmd;
	u32 idx = 0;
	u16 fix_size = (u16) (cmd->meta.len + sizeof(out_cmd->hdr));
	dma_addr_t phys_addr;
	u8 fifo = priv->hw_setting.cmd_queue_no;
	int rc;
	int pad;
	u16 count;

	/* If any of the command structures end up being larger than
	 * the TFD_MAX_PAYLOAD_SIZE, and it sent as a 'small' command then
	 * we will need to increase the size of the TFD entries */
	if((fix_size > TFD_MAX_PAYLOAD_SIZE)
	       && is_cmd_small(cmd)) return -1;
	if (ipw_queue_space(q) < (is_cmd_sync(cmd) ? 1 : 2)) {
		IOLog("No space for Tx\n");
		return -ENOSPC;
	}
	tfd = &txq->bd[q->first_empty * q->element_size];
	memset(tfd, 0, q->element_size);

	control_flags = (u32 *) tfd;

	idx = get_next_cmd_index(q, q->first_empty,
				 cmd->meta.flags & CMD_SIZE_HUGE);
	out_cmd = &txq->cmd[idx];

	out_cmd->hdr.cmd = cmd->id;
	memcpy(&out_cmd->meta, &cmd->meta, sizeof(cmd->meta));
	memcpy(&out_cmd->cmd.payload, cmd->data, cmd->meta.len);

	/* At this point, the out_cmd now has all of the incoming cmd
	 * information */

	out_cmd->hdr.flags = 0;
	out_cmd->hdr.sequence = FIFO_TO_SEQ(fifo) |
	    INDEX_TO_SEQ(q->first_empty);
	if (out_cmd->meta.flags & CMD_SIZE_HUGE)
		out_cmd->hdr.sequence |= SEQ_HUGE_FRAME;

	phys_addr = txq->dma_addr_cmd + sizeof(txq->cmd[0]) * idx +
	    offsetof(struct ipw_cmd, hdr);

	attach_buffer_to_tfd_frame(tfd, phys_addr, fix_size);

	if (priv->is_3945) {
		pad = U32_PAD(out_cmd->meta.len);
		count = TFD_CTL_COUNT_GET(*control_flags);
		*control_flags = TFD_CTL_COUNT_SET(count) |
		    TFD_CTL_PAD_SET(pad);
	}

	if ((out_cmd->hdr.cmd != 0x23 &&
	     out_cmd->hdr.cmd != 0x24 && out_cmd->hdr.cmd != 0x22)) {
		IPW_DEBUG_HC("Sending command %s (#%x), seq: 0x%04X, "
			     "%d bytes at %d[%d]:%d\n",
			     get_cmd_string(out_cmd->hdr.cmd),
			     out_cmd->hdr.cmd, out_cmd->hdr.sequence,
			     fix_size, q->first_empty, idx, fifo);
		//printk_buf(IPW_DL_HOST_COMMAND, cmd->data, cmd->len);
	}

	txq->need_update = 1;
	/*rc = priv->hw_setting.tx_queue_update_wr_ptr(priv, txq,
						     priv->hw_setting.
						     cmd_queue_no, 0);*/
	q->first_empty = ipw_queue_inc_wrap(q->first_empty, q->n_bd);
	ipw_tx_queue_update_write_ptr(priv, txq, priv->hw_setting.cmd_queue_no);

	//if (rc)
	//	return rc;

	return 0;
}

int darwin_iwi4965::ipw_send_cmd(struct ipw_priv *priv, struct ipw_host_cmd *cmd)
{
	int rc;
	unsigned long flags = 0;

	/* If this is an asynchronous command, and we are in a shutdown
	 * process then don't let it start */
	if (!is_cmd_sync(cmd) && (priv->status & STATUS_EXIT_PENDING))
		return -EBUSY;

	/*
	 * The following BUG_ONs are meant to catch programming API misuse
	 * and not run-time failures due to timing, resource constraint, etc.
	 */

	/* A command can not be asynchronous AND expect an SKB to be set */
	if((cmd->meta.flags & CMD_ASYNC)
	       && (cmd->meta.flags & CMD_WANT_SKB)) return -1;

	/* The skb/callback union must be NULL if an SKB is requested */
	if(cmd->meta.u.skb && (cmd->meta.flags & CMD_WANT_SKB)) return -1;

	/* A command can not be synchronous AND have a callback set */
	if(is_cmd_sync(cmd) && cmd->meta.u.callback) return -1;

	/* An asynchronous command MUST have a callback */
	if((cmd->meta.flags & CMD_ASYNC)
	       && !cmd->meta.u.callback) return -1;

	/* A command can not be synchronous AND not use locks */
	if(is_cmd_sync(cmd) && (cmd->meta.flags & CMD_NO_LOCK)) return -1;

	//if (cmd_needs_lock(cmd))
	//	spin_lock_irqsave(&priv->lock, flags);

	if (is_cmd_sync(cmd) && (priv->status & STATUS_HCMD_ACTIVE)) {
		IOLog("Error sending %s: "
			  "Already sending a host command\n",
			  get_cmd_string(cmd->id));
		//if (cmd_needs_lock(cmd))
		//	spin_unlock_irqrestore(&priv->lock, flags);
		return -EBUSY;
	}

	if (is_cmd_sync(cmd))
		priv->status |= STATUS_HCMD_ACTIVE;

	/* When the SKB is provided in the tasklet, it needs
	 * a backpointer to the originating caller so it can
	 * actually copy the skb there */
	if (cmd->meta.flags & CMD_WANT_SKB)
		cmd->meta.u.source = &cmd->meta;

	cmd->meta.len = cmd->len;

	rc = ipw_queue_tx_hcmd(priv, cmd);
	if (rc) {
		if (is_cmd_sync(cmd))
			priv->status &= ~STATUS_HCMD_ACTIVE;
		//if (cmd_needs_lock(cmd))
		//	spin_unlock_irqrestore(&priv->lock, flags);

		IOLog("Error sending %s: "
			  "ipw_queue_tx_hcmd failed: %d\n",
			  get_cmd_string(cmd->id), rc);

		return -ENOSPC;
	}
	//if (cmd_needs_lock(cmd))
	//	spin_unlock_irqrestore(&priv->lock, flags);

	if (is_cmd_sync(cmd)) {
	
	rc=0;
	while (priv->status & STATUS_HCMD_ACTIVE) 
	{
		rc++;
		IODelay(HZ);
		if (rc==HZ) break;
	}
		rc=0;
		/*if (rc == HZ) {
			//if (cmd_needs_lock(cmd))
			//	spin_lock_irqsave(&priv->lock, flags);

			if (priv->status & STATUS_HCMD_ACTIVE) {
				IOLog("Error sending %s: "
					  "time out after %dms.\n",
					  get_cmd_string(cmd->id),
					  0);
				priv->status &= ~STATUS_HCMD_ACTIVE;
				if ((cmd->meta.flags & CMD_WANT_SKB)
				    && cmd->meta.u.skb) {
					////freePacket(cmd->meta.u.skb);
					cmd->meta.u.skb = NULL;
				}

				//if (cmd_needs_lock(cmd))
				//	spin_unlock_irqrestore(&priv->
				//			       lock, flags);
				//return -ETIMEDOUT;
			}
			rc=0;
			//if (cmd_needs_lock(cmd))
			//	spin_unlock_irqrestore(&priv->lock, flags);
		}*/
	}

	if (priv->status & STATUS_RF_KILL_HW) {
		if ((cmd->meta.flags & CMD_WANT_SKB)
		    && cmd->meta.u.skb) {
			if (!(mbuf_type(cmd->meta.u.skb) == MBUF_TYPE_FREE) ) freePacket(cmd->meta.u.skb);
			cmd->meta.u.skb = NULL;
		}

		IOLog("Command %s aborted: RF KILL Switch\n",
			       get_cmd_string(cmd->id));

		return -ECANCELED;
	}

	if (priv->status & STATUS_FW_ERROR) {
		if ((cmd->meta.flags & CMD_WANT_SKB)
		    && cmd->meta.u.skb) {
			if (!(mbuf_type(cmd->meta.u.skb) == MBUF_TYPE_FREE) ) freePacket(cmd->meta.u.skb);
			cmd->meta.u.skb = NULL;
		}

		IOLog("Command %s failed: FW Error\n",
			       get_cmd_string(cmd->id));

		return -EIO;
	}

	if ((cmd->meta.flags & CMD_WANT_SKB) && !cmd->meta.u.skb) {
		IOLog("Error: Response NULL in '%s'\n",
			  get_cmd_string(cmd->id));
		return -EIO;
	}

	return 0;
}

void darwin_iwi4965::ipw_scan_check(ipw_priv *priv)
{
	if (priv->status & STATUS_EXIT_PENDING)
		return;

	if (priv->status & (STATUS_SCANNING | STATUS_SCAN_ABORTING)) {
		IOLog( 
			  "Scan completion watchdog resetting "
			  "adapter (%dms).\n",
			  0);
		if (!(priv->status & STATUS_EXIT_PENDING))
		queue_te(12,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_down),priv,NULL,true);
	}
}

int darwin_iwi4965::initCmdQueue()
{
	cmdq.count=IWI_CMD_RING_COUNT;
	cmdq.queued=0;
	cmdq.cur=cmdq.next=0;
	
	cmdq.memD = MemoryDmaAlloc(cmdq.count*IWI_CMD_DESC_SIZE, &cmdq.physaddr, &cmdq.desc);
	if(!cmdq.memD || !cmdq.physaddr || !cmdq.desc)
	{ 
		IOLog("dma_mem_alloc failer (initCmdQueue)\n");
		return false;
	}

	return true;
}

int darwin_iwi4965::resetCmdQueue()
{
	cmdq.queued=0;
	cmdq.cur=0;
	cmdq.next=0;
	
	return 0;
}


int darwin_iwi4965::initRxQueue()
{
	struct iwi_rx_data *data;
	rxq.count=IWI_RX_RING_COUNT;
	rxq.cur=0;
	
	rxq.data = IONew(struct iwi_rx_data, IWI_RX_RING_COUNT);
	if(!rxq.data)
	{
		IOLog("failed to allocate RX Queue data\n");
		return false;
	}
	memset(rxq.data, 0, rxq.count*sizeof(struct iwi_rx_data));
	
	for(int i=0; i<rxq.count; i++)
	{
		data=&rxq.data[i];

		dma_addr_t physAddr;
		UInt16 *virtAddr;

		data->memD = MemoryDmaAlloc(10000, &physAddr, &virtAddr);
		/*data->memD = IOBufferMemoryDescriptor::withOptions(
				kIOMemoryPhysicallyContiguous,
				IWI_RX_RING_COUNT, PAGE_SIZE);*/
		if(!data->memD)
		{
			IOLog("failed to alloc rx mem\n");
			return false;
		}

		if(data->memD->prepare() != kIOReturnSuccess) {
			data->memD->release();
			return false;
		}
		
		//data->physaddr = data->memD->getPhysicalSegment(0, 0);
		data->physaddr = (dma_addr_t)physAddr;
		data->m_data = (void *)virtAddr;
		//data->m = allocatePacket(10000); //virtAddr;
		/*if(!data->m) {
			IOLog("alloc failure\n");
			return false;
		}*/
		data->reg = IWI_CSR_RX_BASE + i * 4;
	}
    return true;
}


int darwin_iwi4965::resetRxQueue()
{
	rxq.cur=0;
	return 0;
}

/* 2.4 GHz */
static u8 ipw_eeprom_band_1[] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
};

/* 5.2 Ghz bands */
static u8 ipw_eeprom_band_2[] = {
	183, 184, 185, 187, 188, 189, 192, 196, 7, 8, 11, 12, 16
};

static u8 ipw_eeprom_band_3[] = {	/* 5205-5320MHz */
	34, 36, 38, 40, 42, 44, 46, 48, 52, 56, 60, 64
};

static u8 ipw_eeprom_band_4[] = {	/* 5500-5700MHz */
	100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140
};

static u8 ipw_eeprom_band_5[] = {	/* 5725-5825MHz */
	145, 149, 153, 157, 161, 165
};

void darwin_iwi4965::ipw_init_band_reference(struct ipw_priv *priv, int band,
				    int *eeprom_ch_count,
				    const struct ipw_eeprom_channel
				    **eeprom_ch_info,
				    const u8 ** eeprom_ch_index)
{
	switch (band) {
	case 1:		/* 2.4Ghz band */
		*eeprom_ch_count = ARRAY_SIZE(ipw_eeprom_band_1);
		*eeprom_ch_info = priv->eeprom.band_1_channels;
		*eeprom_ch_index = ipw_eeprom_band_1;
		break;
	case 2:		/* 5.2Ghz band */
		*eeprom_ch_count = ARRAY_SIZE(ipw_eeprom_band_2);
		*eeprom_ch_info = priv->eeprom.band_2_channels;
		*eeprom_ch_index = ipw_eeprom_band_2;
		break;
	case 3:		/* 5.2Ghz band */
		*eeprom_ch_count = ARRAY_SIZE(ipw_eeprom_band_3);
		*eeprom_ch_info = priv->eeprom.band_3_channels;
		*eeprom_ch_index = ipw_eeprom_band_3;
		break;
	case 4:		/* 5.2Ghz band */
		*eeprom_ch_count = ARRAY_SIZE(ipw_eeprom_band_4);
		*eeprom_ch_info = priv->eeprom.band_4_channels;
		*eeprom_ch_index = ipw_eeprom_band_4;
		break;
	case 5:		/* 5.2Ghz band */
		*eeprom_ch_count = ARRAY_SIZE(ipw_eeprom_band_5);
		*eeprom_ch_info = priv->eeprom.band_5_channels;
		*eeprom_ch_index = ipw_eeprom_band_5;
		break;
	default:
		return;
	}
}

int darwin_iwi4965::is_channel_valid(const struct ipw_channel_info *ch_info)
{
	if (ch_info == NULL)
		return 0;
	return (ch_info->flags & IPW_CHANNEL_VALID) ? 1 : 0;
}

u8 darwin_iwi4965::is_channel_a_band(const struct ipw_channel_info *ch_info)
{
	return (ch_info->phymode == MODE_IEEE80211A) ? 1 : 0;
}

int darwin_iwi4965::is_channel_passive(const struct ipw_channel_info *ch)
{
	return (!(ch->flags & IPW_CHANNEL_ACTIVE)) ? 1 : 0;
}

int darwin_iwi4965::is_channel_radar(const struct ipw_channel_info *ch_info)
{
	return (ch_info->flags & IPW_CHANNEL_RADAR) ? 1 : 0;
}



int darwin_iwi4965::ipw_init_channel_map(struct ipw_priv *priv)
{
	int eeprom_ch_count = 0;
	const u8 *eeprom_ch_index = NULL;
	const struct ipw_eeprom_channel *eeprom_ch_info = NULL;
	int b, c;
	struct ipw_channel_info *ch_info = priv->channel_info;
	if (priv->eeprom.version < 0x2f) {
		IOLog("Unsupported EEPROM version: 0x%04X\n",
			    priv->eeprom.version);
		return -EINVAL;
	}
	IOLog("Initializing regulatory info from EEPROM\n");

	priv->channel_count =
	    ARRAY_SIZE(ipw_eeprom_band_1) +
	    ARRAY_SIZE(ipw_eeprom_band_2) +
	    ARRAY_SIZE(ipw_eeprom_band_3) +
	    ARRAY_SIZE(ipw_eeprom_band_4) + ARRAY_SIZE(ipw_eeprom_band_5);

	IOLog("Parsing data for %d channels.\n", priv->channel_count);

	//kfree(priv->channel_info);
	priv->channel_info = (struct ipw_channel_info*)kmalloc(sizeof(struct ipw_channel_info) *
				     priv->channel_count, NULL);
	if (!priv->channel_info)
		return -ENOMEM;

	ch_info = priv->channel_info;

	/* Loop through the 5 EEPROM bands adding them in order to the
	 * channel map we maintain (that contains additional information than
	 * what just in the EEPROM) */
	for (b = 1; b <= 5; b++) {

		ipw_init_band_reference(priv, b, &eeprom_ch_count,
					&eeprom_ch_info, &eeprom_ch_index);

		/* Loop through each band adding each of the channels */
		for (c = 0; c < eeprom_ch_count; c++) {
			ch_info->channel = eeprom_ch_index[c];
			ch_info->phymode = (b == 1) ? MODE_IEEE80211B :
				MODE_IEEE80211A;

			/* permanently store EEPROM's channel regulatory flags
			 *   and max power in channel info database. */
			ch_info->eeprom = eeprom_ch_info[c];

			/* Copy the run-time flags so they are there even on
			 * invalid channels */
			ch_info->flags = eeprom_ch_info[c].flags;

			if (!(is_channel_valid(ch_info))) {
				IOLog("Ch. %d [%sGhz] - No Tx\n",
					       ch_info->channel,
					       is_channel_a_band(ch_info) ?
					       "5.2" : "2.4");
				ch_info++;
				continue;
			}

			/* Initialize regulatory-based run-time data */
			ch_info->max_power_avg = ch_info->curr_txpow =
			    eeprom_ch_info[c].max_power_avg;
			ch_info->scan_power = eeprom_ch_info[c].max_power_avg;
			ch_info->min_power = 0;

			if (is_channel_passive(ch_info) ||
			    is_channel_radar(ch_info)) {
				ch_info->tx_locked = 1;
				ch_info->rx_unlock = 0;
			}

			IOLog("Ch. %d [%sGhz] %s%s%s%s%s%s(" BIT_FMT8
				       " %ddBm): Ad-Hoc %ssupported\n",
				       ch_info->channel,
				       is_channel_a_band(ch_info) ?
				       "5.2" : "2.4",
				       CHECK_AND_PRINT(IBSS),
				       CHECK_AND_PRINT(ACTIVE),
				       CHECK_AND_PRINT(RADAR),
				       CHECK_AND_PRINT(WIDE),
				       CHECK_AND_PRINT(NARROW),
				       CHECK_AND_PRINT(DFS),
				       BIT_ARG8(eeprom_ch_info[c].flags),
				       eeprom_ch_info[c].
				       max_power_avg,
				       ((eeprom_ch_info[c].
					 flags & IPW_CHANNEL_IBSS)
					&& !(eeprom_ch_info[c].
					     flags & IPW_CHANNEL_RADAR))
				       ? "" : "not ");

			/* Set the user_txpower_limit to the highest power
			 * supported by any channel */
			if (eeprom_ch_info[c].max_power_avg >
			    priv->user_txpower_limit)
				priv->user_txpower_limit =
				    eeprom_ch_info[c].max_power_avg;

			ch_info++;
		}
	}

	reg_txpower_set_from_eeprom(priv);

	return 0;
}

int darwin_iwi4965::ipw_get_temperature(struct ipw_priv *priv)
{
	return ipw_read32( CSR_UCODE_DRV_GP2);
}

int darwin_iwi4965::reg_temp_out_of_range(int temperature)
{
	return (((temperature < -260) || (temperature > 25)) ? 1 : 0);
}

int darwin_iwi4965::reg_txpower_get_temperature(struct ipw_priv *priv)
{
	int temperature;

	temperature = ipw_get_temperature(priv);

	/* driver's okay range is -260 to +25.
	 *   human readable okay range is 0 to +285 */
	IWI_DEBUG_FULL("Temperature: %d\n", temperature + 260);

	/* handle insane temp reading */
	if (reg_temp_out_of_range(temperature)) {
		IWI_DEBUG_FULL("Error bad temperature value  %d\n", temperature);

		/* if really really hot(?),
		 *   substitute the 3rd band/group's temp measured at factory */
		if (priv->last_temperature > 100)
			temperature = priv->eeprom.groups[2].temperature;
		else		/* else use most recent "sane" value from driver */
			temperature = priv->last_temperature;
	}

	return temperature;	/* raw, not "human readable" */
}

void darwin_iwi4965::reg_init_channel_groups(struct ipw_priv *priv)
{
	u32 i;
	s32 rate_index;
	const struct ipw_eeprom_txpower_group *group;

	IOLog("Initializing factory calib info from EEPROM\n");

	for (i = 0; i < IPW_NUM_TX_CALIB_GROUPS; i++) {
		s8 *clip_pwrs;	/* table of power levels for each rate */
		s8 satur_pwr;   /* saturation power for each chnl group */
		group = &priv->eeprom.groups[i];

		/* sanity check on factory saturation power value */
		if (group->saturation_power < 40) {
			IOLog("Error: saturation power is %d, "
				    "less than minimum expected 40\n",
				    group->saturation_power);
			return;
		}

		/*
		 * Derive requested power levels for each rate, based on
		 *   hardware capabilities (saturation power for band).
		 * Basic value is 3dB down from saturation, with further
		 *   power reductions for highest 3 data rates.  These
		 *   backoffs provide headroom for high rate modulation
		 *   power peaks, without too much distortion (clipping).
		 */
		/* we'll fill in this array with h/w max power levels */
		clip_pwrs = (s8 *)priv->clip_groups[i].clip_powers;

		/* divide factory saturation power by 2 to find -3dB level */
		satur_pwr = (s8) (group->saturation_power >> 1);

		/* fill in channel group's nominal powers for each rate */
		for (rate_index = 0;
		     rate_index < IPW_MAX_RATES; rate_index++, clip_pwrs++) {
			switch (rate_index) {
			case RATE_SCALE_36M_INDEX:
				if (i == 0) /* B/G */
					*clip_pwrs = satur_pwr;
				else	/* A */
					*clip_pwrs = satur_pwr - 5;
				break;
			case RATE_SCALE_48M_INDEX:
				if (i == 0)
					*clip_pwrs = satur_pwr - 7;
				else
					*clip_pwrs = satur_pwr - 10;
				break;
			case RATE_SCALE_54M_INDEX:
				if (i == 0)
					*clip_pwrs = satur_pwr - 9;
				else
					*clip_pwrs = satur_pwr - 12;
				break;
			default:
				*clip_pwrs = satur_pwr;
				break;
			}
		}
	}
}

u16 darwin_iwi4965::reg_get_chnl_grp_index(struct ipw_priv *priv,
				  const struct ipw_channel_info *ch_info)
{
	struct ipw_eeprom_txpower_group *ch_grp = &priv->eeprom.groups[0];
	u8 group;
	u16 group_index = 0;	/* based on factory calib frequencies */
	u8 grp_channel;

	/* Find the group index for the channel ... don't use index 1(?) */
	if (is_channel_a_band(ch_info)) {
		for (group = 1; group < 5; group++) {
			grp_channel = ch_grp[group].group_channel;
			if (ch_info->channel <= grp_channel) {
				group_index = group;
				break;
			}
		}
		/* group 4 has a few channels *above* its factory cal freq */
		if (group == 5)
			group_index = 4;
	} else
		group_index = 0;	/* 2.4 GHz, group 0 */

	IOLog("Chnl %d mapped to grp %d\n", ch_info->channel,
			group_index);
	return group_index;
}

int darwin_iwi4965::reg_adjust_power_by_temp(int new_reading, int old_reading)
{
	return (new_reading - old_reading) * (-11) / 100;
}



int darwin_iwi4965::reg_get_matched_power_index(struct ipw_priv *priv,
				       s8 requested_power,
				       s32 setting_index, s32 * new_index)
{
	const struct ipw_eeprom_txpower_group *chnl_grp = NULL;
	s32 index0, index1;
	s32 rPower = 2 * requested_power;
	s32 i;
	const struct ipw_eeprom_txpower_sample *samples;
	s32 gains0, gains1;
	s32 res;
	s32 denominator;

	chnl_grp = &priv->eeprom.groups[setting_index];
	samples = chnl_grp->samples;
	for (i = 0; i < 5; i++) {
		if (rPower == samples[i].power) {
			*new_index = samples[i].gain_index;
			return 0;
		}
	}

	if (rPower > samples[1].power) {
		index0 = 0;
		index1 = 1;
	} else if (rPower > samples[2].power) {
		index0 = 1;
		index1 = 2;
	} else if (rPower > samples[3].power) {
		index0 = 2;
		index1 = 3;
	} else {
		index0 = 3;
		index1 = 4;
	}

	denominator = (s32) samples[index1].power - (s32) samples[index0].power;
	if (denominator == 0)
		return -EINVAL;
	gains0 = (s32) samples[index0].gain_index * (1 << 19);
	gains1 = (s32) samples[index1].gain_index * (1 << 19);
	res = gains0 + (gains1 - gains0) *
	    ((s32) rPower - (s32) samples[index0].power) / denominator +
	    (1 << 18);
	*new_index = res >> 19;
	return 0;
}



u8 darwin_iwi4965::reg_fix_power_index(int index)
{
	if (index < 0)
		return 0;
	if (index >= IPW_MAX_GAIN_ENTRIES)
		return IPW_MAX_GAIN_ENTRIES - 1;
	return (u8) index;
}



int darwin_iwi4965::reg_txpower_set_from_eeprom(struct ipw_priv *priv)
{
	struct ipw_channel_info *ch_info = NULL;
	struct ipw_channel_power_info *pwr_info;
	int delta_index;
	u8 rate_index;
	u8 scan_tbl_index;
	const s8 *clip_pwrs; /* array of power levels for each rate */
	u8 gain, dsp_atten;
	s8 power;
	u8 pwr_index, base_pwr_index, a_band;
	u8 i;
	int temperature;

	/* save temperature reference,
	 *   so we can determine next time to calibrate */
	temperature = reg_txpower_get_temperature(priv);
	priv->last_temperature = temperature;

	reg_init_channel_groups(priv);

	/* initialize Tx power info for each and every channel, 2.4 and 5.x */
	for (i = 0, ch_info = priv->channel_info; i < priv->channel_count;
	     i++, ch_info++) {
		a_band = is_channel_a_band(ch_info);
		if (!is_channel_valid(ch_info))
			continue;

		/* find this channel's channel group (*not* "band") index */
		ch_info->group_index = reg_get_chnl_grp_index(priv, ch_info);

		/* Get this chnlgrp's rate->max/clip-powers table */
		clip_pwrs = priv->clip_groups[ch_info->group_index].clip_powers;

		/* calculate power index *adjustment* value according to
		 *   diff between current temperature and factory temperature */
		delta_index = reg_adjust_power_by_temp(temperature,
						       priv->eeprom.
						       groups[ch_info->
							      group_index].
						       temperature);
		IOLog("Delta index for channel %d: %d [%d]\n",
			ch_info->channel, delta_index, temperature + 260);

		/* set tx power value for all OFDM rates */
		for (rate_index = 0; rate_index < IPW_OFDM_RATES; rate_index++) {
			s32 power_idx;
			s32 old_power_idx;
			int rc = 0;

			/* use channel group's clip-power table,
			 *   but don't exceed channel's max power */
			s8 power = min(ch_info->max_power_avg,
				       clip_pwrs[rate_index]);

			pwr_info = &ch_info->power_info[rate_index];

			/* get base (i.e. at factory-measured temperature)
			 *    power table index for this rate's power */
			rc = reg_get_matched_power_index(priv, power,
							 ch_info->group_index,
							 &power_idx);
			if (rc)
				return rc;
			pwr_info->base_power_index = (u8) power_idx;

			/* temperature compensate */
			power_idx += delta_index;
			old_power_idx = power_idx;

			/* stay within range of gain table */
			power_idx = reg_fix_power_index(power_idx);

			/* fill 1 OFDM rate's ipw_channel_power_info struct */
			pwr_info->requested_power = power;
			pwr_info->power_table_index = (u8) power_idx;
			pwr_info->tpc.tx_gain =
			    power_gain_table[a_band][power_idx].tx_gain;
			pwr_info->tpc.dsp_atten =
			    power_gain_table[a_band][power_idx].dsp_atten;
		}

		/* set tx power for CCK rates, based on OFDM 12 Mbit settings */
		pwr_info = &ch_info->power_info[RATE_SCALE_12M_INDEX];
		power = pwr_info->requested_power
		    + IPW_CCK_FROM_OFDM_POWER_DIFF;
		pwr_index = pwr_info->power_table_index
		    + IPW_CCK_FROM_OFDM_INDEX_DIFF;
		base_pwr_index = pwr_info->base_power_index
		    + IPW_CCK_FROM_OFDM_INDEX_DIFF;

		/* stay within table range */
		pwr_index = reg_fix_power_index(pwr_index);
		gain = power_gain_table[a_band][pwr_index].tx_gain;
		dsp_atten = power_gain_table[a_band][pwr_index].dsp_atten;

		/* fill each CCK rate's ipw_channel_power_info structure
		 * NOTE:  All CCK-rate Txpwrs are the same for a given chnl!
		 * NOTE:  CCK rates start at end of OFDM rates! */
		for (rate_index = IPW_OFDM_RATES;
		     rate_index < IPW_MAX_RATES; rate_index++) {
			pwr_info = &ch_info->power_info[rate_index];
			pwr_info->requested_power = power;
			pwr_info->power_table_index = pwr_index;
			pwr_info->base_power_index = base_pwr_index;
			pwr_info->tpc.tx_gain = gain;
			pwr_info->tpc.dsp_atten = dsp_atten;
		}

		/* set scan tx power, 1Mbit for CCK, 6Mbit for OFDM */
		for (scan_tbl_index = 0;
		     scan_tbl_index < IPW_NUM_SCAN_RATES; scan_tbl_index++) {
			s32 actual_index = (scan_tbl_index == 0) ?
			    RATE_SCALE_1M_INDEX : RATE_SCALE_6M_INDEX;
			reg_set_scan_power(priv, scan_tbl_index,
					   actual_index, clip_pwrs,
					   ch_info, a_band);
		}
	}

	return 0;
}

void darwin_iwi4965::reg_set_scan_power(struct ipw_priv *priv, u32 scan_tbl_index,
			       s32 rate_index, const s8 * clip_pwrs,
			       struct ipw_channel_info *ch_info, int band_index)
{
	struct ipw_scan_power_info *scan_power_info;
	s8 power;
	u8 power_index;

	scan_power_info = &ch_info->scan_pwr_info[scan_tbl_index];

	/* use this channel group's 6Mbit clipping/saturation pwr,
	 *   but cap at regulatory scan power restriction (set during init
	 *   based on eeprom channel data) for this channel.  */
	power = min(ch_info->scan_power, clip_pwrs[RATE_SCALE_6M_INDEX]);

	/* further limit to user's max power preference.
	 * FIXME:  Other spectrum management power limitations do not
	 *   seem to apply?? */
	power = min(power, priv->user_txpower_limit);
	scan_power_info->requested_power = power;

	/* find difference between new scan *power* and current "normal"
	 *   Tx *power* for 6Mb.  Use this difference (x2) to adjust the
	 *   current "normal" temperature-compensated Tx power *index* for
	 *   this rate (1Mb or 6Mb) to yield new temp-compensated scan power
	 *   *index*. */
	power_index = ch_info->power_info[rate_index].power_table_index
	    - (power - ch_info->power_info
	       [RATE_SCALE_6M_INDEX].requested_power) * 2;

#if 0
	IPW_DEBUG_POWER("chnl %d scan power index %d\n",
			ch_info->channel, power_index);
#endif

	/* store reference index that we use when adjusting *all* scan
	 *   powers.  So we can accomodate user (all channel) or spectrum
	 *   management (single channel) power changes "between" temperature
	 *   feedback compensation procedures.
	 * don't force fit this reference index into gain table; it may be a
	 *   negative number.  This will help avoid errors when we're at
	 *   the lower bounds (highest gains, for warmest temperatures)
	 *   of the table. */

	/* don't exceed table bounds for "real" setting */
	power_index = reg_fix_power_index(power_index);

	scan_power_info->power_table_index = power_index;
	scan_power_info->tpc.tx_gain =
	    power_gain_table[band_index][power_index].tx_gain;
	scan_power_info->tpc.dsp_atten =
	    power_gain_table[band_index][power_index].dsp_atten;
}



void darwin_iwi4965::ipw_init_hw_rates(struct ipw_priv *priv, struct ieee80211_rate *rates)
{
	/*
	 * Rates initialization.
	 */
	rates[0].rate = 10;
	rates[0].val = RATE_SCALE_1M_PLCP;
	rates[0].flags = IEEE80211_RATE_CCK;
	rates[0].val2 = RATE_SCALE_1M_PLCP;
	rates[0].min_rssi_ack = 0;
	rates[0].min_rssi_ack_delta = 0;

	rates[1].rate = 20;
	rates[1].val = RATE_SCALE_2M_PLCP;
	rates[1].flags = IEEE80211_RATE_CCK_2;
	rates[1].val2 = RATE_SCALE_2M_PLCP;
	rates[1].min_rssi_ack = 0;
	rates[1].min_rssi_ack_delta = 0;

	rates[2].rate = 55;
	rates[2].val = RATE_SCALE_5_5M_PLCP;
	rates[2].flags = IEEE80211_RATE_CCK_2;
	rates[2].val2 = RATE_SCALE_5_5M_PLCP;
	rates[2].min_rssi_ack = 0;
	rates[2].min_rssi_ack_delta = 0;

	rates[3].rate = 110;
	rates[3].val = RATE_SCALE_11M_PLCP;
	rates[3].flags = IEEE80211_RATE_CCK_2;
	rates[3].val2 = RATE_SCALE_11M_PLCP;
	rates[3].min_rssi_ack = 0;
	rates[3].min_rssi_ack_delta = 0;

	rates[4].rate = 60;
	rates[4].val = RATE_SCALE_6M_PLCP;
	rates[4].flags = IEEE80211_RATE_OFDM;
	rates[4].val2 = RATE_SCALE_6M_PLCP;
	rates[4].min_rssi_ack = 0;
	rates[4].min_rssi_ack_delta = 0;

	rates[5].rate = 90;
	rates[5].val = RATE_SCALE_9M_PLCP;
	rates[5].flags = IEEE80211_RATE_OFDM;
	rates[5].val2 = RATE_SCALE_9M_PLCP;
	rates[5].min_rssi_ack = 0;
	rates[5].min_rssi_ack_delta = 0;

	rates[6].rate = 120;
	rates[6].val = RATE_SCALE_12M_PLCP;
	rates[6].flags = IEEE80211_RATE_OFDM;
	rates[6].val2 = RATE_SCALE_12M_PLCP;
	rates[6].min_rssi_ack = 0;
	rates[6].min_rssi_ack_delta = 0;

	rates[7].rate = 180;
	rates[7].val = RATE_SCALE_18M_PLCP;
	rates[7].flags = IEEE80211_RATE_OFDM;
	rates[7].val2 = RATE_SCALE_18M_PLCP;
	rates[7].min_rssi_ack = 0;
	rates[7].min_rssi_ack_delta = 0;

	rates[8].rate = 240;
	rates[8].val = RATE_SCALE_24M_PLCP;
	rates[8].flags = IEEE80211_RATE_OFDM;
	rates[8].val2 = RATE_SCALE_24M_PLCP;
	rates[8].min_rssi_ack = 0;
	rates[8].min_rssi_ack_delta = 0;

	rates[9].rate = 360;
	rates[9].val = RATE_SCALE_36M_PLCP;
	rates[9].flags = IEEE80211_RATE_OFDM;
	rates[9].val2 = RATE_SCALE_36M_PLCP;
	rates[9].min_rssi_ack = 0;
	rates[9].min_rssi_ack_delta = 0;

	rates[10].rate = 480;
	rates[10].val = RATE_SCALE_48M_PLCP;
	rates[10].flags = IEEE80211_RATE_OFDM;
	rates[10].val2 = RATE_SCALE_48M_PLCP;
	rates[10].min_rssi_ack = 0;
	rates[10].min_rssi_ack_delta = 0;

	rates[11].rate = 540;
	rates[11].val = RATE_SCALE_54M_PLCP;
	rates[11].flags = IEEE80211_RATE_OFDM;
	rates[11].val2 = RATE_SCALE_54M_PLCP;
	rates[11].min_rssi_ack = 0;
	rates[11].min_rssi_ack_delta = 0;

	rates[12].rate = 600;
	rates[12].val = RATE_SCALE_54M_PLCP;
	rates[12].flags = IEEE80211_RATE_OFDM;
	rates[12].val2 = RATE_SCALE_54M_PLCP;
	rates[12].min_rssi_ack = 0;
	rates[12].min_rssi_ack_delta = 0;

//	priv->hw_setting.init_hw_rates(priv, rates);
}

struct ipw_channel_info *darwin_iwi4965::ipw_get_channel_info(struct ipw_priv *priv,
						     int phymode, int channel)
{
	int i;

	switch (phymode) {
	case MODE_IEEE80211A:
		for (i = 14; i < priv->channel_count; i++) {
			if (priv->channel_info[i].channel == channel)
				return &priv->channel_info[i];
		}
		break;

	case MODE_IEEE80211B:
	case MODE_IEEE80211G:
		if (channel >= 1 && channel <= 14)
			return &priv->channel_info[channel - 1];
		break;

	}

	return NULL;
}

void darwin_iwi4965::ipw_init_geos(struct ipw_priv *priv)
{
	struct ieee80211_local *local = hw_to_local(priv->ieee);
	struct ipw_channel_info *ch;
	//struct ieee80211_hw_mode *modes;
	//struct ieee80211_channel *channels;
	struct ieee80211_channel *geo_ch;
	//struct ieee80211_rate *rates;
	int i = 0;
	enum {
		A = 0,
		B = 1,
		G = 2,
	};

	if (!list_empty(&local->modes_list))
	{
		IOLog("ipw_init_geos error - fixing\n");
		INIT_LIST_HEAD(&local->modes_list);
		//return;
	}

	modes0 = (struct ieee80211_hw_mode*)kmalloc(sizeof(struct ieee80211_hw_mode) * 3, GFP_ATOMIC);
	if (!modes0)
		return;

	channels0 = (struct ieee80211_channel*)kmalloc(sizeof(struct ieee80211_channel) *
			   priv->channel_count, GFP_ATOMIC);
	if (!channels0) {
		kfree(modes0);
		return;
	}

	rates0 = (struct ieee80211_rate*)kmalloc((sizeof(struct ieee80211_rate) * (IPW_MAX_RATES + 1)),
			GFP_ATOMIC);
	if (!rates0) {
		kfree(modes0);
		kfree(channels0);
		return;
	}

	/* 0 = 802.11a
	 * 1 = 802.11b
	 * 2 = 802.11g
	 */

	/* 5.2Ghz channels start after the 2.4Ghz channels */
	modes0[A].mode = MODE_IEEE80211A;
	modes0[A].channels = &channels0[ARRAY_SIZE(ipw_eeprom_band_1)];
	modes0[A].rates = &rates0[4];
	modes0[A].num_rates = 8; /* just OFDM */
	modes0[A].num_channels = 0;

	modes0[B].mode = MODE_IEEE80211B;
	modes0[B].channels = channels0;
	modes0[B].rates = rates0;
	modes0[B].num_rates = 4; /* just CCK */
	modes0[B].num_channels = 0;

	modes0[G].mode = MODE_IEEE80211G;
	modes0[G].channels = channels0;
	modes0[G].rates = rates0;
	modes0[G].num_rates = 12; /* OFDM & CCK */
	modes0[G].num_channels = 0;

	priv->ieee_channels = channels0;
	priv->ieee_rates = rates0;

	ipw_init_hw_rates(priv, rates0);

	for (i = 0, geo_ch = channels0; i < priv->channel_count; i++) {
		ch = &priv->channel_info[i];

		if (!is_channel_valid(ch)) {
			IOLog
				("Channel %d [%sGhz] is Tx only -- skipping.\n",
				 ch->channel, is_channel_a_band(ch) ? "5.2" : "2.4");
			continue;
		}

		if (is_channel_a_band(ch)) {
			if (ch->channel < IEEE80211_52GHZ_MIN_CHANNEL ||
			    ch->channel > IEEE80211_52GHZ_MAX_CHANNEL) {
				IOLog
				    ("Channel %d [5.2Ghz] not supported by "
				     "d80211.\n", ch->channel);
				continue;
			}

			geo_ch = &modes0[A].channels[modes0[A].num_channels++];
		} else {
			if (ch->channel < IEEE80211_24GHZ_MIN_CHANNEL ||
			    ch->channel > IEEE80211_24GHZ_MAX_CHANNEL) {
				IOLog
				    ("Channel %d [2.4Ghz] not supported by "
				     "d80211.\n", ch->channel);
				continue;
			}

			geo_ch = &modes0[B].channels[modes0[B].num_channels++];
			modes0[G].num_channels++;
		}

		geo_ch->freq = ieee80211chan2mhz((ch->channel));
		geo_ch->chan = ch->channel;
		geo_ch->val = ch->channel;
		geo_ch->power_level = ch->max_power_avg;
		geo_ch->antenna_max = 0xff;

		if (is_channel_valid(ch)) {
			geo_ch->flag = IEEE80211_CHAN_W_SCAN;
			if (!(ch->flags & IPW_CHANNEL_IBSS))
				geo_ch->flag |= IEEE80211_CHAN_W_IBSS;

			if (ch->flags & IPW_CHANNEL_ACTIVE)
				geo_ch->flag |= IEEE80211_CHAN_W_ACTIVE_SCAN;

			if (ch->flags & IPW_CHANNEL_RADAR)
				geo_ch->flag |= IEEE80211_CHAN_W_RADAR_DETECT;

			if (ch->max_power_avg > priv->max_channel_txpower_limit)
				priv->max_channel_txpower_limit =
				    ch->max_power_avg;
		}

		geo_ch->val = ch->flags;
	}

	if ((modes0[A].num_channels == 0) && priv->is_abg) {
		IOLog( 
		       ": Incorrectly detected BG card as ABG.  Please send "
		       "your PCI  to maintainer.\n");
		    //   priv->pci_dev->device, priv->pci_dev->subsystem_device);
		priv->is_abg = 0;
	}

	if ((priv->config & CFG_STATIC_CHANNEL) &&
	    !ipw_get_channel_info(priv, priv->active_conf.phymode,
				  priv->active_conf.channel)) {
		IOLog("Invalid channel configured. Resetting to ANY.\n");
		if (priv->active_conf.phymode == MODE_IEEE80211A)
			priv->active_conf.channel = 34;
		else
			priv->active_conf.channel = 1;
		priv->config &= ~CFG_STATIC_CHANNEL;
	}

	IOLog( 
	       ": Tunable channels: %d 802.11bg, %d 802.11a channels\n",
	       modes0[G].num_channels, modes0[A].num_channels);

	if (modes0[A].num_channels>0)
		ieee80211_register_hwmode(priv->ieee, &modes0[A]);
	if (modes0[B].num_channels>0)
		ieee80211_register_hwmode(priv->ieee, &modes0[B]);
	if (modes0[G].num_channels>0)
		ieee80211_register_hwmode(priv->ieee, &modes0[G]);

	priv->status |= STATUS_GEO_CONFIGURED;
}

void darwin_iwi4965::ipw_set_supported_rates_mask(struct ipw_priv *priv, int rates_mask)
{

	priv->active_rate = rates_mask & 0xffff;
	priv->active_rate_basic = (rates_mask >> 16) & 0xffff;
}

int darwin_iwi4965::ieee80211_rate_control_register(struct rate_control_ops *ops)
{
	struct rate_control_alg *alg;

	alg = (struct rate_control_alg*)kmalloc(sizeof(*alg), NULL);
	if (alg == NULL) {
		return -ENOMEM;
	}
	memset(alg, 0, sizeof(*alg));
	alg->ops = ops;

	//mutex_lock(&rate_ctrl_mutex);
	list_add_tail(&alg->list, &rate_ctrl_algs);
	//mutex_unlock(&rate_ctrl_mutex);

	return 0;
}

u16 darwin_iwi4965::ipw_get_active_dwell_time(struct ipw_priv *priv, int phymode)
{
	if (phymode == MODE_IEEE80211A)
		return IPW_ACTIVE_DWELL_TIME_52;
	else
		return IPW_ACTIVE_DWELL_TIME_24;
}

u16 darwin_iwi4965::ipw_get_passive_dwell_time(struct ipw_priv *priv, int phymode)
{
	u16 active = ipw_get_active_dwell_time(priv, phymode);
	u16 passive = (phymode != MODE_IEEE80211A) ?
		IPW_PASSIVE_DWELL_BASE + IPW_PASSIVE_DWELL_TIME_24 :
		IPW_PASSIVE_DWELL_BASE + IPW_PASSIVE_DWELL_TIME_52;

	if (ipw_is_associated(priv)) {
		struct ieee80211_conf *conf = NULL;

		conf = ieee80211_get_hw_conf(priv->ieee);

		/* If we're associated, we clamp the maximum passive
		 * dwell time to be 98% of the beacon interval (minus
		 * 2 * channel tune time) */
		passive = conf->beacon_int;
		if (passive > IPW_PASSIVE_DWELL_BASE)
			passive = IPW_PASSIVE_DWELL_BASE;
		passive = (passive * 98) / 100 - IPW_CHANNEL_TUNE_TIME * 2;
	}

	if (passive <= active)
		passive = active + 1;

	return passive;
}

int darwin_iwi4965::ipw_get_channels_for_scan(struct ipw_priv *priv, int phymode,
				     u8 is_active, u8 direct_mask,
				     struct ipw_scan_channel *scan_ch)
{
	const struct ieee80211_channel *channels = NULL;
	const struct ieee80211_hw_mode *hw_mode;
	struct ipw_channel_info *ch_info;
	u16 passive_dwell = 0;
	u16 active_dwell = 0;
	int added, i;

	hw_mode = ipw_get_hw_mode(priv, phymode);
	if (!hw_mode)
		return 0;

	channels = hw_mode->channels;

	active_dwell = ipw_get_active_dwell_time(priv, phymode);
	passive_dwell = ipw_get_passive_dwell_time(priv, phymode);

	for (i = 0, added = 0; i < hw_mode->num_channels; i++) {
		if (channels[i].chan == priv->active_conf.channel) {
			if (ipw_is_associated(priv)) {
				IPW_DEBUG_SCAN
				    ("Skipping current channel %d\n",
				     priv->active_conf.channel);
				continue;
			}
		} else if (priv->only_active_channel)
			continue;

		scan_ch->channel = channels[i].chan;

		ch_info = ipw_get_channel_info(priv, phymode, scan_ch->channel);
		if (!is_channel_valid(ch_info)) {
			IOLog("Channel %d is INVALID for this SKU.\n",
				       scan_ch->channel);
			continue;
		}

		if (!is_active || is_channel_passive(ch_info) ||
		    !(channels[i].flag & IEEE80211_CHAN_W_ACTIVE_SCAN))
			scan_ch->type = 0;	/* passive */
		else
			scan_ch->type = 1;	/* active */

		if (scan_ch->type & 1)
			scan_ch->type |= (direct_mask << 1);

		if (is_channel_narrow(ch_info))
			scan_ch->type |= (1 << 7);

		scan_ch->active_dwell = active_dwell;
		scan_ch->passive_dwell = passive_dwell;

		/* Set power levels to defaults */
		scan_ch->tpc.dsp_atten = 110;	/*scan_pwr_info->tpc.dsp_atten; */

		/*scan_pwr_info->tpc.tx_gain; */
		if (phymode == MODE_IEEE80211A) {
			scan_ch->tpc.tx_gain = ((1 << 5) | (3 << 3)) | 3;
		} else {
			scan_ch->tpc.tx_gain = ((1 << 5) | (5 << 3));
			/* NOTE: if we were doing 6Mb OFDM for scans we'd use
			 * power level
			 scan_ch->tpc.tx_gain = ((1<<5) | (2 << 3)) | 3;
			 */
		}

		IOLog("Scanning %d [%s %d]\n",
			       scan_ch->channel,
			       (scan_ch->type & 1) ? "ACTIVE" : "PASSIVE",
			       (scan_ch->
				type & 1) ? active_dwell : passive_dwell);

		scan_ch++;
		added++;
	}

	IOLog("total channels to scan %d \n", added);
	return added;
}

int darwin_iwi4965::is_channel_narrow(const struct ipw_channel_info *ch_info)
{
	return (ch_info->flags & IPW_CHANNEL_NARROW) ? 1 : 0;
}

void darwin_iwi4965::ipw_reset_channel_flag(struct ipw_priv *priv)
{
	int i;
	struct ieee80211_channel *chan;
	struct ieee80211_hw_mode *hw_mode;
	struct ieee80211_local *local = hw_to_local(priv->ieee);

	list_for_each_entry(hw_mode, &local->modes_list, list) {
		for (i = 0; i < hw_mode->num_channels; i++) {
			chan = &(hw_mode->channels[i]);
			chan->flag = chan->val;
		}
	}
}

int darwin_iwi4965::ipw_is_alive(struct ipw_priv *priv)
{
	return (priv->status & STATUS_ALIVE) ? 1 : 0;
}

int darwin_iwi4965::check_bits(unsigned long field, unsigned long mask)
{
	return ((field & mask) == mask) ? 1 : 0;
}

int darwin_iwi4965::tune_required(struct ipw_priv *priv)
{
	if (memcmp
	    (priv->staging_rxon.bssid_addr, priv->active_rxon.bssid_addr,
	     ETH_ALEN))
		return 1;

	if ((priv->staging_rxon.dev_type != priv->active_rxon.dev_type) ||
	    (priv->staging_rxon.channel != priv->active_rxon.channel))
		return 1;

	/* Check if we are not switching bands */
	if (check_bits(priv->staging_rxon.flags, RXON_FLG_BAND_24G_MSK) !=
	    check_bits(priv->active_rxon.flags, RXON_FLG_BAND_24G_MSK))
		return 1;

	/* Check if we are switching association toggle */
	if (check_bits(priv->staging_rxon.filter_flags,
		       RXON_FILTER_ASSOC_MSK) &&
	    check_bits(priv->active_rxon.filter_flags, RXON_FILTER_ASSOC_MSK))
		return 0;

	return 1;
}

int darwin_iwi4965::ipw_send_rxon_assoc(struct ipw_priv *priv)
{
	int rc = 0;
	struct ipw_rx_packet *res = NULL;
	struct ipw_rxon_assoc_cmd rxon_assoc;
	struct ipw_host_cmd cmd;// = {
		cmd.id = REPLY_RXON_ASSOC;
		cmd.len = sizeof(struct ipw_rxon_assoc_cmd);
		cmd.meta.flags = CMD_WANT_SKB;
		cmd.data = &rxon_assoc;
	//};

	rxon_assoc.flags = priv->staging_rxon.flags;
	rxon_assoc.filter_flags = priv->staging_rxon.filter_flags;
	rxon_assoc.ofdm_basic_rates = priv->staging_rxon.ofdm_basic_rates;
	rxon_assoc.cck_basic_rates = priv->staging_rxon.cck_basic_rates;
	rxon_assoc.reserved = 0;

	rc = ipw_send_cmd(priv, &cmd);
	if (rc)
		return rc;

	res = (struct ipw_rx_packet *)mbuf_data(cmd.meta.u.skb);//->data;
	if (res->hdr.flags & 0x40) {
		IOLog("Bad return from REPLY_RXON_ASSOC command\n");
		rc = -EIO;
	}

	if (!(mbuf_type(cmd.meta.u.skb) == MBUF_TYPE_FREE) ) freePacket(cmd.meta.u.skb);

	return rc;
}

u8 darwin_iwi4965::ipw_rate_index2plcp(int x)
{

	if (x < ARRAY_SIZE(rate_table_info))
		return rate_table_info[x].rate_plcp;

	return IPW_INVALID_RATE;
}

int darwin_iwi4965::ipw_reg_send_txpower(struct ipw_priv *priv)
{
	int rate_idx;
	struct ipw_channel_info *ch_info = NULL;
	struct ipw_txpowertable_cmd txpower;// = {
		txpower.channel = priv->active_conf.channel;
	//};

	txpower.band = (priv->active_conf.phymode == MODE_IEEE80211A) ? 0 : 1;
	ch_info = ipw_get_channel_info(priv,
				       priv->active_conf.phymode,
				       priv->active_conf.channel);
	if (!ch_info) {
		IOLog
		    ("Failed to get channel info for channel %d [%d]\n",
		     priv->active_conf.channel, priv->active_conf.phymode);
		return -EINVAL;
	}

	if (!is_channel_valid(ch_info)) {
		IPW_DEBUG_POWER("Not calling TX_PWR_TABLE_CMD on "
				"non-Tx channel.\n");
		return 0;
	}

	/* fill cmd with power settings for all rates for current channel */
	for (rate_idx = 0; rate_idx < IPW_MAX_RATES; rate_idx++) {
		txpower.power[rate_idx].tpc =
			ch_info->power_info[rate_idx].tpc;
		txpower.power[rate_idx].rate = ipw_rate_index2plcp(rate_idx);

		IPW_DEBUG_POWER("ch %d:%d rf %d dsp %3d rate code 0x%02x\n",
				txpower.channel,
				txpower.band,
				txpower.power[rate_idx].tpc.tx_gain,
				txpower.power[rate_idx].tpc.dsp_atten,
				txpower.power[rate_idx].rate);
	}

	return ipw_send_cmd_pdu(priv, REPLY_TX_PWR_TABLE_CMD,
				sizeof(struct ipw_txpowertable_cmd), &txpower);

}

u8 darwin_iwi4965::ipw_remove_station(struct ipw_priv *priv, u8 * bssid, int is_ap)
{
	int index = IPW_INVALID_STATION;
	int i;
	unsigned long flags;

	//spin_lock_irqsave(&priv->sta_lock, flags);
	if (is_ap) {
		index = AP_ID;
		if ((priv->stations[index].used))
			priv->stations[index].used = 0;
	} else if (ipw_is_broadcast_ether_addr(bssid)) {
		index = priv->hw_setting.broadcast_id;
		if ((priv->stations[index].used))
			priv->stations[index].used = 0;
	} else {
		for (i = STA_ID; i < (priv->num_stations + STA_ID); i++) {
			if ((priv->stations[i].used)
			    &&
			    (!memcmp
			     (priv->stations[i].sta.sta.MACAddr,
			      bssid, ETH_ALEN))) {
				index = i;
				priv->stations[index].used = 0;
				break;
			}
		}
	}

	if (index != IPW_INVALID_STATION) {
		if (priv->num_stations > 0)
			priv->num_stations--;
		IOLog("Removing STA ID %d: " MAC_FMT "\n",
			index, MAC_ARG(bssid));

	}

	//spin_unlock_irqrestore(&priv->sta_lock, flags);
	return 0;
}

u8 darwin_iwi4965::ipw_add_station(struct ipw_priv *priv, u8 * bssid,
			  int is_ap, u8 flags)
{
	int i = priv->hw_setting.number_of_stations;
	int index = IPW_INVALID_STATION;
	unsigned long flags_spin;

	//spin_lock_irqsave(&priv->sta_lock, flags_spin);
	if (is_ap) {
		index = AP_ID;
		if ((priv->stations[index].used) &&
		    (!memcmp
		     (priv->stations[index].sta.sta.MACAddr, bssid, ETH_ALEN)))
			goto done;
	} else if (ipw_is_broadcast_ether_addr(bssid)) {
		index = priv->hw_setting.broadcast_id;
		if ((priv->stations[index].used) &&
		    (!memcmp
		     (priv->stations[index].sta.sta.MACAddr, bssid, ETH_ALEN)))
			goto done;
	} else {
		for (i = STA_ID; i < (priv->num_stations + STA_ID); i++) {
			if ((priv->stations[i].used)
			    &&
			    (!memcmp
			     (priv->stations[i].sta.sta.MACAddr,
			      bssid, ETH_ALEN))) {
				goto done;
			}

			if ((priv->stations[i].used == 0) &&
			    (index == IPW_INVALID_STATION))
				index = i;
		}
	}

	if (index != IPW_INVALID_STATION)
		i = index;

	if (i == priv->hw_setting.number_of_stations) {
		index = IPW_INVALID_STATION;
		goto done;
	}

	IOLog("Adding STA ID %d: " MAC_FMT "\n", i, MAC_ARG(bssid));

	priv->stations[i].used = 1;
	priv->stations[i].current_rate.s.rate = R_1M;
	memset(&priv->stations[i].sta, 0, sizeof(struct ipw_addsta_cmd));
	memcpy(priv->stations[i].sta.sta.MACAddr, bssid, ETH_ALEN);
	priv->stations[i].sta.ctrlAddModify = 0;
	priv->stations[i].sta.sta.staID = i;
	priv->stations[i].sta.station_flags = 0;

	//todoG do we need this
//      priv->stations[i].sta.tid_disable_tx = 0xffff;  /* all TID's disabled */
	if (priv->active_conf.phymode == MODE_IEEE80211A)
		priv->stations[i].sta.tx_rate.rate_n_flags = R_6M;
	else
		priv->stations[i].sta.tx_rate.rate_n_flags = R_1M |
			priv->hw_setting.cck_flag;

	priv->stations[i].sta.tx_rate.rate_n_flags |= RATE_MCS_ANT_B_MSK;
	priv->stations[i].sta.tx_rate.rate_n_flags &= ~RATE_MCS_ANT_A_MSK;

	priv->stations[i].sta.station_flags |= STA_MODIFY_TX_RATE_MSK;

	priv->stations[i].current_rate.rate_n_flags = priv->stations[i].sta.tx_rate.rate_n_flags;

	priv->num_stations++;
	//spin_unlock_irqrestore(&priv->sta_lock, flags_spin);
	ipw_send_add_station(priv, &priv->stations[i].sta, flags);
	return i;
      done:
	//spin_unlock_irqrestore(&priv->sta_lock, flags_spin);
	return index;

}

int darwin_iwi4965::ipw_send_add_station(struct ipw_priv *priv,
				struct ipw_addsta_cmd *sta, u8 flags)
{
	struct ipw_rx_packet *res = NULL;
	int rc = 0;
	struct ipw_host_cmd cmd;// = {
		cmd.id = REPLY_ADD_STA;
		cmd.len = priv->hw_setting.add_station_size;
		cmd.meta.flags = flags;
		cmd.data = sta;

	if (!(flags & CMD_ASYNC))
		//cmd.meta.u.callback = ipw_add_sta_sync_callback;
	//else
		cmd.meta.flags |= CMD_WANT_SKB;

	rc = ipw_send_cmd(priv, &cmd);

	if (rc || (flags & CMD_ASYNC))
		return rc;

	res = (struct ipw_rx_packet *)mbuf_data(cmd.meta.u.skb);//->data;
	if (res->hdr.flags & 0x40) {
		IOLog("Bad return from REPLY_ADD_STA (0x%08X)\n",
			  res->hdr.flags);
		rc = -EIO;
	}

	if (rc == 0) {
		switch (res->u.add_sta.status) {
		case ADD_STA_SUCCESS_MSK:
			IOLog("REPLY_ADD_STA PASSED\n");
			break;
		default:
			rc = -EIO;
			IOLog("REPLY_ADD_STA failed\n");
			break;
		}
	}
	if (!(mbuf_type(cmd.meta.u.skb) == MBUF_TYPE_FREE) ) freePacket(cmd.meta.u.skb);

	return rc;
}

int darwin_iwi4965::ipw_rxon_add_station(struct ipw_priv *priv, u8 * addr, int is_ap)
{
	/* Remove this station if it happens to already exist */
	ipw_remove_station(priv, addr, is_ap);

	return ipw_add_station(priv, addr, is_ap, 0);
}

int darwin_iwi4965::ipw_commit_rxon(struct ipw_priv *priv)
{
	int rc = 0;

	if (!ipw_is_alive(priv))
		return -1;

	/* always get timestamp with Rx frame */
	priv->staging_rxon.flags |= RXON_FLG_TSF2HOST_MSK;

	/* select antenna */
	priv->staging_rxon.flags &=
	    ~(RXON_FLG_DIS_DIV_MSK | RXON_FLG_ANT_SEL_MSK);
	priv->staging_rxon.flags |= ipw_get_antenna_flags(priv);

	/* If we don't need to retune, we can use ipw_rxon_assoc_cmd which
	 * is used to reconfigure filter and other flags for the current
	 * radio configuration.
	 *
	 * If we need to tune, we need to request the regulatory
	 * daemon to tune and configure the radio via ipw_send_rx_config. */
	if (!tune_required(priv))
		rc = ipw_send_rxon_assoc(priv);
	else {
		/* Sending the RXON command clears out the station table,
		 * so we must clear out our cached table values so we will
		 * re-add stations to the uCode for TX */
		ipw_clear_stations_table(priv);

		/* If we are currently associated and the new config requires
		 * a tune *and* the new config wants the associated mask enabled,
		 * we must clear the associated from the active configuration
		 * before we apply the new config */
		if (ipw_is_associated(priv) &&
		    (priv->staging_rxon.
		     filter_flags & RXON_FILTER_ASSOC_MSK)) {
			IOLog("Toggling associated bit on current "
				       "RXON\n");
			priv->active_rxon.filter_flags &=
				~RXON_FILTER_ASSOC_MSK;
			rc = ipw_send_cmd_pdu(priv, REPLY_RXON,
					      sizeof(struct ipw_rxon_cmd),
					      &priv->active_rxon);

			/* If the mask clearing failed then we set
			 * active_config back to what it was previously */
			if (!rc)
				priv->active_rxon.filter_flags |=
					RXON_FILTER_ASSOC_MSK;

		}
		//rc=0;//hack
		if (!rc)
			rc = ipw_send_cmd_pdu(priv, REPLY_RXON,
					      sizeof(struct ipw_rxon_cmd),
					      &priv->staging_rxon);
		//rc=0;//hack
		if (!rc)
			rc = ipw_reg_send_txpower(priv);

		//rc=0;//hack
		/* Add the broadcast address so we can send broadcast frames */
		if (!rc) {
			if (ipw_rxon_add_station(priv, BROADCAST_ADDR, 0) ==
			    IPW_INVALID_STATION)
				rc = -EIO;
		}
	}
	//rc=0;//hack
	if (rc)
		IOLog("Error setting configuration.  Reload driver.\n");
	else
		memcpy(&priv->active_rxon, &priv->staging_rxon,
		       sizeof(priv->active_rxon));

	return rc;
}

int darwin_iwi4965::ipw_init_rate_scaling(struct ipw_priv *priv)
{
	int rc;
	struct ipw_rate_scaling_cmd_specifics *cmd;
	struct ipw_rate_scaling_info *table;
	unsigned long flags;
	int i;

	cmd = &priv->lq_mngr.scale_rate_cmd;
	table = &cmd->table[0];

	//spin_lock_irqsave(&priv->lq_mngr.lock, flags);

	priv->lq_mngr.flush_time = IPW_RATE_SCALE_FLUSH;
	priv->lq_mngr.stamp_last = jiffies;
	priv->lq_mngr.tx_packets = 0;


	switch (priv->active_conf.phymode) {
	case MODE_IEEE80211A:
		IOLog("Select A mode rate scale\n");

		table[RATE_SCALE_6M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_6M_INDEX].next_rate_index =
		    RATE_SCALE_6M_INDEX;
		table[RATE_SCALE_9M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_9M_INDEX].next_rate_index =
		    RATE_SCALE_6M_INDEX;
		table[RATE_SCALE_12M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_12M_INDEX].next_rate_index =
		    RATE_SCALE_9M_INDEX;
		table[RATE_SCALE_18M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_18M_INDEX].next_rate_index =
		    RATE_SCALE_12M_INDEX;
		table[RATE_SCALE_24M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_24M_INDEX].next_rate_index =
		    RATE_SCALE_18M_INDEX;
		table[RATE_SCALE_36M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_36M_INDEX].next_rate_index =
		    RATE_SCALE_24M_INDEX;
		table[RATE_SCALE_48M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_48M_INDEX].next_rate_index =
		    RATE_SCALE_36M_INDEX;
		table[RATE_SCALE_54M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_54M_INDEX].next_rate_index =
		    RATE_SCALE_48M_INDEX;

		/* If one of the following CCK rates is used,
		 * have it fall back to an above OFDM rate */
		table[RATE_SCALE_1M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_1M_INDEX].next_rate_index =
		    RATE_SCALE_6M_INDEX;
		table[RATE_SCALE_2M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_2M_INDEX].next_rate_index =
		    RATE_SCALE_6M_INDEX;
		table[RATE_SCALE_5_5M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_5_5M_INDEX].next_rate_index =
		    RATE_SCALE_6M_INDEX;
		table[RATE_SCALE_11M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_11M_INDEX].next_rate_index =
		    RATE_SCALE_6M_INDEX;

		for (i = NUM_RATES; i < IPW_MAX_RATES; i++) {
			table[i].try_cnt = priv->retry_rate;
			table[i].next_rate_index = RATE_SCALE_6M_INDEX;
		}
		break;
	case MODE_IEEE80211B:
		IOLog("Select B mode rate scale\n");

		/* If one of the following OFDM rates is used,
		 * have it fall back to the CCK rates at the end */
		table[RATE_SCALE_6M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_6M_INDEX].next_rate_index =
		    RATE_SCALE_1M_INDEX;
		table[RATE_SCALE_9M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_9M_INDEX].next_rate_index =
		    RATE_SCALE_1M_INDEX;
		table[RATE_SCALE_12M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_12M_INDEX].next_rate_index =
		    RATE_SCALE_1M_INDEX;
		table[RATE_SCALE_18M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_18M_INDEX].next_rate_index =
		    RATE_SCALE_1M_INDEX;
		table[RATE_SCALE_24M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_24M_INDEX].next_rate_index =
		    RATE_SCALE_1M_INDEX;
		table[RATE_SCALE_36M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_36M_INDEX].next_rate_index =
		    RATE_SCALE_1M_INDEX;
		table[RATE_SCALE_48M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_48M_INDEX].next_rate_index =
		    RATE_SCALE_1M_INDEX;
		table[RATE_SCALE_54M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_54M_INDEX].next_rate_index =
		    RATE_SCALE_1M_INDEX;

		/* CCK rates... */
		table[RATE_SCALE_1M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_1M_INDEX].next_rate_index =
		    RATE_SCALE_1M_INDEX;
		table[RATE_SCALE_2M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_2M_INDEX].next_rate_index =
		    RATE_SCALE_1M_INDEX;
		table[RATE_SCALE_5_5M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_5_5M_INDEX].next_rate_index =
		    RATE_SCALE_2M_INDEX;
		table[RATE_SCALE_11M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_11M_INDEX].next_rate_index =
		    RATE_SCALE_5_5M_INDEX;
		for (i = NUM_RATES; i < IPW_MAX_RATES; i++) {
			table[i].try_cnt = priv->retry_rate;
			table[i].next_rate_index = RATE_SCALE_1M_INDEX;
		}
		break;
	case MODE_IEEE80211G:
		IOLog("Select G mode rate scale\n");

		table[RATE_SCALE_6M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_6M_INDEX].next_rate_index =
		    RATE_SCALE_2M_INDEX;
		table[RATE_SCALE_9M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_9M_INDEX].next_rate_index =
		    RATE_SCALE_6M_INDEX;
		table[RATE_SCALE_12M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_12M_INDEX].next_rate_index =
		    RATE_SCALE_9M_INDEX;
		table[RATE_SCALE_18M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_18M_INDEX].next_rate_index =
		    RATE_SCALE_12M_INDEX;
		table[RATE_SCALE_24M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_24M_INDEX].next_rate_index =
		    RATE_SCALE_18M_INDEX;
		table[RATE_SCALE_36M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_36M_INDEX].next_rate_index =
		    RATE_SCALE_24M_INDEX;
		table[RATE_SCALE_48M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_48M_INDEX].next_rate_index =
		    RATE_SCALE_36M_INDEX;
		table[RATE_SCALE_54M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_54M_INDEX].next_rate_index =
		    RATE_SCALE_48M_INDEX;
		table[RATE_SCALE_1M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_1M_INDEX].next_rate_index =
		    RATE_SCALE_1M_INDEX;
		table[RATE_SCALE_2M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_2M_INDEX].next_rate_index =
		    RATE_SCALE_1M_INDEX;
		table[RATE_SCALE_5_5M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_5_5M_INDEX].next_rate_index =
		    RATE_SCALE_2M_INDEX;
		table[RATE_SCALE_11M_INDEX].try_cnt = priv->retry_rate;
		table[RATE_SCALE_11M_INDEX].next_rate_index =
		    RATE_SCALE_5_5M_INDEX;
		for (i = NUM_RATES; i < IPW_MAX_RATES; i++) {
			table[i].try_cnt = priv->retry_rate;
			table[i].next_rate_index = RATE_SCALE_6M_INDEX;

		}
		break;
	}

	//spin_unlock_irqrestore(&priv->lq_mngr.lock, flags);

	/* Update the rate scaling for control frame Tx */
	cmd->table_id = 0;
	rc = ipw_send_cmd_pdu(priv, REPLY_RATE_SCALE,
			      sizeof(*cmd), cmd);
	if (rc)
		return rc;

	/* Update the rate scaling for data frame Tx */
	cmd->table_id = 1;
	rc = ipw_send_cmd_pdu(priv, REPLY_RATE_SCALE,
			      sizeof(*cmd), cmd);

	return rc;
}

int darwin_iwi4965::ieee80211_register_hwmode(struct ieee80211_hw *hw,
			      struct ieee80211_hw_mode *mode)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct ieee80211_rate *rate;
	int i;
	
	IOLog("ieee80211_register_hwmode\n");
	
	INIT_LIST_HEAD(&mode->list);
	list_add_tail(&mode->list, &local->modes_list);

	local->hw_modes |= (1 << mode->mode);
	for (i = 0; i < mode->num_rates; i++) {
		rate = &(mode->rates[i]);
		rate->rate_inv = CHAN_UTIL_RATE_LCM / rate->rate;
	}

	if (!local->curr_rates) {
		/* Default to this mode */
		local->hw.conf.phymode = mode->mode;
		local->oper_hw_mode = local->scan_hw_mode = mode;
		local->oper_channel = local->scan_channel = &mode->channels[0];
		local->curr_rates = mode->rates;
		local->num_curr_rates = mode->num_rates;
		ieee80211_prepare_rates(local);
	}

	ieee80211_init_client(local->mdev);

	return 0;
}

static const struct ieee80211_channel_range ieee80211_fcc_channels[] = {
	{ 2412, 2462, 27, 6 } /* IEEE 802.11b/g, channels 1..11 */,
	{ 5180, 5240, 17, 6 } /* IEEE 802.11a, channels 36..48 */,
	{ 5260, 5320, 23, 6 } /* IEEE 802.11a, channels 52..64 */,
	{ 5745, 5825, 30, 6 } /* IEEE 802.11a, channels 149..165, outdoor */,
	{ 0 }
};

static const struct ieee80211_channel_range *channel_range =
	ieee80211_fcc_channels;
	
void darwin_iwi4965::ieee80211_unmask_channel(struct net_device *dev, int mode,
				     struct ieee80211_channel *chan)
{
	int i;
	IOLog("ieee80211_unmask_channel\n");
	chan->flag = 0;

	/*if (ieee80211_regdom == 64 &&
	    (mode == MODE_ATHEROS_TURBO || mode == MODE_ATHEROS_TURBOG)) {
		return;
	}*/

	for (i = 0; channel_range[i].start_freq; i++) {
		const struct ieee80211_channel_range *r = &channel_range[i];
		if (r->start_freq <= chan->freq && r->end_freq >= chan->freq) {
			/*if (ieee80211_regdom == 64 && !ieee80211_japan_5ghz &&
			    chan->freq >= 5260 && chan->freq <= 5320) {
				continue;
			}*/

			if (/*ieee80211_regdom == 0x10 &&*/
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

			/*if (ieee80211_regdom == 64 &&
			    (chan->freq == 5170 || chan->freq == 5190 ||
			     chan->freq == 5210 || chan->freq == 5230)) {

				chan->flag &= ~IEEE80211_CHAN_W_ACTIVE_SCAN;
			}

			if (ieee80211_regdom == 64 &&
			    (chan->freq == 5260 || chan->freq == 5280 ||
			     chan->freq == 5300 || chan->freq == 5320)) {
				chan->flag &= ~IEEE80211_CHAN_W_IBSS;
			}*/

			break;
		}
	}
}

int darwin_iwi4965::ieee80211_unmask_channels(struct net_device *dev)
{
	struct ieee80211_local *local = hw_to_local(priv->ieee);
	//wdev_priv(dev->ieee80211_ptr);
	IOLog("ieee80211_unmask_channels\n");
	struct ieee80211_hw_mode *mode;
	int c;

	list_for_each_entry(mode, &local->modes_list, list) {
		for (c = 0; c < mode->num_channels; c++) {
			ieee80211_unmask_channel(dev, mode->mode,
						 &mode->channels[c]);
		}
	}
	return 0;
}

int darwin_iwi4965::ieee80211_init_client(struct net_device *dev)
{
	//if (ieee80211_regdom == 0x40)
	//	channel_range = ieee80211_mkk_channels;
	IOLog("ieee80211_init_client\n");
	ieee80211_unmask_channels(dev);
	return 0;
}

int darwin_iwi4965::rate_list_match(const int *rate_list, int rate)
{
	int i;

	if (!rate_list)
		return 0;

	for (i = 0; rate_list[i] >= 0; i++)
		if (rate_list[i] == rate)
			return 1;

	return 0;
}

void darwin_iwi4965::ieee80211_prepare_rates(struct ieee80211_local *local)
{
	int i;
	IOLog("ieee80211_prepare_rates\n");
	for (i = 0; i < local->num_curr_rates; i++) {
		struct ieee80211_rate *rate = &local->curr_rates[i];

		rate->flags &= ~(IEEE80211_RATE_SUPPORTED |
				 IEEE80211_RATE_BASIC);

		/*if (local->supp_rates[local->hw.conf.phymode]) { // hack
			if (!rate_list_match(local->supp_rates
					     [local->hw.conf.phymode],
					     rate->rate))
				continue;
		}*/

		rate->flags |= IEEE80211_RATE_SUPPORTED;

		/* Use configured basic rate set if it is available. If not,
		 * use defaults that are sane for most cases. */
		/*if (local->basic_rates[local->hw.conf.phymode]) { //hack
			if (rate_list_match(local->basic_rates
					    [local->hw.conf.phymode],
					    rate->rate))
				rate->flags |= IEEE80211_RATE_BASIC;
		} else */switch (local->hw.conf.phymode) {
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
		switch (local->hw.conf.phymode) {
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
			if (rate->rate != 10 && rate->rate != 20 &&
			    rate->rate != 55 && rate->rate != 110)
				rate->flags |= IEEE80211_RATE_ERP;
			break;
		}
	}
}

int darwin_iwi4965::ieee80211_register_hw(struct ieee80211_hw *hw)
{
	struct ieee80211_local *local = hw_to_local(hw);
	struct net_device *sta_dev;
	int result;

	/*result = wiphy_register(local->hw.wiphy);
	if (result < 0)
		return result;

	result = ieee80211_dev_sysfs_add(local);
	if (result < 0)
		goto fail_sysfs;*/

	local->hw.conf.beacon_int = 1000;

	local->wstats_flags |= local->hw.max_rssi ?
			       IW_QUAL_LEVEL_UPDATED : IW_QUAL_LEVEL_INVALID;
	local->wstats_flags |= local->hw.max_signal ?
			       IW_QUAL_QUAL_UPDATED : IW_QUAL_QUAL_INVALID;
	local->wstats_flags |= local->hw.max_noise ?
			       IW_QUAL_NOISE_UPDATED : IW_QUAL_NOISE_INVALID;
	if (local->hw.max_rssi < 0 || local->hw.max_noise < 0)
		local->wstats_flags |= IW_QUAL_DBM;

	/*result = sta_info_start(local);
	if (result < 0)
		goto fail_sta_info;

	rtnl_lock();
	result = dev_alloc_name(local->mdev, local->mdev->name);
	if (result < 0) {
		rtnl_unlock();
		goto fail_dev;
	}

	memcpy(local->mdev->dev_addr, local->hw.wiphy->perm_addr, ETH_ALEN);
	SET_NETDEV_DEV(local->mdev, wiphy_dev(local->hw.wiphy));

	result = register_netdevice(local->mdev);
	if (result < 0) {
		rtnl_unlock();
		goto fail_dev;
	}
	result = ieee80211_sysfs_add_netdevice(local->mdev);
	if (result < 0) {
		rtnl_unlock();
		goto fail_if_sysfs;
	}*/

	/*result = ieee80211_init_rate_ctrl_alg(local, NULL);
	rtnl_unlock();
	if (result < 0) {
		printk(KERN_DEBUG "%s: Failed to initialize rate control "
		       "algorithm\n", local->mdev->name);
		goto fail_rate;
	}

	result = ieee80211_wep_init(local);

	if (result < 0) {
		printk(KERN_DEBUG "%s: Failed to initialize wep\n",
		       local->mdev->name);
		goto fail_wep;
	}

	ieee80211_install_qdisc(local->mdev);

	rtnl_lock();
	result = ieee80211_if_add(local->mdev, "wlan%d", 1, &sta_dev);
	if (result == 0)
		ieee80211_if_set_type(sta_dev, IEEE80211_IF_TYPE_STA);

	local->reg_state = IEEE80211_DEV_REGISTERED;
	rtnl_unlock();

	ieee80211_led_init(local);*/

	return 0;
/*
fail_wep:
	rate_control_deinitialize(local);
fail_rate:
	ieee80211_sysfs_remove_netdevice(local->mdev);
fail_if_sysfs:
	unregister_netdev(local->mdev);
fail_dev:
	sta_info_stop(local);
fail_sta_info:
	ieee80211_dev_sysfs_del(local);
fail_sysfs:
	wiphy_unregister(local->hw.wiphy);*/
	return result;
}

void darwin_iwi4965::ipw_bg_alive_start()
{
	//struct ipw_priv *priv =
	  //  container_of(work, struct ipw_priv, alive_start.work);
	int rc = 0;
	int thermal_spin = 0;

	if (priv->status & STATUS_EXIT_PENDING)
		return;

	//mutex_lock(&priv->mutex);
	if (priv->card_alive.is_valid != 1) {
		/* We had an error bringing up the hardware, so take it
		 * all the way back down so we can try again */
		IOLog("Alive failed.\n");
		queue_te(12,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_down),priv,NULL,true);
		//mutex_unlock(&priv->mutex);
		return;
	}

	/* bootstrap uCode has loaded runtime uCode ... verify inst image */
	if (ipw_verify_ucode(priv)) {
		/* Runtime instruction load was bad;
		 * take it all the way back down so we can try again */
		IOLog("Bad runtime uCode load.\n");
		queue_te(12,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_down),priv,NULL,true);
		//mutex_unlock(&priv->mutex);
		return;
	}

	/* After the ALIVE response, we can processed host commands */
	priv->status |= STATUS_ALIVE;

	IOLog("Alive received.\n");

	ipw_clear_stations_table(priv);

	if (!(priv->status & STATUS_RF_KILL_MASK)) {
		/* if rfkill is not on, then
		 * wait for thermal sensor in adapter to kick in */
		while (ipw_read32(CSR_UCODE_DRV_GP2)== 0) {
			thermal_spin++;
			udelay(10);
		}
		if (thermal_spin)
			IOLog("Thermal calibration took %dus\n",
				       thermal_spin * 10);
	}
	IOLog("ipw_init_channel_map\n");
	rc = ipw_init_channel_map(priv);
	if (rc) {
		IOLog("initializing regulatory failed: %d\n", rc);
		//mutex_unlock(&priv->mutex);
		return;
	}
	IOLog("ipw_init_geos\n");
	ipw_init_geos(priv);

	if (!(priv->status & STATUS_GEO_CONFIGURED)) return;
	
	if (!priv->netdev_registered) {
	//	mutex_unlock(&priv->mutex);
	IOLog("ieee80211_rate_control_register\n");
		ieee80211_rate_control_register(&priv->rate_control);
	IOLog("ieee80211_register_hw\n");
		rc = ieee80211_register_hw(priv->ieee);
		if (rc) {
			IOLog("Failed to register network "
				  "device (error %d)\n", rc);
			return;
		}

	//	module_put(THIS_MODULE);

	//	mutex_lock(&priv->mutex);
		priv->netdev_registered = 1;
		IOLog("ipw_reset_channel_flag\n");
		ipw_reset_channel_flag(priv);
	}

	memcpy(priv->net_dev->dev_addr, priv->mac_addr, ETH_ALEN);

	priv->rates_mask = IEEE80211_DEFAULT_RATES_MASK;
	IOLog("ipw_set_supported_rates_mask\n");
	ipw_set_supported_rates_mask(priv, priv->rates_mask);
	IOLog("ipw_set_rate\n");
	ipw_set_rate(priv);
	IOLog("ipw_send_power_mode\n");
	ipw_send_power_mode(priv, IPW_POWER_LEVEL(priv->power_mode));

/*
 * ipw_qos_activate(priv, NULL);
 */
	//IOLog("ipw_send_power_mode2\n");
	//ipw_send_power_mode(priv, IPW_POWER_LEVEL(priv->power_mode));

	/* Initialize our rx_config data */
	IOLog("ipw_connection_init_rx_config\n");
	ipw_connection_init_rx_config(priv);
	memcpy(priv->staging_rxon.node_addr, priv->net_dev->dev_addr, ETH_ALEN);

	/* Configure BT coexistence */
	IOLog("ipw_send_bt_config\n");
	ipw_send_bt_config(priv);

	IOLog("ipw_commit_rxon\n");
	/* Configure the adapter for unassociated operation */
	ipw_commit_rxon(priv);

	/* Add the broadcast address so we can send probe requests */
	IOLog("ipw_rxon_add_station\n");
	ipw_rxon_add_station(priv, BROADCAST_ADDR, 0);
	IOLog("ipw_init_rate_scaling\n");
	ipw_init_rate_scaling(priv);

	/* At this point, the NIC is initialized and operational */
	priv->notif_missed_beacons = 0;
	priv->status |= STATUS_READY;

//	ipw_update_link_led(priv);
	IOLog("reg_txpower_periodic\n");
	reg_txpower_periodic(priv);

	//mutex_unlock(&priv->mutex);
	
	//hack: force scan
	//ipw_scan_initiate(priv,0);
}



int darwin_iwi4965::is_temp_calib_needed(struct ipw_priv *priv)
{
	int temp_diff;

	priv->curr_temperature = reg_txpower_get_temperature(priv);
	temp_diff = priv->curr_temperature - priv->last_temperature;

	/* get absolute value */
	if (temp_diff < 0) {
		IWI_DEBUG_FULL("Getting cooler, delta %d,\n", temp_diff);
		temp_diff = -temp_diff;
	} else if (temp_diff == 0)
		IWI_DEBUG_FULL("Same temp,\n");
	else
		IWI_DEBUG_FULL("Getting warmer, delta %d,\n", temp_diff);

	/* if we don't need calibration, *don't* update last_temperature */
	if (temp_diff < IPW_TEMPERATURE_LIMIT_TIMER) {
		IWI_DEBUG_FULL("Timed thermal calib not needed\n");
		return 0;
	}

	IWI_DEBUG_FULL("Timed thermal calib needed\n");

	/* assume that caller will actually do calib ...
	 *   update the "last temperature" value */
	priv->last_temperature = priv->curr_temperature;
	return 1;
}

int darwin_iwi4965::reg_txpower_compensate_for_temperature_dif(struct ipw_priv *priv)
{
	struct ipw_channel_info *ch_info = NULL;
	int delta_index;
	const s8 *clip_pwrs; /* array of h/w max power levels for each rate */
	u8 a_band;
	u8 rate_index;
	u8 scan_tbl_index;
	u8 i;
	int ref_temp;
	int temperature = priv->curr_temperature;

	/* set up new Tx power info for each and every channel, 2.4 and 5.x */
	for (i = 0; i < priv->channel_count; i++) {
		ch_info = &priv->channel_info[i];
		a_band = is_channel_a_band(ch_info);

		/* Get this chnlgrp's factory calibration temperature */
		ref_temp = priv->eeprom.groups[ch_info->group_index].
		    temperature;

		/* get power index adjustment based on curr and factory
		 * temps */
		delta_index = reg_adjust_power_by_temp(temperature, ref_temp);

		/* set tx power value for all rates, OFDM and CCK */
		for (rate_index = 0; rate_index < IPW_MAX_RATES;
		     rate_index++) {
			int power_idx =
			    ch_info->power_info[rate_index].base_power_index;

			/* temperature compensate */
			power_idx += delta_index;

			/* stay within table range */
			power_idx = reg_fix_power_index(power_idx);
			ch_info->power_info[rate_index].
			    power_table_index = (u8) power_idx;
			ch_info->power_info[rate_index].tpc =
			    power_gain_table[a_band][power_idx];
		}

		/* Get this chnlgrp's rate-to-max/clip-powers table */
		clip_pwrs = priv->clip_groups[ch_info->group_index].
			clip_powers;

		/* set scan tx power, 1Mbit for CCK, 6Mbit for OFDM */
		for (scan_tbl_index = 0;
		     scan_tbl_index < IPW_NUM_SCAN_RATES; scan_tbl_index++) {
			s32 actual_index = (scan_tbl_index == 0) ?
			    RATE_SCALE_1M_INDEX : RATE_SCALE_6M_INDEX;
			reg_set_scan_power(priv, scan_tbl_index,
					   actual_index, clip_pwrs,
					   ch_info, a_band);
		}
	}

	/* send Txpower command for current channel to ucode */
	return ipw_reg_send_txpower(priv);
}

void darwin_iwi4965::reg_txpower_periodic(struct ipw_priv *priv)
{
	/* This will kick in the "brute force"
	 *   reg_txpower_compensate_for_temperature_dif() below */
	if (!is_temp_calib_needed(priv))
		goto reschedule;

	/* Set up a new set of temp-adjusted TxPowers, send to NIC.
	 * This is based *only* on current temperature,
	 * ignoring any previous power measurements */
	reg_txpower_compensate_for_temperature_dif(priv);

 reschedule:
	//queue_delayed_work(priv->workqueue,   &priv->thermal_periodic, REG_RECALIB_PERIOD * HZ);
	queue_te(10,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::reg_txpower_periodic),priv,6,true);
}

int darwin_iwi4965::ipw_send_bt_config(struct ipw_priv *priv)
{
	struct ipw_bt_cmd bt_cmd;
		bt_cmd.flags = 3;
		bt_cmd.leadTime = 0xAA;
		bt_cmd.maxKill = 1;
		bt_cmd.killAckMask = 0;
		bt_cmd.killCTSMask = 0;

	return ipw_send_cmd_pdu(priv, REPLY_BT_CONFIG,
				sizeof(struct ipw_bt_cmd), &bt_cmd);
}

const struct ipw_channel_info *darwin_iwi4965::find_channel(struct ipw_priv *priv,
						   u8 channel)
{
	int i;

	for (i = 0; i < priv->channel_count; i++) {
		if (priv->channel_info[i].channel == channel)
			return &priv->channel_info[i];
	}

	return NULL;
}

void darwin_iwi4965::ipw_connection_init_rx_config(struct ipw_priv *priv)
{
	const struct ipw_channel_info *ch_info;

	memset(&priv->staging_rxon, 0, sizeof(priv->staging_rxon));

	switch (priv->iw_mode) {
	case IEEE80211_IF_TYPE_MGMT:
		priv->staging_rxon.dev_type = RXON_DEV_TYPE_AP;
		break;

	case IEEE80211_IF_TYPE_STA:
		priv->staging_rxon.dev_type = RXON_DEV_TYPE_ESS;
		priv->staging_rxon.filter_flags = RXON_FILTER_ACCEPT_GRP_MSK;
		break;

	case IEEE80211_IF_TYPE_IBSS:
		priv->staging_rxon.dev_type = RXON_DEV_TYPE_IBSS;
		priv->staging_rxon.flags = RXON_FLG_SHORT_PREAMBLE_MSK;
		priv->staging_rxon.filter_flags = 0;
		break;

	case IEEE80211_IF_TYPE_MNTR:
		priv->staging_rxon.dev_type = RXON_DEV_TYPE_SNIFFER;
		priv->staging_rxon.filter_flags = RXON_FILTER_PROMISC_MSK |
		    RXON_FILTER_CTL2HOST_MSK | RXON_FILTER_ACCEPT_GRP_MSK;
		break;
	}

	if (priv->config & CFG_PREAMBLE_LONG)
		priv->staging_rxon.flags &= ~RXON_FLG_SHORT_PREAMBLE_MSK;

	ch_info = find_channel(priv, priv->active_conf.channel);
	if (ch_info == NULL)
		ch_info = &priv->channel_info[0];

	priv->staging_rxon.channel = ch_info->channel;
	priv->active_conf.channel = ch_info->channel;

	ipw_set_flags_for_channel(priv, ch_info);
	if (is_channel_a_band(ch_info))
		priv->active_conf.phymode = MODE_IEEE80211A;
	else
		priv->active_conf.phymode = MODE_IEEE80211G;

	priv->staging_rxon.ofdm_basic_rates =
	    R_6M_MSK | R_24M_MSK | R_36M_MSK | R_48M_MSK | R_54M_MSK |
	    R_9M_MSK | R_12M_MSK | R_18M_MSK;

	priv->staging_rxon.cck_basic_rates =
	    R_5_5M_MSK | R_1M_MSK | R_11M_MSK | R_2M_MSK;
}

void darwin_iwi4965::ipw_set_flags_for_channel(struct ipw_priv *priv,
				      const struct ipw_channel_info *ch_info)
{
	if (is_channel_a_band(ch_info)) {
		priv->staging_rxon.flags &=
		    ~(RXON_FLG_BAND_24G_MSK | RXON_FLG_AUTO_DETECT_MSK
		      | RXON_FLG_CCK_MSK);
		priv->staging_rxon.flags |= RXON_FLG_SHORT_SLOT_MSK;
	} else {
		priv->staging_rxon.flags &= ~RXON_FLG_SHORT_SLOT_MSK;
		priv->staging_rxon.flags |= RXON_FLG_BAND_24G_MSK;
		priv->staging_rxon.flags |= RXON_FLG_AUTO_DETECT_MSK;
		priv->staging_rxon.flags &= ~RXON_FLG_CCK_MSK;
	}
}

int darwin_iwi4965::ipw_update_power_cmd(struct ipw_priv *priv,
				struct ipw_powertable_cmd *cmd, u32 mode)
{
	int rc = 0, i;
	u8 skip = 0;
	u32 max_sleep = 0;
	struct ipw_power_vec_entry *range;
	u8 period = 0;
	struct ipw_power_mgr *pow_data;

	if ((mode < IPW_POWER_MODE_CAM) || (mode > IPW_POWER_INDEX_5)) {
		IOLog("Error invalid power mode \n");
		return -1;
	}
	pow_data = &(priv->power_data);

	if (pow_data->active_index == IPW_POWER_RANGE_0)
		range = &pow_data->pwr_range_0[0];
	else
		range = &pow_data->pwr_range_1[1];

	memcpy(cmd, &range[mode].cmd, sizeof(struct ipw_powertable_cmd));

#ifdef IPW_D80211_DISABLE
	if (priv->assoc_network != NULL) {
		unsigned long flags;

		period = priv->assoc_network->tim.tim_period;
	}
#endif				/*IPW_D80211_DISABLE */
	skip = range[mode].no_dtim;

	if (period == 0) {
		period = 1;
		skip = 0;
	}

	if (skip == 0) {
		max_sleep = period;
		cmd->flags &= ~PMC_TCMD_FLAG_SLEEP_OVER_DTIM_MSK;
	} else {
		max_sleep =
		    (cmd->
		     SleepInterval[PMC_TCMD_SLEEP_INTRVL_TABLE_SIZE -
				   1] / period) * period;
		cmd->flags |= PMC_TCMD_FLAG_SLEEP_OVER_DTIM_MSK;
	}

	for (i = 0; i < PMC_TCMD_SLEEP_INTRVL_TABLE_SIZE; i++) {
		if (cmd->SleepInterval[i] > max_sleep)
			cmd->SleepInterval[i] = max_sleep;
	}

	IOLog("Flags value = 0x%08X\n", cmd->flags);
	IOLog("Tx timeout = %u\n", cmd->TxDataTimeout);
	IOLog("Rx timeout = %u\n", cmd->RxDataTimeout);
	IOLog
	    ("Sleep interval vector = { %d , %d , %d , %d , %d }\n",
	     cmd->SleepInterval[0], cmd->SleepInterval[1],
	     cmd->SleepInterval[2], cmd->SleepInterval[3],
	     cmd->SleepInterval[4]);

	return rc;
}

int darwin_iwi4965::ipw_send_cmd_pdu(struct ipw_priv *priv, u8 id, u16 len, void *data)
{
	struct ipw_host_cmd cmd;
		cmd.id = id;
		cmd.len = len;
		cmd.data = data;

	return ipw_send_cmd(priv, &cmd);
}

int darwin_iwi4965::ipw3945_send_power_mode(struct ipw_priv *priv, u32 mode)
{
	int rc = 0;
	struct ipw_powertable_cmd cmd;

	ipw_update_power_cmd(priv, &cmd, mode);

	rc = ipw_send_cmd_pdu(priv, POWER_TABLE_CMD, sizeof(cmd), &cmd);
	return rc;
}

int darwin_iwi4965::ipw_send_power_mode(struct ipw_priv *priv, u32 mode)
{
	u32 final_mode = mode;
	int rc = 0;
	unsigned long flags;

	/* If on battery, set to 3, if AC set to CAM, else user
	 * level */
	switch (mode) {
	case IPW_POWER_BATTERY:
		final_mode = IPW_POWER_INDEX_3;
		break;
	case IPW_POWER_AC:
		final_mode = IPW_POWER_MODE_CAM;
		break;
	default:
		final_mode = mode;
		break;
	}

	//rc = priv->hw_setting.send_power_mode
	rc=ipw3945_send_power_mode(priv, final_mode);

	//spin_lock_irqsave(&priv->lock, flags);

	if (final_mode == IPW_POWER_MODE_CAM) {
		priv->status &= ~STATUS_POWER_PMI;
	} else {
		priv->status |= STATUS_POWER_PMI;
	}

	//spin_unlock_irqrestore(&priv->lock, flags);
	return rc;
}

int darwin_iwi4965::ipw_rate_plcp2index(u8 x)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(rate_table_info); i++) {
		if (rate_table_info[i].rate_plcp == x)
			return i;
	}
	return -1;
}

struct ieee80211_hw_mode *darwin_iwi4965::ipw_get_current_hw(struct ipw_priv *priv)
{
	struct ieee80211_hw_mode *hw_mode;
	struct ieee80211_local *local = hw_to_local(priv->ieee);

	list_for_each_entry(hw_mode, &local->modes_list, list)
		if (hw_mode->mode == priv->active_conf.phymode)
			return hw_mode;

	return NULL;
}

void darwin_iwi4965::ipw_set_supported_rates(struct ipw_priv *priv)
{
	struct ieee80211_hw_mode *hw = NULL;
	int index, i;
	struct ieee80211_rate *rate;

	priv->active_rate = 0;
	priv->active_rate_basic = 0;

	hw = ipw_get_current_hw(priv);
	if (!hw || !hw->rates)
		return;

	for (i = 0; i < hw->num_rates; i++) {
		rate = &(hw->rates[i]);
		index = ipw_rate_plcp2index(rate->val);
		if ((index != -1) && (rate->flags & IEEE80211_RATE_SUPPORTED)) {
			priv->active_rate |= (1 << index);
			if (rate->flags & IEEE80211_RATE_BASIC)
				priv->active_rate_basic |= (1 << index);
		}
	}
}

int darwin_iwi4965::ipw_set_rate(struct ipw_priv *priv)
{
	ipw_set_supported_rates(priv);
	priv->staging_rxon.cck_basic_rates =
	    ((priv->active_rate_basic & 0xF) | R_1M_MSK);
	priv->staging_rxon.ofdm_basic_rates =
	    ((priv->active_rate_basic >> 4) | R_6M_MSK);

	if ((priv->active_rate_basic & 0xF) == 0)
		priv->staging_rxon.cck_basic_rates =
		    R_1M_MSK | R_2M_MSK | R_5_5M_MSK | R_11M_MSK;
	if (priv->active_rate_basic >> 4 == 0)
		priv->staging_rxon.ofdm_basic_rates =
			R_6M_MSK | R_12M_MSK | R_24M_MSK;

	return 0;
}

void darwin_iwi4965::getPacketBufferConstraints(IOPacketBufferConstraints * constraints) const {
    constraints->alignStart  = kIOPacketBufferAlign4;	// even word aligned.
    constraints->alignLength = kIOPacketBufferAlign4;	// no restriction.
}

int darwin_iwi4965::ipw_scan_initiate(struct ipw_priv *priv, unsigned long ms)
{
	if (priv->status & STATUS_SCANNING) {
		IOLog("Scan already in progress.\n");
		return 0;
	}

	if (priv->status & STATUS_EXIT_PENDING) {
		IOLog("Aborting scan due to device shutdown\n");
		priv->status |= STATUS_SCAN_PENDING;
		return 0;
	}

	if (priv->status & STATUS_SCAN_ABORTING) {
		IOLog("Scan request while abort pending.  Queuing.\n");
		priv->status |= STATUS_SCAN_PENDING;
		return 0;
	}

	if (priv->status & STATUS_RF_KILL_MASK) {
		IOLog("Aborting scan due to RF Kill activation\n");
		priv->status |= STATUS_SCAN_PENDING;
		return 0;
	}

	if (!(priv->status & STATUS_READY)) {
		IOLog("Scan request while uninitialized.  Queuing.\n");
		priv->status |= STATUS_SCAN_PENDING;
		return 0;
	}

	IOLog("Setting scan to on\n");
 	priv->scan_bands = 2;
	priv->status |= STATUS_SCANNING;
	priv->scan_start = jiffies;
	priv->scan_pass_start = priv->scan_start;

	return ipw_scan_schedule(priv, ms);
}

int darwin_iwi4965::ipw_scan_schedule(struct ipw_priv *priv, unsigned long ms)
{
	if (priv->status & STATUS_SCAN_ABORTING) {
		IOLog
		    ("Scan abort in progress.  Deferring scan " "request.\n");
		priv->status |= STATUS_SCAN_PENDING;
		return 0;
	}
	queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan),priv,3,true);
	//queue_delayed_work(priv->workqueue,   &priv->request_scan, msecs_to_jiffies(ms));

	return 0;
}

int darwin_iwi4965::ipw_scan_completed(struct ipw_priv *priv, int success)
{
	/* The HW is no longer scanning */
	priv->status &= ~STATUS_SCAN_HW;

	/* The scan completion notification came in, so kill that timer... */
	//cancel_delayed_work(&priv->scan_check);
	queue_td(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan_check));

	IOLog("Scan pass on %sGhz\n",
		       (priv->scan_bands == 2) ? "2.4" : "5.2");

	/* Remove this scanned band from the list
	 * of pending bands to scan */
	priv->scan_bands--;

	/* If a request to abort was given, or the scan did not succeed
	 * then we reset the scan state machine and terminate,
	 * re-queuing another scan if one has been requested */
	if (priv->status & STATUS_SCAN_ABORTING) {
		IOLog("Aborted scan completed.\n");
		priv->status &= ~STATUS_SCAN_ABORTING;
	} else {
		/* If there are more bands on this scan pass reschedule */
		if (priv->scan_bands > 0)
			goto reschedule;
	}

	IOLog("Setting scan to off\n");

	priv->one_direct_scan = 0;
	priv->status &= ~STATUS_SCANNING;

	//IOLog("Scan took %dms\n",
	//	       jiffies_to_msecs(elapsed_jiffies
	//				(priv->scan_start, jiffies)));

	//queue_work(priv->workqueue, &priv->update_link_led);

	if (priv->status & STATUS_SCAN_PENDING)
		ipw_scan_initiate(priv, 0);

	return 0;

      reschedule:
	priv->scan_pass_start = jiffies;
	ipw_scan_schedule(priv, 0);

	return 0;
}

int darwin_iwi4965::x2_queue_used(const struct ipw_queue *q, int i)
{
	return q->first_empty > q->last_used ?
	    (i >= q->last_used && i < q->first_empty) :
	    !(i < q->last_used && i >= q->first_empty);
}

void darwin_iwi4965::ipw_handle_reply_tx(struct ipw_priv *priv, void *data, u16 sequence)
{
	int fifo = SEQ_TO_FIFO(sequence);
	int index = SEQ_TO_INDEX(sequence);
	struct ipw_tx_queue *txq = &priv->txq[fifo];
	struct ieee80211_tx_status *status;
	struct ipw_tx_resp *resp = (struct ipw_tx_resp *)data;

	if ((index >= txq->q.n_bd) || (x2_queue_used(&txq->q, index) == 0)) {
		IOLog("Read index for DMA queue (%d) "
			  "is out of range [0-%d) %d %d\n",
			  index, txq->q.n_bd, txq->q.first_empty,
			  txq->q.last_used);
		return;
	}

	status = &(txq->txb[txq->q.last_used].status);
	status->flags = ((resp->status & 0xFF) == 0x1) ?
		IEEE80211_TX_STATUS_ACK : 0;
	status->retry_count = resp->failure_frame;
	status->queue_number = resp->status;
	status->queue_length = resp->bt_kill_count;
	status->queue_length |= resp->failure_rts;
	status->control.tx_rate = resp->rate;

	IOLog("Tx fifo %d Status %s (0x%08x) plcp rate %d retries %d\n",
		     fifo, get_tx_fail_reason(resp->status),
		     resp->status, resp->rate, resp->failure_frame);

	//if (check_bits(resp->status, TX_ABORT_REQUIRED_MSK)) {
	//	IOLog("TODO:  Impelment Tx ABORT REQUIRED!!!\n");
	//}

	return;
}

int darwin_iwi4965::is_network_packet(struct ipw_priv *priv,
			     struct ieee80211_hdr *header)
{
	/* Filter incoming packets to determine if they are targetted toward
	 * this network, discarding packets coming from ourselves */
	switch (priv->iw_mode) {
	case IEEE80211_IF_TYPE_IBSS:	/* Header: Dest. | Source    | BSSID */
		/* packets from our adapter are dropped (echo) */
		if (!memcmp(header->addr2, priv->net_dev->dev_addr, ETH_ALEN))
			return 0;
		/* {broad,multi}cast packets to our IBSS go through */
		if (ipw_is_broadcast_ether_addr(header->addr1) ||
		    is_multicast_ether_addr(header->addr1))
			return !memcmp(header->addr3, priv->bssid, ETH_ALEN);
		/* packets to our adapter go through */
		return !memcmp(header->addr1, priv->net_dev->dev_addr,
			       ETH_ALEN);
	case IEEE80211_IF_TYPE_STA:	/* Header: Dest. | AP{BSSID} | Source */
		/* packets from our adapter are dropped (echo) */
		if (!memcmp(header->addr3, priv->net_dev->dev_addr, ETH_ALEN))
			return 0;
		/* {broad,multi}cast packets to our BSS go through */
		if (ipw_is_broadcast_ether_addr(header->addr1) ||
		    is_multicast_ether_addr(header->addr1))
			return !memcmp(header->addr2, priv->bssid, ETH_ALEN);
		/* packets to our adapter go through */
		return !memcmp(header->addr1, priv->net_dev->dev_addr,
			       ETH_ALEN);
	}

	return 1;
}

static const unsigned char rfc1042_header[] =
	{ 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };

/* Bridge-Tunnel header (for EtherTypes ETH_P_AARP and ETH_P_IPX) */
static const unsigned char bridge_tunnel_header[] =
	{ 0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8 };
	
int darwin_iwi4965::ieee80211_rx( mbuf_t skb,
		 struct ieee80211_rx_stats *rx_stats)
{
	struct ieee80211_hdr_4addr *hdr;
	size_t hdrlen;
	u16 fc, type, stype, sc;
	struct net_device_stats *stats;
	unsigned int frag;
	u8 *payload;
	u16 ethertype;
	
	u8 dst[ETH_ALEN];
	u8 src[ETH_ALEN];

	hdr = (struct ieee80211_hdr_4addr *)mbuf_data(skb);
	//stats = &ieee->stats;

	if (mbuf_pkthdr_len(skb) < 10) {
	//	IWI_DEBUG( "%s: SKB length < 10\n", ieee->dev->name);
		goto rx_dropped;
	}

	fc = le16_to_cpu(hdr->frame_ctl);
	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);
	sc = le16_to_cpu(hdr->seq_ctl);
	frag = WLAN_GET_SEQ_FRAG(sc);
	hdrlen = ieee80211_get_hdrlen(fc);


//	if (ieee->iw_mode == IW_MODE_MONITOR) {
		//stats->rx_packets++;
		//stats->rx_bytes += mbuf_pkthdr_len(skb);
		//ieee80211_monitor_rx(ieee, skb, rx_stats);
//		return 1;
//	}

	/*can_be_decrypted = (is_multicast_ether_addr(hdr->addr1) ||
			    is_broadcast_ether_addr(hdr->addr2)) ?
	    ieee->host_mc_decrypt : ieee->host_decrypt;

	if (can_be_decrypted) {
		int idx = 0;
		if (mbuf_len(skb) >= hdrlen + 3) {
			idx = ((UInt8*)(mbuf_data(skb)))[hdrlen + 3] >> 6;
		}


		crypt = ieee->crypt[idx];

		if (crypt && (crypt->ops == NULL ||
			      crypt->ops->decrypt_mpdu == NULL))
			crypt = NULL;

		if (!crypt && (fc & IEEE80211_FCTL_PROTECTED)) {
			IWI_DEBUG("Decryption failed (not set)"
					     " (SA=" MAC_FMT ")\n",
					     MAC_ARG(hdr->addr2));
			ieee->ieee_stats.rx_discards_undecryptable++;
			goto rx_dropped;
		}
	}*/

	/* Data frame - extract src/dst addresses */
	if (mbuf_pkthdr_len(skb) < IEEE80211_3ADDR_LEN)
		goto rx_dropped;

	switch (fc & (IEEE80211_FCTL_FROMDS | IEEE80211_FCTL_TODS)) {
	case IEEE80211_FCTL_FROMDS:
		memcpy(dst, hdr->addr1, ETH_ALEN);
		memcpy(src, hdr->addr3, ETH_ALEN);
		break;
	case IEEE80211_FCTL_TODS:
		memcpy(dst, hdr->addr3, ETH_ALEN);
		memcpy(src, hdr->addr2, ETH_ALEN);
		break;
	case IEEE80211_FCTL_FROMDS | IEEE80211_FCTL_TODS:
		if (mbuf_pkthdr_len(skb) < IEEE80211_4ADDR_LEN)
			goto rx_dropped;
		memcpy(dst, hdr->addr3, ETH_ALEN);
		memcpy(src, hdr->addr4, ETH_ALEN);
		break;
	case 0:
		memcpy(dst, hdr->addr1, ETH_ALEN);
		memcpy(src, hdr->addr2, ETH_ALEN);
		break;
	}
	


	//dev->last_rx = jiffies;


	/* Nullfunc frames may have PS-bit set, so they must be passed to
	 * hostap_handle_sta_rx() before being dropped here. */

	stype &= ~IEEE80211_STYPE_QOS_DATA;

	if (stype != IEEE80211_STYPE_DATA &&
	    stype != IEEE80211_STYPE_DATA_CFACK &&
	    stype != IEEE80211_STYPE_DATA_CFPOLL &&
	    stype != IEEE80211_STYPE_DATA_CFACKPOLL) {
		if (stype != IEEE80211_STYPE_NULLFUNC)
			IWI_DEBUG("RX: dropped data frame "
					     "with no data (type=0x%02x, "
					     "subtype=0x%02x, len=%d)\n",
					     type, stype, mbuf_pkthdr_len(skb));
		goto rx_dropped;
	}

	/* skb: hdr + (possibly fragmented, possibly encrypted) payload */

	//if ((fc & IEEE80211_FCTL_PROTECTED) && can_be_decrypted  /* &&
	  //  (keyidx = ieee80211_rx_frame_decrypt(ieee, skb, crypt)) < 0 */ )
	//	goto rx_dropped;

	//hdr = (struct ieee80211_hdr_4addr *)mbuf_data(skb);

	// skb: hdr + (possibly fragmented) plaintext payload 
	// PR: FIXME: hostap has additional conditions in the "if" below:
	// ieee->host_decrypt && (fc & IEEE80211_FCTL_PROTECTED) &&
	/*if ((frag != 0) || (fc & IEEE80211_FCTL_MOREFRAGS)) {
		int flen;
		mbuf_t frag_skb = ieee80211_frag_cache_get(ieee, hdr);
		IWI_DEBUG_FULL("Rx Fragment received (%u)\n", frag);

		if (!frag_skb) {
			IWI_DEBUG("Rx cannot get skb from fragment "
					"cache (morefrag=%d seq=%u frag=%u)\n",
					(fc & IEEE80211_FCTL_MOREFRAGS) != 0,
					WLAN_GET_SEQ_SEQ(sc), frag);
			goto rx_dropped;
		}

		flen = mbuf_len(skb);
		if (frag != 0)
			flen -= hdrlen;
		
		//if (frag_skb->tail + flen > frag_skb->end) { 
		// skb->tail  := mbuf_data(skb)+mbuf_len(skb) 
		// skb->end := mbuf_datastart(skb)+mbuf_maxlen(skb) 
		if (  (UInt8*)mbuf_data(frag_skb) + mbuf_len(frag_skb)  + flen > (UInt8*)mbuf_datastart(frag_skb) + mbuf_maxlen(frag_skb)  ) {
			IWI_DEBUG( "%s: host decrypted and "
			       "reassembled frame did not fit skb\n",
			       dev->name);
			ieee80211_frag_cache_invalidate(ieee, hdr);
			goto rx_dropped;
		}

		if (frag == 0) {
			// copy first fragment (including full headers) into
			 // beginning of the fragment cache skb 
			memcpy(skb_put(frag_skb, flen), (UInt8*)mbuf_data(skb), flen);
		} else {
			// append frame payload to the end of the fragment
			 // cache skb 
			memcpy(skb_put(frag_skb, flen), (UInt8*)mbuf_data(skb) + hdrlen,
			       flen);
		}
		//dev_kfree_skb_any(skb);
		if (skb != NULL) {
			//freePacket(skb);
		}
		skb = NULL;

		if (fc & IEEE80211_FCTL_MOREFRAGS) {
			// more fragments expected - leave the skb in fragment
			 // cache for now; it will be delivered to upper layers
			 //after all fragments have been received 
			goto rx_exit;
		}

		// this was the last fragment and the frame will be
		 // delivered, so remove skb from fragment cache 
		skb = frag_skb;
		hdr = (struct ieee80211_hdr_4addr *)(mbuf_data(skb));
		ieee80211_frag_cache_invalidate(ieee, hdr);
	}*/

	/* skb: hdr + (possible reassembled) full MSDU payload; possibly still
	  encrypted/authenticated  */
	//if ((fc & IEEE80211_FCTL_PROTECTED) && can_be_decrypted /*&&
	  //  ieee80211_rx_frame_decrypt_msdu(ieee, skb, keyidx, crypt) */   )
		//goto rx_dropped;

	/*hdr = (struct ieee80211_hdr_4addr *)(mbuf_data(skb));
	if (crypt && !(fc & IEEE80211_FCTL_PROTECTED) && !ieee->open_wep) {
		if (		
			   ieee80211_is_eapol_frame(ieee, skb)) {
			// pass unencrypted EAPOL frames even if encryption is
			 // configured 
		} else {
			IWI_DEBUG("encryption configured, but RX "
					     "frame not encrypted (SA=" MAC_FMT
					     ")\n", MAC_ARG(hdr->addr2));
			goto rx_dropped;
		}
	}

	if (crypt && !(fc & IEEE80211_FCTL_PROTECTED) && !ieee->open_wep &&
	    !ieee80211_is_eapol_frame(ieee, skb)) {
		IWI_DEBUG("dropped unencrypted RX data "
				     "frame from " MAC_FMT
				     " (drop_unencrypted=1)\n",
				     MAC_ARG(hdr->addr2));
		goto rx_dropped;
	}*/

	/* skb: hdr + (possible reassembled) full plaintext payload */

	payload = ((UInt8*)mbuf_data(skb) + hdrlen);
	ethertype = (payload[6] << 8) | payload[7];



	/* convert hdr + possible LLC headers into Ethernet header */
	if ( mbuf_pkthdr_len(skb) - hdrlen >= 8 &&
	    ((memcmp(payload, rfc1042_header, SNAP_SIZE) == 0 &&
	      ethertype != ETH_P_AARP && ethertype != ETH_P_IPX) ||
	     memcmp(payload, bridge_tunnel_header, SNAP_SIZE) == 0)) {
		/* remove RFC1042 or Bridge-Tunnel encapsulation and
		 * replace EtherType */
		skb_pull(skb, hdrlen + SNAP_SIZE);
		//mbuf_adj(skb, hdrlen + SNAP_SIZE);
		memcpy(skb_push(skb, ETH_ALEN), src, ETH_ALEN);
		memcpy(skb_push(skb, ETH_ALEN), dst, ETH_ALEN);
		//memcpy(((UInt8*)mbuf_data(skb) + ETH_ALEN), src, ETH_ALEN);
		//memcpy(((UInt8*)mbuf_data(skb) +ETH_ALEN), dst, ETH_ALEN);
	} else {
		u16 len;
		/* Leave Ethernet header part of hdr and full payload */
		skb_pull(skb, hdrlen);
		//mbuf_adj(skb, hdrlen);
		len = htons(mbuf_pkthdr_len(skb));
		memcpy(skb_push(skb, 2), &len, 2);
		memcpy(skb_push(skb, ETH_ALEN), src, ETH_ALEN);
		memcpy(skb_push(skb, ETH_ALEN), dst, ETH_ALEN);
		//memcpy(((UInt8*)mbuf_data(skb) + 2), &len, 2);
		//memcpy(((UInt8*)mbuf_data(skb) + ETH_ALEN), src, ETH_ALEN);
		//memcpy(((UInt8*)mbuf_data(skb) + ETH_ALEN), dst, ETH_ALEN);
	}

	netStats->inputPackets++;
	//stats->rx_packets++;
	//stats->rx_bytes += mbuf_pkthdr_len(skb);


	if (skb) {
		//skb->protocol = eth_type_trans(skb, dev);
		//memset(skb->cb, 0, sizeof(skb->cb));
		//skb->dev = dev;
		//skb->ip_summed = CHECKSUM_NONE;	/* 802.11 crc not sufficient */
		if( mbuf_flags(skb) & MBUF_PKTHDR){
		
			//if (ifnet_input(fifnet,skb,NULL)!=0) goto rx_dropped;
			fNetif->inputPacket(skb,mbuf_pkthdr_len(skb),IONetworkInterface::kInputOptionQueuePacket);
		}else{
			IWI_ERR("this packet dont have MBUF_PKTHDR\n");
			//fNetif->inputPacket(skb,mbuf_len(skb),IONetworkInterface::kInputOptionQueuePacket);
			goto rx_dropped;
		}
		//if (netif_rx(skb) == NET_RX_DROP) {
			/* netif_rx always succeeds, but it might drop
			 * the packet.  If it drops the packet, we log that
			 * in our stats. */
		//	IWI_DEBUG ("RX: netif_rx dropped the packet\n");
		//	stats->rx_dropped++;
		//}
	}

      rx_exit:

	return 1;

      rx_dropped:
	IWI_DEBUG("rx dropped %d\n",stats->rx_dropped);
	//stats->rx_dropped++;
	netStats->inputErrors++;
	/* Returning 0 indicates to caller that we have not handled the SKB--
	 * so it is still allocated and can be used again by underlying
	 * hardware as a DMA target */
	return 0;
}



void darwin_iwi4965::ipw_handle_data_packet(struct ipw_priv *priv, int is_data,
				   struct ipw_rx_mem_buffer *rxb,
				   struct ieee80211_rx_status *stats)
{
	IOLog("ipw_handle_data_packet\n");
	struct ieee80211_hdr *hdr;
	struct ipw_rx_packet *pkt = (struct ipw_rx_packet *)mbuf_data(rxb->skb);
	struct ipw_rx_frame_hdr *rx_hdr = IPW_RX_HDR(pkt);
	struct ipw_rx_frame_end *rx_end = IPW_RX_END(pkt);
	short len = le16_to_cpu(rx_hdr->len);

	/* We received data from the HW, so stop the watchdog */
	//ieee80211_netif_oper(priv->ieee, NETIF_UPDATE_TX_START);
	if (unlikely((len + IPW_RX_FRAME_SIZE) > mbuf_pkthdr_len(rxb->skb))) {
		//priv->wstats.discard.misc++;
		IOLog("Corruption detected! Oh no!\n");
		return;
	}

	/* We only process data packets if the interface is open */
	if (!(fNetif->getFlags() & IFF_RUNNING)) {
		//priv->wstats.discard.misc++;
		IOLog("Dropping packet while interface is not up.\n");
		return;
	}
	if (priv->iw_mode == IEEE80211_IF_TYPE_MNTR) {
		/*if (param_hwcrypto)
			ipw_set_decrypted_flag(priv, rxb->skb, rx_end->status,
					       stats);
		ipw_handle_data_packet_monitor(priv, rxb, IPW_RX_DATA(pkt), len,
					       stats);*/
		return;
	}

	stats->flag = 0;
//	skb_reserve(rxb->skb, (void *)rx_hdr->payload - (void *)pkt);
	/* Set the size of the skb to the size of the frame */
//	skb_put(rxb->skb, le16_to_cpu(rx_hdr->len));
//todo check iwi2200 code
mbuf_setdata(rxb->skb,(UInt8*)mbuf_data(rxb->skb) + ((UInt8*)rx_hdr->payload - (UInt8*)pkt), le16_to_cpu(rx_hdr->len));

	if( mbuf_flags(rxb->skb) & MBUF_PKTHDR)
			mbuf_pkthdr_setlen(rxb->skb, le16_to_cpu(rx_hdr->len));
			
	hdr = (struct ieee80211_hdr*)mbuf_data(rxb->skb);
	priv->rx_bytes += mbuf_pkthdr_len(rxb->skb) -
	    ieee80211_get_hdrlen(le16_to_cpu(hdr->frame_control));

	//if (param_hwcrypto)
	//	ipw_set_decrypted_flag(priv, rxb->skb, rx_end->status, stats);

	ieee80211_rx(rxb->skb, NULL);
	rxb->skb = NULL;
	priv->led_packets += rx_hdr->len;
	//ipw_setup_activity_timer(priv);
}



static u8 ipw_lower_rate_g[NUM_RATES] = {
	RATE_SCALE_5_5M_INDEX, RATE_SCALE_5_5M_INDEX,
	RATE_SCALE_11M_INDEX, RATE_SCALE_12M_INDEX,
	RATE_SCALE_18M_INDEX, RATE_SCALE_24M_INDEX,
	RATE_SCALE_36M_INDEX, RATE_SCALE_48M_INDEX,
	255, RATE_SCALE_1M_INDEX, RATE_SCALE_2M_INDEX,
	RATE_SCALE_5_5M_INDEX,

};

static u8 ipw_higher_rate_g[NUM_RATES] = {
	RATE_SCALE_11M_INDEX, RATE_SCALE_11M_INDEX,
	RATE_SCALE_18M_INDEX,
	RATE_SCALE_24M_INDEX, RATE_SCALE_36M_INDEX,
	RATE_SCALE_48M_INDEX,
	RATE_SCALE_54M_INDEX, 255, RATE_SCALE_2M_INDEX,
	RATE_SCALE_5_5M_INDEX, RATE_SCALE_11M_INDEX,
	RATE_SCALE_12M_INDEX
};

static s32 ipw_expected_tpt_g[NUM_RATES] = {
	0, 0, 76, 104, 130, 168, 191, 202, 7, 13, 35, 58
};

static s32 ipw_expected_tpt_g_prot[NUM_RATES] = {
	0, 0, 0, 80, 93, 113, 123, 125, 7, 13, 35, 58
};

static s32 ipw_expected_tpt_a[NUM_RATES] = {
	40, 57, 72, 98, 121, 154, 177, 186, 0, 0, 0, 0
};

static s32 ipw_expected_tpt_b[NUM_RATES] = {
	0, 0, 0, 0, 0, 0, 0, 0, 7, 13, 35, 58
};
	

static u8 ipw_lower_rate_g_prot[NUM_RATES] = {
	RATE_SCALE_5_5M_INDEX, RATE_SCALE_5_5M_INDEX,
	RATE_SCALE_11M_INDEX,
	RATE_SCALE_11M_INDEX, RATE_SCALE_18M_INDEX,
	RATE_SCALE_24M_INDEX,
	RATE_SCALE_36M_INDEX, RATE_SCALE_48M_INDEX, 255,
	RATE_SCALE_1M_INDEX, RATE_SCALE_2M_INDEX,
	RATE_SCALE_5_5M_INDEX,
};

static u8 ipw_higher_rate_g_prot[NUM_RATES] = {
	RATE_SCALE_11M_INDEX, RATE_SCALE_11M_INDEX,
	RATE_SCALE_18M_INDEX,
	RATE_SCALE_24M_INDEX, RATE_SCALE_36M_INDEX,
	RATE_SCALE_48M_INDEX,
	RATE_SCALE_54M_INDEX, 255, RATE_SCALE_2M_INDEX,
	RATE_SCALE_5_5M_INDEX, RATE_SCALE_11M_INDEX,
	RATE_SCALE_18M_INDEX
};

static struct ipw_tpt_entry ipw_tpt_table_a[] = {
	{-60, 22000, 0, 0, RATE_SCALE_54M_INDEX},
	{-64, 20000, 0, 0, RATE_SCALE_48M_INDEX},
	{-72, 18000, 0, 0, RATE_SCALE_36M_INDEX},
	{-80, 16000, 0, 0, RATE_SCALE_24M_INDEX},
	{-84, 12000, 0, 0, RATE_SCALE_18M_INDEX},
	{-85, 8000, 0, 0, RATE_SCALE_12M_INDEX},
	{-87, 7000, 0, 0, RATE_SCALE_9M_INDEX},
	{-89, 5000, 0, 0, RATE_SCALE_6M_INDEX}
};

static struct ipw_tpt_entry ipw_tpt_table_b[] = {
	{-86, 6000, 0, 0, RATE_SCALE_11M_INDEX},
	{-88, 3000, 0, 0, RATE_SCALE_5_5M_INDEX},
	{-90, 1000, 0, 0, RATE_SCALE_2M_INDEX},
	{-92, 800, 0, 0, RATE_SCALE_1M_INDEX}

};

static struct ipw_tpt_entry ipw_tpt_table_g[] = {
	{-60, 22000, 12000, 14000, RATE_SCALE_54M_INDEX},
	{-64, 20000, 11000, 13000, RATE_SCALE_48M_INDEX},
	{-68, 18000, 10000, 14000, RATE_SCALE_36M_INDEX},
	{-80, 16000, 9000, 11000, RATE_SCALE_24M_INDEX},
	{-84, 12000, 7000, 10000, RATE_SCALE_18M_INDEX},
	{-85, 8000, 5000, 8000, RATE_SCALE_12M_INDEX},
	{-86, 6000, 6000, 6000, RATE_SCALE_11M_INDEX},
	{-88, 3000, 3000, 3000, RATE_SCALE_5_5M_INDEX},
	{-90, 1000, 1000, 1000, RATE_SCALE_2M_INDEX},
	{-92, 800, 800, 800, RATE_SCALE_1M_INDEX}
};
	
struct ipw_tpt_entry *darwin_iwi4965::ipw_get_tpt_by_rssi(s32 rssi, u8 mode)
{
	u32 index = 0;
	u32 table_size = 0;
	struct ipw_tpt_entry *tpt_table = NULL;

	if ((rssi < IPW_MIN_RSSI_VAL) || (rssi > IPW_MAX_RSSI_VAL))
		rssi = IPW_MIN_RSSI_VAL;

	switch (mode) {
	case MODE_IEEE80211G:
		tpt_table = ipw_tpt_table_g;
		table_size = ARRAY_SIZE(ipw_tpt_table_g);
		break;

	case MODE_IEEE80211B:
		tpt_table = ipw_tpt_table_b;
		table_size = ARRAY_SIZE(ipw_tpt_table_b);
		break;

	case MODE_IEEE80211A:
		tpt_table = ipw_tpt_table_a;
		table_size = ARRAY_SIZE(ipw_tpt_table_a);
		break;

	default:
		return NULL;
	}

	while ((index < table_size)
	       && (rssi < tpt_table[index].min_rssi))
		index++;

	index = min(index, (table_size - 1));

	return &tpt_table[index];
}

u8 darwin_iwi4965::ipw_rate_scale2plcp(int x)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(rate_table_info); i++) {
		if (rate_table_info[i].rate_scale_index == x)
			return rate_table_info[i].rate_plcp;
	}
	return IPW_INVALID_RATE;
}

u8 darwin_iwi4965::ipw_sync_station(struct ipw_priv *priv, int sta_id,
			   u16 tx_rate, u8 flags)
{

	if (sta_id != IPW_INVALID_STATION) {
		unsigned long flags_spin;

		//spin_lock_irqsave(&priv->sta_lock, flags_spin);

		priv->stations[sta_id].sta.sta.modify_mask =
		    STA_CONTROL_MODIFY_MSK;
		priv->stations[sta_id].sta.tx_rate.rate_n_flags = tx_rate;
		priv->stations[sta_id].current_rate.rate_n_flags = tx_rate;
		priv->stations[sta_id].sta.ctrlAddModify =
		    STA_CONTROL_MODIFY_MSK;

		//spin_unlock_irqrestore(&priv->sta_lock, flags_spin);

		ipw_send_add_station(priv, &priv->stations[sta_id].sta, flags);
		IOLog("SCALE sync station %d to rate %d\n",
			       sta_id, tx_rate);
		return sta_id;
	}

	return IPW_INVALID_STATION;
}
	
int darwin_iwi4965::ipw_rate_scale_rxon_handle(struct ipw_priv *priv, s32 sta_id)
{
	int rc = 0;
	int i;
	s32 rssi = 0;
	struct ipw_tpt_entry *entry = NULL;
	unsigned long flags;
	struct ieee80211_conf *conf = NULL;

	conf = ieee80211_get_hw_conf(priv->ieee);

	if (!ipw_is_associated(priv))
		return 0;

	//spin_lock_irqsave(&priv->lq_mngr.lock, flags);

	priv->lq_mngr.next_lower_rate = ipw_lower_rate_g;
	priv->lq_mngr.next_higher_rate = ipw_higher_rate_g;

	switch (priv->active_conf.phymode) {
	case MODE_IEEE80211G:
		if (priv->active_rxon.flags & RXON_FLG_TGG_PROTECT_MSK) {
			priv->lq_mngr.expected_tpt = ipw_expected_tpt_g_prot;
			priv->lq_mngr.next_higher_rate =
				ipw_higher_rate_g_prot;
			priv->lq_mngr.next_lower_rate = ipw_lower_rate_g_prot;
		} else {
			priv->lq_mngr.expected_tpt = ipw_expected_tpt_g;
			priv->lq_mngr.next_lower_rate = ipw_lower_rate_g;
			priv->lq_mngr.next_higher_rate = ipw_higher_rate_g;
		}
		break;

	case MODE_IEEE80211B:
		priv->lq_mngr.expected_tpt = ipw_expected_tpt_b;
		break;

	case MODE_IEEE80211A:
		priv->lq_mngr.expected_tpt = ipw_expected_tpt_a;
		break;
	default:
		IOLog( "Invalid mode in rxon_handle\n");
		return -EINVAL;
	}

	rssi = priv->last_rx_rssi;
	if (rssi == 0)
		rssi = IPW_MIN_RSSI_VAL;

	IOLog("Network RSSI: %d\n", rssi);

	IOLog("Network RSSI: %d\n", rssi);
	entry = ipw_get_tpt_by_rssi(rssi, priv->active_conf.phymode);
	if (entry)
		i = entry->rate_scale_index;
	else if (priv->active_conf.phymode == MODE_IEEE80211A)
		i = RATE_SCALE_6M_INDEX;
	else
		i = RATE_SCALE_1M_INDEX;

	priv->stations[sta_id].current_rate.s.rate =
		ipw_rate_scale2plcp(i);

	ipw_sync_station(priv, sta_id,
			 priv->stations[sta_id].current_rate.rate_n_flags,
			 CMD_ASYNC | CMD_NO_LOCK);

	IOLog
		("for rssi %d assign rate scale index %d plcp %x\n", rssi,
		 i, priv->stations[sta_id].sta.tx_rate.rate_n_flags);

	//spin_unlock_irqrestore(&priv->lq_mngr.lock, flags);

	return rc;
}

void darwin_iwi4965::ipw_bg_post_associate()
{
	//struct ipw_priv *priv = container_of(work, struct ipw_priv, post_associate);
	struct ieee80211_conf *conf = NULL;

	if (priv->status & STATUS_EXIT_PENDING)
		return;

	//mutex_lock(&priv->mutex);

	conf = ieee80211_get_hw_conf(priv->ieee);

	memset(&priv->rxon_timing, 0, sizeof(struct ipw_rxon_time_cmd));
/*	ipw_setup_rxon_timing(priv);
	ipw_send_cmd_pdu(priv, REPLY_RXON_TIMING,
			 sizeof(priv->rxon_timing), &priv->rxon_timing);
*/
	priv->staging_rxon.assoc_id = priv->assoc_id;
	ipw_commit_rxon(priv);

	switch (priv->iw_mode) {
	case IEEE80211_IF_TYPE_STA:
		if (ipw_rxon_add_station(priv, priv->bssid, 1) ==
		    IPW_INVALID_STATION) {
			IOLog("Could not add STA " MAC_FMT "\n",
				    MAC_ARG(priv->bssid));
			break;
		}

		ipw_rate_scale_rxon_handle(priv, AP_ID);

		break;

	case IEEE80211_IF_TYPE_IBSS:

		/* clear out the station table */
		ipw_clear_stations_table(priv);

		ipw_rxon_add_station(priv, BROADCAST_ADDR, 0);
		ipw_rxon_add_station(priv, priv->bssid, 0);
		ipw_rate_scale_rxon_handle(priv, STA_ID);
		//ipw_send_beacon_cmd(priv);

		break;
	}

	ipw_link_up(priv);

	//mutex_unlock(&priv->mutex);
}
			
void darwin_iwi4965::ipw_handle_reply_rx(struct ipw_priv *priv,
				struct ipw_rx_mem_buffer *rxb)
{
	struct ipw_rx_packet *pkt = (struct ipw_rx_packet*)mbuf_data(rxb->skb);
	struct ipw_rx_frame_stats *rx_stats = IPW_RX_STATS(pkt);
	struct ipw_rx_frame_hdr *rx_hdr = IPW_RX_HDR(pkt);
	struct ipw_rx_frame_end *rx_end = IPW_RX_END(pkt);
	struct ieee80211_hdr *header;
	struct ieee80211_rx_status stats;
		stats.mactime = rx_end->beaconTimeStamp;
		stats.freq =
		(rx_hdr->
		 phy_flags & RX_RES_PHY_FLAGS_BAND_24_MSK) ?
		IEEE80211_24GHZ_BAND : IEEE80211_52GHZ_BAND;
		stats.channel = rx_hdr->channel;
		stats.phymode =
		(rx_hdr->
		 phy_flags & RX_RES_PHY_FLAGS_BAND_24_MSK) ?
		MODE_IEEE80211G : MODE_IEEE80211A;
		stats.ssi = rx_stats->rssi - IPW_RSSI_OFFSET;
		stats.antenna = 0;
		stats.rate = rx_hdr->rate;
		stats.flag = rx_hdr->phy_flags;

	u8 network_packet;
	if ((unlikely(rx_stats->mib_count > 20))) {
		IOLog
			("dsp size out of range [0,20]: "
			 "%d/n", rx_stats->mib_count);
		//priv->wstats.discard.misc++;
		return;
	}

	if (!(rx_end->status & RX_RES_STATUS_NO_CRC32_ERROR)
	    || !(rx_end->status & RX_RES_STATUS_NO_RXE_OVERFLOW)) {
		IOLog("Bad CRC or FIFO: 0x%08X.\n", rx_end->status);
		//priv->wstats.discard.misc++;
		return;
	}

	if (priv->iw_mode == IEEE80211_IF_TYPE_MNTR) {
		ipw_handle_data_packet(priv, 1, rxb, &stats);
		return;
	}

	stats.freq = ieee80211chan2mhz((stats.channel));
	stats.flag = 0;

	/* can be covered by ipw_report_frame() in most cases */
//      IPW_DEBUG_RX("RX status: 0x%08X\n", rx_end->status);

	priv->rx_packets++;

	header = (struct ieee80211_hdr *)IPW_RX_DATA(pkt);

	network_packet = is_network_packet(priv, header);

	//if (ipw_debug_level & IPW_DL_STATS && net_ratelimit())
		IOLog
			("[%c] %d RSSI: %d Signal: %u, Noise: %u, Rate: %u\n",
			 network_packet ? '*' : ' ',
			 stats.channel, stats.ssi, stats.ssi,
			 stats.ssi, stats.rate);

	/*if (network_packet) {
		if (rx_stats->noise_diff) {
			average_add(&priv->average_noise,
				    le16_to_cpu(rx_stats->noise_diff));
		}
	}*/

	/*if (network_packet) {
		average_add(&priv->average_rssi, stats.ssi);

		priv->last_rx_rssi = stats.ssi;

		priv->last_rx_jiffies = jiffies;
		priv->last_beacon_time = rx_end->beaconTimeStamp;
		priv->last_tsf = rx_end->timestamp;
	}*/
	//if (ipw_debug_level & (IPW_DL_RX))
		/* Set "1" to report good data frames in groups of 100 */
	//	ipw_report_frame(priv, pkt, header, 1);

	switch (WLAN_FC_GET_TYPE(le16_to_cpu(header->frame_control))) 
	{
	case IEEE80211_FTYPE_MGMT:
		switch (WLAN_FC_GET_STYPE(le16_to_cpu(header->frame_control))) 
		{
			case IEEE80211_STYPE_PROBE_RESP:
			case IEEE80211_STYPE_BEACON: 
			{
				if ((((priv->iw_mode == IEEE80211_IF_TYPE_STA)
					  &&
					  !(memcmp
					(header->addr2, priv->bssid, ETH_ALEN)))
					 ||
					 ((priv->iw_mode == IEEE80211_IF_TYPE_IBSS)
					  &&
					  !(memcmp
					(header->addr3, priv->bssid,
					 ETH_ALEN))))) 
					 {
					struct ieee80211_mgmt *mgmt =
						(struct ieee80211_mgmt *)header;
					u32 *pos;

					pos =
						(u32 *) & mgmt->u.beacon.timestamp;
					priv->timestamp0 = (pos[0]);
					priv->timestamp1 = le32_to_cpu(pos[1]);
					priv->assoc_capability =
						le16_to_cpu(mgmt->u.beacon.
								capab_info);

					}

				break;
			}

			case IEEE80211_STYPE_ACTION:
				/* TODO: Parse 802.11h frames for CSA... */
				break;

				/*D80211 there is no callback function from upper
				  stack to inform us when associated status. this
				  work around to sniff assoc_resp managment frame
				  and finish the association process for 3945 */
			case IEEE80211_STYPE_ASSOC_RESP:
			case IEEE80211_STYPE_REASSOC_RESP:
			{
				IOLog("associating\n");
				struct ieee80211_mgmt *mgnt =
					(struct ieee80211_mgmt *)header;
				priv->assoc_id = (~((1 << 15) | (1 << 14))
						  & mgnt->u.assoc_resp.aid);
				priv->assoc_capability =
					le16_to_cpu(mgnt->u.assoc_resp.capab_info);
				queue_te(11,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_bg_post_associate),NULL,NULL,true);
				//queue_work(priv->workqueue, &priv->post_associate);
				break;
			}

			case IEEE80211_STYPE_PROBE_REQ: 
			{
				if (priv->iw_mode == IEEE80211_IF_TYPE_IBSS)
					IOLog("Dropping (non network): "
							   MAC_FMT ", " MAC_FMT ", "
							   MAC_FMT "\n",
							   MAC_ARG(header->addr1),
							   MAC_ARG(header->addr2),
							   MAC_ARG(header->addr3));
				return;
			}
		}
		ipw_handle_data_packet(priv, 0, rxb, &stats);
		break;

		case IEEE80211_FTYPE_CTL:
		break;

		case IEEE80211_FTYPE_DATA:
		/*if (unlikely(is_duplicate_packet(priv, header)))
			 IOLog("Dropping (dup): " MAC_FMT ", "
					MAC_FMT ", " MAC_FMT "\n",
					MAC_ARG(header->addr1),
					MAC_ARG(header->addr2),
					MAC_ARG(header->addr3));
		else*/
			ipw_handle_data_packet(priv, 1, rxb, &stats);
		break;
	}
	
}

struct ieee80211_network *darwin_iwi4965::ieee80211_move_network_channel(struct
								ieee80211_device
								*ieee, struct
								ieee80211_network
								*network,
								u8 channel)
{
	struct ieee80211_network *target;
	unsigned long flags;

	//spin_lock_irqsave(&ieee->lock, flags);

	list_for_each_entry(target, &ieee->network_list, list) {
		/* Look to see if we have already received a beacon from
		 * the new network and created a new entry */
		if (!is_same_network_channel_switch(target, network, channel))
			continue;

		/* If we found the network, then return it so the caller
		 * can switch to it. */
		goto exit;
	}

	/* If we reach here, then the new network has not appeared yet.
	 * We can simply update the channel information for this network. */
	network->channel = channel;
	target = network;

      exit:
	//spin_unlock_irqrestore(&ieee->lock, flags);

	return target;
}

static inline unsigned compare_ether_addr(const u8 *_a, const u8 *_b)
{
	const u16 *a = (const u16 *) _a;
	const u16 *b = (const u16 *) _b;

	if (ETH_ALEN != 6) return -1;
	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
}

int darwin_iwi4965::is_same_network_channel_switch(struct ieee80211_network
					  *src, struct ieee80211_network
					  *dst, u8 channel)
{
	return ((src->ssid_len == dst->ssid_len) &&
		(src->channel == channel) &&
		!compare_ether_addr(src->bssid, dst->bssid) &&
		!memcmp(src->ssid, dst->ssid, src->ssid_len));
}

int darwin_iwi4965::ipw_queue_tx_reclaim(struct ipw_priv *priv, int fifo, int index)
{
	struct ipw_tx_queue *txq = &priv->txq[fifo];
	struct ipw_queue *q = &txq->q;
	u8 is_next = 0;
	int used;
	IOLog("ipw_queue_tx_reclaim queue: %d index: %d\n",fifo,index);
	if ((index >= q->n_bd) || (x2_queue_used(q, index) == 0)) {
		IOLog
		    ("Read index for DMA queue (%d) is out of range [0-%d) %d %d\n",
		     index, q->n_bd, q->first_empty, q->last_used);
		goto done;
	}
	//if (!index) index=0;//hack index
	index = ipw_queue_inc_wrap(index, q->n_bd);
	for (; q->last_used != index;
	     q->last_used = ipw_queue_inc_wrap(q->last_used, q->n_bd)) {
		if (is_next) {
			IOLog("XXXL we have skipped command\n");
			//queue_delayed_work(priv->workqueue, &priv->down, 0);
			queue_te(12,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_down),priv,NULL,true);
		}
		if (fifo != CMD_QUEUE_NUM) {
			ipw_queue_tx_free_tfd(priv, txq);
			priv->tx_packets++;
		}

		is_next = 1;
	}
      done:
	if (ipw_queue_space(q) > q->low_mark && (fifo >= 0)
	    && (fifo != CMD_QUEUE_NUM)
	    && (priv->status & STATUS_ASSOCIATED) && (fNetif->getFlags() & IFF_RUNNING))
		{ //&& netif_running(priv->net_dev)){
		IOLog("queue is available\n");
		fTransmitQueue->setCapacity(1024);
		fTransmitQueue->start();
	   // && priv->netdev_registered && netif_running(priv->net_dev))
		//netif_wake_queue(priv->net_dev);
		}
	used = q->first_empty - q->last_used;
	if (used < 0)
		used += q->n_window;
	return used;
}

int darwin_iwi4965::ipw_queue_space(const struct ipw_queue *q)
{
	int s = q->last_used - q->first_empty;
	if (q->last_used > q->first_empty)
		s -= q->n_bd;

	if (s <= 0)
		s += q->n_window;
	s -= 2;			/* keep some reserve to not confuse empty and full situations */
	if (s < 0)
		s = 0;
	return s;
}

u8 darwin_iwi4965::get_next_cmd_index(struct ipw_queue *q, u32 index, int is_huge)
{
	if (is_huge)
		return q->n_window;

	return (u8) (index % q->n_window);
}

void darwin_iwi4965::ipw_tx_complete(struct ipw_priv *priv,
			    struct ipw_rx_mem_buffer *rxb)
{
	struct ipw_rx_packet *pkt = (struct ipw_rx_packet *)mbuf_data(rxb->skb);
	int fifo = SEQ_TO_FIFO(pkt->hdr.sequence);
	int index = SEQ_TO_INDEX(pkt->hdr.sequence);
	int is_huge = (pkt->hdr.sequence & SEQ_HUGE_FRAME);
	int cmd_index;
	struct ipw_cmd *cmd;
	if (fifo > MAX_REAL_TX_QUEUE_NUM)
		return;
	if (fifo != priv->hw_setting.cmd_queue_no) {
		ipw_queue_tx_reclaim(priv, fifo, index);
		return;
	}

	cmd_index =
	    get_next_cmd_index(&priv->txq[priv->hw_setting.cmd_queue_no].q,
			       index, is_huge);
	cmd = &priv->txq[priv->hw_setting.cmd_queue_no].cmd[cmd_index];
	/* Input error checking is done when commands are added to queue. */
	if (cmd->meta.flags & CMD_WANT_SKB) {
		cmd->meta.u.source->u.skb = rxb->skb;
		rxb->skb = NULL;
	} else if (cmd->meta.u.callback &&
		   !cmd->meta.u.callback(priv, cmd, rxb->skb))
		rxb->skb = NULL;

	ipw_queue_tx_reclaim(priv, fifo, index);

	/* is_cmd_sync(cmd) works with ipw_host_cmd... here we only have ipw_cmd */
	if (!(cmd->meta.flags & CMD_ASYNC)) {
		priv->status &= ~STATUS_HCMD_ACTIVE;
		//wake_up_interruptible(&priv->wait_command_queue);
	}
}

void darwin_iwi4965::RxQueueIntr()
{
	struct ipw_rx_mem_buffer *rxb;
	struct ipw_rx_packet *pkt;
	u32 r, i;
	int pkt_from_hardware;
	r = ((struct ipw_shared_t*)(priv->hw_setting.shared_virt))->rx_read_ptr[0];
	i = priv->rxq->read;
	while (i != r) {
		rxb = priv->rxq->queue[i];
		if (rxb == NULL) return;
		priv->rxq->queue[i] = NULL;

		pkt = (struct ipw_rx_packet *)mbuf_data(rxb->skb);

		/* If this frame wasn't received then it is a response from
		 * a host request */
		pkt_from_hardware = !(pkt->hdr.sequence & SEQ_RX_FRAME);

		/* Don't report replies covered by debug messages below ...
		 * switch statement for readability ... compiler may optimize.
		 * Hack at will to see/not-see what you want in logs. */
		switch (pkt->hdr.cmd) {
		case SCAN_START_NOTIFICATION:
		case SCAN_RESULTS_NOTIFICATION:
		case SCAN_COMPLETE_NOTIFICATION:
		case REPLY_STATISTICS_CMD:
		case STATISTICS_NOTIFICATION:
		case REPLY_RX:
		case REPLY_ALIVE:
		case REPLY_ADD_STA:
		case REPLY_ERROR:
			IOLog("Received %s (#%x)\n",get_cmd_string(pkt->hdr.cmd));
			break;
		default:
			IOLog
			    ("Received %s command (#%x), seq:0x%04X, "
			     "flags=0x%02X, len = %d\n","",
			     get_cmd_string(pkt->hdr.cmd),
			     pkt->hdr.cmd, pkt->hdr.sequence,
			     pkt->hdr.flags, le16_to_cpu(pkt->len));
		}

		switch (pkt->hdr.cmd) {
		case REPLY_RX:	/* 802.11 frame */
			ipw_handle_reply_rx(priv, rxb);
			break;

		case REPLY_ALIVE:{
				memcpy(&priv->card_alive,
				       &pkt->u.alive_frame,
				       sizeof(struct ipw_alive_resp));

				IOLog
				    ("Alive ucode status 0x%08X revision "
				     "0x%01X 0x%01X\n",
				     priv->card_alive.is_valid,
				     priv->card_alive.ver_type,
				     priv->card_alive.ver_subtype);
				/* We delay the ALIVE response by 5ms to
				 * give the HW RF Kill time to activate... */
				if (priv->card_alive.is_valid == UCODE_VALID_OK)
				{
					udelay(5);
					queue_te(9,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_bg_alive_start),priv,NULL,true);
					/*queue_delayed_work(priv->workqueue,
							   &priv->alive_start,
							   msecs_to_jiffies(5));*/
				}
				else
					IOLog
					    ("uCode did not respond OK.\n");
				break;
			}

		case REPLY_ADD_STA:{
				IOLog
				    ("Received REPLY_ADD_STA: 0x%02X\n",
				     pkt->u.status);
				break;
			}

		case REPLY_ERROR:{
				u32 err_type = pkt->u.err_resp.enumErrorType;
				u8 cmd_id = pkt->u.err_resp.currentCmdID;
				u16 seq = pkt->u.err_resp.erroneousCmdSeqNum;
				u32 ser = pkt->u.err_resp.errorService;
				IOLog("Error Reply type 0x%08X "
					  "cmd %s (0x%02X) "
					  "seq 0x%04X ser 0x%08X\n",
					  err_type,"",
					  get_cmd_string(cmd_id),
					  cmd_id, seq, ser);
				break;
			}
		case REPLY_TX:
		IOLog("ipw_handle_reply_tx\n");
			ipw_handle_reply_tx(priv, &pkt->u.tx_resp,
					    pkt->hdr.sequence);
			break;

		case CHANNEL_SWITCH_NOTIFICATION:{
				struct ipw_csa_notification *csa =
				    &(pkt->u.csa_notif);
				IOLog
				    ("CSA notif: channel %d, status %d\n",
				     csa->channel, csa->status);
				priv->channel = csa->channel;
				priv->active_conf.channel = csa->channel;
				break;
			}

		case SPECTRUM_MEASURE_NOTIFICATION:{
				struct ipw_spectrum_notification
				*report = &(pkt->u.spectrum_notif);

				if (!report->state) {
					IOLog(						  "Spectrum Measure Notification: "
						  "Start\n");
					break;
				}

				memcpy(&priv->measure_report, report,
				       sizeof(*report));
				//queue_delayed_work(priv->workqueue,
				//		   &priv->report_work, 0);
				break;
			}

		case QUIET_NOTIFICATION:
			IOLog("UNHANDLED - Quiet Notification.\n");
			break;

		case MEASURE_ABORT_NOTIFICATION:
			IOLog
			    ("UNHANDLED - Measure Abort Notification.\n");
			break;

		case RADAR_NOTIFICATION:
			IOLog("UNHANDLED - Radar Notification.\n");
			break;

		case PM_SLEEP_NOTIFICATION:{
				struct ipw_sleep_notification *sleep =
				    &(pkt->u.sleep_notif);
				IOLog
				    ("sleep mode: %d, src: %d\n",
				     sleep->pm_sleep_mode,
				     sleep->pm_wakeup_src);
				break;
			}

		case PM_DEBUG_STATISTIC_NOTIFIC:
			IOLog
			    ("Dumping %d bytes of unhandled "
			     "notification for %s:\n",
			     le16_to_cpu(pkt->len),   get_cmd_string(pkt->hdr.cmd));
			//printk_buf(IPW_DL_RADIO, pkt->u.raw,
			//	   le16_to_cpu(pkt->len));
			break;

		case BEACON_NOTIFICATION:{
#ifdef CONFIG_IPW3945_DEBUG
				struct BeaconNtfSpecifics *beacon =
				    &(pkt->u.beacon_status);
				IOLog
				    ("beacon status %x retries %d iss %d "
				     "tsf %d %d rate %d\n",
				     beacon->bconNotifHdr.status,
				     beacon->bconNotifHdr.
				     failure_frame,
				     beacon->ibssMgrStatus,
				     beacon->highTSF, beacon->lowTSF,
				     beacon->bconNotifHdr.rate);
#endif
			}
			break;

		case REPLY_STATISTICS_CMD:
		case STATISTICS_NOTIFICATION:
			IOLog
			    ("Statistics notification received (%zd vs %d).\n",
			     sizeof(priv->statistics), pkt->len);
			memcpy(&priv->statistics, pkt->u.raw,
			       sizeof(priv->statistics));
			break;

		case WHO_IS_AWAKE_NOTIFICATION:
			IOLog("Notification from the card \n");
			break;

		case SCAN_REQUEST_NOTIFICATION:{
#ifdef CONFIG_IPW3945_DEBUG
				struct ipw_scanreq_notification *notif
				    =
				    (struct ipw_scanreq_notification
				     *)pkt->u.raw;
				IOLog
				    ("Scan request status = 0x%x\n",
				     notif->status);
#endif
				break;
			}

		case SCAN_START_NOTIFICATION:{
				struct ipw_scanstart_notification
				*notif =
				    (struct ipw_scanstart_notification
				     *)pkt->u.raw;
				priv->scan_start_tsf = notif->tsf_low;
				IOLog("Scan start: "
					       "%d [802.11%s] "
					       "(TSF: 0x%08X:%08X) - %d (beacon timer %u)\n",
					       notif->channel,
					       notif->
					       band ? "bg" : "a",
					       notif->tsf_high,
					       notif->tsf_low,
					       notif->status,
					       notif->beacon_timer);
				break;
			}

		case SCAN_RESULTS_NOTIFICATION:{
#ifdef CONFIG_IPW3945_DEBUG
				struct ipw_scanresults_notification
				*notif = (struct ipw_scanresults_notification *)
				    pkt->u.raw;

				IOLog("Scan ch.res: "
					       "%d [802.11%s] "
					       "(TSF: 0x%08X:%08X) - %d "
					       "elapsed=%lu usec (%dms since last)\n",
					       notif->channel,
					       notif->
					       band ? "bg" : "a",
					       notif->tsf_high,
					       notif->tsf_low,
					       notif->statistics[0],
					       notif->tsf_low -
					       priv->scan_start_tsf,
					       0);
#endif
				priv->last_scan_jiffies = jiffies;
				break;
			}

		case SCAN_COMPLETE_NOTIFICATION:{
				struct ipw_scancomplete_notification
				*scan_notif =
				    (struct ipw_scancomplete_notification *)
				    pkt->u.raw;
				IOLog
				    ("Scan complete: %d channels "
				     "(TSF 0x%08X:%08X) - %d\n",
				     scan_notif->scanned_channels,
				     scan_notif->tsf_low,
				     scan_notif->tsf_high, scan_notif->status);

				ipw_scan_completed(priv,
						   scan_notif->status == 1);
				break;
			}

		case CARD_STATE_NOTIFICATION:{
				u32 flags =
				    le32_to_cpu(pkt->u.card_state_notif.flags);
				u32 status = priv->status;
				IOLog
				    ("Card state received: "
				     "HW:%s SW:%s\n",
				     (flags & HW_CARD_DISABLED) ?
				     "Off" : "On",
				     (flags & SW_CARD_DISABLED) ? "Off" : "On");

				if (flags & HW_CARD_DISABLED) {
					ipw_write32(
						    CSR_UCODE_DRV_GP1_SET,
						    CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);

					priv->status |= STATUS_RF_KILL_HW;
				} else
					priv->status &= ~STATUS_RF_KILL_HW;

				if (flags & SW_CARD_DISABLED)
					priv->status |= STATUS_RF_KILL_SW;
				else
					priv->status &= ~STATUS_RF_KILL_SW;

				priv->status &=
				    ~(STATUS_ASSOCIATED | STATUS_ASSOCIATING);

			//	ipw_scan_cancel(priv);

				if (((status & STATUS_RF_KILL_HW) !=
				     (priv->status & STATUS_RF_KILL_HW))
				    || ((status & STATUS_RF_KILL_SW)
					!= (priv->status & STATUS_RF_KILL_SW))) {
					queue_te(3,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_rf_kill),priv,NULL,true);
					//queue_delayed_work(priv->workqueue,
					//		   &priv->rf_kill, 0);
				};// else
					//wake_up_interruptible(&priv->
					//		      wait_command_queue);
				
				break;
			}
		default:
			break;
		}

		if (pkt_from_hardware) {
			/* Invoke any callbacks, transfer the skb to
			 * caller, and fire off the (possibly) blocking
			 * ipw_send_cmd() via as we reclaim the queue... */
			if (rxb && rxb->skb)
			{
				ipw_tx_complete(priv, rxb);
			}
			else
				IOLog("Claim null rxb?\n");
		}

		/* For now we just don't re-use anything.  We can tweak this
		 * later to try and re-use notification packets and SKBs that
		 * fail to Rx correctly */
		if (rxb->skb != NULL) {
			//dev_kfree_skb_any(rxb->skb);
			if (!(mbuf_type(rxb->skb) == MBUF_TYPE_FREE) ) freePacket(rxb->skb);
			//rxb->skb = NULL;
		}
		rxb->dma_addr=NULL;
		//pci_unmap_single(priv->pci_dev, rxb->dma_addr,
		//		 IPW_RX_BUF_SIZE, PCI_DMA_FROMDEVICE);
		list_add_tail(&rxb->list, &priv->rxq->rx_used);
		i = (i + 1) % RX_QUEUE_SIZE;
	}

		//if(doFlushQueue){
		IWI_DEBUG("flushing Input Queue\n");
		fNetif->flushInputQueue();		
		fTransmitQueue->service(IOBasicOutputQueue::kServiceAsync);
		//}
	/* Backtrack one entry */
	priv->rxq->read = i;
	ipw_rx_queue_restock(priv);

}


int darwin_iwi4965::initTxQueue()
{
	txq.count = IWI_TX_RING_COUNT;
	txq.queued = 0;
	txq.cur = 0;

	txq.memD = MemoryDmaAlloc(txq.count * IWI_TX_DESC_SIZE, &txq.physaddr, &txq.desc);
	txq.data = IONew(iwi_tx_data, txq.count);

	return true;
}

int darwin_iwi4965::resetTxQueue()
{
	rxq.cur=0;
	return 0;
}


void darwin_iwi4965::free(void)
{
	IOLog("todo: Freeing\n");
	return; // need to fix this
	/*if (pl==0)
	{
		stop(NULL);*/
		super::free();
	//}
	
	return;
}

void darwin_iwi4965::stop(IOService *provider)
{
	CSR_WRITE_4(memBase, IWI_CSR_RST, IWI_RST_SOFT_RESET);

	if (fInterruptSrc && fWorkLoop)
	        fWorkLoop->removeEventSource(fInterruptSrc);

	fPCIDevice->close(this);
	RELEASE(fInterruptSrc);
	RELEASE(fPCIDevice);
	RELEASE(map);
		
	if (provider) super::stop(provider);
}

IOReturn darwin_iwi4965::disable( IONetworkInterface * netif )
{
	IWI_DEBUG("ifconfig down\n");
	switch ((fNetif->getFlags() & IFF_UP) && (fNetif->getFlags() & IFF_RUNNING))
	{
	case true:
		IWI_DEBUG("ifconfig going down\n");
		//super::disable(fNetif);
		//fNetif->setPoweredOnByUser(false);
		fTransmitQueue->stop();
		setLinkStatus(kIONetworkLinkValid);
		//fNetif->setLinkState(kIO80211NetworkLinkDown);
		//fNetif->syncSIOCSIFFLAGS( /*IONetworkController * */this);
		//(if_flags & ~mask) | (new_flags & mask) if mask has IFF_UP if_updown fires up (kpi_interface.c in xnu)
		ifnet_set_flags(fifnet, 0 , IFF_UP | IFF_RUNNING );
		
		
		fTransmitQueue->setCapacity(0);
		fTransmitQueue->flush();
		
				
		//if ((priv->status & STATUS_ASSOCIATED)) enable(fNetif);
		
		return kIOReturnSuccess;
		
		break;
	default:
		IWI_DEBUG("ifconfig already down\n");
		return -1;
		break;
	}

}

/*const char * darwin_iwi4965::getNamePrefix() const
{
	return "wlan";
}*/

void inline
darwin_iwi4965::eeprom_write_reg(UInt32 data)
{
	OSWriteLittleInt32((void*)memBase, IPW_INDIRECT_ADDR, FW_MEM_REG_EEPROM_ACCESS);
	OSWriteLittleInt32((void*)memBase, IPW_INDIRECT_DATA, data);
	
	// Sleep for 1 uS to hold the data there
	IODelay(1);
}

/* EEPROM Chip Select */
void inline
darwin_iwi4965::eeprom_cs(bool sel)
{
	if (sel)	// Set the CS pin on the EEPROM
	{
		// clear everything out
		eeprom_write_reg(0);
		// set the chip select pin and keep it selected
		eeprom_write_reg(EEPROM_BIT_CS);
		// give the eeprom a cycle on the clock (SK) pin to register the enable
		eeprom_write_reg(EEPROM_BIT_CS | EEPROM_BIT_SK);
		// end the clock cycle, keeping CS selected
		eeprom_write_reg(EEPROM_BIT_CS);
	}
	else		// Clear the CS pin on the EEPROM
	{
		// Make sure CS is set
		eeprom_write_reg(EEPROM_BIT_CS);
		// Clear everything out
		eeprom_write_reg(0);
		// Give the EEPROM a clock
		eeprom_write_reg(EEPROM_BIT_SK);
	}
}

void inline
darwin_iwi4965::eeprom_write_bit(UInt8 bit)
{
	// short way of saying: if bit, then set DI line high, data = 0 otherwise.
	// Note that because of this implementation we can pass in any value > 0 and
	// it will be interpreted as a '1' bit. Simplifies some operations in other 
	// functions.
	UInt32 data = (bit ? EEPROM_BIT_DI:0);
	// write data with the chip enabled
	eeprom_write_reg(EEPROM_BIT_CS | data);
	// keep data, chip enabled, and give it a rising clock edge
	eeprom_write_reg(EEPROM_BIT_CS | data | EEPROM_BIT_SK);
}

void
darwin_iwi4965::eeprom_op(UInt8 op, UInt8 addr)
{
	int i;
	
	// enable the chip
	eeprom_cs(true);
	
	// write the command (all commands start with a '1' bit followed by 2 other bits)
	eeprom_write_bit(1);
	eeprom_write_bit(op & 2);
	eeprom_write_bit(op & 1);
	
	// write the 8-bit address
	for (i=7; i>=0; i--) {
		eeprom_write_bit(addr & (1 << i));
	}
}

UInt16
darwin_iwi4965::eeprom_read_UInt16(UInt8 addr)
{
	int i;
	u16 r = 0;

	/* Send READ Opcode */
	eeprom_op(EEPROM_CMD_READ, addr);

	/* Send dummy bit */
	eeprom_write_reg(EEPROM_BIT_CS);

	/* Read the byte off the eeprom one bit at a time */
	for (i = 0; i < 16; i++) {
		u32 data = 0;
		eeprom_write_reg(EEPROM_BIT_CS | EEPROM_BIT_SK);
		eeprom_write_reg(EEPROM_BIT_CS);
		data = ipw_read_reg32(FW_MEM_REG_EEPROM_ACCESS);
		r = (r << 1) | ((data & EEPROM_BIT_DO) ? 1 : 0);
	}

	/* Send another dummy bit */
	eeprom_write_reg(0);
	//eeprom_disable_cs();
	eeprom_cs(false);

	return r;
}

/*
 * Here we cache the EEPROM into memory for ease of use
 * FIXME: Can the EEPROM change behind our backs?
 */
void
darwin_iwi4965::cacheEEPROM(struct ipw_priv *priv)
{
}


UInt32
darwin_iwi4965::read_reg_UInt32(UInt32 reg)
{
	UInt32 value;
	
	OSWriteLittleInt32((void*)memBase, IPW_INDIRECT_ADDR, reg);
	value = OSReadLittleInt32((void*)memBase, IPW_INDIRECT_DATA);
	return value;
}

int
darwin_iwi4965::ipw_poll_bit(struct ipw_priv *priv, u32 addr,
			u32 bits, u32 mask, int timeout)
{
	int i = 0;

	do {
		if ((_ipw_read32(memBase,addr) & mask) == (bits & mask))
			return i;
		mdelay(10);
		i += 10;
	} while (i < timeout);

	return -ETIMEDOUT;
	
}



/******************************************************************************* 
 * Functions which MUST be implemented by any class which inherits
 * from IO80211Controller.
 ******************************************************************************/
/*SInt32
darwin_iwi4965::getSSID(IO80211Interface *interface,
						struct apple80211_ssid_data *sd)
{
	IOLog("getSSID %s l:%d\n",escape_essid((const char*)sd->ssid_bytes, sd->ssid_len));
	return 0;
}

SInt32
darwin_iwi4965::getCHANNEL(IO80211Interface *interface,
						  struct apple80211_channel_data *cd)
{
	IOLog("getCHANNEL c:%d f:%d\n",cd->channel.channel,cd->channel.flags);
	return 0;
}

SInt32
darwin_iwi4965::getBSSID(IO80211Interface *interface,
						struct apple80211_bssid_data *bd)
{
	IOLog("getBSSID %s\n",escape_essid((const char*)bd->bssid.octet,sizeof(bd->bssid.octet)));
	return 0;
}

SInt32
darwin_iwi4965::getCARD_CAPABILITIES(IO80211Interface *interface,
									  struct apple80211_capability_data *cd)
{
	IOLog("getCARD_CAPABILITIES %d\n",sizeof(cd->capabilities));
	publishProperties();
	return 0;
}

SInt32
darwin_iwi4965::getSTATE(IO80211Interface *interface,
						  struct apple80211_state_data *sd)
{
	IOLog("getSTATE %d\n",sd->state);
	return 0;
}

SInt32
darwin_iwi4965::getRSSI(IO80211Interface *interface,
					   struct apple80211_rssi_data *rd)
{
	IOLog("getRSSI \n");
	return 0;
}

SInt32
darwin_iwi4965::getPOWER(IO80211Interface *interface,
						struct apple80211_power_data *pd)
{

	IOLog("getPOWER %d, %d %d %d %d\n",pd->num_radios, pd->power_state[0],pd->power_state[1],pd->power_state[2],pd->power_state[3]);
	return 0;
}

SInt32
darwin_iwi4965::getSCAN_RESULT(IO80211Interface *interface,
							  struct apple80211_scan_result **scan_result)
{
	IOLog("getSCAN_RESULT \n");
	return 0;
}


SInt32
darwin_iwi4965::getRATE(IO80211Interface *interface,
					   struct apple80211_rate_data *rd)
{
	IOLog("getRATE %d\n",rd->rate);
	return 0;
}

SInt32
darwin_iwi4965::getSTATUS_DEV(IO80211Interface *interface,
							 struct apple80211_status_dev_data *dd)
{
	char i[4];
	int n=interface->getUnitNumber();
	sprintf(i,"en%d",n);
	IOLog("getSTATUS_DEV %s\n",dd->dev_name);
	ifnet_find_by_name(i,&fifnet);
	IOLog("ifnet_t %s%d = %x\n",ifnet_name(fifnet),ifnet_unit(fifnet),fifnet);
	//ifnet_set_mtu(fifnet,IPW_RX_BUF_SIZE); //>=IPW_RX_BUF_SIZE
	//ipw_sw_reset(1);
	//memcpy(&priv->ieee->dev->name,i,sizeof(i));

	super::enable(fNetif);
	interface->setPoweredOnByUser(true);
	ipw_up(priv);
	return 0;
}

SInt32
darwin_iwi4965::getRATE_SET(IO80211Interface	*interface,
						   struct apple80211_rate_set_data *rd)
{
	IOLog("getRATE_SET %d r0:%d f0:%d\n",rd->num_rates, rd->rates[0].rate,rd->rates[0].flags);
	return 0;
}

SInt32	darwin_iwi4965::getASSOCIATION_STATUS( IO80211Interface * interface, struct apple80211_assoc_status_data * asd )
{
	IOLog("getASSOCIATION_STATUS %d\n",asd->status);
	return 0;
}

SInt32
darwin_iwi4965::setSCAN_REQ(IO80211Interface *interface,
						   struct apple80211_scan_data *sd)
{
	IOLog("setSCAN_REQ \n");
	return 0;
}

SInt32
darwin_iwi4965::setASSOCIATE(IO80211Interface *interface,
							struct apple80211_assoc_data *ad)
{
	IOLog("setASSOCIATE \n");
	return 0;
}

SInt32
darwin_iwi4965::setPOWER(IO80211Interface *interface,
						struct apple80211_power_data *pd)
{
	IOLog("setPOWER %d, %d %d %d %d\n",pd->num_radios, pd->power_state[0],pd->power_state[1],pd->power_state[2],pd->power_state[3]);
	if (pd->power_state[pd->num_radios]==1)
	{
		IOLog("power on\n");
	}
	else
	{
		IOLog("power off ignored\n");
		return -1;
	}
	return 0;
}

SInt32
darwin_iwi4965::setCIPHER_KEY(IO80211Interface *interface,
							 struct apple80211_key *key)
{
	IOLog("setCIPHER_KEY \n");
	return 0;
}

SInt32
darwin_iwi4965::setAUTH_TYPE(IO80211Interface *interface,
							struct apple80211_authtype_data *ad)
{
	IOLog("setAUTH_TYPE \n");
	return 0;
}

SInt32
darwin_iwi4965::setDISASSOCIATE(IO80211Interface	*interface)
{
	IOLog("setDISASSOCIATE \n");
	return 0;
}

SInt32
darwin_iwi4965::setSSID(IO80211Interface *interface,
					   struct apple80211_ssid_data *sd)
{
	IOLog("setSSID \n");
	return 0;
}

SInt32
darwin_iwi4965::setAP_MODE(IO80211Interface *interface,
						  struct apple80211_apmode_data *ad)
{
	IOLog("setAP_MODE \n");
	return 0;
}

bool darwin_iwi4965::attachInterfaceWithMacAddress( void * macAddr, 
												UInt32 macLen, 
												IONetworkInterface ** interface, 
												bool doRegister ,
												UInt32 timeout  )
{
	IOLog("attachInterfaceWithMacAddress \n");
	return super::attachInterfaceWithMacAddress(macAddr,macLen,interface,doRegister,timeout);
}												
												
void darwin_iwi4965::dataLinkLayerAttachComplete( IO80211Interface * interface )											
{
	IOLog("dataLinkLayerAttachComplete \n");
	super::dataLinkLayerAttachComplete(interface);
}*/


void darwin_iwi4965::queue_te(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, bool start)
{
	if (tlink[num]) queue_td(num,NULL);
	//IOLog("queue_te0 %d\n",tlink[num]);
	tlink[num]=thread_call_allocate(func,this);
	//IOLog("queue_te1 %d\n",tlink[num]);
	uint64_t timei2;
	if (timei) clock_interval_to_deadline(timei,kSecondScale,&timei2);
	//IOLog("queue_te time %d %d\n",timei,timei2);
	int r;
	if (start==true && tlink[num])
	{
		if (!par && !timei)	r=thread_call_enter(tlink[num]);
		if (!par && timei)	r=thread_call_enter_delayed(tlink[num],timei2);
		if (par && !timei)	r=thread_call_enter1(tlink[num],par);
		if (par && timei)	r=thread_call_enter1_delayed(tlink[num],par,timei2);
	}
	//IOLog("queue_te result %d\n",r);
}

void darwin_iwi4965::queue_td(int num , thread_call_func_t func)
{
	//IOLog("queue_td0 %d\n",tlink[num]);
	int r=1,r1;
	//IOLog("queue_td0 %d\n",tlink[num]);
	if (tlink[num])
	{ 
		//rep1:
		r=thread_call_cancel(tlink[num]);
		//if (r!=0) goto rep1;
		//rep2:
		r1=thread_call_free(tlink[num]);
		//if (r!=1) goto rep2;
		tlink[num]=NULL;
	}
	//IOLog("queue_td1-%d , %d %d\n",num,r,r1);
}

IOReturn darwin_iwi4965::message( UInt32 type, IOService * provider,
                              void * argument)
{
	IOLog("message %8x\n",type);
	return 0;

}

int darwin_iwi4965::ipw_is_valid_channel(struct ieee80211_device *ieee, u8 channel)
{
}

void darwin_iwi4965::ipw_create_bssid(struct ipw_priv *priv, u8 * bssid)
{
	/* First 3 bytes are manufacturer */
	bssid[0] = priv->mac_addr[0];
	bssid[1] = priv->mac_addr[1];
	bssid[2] = priv->mac_addr[2];

	/* Last bytes are random */
	//get_random_bytes(&bssid[3], ETH_ALEN - 3);
	bssid[3]=0x12;

	bssid[0] &= 0xfe;	/* clear multicast bit */
	bssid[0] |= 0x02;	/* set local assignment bit (IEEE802) */
}

void darwin_iwi4965::ipw_adhoc_create(struct ipw_priv *priv,
			     struct ieee80211_network *network)
{
	
}

int darwin_iwi4965::ipw_is_rate_in_mask(struct ipw_priv *priv, int ieee_mode, u8 rate)
{
	rate &= ~IEEE80211_BASIC_RATE_MASK;
	if (ieee_mode == IEEE_A) {
		switch (rate) {
		case IEEE80211_OFDM_RATE_6MB:
			return priv->rates_mask & IEEE80211_OFDM_RATE_6MB_MASK ?
			    1 : 0;
		case IEEE80211_OFDM_RATE_9MB:
			return priv->rates_mask & IEEE80211_OFDM_RATE_9MB_MASK ?
			    1 : 0;
		case IEEE80211_OFDM_RATE_12MB:
			return priv->
			    rates_mask & IEEE80211_OFDM_RATE_12MB_MASK ? 1 : 0;
		case IEEE80211_OFDM_RATE_18MB:
			return priv->
			    rates_mask & IEEE80211_OFDM_RATE_18MB_MASK ? 1 : 0;
		case IEEE80211_OFDM_RATE_24MB:
			return priv->
			    rates_mask & IEEE80211_OFDM_RATE_24MB_MASK ? 1 : 0;
		case IEEE80211_OFDM_RATE_36MB:
			return priv->
			    rates_mask & IEEE80211_OFDM_RATE_36MB_MASK ? 1 : 0;
		case IEEE80211_OFDM_RATE_48MB:
			return priv->
			    rates_mask & IEEE80211_OFDM_RATE_48MB_MASK ? 1 : 0;
		case IEEE80211_OFDM_RATE_54MB:
			return priv->
			    rates_mask & IEEE80211_OFDM_RATE_54MB_MASK ? 1 : 0;
		default:
			return 0;
		}
	}

	/* B and G mixed */
	switch (rate) {
	case IEEE80211_CCK_RATE_1MB:
		return priv->rates_mask & IEEE80211_CCK_RATE_1MB_MASK ? 1 : 0;
	case IEEE80211_CCK_RATE_2MB:
		return priv->rates_mask & IEEE80211_CCK_RATE_2MB_MASK ? 1 : 0;
	case IEEE80211_CCK_RATE_5MB:
		return priv->rates_mask & IEEE80211_CCK_RATE_5MB_MASK ? 1 : 0;
	case IEEE80211_CCK_RATE_11MB:
		return priv->rates_mask & IEEE80211_CCK_RATE_11MB_MASK ? 1 : 0;
	}

	/* If we are limited to B modulations, bail at this point */
	if (ieee_mode == IEEE_B)
		return 0;

	/* G */
	switch (rate) {
	case IEEE80211_OFDM_RATE_6MB:
		return priv->rates_mask & IEEE80211_OFDM_RATE_6MB_MASK ? 1 : 0;
	case IEEE80211_OFDM_RATE_9MB:
		return priv->rates_mask & IEEE80211_OFDM_RATE_9MB_MASK ? 1 : 0;
	case IEEE80211_OFDM_RATE_12MB:
		return priv->rates_mask & IEEE80211_OFDM_RATE_12MB_MASK ? 1 : 0;
	case IEEE80211_OFDM_RATE_18MB:
		return priv->rates_mask & IEEE80211_OFDM_RATE_18MB_MASK ? 1 : 0;
	case IEEE80211_OFDM_RATE_24MB:
		return priv->rates_mask & IEEE80211_OFDM_RATE_24MB_MASK ? 1 : 0;
	case IEEE80211_OFDM_RATE_36MB:
		return priv->rates_mask & IEEE80211_OFDM_RATE_36MB_MASK ? 1 : 0;
	case IEEE80211_OFDM_RATE_48MB:
		return priv->rates_mask & IEEE80211_OFDM_RATE_48MB_MASK ? 1 : 0;
	case IEEE80211_OFDM_RATE_54MB:
		return priv->rates_mask & IEEE80211_OFDM_RATE_54MB_MASK ? 1 : 0;
	}

	return 0;
}

int darwin_iwi4965::ipw_compatible_rates(struct ipw_priv *priv,
				const struct ieee80211_network *network,
				struct ipw_supported_rates *rates)
{
	int num_rates, i;

	memset(rates, 0, sizeof(*rates));
	num_rates = min(network->rates_len, (u8) IPW_MAX_RATES);
	rates->num_rates = 0;
	for (i = 0; i < num_rates; i++) {
		if (!ipw_is_rate_in_mask(priv, network->mode,
					 network->rates[i])) {

			if (network->rates[i] & IEEE80211_BASIC_RATE_MASK) {
				IOLog("Adding masked mandatory "
					       "rate %02X\n",
					       network->rates[i]);
				rates->supported_rates[rates->num_rates++] =
				    network->rates[i];
				continue;
			}

			IOLog("Rate %02X masked : 0x%08X\n",
				       network->rates[i], priv->rates_mask);
			continue;
		}

		rates->supported_rates[rates->num_rates++] = network->rates[i];
	}

	num_rates = min(network->rates_ex_len,
			(u8) (IPW_MAX_RATES - num_rates));
	for (i = 0; i < num_rates; i++) {
		if (!ipw_is_rate_in_mask(priv, network->mode,
					 network->rates_ex[i])) {
			if (network->rates_ex[i] & IEEE80211_BASIC_RATE_MASK) {
				IOLog("Adding masked mandatory "
					       "rate %02X\n",
					       network->rates_ex[i]);
				rates->supported_rates[rates->num_rates++] =
				    network->rates[i];
				continue;
			}

			IOLog("Rate %02X masked : 0x%08X\n",
				       network->rates_ex[i], priv->rates_mask);
			continue;
		}

		rates->supported_rates[rates->num_rates++] =
		    network->rates_ex[i];
	}

	return 1;
}

void darwin_iwi4965::ipw_copy_rates(struct ipw_supported_rates *dest,
			   const struct ipw_supported_rates *src)
{
	u8 i;
	for (i = 0; i < src->num_rates; i++)
		dest->supported_rates[i] = src->supported_rates[i];
	dest->num_rates = src->num_rates;
}

int darwin_iwi4965::ipw_best_network(struct ipw_priv *priv,
			    struct ipw_network_match *match,
			    struct ieee80211_network *network, int roaming)
{

}

int darwin_iwi4965::ipw_associate(ipw_priv *data)
{
	
}

void darwin_iwi4965::ipw_set_fixed_rate(struct ipw_priv *priv, int mode)
{
	
}

int darwin_iwi4965::ipw_associate_network(struct ipw_priv *priv,
				 struct ieee80211_network *network,
				 struct ipw_supported_rates *rates, int roaming)
{

}

int darwin_iwi4965::ipw_get_ordinal(struct ipw_priv *priv, u32 ord, void *val, u32 * len)
{
	
}

void darwin_iwi4965::ipw_reset_stats(struct ipw_priv *priv)
{
	
}

void darwin_iwi4965::ipw_read_indirect(struct ipw_priv *priv, u32 addr, u8 * buf,
			       int num)
{
	u32 aligned_addr = addr & IPW_INDIRECT_ADDR_MASK;	/* dword align */
	u32 dif_len = addr - aligned_addr;
	u32 i;

	IOLog("addr = %d, buf = %p, num = %d\n", addr, buf, num);

	if (num <= 0) {
		return;
	}

	/* Read the first dword (or portion) byte by byte */
	if (unlikely(dif_len)) {
		ipw_write32( IPW_INDIRECT_ADDR, aligned_addr);
		/* Start reading at aligned_addr + dif_len */
		for (i = dif_len; ((i < 4) && (num > 0)); i++, num--)
			*buf++ = _ipw_read8(memBase, IPW_INDIRECT_DATA + i);
		aligned_addr += 4;
	}

	/* Read all of the middle dwords as dwords, with auto-increment */
	ipw_write32( IPW_AUTOINC_ADDR, aligned_addr);
	for (; num >= 4; buf += 4, aligned_addr += 4, num -= 4)
		*(u32 *) buf = ipw_read32( IPW_AUTOINC_DATA);

	/* Read the last dword (or portion) byte by byte */
	if (unlikely(num)) {
		ipw_write32( IPW_INDIRECT_ADDR, aligned_addr);
		for (i = 0; num > 0; i++, num--)
			*buf++ = _ipw_read8(memBase, IPW_INDIRECT_DATA + i);
	}
}

void darwin_iwi4965::ipw_link_up(struct ipw_priv *priv)
{
	priv->last_seq_num = -1;
	priv->last_frag_num = -1;
	priv->last_packet_time = 0;

	
	
	//fNetif->setLinkState(kIO80211NetworkLinkUp);
	/*netif_carrier_on(priv->net_dev);
	if (netif_queue_stopped(priv->net_dev)) {
		IOLog("waking queue\n");
		netif_wake_queue(priv->net_dev);
	} else {
		IOLog("starting queue\n");
		netif_start_queue(priv->net_dev);
	}*/
	
	enable(fNetif);
	
	queue_td(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan));	
	queue_td(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan_check));
	//ipw_reset_stats(priv);
	/* Ensure the rate is updated immediately */
	priv->last_rate = ipw_get_current_rate(priv);
	setLinkStatus(kIONetworkLinkValid | (priv->last_rate ? kIONetworkLinkActive : 0), mediumTable[MEDIUM_TYPE_AUTO],priv->last_rate);

	//ipw_gather_stats(priv);
	//ipw_led_link_on(priv);
	//notify_wx_assoc_event(priv);

	if (priv->config & CFG_BACKGROUND_SCAN)
		queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan),priv,3,true);
}

void darwin_iwi4965::average_add(struct average *avg, s16 val)
{
	avg->sum -= avg->entries[avg->pos];
	avg->sum += val;
	avg->entries[avg->pos++] = val;
	if (unlikely(avg->pos == AVG_ENTRIES)) {
		avg->init = 1;
		avg->pos = 0;
	}
}

void darwin_iwi4965::ipw_gather_stats(struct ipw_priv *priv)
{

}

u32 darwin_iwi4965::ipw_get_max_rate(struct ipw_priv *priv)
{

}

u32 darwin_iwi4965::ipw_get_current_rate(struct ipw_priv *priv)
{
	u32 rate;
	unsigned long flags;

	//spin_lock_irqsave(&priv->sta_lock, flags);
	if (priv->iw_mode == IEEE80211_IF_TYPE_IBSS)
		rate = priv->stations[STA_ID].current_rate.s.rate;
	else
		rate = priv->stations[AP_ID].current_rate.s.rate;
	//spin_unlock_irqrestore(&priv->sta_lock, flags);

	switch (rate) {
	case IPW_TX_RATE_1MB:
		return 1000000;
	case IPW_TX_RATE_2MB:
		return 2000000;
	case IPW_TX_RATE_5MB:
		return 5500000;
	case IPW_TX_RATE_6MB:
		return 6000000;
	case IPW_TX_RATE_9MB:
		return 9000000;
	case IPW_TX_RATE_11MB:
		return 11000000;
	case IPW_TX_RATE_12MB:
		return 12000000;
	case IPW_TX_RATE_18MB:
		return 18000000;
	case IPW_TX_RATE_24MB:
		return 24000000;
	case IPW_TX_RATE_36MB:
		return 36000000;
	case IPW_TX_RATE_48MB:
		return 48000000;
	case IPW_TX_RATE_54MB:
		return 54000000;
	}

	return 0;
}

void darwin_iwi4965::ipw_link_down(struct ipw_priv *priv)
{
	ipw_led_link_down(priv);
	//fNetif->setLinkState(kIO80211NetworkLinkDown);
	//netif_carrier_off(priv->net_dev);
	//netif_stop_queue(priv->net_dev);
	//notify_wx_assoc_event(priv);

	/* Cancel any queued work ... */
	queue_td(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan));
	queue_td(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan_check));
	//cancel_delayed_work(&priv->adhoc_check);
	//cancel_delayed_work(&priv->gather_stats);

	ipw_reset_stats(priv);

	if (!(priv->status & STATUS_EXIT_PENDING)) {
		/* Queue up another scan... */
		queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi4965::ipw_scan),priv,3,true);
	}
}

mbuf_t darwin_iwi4965::mergePacket(mbuf_t m)
{
	mbuf_t nm,nm2;
	int offset;
	if(!mbuf_next(m))
	{
		offset = (4 - ((int)(mbuf_data(m)) & 3)) % 4;    //packet needs to be 4 byte aligned
		if (offset==0) return m;
		IWI_DEBUG_FULL("this packet dont have mbuf_next, merge  is not required\n");
		goto copy_packet;
	}

	/* allocate and Initialize New mbuf */
	nm = allocatePacket(mbuf_pkthdr_len(m));
	
	mbuf_setlen(nm,0);
	mbuf_pkthdr_setlen(nm,0);
	
	
	/* merging chains to single mbuf */
	for (nm2 = m; nm2;  nm2 = mbuf_next(nm2)) {
		memcpy (skb_put (nm, mbuf_len(nm2)), (UInt8*)mbuf_data(nm2), mbuf_len(nm2));
	}
	
	/* checking if merged or not. */
	if( mbuf_len(nm) == mbuf_pkthdr_len(m) ) 
		return nm;

	/* merging is not completed. */

	if (!(mbuf_type(nm) == MBUF_TYPE_FREE) ) freePacket(nm);
	nm=NULL;
	return NULL;

copy_packet: 
		
		return copyPacket(m, 0); 
}

void darwin_iwi4965::freePacket2(mbuf_t m)
{
	if (m)
	if (!(mbuf_type(m) & MBUF_TYPE_FREE) && mbuf_len(m)!=0)
	{
		if (!(mbuf_type(m) & MBUF_TYPE_FREE) && mbuf_len(m)!=0 && mbuf_data(m)!=NULL)
		if (!mbuf_next(m))
		{
			//freePacket(m);
			return;
		}
		mbuf_t nm=m;
		while (nm) 
		{
			if (!(mbuf_type(nm) & MBUF_TYPE_FREE) && mbuf_len(nm)!=0 && mbuf_data(nm)!=NULL) 
			{
				nm=mbuf_free(nm);
				//release//freePackets();
			}
			else 
			{
				if (nm)
				{
					mbuf_setlen(nm,0);
					if (mbuf_next(nm))
					{
						nm=mbuf_next(nm);
					}
					else nm=NULL;
				}
			}
		}
	}
}

UInt32 darwin_iwi4965::outputPacket(mbuf_t m, void * param)
{
	IOLog("outputPacket\n");
	if(!(fNetif->getFlags() & IFF_RUNNING) || mbuf_pkthdr_len(m)==0 || m==NULL)
	{
		if (!(mbuf_type(m) == MBUF_TYPE_FREE) ) freePacket(m);
		m=NULL;
		netStats->outputErrors++;
		return kIOReturnOutputDropped;
	}
	
	
	mbuf_t nm;
	int ret = kIOReturnOutputDropped;

	//checking supported packet
	
	IWI_DEBUG("outputPacket t: %d f:%04x\n",mbuf_type(m),mbuf_flags(m));
	
	//drop mbuf is not PKTHDR
	if (!(mbuf_flags(m) & MBUF_PKTHDR) ){
		IWI_ERR("BUG: dont support mbuf without pkthdr and dropped \n");
		netStats->outputErrors++;
		goto finish;
	}
	
	if(mbuf_type(m) == MBUF_TYPE_FREE){
		IWI_ERR("BUG: this is freed packet and dropped \n");
		netStats->outputErrors++;
		goto finish;
	}
	
	nm = mergePacket(m);
	
	if (nm==NULL) 
	{
		netStats->outputErrors++;
		goto finish;
	}
	
	if(mbuf_next(nm)){
		IWI_ERR("BUG: dont support chains mbuf\n");
		IWI_ERR("BUG: tx packet is not single mbuf mbuf_len(%d) mbuf_pkthdr_len(%d)\n",mbuf_len(nm) , mbuf_pkthdr_len(nm) );
		IWI_ERR("BUG: next mbuf size %d\n",mbuf_len(mbuf_next(nm)));
	}
	
	IWI_DEBUG_FULL("call ieee80211_xmit\n");
	//ret  = ieee80211_xmit(nm,priv->net_dev);
	struct ieee80211_tx_control ctrl;
	ret=ipw_tx_skb(priv, nm, &ctrl);

finish:	
	
	/* free finished packet */
	//freePacket(m);
	m=NULL;
	if (ret ==  kIOReturnOutputDropped) { 
		if (!(mbuf_type(nm) == MBUF_TYPE_FREE) ) freePacket(nm);
		//nm=NULL;
	}
	return ret;	
}

struct ieee80211_txb *darwin_iwi4965::ieee80211_alloc_txb(int nr_frags, int txb_size,
						 int headroom, int gfp_mask)
{
	struct ieee80211_txb *txb;
	int i;
	txb = (struct ieee80211_txb *)IOMalloc(sizeof(struct ieee80211_txb) + (sizeof(u8 *) * nr_frags));//, NULL);//gfp_mask);
	if (!txb)
		return NULL;

	memset(txb, 0, sizeof(struct ieee80211_txb));
	txb->nr_frags = nr_frags;
	txb->frag_size = txb_size;

	for (i = 0; i < nr_frags; i++) {
		txb->fragments[i] = allocatePacket(txb_size + headroom);
		//__dev_alloc_skb(txb_size + headroom,						    gfp_mask);
		if (unlikely(!txb->fragments[i])) {
			i--;
			break;
		}
		// default m_len is alocated size in mbuf
		// must set 0 m_len , pkthdr.len . 
		//mbuf_setlen(txb->fragments[i],0);
		//mbuf_pkthdr_setlen(txb->fragments[i],0);

		//skb_reserve(txb->fragments[i], headroom);
		// fix me: should check later
		mbuf_setlen(txb->fragments[i], headroom);
		mbuf_pkthdr_setlen(txb->fragments[i],headroom);
	}
	if (unlikely(i != nr_frags)) {
		while (i >= 0)
		{
			i--;
			if (txb->fragments[i]!=NULL){
				if (!(mbuf_type(txb->fragments[i]) == MBUF_TYPE_FREE) ) freePacket(txb->fragments[i]);
				 txb->fragments[i]=NULL;
			}
			//txb->fragments[i--]=NULL;
		//	dev_kfree_skb_any(txb->fragments[i--]);
		}
		IOFree(txb,sizeof(struct ieee80211_txb) + (sizeof(u8 *) * nr_frags));
		txb=NULL;
		return NULL;
	}
	return txb;
}

int darwin_iwi4965::ieee80211_xmit(mbuf_t skb, struct net_device *dev)
{
	struct ieee80211_device *ieee = (struct ieee80211_device *)priv->ieee;//hack!!
	struct ieee80211_txb *txb = NULL;
	struct ieee80211_hdr_3addrqos *frag_hdr;
	int i, bytes_per_frag, nr_frags, bytes_last_frag, frag_size,
	    rts_required;
	struct net_device_stats *stats = &ieee->stats;
	int ether_type, encrypt, host_encrypt, host_encrypt_msdu, host_build_iv;
	int bytes, fc, hdr_len;
	mbuf_t skb_frag;
	struct ieee80211_hdr_3addrqos header;/* Ensure zero initialized */
		header.duration_id = 0;
		header.seq_ctl = 0;
		header.qos_ctl = 0;
	u8 dest[ETH_ALEN], src[ETH_ALEN];
	struct ieee80211_crypt_data *crypt;
	int priority = 0;//skb->priority;
	int snapped = 0;
	int ret;	  
	//IWI_DEBUG_FN("%d \n",call_count++);
	//if (/* ieee->is_queue_full  && */ ipw_net_is_queue_full(dev, priority))
	/*{
		IWI_LOG( " tx queue is full \n");
		netStats->outputErrors++;
		return kIOReturnOutputDropped;//kIOReturnOutputStall;//NETDEV_TX_BUSY;
	}*/
	//IOLockLock(mutex);
	//spin_lock_irqsave(&ieee->lock, flags);
	/* If there is no driver handler to take the TXB, dont' bother
	 * creating it... */
	/*if (!ieee->hard_start_xmit) {
		printk(KERN_WARNING "%s: No xmit handler.\n", ieee->dev->name);
		goto success;
	}*/

	if (unlikely(mbuf_pkthdr_len(skb) < SNAP_SIZE + sizeof(u16))) {
		IWI_DEBUG_FULL( "%s: skb too small (%d).\n",
		       ieee->dev->name, mbuf_pkthdr_len(skb));
		goto success;
	}
	
	ether_type = ntohs(((struct ethhdr *)(mbuf_data(skb)))->h_proto);

	crypt = ieee->crypt[ieee->tx_keyidx];

	encrypt = !(ether_type == ETH_P_PAE && ieee->ieee802_1x) &&
	    ieee->sec.encrypt;

	host_encrypt = ieee->host_encrypt && encrypt && crypt;
	host_encrypt_msdu = ieee->host_encrypt_msdu && encrypt && crypt;
	host_build_iv = ieee->host_build_iv && encrypt && crypt;

	if (!encrypt && ieee->ieee802_1x &&
	    ieee->drop_unencrypted && ether_type != ETH_P_PAE) {
		stats->tx_dropped++;
		goto success;
	}

	/* Save source and destination addresses */
	memcpy(dest, mbuf_data(skb), ETH_ALEN);
	memcpy(src, ((UInt8*)mbuf_data(skb) + ETH_ALEN), ETH_ALEN);

	if (host_encrypt || host_build_iv)
		fc = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA |
		    IEEE80211_FCTL_PROTECTED;
	else
		fc = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA;

	if (ieee->iw_mode == IW_MODE_INFRA) {
		fc |= IEEE80211_FCTL_TODS;
		/* To DS: Addr1 = BSSID, Addr2 = SA, Addr3 = DA */
		memcpy(header.addr1, ieee->bssid, ETH_ALEN);
		memcpy(header.addr2, src, ETH_ALEN);
		memcpy(header.addr3, dest, ETH_ALEN);
	} else if (ieee->iw_mode == IW_MODE_ADHOC) {
		/* not From/To DS: Addr1 = DA, Addr2 = SA, Addr3 = BSSID */
		memcpy(header.addr1, dest, ETH_ALEN);
		memcpy(header.addr2, src, ETH_ALEN);
		memcpy(header.addr3, ieee->bssid, ETH_ALEN);
	}
	hdr_len = IEEE80211_3ADDR_LEN;

	/*if (qos_enable)
	if (ieee->is_qos_active && ipw_is_qos_active(dev, skb)) {
		fc |= IEEE80211_STYPE_QOS_DATA;
		hdr_len += 2;

		//skb->priority = ieee80211_classify(skb);
		//header.qos_ctl |= cpu_to_le16(skb->priority & IEEE80211_QCTL_TID);
		header.qos_ctl |= cpu_to_le16(priority & IEEE80211_QCTL_TID);
	}*/
	header.frame_ctl = cpu_to_le16(fc);
	
	/* Advance the SKB to the start of the payload */
	skb_pull(skb, sizeof(struct ethhdr));
	
	//mbuf_adj(skb, sizeof(struct ethhdr));
	/* Determine total amount of storage required for TXB packets */
	// fix me : mbuf_pkthdr_len ?
	bytes = mbuf_pkthdr_len(skb) + SNAP_SIZE + sizeof(u16);
	//bytes = mbuf_pkthdr_len(skb) + SNAP_SIZE + sizeof(u16);

	/* Encrypt msdu first on the whole data packet. */
	/*if ((host_encrypt || host_encrypt_msdu) &&
	    crypt && crypt->ops && crypt->ops->encrypt_msdu) {
		IWI_DEBUG_FN("BUG dont support encrypt");
		goto failed;
		int res = 0;
		int len = bytes + hdr_len + crypt->ops->extra_msdu_prefix_len +
		    crypt->ops->extra_msdu_postfix_len;
		mbuf_t skb_new = allocatePacket(len);

		if (unlikely(!skb_new))
			goto failed;

		//skb_reserve(skb_new, crypt->ops->extra_msdu_prefix_len);
		mbuf_setlen(skb_new, crypt->ops->extra_msdu_prefix_len);
		memcpy(skb_put(skb_new, hdr_len), &header, hdr_len);
		//memcpy(((UInt8*)mbuf_data(skb_new)+hdr_len), &header, hdr_len);
		snapped = 1;
		ieee80211_copy_snap((u8*)skb_put(skb_new, SNAP_SIZE + sizeof(u16)),
		//ieee80211_copy_snap(((UInt8*)mbuf_data(skb_new) +SNAP_SIZE + sizeof(u16)),
				    ether_type);
		memcpy(skb_put(skb_new, mbuf_len(skb)), mbuf_data(skb), mbuf_len(skb));
		//memcpy(((UInt8*)mbuf_data(skb_new)+mbuf_len(skb)), mbuf_data(skb), mbuf_len(skb));
		IWI_DEBUG("TODO: msdu encryption\n");
		res = -1;//crypt->ops->encrypt_msdu(skb_new, hdr_len, crypt->priv);
		if (res < 0) {
			IWI_DEBUG("msdu encryption failed\n");
			//dev_kfree_skb_any(skb_new);
			////freePacket(skb);
			if (skb_new!=NULL) //freePacket(skb_new);
			skb_new=NULL;
			goto failed;
		}
		//dev_kfree_skb_any(skb);
		 if (skb!=NULL) //freePacket(skb);
		skb=NULL;
		
		skb = skb_new;
		bytes += crypt->ops->extra_msdu_prefix_len +
		    crypt->ops->extra_msdu_postfix_len;
		skb_pull(skb, hdr_len);
		//mbuf_adj(skb, hdr_len);
	}*/

	if (host_encrypt || ieee->host_open_frag) {
		/* Determine fragmentation size based on destination (multicast
		 * and broadcast are not fragmented) */
		if (is_multicast_ether_addr(dest) ||
		    is_broadcast_ether_addr(dest))
			frag_size = MAX_FRAG_THRESHOLD;
		else
			frag_size = ieee->fts;

		/* Determine amount of payload per fragment.  Regardless of if
		 * this stack is providing the full 802.11 header, one will
		 * eventually be affixed to this fragment -- so we must account
		 * for it when determining the amount of payload space. */
		bytes_per_frag = frag_size - IEEE80211_3ADDR_LEN;
		if (ieee->config &
		    (CFG_IEEE80211_COMPUTE_FCS | CFG_IEEE80211_RESERVE_FCS))
			bytes_per_frag -= IEEE80211_FCS_LEN;

		/* Each fragment may need to have room for encryptiong
		 * pre/postfix */
		if (host_encrypt)
			bytes_per_frag -= crypt->ops->extra_mpdu_prefix_len +
			    crypt->ops->extra_mpdu_postfix_len;

		/* Number of fragments is the total
		 * bytes_per_frag / payload_per_fragment */
		nr_frags = bytes / bytes_per_frag;
		bytes_last_frag = bytes % bytes_per_frag;
		if (bytes_last_frag)
			nr_frags++;
		else
			bytes_last_frag = bytes_per_frag;
	} else {
		nr_frags = 1;
		bytes_per_frag = bytes_last_frag = bytes;
		frag_size = bytes + IEEE80211_3ADDR_LEN;
	}

	rts_required = (frag_size > ieee->rts
			&& ieee->config & CFG_IEEE80211_RTS);
	if (rts_required)
		nr_frags++;
	
	/* When we allocate the TXB we allocate enough space for the reserve
	 * and full fragment bytes (bytes_per_frag doesn't include prefix,
	 * postfix, header, FCS, etc.) */
	
	txb = ieee80211_alloc_txb(nr_frags, frag_size,
				  ieee->tx_headroom, NULL);
	
	if (unlikely(!txb)) {
		IWI_ERR( "%s: Could not allocate TXB\n",
		       ieee->dev->name);
		goto failed;
	}
	
	txb->encrypted = encrypt;
	if (host_encrypt)
		txb->payload_size = frag_size * (nr_frags - 1) +
		    bytes_last_frag;
	else
		txb->payload_size = bytes;

	if (rts_required) {
		skb_frag = txb->fragments[0];
		//frag_hdr =(struct ieee80211_hdr_3addrqos *)((UInt8*)mbuf_data(skb_frag)+hdr_len);
		 frag_hdr =  (struct ieee80211_hdr_3addrqos *)skb_put(skb_frag, hdr_len);

		/*
		 * Set header frame_ctl to the RTS.
		 */
		header.frame_ctl =
		    cpu_to_le16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_RTS);
		memcpy(frag_hdr, &header, hdr_len);

		/*
		 * Restore header frame_ctl to the original data setting.
		 */
		header.frame_ctl = cpu_to_le16(fc);

		if (ieee->config &
		   (CFG_IEEE80211_COMPUTE_FCS | CFG_IEEE80211_RESERVE_FCS))
		   //mbuf_adj(skb_frag, 4);
		       skb_put(skb_frag, 4);

		txb->rts_included = 1;
		i = 1;
	} else
		i = 0;
	
	
	for (; i < nr_frags; i++) {
	
		skb_frag = txb->fragments[i];

		if (host_encrypt || host_build_iv)
		{
			//skb_reserve(skb_frag, crypt->ops->extra_mpdu_prefix_len);
			mbuf_setlen(skb_frag,crypt->ops->extra_mpdu_prefix_len);
			//frag_hdr =(struct ieee80211_hdr_3addrqos *)((UInt8*)mbuf_data(skb_frag)+hdr_len);
			mbuf_pkthdr_setlen(skb_frag,crypt->ops->extra_mpdu_prefix_len);
		}
		frag_hdr  = (struct ieee80211_hdr_3addrqos *)skb_put(skb_frag, hdr_len);
		memcpy(frag_hdr, &header, hdr_len);
		
		IWI_DEBUG_FULL("src " MAC_FMT "desc " MAC_FMT  " bssid " MAC_FMT "\n" ,  
			MAC_ARG(frag_hdr->addr2), MAC_ARG(frag_hdr->addr3) , MAC_ARG(frag_hdr->addr1)  );
		/* If this is not the last fragment, then add the MOREFRAGS
		 * bit to the frame control */
		if (i != nr_frags - 1) {
			frag_hdr->frame_ctl =
			    cpu_to_le16(fc | IEEE80211_FCTL_MOREFRAGS);
			bytes = bytes_per_frag;
		} else {
			/* The last fragment takes the remaining length */
			bytes = bytes_last_frag;
		}
	
	
		if (i == 0 && !snapped) {
			//ieee80211_copy_snap(((UInt8*)mbuf_data(skb_frag)+ SNAP_SIZE + sizeof(u16)),
			ieee80211_copy_snap((u8*)skb_put
						 (skb_frag, SNAP_SIZE + sizeof(u16)),
						ether_type);
			bytes -= SNAP_SIZE + sizeof(u16);
		}
		
		IWI_DUMP_MBUF(3,skb,bytes); 
		IWI_DUMP_MBUF(4,skb_frag,bytes);
		if ( mbuf_trailingspace(skb_frag) < bytes  ) {
			IWI_ERR("freespace is not enough.\n");
			//goto failed; // kazu test
		}
		// FIXME: this routine only copy first mbuf in changes
		//            when mbuf with n_next , must copy next mbuf in chains? 
		memcpy(skb_put(skb_frag, bytes), mbuf_data(skb), bytes);
		
		//memcpy(((UInt8*)mbuf_data(skb_frag)+bytes), mbuf_data(skb), bytes);
		/* Advance the SKB... */
		skb_pull(skb, bytes);
		//mbuf_adj(skb, bytes);
		/* Encryption routine will move the header forward in order
		 * to insert the IV between the header and the payload */
		 
#if 0 /* fix me: encrption */		 
		if (host_encrypt)
			ieee80211_encrypt_fragment(ieee, skb_frag, hdr_len);
		else if (host_build_iv) {
			struct ieee80211_crypt_data *crypt;

			crypt = ieee->crypt[ieee->tx_keyidx];
			atomic_inc(&crypt->refcnt);
			if (crypt->ops->build_iv)
				crypt->ops->build_iv(skb_frag, hdr_len,
				      ieee->sec.keys[ieee->sec.active_key],
				      ieee->sec.key_sizes[ieee->sec.active_key],
				      crypt->priv);
			atomic_dec(&crypt->refcnt);
		}
#endif
		if (ieee->config &
		   (CFG_IEEE80211_COMPUTE_FCS | CFG_IEEE80211_RESERVE_FCS))
			//mbuf_adj(skb_frag, 4);
			skb_put(skb_frag, 4);
	}

      success:
	//spin_unlock_irqrestore(&ieee->lock, flags);
	//IOLockUnlock(mutex);
	//dev_kfree_skb_any(skb);
	//skb=NULL;
	if (skb!=NULL) 
	{
	     if (!(mbuf_type(skb) == MBUF_TYPE_FREE) ) freePacket(skb);
               skb=NULL;
	}

	
	if (txb) {
		//int ret = ipw_tx_skb(priv,txb, priority);
		// test comment out.
		ret=ipw_net_hard_start_xmit(txb,dev,priority); 
				
		if (ret == kIOReturnOutputSuccess) {
			stats->tx_packets++;
			netStats->outputPackets++;
			stats->tx_bytes += txb->payload_size;
			return kIOReturnOutputSuccess;
		}

		ieee80211_txb_free(txb);
		if (!(mbuf_type(skb_frag) == MBUF_TYPE_FREE) ) freePacket(skb_frag);
		skb_frag=NULL;
	}

	return ret;

      failed:
	//spin_unlock_irqrestore(&ieee->lock, flags);
	//IOLockUnlock(mutex);
	//netif_stop_queue(dev);
	IWI_LOG("TX drop\n");
	if (!(mbuf_type(skb) == MBUF_TYPE_FREE) ) freePacket(skb);
	skb=NULL;
	ieee80211_txb_free(txb);
	if (!(mbuf_type(skb_frag) == MBUF_TYPE_FREE) ) freePacket(skb_frag);
	skb_frag=NULL;
	//fTransmitQueue->stop();
	////fTransmitQueue->setCapacity(0);
	//fTransmitQueue->flush();
	stats->tx_errors++;
	netStats->outputErrors++;
	return kIOReturnOutputDropped;
}

int darwin_iwi4965::ipw_net_hard_start_xmit(struct ieee80211_txb *txb,
				   struct net_device *dev, int pri)
{
	//struct ipw_priv *priv = ieee80211_priv(dev);
	int ret;
	//IOInterruptState	instate;

	IWI_DEBUG("dev->xmit(%d bytes)\n", txb->payload_size);
	//spin_lock_irqsave(&priv->lock, flags);
	//IOLockLock(mutex);
	// this is checking of race conditions
	//instate = IOSimpleLockLockDisableInterrupt( spin);
	
	if (!(priv->status & STATUS_ASSOCIATED)) {
		IWI_ERR("Tx attempt while not associated.\n");
		//priv->ieee->stats.tx_carrier_errors++;
		//netif_stop_queue(dev);
		//fTransmitQueue->stop();
		////fTransmitQueue->setCapacity(0);
		//fTransmitQueue->flush();
		goto fail_unlock;
	}
	if (txb->payload_size==0) goto fail_unlock;
	
	//ret = ipw_tx_skb(priv, txb, pri);
//	if (ret == kIOReturnOutputSuccess)//NETDEV_TX_OK)
//		__ipw_led_activity_on(priv);
	//spin_unlock_irqrestore(&priv->lock, flags);
	//IOLockUnlock(mutex);
	//IOSimpleLockUnlockEnableInterrupt( spin, instate );
	
	return ret;

      fail_unlock:
	  //IOLockUnlock(mutex);
	//spin_unlock_irqrestore(&priv->lock, flags);
	//IOSimpleLockUnlockEnableInterrupt( spin, instate );
	return kIOReturnOutputDropped;//kIOReturnOutputStall;
}

u8 darwin_iwi4965::ipw_find_station(struct ipw_priv *priv, u8 * bssid)
{
	int i;
	int start = 0;
	int ret = IPW_INVALID_STATION;
	unsigned long flags;

	if (priv->iw_mode == IEEE80211_IF_TYPE_IBSS)
		start = STA_ID;

	if (ipw_is_broadcast_ether_addr(bssid))
		return priv->hw_setting.broadcast_id;

	//spin_lock_irqsave(&priv->sta_lock, flags);
	for (i = start; i < (start + priv->num_stations); i++)
		if ((priv->stations[i].used) &&
		    (!memcmp
		     (priv->stations[i].sta.sta.MACAddr, bssid, ETH_ALEN))) {
			ret = i;
			goto out;
		}

	IOLog("can not find STA " MAC_FMT " (total %d)\n",
			MAC_ARG(bssid), priv->num_stations);
      out:
	//spin_unlock_irqrestore(&priv->sta_lock, flags);
	return ret;
}

void darwin_iwi4965::ipw_get_supported_rates(struct ipw_priv *priv,
				    struct ieee80211_hdr *hdr,
				    u16 * data_rate, u16 * ctrl_rate)
{
	*data_rate = priv->active_rate;
	*ctrl_rate = priv->active_rate;

	if (hdr && (is_multicast_ether_addr(hdr->addr1))
	    && (priv->active_rate_basic)) {
		*data_rate = priv->active_rate_basic;
		*ctrl_rate = priv->active_rate_basic;
	}
}

int darwin_iwi4965::ipw_build_tx_cmd_rate(struct ipw_priv *priv,
				 struct ipw_cmd *cmd,
				 struct ieee80211_tx_control *ctrl,
				 struct ieee80211_hdr *hdr,
				 int sta_id, int tx_id)
{
	u16 rate_mask, ctrl_rate;
	unsigned long flags;
	int rate = ctrl->tx_rate;
	u8 rts_retry_limit = 0;
	u8 data_retry_limit = 0;
	u32 tx_flags;

	tx_flags = cmd->cmd.tx.tx_flags;

	ipw_get_supported_rates(priv, hdr, &rate_mask, &ctrl_rate);
	rate = ctrl->tx_rate;

	if ((rate & 0xFF) == IPW_INVALID_RATE) {
		IOLog("ERROR: No TX rate available.\n");
		return -1;
	}

	IOLog
	    ("Tx sta %d ew plcp rate %X old %d rate mask %x\n",
	     sta_id, rate,
	     priv->stations[sta_id].current_rate.rate_n_flags, rate_mask);

	//spin_lock_irqsave(&priv->sta_lock, flags);

	priv->stations[sta_id].current_rate.rate_n_flags = rate;

	if ((priv->iw_mode == IEEE80211_IF_TYPE_IBSS) &&
	    (sta_id != priv->hw_setting.broadcast_id) &&
	    (sta_id != MULTICAST_ID))
		priv->stations[STA_ID].current_rate.rate_n_flags = rate;

	//spin_unlock_irqrestore(&priv->sta_lock, flags);

	if (tx_id >= priv->hw_setting.cmd_queue_no)
		rts_retry_limit = 3;
	else
		rts_retry_limit = 7;

	if (ieee80211_is_probe_response(hdr->frame_control)) {
		data_retry_limit = 3;
		if (data_retry_limit < rts_retry_limit)
			rts_retry_limit = data_retry_limit;
	} else
		data_retry_limit = IPW_DEFAULT_TX_RETRY;

	if (priv->data_retry_limit != -1)
		data_retry_limit = priv->data_retry_limit;

	if (WLAN_FC_GET_TYPE(hdr->frame_control) == IEEE80211_FTYPE_MGMT) {
		switch (WLAN_FC_GET_STYPE(hdr->frame_control)) {
		case IEEE80211_STYPE_AUTH:
		case IEEE80211_STYPE_DEAUTH:
		case IEEE80211_STYPE_ASSOC_REQ:
		case IEEE80211_STYPE_REASSOC_REQ:
			if (tx_flags & TX_CMD_FLG_RTS_MSK) {
				tx_flags &= ~TX_CMD_FLG_RTS_MSK;
				tx_flags |= TX_CMD_FLG_CTS_MSK;
			}
			break;
		default:
			break;
		}
	}

	cmd->cmd.tx.rts_retry_limit = rts_retry_limit;
	cmd->cmd.tx.data_retry_limit = data_retry_limit;
	cmd->cmd.tx.rate = rate;
	cmd->cmd.tx.tx_flags = tx_flags;

	/* OFDM */
	cmd->cmd.tx.supp_rates[0] = rate_mask >> 4;

	/* CCK */
	cmd->cmd.tx.supp_rates[1] = rate_mask & 0xF;

	return 0;
}

int darwin_iwi4965::ipw_get_sta_id(struct ipw_priv *priv,
			  struct ieee80211_hdr *hdr)
{
	int sta_id;
	int unicast = !ipw_is_broadcast_ether_addr(hdr->addr1) &&
		!is_multicast_ether_addr(hdr->addr1);

	/* If this frame is not unicast, is not data, or is a probe response
	 * then we use the broadcast station id */
	if ((WLAN_FC_GET_TYPE(hdr->frame_control) != IEEE80211_FTYPE_DATA) ||
	    !unicast || ieee80211_is_probe_response(hdr->frame_control))
		return ipw_find_station(priv, BROADCAST_ADDR);

	/* If this frame is part of a BSS network (we're a station), then
	 * we use the AP's station id */
	if (priv->iw_mode == IEEE80211_IF_TYPE_STA)
		return AP_ID;

	/* If this frame is part of a IBSS network, then we use the
	 * target specific station id */
	if (priv->iw_mode == IEEE80211_IF_TYPE_IBSS) {
		sta_id = ipw_find_station(priv, hdr->addr1);
		if (sta_id != IPW_INVALID_STATION)
			return sta_id;

		sta_id = ipw_add_station(priv, hdr->addr1, 0,
					 (CMD_ASYNC | CMD_NO_LOCK));

		if (sta_id != IPW_INVALID_STATION)
			return sta_id;

		IOLog("Station " MAC_FMT " not in station map. "
			       "Defaulting to broadcast...\n",
			       MAC_ARG(hdr->addr1));
		//printk_buf(IPW_DL_DROP, (u8 *) hdr, sizeof(*hdr));
		return ipw_find_station(priv, BROADCAST_ADDR);
	}

	/* Otherwise we default to the broadcast station id */
	return ipw_find_station(priv, BROADCAST_ADDR);


}

int darwin_iwi4965::ipw_tx_skb(struct ipw_priv *priv, mbuf_t skb, struct ieee80211_tx_control *ctl)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)mbuf_data(skb);
	u8 *tfd;
	u32 *control_flags;
	int tx_id = 0;//ctl->queue + priv->hw_setting.start_cmd_queue;
	struct ipw_tx_queue *txq = &priv->txq[tx_id];
	struct ipw_queue *q = &txq->q;
	dma_addr_t phys_addr, scratch_phys;
	struct ipw_cmd *out_cmd = NULL;
	u16 len, idx;
	u8 id, hdr_len, unicast;
	u8 sta_id;
	u16 seq_number;
	int rc;
	u16 fc;

	if (priv->status & STATUS_RF_KILL_MASK)
		goto drop;

	unicast = !ipw_is_broadcast_ether_addr(hdr->addr1) &&
	    !is_multicast_ether_addr(hdr->addr1);
	id = 0;

	fc = le16_to_cpu(hdr->frame_control);

	if ((priv->status & STATUS_SCANNING) &&
	    (WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) &&
	    (WLAN_FC_GET_STYPE(fc) == IEEE80211_STYPE_PROBE_REQ))
		goto drop;

	hdr_len = ieee80211_get_hdrlen(fc);
	
	sta_id = ipw_get_sta_id(priv, hdr);
	if (sta_id == IPW_INVALID_STATION)
		goto drop;

	IOLog("station Id %d\n", sta_id);
	seq_number = priv->stations[sta_id].tid[tx_id].seq_number;
	priv->stations[sta_id].tid[tx_id].seq_number++;

	tfd = (u8 *) (&txq->bd[q->first_empty * q->element_size]);
	memset(tfd, 0, q->element_size);
	control_flags = (u32 *) tfd;
	idx = get_next_cmd_index(q, q->first_empty, 0);

	memset(&(txq->txb[q->first_empty]), 0, sizeof(struct ipw_tx_info));
	txq->txb[q->first_empty].skb[0] = skb;
	memcpy(&(txq->txb[q->first_empty].status.control),
	       ctl, sizeof(struct ieee80211_tx_control));
	out_cmd = &txq->cmd[idx];
	memset(&out_cmd->hdr, 0, sizeof(out_cmd->hdr));
	memset(&out_cmd->cmd.tx, 0, sizeof(out_cmd->cmd.tx));
	out_cmd->hdr.cmd = REPLY_TX;
	out_cmd->hdr.sequence = FIFO_TO_SEQ(tx_id) |
	    INDEX_TO_SEQ(q->first_empty);
	/* copy frags header */
	memcpy(out_cmd->cmd.tx.hdr, hdr, hdr_len);

	//hdr = (struct ieee80211_hdr *)out_cmd->cmd.tx.hdr;
	len = priv->hw_setting.tx_cmd_len +
	    sizeof(struct ipw_cmd_header) + hdr_len;

	len = (len + 3) & ~3;

	phys_addr =
	    txq->dma_addr_cmd + sizeof(struct ipw_cmd) * idx +
	    offsetof(struct ipw_cmd, hdr);

	scratch_phys = phys_addr;

	attach_buffer_to_tfd_frame(&tfd, phys_addr, cpu_to_le16(len));

	//if (ctl->key_idx != -1)
	//	ipw_build_tx_cmd_hwcrypto(priv, ctl, out_cmd, skb, 0);

	mbuf_adj(skb,hdr_len);//todo check if works
	skb_push(skb,hdr_len);
	phys_addr=cpu_to_le32(mbuf_data_to_physical(mbuf_data(skb)));		
	/*phys_addr = cpu_to_le32(pci_map_single(priv->pci_dev,
					       skb->
					       data + hdr_len,
					       skb->
					       len - hdr_len,
					       PCI_DMA_TODEVICE));*/
	len = mbuf_len(skb);// - hdr_len;
	attach_buffer_to_tfd_frame(&tfd, phys_addr, cpu_to_le16(len));

	out_cmd->cmd.tx.len = mbuf_len(skb);
	if (priv->is_3945)
		*control_flags = TFD_CTL_COUNT_SET(2) |
		    TFD_CTL_PAD_SET(U32_PAD(len));

	//todoG need this for burst mode later on
	if (ipw_build_tx_cmd_basic(priv, out_cmd,
				   ctl, hdr, unicast, sta_id, tx_id)) {
		IOLog("tx build cmd basic failed.\n");
		goto drop;
	}

	if (ipw_build_tx_cmd_rate(priv, out_cmd, ctl, hdr, sta_id, tx_id)) {
		IOLog("tx cmd rate scale  failed.\n");
		goto drop;
	}

	IOLog("Tx rate %d (%02X:%02X)\n",
		     out_cmd->cmd.tx.rate,
		     out_cmd->cmd.tx.supp_rates[0],
		     out_cmd->cmd.tx.supp_rates[1]);

	len = out_cmd->cmd.tx.len;
	out_cmd->cmd.tx.tx_flags |= TX_CMD_FLG_SEQ_CTL_MSK;

	//printk_buf(IPW_DL_TX, out_cmd->cmd.payload, sizeof(out_cmd->cmd.tx));

	//printk_buf(IPW_DL_TX, (u8 *) out_cmd->cmd.tx.hdr,
	//	   ieee80211_get_hdrlen(out_cmd->cmd.tx.hdr->frame_control));

	//priv->hw_setting.tx_cmd
	ipw3945_tx_cmd(priv, out_cmd, sta_id, scratch_phys,
				hdr, hdr_len, ctl);

	txq->need_update = 1;

	//rc = priv->hw_setting.tx_queue_update_wr_ptr(priv, txq, tx_id, len);
	q->first_empty = ipw_queue_inc_wrap(q->first_empty, q->n_bd);
	rc = ipw_tx_queue_update_write_ptr(priv, txq, tx_id);

	if (rc)
		return rc;
	if ((ipw_queue_space(q) < q->high_mark)
	    && priv->netdev_registered) fTransmitQueue->stop();
	//	ieee80211_stop_queue(priv->ieee, ctl->queue);

	return kIOReturnOutputSuccess;

      drop:
	IOLog("Silently dropping Tx packet.\n");
	return kIOReturnOutputDropped;
}

int darwin_iwi4965::ipw_build_tx_cmd_basic(struct ipw_priv *priv,
				  struct ipw_cmd *cmd,
				  struct ieee80211_tx_control *ctrl,
				  struct ieee80211_hdr *hdr,
				  int is_unicast, u8 std_id, int tx_id)
{
	u32 tx_flags;
	u16 fc = le16_to_cpu(hdr->frame_control);

	tx_flags = cmd->cmd.tx.tx_flags;

	cmd->cmd.tx.u.life_time = 0xFFFFFFFF;
	if (!ctrl->flags & IEEE80211_TXCTL_NO_ACK) {
		tx_flags |= TX_CMD_FLG_ACK_MSK;
		if (WLAN_FC_GET_TYPE(hdr->frame_control) ==
		    IEEE80211_FTYPE_MGMT) {
			tx_flags |= TX_CMD_FLG_SEQ_CTL_MSK;
		}
		if (ieee80211_is_probe_response(hdr->frame_control)) {
			if ((hdr->seq_ctrl & 0x000F) == 0) {
				tx_flags |= TX_CMD_FLG_TSF_MSK;
			}
		}
	} else {
		tx_flags &= (~TX_CMD_FLG_ACK_MSK);
		tx_flags |= TX_CMD_FLG_SEQ_CTL_MSK;
	}

	if (std_id == IPW_INVALID_STATION)
		return -1;

	cmd->cmd.tx.sta_id = std_id;
	if (ieee80211_get_morefrag(hdr))
		tx_flags |= TX_CMD_FLG_MORE_FRAG_MSK;
	if (ieee80211_get_hdrlen(fc) == 26) {
		u8 *qc =
		    (u8 *) hdr + ieee80211_get_hdrlen(fc) - 2;
		cmd->cmd.tx.tid_tspec = (u8) (qc[0] & 0x0F);
	} else
		tx_flags |= TX_CMD_FLG_SEQ_CTL_MSK;

	if (ctrl->flags & IEEE80211_TXCTL_USE_RTS_CTS) {
		tx_flags |= TX_CMD_FLG_RTS_MSK;
		tx_flags &= ~TX_CMD_FLG_CTS_MSK;
	} else if (ctrl->flags & IEEE80211_TXCTL_USE_CTS_PROTECT) {
		tx_flags &= ~TX_CMD_FLG_RTS_MSK;
		tx_flags |= TX_CMD_FLG_CTS_MSK;
	}

	if ((tx_flags & TX_CMD_FLG_RTS_MSK) || (tx_flags & TX_CMD_FLG_CTS_MSK))
		tx_flags |= TX_CMD_FLG_FULL_TXOP_PROT_MSK;

	tx_flags &= ~(TX_CMD_FLG_ANT_SEL_MSK);
	if (WLAN_FC_GET_TYPE(hdr->frame_control) == IEEE80211_FTYPE_MGMT) {
		if (((WLAN_FC_GET_STYPE(hdr->frame_control)) ==
		     IEEE80211_STYPE_ASSOC_REQ)
		    || ((WLAN_FC_GET_STYPE(hdr->frame_control)) ==
			IEEE80211_STYPE_REASSOC_REQ)) {
			cmd->cmd.tx.u2.pm_frame_timeout = 3;
		} else {
			cmd->cmd.tx.u2.pm_frame_timeout = 2;
		}
	} else
		cmd->cmd.tx.u2.pm_frame_timeout = 0;

	cmd->cmd.tx.driver_txop = 0;

	cmd->cmd.tx.tx_flags = tx_flags;

	cmd->cmd.tx.next_frame_len = 0;

	return 0;
}

int darwin_iwi4965::ipw3945_tx_cmd(struct ipw_priv *priv, struct ipw_cmd *out_cmd,
		   u8 sta_id, dma_addr_t scratch_phys,
		   struct ieee80211_hdr *hdr, u8 hdr_len,
		   struct ieee80211_tx_control *ctrl)
{
	out_cmd->cmd.tx.tx_flags &= ~TX_CMD_FLG_ANT_A_MSK;
	out_cmd->cmd.tx.tx_flags &= ~TX_CMD_FLG_ANT_B_MSK;
	return 0;
}

u8 P802_1H_OUI[P80211_OUI_LEN] = { 0x00, 0x00, 0xf8 };
u8 RFC1042_OUI[P80211_OUI_LEN] = { 0x00, 0x00, 0x00 };

int darwin_iwi4965::ieee80211_copy_snap(u8 * data, u16 h_proto)
{
	struct ieee80211_snap_hdr *snap;
	u8 *oui;

	snap = (struct ieee80211_snap_hdr *)data;
	snap->dsap = 0xaa;
	snap->ssap = 0xaa;
	snap->ctrl = 0x03;

	if (h_proto == 0x8137 || h_proto == 0x80f3)
		oui = P802_1H_OUI;
	else
		oui = RFC1042_OUI;
	snap->oui[0] = oui[0];
	snap->oui[1] = oui[1];
	snap->oui[2] = oui[2];

	*(u16 *) (data + SNAP_SIZE) = htons(h_proto);

	return SNAP_SIZE + sizeof(u16);
}

const char* darwin_iwi4965::ipw_get_status_code(u16 status)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(ipw_status_codes); i++)
		if (ipw_status_codes[i].status == (status & 0xff))
			return ipw_status_codes[i].reason;
	return "Unknown status value.";
}

void darwin_iwi4965::notifIntr(struct ipw_priv *priv,
				struct ipw_rx_notification *notif)
{
	
}

int ConnectClient(kern_ctl_ref kctlref,struct sockaddr_ctl *sac,void **unitinfo)
{
	IWI_LOG("connect\n");
	clone->userInterfaceLink=1;
	return(0);
}

int disconnectClient(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo)
{
	clone->userInterfaceLink=0;
	IWI_LOG("disconnect\n");
	return(0);
}

int configureConnection(kern_ctl_ref ctlref, u_int unit, void *userdata, int opt, void *data, size_t len)
{
	//int i=*((int*)data);
	if (opt==4)// mode
	{
		int m=*((int*)data);
		m=m-1;
		IWI_LOG("setting mode to %d\n",m);
		if (clone->priv->config & CFG_NO_LED) clone->led=0; else clone->led=1;
		clone->associate=0;
		clone->mode=m;
		clone->ipw_sw_reset(0);
		clone->ipw_down(clone->priv);
	}
	if (opt==3)// led
	{
		/*if (clone->priv->config & CFG_NO_LED)
			clone->priv->config &= ~CFG_NO_LED;
		else
			clone->priv->config |= CFG_NO_LED;
			
		if (clone->priv->config & CFG_NO_LED) clone->ipw_led_shutdown(clone->priv);
		else clone->ipw_led_link_on(clone->priv);*/
	}
	if (opt==2) //associate network.
	{
		//todo: check other priv status
		/*clone->priv->status |= STATUS_RF_KILL_HW;
		clone->priv->status &= ~(STATUS_ASSOCIATED | STATUS_ASSOCIATING);
		clone->setLinkStatus(kIONetworkLinkValid);
		if ((clone->fNetif->getFlags() & IFF_RUNNING)) clone->ipw_link_down(clone->priv); else clone->ipw_led_link_off(clone->priv);
		clone->priv->status &= ~STATUS_RF_KILL_HW;
		struct ieee80211_network *network = NULL;	
		struct ipw_network_match match = {NULL};
		struct ipw_supported_rates *rates;
		
		list_for_each_entry(network, &clone->priv->ieee->network_list, list) 
		{
			if (!memcmp(network->bssid,((struct ieee80211_network *)data)->bssid,sizeof(network->bssid)))
			{
				clone->ipw_best_network(clone->priv, &match, network, 0);
				goto ex1;;
			}
		}
		ex1:
		network = match.network;
		rates = &match.rates;
		if (network == NULL)
		{
			IWI_LOG("can't associate to this network\n");
			return 1;
		}
		int rep=0;
		while (!(clone->priv->status & STATUS_ASSOCIATED)) 
		{
			clone->ipw_adapter_restart(clone->priv);
			IODelay(5000*1000);
			clone->ipw_associate_network(clone->priv, network, rates, 0);
			IODelay(5000*1000);
			rep++;
			if (rep==5) break;
		}
		if (rep == 5)
		{
			IWI_LOG("failed when associating to this network\n");
			return 1;
		}*/
	}
	if (opt==1) //HACK: start/stop the nic
	{
		if (clone->priv->status & (STATUS_RF_KILL_SW | STATUS_RF_KILL_HW)) // off -> on
		{
			clone->priv->config &= ~CFG_ASSOCIATE;
			/*int q=0;
			if (clone->rf_kill_active(clone->priv)) 
			{	
				if (clone->ipw_read32(0x05c)==0x40001)// clone->ipw_write32(0x30, 0x1);//0x0f0ff);
				//else 
				clone->ipw_write32(0x05c, clone->ipw_read32(0x05c) - 0x1);
				
				if (clone->ipw_read32(0x05c)!=0x50000)
				{
					UInt32 r1=0;
					while (!((clone->priv->status & STATUS_SCANNING)))
					//( clone->ipw_read32(0x30)!=0x50000 ) 
					{
						clone->ipw_write32(0x05c, 0x1);// clone->ipw_read32(0x30) + 0x1);
						//if (clone->priv->status & STATUS_SCANNING) break;
						r1++;
						//if (r1==5000000) break;
					}
					//UInt32 r=0x50001 - clone->ipw_read32(0x30);
					clone->ipw_write32(0x05c, 0x50001);//clone->ipw_read32(0x30) + r);
					//UInt32 r=clone->ipw_read32(0x30)- 0x50000;
					//clone->ipw_write32(0x30, clone->ipw_read32(0x30) - r+1);
					//if (r1==5000000 && (clone->priv->status & STATUS_RF_KILL_HW)) return 0;
				}
			} else q=1;*/
			IWI_LOG("radio on 0x40000 = 0x%x\n",clone->ipw_read32(0x05c));
			clone->priv->status &= ~STATUS_RF_KILL_HW;
			clone->priv->status &= ~STATUS_RF_KILL_SW;
			clone->priv->status &= ~(STATUS_ASSOCIATED | STATUS_ASSOCIATING);
			clone->ipw_scan_initiate(clone->priv,0);
			//clone->pl=1;
			//clone->ipw_up(clone->priv);
		}
		else
		{
			/*if (!(clone->rf_kill_active(clone->priv))) 
			{
				if (clone->ipw_read32(0x05c)==0x50000) clone->ipw_write32(0x05c, 0x1);
				else 
				clone->ipw_write32(0x05c, clone->ipw_read32(0x05c) - 0x1);
				
				if (clone->ipw_read32(0x05c)!=0x40000)
				{
					UInt32 r1=0;
					while ( clone->ipw_read32(0x05c)!=0x40000 ) 
					{
						clone->ipw_write32(0x05c, clone->ipw_read32(0x05c) + 0x1);
						r1++;
						if (r1==5000000) break;
					}
					UInt32 r=clone->ipw_read32(0x05c)- 0x40000;
					clone->ipw_write32(0x05c, clone->ipw_read32(0x05c) - r+1);
				}
			}*/
			IWI_LOG("radio off 0x40000 = 0x%x\n",clone->ipw_read32(0x05c));
			clone->priv->status |= STATUS_RF_KILL_HW;
			clone->priv->status &= ~STATUS_RF_KILL_SW;
			clone->priv->status &= ~(STATUS_ASSOCIATED | STATUS_ASSOCIATING);
			clone->setLinkStatus(kIONetworkLinkValid);
			//clone->ipw_down(clone->priv);
		}	
	}

	return(0);
}

int sendNetworkList(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,int opt, void *data, size_t *len)
{
	if (opt==0) memcpy(data,clone->priv,*len);
	if (opt==1) memcpy(data,clone->priv->ieee,*len);
	if (opt==2)
	{
		/*struct ieee80211_network *n=NULL,*n2=(struct ieee80211_network*)data;
		int i=0;
		list_for_each_entry(n, &clone->priv->ieee->network_list, list)
		{
			i++;
			if (n2->ssid_len==0)
			{
				memcpy(data,n,*len);
				goto ex;
			}
			else
			{
				if (!memcmp(n2->bssid,n->bssid,sizeof(n->bssid)) && n->ssid_len>0)
				{
					//memcpy(data,&n0,*len);
					n2->ssid_len=0;
					//n2=(struct ieee80211_network*)data;
				}
			}
		}
		ex:
		IWI_LOG("found %d networks\n",i);*/
	}
	if (opt==3) memcpy(data,clone->priv->assoc_network,*len);
	if (opt==4)
	{	
		if (clone->netStats->outputPackets<30 || !(clone->priv->status & STATUS_ASSOCIATED)) return 1;
		ifaddr_t *addresses;
		struct sockaddr *out_addr, ou0;
		out_addr=&ou0;
		int p=0;
		if (ifnet_get_address_list_family(clone->fifnet, &addresses, AF_INET)==0)
		{
			if (!addresses[0]) p=1;
			else
			if (ifaddr_address(addresses[0], out_addr, sizeof(*out_addr))==0)
			{
				//IWI_LOG("my ip address: " IP_FORMAT "\n",IP_LIST(out_addr->sa_data));
				memcpy(data,out_addr->sa_data,*len);
				/*if (clone->priv->ieee->iw_mode == IW_MODE_INFRA)
				if ((int)(IP_CH(out_addr->sa_data)[2])==169 && (int)(IP_CH(out_addr->sa_data)[3])==254)
				{
					IWI_LOG("no internet connection!\n");// dissasociate , invalidade this network, re-scan
					clone->priv->assoc_network->exclude=1;
				}*/
			}
			else p=1;
			ifnet_free_address_list(addresses);
		} else p=1;
		if (p==1) return 1;
	}
	if (opt==5) memcpy(data,clone->priv->net_dev,*len);
	return (0);
}

int setSelectedNetwork(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,mbuf_t m, int flags)
{
return 0;
}
