/*ipw3945: priv->ucode_raw->size: 111572
ipw3945: ucode->boot_size: 900
ipw3945: ucode->inst_size: 77888
ipw3945: ucode->data_size: 32768
ipw3945: sizeof(*ucode):  16
*/
#include "firmware/ipw3945.ucode.h"
#include "defines.h"


// Define my superclass
#define super IO80211Controller
// REQUIRED! This macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires. Do NOT use super as the
// second parameter. You must use the literal name of the superclass.
OSDefineMetaClassAndStructors(darwin_iwi3945, IO80211Controller);

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

	 
bool darwin_iwi3945::init(OSDictionary *dict)
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
  associate = 1;
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


int darwin_iwi3945::ipw_sw_reset(int option)
{

	int err = 0;
	struct net_device *net_dev;
	void __iomem *base;
	u32 length, val;
	int i;
	struct ieee80211_device *ieee;
	
	
	//net_dev=(struct net_device*)fifnet;
	net_dev=&net_dev2;
	//memset(&net_dev,0,sizeof(struct ieee80211_device) + sizeof(struct ipw_priv));
	if (!net_dev) {
		IOLog("Unable to network device.\n");
		return -1;
	}
	
	//ieee = (struct ieee80211_device*)netdev_priv(net_dev);
	ieee=&ieee2;
	ieee->dev = net_dev;

	(void*)ieee->networks = kmalloc(MAX_NETWORK_COUNT * sizeof(struct ieee80211_network), GFP_KERNEL);
	memset(ieee->networks, 0, MAX_NETWORK_COUNT * sizeof(struct ieee80211_network));
	INIT_LIST_HEAD(&ieee->network_free_list);
	INIT_LIST_HEAD(&ieee->network_list);
	for (i = 0; i < MAX_NETWORK_COUNT; i++)
		list_add_tail(&ieee->networks[i].list,
			      &ieee->network_free_list);
	/* Default fragmentation threshold is maximum payload size */
	ieee->fts = DEFAULT_FTS;
	ieee->rts = DEFAULT_FTS;
	ieee->scan_age = DEFAULT_MAX_SCAN_AGE;
	ieee->open_wep = 1;

	/* Default to enabling full open WEP with host based encrypt/decrypt */
	ieee->host_encrypt = 1;
	ieee->host_decrypt = 1;
	ieee->host_mc_decrypt = 1;

	/* Host fragementation in Open mode. Default is enabled.
	 * Note: host fragmentation is always enabled if host encryption
	 * is enabled. For cards can do hardware encryption, they must do
	 * hardware fragmentation as well. So we don't need a variable
	 * like host_enc_frag. */
	ieee->host_open_frag = 1;
	ieee->ieee802_1x = 1;	/* Default to supporting 802.1x */

	INIT_LIST_HEAD(&ieee->crypt_deinit_list);
	//init_timer(&ieee->crypt_deinit_timer);
	ieee->crypt_deinit_timer.data = (unsigned long)ieee;
	//ieee->crypt_deinit_timer.function = ieee80211_crypt_deinit_handler;
	ieee->crypt_quiesced = 0;

	ieee->wpa_enabled = 0;
	ieee->drop_unencrypted = 0;
	ieee->privacy_invoked = 0;

	priv = &priv2;
	//priv=(struct ipw_priv*)ieee80211_priv(net_dev);
	priv->ieee = ieee;

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

	//INIT_LIST_HEAD(&priv->daemon_in_list);
	//INIT_LIST_HEAD(&priv->daemon_out_list);
	//INIT_LIST_HEAD(&priv->daemon_free_list);

	memset(&(priv->txq[0]), 0, sizeof(struct ipw_tx_queue) * 6);
	memset(&priv->card_alive, 0, sizeof(struct ipw_alive_resp));
	priv->data_retry_limit = -1;
	priv->auth_state = AUTH_INIT;

	priv->hw_base = memBase;

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
		priv->ieee->iw_mode = IW_MODE_ADHOC;
		break;
	case 2:
		priv->ieee->iw_mode = IW_MODE_MONITOR;
		break;
	default:
	case 0:
		priv->ieee->iw_mode = IW_MODE_INFRA;
		break;
	}

	priv->ieee->mode = IEEE_G | IEEE_B;
	priv->ieee->freq_band = IEEE80211_24GHZ_BAND;
	priv->ieee->modulation = IEEE80211_OFDM_MODULATION |
	    IEEE80211_CCK_MODULATION;

	u32 pci_id = (deviceID << 16) | vendorID;
	//fPCIDevice->configRead16(kIOPCIConfigDeviceID) | fPCIDevice->configRead16(kIOPCIConfigVendorID);
	IWI_LOG("pci_id 0x%08x\n",pci_id);
	switch (pci_id) {
	case 0x42221005:	/* 0x4222 0x8086 0x1005 is BG SKU */
	case 0x42221034:	/* 0x4222 0x8086 0x1034 is BG SKU */
	case 0x42271014:	/* 0x4227 0x8086 0x1014 is BG SKU */
	case 0x42221044:	/* 0x4222 0x8086 0x1044 is BG SKU */
		priv->is_abg = 0;
		break;

	default:		/* Rest are assumed ABG SKU -- if this is not the
				 * case then the card will get the wrong 'Detected'
				 * line in the kernel log however the code that
				 * initializes the GEO table will detect no A-band
				 * channels and remove the is_abg mask. */
		priv->ieee->mode |= IEEE_A;
		priv->ieee->freq_band |= IEEE80211_52GHZ_BAND;
		priv->is_abg = 1;
		break;
	}

	IOLog(": Detected Intel PRO/Wireless 3945%s Network Connection\n",
	       priv->is_abg ? "ABG" : "BG");

	if (channel != 0) {
		priv->config |= CFG_STATIC_CHANNEL;
		priv->channel = channel;
		IOLog("Bind to static channel %d\n", channel);
		/* TODO: Validate that provided channel is in range */
	} else
		priv->channel = 1;

	ipw_read_ucode(priv);


	priv->rates_mask = IEEE80211_DEFAULT_RATES_MASK |
	    (IEEE80211_OFDM_BASIC_RATES_MASK |
	     IEEE80211_CCK_BASIC_RATES_MASK) << 16;
	priv->missed_beacon_threshold = IPW_MB_DISASSOCIATE_THRESHOLD_DEFAULT;
	priv->roaming_threshold = IPW_MB_ROAMING_THRESHOLD_DEFAULT;
	priv->rts_threshold = DEFAULT_RTS_THRESHOLD;
	/* If power management is turned on, default to AC mode */
	priv->power_mode = IPW_POWER_AC;
	priv->actual_txpower_limit = IPW_DEFAULT_TX_POWER;
	priv->ieee->perfect_rssi = -20;
	priv->ieee->worst_rssi = -95;

	IOLog("Waiting for ipw3945d to request INIT.\n");

	return 0;
	
}

int darwin_iwi3945::ipw_read_ucode(struct ipw_priv *priv)
{
	struct ipw_ucode *ucode;
	int rc = 0;
	struct firmware *ucode_raw;
	const char *name = "iwlwifi-3945.ucode";	/* firmware file name */
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

IOOptionBits darwin_iwi3945::getState( void ) const
{
	IOOptionBits r=super::getState();
	IOLog("getState = %x\n",r);
	return r;
}

bool darwin_iwi3945::start(IOService *provider)
{
	UInt16	reg;

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
			this, (IOInterruptEventAction) &darwin_iwi3945::interruptOccurred,
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
		
		ipw_sw_reset(1);
		//resetDevice((UInt16 *)memBase); //iwi2200 code to fix
		ipw_nic_init(priv);
		//ipw_nic_reset(priv);
		//ipw_bg_resume_work();
		
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
		//IW_SCAN_TYPE_ACTIVE
		queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan),NULL,NULL,false);
		queue_te(1,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_adapter_restart),NULL,NULL,false);
		queue_te(2,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_led_link_on),NULL,NULL,false);
		queue_te(3,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_rf_kill),NULL,NULL,false);
		queue_te(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan_check),NULL,NULL,false);
		queue_te(5,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_associate),NULL,NULL,false);
		queue_te(6,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_gather_stats),NULL,NULL,false);
		queue_te(7,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_rx_queue_replenish),NULL,NULL,false);
		//queue_te(8,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_adhoc_check),NULL,NULL,false);
		//queue_te(9,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_bg_qos_activate),NULL,NULL,false);
		queue_te(8,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_led_activity_off),NULL,NULL,false);
		
		pl=1;
		return true;			// end start successfully
	} while (false);
		
	//stop(provider);
	free();
	return false;			// end start insuccessfully
}

void darwin_iwi3945::ipw_bg_resume_work()
{
	unsigned long flags;

	//mutex_lock(&priv->mutex);
	IOLockLock(mutex);
	
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
	IOLockUnlock(mutex);
}

IOReturn darwin_iwi3945::selectMedium(const IONetworkMedium * medium)
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

bool darwin_iwi3945::addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name) {	
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

IOOutputQueue * darwin_iwi3945::createOutputQueue( void )
{
	// An IOGatedOutputQueue will serialize all calls to the driver's
    // outputPacket() function with its work loop. This essentially
    // serializes all access to the driver and the hardware through
    // the driver's work loop, which simplifies the driver but also
    // carries a small performance cost (relatively for 10/100 Mb).

    return IOGatedOutputQueue::withTarget( this, getWorkLoop() );
}

bool darwin_iwi3945::createWorkLoop( void )
{
    fWorkLoop = IOWorkLoop::workLoop();
	
    return ( fWorkLoop != 0 );
}

IOWorkLoop * darwin_iwi3945::getWorkLoop( void ) const
{
    // Override IOService::getWorkLoop() method to return the work loop
    // we allocated in createWorkLoop().

	return fWorkLoop;
}

const OSString * darwin_iwi3945::newVendorString( void ) const
{
    return OSString::withCString("Intel");
}

const OSString * darwin_iwi3945::newModelString( void ) const
{
    const char * model = "3945";

    return OSString::withCString(model);
}

int darwin_iwi3945::ipw_stop_nic()
{

}

int darwin_iwi3945::ipw_init_nic()
{

}

int darwin_iwi3945::ipw_reset_nic(struct ipw_priv *priv)
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


void darwin_iwi3945::ipw_start_nic()
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

inline void darwin_iwi3945::ipw_enable_interrupts(struct ipw_priv *priv)
{
	if (priv->status & STATUS_INT_ENABLED)
		return;
	priv->status |= STATUS_INT_ENABLED;
	ipw_write32(IPW_INTA_MASK_R, IPW_INTA_MASK_ALL);
}

int darwin_iwi3945::ipw_load(struct ipw_priv *priv)
{
	
}

int darwin_iwi3945::rf_kill_active(struct ipw_priv *priv)
{
	if (0 == (ipw_read32( 0x30) & 0x10000))
		priv->status |= STATUS_RF_KILL_HW;
	else
		priv->status &= ~STATUS_RF_KILL_HW;

	return (priv->status & STATUS_RF_KILL_HW) ? 1 : 0;
}

void darwin_iwi3945::ipw_adapter_restart(ipw_priv *adapter)
{
	struct ipw_priv *priv = adapter;
	if (priv->status & STATUS_RF_KILL_MASK)
		return;

	IOLog("ipw_adapter_restart\n");
	//queue_td(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan));
	//queue_td(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan_check));
	//priv->status |= STATUS_RF_KILL_HW;
	//queue_td(2,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_led_link_on));
	//priv->status  &= ~(STATUS_RF_KILL_HW);
	ipw_down(priv);
	
	if (priv->assoc_network &&
	    (priv->assoc_network->capability & WLAN_CAPABILITY_IBSS))
		ipw_remove_current_network(priv);

	
	pl=1;
	if (ipw_up(priv)) {
		IOLog("Failed to up device\n");
		return;
	}
}

void darwin_iwi3945::ipw_remove_current_network(struct ipw_priv *priv)
{
	struct list_head *element, *safe;
	struct ieee80211_network *network = NULL;
	unsigned long flags;

	list_for_each_safe(element, safe, &priv->ieee->network_list) {
		network = list_entry(element, struct ieee80211_network, list);
		if (!memcmp(network->bssid, priv->bssid, ETH_ALEN)) {
			list_del(element);
			list_add_tail(&network->list,
				      &priv->ieee->network_free_list);
		}
	}
}

void darwin_iwi3945::ipw_rf_kill(ipw_priv *priv)
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
			ipw_down(priv);
	} else {
		priv->led_state = IPW_LED_LINK_RADIOOFF;

		if (!(priv->status & STATUS_RF_KILL_HW))
			IOLog
			    ("Can not turn radio back on - "
			     "disabled by SW switch\n");
		else
			IOLog
			    ("Radio Frequency Kill Switch is On:\n"
			     "Kill switch must be turned off for "
			     "wireless networking to work.\n");
	}
	//mutex_unlock(&priv->mutex);
}

int darwin_iwi3945::ipw_set_geo(struct ieee80211_device *ieee,
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

IOReturn darwin_iwi3945::setPowerState ( unsigned long powerStateOrdinal, IOService* whatDevice )
{
	IOLog("setPowerState to %d\n",powerStateOrdinal);
	power=powerStateOrdinal;
	return super::setPowerState(powerStateOrdinal,whatDevice);
}

void darwin_iwi3945::ipw_init_ordinals(struct ipw_priv *priv)
{

}

int darwin_iwi3945::ipw_grab_restricted_access(struct ipw_priv *priv)
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
			IOLog("MAC is in deep sleep!\n");
			//return -EIO;
		}
	//}

	priv->status |= STATUS_RESTRICTED;

	return 0;

}

void darwin_iwi3945::_ipw_write_restricted(struct ipw_priv *priv,
					 u32 reg, u32 value)
{
//      _ipw_grab_restricted_access(priv);
	_ipw_write32(memBase, reg, value);
//      _ipw_release_restricted_access(priv);
}

void darwin_iwi3945::_ipw_write_restricted_reg(struct ipw_priv *priv,
					     u32 addr, u32 val)
{
	_ipw_write_restricted(priv, HBUS_TARG_PRPH_WADDR,
			      ((addr & 0x0000FFFF) | (3 << 24)));
	_ipw_write_restricted(priv, HBUS_TARG_PRPH_WDAT, val);
}

int darwin_iwi3945::ipw_copy_ucode_images(struct ipw_priv *priv,
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

void darwin_iwi3945::_ipw_release_restricted_access(struct ipw_priv
						  *priv)
{
	ipw_clear_bit(CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);

	priv->status &= ~STATUS_RESTRICTED;
}

void darwin_iwi3945::ipw_write_restricted_reg_buffer(struct ipw_priv
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


int darwin_iwi3945::ipw_download_ucode_base(struct ipw_priv *priv, u8 * image, u32 len)
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

u32 darwin_iwi3945::_ipw_read_restricted_reg(struct ipw_priv *priv, u32 reg)
{
	_ipw_write_restricted(priv, HBUS_TARG_PRPH_RADDR, reg | (3 << 24));
	return _ipw_read_restricted(priv, HBUS_TARG_PRPH_RDAT);
}

u32 darwin_iwi3945::_ipw_read_restricted(struct ipw_priv *priv, u32 reg)
{
	u32 val;
//      _ipw_grab_restricted_access(priv);
	val = _ipw_read32(memBase, reg);
//      _ipw_release_restricted_access(priv);
	return val;
}

int darwin_iwi3945::attach_buffer_to_tfd_frame(struct tfd_frame *tfd,
				      dma_addr_t addr, u16 len)
{
	int count = 0;
	u32 pad;

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

void darwin_iwi3945::ipw_write_buffer_restricted(struct ipw_priv *priv,
					u32 reg, u32 len, u32 * values)
{
	u32 count = sizeof(u32);
	if ((priv != NULL) && (values != NULL)) {
		for (; 0 < len; len -= count, reg += count, values++)
			_ipw_write_restricted(priv, reg, *values);
	}
}

int darwin_iwi3945::ipw_download_ucode(struct ipw_priv *priv,
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
		IOLog("3945ABG card ucode DOWNLOAD FAILED \n");
		goto done;
	}

	rc = 0;

	IOLog("3945ABG card ucode download is good \n");

	_ipw_write_restricted(priv, FH_TCSR_CREDIT(ALM_FH_SRVC_CHNL), 0x0);

      done:
	_ipw_release_restricted_access(priv);
	return rc;
}

int darwin_iwi3945::ipw_poll_restricted_bit(struct ipw_priv *priv,
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

int darwin_iwi3945::ipw_load_ucode(struct ipw_priv *priv,
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
		IOLog("3945ABG card ucode DOWNLOAD FAILED \n");
		//goto done;
	}

	rc = 0;

	IOLog("3945ABG card ucode download is good \n");

	_ipw_write_restricted(priv, FH_TCSR_CREDIT(ALM_FH_SRVC_CHNL), 0x0);

      done:
	_ipw_release_restricted_access(priv);
	return rc;

}

void darwin_iwi3945::ipw_clear_stations_table(struct ipw_priv *priv)
{

	priv->num_stations = 0;
	memset(priv->stations, 0,
	       NUM_OF_STATIONS * sizeof(struct ipw_station_entry));
}

void darwin_iwi3945::ipw_nic_start(struct ipw_priv *priv)
{
	unsigned long flags;

	//spin_lock_irqsave(&priv->lock, flags);
	ipw_clear_bit( CSR_RESET,
		      CSR_RESET_REG_FLAG_MASTER_DISABLED |
		      CSR_RESET_REG_FLAG_STOP_MASTER |
		      CSR_RESET_REG_FLAG_NEVO_RESET);
	//spin_unlock_irqrestore(&priv->lock, flags);
}

int darwin_iwi3945::ipw_query_eeprom(struct ipw_priv *priv, u32 offset,
			    u32 len, u8 * buf)
{
/*	if (EEPROM_IMAGE_SIZE < (offset + len))
		return -1;

	memcpy(buf, &(priv->eeprom[offset]), len);

	return 0;*/
}

int darwin_iwi3945::ipw_card_show_info(struct ipw_priv *priv)
{
	IOLog("3945ABG HW Version %u.%u.%u\n",
		       ((priv->eeprom.board_revision >> 8) & 0x0F),
		       ((priv->eeprom.board_revision >> 8) >> 4),
		       (priv->eeprom.board_revision & 0x00FF));

	IOLog("3945ABG PBA Number %.*s\n",
		       (int)sizeof(priv->eeprom.board_pba_number),
		       priv->eeprom.board_pba_number);

	IOLog("EEPROM_ANTENNA_SWITCH_TYPE is 0x%02X\n",
		       priv->eeprom.antenna_switch_type);


}

#define PCI_LINK_CTRL      0x0F0

int darwin_iwi3945::ipw_power_init_handle(struct ipw_priv *priv)
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

void darwin_iwi3945::__ipw_set_bits_restricted_reg(u32 line, struct ipw_priv
						 *priv, u32 reg, u32 mask)
{
	if (!(priv->status & STATUS_RESTRICTED))
		IOLog("Unrestricted access from line %d\n", line);
	_ipw_set_bits_restricted_reg(priv, reg, mask);
}

int darwin_iwi3945::ipw_eeprom_init_sram(struct ipw_priv *priv)
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

int darwin_iwi3945::ipw_rate_scale_clear_window(struct ipw_rate_scale_data
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

int darwin_iwi3945::ipw_rate_scale_init_handle(struct ipw_priv *priv, s32 window_size)
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

int darwin_iwi3945::ipw_nic_set_pwr_src(struct ipw_priv *priv, int pwr_max)
{

}

void darwin_iwi3945::__ipw_set_bits_mask_restricted_reg(u32 line, struct ipw_priv
						      *priv, u32 reg,
						      u32 bits, u32 mask)
{
	if (!(priv->status & STATUS_RESTRICTED))
		IOLog("Unrestricted access from line %d\n", line);
	_ipw_set_bits_mask_restricted_reg(priv, reg, bits, mask);
}

int darwin_iwi3945::ipw3945_nic_set_pwr_src(struct ipw_priv *priv, int pwr_max)
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

int darwin_iwi3945::ipw_nic_stop_master(struct ipw_priv *priv)
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

int darwin_iwi3945::ipw_nic_reset(struct ipw_priv *priv)
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

void darwin_iwi3945::ipw_clear_bits_restricted_reg(struct ipw_priv
					  *priv, u32 reg, u32 mask)
{
	u32 val = _ipw_read_restricted_reg(priv, reg);
	_ipw_write_restricted_reg(priv, reg, (val & ~mask));
}

int darwin_iwi3945::ipw_nic_init(struct ipw_priv *priv)
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
		IOLog("3945ABG revision is 0x%X\n",
			       priv->eeprom.board_revision);
		ipw_set_bit( CSR_HW_IF_CONFIG_REG,
			    CSR_HW_IF_CONFIG_REG_BIT_BOARD_TYPE);
	} else {
		IOLog("3945ABG revision is 0x%X\n",
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
	
//return 0;// TODO check rxq

	/* Allocate the RX queue, or reset if it is already allocated */
	if (!priv->rxq)
		priv->rxq = ipw_rx_queue_alloc(priv);
	else
		ipw_rx_queue_reset(priv, priv->rxq);

	if (!priv->rxq) {
		IOLog("Unable to initialize Rx queue\n");
		//return -ENOMEM;
	}
	ipw_rx_queue_replenish(priv);

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

	rc = ipw_queue_reset(priv);
	//if (rc)
	//	return rc;

	priv->status |= STATUS_INIT;

	return 0;

}

int darwin_iwi3945::ipw_queue_inc_wrap(int index, int n_bd)
{
	return (++index == n_bd) ? 0 : index;
}

void darwin_iwi3945::ipw_queue_tx_free_tfd(struct ipw_priv *priv,
				  struct ipw_tx_queue *txq)
{
	struct tfd_frame *bd = &txq->bd[txq->q.last_used];
	//struct pci_dev *dev = priv->pci_dev;
	int i;
	int counter = 0;
	/* classify bd */
	if (txq->q.id == CMD_QUEUE_NUM)
		/* nothing to cleanup after for host commands */
		return;

	/* sanity check */
	counter = TFD_CTL_COUNT_GET(le32_to_cpu(bd->control_flags));
	if (counter > NUM_TFD_CHUNKS) {
		IOLog("Too many chunks: %i\n", counter);
		/** @todo issue fatal error, it is quite serious situation */
		return;
	}

	/* unmap chunks if any */

	for (i = 1; i < counter; i++) {
		//pci_unmap_single(dev, le32_to_cpu(bd->pa[i].addr),
		//		 le16_to_cpu(bd->pa[i].len), PCI_DMA_TODEVICE);
				 bd->pa[i].addr=NULL;
		if (txq->txb[txq->q.last_used]) {
			mbuf_t skb =
			    txq->txb[txq->q.last_used]->fragments[0];
			struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)mbuf_data(skb);
			priv->tx_bytes += mbuf_len(skb) -
			    ieee80211_get_hdrlen(hdr->frame_ctl);
			ieee80211_txb_free(txq->txb[txq->q.last_used]);
			txq->txb[txq->q.last_used] = NULL;
		}
	}
}

void darwin_iwi3945::ieee80211_txb_free(struct ieee80211_txb *txb)
{
	int i;
	if (unlikely(!txb))
		return;
	for (i = 0; i < txb->nr_frags; i++)
		if (txb->fragments[i]) 
		{
			mbuf_freem_list(txb->fragments[i]);
			freePacket(txb->fragments[i]);
			txb->fragments[i]=NULL;
			
		}
	kfree(txb);
	txb=NULL;
}

void darwin_iwi3945::ipw_queue_tx_free(struct ipw_priv *priv, struct ipw_tx_queue *txq)
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

	len = (sizeof(txq->cmd[0]) * q->n_window) + DAEMON_MAX_SCAN_SIZE;
	//pci_free_consistent(dev, len, txq->cmd, txq->dma_addr_cmd);
	txq->dma_addr_cmd=NULL;

	/* free buffers belonging to queue itself */
	//pci_free_consistent(dev, sizeof(txq->bd[0]) * q->n_bd,
	//		    txq->bd, q->dma_addr);

	q->dma_addr=NULL;
	kfree(txq->txb);

	/* 0 fill whole structure */
	memset(txq, 0, sizeof(*txq));
}

/**
 * Destroy all DMA queues and structures
 *
 * @param priv
 */
void darwin_iwi3945::ipw_tx_queue_free(struct ipw_priv *priv)
{

	/* Tx queues */
	ipw_queue_tx_free(priv, &priv->txq[0]);
	ipw_queue_tx_free(priv, &priv->txq[1]);
	ipw_queue_tx_free(priv, &priv->txq[2]);
	ipw_queue_tx_free(priv, &priv->txq[3]);
	ipw_queue_tx_free(priv, &priv->txq[4]);
	ipw_queue_tx_free(priv, &priv->txq[5]);
}

int darwin_iwi3945::ipw_tx_reset(struct ipw_priv *priv)
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

	_ipw_write_restricted(priv, FH_TSSR_CBB_BASE, priv->shared_phys);

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

int darwin_iwi3945::ipw_queue_tx_init(struct ipw_priv *priv,
			     struct ipw_tx_queue *q, int count, u32 id)
{
	//struct pci_dev *dev = priv->pci_dev;
	int len;

	(void*)q->txb = kmalloc(sizeof(q->txb[0]) * TFD_QUEUE_SIZE_MAX, GFP_ATOMIC);
	if (!q->txb) {
		IOLog("kmalloc for auxilary BD structures failed\n");
		return -ENOMEM;
	}

	MemoryDmaAlloc(sizeof(q->bd[0]) *
				 TFD_QUEUE_SIZE_MAX, &(q->q.dma_addr), &(q->bd));

	   // pci_alloc_consistent(dev,
		//		 sizeof(q->bd[0]) *
		//		 TFD_QUEUE_SIZE_MAX, &q->q.dma_addr);
	if (!q->bd) {
		IOLog("pci_alloc_consistent(%zd) failed\n",
			  sizeof(q->bd[0]) * count);
		kfree(q->txb);
		q->txb = NULL;
		return -ENOMEM;
	}

	/* alocate command space + one big command for scan since scan
	 * command is very huge the system will not have two scan at the
	 * same time */
	len = (sizeof(struct ipw_cmd) * count) + DAEMON_MAX_SCAN_SIZE;
	//q->cmd = pci_alloc_consistent(dev, len, &q->dma_addr_cmd);
	MemoryDmaAlloc(len, &(q->dma_addr_cmd), &(q->cmd));
	if (!q->cmd) {
		IOLog("pci_alloc_consistent(%zd) failed\n",
			  sizeof(q->cmd[0]) * count);
		kfree(q->txb);
		q->txb = NULL;
		q->q.dma_addr=NULL;
		//pci_free_consistent(dev,
		//		    sizeof(q->bd[0]) *
		//		    TFD_QUEUE_SIZE_MAX, q->bd, q->q.dma_addr);

		return -ENOMEM;
	}

	q->need_update = 0;
	ipw_queue_init(priv, &q->q, TFD_QUEUE_SIZE_MAX, count, id);
	return 0;
}

int darwin_iwi3945::ipw_queue_init(struct ipw_priv *priv, struct ipw_queue *q,
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
	priv->shared_virt->tx_base_ptr[id] = (u32) q->dma_addr;

	//spin_lock_irqsave(&priv->lock, flags);
	rc = ipw_grab_restricted_access(priv);
	/*if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}*/
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

	ipw_read32( FH_TSSR_CBB_BASE);	/* fake read to flush all prev. writes */

	//spin_unlock_irqrestore(&priv->lock, flags);
	return 0;
}

int darwin_iwi3945::ipw_queue_reset(struct ipw_priv *priv)
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

int darwin_iwi3945::ipw_rx_init(struct ipw_priv *priv, struct ipw_rx_queue *rxq)
{
	int rc;
	unsigned long flags;

	//spin_lock_irqsave(&priv->lock, flags);
	rc = ipw_grab_restricted_access(priv);
	/*if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}*/

	_ipw_write_restricted(priv, FH_RCSR_RBD_BASE(0), rxq->dma_addr);
	_ipw_write_restricted(priv, FH_RCSR_RPTR_ADDR(0),
			     priv->shared_phys +
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

int darwin_iwi3945::ipw_rx_queue_space(struct ipw_rx_queue *q)
{
	int s = q->read - q->write;
	if (s <= 0)
		s += RX_QUEUE_SIZE;
	s -= 2;			// keep some buffer to not confuse full and empty queue
	if (s < 0)
		s = 0;
	return s;
}

int darwin_iwi3945::ipw_rx_queue_update_write_ptr(struct ipw_priv *priv,
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

int darwin_iwi3945::ipw_rx_queue_restock(struct ipw_priv *priv)
{
	struct ipw_rx_queue *rxq = priv->rxq;
	struct list_head *element;
	struct ipw_rx_mem_buffer *rxb;
	unsigned long flags;
	int write;
	int counter = 0;
	int rc;

	//spin_lock_irqsave(&rxq->lock, flags);
	write = rxq->write & ~0x7;
	while ((ipw_rx_queue_space(rxq) > 0) && (rxq->free_count)) {
		element = rxq->rx_free.next;
		rxb = list_entry(element, struct ipw_rx_mem_buffer, list);
		list_del(element);

		((u32 *) rxq->bd)[rxq->write] = (u32) rxb->dma_addr;

		rxq->queue[rxq->write] = rxb;
		rxq->write = (rxq->write + 1) % RX_QUEUE_SIZE;
		rxq->free_count--;
		counter++;
	}
	//spin_unlock_irqrestore(&rxq->lock, flags);
	/* If the pre-allocated buffer pool is dropping low, schedule to
	 * refill it */
	if (rxq->free_count <= RX_LOW_WATERMARK) {
		queue_te(7,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_rx_queue_replenish),priv,NULL,true);
		//queue_work(priv->workqueue, &priv->rx_replenish);
	}

	counter = ipw_rx_queue_space(rxq);
	/* If we've added more space for the firmware to place data, tell it */
	if ((write != (rxq->write & ~0x7))
	    || (rxq->write - rxq->read > 7) || (-rxq->write + rxq->read > 7) ) {
		//spin_lock_irqsave(&rxq->lock, flags);
		rxq->need_update = 1;
		//spin_unlock_irqrestore(&rxq->lock, flags);
		rc = ipw_rx_queue_update_write_ptr(priv, rxq);
		if (rc) {
			return rc;
		}
	}

	return 0;
}

void darwin_iwi3945::ipw_rx_queue_replenish(struct ipw_priv *priv)
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

void darwin_iwi3945::ipw_rx_queue_reset(struct ipw_priv *priv,
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
			freePacket(rxq->pool[i].skb);
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

void darwin_iwi3945::freePacket(mbuf_t m, IOOptionBits options)
{
	if( m != NULL)
	if (mbuf_len(m) != 0 && mbuf_type(m) != MBUF_TYPE_FREE )
		super::freePacket(m,options);
}

struct ipw_rx_queue *darwin_iwi3945::ipw_rx_queue_alloc(struct ipw_priv *priv)
{
	struct ipw_rx_queue *rxq;
	//struct pci_dev *dev = priv->pci_dev;
	int i;
	rxq = (struct ipw_rx_queue *)kmalloc(sizeof(*rxq), GFP_ATOMIC);
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

int darwin_iwi3945::ipw_rf_eeprom_ready(struct ipw_priv *priv)
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

int darwin_iwi3945::ipw_verify_bootstrap(struct ipw_priv *priv)
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

int darwin_iwi3945::ipw_verify_ucode(struct ipw_priv *priv)
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

int darwin_iwi3945::ipw_setup_bootstrap(struct ipw_priv *priv)
{
	int rc = 0;

	/* Load bootstrap uCode data into card via card's TFD DMA channel */
	rc = ipw_load_ucode(priv, &(priv->ucode_boot_data),
			    ALM_RTC_DATA_SIZE, RTC_DATA_LOWER_BOUND);
//	if (rc)
//		goto error;

	/* Load bootstrap uCode instructions, same way */
	rc = ipw_load_ucode(priv, &(priv->ucode_boot),
			    ALM_RTC_INST_SIZE, RTC_INST_LOWER_BOUND);
//	if (rc)
//		goto error;

	/* verify bootstrap in-place in DATA and INSTRUCTION SRAM */
	ipw_verify_bootstrap(priv);

	/* tell bootstrap uCode where to find the runtime uCode in host DRAM */
	rc = ipw_grab_restricted_access(priv);
//	if (rc)
//		goto error;

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

int darwin_iwi3945::ipw_up(struct ipw_priv *priv)
{
			
	int rc, i;

	if (priv->status & STATUS_EXIT_PENDING) {
		IOLog("Exit pending will not bring the NIC up\n");
		return -EIO;
	}

	if (priv->status & STATUS_RF_KILL_SW) {
		IOLog("Radio disabled by module parameter.\n");
		return 0;
	} else if (priv->status & STATUS_RF_KILL_HW)
		return 0;

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

	for (i = 0; i < MAX_HW_RESTARTS; i++) {

		ipw_clear_stations_table(priv);

		rc = ipw_setup_bootstrap(priv);
		if (rc) {
			IOLog("Unable to set up bootstrap uCode: %d\n", rc);
		//	continue;
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
	ipw_down(priv);

	/* tried to restart and config the device for as long as our
	 * patience could withstand */
	IOLog("Unable to initialize device after %d attempts.\n", i);
	return -EIO;

}

IOReturn darwin_iwi3945::enable( IONetworkInterface * netif ) 
{
	IOLog("ifconfig up\n");
	switch ((ifnet_flags(fifnet) & IFF_UP) && (ifnet_flags(fifnet) & IFF_RUNNING))
	{
	case false:
		IOLog("ifconfig going up\n ");
		//super::enable(fNetif);
		//fNetif->setPoweredOnByUser(true);
		setLinkStatus(kIONetworkLinkActive, mediumTable[MEDIUM_TYPE_AUTO]);
		fNetif->setLinkState(kIO80211NetworkLinkUp);
		//(if_flags & ~mask) | (new_flags & mask) if mask has IFF_UP if_updown fires up (kpi_interface.c in xnu)
		ifnet_set_flags(fifnet, IFF_UP|IFF_RUNNING|IFF_BROADCAST|IFF_SIMPLEX|IFF_MULTICAST|IFF_NOTRAILERS 
		, IFF_UP | IFF_RUNNING );
		return kIOReturnSuccess;
		break;
	default:
		IOLog("ifconfig already up\n");
		return -1;
		break;
	}
}

inline int darwin_iwi3945::ipw_is_init(struct ipw_priv *priv)
{
	return (priv->status & STATUS_INIT) ? 1 : 0;
}

u32 darwin_iwi3945::ipw_register_toggle(u32 reg)
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

void darwin_iwi3945::ipw_led_activity_off(struct ipw_priv *priv)
{

}

void darwin_iwi3945::ipw_led_link_down(struct ipw_priv *priv)
{
	ipw_led_activity_off(priv);
	ipw_led_link_off(priv);

	if (priv->status & STATUS_RF_KILL_MASK)
		ipw_led_radio_off(priv);
}

void darwin_iwi3945::ipw_led_link_off(struct ipw_priv *priv)
{

}

void darwin_iwi3945::ipw_led_band_off(struct ipw_priv *priv)
{
	
}

void darwin_iwi3945::ipw_led_shutdown(struct ipw_priv *priv)
{
	ipw_led_activity_off(priv);
	ipw_led_link_off(priv);
	ipw_led_band_off(priv);
	queue_td(2,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_led_link_on));
	//cancel_delayed_work(&priv->led_link_off);
	//cancel_delayed_work(&priv->led_act_off);
}

void darwin_iwi3945::ipw_abort_scan(struct ipw_priv *priv)
{
	int err;

	if (priv->status & STATUS_SCAN_ABORTING) {
		IOLog("Ignoring concurrent scan abort request.\n");
		return;
	}
	priv->status |= STATUS_SCAN_ABORTING;
	queue_td(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan));
	queue_td(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan_check));
	err = sendCommand(IPW_CMD_SCAN_ABORT, NULL,0, 0);
	if (err)
		IOLog("Request to abort scan failed.\n");
}

void darwin_iwi3945::ipw_send_disassociate(struct ipw_priv *priv, int quiet)
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

int darwin_iwi3945::ipw_send_associate(struct ipw_priv *priv,
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

int darwin_iwi3945::ipw_disassociate(struct ipw_priv *data)
{
	struct ipw_priv *priv = data;
	if (!(priv->status & (STATUS_ASSOCIATED | STATUS_ASSOCIATING)))
		return 0;
	ipw_send_disassociate(data, 0);
	return 1;
}

void darwin_iwi3945::ipw_deinit(struct ipw_priv *priv)
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


inline void darwin_iwi3945::ipw_disable_interrupts(struct ipw_priv *priv)
{
	if (!(priv->status & STATUS_INT_ENABLED))
		return;
	priv->status &= ~STATUS_INT_ENABLED;
	ipw_write32(CSR_INT_MASK, 0x00000000);
	ipw_write32(CSR_INT, CSR_INI_SET_MASK);
	ipw_write32( CSR_FH_INT_STATUS, 0xff);
	ipw_write32( CSR_FH_INT_STATUS, 0x00070000);

}

void darwin_iwi3945::ipw_down(struct ipw_priv *priv)
{
	int exit_pending = priv->status & STATUS_EXIT_PENDING;

	priv->status |= STATUS_EXIT_PENDING;

	if (ipw_is_init(priv))
		ipw_deinit(priv);

	/* Wipe out the EXIT_PENDING status bit if we are not actually
	 * exiting the module */
	if (!exit_pending)
		priv->status &= ~STATUS_EXIT_PENDING;

	/* tell the device to stop sending interrupts */
	ipw_disable_interrupts(priv);

	/* Clear all bits but the RF Kill */
	priv->status &= STATUS_RF_KILL_MASK | STATUS_EXIT_PENDING;
	//fNetif->setLinkState(kIO80211NetworkLinkDown);
	//netif_stop_queue(priv->net_dev);

	ipw_stop_nic();

	ipw_led_radio_off(priv);
}


void darwin_iwi3945::ipw_led_radio_off(struct ipw_priv *priv)
{
	ipw_led_activity_off(priv);
	ipw_led_link_off(priv);
}

void darwin_iwi3945::interruptOccurred(OSObject * owner, 
	//IOInterruptEventSource * src, int /*count*/) 
	void		*src,  IOService *nub, int source)
{
	darwin_iwi3945 *self = OSDynamicCast(darwin_iwi3945, owner); //(darwin_iwi3945 *)owner;
	self->handleInterrupt();
}

void darwin_iwi3945::ipw_irq_handle_error(struct ipw_priv *priv)
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
			  ipw_down(priv);
		//queue_work(priv->workqueue, &priv->down);
	}
}

int darwin_iwi3945::ipw3945_rx_queue_update_wr_ptr(struct ipw_priv *priv,
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

int darwin_iwi3945::ipw_tx_queue_update_write_ptr(struct ipw_priv *priv,
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

UInt32 darwin_iwi3945::handleInterrupt(void)
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
		IOLog("IRQ INTA == 0xFFFFFFFF\n");
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


UInt16 darwin_iwi3945::readPromWord(UInt16 *base, UInt8 addr)
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


IOReturn darwin_iwi3945::getHardwareAddress( IOEthernetAddress * addr )
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
		memcpy(priv->ieee->dev->dev_addr, &fEnetAddr.bytes, ETH_ALEN);
		//IOLog("getHardwareAddress " MAC_FMT "\n",MAC_ARG(priv->mac_addr));
	}
	
	return kIOReturnSuccess;
}


void darwin_iwi3945::stopMaster(UInt16 *base) {
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

void darwin_iwi3945::stopDevice(UInt16 *base)
{
	stopMaster(base);
	
	CSR_WRITE_4(base, IWI_CSR_RST, IWI_RST_SOFT_RESET);
}

bool darwin_iwi3945::resetDevice(UInt16 *base) 
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


void darwin_iwi3945::ipw_write_reg8(UInt32 reg, UInt8 value)
{
	UInt32 aligned_addr = reg & IPW_INDIRECT_ADDR_MASK;	/* dword align */
	UInt32 dif_len = reg - aligned_addr;

	_ipw_write32(memBase, IPW_INDIRECT_ADDR, aligned_addr);
	_ipw_write8(memBase, IPW_INDIRECT_DATA + dif_len, value);
}

UInt8 darwin_iwi3945::ipw_read_reg8(UInt32 reg)
{
	UInt32 word;
	_ipw_write32(memBase, IPW_INDIRECT_ADDR, reg & IPW_INDIRECT_ADDR_MASK);
	word = _ipw_read32(memBase, IPW_INDIRECT_DATA);
	return (word >> ((reg & 0x3) * 8)) & 0xff;
}

void darwin_iwi3945::ipw_write_reg16(UInt32 reg, UInt16 value)
{
	UInt32 aligned_addr = reg & IPW_INDIRECT_ADDR_MASK;	/* dword align */
	UInt32 dif_len = (reg - aligned_addr) & (~0x1ul);

	_ipw_write32(memBase, IPW_INDIRECT_ADDR, aligned_addr);
	_ipw_write16(memBase, IPW_INDIRECT_DATA + dif_len, value);
	
}

int darwin_iwi3945::ipw_stop_master()
{
}

void darwin_iwi3945::ipw_arc_release()
{
	mdelay(5);

	ipw_clear_bit( IPW_RESET_REG, CBD_RESET_REG_PRINCETON_RESET);

	/* no one knows timing, for safety add some delay */
	mdelay(5);
}

bool darwin_iwi3945::uploadUCode(const unsigned char * data, UInt16 len)
{
	
}



void inline darwin_iwi3945::ipw_write32(UInt32 offset, UInt32 data)
{
	//OSWriteLittleInt32((void*)memBase, offset, data);
	_ipw_write32(memBase, offset, data);
}

UInt32 inline darwin_iwi3945::ipw_read32(UInt32 offset)
{
	//return OSReadLittleInt32((void*)memBase, offset);
	return _ipw_read32(memBase,offset);
}

void inline darwin_iwi3945::ipw_clear_bit(UInt32 reg, UInt32 mask)
{
	ipw_write32(reg, ipw_read32(reg) & ~mask);
}

void inline darwin_iwi3945::ipw_set_bit(UInt32 reg, UInt32 mask)
{
	ipw_write32(reg, ipw_read32(reg) | mask);
}

int darwin_iwi3945::ipw_fw_dma_add_command_block(
					UInt32 src_address,
					UInt32 dest_address,
					UInt32 length,
					int interrupt_enabled, int is_last)
{

	return 0;
}

void darwin_iwi3945::ipw_zero_memory(UInt32 start, UInt32 count)
{
	count >>= 2;
	if (!count)
		return;
	_ipw_write32(memBase,IPW_AUTOINC_ADDR, start);
	while (count--)
		_ipw_write32(memBase,IPW_AUTOINC_DATA, 0);
}

void darwin_iwi3945::ipw_fw_dma_reset_command_blocks()
{

}

void darwin_iwi3945::ipw_write_reg32( UInt32 reg, UInt32 value)
{
	_ipw_write32(memBase,IPW_INDIRECT_ADDR, reg);
	_ipw_write32(memBase,IPW_INDIRECT_DATA, value);
}

int darwin_iwi3945::ipw_fw_dma_enable()
{				/* start dma engine but no transfers yet */

	ipw_fw_dma_reset_command_blocks();
	ipw_write_reg32(IPW_DMA_I_CB_BASE, IPW_SHARED_SRAM_DMA_CONTROL);
	return 0;
}

void darwin_iwi3945::ipw_write_indirect(UInt32 addr, UInt8 * buf,
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


int darwin_iwi3945::ipw_fw_dma_add_buffer(UInt32 src_phys, UInt32 dest_address, UInt32 length)
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

int darwin_iwi3945::ipw_fw_dma_write_command_block(int index,
					  struct command_block *cb)
{
		return 0;

}

int darwin_iwi3945::ipw_fw_dma_kick()
{
	
	return 0;
}

UInt32 darwin_iwi3945::ipw_read_reg32( UInt32 reg)
{
	UInt32 value;


	_ipw_write32(memBase, IPW_INDIRECT_ADDR, reg);
	value = _ipw_read32(memBase, IPW_INDIRECT_DATA);
	return value;
}

int darwin_iwi3945::ipw_fw_dma_command_block_index()
{

}

void darwin_iwi3945::ipw_fw_dma_dump_command_block()
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

void darwin_iwi3945::ipw_fw_dma_abort()
{

}

int darwin_iwi3945::ipw_fw_dma_wait()
{
	
}


bool darwin_iwi3945::uploadFirmware(u8 * data, size_t len)
{	
	
}

bool darwin_iwi3945::uploadUCode2(UInt16 *base, const unsigned char *uc, UInt16 size, int offset)
{
	
}


bool darwin_iwi3945::uploadFirmware2(UInt16 *base, const unsigned char *fw, UInt32 size, int offset)
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


int darwin_iwi3945::ipw_get_fw(const struct firmware **fw, const char *name)
{
		
}

IOBufferMemoryDescriptor*
darwin_iwi3945::MemoryDmaAlloc(UInt32 buf_size, dma_addr_t *phys_add, void *virt_add)
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


int darwin_iwi3945::sendCommand(UInt8 type,void *data,UInt8 len,bool async)
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

const struct ieee80211_geo* darwin_iwi3945::ipw_get_geo(struct ieee80211_device *ieee)
{
	return &ieee->geo;
}

int darwin_iwi3945::ipw_set_tx_power(struct ipw_priv *priv)
{

}

void darwin_iwi3945::init_sys_config(struct ipw_sys_config *sys_config)
{
	
}

void darwin_iwi3945::ipw_add_cck_scan_rates(struct ipw_supported_rates *rates,
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

void darwin_iwi3945::ipw_add_ofdm_scan_rates(struct ipw_supported_rates *rates,
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

int darwin_iwi3945::init_supported_rates(struct ipw_priv *priv,
				struct ipw_supported_rates *rates)
{
	/* TODO: Mask out rates based on priv->rates_mask */

	memset(rates, 0, sizeof(*rates));
	/* configure supported rates */
	switch (priv->ieee->freq_band) {
	case IEEE80211_52GHZ_BAND:
		rates->ieee_mode = IPW_A_MODE;
		rates->purpose = IPW_RATE_CAPABILITIES;
		ipw_add_ofdm_scan_rates(rates, IEEE80211_CCK_MODULATION,
					IEEE80211_OFDM_DEFAULT_RATES_MASK);
		break;

	default:		/* Mixed or 2.4Ghz */
		rates->ieee_mode = IPW_G_MODE;
		rates->purpose = IPW_RATE_CAPABILITIES;
		ipw_add_cck_scan_rates(rates, IEEE80211_CCK_MODULATION,
				       IEEE80211_CCK_DEFAULT_RATES_MASK);
		if (priv->ieee->modulation & IEEE80211_OFDM_MODULATION) {
			ipw_add_ofdm_scan_rates(rates, IEEE80211_CCK_MODULATION,
						IEEE80211_OFDM_DEFAULT_RATES_MASK);
		}
		break;
	}

	return 0;
}

void darwin_iwi3945::ipw_send_tgi_tx_key(struct ipw_priv *priv, int type, int index)
{
	struct ipw_tgi_tx_key key;

	if (!(priv->ieee->sec.flags & (1 << index)))
		return;

	key.key_id = index;
	memcpy(key.key, priv->ieee->sec.keys[index], SCM_TEMPORAL_KEY_LENGTH);
	key.security_type = type;
	key.station_index = 0;	/* always 0 for BSS */
	key.flags = 0;
	/* 0 for new key; previous value of counter (after fatal error) */
	key.tx_counter[0] = cpu_to_le32(0);
	key.tx_counter[1] = cpu_to_le32(0);

	sendCommand(IPW_CMD_TGI_TX_KEY, &key,sizeof(key), 1);
}

void darwin_iwi3945::ipw_send_wep_keys(struct ipw_priv *priv, int type)
{
	
}

void darwin_iwi3945::ipw_set_hw_decrypt_unicast(struct ipw_priv *priv, int level)
{
	
}

void darwin_iwi3945::ipw_set_hw_decrypt_multicast(struct ipw_priv *priv, int level)
{
	
}

void darwin_iwi3945::ipw_set_hwcrypto_keys(struct ipw_priv *priv)
{
	
}

bool darwin_iwi3945::configureInterface(IONetworkInterface * netif)
 {
    IONetworkData * data;
    IOLog("configureInterface\n");
    if (super::configureInterface(netif) == false)
            return false;
    return true;
}

int darwin_iwi3945::configu(struct ipw_priv *priv)
{
	
}

u8 darwin_iwi3945::ipw_qos_current_mode(struct ipw_priv *priv)
{
	u8 mode = 0;

	if (priv->status & STATUS_ASSOCIATED) {
		unsigned long flags;

		//spin_lock_irqsave(&priv->ieee->lock, flags);
		mode = priv->assoc_network->mode;
		//spin_unlock_irqrestore(&priv->ieee->lock, flags);
	} else {
		mode = priv->ieee->mode;
	}
	IOLog("QoS network/card mode %d \n", mode);
	return mode;
}

u32 darwin_iwi3945::ipw_qos_get_burst_duration(struct ipw_priv *priv)
{
	
}

int darwin_iwi3945::ipw_qos_activate(struct ipw_priv *priv,
			    struct ieee80211_qos_data *qos_network_data)
{
	
}

void darwin_iwi3945::ipw_led_link_on(struct ipw_priv *priv)
{
	
}

void darwin_iwi3945::ipw_led_init(struct ipw_priv *priv)
{
	
}


void darwin_iwi3945::ipw_led_band_on(struct ipw_priv *priv)
{
	
}

int darwin_iwi3945::ipw_channel_to_index(struct ieee80211_device *ieee, u8 channel)
{
	int i;

	/* Driver needs to initialize the geography map before using
	 * these helper functions */
	if(ieee->geo.bg_channels == 0 && ieee->geo.a_channels == 0) return -1;

	if (ieee->freq_band & IEEE80211_24GHZ_BAND)
		for (i = 0; i < ieee->geo.bg_channels; i++)
			if (ieee->geo.bg[i].channel == channel)
				return i;

	if (ieee->freq_band & IEEE80211_52GHZ_BAND)
		for (i = 0; i < ieee->geo.a_channels; i++)
			if (ieee->geo.a[i].channel == channel)
				return i;

	return -1;
}

void darwin_iwi3945::ipw_add_scan_channels(struct ipw_priv *priv,
				  struct ipw_scan_request_ext *scan,
				  int scan_type)
{
	
}

int darwin_iwi3945::ipw_scan(struct ipw_priv *priv, int type)
{
		
/*	
	struct ipw_scan_request_ext scan;
	int err = 0, scan_type;
	IOLog("scanning...\n");
	if (!(priv->status & STATUS_INIT) ||
	    (priv->status & STATUS_EXIT_PENDING))
		return 0;


	if (priv->status & STATUS_SCANNING) {
		IOLog("Concurrent scan requested.  Ignoring.\n");
		priv->status |= STATUS_SCAN_PENDING;
		goto done;
	}

	if (!(priv->status & STATUS_SCAN_FORCED) &&
	    priv->status & STATUS_SCAN_ABORTING) {
		IOLog("Scan request while abort pending.  Queuing.\n");
		priv->status |= STATUS_SCAN_PENDING;
		goto done;
	}

	if (priv->status & STATUS_RF_KILL_MASK) {
		IOLog("Aborting scan due to RF Kill activation\n");
		priv->status |= STATUS_SCAN_PENDING;
		goto done;
	}

	memset(&scan, 0, sizeof(scan));
	scan.full_scan_index = cpu_to_le32(ieee80211_get_scans(priv->ieee));

	if (type == IW_SCAN_TYPE_PASSIVE) {
		IOLog("use passive scanning\n");
		scan_type = IPW_SCAN_PASSIVE_FULL_DWELL_SCAN;
		scan.dwell_time[IPW_SCAN_PASSIVE_FULL_DWELL_SCAN] =
		    cpu_to_le16(120);
		ipw_add_scan_channels(priv, &scan, scan_type);
		goto send_request;
	}

	if (priv->config & CFG_SPEED_SCAN)
		scan.dwell_time[IPW_SCAN_ACTIVE_BROADCAST_SCAN] =
		    cpu_to_le16(30);
	else
		scan.dwell_time[IPW_SCAN_ACTIVE_BROADCAST_SCAN] =
		    cpu_to_le16(20);

	scan.dwell_time[IPW_SCAN_ACTIVE_BROADCAST_AND_DIRECT_SCAN] =
	    cpu_to_le16(20);

	scan.dwell_time[IPW_SCAN_PASSIVE_FULL_DWELL_SCAN] = cpu_to_le16(120);

	if (priv->ieee->iw_mode == IW_MODE_MONITOR) {
		u8 channel;
		u8 band = 0;

		switch (ipw_is_valid_channel(priv->ieee, priv->channel)) {
		case IEEE80211_52GHZ_BAND:
			band = (u8) (IPW_A_MODE << 6) | 1;
			channel = priv->channel;
			break;

		case IEEE80211_24GHZ_BAND:
			band = (u8) (IPW_B_MODE << 6) | 1;
			channel = priv->channel;
			break;

		default:
			band = (u8) (IPW_B_MODE << 6) | 1;
			channel = 9;
			break;
		}

		scan.channels_list[0] = band;
		scan.channels_list[1] = channel;
		ipw_set_scan_type(&scan, 1, IPW_SCAN_PASSIVE_FULL_DWELL_SCAN);


		scan.dwell_time[IPW_SCAN_PASSIVE_FULL_DWELL_SCAN] =
		    cpu_to_le16(2000);
	} else {

		if ((priv->status & STATUS_ROAMING)
		    || (!(priv->status & STATUS_ASSOCIATED)
			&& (priv->config & CFG_STATIC_ESSID)
			&& (le32_to_cpu(scan.full_scan_index) % 2))) {
			err=sendCommand(IPW_CMD_SSID, &priv->essid,min( priv->essid_len, IW_ESSID_MAX_SIZE), 1);
			if (err) {
				IOLog("Attempt to send SSID command "
					     "failed.\n");
				goto done;
			}

			scan_type = IPW_SCAN_ACTIVE_BROADCAST_AND_DIRECT_SCAN;
		} else
			scan_type = IPW_SCAN_ACTIVE_BROADCAST_SCAN;

		ipw_add_scan_channels(priv, &scan, scan_type);
	}

      send_request:
	  struct ipw_scan_request_ext *rq=&scan;
	err = sendCommand(IPW_CMD_SCAN_REQUEST_EXT, &rq,sizeof(rq), 1);

	if (err) {
		IOLog("Sending scan command failed: %08X\n", err);
		goto done;
	}

	priv->status |= STATUS_SCANNING;
	priv->status &= ~STATUS_SCAN_PENDING;
	queue_te(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan_check),priv,5,true);

 
	  done:
	return err;
*/
}

void darwin_iwi3945::ipw_scan_check(ipw_priv *priv)
{
	if (priv->status & (STATUS_SCANNING | STATUS_SCAN_ABORTING)) {
		IOLog("Scan completion resetting\n");
		queue_te(1,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_adapter_restart),priv,NULL,true);
	}
}

int darwin_iwi3945::initCmdQueue()
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

int darwin_iwi3945::resetCmdQueue()
{
	cmdq.queued=0;
	cmdq.cur=0;
	cmdq.next=0;
	
	return 0;
}


int darwin_iwi3945::initRxQueue()
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


int darwin_iwi3945::resetRxQueue()
{
	rxq.cur=0;
	return 0;
}

void darwin_iwi3945::ipw_bg_alive_start()
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
		//ipw_down(priv);
		//mutex_unlock(&priv->mutex);
		//return;
	}

	/* bootstrap uCode has loaded runtime uCode ... verify inst image */
	if (ipw_verify_ucode(priv)) {
		/* Runtime instruction load was bad;
		 * take it all the way back down so we can try again */
		IOLog("Bad runtime uCode load.\n");
		//ipw_down(priv);
		//mutex_unlock(&priv->mutex);
		//return;
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

//	rc = ipw_init_channel_map(priv);
	if (rc) {
		IOLog("initializing regulatory failed: %d\n", rc);
		//mutex_unlock(&priv->mutex);
		return;
	}

//	ipw_init_geos(priv);

	if (!priv->netdev_registered) {
	//	mutex_unlock(&priv->mutex);
	//	ieee80211_rate_control_register(&priv->rate_control);

		//rc = ieee80211_register_hw(priv->ieee);
		if (rc) {
			IOLog("Failed to register network "
				  "device (error %d)\n", rc);
			return;
		}

	//	module_put(THIS_MODULE);

	//	mutex_lock(&priv->mutex);
		priv->netdev_registered = 1;

		//ipw_reset_channel_flag(priv);
	}

	memcpy(priv->net_dev->dev_addr, priv->mac_addr, ETH_ALEN);

	priv->rates_mask = IEEE80211_DEFAULT_RATES_MASK;
	//ipw_set_supported_rates_mask(priv, priv->rates_mask);

	//ipw_set_rate(priv);

	//ipw_send_power_mode(priv, IPW_POWER_LEVEL(priv->power_mode));

/*
 * ipw_qos_activate(priv, NULL);
 */
	//ipw_send_power_mode(priv, IPW_POWER_LEVEL(priv->power_mode));

	/* Initialize our rx_config data */
//	ipw_connection_init_rx_config(priv);
	//memcpy(priv->staging_rxon.node_addr, priv->net_dev->dev_addr, ETH_ALEN);

	/* Configure BT coexistence */
//	ipw_send_bt_config(priv);

	/* Configure the adapter for unassociated operation */
	//ipw_commit_rxon(priv);

	/* Add the broadcast address so we can send probe requests */
	//ipw_rxon_add_station(priv, BROADCAST_ADDR, 0);
	//ipw_init_rate_scaling(priv);

	/* At this point, the NIC is initialized and operational */
	priv->notif_missed_beacons = 0;
	priv->status |= STATUS_READY;

//	ipw_update_link_led(priv);

//	reg_txpower_periodic(priv);

	//mutex_unlock(&priv->mutex);
}

void darwin_iwi3945::RxQueueIntr()
{
	struct ipw_rx_mem_buffer *rxb;
	struct ipw_rx_packet *pkt;
	u32 r, i;
	int pkt_from_hardware;
	//TODO: check r is ok
	r = ((struct ipw_shared_t *)memBase)->rx_read_ptr[0];//priv->shared_virt->rx_read_ptr[0];
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
			break;
		default:
			IOLog
			    ("Received %s command (#%x), seq:0x%04X, "
			     "flags=0x%02X, len = %d\n","",
	//		     get_cmd_string(pkt->hdr.cmd),
			     pkt->hdr.cmd, pkt->hdr.sequence,
			     pkt->hdr.flags, le16_to_cpu(pkt->len));
		}

		switch (pkt->hdr.cmd) {
		case REPLY_RX:	/* 802.11 frame */
			IOLog("todo: ipw_handle_reply_rx\n");
			//ipw_handle_reply_rx(priv, rxb);
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
					ipw_bg_alive_start();
					/*queue_delayed_work(priv->workqueue,
							   &priv->alive_start,
							   msecs_to_jiffies(5));*/
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
					//  get_cmd_string(cmd_id),
					  cmd_id, seq, ser);
				break;
			}
		case REPLY_TX:
		IOLog("todo: ipw_handle_reply_tx\n");
			//ipw_handle_reply_tx(priv, &pkt->u.tx_resp,
			//		    pkt->hdr.sequence);
			break;

		case CHANNEL_SWITCH_NOTIFICATION:{
				struct ipw_csa_notification *csa =
				    &(pkt->u.csa_notif);
				IOLog
				    ("CSA notif: channel %d, status %d\n",
				     csa->channel, csa->status);
				priv->channel = csa->channel;
				/*priv->assoc_network =
				    ieee80211_move_network_channel
				    (priv->ieee, priv->assoc_network,
				     csa->channel);*/
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
#ifdef CONFIG_IPW3945_DEBUG
				struct ipw_sleep_notification *sleep =
				    &(pkt->u.sleep_notif);
				IPW_DEBUG_RX
				    ("sleep mode: %d, src: %d\n",
				     sleep->pm_sleep_mode,
				     sleep->pm_wakeup_src);
#endif
				break;
			}

		case PM_DEBUG_STATISTIC_NOTIFIC:
			IOLog
			    ("Dumping %d bytes of unhandled "
			     "notification for %s:\n",
			     le16_to_cpu(pkt->len),"");
			    // get_cmd_string(pkt->hdr.cmd));
			//printk_buf(IPW_DL_RADIO, pkt->u.raw,
			//	   le16_to_cpu(pkt->len));
			break;

		case BEACON_NOTIFICATION:{
#ifdef CONFIG_IPW3945_DEBUG
				struct BeaconNtfSpecifics *beacon =
				    &(pkt->u.beacon_status);
				IPW_DEBUG_INFO
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
				IPW_DEBUG_RX
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

				IPW_DEBUG_SCAN("Scan ch.res: "
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
					       jiffies_to_msecs
					       (elapsed_jiffies
						(priv->
						 last_scan_jiffies, jiffies)));
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

				//ipw_scan_completed(priv,
				//		   scan_notif->status == 1);
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
					queue_te(3,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_rf_kill),priv,0,true);
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
				//ipw_tx_complete(priv, rxb);
				IOLog("todo: ipw_tx_complete \n");
			}
			else
				IOLog("Claim null rxb?\n");
		}

		/* For now we just don't re-use anything.  We can tweak this
		 * later to try and re-use notification packets and SKBs that
		 * fail to Rx correctly */
		if (rxb->skb != NULL) {
			//dev_kfree_skb_any(rxb->skb);
			freePacket(rxb->skb);
			rxb->skb = NULL;
		}
		rxb->dma_addr=NULL;
		//pci_unmap_single(priv->pci_dev, rxb->dma_addr,
		//		 IPW_RX_BUF_SIZE, PCI_DMA_FROMDEVICE);
		list_add_tail(&rxb->list, &priv->rxq->rx_used);
		i = (i + 1) % RX_QUEUE_SIZE;
	}

	/* Backtrack one entry */
	priv->rxq->read = i;
	ipw_rx_queue_restock(priv);

}


int darwin_iwi3945::initTxQueue()
{
	txq.count = IWI_TX_RING_COUNT;
	txq.queued = 0;
	txq.cur = 0;

	txq.memD = MemoryDmaAlloc(txq.count * IWI_TX_DESC_SIZE, &txq.physaddr, &txq.desc);
	txq.data = IONew(iwi_tx_data, txq.count);

	return true;
}

int darwin_iwi3945::resetTxQueue()
{
	rxq.cur=0;
	return 0;
}


void darwin_iwi3945::free(void)
{
	IOLog("todo: Freeing\n");
	return;
	
	if (pl==0)
	{
		stop(NULL);
		super::free();
	}
}

void darwin_iwi3945::stop(IOService *provider)
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

IOReturn darwin_iwi3945::disable( IONetworkInterface * netif )
{
	IOLog("ifconfig down\n");
	switch ((ifnet_flags(fifnet) & IFF_UP) && (ifnet_flags(fifnet) & IFF_RUNNING))
	{
	case true:
		IOLog("ifconfig going down\n");
		//super::disable(fNetif);
		//fNetif->setPoweredOnByUser(false);
		setLinkStatus(kIONetworkLinkValid, mediumTable[MEDIUM_TYPE_AUTO]);
		fNetif->setLinkState(kIO80211NetworkLinkDown);
		
		//(if_flags & ~mask) | (new_flags & mask) if mask has IFF_UP if_updown fires up (kpi_interface.c in xnu)
		ifnet_set_flags(fifnet, 0 , IFF_UP | IFF_RUNNING );
		
		if ((priv->status & STATUS_ASSOCIATED)) enable(fNetif);
		
		return kIOReturnSuccess;
		
		break;
	default:
		IOLog("ifconfig already down\n");
		return -1;
		break;
	}
}

/*const char * darwin_iwi3945::getNamePrefix() const
{
	return "wlan";
}*/

void inline
darwin_iwi3945::eeprom_write_reg(UInt32 data)
{
	OSWriteLittleInt32((void*)memBase, IPW_INDIRECT_ADDR, FW_MEM_REG_EEPROM_ACCESS);
	OSWriteLittleInt32((void*)memBase, IPW_INDIRECT_DATA, data);
	
	// Sleep for 1 uS to hold the data there
	IODelay(1);
}

/* EEPROM Chip Select */
void inline
darwin_iwi3945::eeprom_cs(bool sel)
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
darwin_iwi3945::eeprom_write_bit(UInt8 bit)
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
darwin_iwi3945::eeprom_op(UInt8 op, UInt8 addr)
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
darwin_iwi3945::eeprom_read_UInt16(UInt8 addr)
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
darwin_iwi3945::cacheEEPROM(struct ipw_priv *priv)
{
}


UInt32
darwin_iwi3945::read_reg_UInt32(UInt32 reg)
{
	UInt32 value;
	
	OSWriteLittleInt32((void*)memBase, IPW_INDIRECT_ADDR, reg);
	value = OSReadLittleInt32((void*)memBase, IPW_INDIRECT_DATA);
	return value;
}

int
darwin_iwi3945::ipw_poll_bit(struct ipw_priv *priv, u32 addr,
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
SInt32
darwin_iwi3945::getSSID(IO80211Interface *interface,
						struct apple80211_ssid_data *sd)
{
	IOLog("getSSID %s l:%d\n",escape_essid((const char*)sd->ssid_bytes, sd->ssid_len));
	return 0;
}

SInt32
darwin_iwi3945::getCHANNEL(IO80211Interface *interface,
						  struct apple80211_channel_data *cd)
{
	IOLog("getCHANNEL c:%d f:%d\n",cd->channel.channel,cd->channel.flags);
	return 0;
}

SInt32
darwin_iwi3945::getBSSID(IO80211Interface *interface,
						struct apple80211_bssid_data *bd)
{
	IOLog("getBSSID %s\n",escape_essid((const char*)bd->bssid.octet,sizeof(bd->bssid.octet)));
	return 0;
}

SInt32
darwin_iwi3945::getCARD_CAPABILITIES(IO80211Interface *interface,
									  struct apple80211_capability_data *cd)
{
	IOLog("getCARD_CAPABILITIES %d\n",sizeof(cd->capabilities));
	publishProperties();
	return 0;
}

SInt32
darwin_iwi3945::getSTATE(IO80211Interface *interface,
						  struct apple80211_state_data *sd)
{
	IOLog("getSTATE %d\n",sd->state);
	return 0;
}

SInt32
darwin_iwi3945::getRSSI(IO80211Interface *interface,
					   struct apple80211_rssi_data *rd)
{
	IOLog("getRSSI \n");
	return 0;
}

SInt32
darwin_iwi3945::getPOWER(IO80211Interface *interface,
						struct apple80211_power_data *pd)
{
	//IOPMprot *p=pm_vars;
	//memset(&(pd->power_state),0,sizeof(pd->power_state));

	/*pd->num_radios=p->myCurrentState;//theNumberOfPowerStates;
	for (int c=0;c < p->theNumberOfPowerStates;c++)
	{
		IOPMPowerState *pstate=&p->thePowerStates[c];
		IOPMPowerFlags f=pstate->capabilityFlags;
		if (c < APPLE80211_MAX_RADIO) 
		{
			pd->power_state[c]=f;
		}
	
	IOPMPowerFlags pf=p->myCurrentState;
	IOLog("powerf 0x%4x\n",pf);
	//memcpy(&pd->power_state,(void*)pf,sizeof(IOPMPowerFlags));
	IOLog("powerf 0x%4x\n",pd->power_state);
	interface->setPowerState(pf,this);*/
	IOLog("getPOWER %d, %d %d %d %d\n",pd->num_radios, pd->power_state[0],pd->power_state[1],pd->power_state[2],pd->power_state[3]);
	return 0;
}

SInt32
darwin_iwi3945::getSCAN_RESULT(IO80211Interface *interface,
							  struct apple80211_scan_result **scan_result)
{
	IOLog("getSCAN_RESULT \n");
	return 0;
}

/*SInt32
darwin_iwi3945::getASSOCIATE_RESULT(IO80211Interface *interface,
								   struct apple80211_assoc_result_data *ard)
{
	IOLog("getASSOCIATE_RESULT \n");
	return 0;
}*/

SInt32
darwin_iwi3945::getRATE(IO80211Interface *interface,
					   struct apple80211_rate_data *rd)
{
	IOLog("getRATE %d\n",rd->rate);
	return 0;
}

SInt32
darwin_iwi3945::getSTATUS_DEV(IO80211Interface *interface,
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
	memcpy(&priv->ieee->dev->name,i,sizeof(i));

	super::enable(fNetif);
	interface->setPoweredOnByUser(true);
	ipw_up(priv);
	return 0;
}

SInt32
darwin_iwi3945::getRATE_SET(IO80211Interface	*interface,
						   struct apple80211_rate_set_data *rd)
{
	IOLog("getRATE_SET %d r0:%d f0:%d\n",rd->num_rates, rd->rates[0].rate,rd->rates[0].flags);
	return 0;
}

SInt32	darwin_iwi3945::getASSOCIATION_STATUS( IO80211Interface * interface, struct apple80211_assoc_status_data * asd )
{
	IOLog("getASSOCIATION_STATUS %d\n",asd->status);
	return 0;
}

SInt32
darwin_iwi3945::setSCAN_REQ(IO80211Interface *interface,
						   struct apple80211_scan_data *sd)
{
	IOLog("setSCAN_REQ \n");
	return 0;
}

SInt32
darwin_iwi3945::setASSOCIATE(IO80211Interface *interface,
							struct apple80211_assoc_data *ad)
{
	IOLog("setASSOCIATE \n");
	return 0;
}

SInt32
darwin_iwi3945::setPOWER(IO80211Interface *interface,
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
darwin_iwi3945::setCIPHER_KEY(IO80211Interface *interface,
							 struct apple80211_key *key)
{
	IOLog("setCIPHER_KEY \n");
	return 0;
}

SInt32
darwin_iwi3945::setAUTH_TYPE(IO80211Interface *interface,
							struct apple80211_authtype_data *ad)
{
	IOLog("setAUTH_TYPE \n");
	return 0;
}

SInt32
darwin_iwi3945::setDISASSOCIATE(IO80211Interface	*interface)
{
	IOLog("setDISASSOCIATE \n");
	return 0;
}

SInt32
darwin_iwi3945::setSSID(IO80211Interface *interface,
					   struct apple80211_ssid_data *sd)
{
	IOLog("setSSID \n");
	return 0;
}

SInt32
darwin_iwi3945::setAP_MODE(IO80211Interface *interface,
						  struct apple80211_apmode_data *ad)
{
	IOLog("setAP_MODE \n");
	return 0;
}

bool darwin_iwi3945::attachInterfaceWithMacAddress( void * macAddr, 
												UInt32 macLen, 
												IONetworkInterface ** interface, 
												bool doRegister ,
												UInt32 timeout  )
{
	IOLog("attachInterfaceWithMacAddress \n");
	return super::attachInterfaceWithMacAddress(macAddr,macLen,interface,doRegister,timeout);
}												
												
void darwin_iwi3945::dataLinkLayerAttachComplete( IO80211Interface * interface )											
{
	IOLog("dataLinkLayerAttachComplete \n");
	super::dataLinkLayerAttachComplete(interface);
}


void darwin_iwi3945::queue_te(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, bool start)
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

void darwin_iwi3945::queue_td(int num , thread_call_func_t func)
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

IOReturn darwin_iwi3945::message( UInt32 type, IOService * provider,
                              void * argument)
{
	IOLog("message %8x\n",type);
	return 0;

}

int darwin_iwi3945::ipw_is_valid_channel(struct ieee80211_device *ieee, u8 channel)
{
	int i;

	/* Driver needs to initialize the geography map before using
	 * these helper functions */
	if (ieee->geo.bg_channels == 0 && ieee->geo.a_channels == 0) return -1;

	if (ieee->freq_band & IEEE80211_24GHZ_BAND)
		for (i = 0; i < ieee->geo.bg_channels; i++)
			/* NOTE: If G mode is currently supported but
			 * this is a B only channel, we don't see it
			 * as valid. */
			if ((ieee->geo.bg[i].channel == channel) &&
			    (!(ieee->mode & IEEE_G) ||
			     !(ieee->geo.bg[i].flags & IEEE80211_CH_B_ONLY)))
				return IEEE80211_24GHZ_BAND;

	if (ieee->freq_band & IEEE80211_52GHZ_BAND)
		for (i = 0; i < ieee->geo.a_channels; i++)
			if (ieee->geo.a[i].channel == channel)
				return IEEE80211_52GHZ_BAND;

	return 0;
}

void darwin_iwi3945::ipw_create_bssid(struct ipw_priv *priv, u8 * bssid)
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

void darwin_iwi3945::ipw_adhoc_create(struct ipw_priv *priv,
			     struct ieee80211_network *network)
{
	
}

int darwin_iwi3945::ipw_is_rate_in_mask(struct ipw_priv *priv, int ieee_mode, u8 rate)
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

int darwin_iwi3945::ipw_compatible_rates(struct ipw_priv *priv,
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

void darwin_iwi3945::ipw_copy_rates(struct ipw_supported_rates *dest,
			   const struct ipw_supported_rates *src)
{
	u8 i;
	for (i = 0; i < src->num_rates; i++)
		dest->supported_rates[i] = src->supported_rates[i];
	dest->num_rates = src->num_rates;
}

int darwin_iwi3945::ipw_best_network(struct ipw_priv *priv,
			    struct ipw_network_match *match,
			    struct ieee80211_network *network, int roaming)
{
	struct ipw_supported_rates rates;
	/* Verify that this network's capability is compatible with the
	 * current mode (AdHoc or Infrastructure) */
	if ((priv->ieee->iw_mode == IW_MODE_INFRA &&
	     !(network->capability & WLAN_CAPABILITY_ESS)) ||
	    (priv->ieee->iw_mode == IW_MODE_ADHOC &&
	     !(network->capability & WLAN_CAPABILITY_IBSS))) {
		IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded due to "
				"capability mismatch.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid));
		//return 0;
	}

	/* If we do not have an ESSID for this AP, we can not associate with
	 * it */
	if (network->flags & NETWORK_EMPTY_ESSID) {
		IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of hidden ESSID.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid));
		//return 0;
	}

	if (unlikely(roaming)) {
		/* If we are roaming, then ensure check if this is a valid
		 * network to try and roam to */
		if ((network->ssid_len != match->network->ssid_len) ||
		    memcmp(network->ssid, match->network->ssid,
			   network->ssid_len)) {
			IOLog("Netowrk '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
					"because of non-network ESSID.\n",
					escape_essid((const char*)network->ssid,
						     network->ssid_len),
					MAC_ARG(network->bssid));
			//return 0;
		}
	} else {
		/* If an ESSID has been configured then compare the broadcast
		 * ESSID to ours */
		if ((priv->config & CFG_STATIC_ESSID) &&
		    ((network->ssid_len != priv->essid_len) ||
		     memcmp(network->ssid, priv->essid,
			    min(network->ssid_len, priv->essid_len)))) {
			char escaped[IW_ESSID_MAX_SIZE * 2 + 1];
			strncpy(escaped,
				escape_essid((const char*)network->ssid, network->ssid_len),
				sizeof(escaped));
			IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
					"because of ESSID mismatch: '%s'.\n",
					escaped, MAC_ARG(network->bssid),
					escape_essid((const char*)priv->essid,
						     priv->essid_len));
			//return 0;
		}
	}

	/* If the old network rate is better than this one, don't bother
	 * testing everything else. */
	if (match->network && match->network->stats.rssi > network->stats.rssi) {
		char escaped[IW_ESSID_MAX_SIZE * 2 + 1];
		strncpy(escaped,
			escape_essid((const char*)network->ssid, network->ssid_len),
			sizeof(escaped));
		IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded because "
				"'%s (%02x:%02x:%02x:%02x:%02x:%02x)' has a stronger signal.\n",
				escaped, MAC_ARG(network->bssid),
				escape_essid((const char*)match->network->ssid,
					     match->network->ssid_len),
				MAC_ARG(match->network->bssid));
		//return 0;
	}

	/* If this network has already had an association attempt within the
	 * last 3 seconds, do not try and associate again... */
	if (network->last_associate /*&&
	    time_after(network->last_associate + (HZ * 3UL), jiffies)*/) {
		IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of storming (%ums since last "
				"assoc attempt).\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid),
				/*jiffies_to_msecs(jiffies -
						 network->last_associate)*/0);
		//return 0;
	}

	/* Now go through and see if the requested network is valid... */
	if (priv->ieee->scan_age != 0 /*&&
	    time_after(jiffies, network->last_scanned + priv->ieee->scan_age)*/) {
		IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of age: %ums.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid),
				/*jiffies_to_msecs(jiffies -
						 network->last_scanned)*/0);
		//return 0;
	}

	if ((priv->config & CFG_STATIC_CHANNEL) &&
	    (network->channel != priv->channel)) {
		IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of channel mismatch: %d != %d.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid),
				network->channel, priv->channel);
		//return 0;
	}

	/* Verify privacy compatability */
	if (((priv->capability & CAP_PRIVACY_ON) ? 1 : 0) !=
	    ((network->capability & WLAN_CAPABILITY_PRIVACY) ? 1 : 0)) {
		IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of privacy mismatch: %s != %s.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid),
				priv->capability & CAP_PRIVACY_ON ? "on" :
				"off",
				network->capability &
				WLAN_CAPABILITY_PRIVACY ? "on" : "off");
		//return 0;
	}

	if ((priv->config & CFG_STATIC_BSSID) &&
	    memcmp(network->bssid, priv->bssid, ETH_ALEN)) {
		IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of BSSID mismatch: %02x:%02x:%02x:%02x:%02x:%02x.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid), MAC_ARG(priv->bssid));
		//return 0;
	}

	/* Filter out any incompatible freq / mode combinations */
	if (!ieee80211_is_valid_mode(priv->ieee, network->mode)) {
		IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of invalid frequency/mode "
				"combination.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid));
		//return 0;
	}

	/* Filter out invalid channel in current GEO */
	if (!ipw_is_valid_channel(priv->ieee, network->channel)) {
		IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of invalid channel in current GEO\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid));
		//return 0;
	}

	/* Ensure that the rates supported by the driver are compatible with
	 * this AP, including verification of basic rates (mandatory) */
	if (!ipw_compatible_rates(priv, network, &rates)) {
		IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because configured rate mask excludes "
				"AP mandatory rate.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid));
		//return 0;
	}

	if (rates.num_rates == 0) {
		IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of no compatible rates.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid));
		//return 0;
	}

	/* TODO: Perform any further minimal comparititive tests.  We do not
	 * want to put too much policy logic here; intelligent scan selection
	 * should occur within a generic IEEE 802.11 user space tool.  */

	/* Set up 'new' AP to this network */
	ipw_copy_rates(&match->rates, &rates);
	match->network = network;

	IOLog("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' is a viable match.\n",
			escape_essid((const char*)network->ssid, network->ssid_len),
			MAC_ARG(network->bssid));

	return 1;
}

int darwin_iwi3945::ipw_associate(ipw_priv *data)
{
	
}

void darwin_iwi3945::ipw_set_fixed_rate(struct ipw_priv *priv, int mode)
{
	
}

int darwin_iwi3945::ipw_associate_network(struct ipw_priv *priv,
				 struct ieee80211_network *network,
				 struct ipw_supported_rates *rates, int roaming)
{

}

int darwin_iwi3945::ipw_get_ordinal(struct ipw_priv *priv, u32 ord, void *val, u32 * len)
{
	
}

void darwin_iwi3945::ipw_reset_stats(struct ipw_priv *priv)
{
	
}

void darwin_iwi3945::ipw_read_indirect(struct ipw_priv *priv, u32 addr, u8 * buf,
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

void darwin_iwi3945::ipw_link_up(struct ipw_priv *priv)
{
	priv->last_seq_num = -1;
	priv->last_frag_num = -1;
	priv->last_packet_time = 0;

	
	
	fNetif->setLinkState(kIO80211NetworkLinkUp);
	/*netif_carrier_on(priv->net_dev);
	if (netif_queue_stopped(priv->net_dev)) {
		IOLog("waking queue\n");
		netif_wake_queue(priv->net_dev);
	} else {
		IOLog("starting queue\n");
		netif_start_queue(priv->net_dev);
	}*/
	queue_td(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan));	
	queue_td(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan_check));
	ipw_reset_stats(priv);
	/* Ensure the rate is updated immediately */
	priv->last_rate = ipw_get_current_rate(priv);
	ipw_gather_stats(priv);
	ipw_led_link_on(priv);
	//notify_wx_assoc_event(priv);

	if (priv->config & CFG_BACKGROUND_SCAN)
		queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan),priv,3,true);
}

void darwin_iwi3945::average_add(struct average *avg, s16 val)
{
	avg->sum -= avg->entries[avg->pos];
	avg->sum += val;
	avg->entries[avg->pos++] = val;
	if (unlikely(avg->pos == AVG_ENTRIES)) {
		avg->init = 1;
		avg->pos = 0;
	}
}

void darwin_iwi3945::ipw_gather_stats(struct ipw_priv *priv)
{

}

u32 darwin_iwi3945::ipw_get_max_rate(struct ipw_priv *priv)
{
	u32 i = 0x80000000;
	u32 mask = priv->rates_mask;
	/* If currently associated in B mode, restrict the maximum
	 * rate match to B rates */
	if (priv->assoc_request.ieee_mode == IPW_B_MODE)
		mask &= IEEE80211_CCK_RATES_MASK;

	/* TODO: Verify that the rate is supported by the current rates
	 * list. */

	while (i && !(mask & i))
		i >>= 1;
	switch (i) {
	case IEEE80211_CCK_RATE_1MB_MASK:
		return 1000000;
	case IEEE80211_CCK_RATE_2MB_MASK:
		return 2000000;
	case IEEE80211_CCK_RATE_5MB_MASK:
		return 5500000;
	case IEEE80211_OFDM_RATE_6MB_MASK:
		return 6000000;
	case IEEE80211_OFDM_RATE_9MB_MASK:
		return 9000000;
	case IEEE80211_CCK_RATE_11MB_MASK:
		return 11000000;
	case IEEE80211_OFDM_RATE_12MB_MASK:
		return 12000000;
	case IEEE80211_OFDM_RATE_18MB_MASK:
		return 18000000;
	case IEEE80211_OFDM_RATE_24MB_MASK:
		return 24000000;
	case IEEE80211_OFDM_RATE_36MB_MASK:
		return 36000000;
	case IEEE80211_OFDM_RATE_48MB_MASK:
		return 48000000;
	case IEEE80211_OFDM_RATE_54MB_MASK:
		return 54000000;
	}

	if (priv->ieee->mode == IEEE_B)
		return 11000000;
	else
		return 54000000;
}

u32 darwin_iwi3945::ipw_get_current_rate(struct ipw_priv *priv)
{
	u32 rate, len = sizeof(rate);
	int err;

	if (!(priv->status & STATUS_ASSOCIATED))
		return 0;

	if (priv->tx_packets > IPW_REAL_RATE_RX_PACKET_THRESHOLD) {
		err = ipw_get_ordinal(priv, IPW_ORD_STAT_TX_CURR_RATE, &rate,
				      &len);
		if (err) {
			IOLog("failed querying ordinals.\n");
			return 0;
		}
	} else
		return ipw_get_max_rate(priv);

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

void darwin_iwi3945::ipw_link_down(struct ipw_priv *priv)
{
	ipw_led_link_down(priv);
	fNetif->setLinkState(kIO80211NetworkLinkDown);
	//netif_carrier_off(priv->net_dev);
	//netif_stop_queue(priv->net_dev);
	//notify_wx_assoc_event(priv);

	/* Cancel any queued work ... */
	queue_td(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan));
	queue_td(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan_check));
	//cancel_delayed_work(&priv->adhoc_check);
	//cancel_delayed_work(&priv->gather_stats);

	ipw_reset_stats(priv);

	if (!(priv->status & STATUS_EXIT_PENDING)) {
		/* Queue up another scan... */
		queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi3945::ipw_scan),priv,3,true);
	}
}

const char* darwin_iwi3945::ipw_get_status_code(u16 status)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(ipw_status_codes); i++)
		if (ipw_status_codes[i].status == (status & 0xff))
			return ipw_status_codes[i].reason;
	return "Unknown status value.";
}

void darwin_iwi3945::notifIntr(struct ipw_priv *priv,
				struct ipw_rx_notification *notif)
{
	
}

