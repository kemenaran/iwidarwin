#include "firmware/iwi_bss.fw.h"
#include "firmware/iwi_ibss.fw.h"
#include "firmware/iwi_mon.fw.h"
#include "defines.h"

//			<string>0x25208086 0x25218086 0x25248086 0x25258086 0x25268086 0x25228086 0x25238086 0x25278086 0x25288086 0x25298086 0x252B8086 0x252C8086 0x252D8086 0x25508086 0x25518086 0x25538086 0x25548086 0x25558086 0x25608086 0x25628086 0x25638086 0x25618086 0x25658086 0x25668086 0x25678086 0x25708086 0x25808086 0x25828086 0x25838086 0x25818086 0x25858086 0x25868086 0x25878086 0x25908086 0x25928086 0x25918086 0x25938086 0x25968086 0x25988086 0x25A08086</string>

// Define my superclass
#define super IO80211Controller
// REQUIRED! This macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires. Do NOT use super as the
// second parameter. You must use the literal name of the superclass.
OSDefineMetaClassAndStructors(darwin_iwi2100, IO80211Controller);

static const char *frame_types[] = {
	"COMMAND_STATUS_VAL",
	"STATUS_CHANGE_VAL",
	"P80211_DATA_VAL",
	"P8023_DATA_VAL",
	"HOST_NOTIFICATION_VAL"
};

static const char *command_types[] = {
	"undefined",
	"unused",		/* HOST_ATTENTION */
	"HOST_COMPLETE",
	"unused",		/* SLEEP */
	"unused",		/* HOST_POWER_DOWN */
	"unused",
	"SYSTEM_CONFIG",
	"unused",		/* SET_IMR */
	"SSID",
	"MANDATORY_BSSID",
	"AUTHENTICATION_TYPE",
	"ADAPTER_ADDRESS",
	"PORT_TYPE",
	"INTERNATIONAL_MODE",
	"CHANNEL",
	"RTS_THRESHOLD",
	"FRAG_THRESHOLD",
	"POWER_MODE",
	"TX_RATES",
	"BASIC_TX_RATES",
	"WEP_KEY_INFO",
	"unused",
	"unused",
	"unused",
	"unused",
	"WEP_KEY_INDEX",
	"WEP_FLAGS",
	"ADD_MULTICAST",
	"CLEAR_ALL_MULTICAST",
	"BEACON_INTERVAL",
	"ATIM_WINDOW",
	"CLEAR_STATISTICS",
	"undefined",
	"undefined",
	"undefined",
	"undefined",
	"TX_POWER_INDEX",
	"undefined",
	"undefined",
	"undefined",
	"undefined",
	"undefined",
	"undefined",
	"BROADCAST_SCAN",
	"CARD_DISABLE",
	"PREFERRED_BSSID",
	"SET_SCAN_OPTIONS",
	"SCAN_DWELL_TIME",
	"SWEEP_TABLE",
	"AP_OR_STATION_TABLE",
	"GROUP_ORDINALS",
	"SHORT_RETRY_LIMIT",
	"LONG_RETRY_LIMIT",
	"unused",		/* SAVE_CALIBRATION */
	"unused",		/* RESTORE_CALIBRATION */
	"undefined",
	"undefined",
	"undefined",
	"HOST_PRE_POWER_DOWN",
	"unused",		/* HOST_INTERRUPT_COALESCING */
	"undefined",
	"CARD_DISABLE_PHY_OFF",
	"MSDU_TX_RATES" "undefined",
	"undefined",
	"SET_STATION_STAT_BITS",
	"CLEAR_STATIONS_STAT_BITS",
	"LEAP_ROGUE_MODE",
	"SET_SECURITY_INFORMATION",
	"DISASSOCIATION_BSSID",
	"SET_WPA_ASS_IE"
};

static const struct ipw2100_status_code ipw2100_status_codes[] = {
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
	 14,
	 NULL,
	 {{2412, 1}, {2417, 2}, {2422, 3},
		{2427, 4}, {2432, 5}, {2437, 6},
		{2442, 7}, {2447, 8}, {2452, 9},
		{2457, 10}, {2462, 11}, {2467, 12},
		{2472, 13}, {2484, 14}},
	NULL
	 }
};


bool darwin_iwi2100::init(OSDictionary *dict)
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
  //led=OSDynamicCast(OSNumber,dict->getObject("p_led"))->unsigned32BitValue();
  mode=OSDynamicCast(OSNumber,dict->getObject("p_mode"))->unsigned32BitValue();

 IOLog("disable %d mode %d\n",disable2, mode);

 return super::init(dict);
}

int darwin_iwi2100::bd_queue_allocate(struct ipw2100_priv *priv,
			     struct ipw2100_bd_queue *q, int entries)
{

	memset(q, 0, sizeof(struct ipw2100_bd_queue));

	q->entries = entries;
	q->size = entries * sizeof(struct ipw2100_bd);
	MemoryDmaAlloc(q->size, &q->nic, &q->drv);
	//q->drv = pci_alloc_consistent(priv->pci_dev, q->size, &q->nic);
	if (!q->drv) {
		IOLog
		    ("can't allocate shared memory for buffer descriptors\n");
		return -ENOMEM;
	}
	memset(q->drv, 0, q->size);


	return 0;
}

void darwin_iwi2100::bd_queue_free(struct ipw2100_priv *priv, struct ipw2100_bd_queue *q)
{

	if (!q)
		return;

	if (q->drv) {
		//pci_free_consistent(priv->pci_dev, q->size, q->drv, q->nic);
		q->nic=NULL;
		q->drv=NULL;
		q->drv = NULL;
	}

}

int darwin_iwi2100::ipw2100_tx_allocate(struct ipw2100_priv *priv)
{
	int i, j, err = -EINVAL;
	void *v;
	dma_addr_t p;


	err = bd_queue_allocate(priv, &priv->tx_queue, TX_QUEUE_LENGTH);
	if (err) {
		IOLog("%s: failed bd_queue_allocate\n",
				priv->net_dev->name);
		return err;
	}

	priv->tx_buffers =
	    (struct ipw2100_tx_packet *)kmalloc(TX_PENDED_QUEUE_LENGTH *
						sizeof(struct
						       ipw2100_tx_packet),
						GFP_ATOMIC);
	if (!priv->tx_buffers) {
		IOLog( 
		       ": %s: alloc failed form tx buffers.\n",
		       priv->net_dev->name);
		bd_queue_free(priv, &priv->tx_queue);
		return -ENOMEM;
	}

	for (i = 0; i < TX_PENDED_QUEUE_LENGTH; i++) {
	
		MemoryDmaAlloc(sizeof(struct ipw2100_data_header), &p, &v);
		/*v = pci_alloc_consistent(priv->pci_dev,
					 sizeof(struct ipw2100_data_header),
					 &p);*/
		if (!v) {
			IOLog( 
			       ": %s: PCI alloc failed for tx " "buffers.\n",
			       priv->net_dev->name);
			err = -ENOMEM;
			break;
		}

		priv->tx_buffers[i].type = DATA;
		priv->tx_buffers[i].info.d_struct.data =
		    (struct ipw2100_data_header *)v;
		priv->tx_buffers[i].info.d_struct.data_phys = p;
		priv->tx_buffers[i].info.d_struct.txb = NULL;
	}

	if (i == TX_PENDED_QUEUE_LENGTH)
		return 0;

	for (j = 0; j < i; j++) {
		priv->tx_buffers[j].info.d_struct.data=NULL;
		priv->tx_buffers[j].info.d_struct.
				    data_phys=NULL;
		/*pci_free_consistent(priv->pci_dev,
				    sizeof(struct ipw2100_data_header),
				    priv->tx_buffers[j].info.d_struct.data,
				    priv->tx_buffers[j].info.d_struct.
				    data_phys);*/
	}

	kfree(priv->tx_buffers);
	priv->tx_buffers = NULL;

	return err;
}

int darwin_iwi2100::status_queue_allocate(struct ipw2100_priv *priv, int entries)
{
	struct ipw2100_status_queue *q = &priv->status_queue;


	q->size = entries * sizeof(struct ipw2100_status);
	MemoryDmaAlloc(q->size, &q->nic, &q->drv);
	/*q->drv =
	    (struct ipw2100_status *)pci_alloc_consistent(priv->pci_dev,
							  q->size, &q->nic);*/
	if (!q->drv) {
		IOLog("Can not allocate status queue.\n");
		return -ENOMEM;
	}

	memset(q->drv, 0, q->size);


	return 0;
}

void darwin_iwi2100::status_queue_free(struct ipw2100_priv *priv)
{

	if (priv->status_queue.drv) {
		/*pci_free_consistent(priv->pci_dev, priv->status_queue.size,
				    priv->status_queue.drv,
				    priv->status_queue.nic);*/
					priv->status_queue.nic=NULL;
		priv->status_queue.drv = NULL;
	}

}

int darwin_iwi2100::ipw2100_alloc_skb(struct ipw2100_priv *priv,
				    struct ipw2100_rx_packet *packet)
{
	packet->skb = allocatePacket(sizeof(struct ipw2100_rx));
	if (!packet->skb)
		return -ENOMEM;

	packet->rxp = (struct ipw2100_rx *)mbuf_data(packet->skb);
	packet->dma_addr = mbuf_data_to_physical(mbuf_data(packet->skb));
	/*pci_map_single(priv->pci_dev, packet->skb->data,
					  sizeof(struct ipw2100_rx),
					  PCI_DMA_FROMDEVICE);*/
	/* NOTE: pci_map_single does not return an error code, and 0 is a valid
	 *       dma_addr */

	return 0;
}

int darwin_iwi2100::ipw2100_rx_allocate(struct ipw2100_priv *priv)
{
	int i, j, err = -EINVAL;


	err = bd_queue_allocate(priv, &priv->rx_queue, RX_QUEUE_LENGTH);
	if (err) {
		IOLog("failed bd_queue_allocate\n");
		return err;
	}

	err = status_queue_allocate(priv, RX_QUEUE_LENGTH);
	if (err) {
		IOLog("failed status_queue_allocate\n");
		bd_queue_free(priv, &priv->rx_queue);
		return err;
	}

	/*
	 * allocate packets
	 */
	priv->rx_buffers = (struct ipw2100_rx_packet *)
	    kmalloc(RX_QUEUE_LENGTH * sizeof(struct ipw2100_rx_packet),
		    GFP_KERNEL);
	if (!priv->rx_buffers) {
		IOLog("can't allocate rx packet buffer table\n");

		bd_queue_free(priv, &priv->rx_queue);

		status_queue_free(priv);

		return -ENOMEM;
	}

	for (i = 0; i < RX_QUEUE_LENGTH; i++) {
		struct ipw2100_rx_packet *packet = &priv->rx_buffers[i];

		err = ipw2100_alloc_skb(priv, packet);
		if (unlikely(err)) {
			err = -ENOMEM;
			break;
		}

		/* The BD holds the cache aligned address */
		priv->rx_queue.drv[i].host_addr = packet->dma_addr;
		priv->rx_queue.drv[i].buf_length = IPW_RX_NIC_BUFFER_LENGTH;
		priv->status_queue.drv[i].status_fields = 0;
	}

	if (i == RX_QUEUE_LENGTH)
		return 0;

	for (j = 0; j < i; j++) {
		priv->rx_buffers[j].dma_addr=NULL;
		freePacket(priv->rx_buffers[j].skb);
		/*pci_unmap_single(priv->pci_dev, priv->rx_buffers[j].dma_addr,
				 sizeof(struct ipw2100_rx_packet),
				 PCI_DMA_FROMDEVICE);
		dev_kfree_skb(priv->rx_buffers[j].skb);*/
	}

	kfree(priv->rx_buffers);
	priv->rx_buffers = NULL;

	bd_queue_free(priv, &priv->rx_queue);

	status_queue_free(priv);

	return err;
}

int darwin_iwi2100::ipw2100_msg_allocate(struct ipw2100_priv *priv)
{
	int i, j, err = -EINVAL;
	void *v;
	dma_addr_t p;

	priv->msg_buffers =
	    (struct ipw2100_tx_packet *)kmalloc(IPW_COMMAND_POOL_SIZE *
						sizeof(struct
						       ipw2100_tx_packet),
						GFP_KERNEL);
	if (!priv->msg_buffers) {
		IOLog(  ": %s: PCI alloc failed for msg "
		       "buffers.\n", priv->net_dev->name);
		return -ENOMEM;
	}

	for (i = 0; i < IPW_COMMAND_POOL_SIZE; i++) {
		MemoryDmaAlloc(sizeof(struct ipw2100_cmd_header), &p, &v);
		/*v = pci_alloc_consistent(priv->pci_dev,
					 sizeof(struct ipw2100_cmd_header), &p);*/
		if (!v) {
			IOLog(  ": "
			       "%s: PCI alloc failed for msg "
			       "buffers.\n", priv->net_dev->name);
			err = -ENOMEM;
			break;
		}

		memset(v, 0, sizeof(struct ipw2100_cmd_header));

		priv->msg_buffers[i].type = COMMAND;
		priv->msg_buffers[i].info.c_struct.cmd =
		    (struct ipw2100_cmd_header *)v;
		priv->msg_buffers[i].info.c_struct.cmd_phys = p;
	}

	if (i == IPW_COMMAND_POOL_SIZE)
		return 0;

	for (j = 0; j < i; j++) {
	priv->msg_buffers[j].info.c_struct.cmd=NULL;
	 priv->msg_buffers[j].info.c_struct.
				    cmd_phys=NULL;
		/*pci_free_consistent(priv->pci_dev,
				    sizeof(struct ipw2100_cmd_header),
				    priv->msg_buffers[j].info.c_struct.cmd,
				    priv->msg_buffers[j].info.c_struct.
				    cmd_phys);*/
	}

	kfree(priv->msg_buffers);
	priv->msg_buffers = NULL;

	return err;
}

void darwin_iwi2100::ieee80211_txb_free(struct ieee80211_txb *txb)
{
	int i;
	if (unlikely(!txb))
		return;
	for (i = 0; i < txb->nr_frags; i++)
		if (txb->fragments[i]) 
		{
			freePacket(txb->fragments[i]);
			txb->fragments[i]=NULL;
			
		}
	kfree(txb);
	txb=NULL;
}

void darwin_iwi2100::ipw2100_tx_free(struct ipw2100_priv *priv)
{
	int i;


	bd_queue_free(priv, &priv->tx_queue);

	if (!priv->tx_buffers)
		return;

	for (i = 0; i < TX_PENDED_QUEUE_LENGTH; i++) {
		if (priv->tx_buffers[i].info.d_struct.txb) {
			ieee80211_txb_free(priv->tx_buffers[i].info.d_struct.
					   txb);
			priv->tx_buffers[i].info.d_struct.txb = NULL;
		}
		if (priv->tx_buffers[i].info.d_struct.data)
		{
			priv->tx_buffers[i].info.d_struct.
					    data=NULL;
						priv->tx_buffers[i].info.d_struct.
					    data_phys=NULL;
			/*pci_free_consistent(priv->pci_dev,
					    sizeof(struct ipw2100_data_header),
					    priv->tx_buffers[i].info.d_struct.
					    data,
					    priv->tx_buffers[i].info.d_struct.
					    data_phys);*/
		}
	}

	kfree(priv->tx_buffers);
	priv->tx_buffers = NULL;

}

void darwin_iwi2100::ipw2100_rx_free(struct ipw2100_priv *priv)
{
	int i;


	bd_queue_free(priv, &priv->rx_queue);
	status_queue_free(priv);

	if (!priv->rx_buffers)
		return;

	for (i = 0; i < RX_QUEUE_LENGTH; i++) {
		if (priv->rx_buffers[i].rxp) {
		priv->rx_buffers[i].dma_addr=NULL;
			/*pci_unmap_single(priv->pci_dev,
					 priv->rx_buffers[i].dma_addr,
					 sizeof(struct ipw2100_rx),
					 PCI_DMA_FROMDEVICE);
			dev_kfree_skb(priv->rx_buffers[i].skb);*/
			freePacket(priv->rx_buffers[i].skb);
		}
	}

	kfree(priv->rx_buffers);
	priv->rx_buffers = NULL;

}

void darwin_iwi2100::ipw2100_msg_free(struct ipw2100_priv *priv)
{
	int i;

	if (!priv->msg_buffers)
		return;

	for (i = 0; i < IPW_COMMAND_POOL_SIZE; i++) {
	priv->msg_buffers[i].info.c_struct.cmd=NULL;
	priv->msg_buffers[i].info.c_struct.
				    cmd_phys=NULL;
		/*pci_free_consistent(priv->pci_dev,
				    sizeof(struct ipw2100_cmd_header),
				    priv->msg_buffers[i].info.c_struct.cmd,
				    priv->msg_buffers[i].info.c_struct.
				    cmd_phys);*/
	}

	kfree(priv->msg_buffers);
	priv->msg_buffers = NULL;
}

int darwin_iwi2100::ipw2100_queues_allocate(struct ipw2100_priv *priv)
{
	if (ipw2100_tx_allocate(priv) ||
	    ipw2100_rx_allocate(priv) || ipw2100_msg_allocate(priv))
		goto fail;

	return 0;

      fail:
	ipw2100_tx_free(priv);
	ipw2100_rx_free(priv);
	ipw2100_msg_free(priv);
	return -ENOMEM;
}

void darwin_iwi2100::bd_queue_initialize(struct ipw2100_priv *priv,
				struct ipw2100_bd_queue *q, u32 base, u32 size,
				u32 r, u32 w)
{

	IOLog("initializing bd queue at virt=%p, phys=%08x\n", q->drv,
		       (u32) q->nic);

	write_register(priv->net_dev, base, q->nic);
	write_register(priv->net_dev, size, q->entries);
	write_register(priv->net_dev, r, q->oldest);
	write_register(priv->net_dev, w, q->next);

}

void darwin_iwi2100::ipw2100_tx_initialize(struct ipw2100_priv *priv)
{
	int i;


	/*
	 * reinitialize packet info lists
	 */
	INIT_LIST_HEAD(&priv->fw_pend_list);
	INIT_STAT(&priv->fw_pend_stat);

	/*
	 * reinitialize lists
	 */
	INIT_LIST_HEAD(&priv->tx_pend_list);
	INIT_LIST_HEAD(&priv->tx_free_list);
	INIT_STAT(&priv->tx_pend_stat);
	INIT_STAT(&priv->tx_free_stat);

	for (i = 0; i < TX_PENDED_QUEUE_LENGTH; i++) {
		/* We simply drop any SKBs that have been queued for
		 * transmit */
		if (priv->tx_buffers[i].info.d_struct.txb) {
			ieee80211_txb_free(priv->tx_buffers[i].info.d_struct.
					   txb);
			priv->tx_buffers[i].info.d_struct.txb = NULL;
		}

		list_add_tail(&priv->tx_buffers[i].list, &priv->tx_free_list);
	}

	SET_STAT(&priv->tx_free_stat, i);

	priv->tx_queue.oldest = 0;
	priv->tx_queue.available = priv->tx_queue.entries;
	priv->tx_queue.next = 0;
	INIT_STAT(&priv->txq_stat);
	SET_STAT(&priv->txq_stat, priv->tx_queue.available);

	bd_queue_initialize(priv, &priv->tx_queue,
			    IPW_MEM_HOST_SHARED_TX_QUEUE_BD_BASE,
			    IPW_MEM_HOST_SHARED_TX_QUEUE_BD_SIZE,
			    IPW_MEM_HOST_SHARED_TX_QUEUE_READ_INDEX,
			    IPW_MEM_HOST_SHARED_TX_QUEUE_WRITE_INDEX);


}

void darwin_iwi2100::ipw2100_rx_initialize(struct ipw2100_priv *priv)
{

	priv->rx_queue.oldest = 0;
	priv->rx_queue.available = priv->rx_queue.entries - 1;
	priv->rx_queue.next = priv->rx_queue.entries - 1;

	INIT_STAT(&priv->rxq_stat);
	SET_STAT(&priv->rxq_stat, priv->rx_queue.available);

	bd_queue_initialize(priv, &priv->rx_queue,
			    IPW_MEM_HOST_SHARED_RX_BD_BASE,
			    IPW_MEM_HOST_SHARED_RX_BD_SIZE,
			    IPW_MEM_HOST_SHARED_RX_READ_INDEX,
			    IPW_MEM_HOST_SHARED_RX_WRITE_INDEX);

	/* set up the status queue */
	write_register(priv->net_dev, IPW_MEM_HOST_SHARED_RX_STATUS_BASE,
		       priv->status_queue.nic);

}

int darwin_iwi2100::ipw2100_msg_initialize(struct ipw2100_priv *priv)
{
	int i;

	INIT_LIST_HEAD(&priv->msg_free_list);
	INIT_LIST_HEAD(&priv->msg_pend_list);

	for (i = 0; i < IPW_COMMAND_POOL_SIZE; i++)
		list_add_tail(&priv->msg_buffers[i].list, &priv->msg_free_list);
	SET_STAT(&priv->msg_free_stat, i);

	return 0;
}

void darwin_iwi2100::ipw2100_queues_initialize(struct ipw2100_priv *priv)
{
	ipw2100_tx_initialize(priv);
	ipw2100_rx_initialize(priv);
	ipw2100_msg_initialize(priv);
}

int darwin_iwi2100::ipw2100_sw_reset(int option)
{
	int err = 0;
	struct net_device *net_dev;
	void __iomem *base;
	u32 length, val;
	int i;
	struct ieee80211_device *ieee;
	int registered = 0;
	
	//net_dev=(struct net_device*)fifnet;
	net_dev=&net_dev2;
	//memset(&net_dev,0,sizeof(struct ieee80211_device) + sizeof(struct ipw2100_priv));
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
	//priv=(struct ipw2100_priv*)ieee80211_priv(net_dev);
	priv->ieee = ieee;

	priv->net_dev = net_dev;
	
	priv->ieee->perfect_rssi = -20;
	priv->ieee->worst_rssi = -85;

	priv->power_mode = IPW_POWER_AUTO;

#ifdef CONFIG_IPW2100_MONITOR
	priv->config |= CFG_CRC_CHECK;
#endif
	priv->ieee->wpa_enabled = 0;
	priv->ieee->drop_unencrypted = 0;
	priv->ieee->privacy_invoked = 0;
	priv->ieee->ieee802_1x = 1;

	/* Set module parameters */
	switch (mode) {
	case 1:
		priv->ieee->iw_mode = IW_MODE_ADHOC;
		break;
#ifdef CONFIG_IPW2100_MONITOR
	case 2:
		priv->ieee->iw_mode = IW_MODE_MONITOR;
		break;
#endif
	default:
	case 0:
		priv->ieee->iw_mode = IW_MODE_INFRA;
		break;
	}

	if (disable2 == 1)
		priv->status |= STATUS_RF_KILL_SW;

	if (channel != 0 &&
	    ((channel >= REG_MIN_CHANNEL) && (channel <= REG_MAX_CHANNEL))) {
		priv->config |= CFG_STATIC_CHANNEL;
		priv->channel = channel;
	}

	if (associate)
		priv->config |= CFG_ASSOCIATE;

	priv->beacon_interval = DEFAULT_BEACON_INTERVAL;
	priv->short_retry_limit = DEFAULT_SHORT_RETRY_LIMIT;
	priv->long_retry_limit = DEFAULT_LONG_RETRY_LIMIT;
	priv->rts_threshold = DEFAULT_RTS_THRESHOLD | RTS_DISABLED;
	priv->frag_threshold = DEFAULT_FTS | FRAG_DISABLED;
	priv->tx_power = IPW_TX_POWER_DEFAULT;
	priv->tx_rates = DEFAULT_TX_RATES;


	INIT_LIST_HEAD(&priv->msg_free_list);
	INIT_LIST_HEAD(&priv->msg_pend_list);
	INIT_STAT(&priv->msg_free_stat);
	INIT_STAT(&priv->msg_pend_stat);

	INIT_LIST_HEAD(&priv->tx_free_list);
	INIT_LIST_HEAD(&priv->tx_pend_list);
	INIT_STAT(&priv->tx_free_stat);
	INIT_STAT(&priv->tx_pend_stat);

	INIT_LIST_HEAD(&priv->fw_pend_list);
	INIT_STAT(&priv->fw_pend_stat);

	priv->stop_rf_kill = 1;
	priv->stop_hang_check = 1;


	/*if (!ipw2100_hw_is_adapter_in_system(dev)) {
		printk(KERN_WARNING DRV_NAME
		       "Device not found via register read.\n");
		err = -ENODEV;
		goto fail;
	}*/


	/* Force interrupts to be shut off on the device */
	priv->status |= STATUS_INT_ENABLED;
	ipw2100_disable_interrupts(priv);

	IOLog("ipw2100_queues_allocate.\n");
	/* Allocate and initialize the Tx/Rx queues and lists */
	if (ipw2100_queues_allocate(priv)) {
		IOLog(
		       "Error calilng ipw2100_queues_allocate.\n");
	}
	//ipw2100_queues_initialize(priv);

	//ipw2100_initialize_ordinals(priv);
	
	IOLog(": Detected Intel PRO/Wireless 2100 Network Connection\n");

	ipw2100_up(priv,1);
	/*if (!(priv->status & STATUS_RF_KILL_MASK)) {
		if (ipw2100_enable_adapter(priv)) {
			IOLog(
			       ": %s: failed in call to enable adapter.\n",
			       priv->net_dev->name);
			ipw2100_hw_stop_adapter(priv);
			return -EIO;
		}

		//ipw2100_set_scan_options(priv);
		//ipw2100_start_scan(priv);
	}*/
	registered = 1;

	priv->status |= STATUS_INITIALIZED;
	
	
		
	return 0;

}

int darwin_iwi2100::ipw2100_hw_phy_off(struct ipw2100_priv *priv)
{

#define HW_PHY_OFF_LOOP_DELAY (HZ / 5000)

	struct host_command cmd;
		cmd.host_command = CARD_DISABLE_PHY_OFF;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = 0;

	int err, i;
	u32 val1, val2;

	IOLog("CARD_DISABLE_PHY_OFF\n");

	/* Turn off the radio */
	err = ipw2100_hw_send_command(priv, &cmd);
	if (err)
		return err;

	for (i = 0; i < 2500; i++) {
		read_nic_dword(priv->net_dev, IPW2100_CONTROL_REG, &val1);
		read_nic_dword(priv->net_dev, IPW2100_COMMAND, &val2);

		if ((val1 & IPW2100_CONTROL_PHY_OFF) &&
		    (val2 & IPW2100_COMMAND_PHY_OFF))
			return 0;

		//set_current_state(TASK_UNINTERRUPTIBLE);
		//schedule_timeout(HW_PHY_OFF_LOOP_DELAY);
	}

	return -EIO;
}

int darwin_iwi2100::ipw2100_hw_stop_adapter(struct ipw2100_priv *priv)
{
#define HW_POWER_DOWN_DELAY (msecs_to_jiffies(100))

	struct host_command cmd;
		cmd.host_command = HOST_PRE_POWER_DOWN;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = 0;

	int err, i;
	u32 reg;

	if (!(priv->status & STATUS_RUNNING))
		return 0;

	priv->status |= STATUS_STOPPING;

	/* We can only shut down the card if the firmware is operational.  So,
	 * if we haven't reset since a fatal_error, then we can not send the
	 * shutdown commands. */
	if (!priv->fatal_error) {
		/* First, make sure the adapter is enabled so that the PHY_OFF
		 * command can shut it down */
		ipw2100_enable_adapter(priv);

		err = ipw2100_hw_phy_off(priv);
		if (err)
			IOLog(
			       ": Error disabling radio %d\n", err);

		/*
		 * If in D0-standby mode going directly to D3 may cause a
		 * PCI bus violation.  Therefore we must change out of the D0
		 * state.
		 *
		 * Sending the PREPARE_FOR_POWER_DOWN will restrict the
		 * hardware from going into standby mode and will transition
		 * out of D0-standby if it is already in that state.
		 *
		 * STATUS_PREPARE_POWER_DOWN_COMPLETE will be sent by the
		 * driver upon completion.  Once received, the driver can
		 * proceed to the D3 state.
		 *
		 * Prepare for power down command to fw.  This command would
		 * take HW out of D0-standby and prepare it for D3 state.
		 *
		 * Currently FW does not support event notification for this
		 * event. Therefore, skip waiting for it.  Just wait a fixed
		 * 100ms
		 */
		IOLog("HOST_PRE_POWER_DOWN\n");

		err = ipw2100_hw_send_command(priv, &cmd);
		if (err)
			IOLog(  ": "
			       "%s: Power down command failed: Error %d\n",
			       priv->net_dev->name, err);
		//else {
		//	set_current_state(TASK_UNINTERRUPTIBLE);
		//	schedule_timeout(HW_POWER_DOWN_DELAY);
		//}
	}

	priv->status &= ~STATUS_ENABLED;

	/*
	 * Set GPIO 3 writable by FW; GPIO 1 writable
	 * by driver and enable clock
	 */
	ipw2100_hw_set_gpio(priv);

	/*
	 * Power down adapter.  Sequence:
	 * 1. Stop master assert (RESET_REG[9]=1)
	 * 2. Wait for stop master (RESET_REG[8]==1)
	 * 3. S/w reset assert (RESET_REG[7] = 1)
	 */

	/* Stop master assert */
	write_register(priv->net_dev, IPW_REG_RESET_REG,
		       IPW_AUX_HOST_RESET_REG_STOP_MASTER);

	/* wait stop master not more than 50 usec.
	 * Otherwise return error. */
	for (i = 5; i > 0; i--) {
		udelay(10);

		/* Check master stop bit */
		read_register(priv->net_dev, IPW_REG_RESET_REG, &reg);

		if (reg & IPW_AUX_HOST_RESET_REG_MASTER_DISABLED)
			break;
	}

	if (i == 0)
		IOLog( 
		       ": %s: Could now power down adapter.\n",
		       priv->net_dev->name);

	/* assert s/w reset */
	write_register(priv->net_dev, IPW_REG_RESET_REG,
		       IPW_AUX_HOST_RESET_REG_SW_RESET);

	priv->status &= ~(STATUS_RUNNING | STATUS_STOPPING);

	return 0;
}

int darwin_iwi2100::ipw2100_start_scan(struct ipw2100_priv *priv)
{
	struct host_command cmd;// = {
		cmd.host_command = BROADCAST_SCAN;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = 4;
	//};
	int err;

	IOLog("START_SCAN\n");

	cmd.host_command_parameters[0] = 0;

	/* No scanning if in monitor mode */
	if (priv->ieee->iw_mode == IW_MODE_MONITOR)
		return 1;

	if (priv->status & STATUS_SCANNING) {
		IOLog("Scan requested while already in scan...\n");
		return 0;
	}


	/* Not clearing here; doing so makes iwlist always return nothing...
	 *
	 * We should modify the table logic to use aging tables vs. clearing
	 * the table on each scan start.
	 */
	IOLog("starting scan\n");

	priv->status |= STATUS_SCANNING;
	err = ipw2100_hw_send_command(priv, &cmd);
	if (err)
		priv->status &= ~STATUS_SCANNING;


	return err;
}

void darwin_iwi2100::freePacket(mbuf_t m, IOOptionBits options)
{
	//mbuf_t m_next;
	if( m != NULL){
		//m_next = mbuf_next(m);
		if (mbuf_pkthdr_len(m) != 0 && mbuf_type(m) != MBUF_TYPE_FREE )
			super::freePacket(m,NULL);
		// checking chains
		/*if(  m_next != NULL &&
		     mbuf_len(m_next) != 0  &&  
		     mbuf_type(m_next) != MBUF_TYPE_FREE ){
			IWI_WARNING("mbuf is freed. but chains is not freed \n");
		}*/
		//if (kDelayFree & kDelayFree) releaseFreePackets();
	}
}

void darwin_iwi2100::getPacketBufferConstraints(IOPacketBufferConstraints * constraints) const {
    constraints->alignStart  = kIOPacketBufferAlign4;	// even word aligned.
    constraints->alignLength = kIOPacketBufferAlign4;	// no restriction.
}

int darwin_iwi2100::ipw2100_set_scan_options(struct ipw2100_priv *priv)
{
	struct host_command cmd;// = {
		cmd.host_command = SET_SCAN_OPTIONS;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = 8;
	//};
	int err;


	IOLog("setting scan options\n");

	cmd.host_command_parameters[0] = 0;

	if (!(priv->config & CFG_ASSOCIATE))
		cmd.host_command_parameters[0] |= IPW_SCAN_NOASSOCIATE;
	if ((priv->ieee->sec.flags & SEC_ENABLED) && priv->ieee->sec.enabled)
		cmd.host_command_parameters[0] |= IPW_SCAN_MIXED_CELL;
	if (priv->config & CFG_PASSIVE_SCAN)
		cmd.host_command_parameters[0] |= IPW_SCAN_PASSIVE;

	cmd.host_command_parameters[1] = priv->channel_mask;

	err = ipw2100_hw_send_command(priv, &cmd);

	IOLog("SET_SCAN_OPTIONS 0x%04X\n",
		     cmd.host_command_parameters[0]);

	return err;
}

void darwin_iwi2100::ipw2100_initialize_ordinals(struct ipw2100_priv *priv)
{
	struct ipw2100_ordinals *ord = &priv->ordinals;


	read_register(priv->net_dev, IPW_MEM_HOST_SHARED_ORDINALS_TABLE_1,
		      &ord->table1_addr);

	read_register(priv->net_dev, IPW_MEM_HOST_SHARED_ORDINALS_TABLE_2,
		      &ord->table2_addr);

	read_nic_dword(priv->net_dev, ord->table1_addr, &ord->table1_size);
	read_nic_dword(priv->net_dev, ord->table2_addr, &ord->table2_size);

	ord->table2_size &= 0x0000FFFF;

	IOLog("table 1 size: %d\n", ord->table1_size);
	IOLog("table 2 size: %d\n", ord->table2_size);
}

int darwin_iwi2100::ipw2100_get_ordinal(struct ipw2100_priv *priv, u32 ord,
			       void *val, u32 * len)
{
	struct ipw2100_ordinals *ordinals = &priv->ordinals;
	u32 addr;
	u32 field_info;
	u16 field_len;
	u16 field_count;
	u32 total_length;

	if (ordinals->table1_addr == 0) {
		IOLog( ": attempt to use fw ordinals "
		       "before they have been loaded.\n");
		return -EINVAL;
	}

	if (IS_ORDINAL_TABLE_ONE(ordinals, ord)) {
		if (*len < IPW_ORD_TAB_1_ENTRY_SIZE) {
			*len = IPW_ORD_TAB_1_ENTRY_SIZE;

			IOLog(
			       ": ordinal buffer length too small, need %zd\n",
			       IPW_ORD_TAB_1_ENTRY_SIZE);

			return -EINVAL;
		}

		read_nic_dword(priv->net_dev,
			       ordinals->table1_addr + (ord << 2), &addr);
		read_nic_dword(priv->net_dev, addr, (u32*)val);

		*len = IPW_ORD_TAB_1_ENTRY_SIZE;

		return 0;
	}

	if (IS_ORDINAL_TABLE_TWO(ordinals, ord)) {

		ord -= IPW_START_ORD_TAB_2;

		/* get the address of statistic */
		read_nic_dword(priv->net_dev,
			       ordinals->table2_addr + (ord << 3), &addr);

		/* get the second DW of statistics ;
		 * two 16-bit words - first is length, second is count */
		read_nic_dword(priv->net_dev,
			       ordinals->table2_addr + (ord << 3) + sizeof(u32),
			       &field_info);

		/* get each entry length */
		field_len = *((u16 *) & field_info);

		/* get number of entries */
		field_count = *(((u16 *) & field_info) + 1);

		/* abort if no enought memory */
		total_length = field_len * field_count;
		if (total_length > *len) {
			*len = total_length;
			return -EINVAL;
		}

		*len = total_length;
		if (!total_length)
			return 0;

		/* read the ordinal data from the SRAM */
		read_nic_memory(priv->net_dev, addr, total_length, (u8*)val);

		return 0;
	}

	IOLog( ": ordinal %d neither in table 1 nor "
	       "in table 2\n", ord);

	return -EINVAL;
}

int darwin_iwi2100::ipw2100_wait_for_card_state(struct ipw2100_priv *priv, int state)
{
	int i;
	u32 card_state;
	u32 len = sizeof(card_state);
	int err;

	for (i = 0; i <= IPW_CARD_DISABLE_COMPLETE_WAIT * 1000; i += 50) {
		err = ipw2100_get_ordinal(priv, IPW_ORD_CARD_DISABLED,
					  &card_state, &len);
		/*if (err) {
			IOLog("Query of CARD_DISABLED ordinal "
				       "failed.\n");
			//return 0;
		}*/

		/* We'll break out if either the HW state says it is
		 * in the state we want, or if HOST_COMPLETE command
		 * finishes */
		if ((card_state == state) ||
		    ((priv->status & STATUS_ENABLED) ?
		     IPW_HW_STATE_ENABLED : IPW_HW_STATE_DISABLED) == state) {
			if (state == IPW_HW_STATE_ENABLED)
				priv->status |= STATUS_ENABLED;
			else
				priv->status &= ~STATUS_ENABLED;

			return 0;
		}

		udelay(50);
	}

	IOLog("ipw2100_wait_for_card_state to %s state timed out\n",
		       state ? "DISABLED" : "ENABLED");
	return -EIO;
}

void darwin_iwi2100::ipw2100_tx_send_commands(struct ipw2100_priv *priv)
{
	struct list_head *element;
	struct ipw2100_tx_packet *packet;
	struct ipw2100_bd_queue *txq = &priv->tx_queue;
	struct ipw2100_bd *tbd;
	int next = txq->next;

	while (!list_empty(&priv->msg_pend_list)) {
		/* if there isn't enough space in TBD queue, then
		 * don't stuff a new one in.
		 * NOTE: 3 are needed as a command will take one,
		 *       and there is a minimum of 2 that must be
		 *       maintained between the r and w indexes
		 */
		if (txq->available <= 3) {
			IOLog("no room in tx_queue\n");
			break;
		}

		element = priv->msg_pend_list.next;
		list_del(element);
		DEC_STAT(&priv->msg_pend_stat);

		packet = list_entry(element, struct ipw2100_tx_packet, list);

		IOLog("using TBD at virt=%p, phys=%p\n",
			     &txq->drv[txq->next],
			     (void *)(txq->nic + txq->next *
				      sizeof(struct ipw2100_bd)));

		packet->index = txq->next;

		tbd = &txq->drv[txq->next];

		/* initialize TBD */
		tbd->host_addr = packet->info.c_struct.cmd_phys;
		tbd->buf_length = sizeof(struct ipw2100_cmd_header);
		/* not marking number of fragments causes problems
		 * with f/w debug version */
		tbd->num_fragments = 1;
		tbd->status.info.field =
		    IPW_BD_STATUS_TX_FRAME_COMMAND |
		    IPW_BD_STATUS_TX_INTERRUPT_ENABLE;

		/* update TBD queue counters */
		txq->next++;
		txq->next %= txq->entries;
		txq->available--;
		DEC_STAT(&priv->txq_stat);

		list_add_tail(element, &priv->fw_pend_list);
		INC_STAT(&priv->fw_pend_stat);
	}

	if (txq->next != next) {
		/* kick off the DMA by notifying firmware the
		 * write index has moved; make sure TBD stores are sync'd */
		//wmb();
		write_register(priv->net_dev,
			       IPW_MEM_HOST_SHARED_TX_QUEUE_WRITE_INDEX,
			       txq->next);
	}
}

/*
 * ipw2100_tx_send_data
 *
 */
void darwin_iwi2100::ipw2100_tx_send_data(struct ipw2100_priv *priv)
{
	struct list_head *element;
	struct ipw2100_tx_packet *packet;
	struct ipw2100_bd_queue *txq = &priv->tx_queue;
	struct ipw2100_bd *tbd;
	int next = txq->next;
	int i = 0;
	struct ipw2100_data_header *ipw_hdr;
	struct ieee80211_hdr_3addr *hdr;

	while (!list_empty(&priv->tx_pend_list)) {
		/* if there isn't enough space in TBD queue, then
		 * don't stuff a new one in.
		 * NOTE: 4 are needed as a data will take two,
		 *       and there is a minimum of 2 that must be
		 *       maintained between the r and w indexes
		 */
		element = priv->tx_pend_list.next;
		packet = list_entry(element, struct ipw2100_tx_packet, list);

		if (unlikely(1 + packet->info.d_struct.txb->nr_frags >
			     IPW_MAX_BDS)) {
			/* TODO: Support merging buffers if more than
			 * IPW_MAX_BDS are used */
			IOLog("%s: Maximum BD theshold exceeded.  "
				       "Increase fragmentation level.\n",
				       priv->net_dev->name);
		}

		if (txq->available <= 3 + packet->info.d_struct.txb->nr_frags) {
			IOLog("no room in tx_queue\n");
			break;
		}

		list_del(element);
		DEC_STAT(&priv->tx_pend_stat);

		tbd = &txq->drv[txq->next];

		packet->index = txq->next;

		ipw_hdr = packet->info.d_struct.data;
		hdr = (struct ieee80211_hdr_3addr *)mbuf_data(packet->info.d_struct.txb->
		    fragments[0]);

		if (priv->ieee->iw_mode == IW_MODE_INFRA) {
			/* To DS: Addr1 = BSSID, Addr2 = SA,
			   Addr3 = DA */
			memcpy(ipw_hdr->src_addr, hdr->addr2, ETH_ALEN);
			memcpy(ipw_hdr->dst_addr, hdr->addr3, ETH_ALEN);
		} else if (priv->ieee->iw_mode == IW_MODE_ADHOC) {
			/* not From/To DS: Addr1 = DA, Addr2 = SA,
			   Addr3 = BSSID */
			memcpy(ipw_hdr->src_addr, hdr->addr2, ETH_ALEN);
			memcpy(ipw_hdr->dst_addr, hdr->addr1, ETH_ALEN);
		}

		ipw_hdr->host_command_reg = SEND;
		ipw_hdr->host_command_reg1 = 0;

		/* For now we only support host based encryption */
		ipw_hdr->needs_encryption = 0;
		ipw_hdr->encrypted = packet->info.d_struct.txb->encrypted;
		if (packet->info.d_struct.txb->nr_frags > 1)
			ipw_hdr->fragment_size =
			    packet->info.d_struct.txb->frag_size -
			    IEEE80211_3ADDR_LEN;
		else
			ipw_hdr->fragment_size = 0;

		tbd->host_addr = packet->info.d_struct.data_phys;
		tbd->buf_length = sizeof(struct ipw2100_data_header);
		tbd->num_fragments = 1 + packet->info.d_struct.txb->nr_frags;
		tbd->status.info.field =
		    IPW_BD_STATUS_TX_FRAME_802_3 |
		    IPW_BD_STATUS_TX_FRAME_NOT_LAST_FRAGMENT;
		txq->next++;
		txq->next %= txq->entries;

		IOLog("data header tbd TX%d P=%08x L=%d\n",
			     packet->index, tbd->host_addr, tbd->buf_length);
//#ifdef CONFIG_IPW2100_DEBUG
		if (packet->info.d_struct.txb->nr_frags > 1)
			IOLog("fragment Tx: %d frames\n",
				       packet->info.d_struct.txb->nr_frags);
//#endif

		for (i = 0; i < packet->info.d_struct.txb->nr_frags; i++) {
			tbd = &txq->drv[txq->next];
			if (i == packet->info.d_struct.txb->nr_frags - 1)
				tbd->status.info.field =
				    IPW_BD_STATUS_TX_FRAME_802_3 |
				    IPW_BD_STATUS_TX_INTERRUPT_ENABLE;
			else
				tbd->status.info.field =
				    IPW_BD_STATUS_TX_FRAME_802_3 |
				    IPW_BD_STATUS_TX_FRAME_NOT_LAST_FRAGMENT;

			tbd->buf_length = mbuf_len(packet->info.d_struct.txb->
			    fragments[i]) - IEEE80211_3ADDR_LEN;

			/*tbd->host_addr = pci_map_single(priv->pci_dev,
							packet->info.d_struct.
							txb->fragments[i]->
							data +
							IEEE80211_3ADDR_LEN,
							tbd->buf_length,
							PCI_DMA_TODEVICE);*/
			tbd->host_addr=(u32)((UInt8*)mbuf_data(packet->info.d_struct.
							txb->fragments[i])+IEEE80211_3ADDR_LEN);
			IOLog("data frag tbd TX%d P=%08x L=%d\n",
				     txq->next, tbd->host_addr,
				     tbd->buf_length);

			/*pci_dma_sync_single_for_device(priv->pci_dev,
						       tbd->host_addr,
						       tbd->buf_length,
						       PCI_DMA_TODEVICE);*/

			txq->next++;
			txq->next %= txq->entries;
		}

		txq->available -= 1 + packet->info.d_struct.txb->nr_frags;
		SET_STAT(&priv->txq_stat, txq->available);

		list_add_tail(element, &priv->fw_pend_list);
		INC_STAT(&priv->fw_pend_stat);
	}

	if (txq->next != next) {
		/* kick off the DMA by notifying firmware the
		 * write index has moved; make sure TBD stores are sync'd */
		write_register(priv->net_dev,
			       IPW_MEM_HOST_SHARED_TX_QUEUE_WRITE_INDEX,
			       txq->next);
	}
	return;
}

int darwin_iwi2100::ipw2100_hw_send_command(struct ipw2100_priv *priv,
				   struct host_command *cmd)
{
	struct list_head *element;
	struct ipw2100_tx_packet *packet;
	unsigned long flags;
	int err = 0;

	IOLog("Sending %s command (#%d), %d bytes\n",
		     command_types[cmd->host_command], cmd->host_command,
		     cmd->host_command_length);


	//spin_lock_irqsave(&priv->low_lock, flags);

	if (priv->fatal_error) {
		IOLog
		    ("Attempt to send command while hardware in fatal error condition.\n");
		//err = -EIO;
		//goto fail_unlock;
	}

	if (!(priv->status & STATUS_RUNNING)) {
		IOLog
		    ("Attempt to send command while hardware is not running.\n");
		//err = -EIO;
		//goto fail_unlock;
	}

	if (priv->status & STATUS_CMD_ACTIVE) {
		IOLog
		    ("Attempt to send command while another command is pending.\n");
		//err = -EBUSY;
		//goto fail_unlock;
	}

	if (list_empty(&priv->msg_free_list)) {
		IOLog("no available msg buffers\n");
		goto fail_unlock;
	}

	priv->status |= STATUS_CMD_ACTIVE;
	priv->messages_sent++;

	element = priv->msg_free_list.next;

	packet = list_entry(element, struct ipw2100_tx_packet, list);
	packet->jiffy_start = jiffies;

	/* initialize the firmware command packet */
	packet->info.c_struct.cmd->host_command_reg = cmd->host_command;
	packet->info.c_struct.cmd->host_command_reg1 = cmd->host_command1;
	packet->info.c_struct.cmd->host_command_len_reg =
	    cmd->host_command_length;
	packet->info.c_struct.cmd->sequence = cmd->host_command_sequence;

	memcpy(packet->info.c_struct.cmd->host_command_params_reg,
	       cmd->host_command_parameters,
	       sizeof(packet->info.c_struct.cmd->host_command_params_reg));

	list_del(element);
	DEC_STAT(&priv->msg_free_stat);

	list_add_tail(element, &priv->msg_pend_list);
	INC_STAT(&priv->msg_pend_stat);

	ipw2100_tx_send_commands(priv);
	ipw2100_tx_send_data(priv);

	//spin_unlock_irqrestore(&priv->low_lock, flags);

	/*
	 * We must wait for this command to complete before another
	 * command can be sent...  but if we wait more than 3 seconds
	 * then there is a problem.
	 */

	/*err =
	    wait_event_interruptible_timeout(priv->wait_command_queue,
					     !(priv->
					       status & STATUS_CMD_ACTIVE),
					     HOST_COMPLETE_TIMEOUT);*/

	err=0;
	while (priv->status & STATUS_CMD_ACTIVE) 
	{
		err++;
		IODelay(HZ);
		if (err==HZ) break;
	}
	if (err == HZ) {
		IOLog("Command completion failed out \n");//;after %dms.\n",
			      // 1000 * (HOST_COMPLETE_TIMEOUT / HZ));
		priv->fatal_error = IPW2100_ERR_MSG_TIMEOUT;
		priv->status &= ~STATUS_CMD_ACTIVE;
		//schedule_reset(priv);
		//return -EIO;
	}

	if (priv->fatal_error) {
		IOLog( ": %s: firmware fatal error\n",
		       priv->net_dev->name);
		//return -EIO;
	}

	/* !!!!! HACK TEST !!!!!
	 * When lots of debug trace statements are enabled, the driver
	 * doesn't seem to have as many firmware restart cycles...
	 *
	 * As a test, we're sticking in a 1/100s delay here */
	//set_current_state(TASK_UNINTERRUPTIBLE);
	//schedule_timeout(msecs_to_jiffies(10));

	return 0;

      fail_unlock:
	//spin_unlock_irqrestore(&priv->low_lock, flags);

	return err;
}

void darwin_iwi2100::ipw2100_hang_check(struct ipw2100_priv *priv)
{
	unsigned long flags;
	u32 rtc = 0xa5a5a5a5;
	u32 len = sizeof(rtc);
	int restart = 0;

	//spin_lock_irqsave(&priv->low_lock, flags);

	if (priv->fatal_error != 0) {
		/* If fatal_error is set then we need to restart */
		IOLog("%s: Hardware fatal error detected.\n",
			       priv->net_dev->name);

		restart = 1;
	} else if (ipw2100_get_ordinal(priv, IPW_ORD_RTC_TIME, &rtc, &len) ||
		   (rtc == priv->last_rtc)) {
		/* Check if firmware is hung */
		IOLog("%s: Firmware RTC stalled.\n",
			       priv->net_dev->name);

		restart = 1;
	}

	if (restart) {
		/* Kill timer */
		priv->stop_hang_check = 1;
		priv->hangs++;

		/* Restart the NIC */
		schedule_reset(priv);
	}

	priv->last_rtc = rtc;

	if (!priv->stop_hang_check)
	queue_te(7,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_hang_check),priv,1,true);
	//	queue_delayed_work(priv->workqueue, &priv->hang_check, HZ / 2);

	//spin_unlock_irqrestore(&priv->low_lock, flags);
}

int darwin_iwi2100::ipw2100_enable_adapter(struct ipw2100_priv *priv)
{
	struct host_command cmd;
		cmd.host_command = HOST_COMPLETE;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = 0;
	int err = 0;

	IOLog("HOST_COMPLETE\n");

	if (priv->status & STATUS_ENABLED)
		return 0;


	if (rf_kill_active(priv)) {
		IOLog("Command aborted due to RF kill active.\n");
		goto fail_up;
	}

	err = ipw2100_hw_send_command(priv, &cmd);
	if (err) {
		IOLog("Failed to send HOST_COMPLETE command\n");
		goto fail_up;
	}

	err = ipw2100_wait_for_card_state(priv, IPW_HW_STATE_ENABLED);
	if (err) {
		IOLog("%s: card not responding to init command.\n",
			       priv->net_dev->name);
		goto fail_up;
	}

	if (priv->stop_hang_check) {
		priv->stop_hang_check = 0;
		queue_te(7,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_hang_check),priv,1,true);
		//queue_delayed_work(priv->workqueue, &priv->hang_check, HZ / 2);
	}

      fail_up:
	return err;
}

IOOptionBits darwin_iwi2100::getState( void ) const
{
	IOOptionBits r=super::getState();
	IOLog("getState = %x\n",r);
	return r;
}

bool darwin_iwi2100::start(IOService *provider)
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
			this, (IOInterruptEventAction) &darwin_iwi2100::interruptOccurred,
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
		
		fTransmitQueue = createOutputQueue();
		if (fTransmitQueue == NULL)
		{
			IWI_ERR("ERR: getOutputQueue()\n");
			break;
		}
		fTransmitQueue->setCapacity(1024);
		
		//resetDevice((UInt16 *)memBase); //iwi2200 code to fix
		ipw2100_sw_reset(1);
		priv->status &= ~STATUS_POWERED; //keep power on!!
		
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
		queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_scan),NULL,NULL,false);
		queue_te(1,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_adapter_restart),NULL,NULL,false);
		queue_te(2,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_led_link_on),NULL,NULL,false);
		queue_te(3,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_rf_kill),NULL,NULL,false);
		queue_te(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_scan_check),NULL,NULL,false);
		queue_te(5,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_associate),NULL,NULL,false);
		queue_te(6,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_gather_stats),NULL,NULL,false);
		queue_te(7,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_hang_check),NULL,NULL,false);
		
		
		pl=1;
		return true;			// end start successfully
	} while (false);
		
	//stop(provider);
	free();
	return false;			// end start insuccessfully
}

IOReturn darwin_iwi2100::selectMedium(const IONetworkMedium * medium)
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

bool darwin_iwi2100::addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name) {	
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

IOOutputQueue * darwin_iwi2100::createOutputQueue( void )
{
	// An IOGatedOutputQueue will serialize all calls to the driver's
    // outputPacket() function with its work loop. This essentially
    // serializes all access to the driver and the hardware through
    // the driver's work loop, which simplifies the driver but also
    // carries a small performance cost (relatively for 10/100 Mb).

    return IOGatedOutputQueue::withTarget( this, getWorkLoop() );
}

bool darwin_iwi2100::createWorkLoop( void )
{
    fWorkLoop = IOWorkLoop::workLoop();
	
    return ( fWorkLoop != 0 );
}

IOWorkLoop * darwin_iwi2100::getWorkLoop( void ) const
{
    // Override IOService::getWorkLoop() method to return the work loop
    // we allocated in createWorkLoop().

	return fWorkLoop;
}

const OSString * darwin_iwi2100::newVendorString( void ) const
{
    return OSString::withCString("Intel");
}

const OSString * darwin_iwi2100::newModelString( void ) const
{
    const char * model = "2100";
    return OSString::withCString(model);
}

int darwin_iwi2100::ipw2100_stop_nic()
{
	int rc = 0;

	/* stop */
	ipw2100_write32(IPW_RESET_REG, IPW_RESET_REG_STOP_MASTER);

	rc = ipw2100_poll_bit(IPW_RESET_REG,
			  IPW_RESET_REG_MASTER_DISABLED, 500);
	if (rc < 0) {
		IOLog("wait for reg master disabled failed after 500ms\n");
		return rc;
	}

	ipw2100_set_bit(IPW_RESET_REG, CBD_RESET_REG_PRINCETON_RESET);

	return rc;
}

int darwin_iwi2100::ipw2100_init_nic()
{
	int rc;

	/* reset */
	/*prvHwInitNic */
	/* set "initialization complete" bit to move adapter to D0 state */
	ipw2100_set_bit(IPW_GP_CNTRL_RW, IPW_GP_CNTRL_BIT_INIT_DONE);

	/* low-level PLL activation */
	ipw2100_write32(IPW_READ_INT_REGISTER,
		    IPW_BIT_INT_HOST_SRAM_READ_INT_REGISTER);

	/* wait for clock stabilization */
	rc = ipw2100_poll_bit(IPW_GP_CNTRL_RW,
			  IPW_GP_CNTRL_BIT_CLOCK_READY, 250);
	if (rc < 0)
		IOLog("FAILED wait for clock stablization\n");

	/* assert SW reset */
	ipw2100_set_bit(IPW_RESET_REG, IPW_RESET_REG_SW_RESET);

	udelay(10);

	/* set "initialization complete" bit to move adapter to D0 state */
	ipw2100_set_bit(IPW_GP_CNTRL_RW, IPW_GP_CNTRL_BIT_INIT_DONE);

	return 0;
}

int darwin_iwi2100::ipw2100_reset_nic(struct ipw2100_priv *priv)
{
	int rc = 0;
	unsigned long flags;


	rc = ipw2100_init_nic();

	/* Clear the 'host command active' bit... */
	priv->status &= ~STATUS_HCMD_ACTIVE;
	//wake_up_interruptible(&priv->wait_command_queue);
	priv->status &= ~(STATUS_SCANNING | STATUS_SCAN_ABORTING);
	//wake_up_interruptible(&priv->wait_state);

	return rc;
}


void darwin_iwi2100::ipw2100_start_nic()
{

	/* prvHwStartNic  release ARC */
	ipw2100_clear_bit(IPW_RESET_REG,
		      IPW_RESET_REG_MASTER_DISABLED |
		      IPW_RESET_REG_STOP_MASTER |
		      CBD_RESET_REG_PRINCETON_RESET);

	/* enable power management */
	ipw2100_set_bit(IPW_GP_CNTRL_RW,
		    IPW_GP_CNTRL_BIT_HOST_ALLOWS_STANDBY);

}

inline void darwin_iwi2100::ipw2100_enable_interrupts(struct ipw2100_priv *priv)
{
	if (priv->status & STATUS_INT_ENABLED)
		return;
	priv->status |= STATUS_INT_ENABLED;
	ipw2100_write32(IPW_INTA_MASK_R, IPW_INTA_MASK_ALL);
}

int darwin_iwi2100::ipw2100_load(struct ipw2100_priv *priv)
{
	
}

int darwin_iwi2100::rf_kill_active(struct ipw2100_priv *priv)
{
	unsigned short value = 0;
	u32 reg = 0;
	int i;

	if (!(priv->hw_features & HW_FEATURE_RFKILL)) {
		priv->status &= ~STATUS_RF_KILL_HW;
		return 0;
	}

	for (i = 0; i < MAX_RF_KILL_CHECKS; i++) {
		udelay(RF_KILL_CHECK_DELAY);
		read_register(priv->net_dev, IPW_REG_GPIO, &reg);
		value = (value << 1) | ((reg & IPW_BIT_GPIO_RF_KILL) ? 0 : 1);
	}

	if (value == 0)
		priv->status |= STATUS_RF_KILL_HW;
	else
		priv->status &= ~STATUS_RF_KILL_HW;

	return (value == 0);
}

void darwin_iwi2100::ipw2100_adapter_restart(ipw2100_priv *adapter)
{
	
}

void darwin_iwi2100::ipw2100_remove_current_network(struct ipw2100_priv *priv)
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

void darwin_iwi2100::schedule_reset(struct ipw2100_priv *priv)
{
/*	unsigned long now = get_seconds();


	if (priv->reset_backoff &&
	    (now - priv->last_reset > priv->reset_backoff))
		priv->reset_backoff = 0;

	priv->last_reset = get_seconds();

	if (!(priv->status & STATUS_RESET_PENDING)) {
		IOLog("%s: Scheduling firmware restart (%ds).\n",
			       priv->net_dev->name, priv->reset_backoff);
		netif_carrier_off(priv->net_dev);
		netif_stop_queue(priv->net_dev);
		priv->status |= STATUS_RESET_PENDING;
		if (priv->reset_backoff)
			queue_delayed_work(priv->workqueue, &priv->reset_work,
					   priv->reset_backoff * HZ);
		else
			queue_delayed_work(priv->workqueue, &priv->reset_work,
					   0);

		if (priv->reset_backoff < MAX_RESET_BACKOFF)
			priv->reset_backoff++;

		wake_up_interruptible(&priv->wait_command_queue);
	} else
		IOLog("%s: Firmware restart already in progress.\n",
			       priv->net_dev->name);
*/
}

void darwin_iwi2100::ipw2100_rf_kill(ipw2100_priv *priv)
{
	unsigned long flags;

	//spin_lock_irqsave(&priv->low_lock, flags);

	if (rf_kill_active(priv)) {
		IOLog("RF Kill active, rescheduling GPIO check\n");
		//if (!priv->stop_rf_kill)
		//	queue_delayed_work(priv->workqueue, &priv->rf_kill, HZ);
		goto exit_unlock;
	}

	/* RF Kill is now disabled, so bring the device back up */

	if (!(priv->status & STATUS_RF_KILL_MASK)) {
		IOLog("HW RF Kill no longer active, restarting "
				  "device\n");
		schedule_reset(priv);
	} else
		IOLog("HW RF Kill deactivated.  SW RF Kill still "
				  "enabled\n");

      exit_unlock:
	//spin_unlock_irqrestore(&priv->low_lock, flags);
	return;

}

int darwin_iwi2100::ipw2100_set_geo(struct ieee80211_device *ieee,
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

IOReturn darwin_iwi2100::setPowerState ( unsigned long powerStateOrdinal, IOService* whatDevice )
{
	IOLog("setPowerState to %d\n",powerStateOrdinal);
	power=powerStateOrdinal;
	return super::setPowerState(powerStateOrdinal,whatDevice);
}

void darwin_iwi2100::ipw2100_init_ordinals(struct ipw2100_priv *priv)
{

}

int darwin_iwi2100::ipw2100_grab_restricted_access(struct ipw2100_priv *priv)
{
	
}

void darwin_iwi2100::_ipw_write_restricted(struct ipw2100_priv *priv,
					 u32 reg, u32 value)
{
//      _ipw_grab_restricted_access(priv);
	_ipw_write32(memBase, reg, value);
//      _ipw_release_restricted_access(priv);
}

void darwin_iwi2100::_ipw_write_restricted_reg(struct ipw2100_priv *priv,
					     u32 addr, u32 val)
{

}

int darwin_iwi2100::ipw2100_copy_ucode_images(struct ipw2100_priv *priv,
				 u8 * image_code,
				 size_t image_len_code,
				 u8 * image_data, size_t image_len_data)
{
	
}

void darwin_iwi2100::_ipw_release_restricted_access(struct ipw2100_priv
						  *priv)
{

}

void darwin_iwi2100::ipw2100_write_restricted_reg_buffer(struct ipw2100_priv
						   *priv, u32 reg,
						   u32 len, u8 * values)
{
	
}


int darwin_iwi2100::ipw2100_download_ucode_base(struct ipw2100_priv *priv, u8 * image, u32 len)
{

}

u32 darwin_iwi2100::_ipw_read_restricted_reg(struct ipw2100_priv *priv, u32 reg)
{
	
}


int darwin_iwi2100::attach_buffer_to_tfd_frame(struct tfd_frame *tfd,
				      dma_addr_t addr, u16 len)
{
	
}

void darwin_iwi2100::ipw2100_write_buffer_restricted(struct ipw2100_priv *priv,
					u32 reg, u32 len, u32 * values)
{
	u32 count = sizeof(u32);
	if ((priv != NULL) && (values != NULL)) {
		for (; 0 < len; len -= count, reg += count, values++)
			_ipw_write_restricted(priv, reg, *values);
	}
}

int darwin_iwi2100::ipw2100_download_ucode(struct ipw2100_priv *priv,
			      struct fw_image_desc *desc,
			      u32 mem_size, dma_addr_t dst_addr)
{
	
}

int darwin_iwi2100::ipw2100_poll_restricted_bit(struct ipw2100_priv *priv,
					  u32 addr, u32 mask, int timeout)
{
	
}

int darwin_iwi2100::ipw2100_load_ucode(struct ipw2100_priv *priv)
{
	
}

void darwin_iwi2100::ipw2100_clear_stations_table(struct ipw2100_priv *priv)
{

	
}

void darwin_iwi2100::ipw2100_nic_start(struct ipw2100_priv *priv)
{
	
}

int darwin_iwi2100::ipw2100_query_eeprom(struct ipw2100_priv *priv, u32 offset,
			    u32 len, u8 * buf)
{
	
}

int darwin_iwi2100::ipw2100_card_show_info(struct ipw2100_priv *priv)
{
	
}

#define PCI_LINK_CTRL      0x0F0

int darwin_iwi2100::ipw2100_power_init_handle(struct ipw2100_priv *priv)
{
	
}

void darwin_iwi2100::__ipw_set_bits_restricted_reg(u32 line, struct ipw2100_priv
						 *priv, u32 reg, u32 mask)
{
	
}

int darwin_iwi2100::ipw2100_eeprom_init_sram(struct ipw2100_priv *priv)
{
	
}

int darwin_iwi2100::ipw2100_rate_scale_clear_window(struct ipw2100_rate_scale_data
				       *window)
{

}

int darwin_iwi2100::ipw2100_rate_scale_init_handle(struct ipw2100_priv *priv, s32 window_size)
{
	
}

int darwin_iwi2100::ipw2100_nic_set_pwr_src(struct ipw2100_priv *priv, int pwr_max)
{
	
}

void darwin_iwi2100::__ipw_set_bits_mask_restricted_reg(u32 line, struct ipw2100_priv
						      *priv, u32 reg,
						      u32 bits, u32 mask)
{

}

int darwin_iwi2100::ipw2100_nic_init(struct ipw2100_priv *priv)
{
	
}

int darwin_iwi2100::ipw2100_rf_eeprom_ready(struct ipw2100_priv *priv)
{
	
}

int darwin_iwi2100::ipw2100_verify_ucode(struct ipw2100_priv *priv)
{
	
}

void darwin_iwi2100::ipw2100_reset_fatalerror(struct ipw2100_priv *priv)
{
	if (!priv->fatal_error)
		return;

	priv->fatal_errors[priv->fatal_index++] = priv->fatal_error;
	priv->fatal_index %= IPW2100_ERROR_QUEUE;
	priv->fatal_error = 0;
}

void darwin_iwi2100::ipw2100_hw_set_gpio(struct ipw2100_priv *priv)
{
	u32 reg = 0;
	/*
	 * Set GPIO 3 writable by FW; GPIO 1 writable
	 * by driver and enable clock
	 */
	reg = (IPW_BIT_GPIO_GPIO3_MASK | IPW_BIT_GPIO_GPIO1_ENABLE |
	       IPW_BIT_GPIO_LED_OFF);
	write_register(priv->net_dev, IPW_REG_GPIO, reg);
}

int darwin_iwi2100::ipw2100_power_cycle_adapter(struct ipw2100_priv *priv)
{
	u32 reg;
	int i;

	IOLog("Power cycling the hardware.\n");

	ipw2100_hw_set_gpio(priv);

	/* Step 1. Stop Master Assert */
	write_register(priv->net_dev, IPW_REG_RESET_REG,
		       IPW_AUX_HOST_RESET_REG_STOP_MASTER);

	/* Step 2. Wait for stop Master Assert
	 *         (not more then 50us, otherwise ret error */
	i = 5;
	do {
		udelay(IPW_WAIT_RESET_MASTER_ASSERT_COMPLETE_DELAY);
		read_register(priv->net_dev, IPW_REG_RESET_REG, &reg);

		if (reg & IPW_AUX_HOST_RESET_REG_MASTER_DISABLED)
			break;
	} while (i--);

	priv->status &= ~STATUS_RESET_PENDING;

	if (!i) {
		IOLog
		    ("exit - waited too long for master assert stop\n");
		//return -EIO;
	}

	write_register(priv->net_dev, IPW_REG_RESET_REG,
		       IPW_AUX_HOST_RESET_REG_SW_RESET);

	/* Reset any fatal_error conditions */
	ipw2100_reset_fatalerror(priv);

	/* At this point, the adapter is now stopped and disabled */
	priv->status &= ~(STATUS_RUNNING | STATUS_ASSOCIATING |
			  STATUS_ASSOCIATED | STATUS_ENABLED);

	return 0;
}

int darwin_iwi2100::sw_reset_and_clock(struct ipw2100_priv *priv)
{
	int i;
	u32 r;

	// assert s/w reset
	write_register(priv->net_dev, IPW_REG_RESET_REG,
		       IPW_AUX_HOST_RESET_REG_SW_RESET);

	// wait for clock stabilization
	for (i = 0; i < 1000; i++) {
		udelay(IPW_WAIT_RESET_ARC_COMPLETE_DELAY);
		// check clock ready bit
		read_register(priv->net_dev, IPW_REG_RESET_REG, &r);
		if (r & IPW_AUX_HOST_RESET_REG_PRINCETON_RESET)
			break;
	}

	if (i == 1000)
		return -EIO;	// TODO: better error value

	/* set "initialization complete" bit to move adapter to
	 * D0 state */
	write_register(priv->net_dev, IPW_REG_GP_CNTRL,
		       IPW_AUX_HOST_GP_CNTRL_BIT_INIT_DONE);

	/* wait for clock stabilization */
	for (i = 0; i < 10000; i++) {
		udelay(IPW_WAIT_CLOCK_STABILIZATION_DELAY * 4);

		/* check clock ready bit */
		read_register(priv->net_dev, IPW_REG_GP_CNTRL, &r);
		if (r & IPW_AUX_HOST_GP_CNTRL_BIT_CLOCK_READY)
			break;
	}

	if (i == 10000)
		return -EIO;	/* TODO: better error value */

	/* set D0 standby bit */
	read_register(priv->net_dev, IPW_REG_GP_CNTRL, &r);
	write_register(priv->net_dev, IPW_REG_GP_CNTRL,
		       r | IPW_AUX_HOST_GP_CNTRL_BIT_HOST_ALLOWS_STANDBY);

	return 0;
}

int darwin_iwi2100::ipw2100_verify(struct ipw2100_priv *priv)
{
	u32 data1, data2;
	u32 address;

	u32 val1 = 0x76543210;
	u32 val2 = 0xFEDCBA98;

	/* Domain 0 check - all values should be DOA_DEBUG */
	for (address = IPW_REG_DOA_DEBUG_AREA_START;
	     address < IPW_REG_DOA_DEBUG_AREA_END; address += sizeof(u32)) {
		read_register(priv->net_dev, address, &data1);
		if (data1 != IPW_DATA_DOA_DEBUG_VALUE)
			return -EIO;
	}

	/* Domain 1 check - use arbitrary read/write compare  */
	for (address = 0; address < 5; address++) {
		/* The memory area is not used now */
		write_register(priv->net_dev, IPW_REG_DOMAIN_1_OFFSET + 0x32,
			       val1);
		write_register(priv->net_dev, IPW_REG_DOMAIN_1_OFFSET + 0x36,
			       val2);
		read_register(priv->net_dev, IPW_REG_DOMAIN_1_OFFSET + 0x32,
			      &data1);
		read_register(priv->net_dev, IPW_REG_DOMAIN_1_OFFSET + 0x36,
			      &data2);
		if (val1 == data1 && val2 == data2)
			return 0;
	}

	return -EIO;
}

int darwin_iwi2100::ipw2100_ucode_download(struct ipw2100_priv *priv,
				  struct ipw2100_fw *fw)
{
	struct net_device *dev = priv->net_dev;
	const unsigned char *microcode_data = (const unsigned char*)fw->uc.data;
	unsigned int microcode_data_left = fw->uc.size;
	void __iomem *reg = (void __iomem *)memBase;//dev->base_addr;

	struct symbol_alive_response response;
	int i, j;
	u8 data;

	/* Symbol control */
	write_nic_word(dev, IPW2100_CONTROL_REG, 0x703);
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	write_nic_word(dev, IPW2100_CONTROL_REG, 0x707);
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	/* HW config */
	write_nic_byte(dev, 0x210014, 0x72);	/* fifo width =16 */
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	write_nic_byte(dev, 0x210014, 0x72);	/* fifo width =16 */
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	/* EN_CS_ACCESS bit to reset control store pointer */
	write_nic_byte(dev, 0x210000, 0x40);
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	write_nic_byte(dev, 0x210000, 0x0);
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	write_nic_byte(dev, 0x210000, 0x40);
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	/* copy microcode from buffer into Symbol */

	while (microcode_data_left > 0) {
		write_nic_byte(dev, 0x210010, *microcode_data++);
		write_nic_byte(dev, 0x210010, *microcode_data++);
		microcode_data_left -= 2;
	}

	/* EN_CS_ACCESS bit to reset the control store pointer */
	write_nic_byte(dev, 0x210000, 0x0);
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	/* Enable System (Reg 0)
	 * first enable causes garbage in RX FIFO */
	write_nic_byte(dev, 0x210000, 0x0);
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	write_nic_byte(dev, 0x210000, 0x80);
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	/* Reset External Baseband Reg */
	write_nic_word(dev, IPW2100_CONTROL_REG, 0x703);
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	write_nic_word(dev, IPW2100_CONTROL_REG, 0x707);
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	/* HW Config (Reg 5) */
	write_nic_byte(dev, 0x210014, 0x72);	// fifo width =16
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	write_nic_byte(dev, 0x210014, 0x72);	// fifo width =16
	//readl(reg);
	OSReadLittleInt32(memBase,0);

	/* Enable System (Reg 0)
	 * second enable should be OK */
	write_nic_byte(dev, 0x210000, 0x00);	// clear enable system
	//readl(reg);
	OSReadLittleInt32(memBase,0);
	write_nic_byte(dev, 0x210000, 0x80);	// set enable system

	/* check Symbol is enabled - upped this from 5 as it wasn't always
	 * catching the update */
	for (i = 0; i < 10; i++) {
		udelay(10);

		/* check Dino is enabled bit */
		read_nic_byte(dev, 0x210000, &data);
		if (data & 0x1)
			break;
	}

	if (i == 10) {
		IOLog( ": %s: Error initializing Symbol\n",
		       dev->name);
		return -EIO;
	}

	/* Get Symbol alive response */
	for (i = 0; i < 30; i++) {
		/* Read alive response structure */
		for (j = 0;
		     j < (sizeof(struct symbol_alive_response) >> 1); j++)
			read_nic_word(dev, 0x210004, ((u16 *) & response) + j);

		if ((response.cmd_id == 1) && (response.ucode_valid == 0x1))
			break;
		udelay(10);
	}

	if (i == 30) {
		IOLog( 
		       ": %s: No response from Symbol - hw not alive\n",
		       dev->name);
		//printk_buf(IPW_DL_ERROR, (u8 *) & response, sizeof(response));
		return -EIO;
	}

	return 0;
}

int darwin_iwi2100::ipw2100_fw_download(struct ipw2100_priv *priv, struct ipw2100_fw *fw)
{
	/* firmware is constructed of N contiguous entries, each entry is
	 * structured as:
	 *
	 * offset    sie         desc
	 * 0         4           address to write to
	 * 4         2           length of data run
	 * 6         length      data
	 */
	unsigned int addr;
	unsigned short len;

	const unsigned char *firmware_data = (const unsigned char*)fw->fw.data;
	unsigned int firmware_data_left = fw->fw.size;

	while (firmware_data_left > 0) {
		addr = *(u32 *) (firmware_data);
		firmware_data += 4;
		firmware_data_left -= 4;

		len = *(u16 *) (firmware_data);
		firmware_data += 2;
		firmware_data_left -= 2;

		if (len > 32) {
			IOLog( ": "
			       "Invalid firmware run-length of %d bytes\n",
			       len);
			return -EINVAL;
		}

		write_nic_memory(priv->net_dev, addr, len, firmware_data);
		firmware_data += len;
		firmware_data_left -= len;
	}

	return 0;
}

int darwin_iwi2100::ipw2100_download_firmware(struct ipw2100_priv *priv)
{
	u32 address;
	int err;
	struct ipw2100_fw *ipw2100_firmware, ff0;
	struct firmware w2;
	
	
	ipw2100_firmware=&ff0;
	ipw2100_firmware->fw_entry=&w2;

	if (priv->fatal_error) {
		IOLog("%s: ipw2100_download_firmware called after "
				"fatal error %d.  Interface must be brought down.\n",
				priv->net_dev->name, priv->fatal_error);
		return -EINVAL;
	}
	switch (priv->ieee->iw_mode) {
	case IW_MODE_ADHOC:
		(void*)ipw2100_firmware->fw_entry->data=(void*)iwi_ibss;
		break;
	case IW_MODE_MONITOR:
		(void*)ipw2100_firmware->fw_entry->data=(void*)iwi_mon;
		break;
	case IW_MODE_INFRA:
	default:
		(void*)ipw2100_firmware->fw_entry->data=(void*)iwi_bss;
		break;
	}
	struct ipw2100_fw_header *h =
	    (struct ipw2100_fw_header *)ipw2100_firmware->fw_entry->data;

	if (IPW2100_FW_MAJOR(h->version) != IPW2100_FW_MAJOR_VERSION) {
		IOLog(  ": Firmware image not compatible "
		       "(detected version id of %d). "
		       "See Documentation/networking/README.ipw2100\n",
		       h->version);
		return 1;
	}

	ipw2100_firmware->version = h->version;
	ipw2100_firmware->fw.data = ipw2100_firmware->fw_entry->data + sizeof(struct ipw2100_fw_header);
	ipw2100_firmware->fw.size = h->fw_size;
	ipw2100_firmware->uc.data = (UInt8*)ipw2100_firmware->fw.data + h->fw_size;
	ipw2100_firmware->uc.size = h->uc_size;

	IOLog("fw version %d s: %d uc s:%d",ipw2100_firmware->version,ipw2100_firmware->fw.size,ipw2100_firmware->uc.size );
	/*err = ipw2100_get_firmware(priv, &ipw2100_firmware);
	if (err) {
		IOLog("%s: ipw2100_get_firmware failed: %d\n",
				priv->net_dev->name, err);
		priv->fatal_error = IPW2100_ERR_FW_LOAD;
		goto fail;
	}*/
	priv->firmware_version = ipw2100_firmware->version;

	/* s/w reset and clock stabilization */
	err = sw_reset_and_clock(priv);
	if (err) {
		IOLog("%s: sw_reset_and_clock failed: %d\n",
				priv->net_dev->name, err);
		//goto fail;
	}
	err = ipw2100_verify(priv);
	if (err) {
		IOLog("%s: ipw2100_verify failed: %d\n",
				priv->net_dev->name, err);
		//goto fail;
	}

	/* Hold ARC */
	write_nic_dword(priv->net_dev,
			IPW_INTERNAL_REGISTER_HALT_AND_RESET, 0x80000000);

	/* allow ARC to run */
	write_register(priv->net_dev, IPW_REG_RESET_REG, 0);

	/* load microcode */
	err = ipw2100_ucode_download(priv, ipw2100_firmware);
	if (err) {
		IOLog(": %s: Error loading microcode: %d\n",
		       priv->net_dev->name, err);
		//goto fail;
	}

	/* release ARC */
	write_nic_dword(priv->net_dev,
			IPW_INTERNAL_REGISTER_HALT_AND_RESET, 0x00000000);

	/* s/w reset and clock stabilization (again!!!) */
	err = sw_reset_and_clock(priv);
	if (err) {
		IOLog(
		       ": %s: sw_reset_and_clock failed: %d\n",
		       priv->net_dev->name, err);
		//goto fail;
	}

	/* load f/w */
	err = ipw2100_fw_download(priv, ipw2100_firmware);
	if (err) {
		IOLog("%s: Error loading firmware: %d\n",
				priv->net_dev->name, err);
		//goto fail;
	}


	/* zero out Domain 1 area indirectly (Si requirement) */
	for (address = IPW_HOST_FW_SHARED_AREA0;
	     address < IPW_HOST_FW_SHARED_AREA0_END; address += 4)
		write_nic_dword(priv->net_dev, address, 0);
	for (address = IPW_HOST_FW_SHARED_AREA1;
	     address < IPW_HOST_FW_SHARED_AREA1_END; address += 4)
		write_nic_dword(priv->net_dev, address, 0);
	for (address = IPW_HOST_FW_SHARED_AREA2;
	     address < IPW_HOST_FW_SHARED_AREA2_END; address += 4)
		write_nic_dword(priv->net_dev, address, 0);
	for (address = IPW_HOST_FW_SHARED_AREA3;
	     address < IPW_HOST_FW_SHARED_AREA3_END; address += 4)
		write_nic_dword(priv->net_dev, address, 0);
	for (address = IPW_HOST_FW_INTERRUPT_AREA;
	     address < IPW_HOST_FW_INTERRUPT_AREA_END; address += 4)
		write_nic_dword(priv->net_dev, address, 0);

	return 0;

      fail:
	//ipw2100_release_firmware(priv, &ipw2100_firmware);
	return err;
}

int darwin_iwi2100::ipw2100_start_adapter(struct ipw2100_priv *priv)
{
	int i;
	u32 inta, inta_mask, gpio;


	if (priv->status & STATUS_RUNNING)
		return 0;

	/*
	 * Initialize the hw - drive adapter to DO state by setting
	 * init_done bit. Wait for clk_ready bit and Download
	 * fw & dino ucode
	 */
	if (ipw2100_download_firmware(priv)) {
		IOLog(
		       ": %s: Failed to power on the adapter.\n",
		       priv->net_dev->name);
		return -EIO;
	}

	/* Clear the Tx, Rx and Msg queues and the r/w indexes
	 * in the firmware RBD and TBD ring queue */
	ipw2100_queues_initialize(priv);

	ipw2100_hw_set_gpio(priv);

	/* TODO -- Look at disabling interrupts here to make sure none
	 * get fired during FW initialization */

	/* Release ARC - clear reset bit */
	write_register(priv->net_dev, IPW_REG_RESET_REG, 0);

	/* wait for f/w intialization complete */
	IOLog("Waiting for f/w initialization to complete...\n");
	i = 5000;
	do {
		//set_current_state(TASK_UNINTERRUPTIBLE);
		//schedule_timeout(msecs_to_jiffies(40));
		IODelay(40);
		/* Todo... wait for sync command ... */

		read_register(priv->net_dev, IPW_REG_INTA, &inta);

		/* check "init done" bit */
		if (inta & IPW2100_INTA_FW_INIT_DONE) {
			/* reset "init done" bit */
			write_register(priv->net_dev, IPW_REG_INTA,
				       IPW2100_INTA_FW_INIT_DONE);
			break;
		}

		/* check error conditions : we check these after the firmware
		 * check so that if there is an error, the interrupt handler
		 * will see it and the adapter will be reset */
		if (inta &
		    (IPW2100_INTA_FATAL_ERROR | IPW2100_INTA_PARITY_ERROR)) {
			/* clear error conditions */
			write_register(priv->net_dev, IPW_REG_INTA,
				       IPW2100_INTA_FATAL_ERROR |
				       IPW2100_INTA_PARITY_ERROR);
		}
	} while (i--);

	/* Clear out any pending INTAs since we aren't supposed to have
	 * interrupts enabled at this point... */
	read_register(priv->net_dev, IPW_REG_INTA, &inta);
	read_register(priv->net_dev, IPW_REG_INTA_MASK, &inta_mask);
	inta &= IPW_INTERRUPT_MASK;
	/* Clear out any pending interrupts */
	if (inta & inta_mask)
		write_register(priv->net_dev, IPW_REG_INTA, inta);

	IOLog("f/w initialization complete: %s\n",
		     i ? "SUCCESS" : "FAILED");

	if (!i) {
		IOLog(
		       ": %s: Firmware did not initialize.\n",
		       priv->net_dev->name);
		//return -EIO;
	}

	/* allow firmware to write to GPIO1 & GPIO3 */
	read_register(priv->net_dev, IPW_REG_GPIO, &gpio);

	gpio |= (IPW_BIT_GPIO_GPIO1_MASK | IPW_BIT_GPIO_GPIO3_MASK);

	write_register(priv->net_dev, IPW_REG_GPIO, gpio);

	/* Ready to receive commands */
	priv->status |= STATUS_RUNNING;

	/* The adapter has been reset; we are not associated */
	priv->status &= ~(STATUS_ASSOCIATING | STATUS_ASSOCIATED);


	return 0;
}

int darwin_iwi2100::ipw2100_get_hw_features(struct ipw2100_priv *priv)
{
	u32 addr, len;
	u32 val;

	/*
	 * EEPROM_SRAM_DB_START_ADDRESS using ordinal in ordinal table 1
	 */
	len = sizeof(addr);
	if (ipw2100_get_ordinal
	    (priv, IPW_ORD_EEPROM_SRAM_DB_BLOCK_START_ADDRESS, &addr, &len)) {
		IOLog("failed querying ordinals at line %d\n",
			       __LINE__);
		return -EIO;
	}

	IOLog("EEPROM address: %08X\n", addr);
					   
	/*
	 * EEPROM version is the byte at offset 0xfd in firmware
	 * We read 4 bytes, then shift out the byte we actually want */
	read_nic_dword(priv->net_dev, addr + 0xFC, &val);
	priv->eeprom_version = (val >> 24) & 0xFF;
	IOLog("EEPROM version: %d\n", priv->eeprom_version);

	/*
	 *  HW RF Kill enable is bit 0 in byte at offset 0x21 in firmware
	 *
	 *  notice that the EEPROM bit is reverse polarity, i.e.
	 *     bit = 0  signifies HW RF kill switch is supported
	 *     bit = 1  signifies HW RF kill switch is NOT supported
	 */
	read_nic_dword(priv->net_dev, addr + 0x20, &val);
	if (!((val >> 24) & 0x01))
		priv->hw_features |= HW_FEATURE_RFKILL;

	IOLog("HW RF Kill: %ssupported.\n",
		       (priv->hw_features & HW_FEATURE_RFKILL) ? "" : "not ");

	return 0;
}

int darwin_iwi2100::ipw2100_set_ordinal(struct ipw2100_priv *priv, u32 ord, u32 * val,
			       u32 * len)
{
	struct ipw2100_ordinals *ordinals = &priv->ordinals;
	u32 addr;

	if (IS_ORDINAL_TABLE_ONE(ordinals, ord)) {
		if (*len != IPW_ORD_TAB_1_ENTRY_SIZE) {
			*len = IPW_ORD_TAB_1_ENTRY_SIZE;
			IOLog("wrong size\n");
			return -EINVAL;
		}

		read_nic_dword(priv->net_dev,
			       ordinals->table1_addr + (ord << 2), &addr);

		write_nic_dword(priv->net_dev, addr, *val);

		*len = IPW_ORD_TAB_1_ENTRY_SIZE;

		return 0;
	}

	IOLog("wrong table\n");
	if (IS_ORDINAL_TABLE_TWO(ordinals, ord))
		return -EINVAL;

	return -EINVAL;
}

int darwin_iwi2100::ipw_set_geo(struct ieee80211_device *ieee,
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

int darwin_iwi2100::ipw2100_adapter_setup(struct ipw2100_priv *priv)
{
	int err;
	int batch_mode = 1;
	u8 *bssid;
/*

	err = ipw2100_disable_adapter(priv);
	if (err)
		return err;
#ifdef CONFIG_IPW2100_MONITOR
	if (priv->ieee->iw_mode == IW_MODE_MONITOR) {
		err = ipw2100_set_channel(priv, priv->channel, batch_mode);
		if (err)
			return err;

		IPW_DEBUG_INFO("exit\n");

		return 0;
	}
#endif				

	err = ipw2100_read_mac_address(priv);
	if (err)
		return -EIO;

	err = ipw2100_set_mac_address(priv, batch_mode);
	if (err)
		return err;

	err = ipw2100_set_port_type(priv, priv->ieee->iw_mode, batch_mode);
	if (err)
		return err;

	if (priv->ieee->iw_mode == IW_MODE_ADHOC) {
		err = ipw2100_set_channel(priv, priv->channel, batch_mode);
		if (err)
			return err;
	}

	err = ipw2100_system_config(priv, batch_mode);
	if (err)
		return err;

	err = ipw2100_set_tx_rates(priv, priv->tx_rates, batch_mode);
	if (err)
		return err;

	err = ipw2100_set_power_mode(priv, IPW_POWER_MODE_CAM);
	if (err)
		return err;

	err = ipw2100_set_rts_threshold(priv, priv->rts_threshold);
	if (err)
		return err;

	if (priv->config & CFG_STATIC_BSSID)
		bssid = priv->bssid;
	else
		bssid = NULL;
	err = ipw2100_set_mandatory_bssid(priv, bssid, batch_mode);
	if (err)
		return err;

	if (priv->config & CFG_STATIC_ESSID)
		err = ipw2100_set_essid(priv, priv->essid, priv->essid_len,
					batch_mode);
	else
		err = ipw2100_set_essid(priv, NULL, 0, batch_mode);
	if (err)
		return err;

	err = ipw2100_configure_security(priv, batch_mode);
	if (err)
		return err;

	if (priv->ieee->iw_mode == IW_MODE_ADHOC) {
		err =
		    ipw2100_set_ibss_beacon_interval(priv,
						     priv->beacon_interval,
						     batch_mode);
		if (err)
			return err;

		err = ipw2100_set_tx_power(priv, priv->tx_power);
		if (err)
			return err;
	}

*/
	return 0;
}

#define MAX_HW_RESTARTS 2
int darwin_iwi2100::ipw2100_up(struct ipw2100_priv *priv, int deferred)
{
		unsigned long flags;
	int rc = 0;
	u32 lock;
	u32 ord_len = sizeof(lock);

	/* Quite if manually disabled. */
	if (priv->status & STATUS_RF_KILL_SW) {
		IOLog("%s: Radio is disabled by Manual Disable "
			       "switch\n", priv->net_dev->name);
		//return 0;
	}

	/* If the interrupt is enabled, turn it off... */
	ipw2100_disable_interrupts(priv);

	/* Reset any fatal_error conditions */
	ipw2100_reset_fatalerror(priv);
	if (priv->status & STATUS_POWERED ||
	    (priv->status & STATUS_RESET_PENDING)) {
		/* Power cycle the card ... */
		/*if (ipw2100_power_cycle_adapter(priv)) {
			IOLog(
			       ": %s: Could not cycle adapter.\n",
			       priv->net_dev->name);
			rc = 1;
			goto exit;
		}*/
	} else
		priv->status |= STATUS_POWERED;
	/* Load the firmware, start the clocks, etc. */
	if (ipw2100_start_adapter(priv)) {
		IOLog(
		       ": %s: Failed to start the firmware.\n",
		       priv->net_dev->name);
		//rc = 1;
		//goto exit;
	}

	ipw2100_initialize_ordinals(priv);

	/* Determine capabilities of this particular HW configuration */
	if (ipw2100_get_hw_features(priv)) {
		IOLog(
		       ": %s: Failed to determine HW features.\n",
		       priv->net_dev->name);
		//rc = 1;
		//goto exit;
	}

	/* Initialize the geo */
	if (ipw_set_geo(priv->ieee, &ipw_geos[0])) {
		IOLog( "Could not set geo\n");
		//return 0;
	}
	priv->ieee->freq_band = IEEE80211_24GHZ_BAND;

	lock = LOCK_NONE;
	if (ipw2100_set_ordinal(priv, IPW_ORD_PERS_DB_LOCK, &lock, &ord_len)) {
		IOLog(
		       ": %s: Failed to clear ordinal lock.\n",
		       priv->net_dev->name);
		//rc = 1;
		//goto exit;
	}

	priv->status &= ~STATUS_SCANNING;

	if (rf_kill_active(priv)) {
		IOLog( "%s: Radio is disabled by RF switch.\n",
		       priv->net_dev->name);

		if (priv->stop_rf_kill) {
			priv->stop_rf_kill = 0;
			//queue_delayed_work(priv->workqueue, &priv->rf_kill, HZ);
		}

		deferred = 1;
	}

	/* Turn on the interrupt so that commands can be processed */
	ipw2100_enable_interrupts(priv);

	/* Send all of the commands that must be sent prior to
	 * HOST_COMPLETE */
	if (ipw2100_adapter_setup(priv)) {
		IOLog( ": %s: Failed to start the card.\n",
		       priv->net_dev->name);
		//rc = 1;
		//goto exit;
	}

	if (!deferred) {
		/* Enable the adapter - sends HOST_COMPLETE */
		if (ipw2100_enable_adapter(priv)) {
			IOLog( ": "
			       "%s: failed in call to enable adapter.\n",
			       priv->net_dev->name);
			//ipw2100_hw_stop_adapter(priv);
			//rc = 1;
			//goto exit;
		}

		/* Start a scan . . . */
		ipw2100_set_scan_options(priv);
		ipw2100_start_scan(priv);
	}

      exit:
	return rc;

}

IOReturn darwin_iwi2100::enable( IONetworkInterface * netif ) 
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

inline int darwin_iwi2100::ipw2100_is_init(struct ipw2100_priv *priv)
{
	return (priv->status & STATUS_INIT) ? 1 : 0;
}

u32 darwin_iwi2100::ipw2100_register_toggle(u32 reg)
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

void darwin_iwi2100::ipw2100_led_activity_off(struct ipw2100_priv *priv)
{

}

void darwin_iwi2100::ipw2100_led_link_down(struct ipw2100_priv *priv)
{
	ipw2100_led_activity_off(priv);
	ipw2100_led_link_off(priv);

	if (priv->status & STATUS_RF_KILL_MASK)
		ipw2100_led_radio_off(priv);
}

void darwin_iwi2100::ipw2100_led_link_off(struct ipw2100_priv *priv)
{

}

void darwin_iwi2100::ipw2100_led_band_off(struct ipw2100_priv *priv)
{
	
}

void darwin_iwi2100::ipw2100_led_shutdown(struct ipw2100_priv *priv)
{
	ipw2100_led_activity_off(priv);
	ipw2100_led_link_off(priv);
	ipw2100_led_band_off(priv);
	queue_td(2,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_led_link_on));
	//cancel_delayed_work(&priv->led_link_off);
	//cancel_delayed_work(&priv->led_act_off);
}

void darwin_iwi2100::ipw2100_abort_scan(struct ipw2100_priv *priv)
{
	int err;

	if (priv->status & STATUS_SCAN_ABORTING) {
		IOLog("Ignoring concurrent scan abort request.\n");
		return;
	}
	priv->status |= STATUS_SCAN_ABORTING;
	queue_td(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_scan));
	queue_td(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_scan_check));
	err = sendCommand(IPW_CMD_SCAN_ABORT, NULL,0, 0);
	if (err)
		IOLog("Request to abort scan failed.\n");
}

void darwin_iwi2100::ipw2100_send_disassociate(struct ipw2100_priv *priv, int quiet)
{

}

int darwin_iwi2100::ipw2100_send_associate(struct ipw2100_priv *priv,
			      struct ipw2100_associate *associate)
{

}

int darwin_iwi2100::ipw2100_disassociate(struct ipw2100_priv *data)
{
	struct ipw2100_priv *priv = data;
	if (!(priv->status & (STATUS_ASSOCIATED | STATUS_ASSOCIATING)))
		return 0;
	ipw2100_send_disassociate(data, 0);
	return 1;
}

void darwin_iwi2100::ipw2100_deinit(struct ipw2100_priv *priv)
{
	int i;

	if (priv->status & STATUS_SCANNING) {
		IOLog("Aborting scan during shutdown.\n");
		ipw2100_abort_scan(priv);
	}

	if (priv->status & STATUS_ASSOCIATED) {
		IOLog("Disassociating during shutdown.\n");
		ipw2100_disassociate(priv);
	}

	ipw2100_led_shutdown(priv);

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


inline void darwin_iwi2100::ipw2100_disable_interrupts(struct ipw2100_priv *priv)
{
	if (!(priv->status & STATUS_INT_ENABLED))
		return;
	priv->status &= ~STATUS_INT_ENABLED;
	ipw2100_write32( IPW_INTA_MASK_R, ~IPW_INTA_MASK_ALL);
}

void darwin_iwi2100::ipw2100_down(struct ipw2100_priv *priv)
{
	int exit_pending = priv->status & STATUS_EXIT_PENDING;

	priv->status |= STATUS_EXIT_PENDING;

	if (ipw2100_is_init(priv))
		ipw2100_deinit(priv);

	/* Wipe out the EXIT_PENDING status bit if we are not actually
	 * exiting the module */
	if (!exit_pending)
		priv->status &= ~STATUS_EXIT_PENDING;

	/* tell the device to stop sending interrupts */
	ipw2100_disable_interrupts(priv);

	/* Clear all bits but the RF Kill */
	priv->status &= STATUS_RF_KILL_MASK | STATUS_EXIT_PENDING;
	//fNetif->setLinkState(kIO80211NetworkLinkDown);
	//netif_stop_queue(priv->net_dev);

	ipw2100_stop_nic();

	ipw2100_led_radio_off(priv);
}


void darwin_iwi2100::ipw2100_led_radio_off(struct ipw2100_priv *priv)
{
	ipw2100_led_activity_off(priv);
	ipw2100_led_link_off(priv);
}

void darwin_iwi2100::interruptOccurred(OSObject * owner, 
	//IOInterruptEventSource * src, int /*count*/) 
	void		*src,  IOService *nub, int source)
{
	darwin_iwi2100 *self = OSDynamicCast(darwin_iwi2100, owner); //(darwin_iwi2100 *)owner;
	self->handleInterrupt();
}

int darwin_iwi2100::ipw2100_corruption_check(struct ipw2100_priv *priv, int i)
{
	struct ipw2100_status *status = &priv->status_queue.drv[i];
	struct ipw2100_rx *u = priv->rx_buffers[i].rxp;
	u16 frame_type = status->status_fields & STATUS_TYPE_MASK;

	switch (frame_type) {
	case COMMAND_STATUS_VAL:
		return (status->frame_size != sizeof(u->rx_data.command));
	case STATUS_CHANGE_VAL:
		return (status->frame_size != sizeof(u->rx_data.status));
	case HOST_NOTIFICATION_VAL:
		return (status->frame_size < sizeof(u->rx_data.notification));
	case P80211_DATA_VAL:
	case P8023_DATA_VAL:
#ifdef CONFIG_IPW2100_MONITOR
		return 0;
#else
		switch (WLAN_FC_GET_TYPE(u->rx_data.header.frame_ctl)) {
		case IEEE80211_FTYPE_MGMT:
		case IEEE80211_FTYPE_CTL:
			return 0;
		case IEEE80211_FTYPE_DATA:
			return (status->frame_size >
				IPW_MAX_802_11_PAYLOAD_LENGTH);
		}
#endif
	}

	return 1;
}

void darwin_iwi2100::isr_rx_complete_command(struct ipw2100_priv *priv,
				    struct ipw2100_cmd_header *cmd)
{
	if (cmd->host_command_reg < ARRAY_SIZE(command_types)) {
		IOLog("Command completed '%s (%d)'\n",
			     command_types[cmd->host_command_reg],
			     cmd->host_command_reg);
	}
	if (cmd->host_command_reg == HOST_COMPLETE)
		priv->status |= STATUS_ENABLED;

	if (cmd->host_command_reg == CARD_DISABLE)
		priv->status &= ~STATUS_ENABLED;

	priv->status &= ~STATUS_CMD_ACTIVE;

	//wake_up_interruptible(&priv->wait_command_queue);
}

void darwin_iwi2100::isr_status_change(struct ipw2100_priv *priv, int status)
{
	int i;

	if (status == IPW_STATE_SCANNING &&
	    priv->status & STATUS_ASSOCIATED &&
	    !(priv->status & STATUS_SCANNING)) {
		IOLog("Scan detected while associated, with "
			       "no scan request.  Restarting firmware.\n");

		/* Wake up any sleeping jobs */
		schedule_reset(priv);
	}

	/*for (i = 0; status_handlers[i].status != -1; i++) {
		if (status == status_handlers[i].status) {
			IOLog("Status change: %s\n",
					status_handlers[i].name);
			if (status_handlers[i].cb)
				status_handlers[i].cb(priv, status);
			priv->wstats.status = status;
			return;
		}
	}*/

	IOLog("unknown status received: %04x\n", status);
}

void darwin_iwi2100::ieee80211_rx_mgt(struct ieee80211_device *ieee, 
        struct ieee80211_hdr_4addr *header,struct ieee80211_rx_stats *stats)
{

}

void darwin_iwi2100::__ipw2100_rx_process(struct ipw2100_priv *priv)
{
	struct ipw2100_bd_queue *rxq = &priv->rx_queue;
	struct ipw2100_status_queue *sq = &priv->status_queue;
	struct ipw2100_rx_packet *packet;
	u16 frame_type;
	u32 r, w, i, s;
	struct ipw2100_rx *u;
	struct ieee80211_rx_stats stats;// = {
		stats.mac_time = jiffies;
	//};

	read_register(priv->net_dev, IPW_MEM_HOST_SHARED_RX_READ_INDEX, &r);
	read_register(priv->net_dev, IPW_MEM_HOST_SHARED_RX_WRITE_INDEX, &w);

	if (r >= rxq->entries) {
		IOLog("exit - bad read index\n");
		return;
	}

	i = (rxq->next + 1) % rxq->entries;
	s = i;
	while (i != r) {
		/* IPW_DEBUG_RX("r = %d : w = %d : processing = %d\n",
		   r, rxq->next, i); */

		packet = &priv->rx_buffers[i];

		/* Sync the DMA for the STATUS buffer so CPU is sure to get
		 * the correct values */
		/*pci_dma_sync_single_for_cpu(priv->pci_dev,
					    sq->nic +
					    sizeof(struct ipw2100_status) * i,
					    sizeof(struct ipw2100_status),
					    PCI_DMA_FROMDEVICE);*/

		/* Sync the DMA for the RX buffer so CPU is sure to get
		 * the correct values */
		/*pci_dma_sync_single_for_cpu(priv->pci_dev, packet->dma_addr,
					    sizeof(struct ipw2100_rx),
					    PCI_DMA_FROMDEVICE);*/

		if (unlikely(ipw2100_corruption_check(priv, i))) {
			//ipw2100_corruption_detected(priv, i);
			goto increment;
		}

		u = packet->rxp;
		frame_type = sq->drv[i].status_fields & STATUS_TYPE_MASK;
		stats.rssi = sq->drv[i].rssi + IPW2100_RSSI_TO_DBM;
		stats.len = sq->drv[i].frame_size;

		stats.mask = 0;
		if (stats.rssi != 0)
			stats.mask |= IEEE80211_STATMASK_RSSI;
		stats.freq = IEEE80211_24GHZ_BAND;

		IOLog("%s: '%s' frame type received (%d).\n",
			     priv->net_dev->name, frame_types[frame_type],
			     stats.len);

		switch (frame_type) {
		case COMMAND_STATUS_VAL:
			/* Reset Rx watchdog */
			isr_rx_complete_command(priv, &u->rx_data.command);
			break;

		case STATUS_CHANGE_VAL:
			isr_status_change(priv, u->rx_data.status);
			break;

		case P80211_DATA_VAL:
		case P8023_DATA_VAL:
#ifdef CONFIG_IPW2100_MONITOR
			if (priv->ieee->iw_mode == IW_MODE_MONITOR) {
				isr_rx_monitor(priv, i, &stats);
				break;
			}
#endif
			if (stats.len < sizeof(struct ieee80211_hdr_3addr))
				break;
			switch (WLAN_FC_GET_TYPE(u->rx_data.header.frame_ctl)) {
			case IEEE80211_FTYPE_MGMT:
				ieee80211_rx_mgt(priv->ieee,&u->rx_data.header, &stats);
				break;

			case IEEE80211_FTYPE_CTL:
				break;

			case IEEE80211_FTYPE_DATA:
				//isr_rx(priv, i, &stats);
				IOLog("todo: isr_rx\n ");
				break;

			}
			break;
		}

	      increment:
		/* clear status field associated with this RBD */
		rxq->drv[i].status.info.field = 0;

		i = (i + 1) % rxq->entries;
	}

	if (i != s) {
		/* backtrack one entry, wrapping to end if at 0 */
		rxq->next = (i ? i : rxq->entries) - 1;

		write_register(priv->net_dev,
			       IPW_MEM_HOST_SHARED_RX_WRITE_INDEX, rxq->next);
	}
}

int darwin_iwi2100::__ipw2100_tx_process(struct ipw2100_priv *priv)
{
	struct ipw2100_bd_queue *txq = &priv->tx_queue;
	struct ipw2100_bd *tbd;
	struct list_head *element;
	struct ipw2100_tx_packet *packet;
	int descriptors_used;
	int e, i;
	u32 r, w, frag_num = 0;

	if (list_empty(&priv->fw_pend_list))
		return 0;

	element = priv->fw_pend_list.next;

	packet = list_entry(element, struct ipw2100_tx_packet, list);
	tbd = &txq->drv[packet->index];

	/* Determine how many TBD entries must be finished... */
	switch (packet->type) {
	case COMMAND:
		/* COMMAND uses only one slot; don't advance */
		descriptors_used = 1;
		e = txq->oldest;
		break;

	case DATA:
		/* DATA uses two slots; advance and loop position. */
		descriptors_used = tbd->num_fragments;
		frag_num = tbd->num_fragments - 1;
		e = txq->oldest + frag_num;
		e %= txq->entries;
		break;

	default:
		IOLog(  ": %s: Bad fw_pend_list entry!\n",
		       priv->net_dev->name);
		return 0;
	}

	/* if the last TBD is not done by NIC yet, then packet is
	 * not ready to be released.
	 *
	 */
	read_register(priv->net_dev, IPW_MEM_HOST_SHARED_TX_QUEUE_READ_INDEX,
		      &r);
	read_register(priv->net_dev, IPW_MEM_HOST_SHARED_TX_QUEUE_WRITE_INDEX,
		      &w);
	if (w != txq->next)
		IOLog(  ": %s: write index mismatch\n",
		       priv->net_dev->name);

	/*
	 * txq->next is the index of the last packet written txq->oldest is
	 * the index of the r is the index of the next packet to be read by
	 * firmware
	 */

	/*
	 * Quick graphic to help you visualize the following
	 * if / else statement
	 *
	 * ===>|                     s---->|===============
	 *                               e>|
	 * | a | b | c | d | e | f | g | h | i | j | k | l
	 *       r---->|
	 *               w
	 *
	 * w - updated by driver
	 * r - updated by firmware
	 * s - start of oldest BD entry (txq->oldest)
	 * e - end of oldest BD entry
	 *
	 */
	if (!((r <= w && (e < r || e >= w)) || (e < r && e >= w))) {
		IOLog("exit - no processed packets ready to release.\n");
		return 0;
	}

	list_del(element);
	DEC_STAT(&priv->fw_pend_stat);

#ifdef CONFIG_IPW2100_DEBUG
	{
		int i = txq->oldest;
		IOLog("TX%d V=%p P=%04X T=%04X L=%d\n", i,
			     &txq->drv[i],
			     (u32) (txq->nic + i * sizeof(struct ipw2100_bd)),
			     txq->drv[i].host_addr, txq->drv[i].buf_length);

		if (packet->type == DATA) {
			i = (i + 1) % txq->entries;

			IOLog("TX%d V=%p P=%04X T=%04X L=%d\n", i,
				     &txq->drv[i],
				     (u32) (txq->nic + i *
					    sizeof(struct ipw2100_bd)),
				     (u32) txq->drv[i].host_addr,
				     txq->drv[i].buf_length);
		}
	}
#endif

	switch (packet->type) {
	case DATA:
		if (txq->drv[txq->oldest].status.info.fields.txType != 0)
			IOLog(  ": %s: Queue mismatch.  "
			       "Expecting DATA TBD but pulled "
			       "something else: ids %d=%d.\n",
			       priv->net_dev->name, txq->oldest, packet->index);

		/* DATA packet; we have to unmap and free the SKB */
		for (i = 0; i < frag_num; i++) {
			tbd = &txq->drv[(packet->index + 1 + i) % txq->entries];

			IOLog("TX%d P=%08x L=%d\n",
				     (packet->index + 1 + i) % txq->entries,
				     tbd->host_addr, tbd->buf_length);

			tbd->host_addr=NULL;
			/*pci_unmap_single(priv->pci_dev,
					 tbd->host_addr,
					 tbd->buf_length, PCI_DMA_TODEVICE);*/
		}

		ieee80211_txb_free(packet->info.d_struct.txb);
		packet->info.d_struct.txb = NULL;

		list_add_tail(element, &priv->tx_free_list);
		INC_STAT(&priv->tx_free_stat);

		/* We have a free slot in the Tx queue, so wake up the
		 * transmit layer if it is stopped. */
		if (priv->status & STATUS_ASSOCIATED)
			fTransmitQueue->start();
		//	netif_wake_queue(priv->net_dev);

		/* A packet was processed by the hardware, so update the
		 * watchdog */
		priv->net_dev->trans_start = jiffies;

		break;

	case COMMAND:
		if (txq->drv[txq->oldest].status.info.fields.txType != 1)
			IOLog(  ": %s: Queue mismatch.  "
			       "Expecting COMMAND TBD but pulled "
			       "something else: ids %d=%d.\n",
			       priv->net_dev->name, txq->oldest, packet->index);

#ifdef CONFIG_IPW2100_DEBUG
		if (packet->info.c_struct.cmd->host_command_reg <
		    sizeof(command_types) / sizeof(*command_types))
			IOLog("Command '%s (%d)' processed: %d.\n",
				     command_types[packet->info.c_struct.cmd->
						   host_command_reg],
				     packet->info.c_struct.cmd->
				     host_command_reg,
				     packet->info.c_struct.cmd->cmd_status_reg);
#endif

		list_add_tail(element, &priv->msg_free_list);
		INC_STAT(&priv->msg_free_stat);
		break;
	}

	/* advance oldest used TBD pointer to start of next entry */
	txq->oldest = (e + 1) % txq->entries;
	/* increase available TBDs number */
	txq->available += descriptors_used;
	SET_STAT(&priv->txq_stat, txq->available);

	IOLog("packet latency (send to process)  %ld jiffies\n",
		     jiffies - packet->jiffy_start);

	return (!list_empty(&priv->fw_pend_list));
}

void darwin_iwi2100::__ipw2100_tx_complete(struct ipw2100_priv *priv)
{
	int i = 0;

	while (__ipw2100_tx_process(priv) && i < 200)
		i++;

	if (i == 200) {
		IOLog(  ": "
		       "%s: Driver is running slow (%d iters).\n",
		       priv->net_dev->name, i);
	}
}

UInt32 darwin_iwi2100::handleInterrupt(void)
{
	struct net_device *dev = priv->net_dev;
	unsigned long flags;
	u32 inta, tmp;

	//spin_lock_irqsave(&priv->low_lock, flags);
	ipw2100_disable_interrupts(priv);

	read_register(dev, IPW_REG_INTA, &inta);

	if (inta==0) goto skipi;
	
	//IOLog("enter - INTA: 0x%08lX\n",
	//	      (unsigned long)inta & IPW_INTERRUPT_MASK);

	priv->in_isr++;
	priv->interrupts++;

	/* We do not loop and keep polling for more interrupts as this
	 * is frowned upon and doesn't play nicely with other potentially
	 * chained IRQs */
	IOLog("INTA: 0x%08lX\n",
		      (unsigned long)inta & IPW_INTERRUPT_MASK);

	if (inta & IPW2100_INTA_FATAL_ERROR) {
		IOLog( 
		       ": Fatal interrupt. Scheduling firmware restart.\n");
		priv->inta_other++;
		write_register(dev, IPW_REG_INTA, IPW2100_INTA_FATAL_ERROR);

		read_nic_dword(dev, IPW_NIC_FATAL_ERROR, &priv->fatal_error);
		IOLog("%s: Fatal error value: 0x%08X\n",
			       priv->net_dev->name, priv->fatal_error);

		read_nic_dword(dev, IPW_ERROR_ADDR(priv->fatal_error), &tmp);
		IOLog("%s: Fatal error address value: 0x%08X\n",
			       priv->net_dev->name, tmp);

		/* Wake up any sleeping jobs */
		schedule_reset(priv);
	}

	if (inta & IPW2100_INTA_PARITY_ERROR) {
		IOLog( 
		       ": ***** PARITY ERROR INTERRUPT !!!! \n");
		priv->inta_other++;
		write_register(dev, IPW_REG_INTA, IPW2100_INTA_PARITY_ERROR);
	}

	if (inta & IPW2100_INTA_RX_TRANSFER) {
		IOLog("RX interrupt\n");

		priv->rx_interrupts++;

		write_register(dev, IPW_REG_INTA, IPW2100_INTA_RX_TRANSFER);

		__ipw2100_rx_process(priv);
		__ipw2100_tx_complete(priv);
	}

	if (inta & IPW2100_INTA_TX_TRANSFER) {
		IOLog("TX interrupt\n");

		priv->tx_interrupts++;

		write_register(dev, IPW_REG_INTA, IPW2100_INTA_TX_TRANSFER);

		__ipw2100_tx_complete(priv);
		ipw2100_tx_send_commands(priv);
		ipw2100_tx_send_data(priv);
	}

	if (inta & IPW2100_INTA_TX_COMPLETE) {
		IOLog("TX complete\n");
		priv->inta_other++;
		write_register(dev, IPW_REG_INTA, IPW2100_INTA_TX_COMPLETE);

		__ipw2100_tx_complete(priv);
	}

	if (inta & IPW2100_INTA_EVENT_INTERRUPT) {
		/* ipw2100_handle_event(dev); */
		priv->inta_other++;
		write_register(dev, IPW_REG_INTA, IPW2100_INTA_EVENT_INTERRUPT);
	}

	if (inta & IPW2100_INTA_FW_INIT_DONE) {
		IOLog("FW init done interrupt\n");
		priv->inta_other++;

		read_register(dev, IPW_REG_INTA, &tmp);
		if (tmp & (IPW2100_INTA_FATAL_ERROR |
			   IPW2100_INTA_PARITY_ERROR)) {
			write_register(dev, IPW_REG_INTA,
				       IPW2100_INTA_FATAL_ERROR |
				       IPW2100_INTA_PARITY_ERROR);
		}

		write_register(dev, IPW_REG_INTA, IPW2100_INTA_FW_INIT_DONE);
	}

	if (inta & IPW2100_INTA_STATUS_CHANGE) {
		IOLog("Status change interrupt\n");
		priv->inta_other++;
		write_register(dev, IPW_REG_INTA, IPW2100_INTA_STATUS_CHANGE);
	}

	if (inta & IPW2100_INTA_SLAVE_MODE_HOST_COMMAND_DONE) {
		IOLog("slave host mode interrupt\n");
		priv->inta_other++;
		write_register(dev, IPW_REG_INTA,
			       IPW2100_INTA_SLAVE_MODE_HOST_COMMAND_DONE);
	}

	priv->in_isr--;
	
skipi:
	ipw2100_enable_interrupts(priv);
	return 0;
}


UInt16 darwin_iwi2100::readPromWord(UInt16 *base, UInt8 addr)
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


IOReturn darwin_iwi2100::getHardwareAddress( IOEthernetAddress * addr )
{
	UInt16 val;
	if (fEnetAddr.bytes[0]==0 && fEnetAddr.bytes[1]==0 && fEnetAddr.bytes[2]==0
	&& fEnetAddr.bytes[3]==0 && fEnetAddr.bytes[4]==0 && fEnetAddr.bytes[5]==0)
	{
		if (priv)
		{
			u32 length = ETH_ALEN;
			u8 mac[ETH_ALEN];

			int err;

			err = ipw2100_get_ordinal(priv, IPW_ORD_STAT_ADAPTER_MAC, mac, &length);
			if (err) {
				IOLog("MAC address read failed\n");
				return -EIO;
			}
			IOLog("card MAC is %02X:%02X:%02X:%02X:%02X:%02X\n",
					   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

			memcpy(fEnetAddr.bytes, mac, ETH_ALEN);
			ifnet_set_lladdr(fifnet, &fEnetAddr.bytes, ETH_ALEN);
		}
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


void darwin_iwi2100::stopMaster(UInt16 *base) {
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

void darwin_iwi2100::stopDevice(UInt16 *base)
{
	stopMaster(base);
	
	CSR_WRITE_4(base, IWI_CSR_RST, IWI_RST_SOFT_RESET);
}

bool darwin_iwi2100::resetDevice(UInt16 *base) 
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
		return false;
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


void darwin_iwi2100::ipw2100_write_reg8(UInt32 reg, UInt8 value)
{
	UInt32 aligned_addr = reg & IPW_INDIRECT_ADDR_MASK;	/* dword align */
	UInt32 dif_len = reg - aligned_addr;

	_ipw_write32(memBase, IPW_INDIRECT_ADDR, aligned_addr);
	_ipw_write8(memBase, IPW_INDIRECT_DATA + dif_len, value);
}

UInt8 darwin_iwi2100::ipw2100_read_reg8(UInt32 reg)
{
	UInt32 word;
	_ipw_write32(memBase, IPW_INDIRECT_ADDR, reg & IPW_INDIRECT_ADDR_MASK);
	word = _ipw_read32(memBase, IPW_INDIRECT_DATA);
	return (word >> ((reg & 0x3) * 8)) & 0xff;
}

void darwin_iwi2100::ipw2100_write_reg16(UInt32 reg, UInt16 value)
{
	UInt32 aligned_addr = reg & IPW_INDIRECT_ADDR_MASK;	/* dword align */
	UInt32 dif_len = (reg - aligned_addr) & (~0x1ul);

	_ipw_write32(memBase, IPW_INDIRECT_ADDR, aligned_addr);
	_ipw_write16(memBase, IPW_INDIRECT_DATA + dif_len, value);
	
}

int darwin_iwi2100::ipw2100_stop_master()
{
	int rc;

	/* stop master. typical delay - 0 */
	ipw2100_set_bit( IPW_RESET_REG, IPW_RESET_REG_STOP_MASTER);

	/* timeout is in msec, polled in 10-msec quanta */
	rc = ipw2100_poll_bit( IPW_RESET_REG,
			  IPW_RESET_REG_MASTER_DISABLED, 100);
	if (rc < 0) {
		IOLog("wait for stop master failed after 100ms\n");
		return -1;
	}

	//IOLog("stop master %dms\n", rc);

	return rc;
}

void darwin_iwi2100::ipw2100_arc_release()
{
	mdelay(5);

	ipw2100_clear_bit( IPW_RESET_REG, CBD_RESET_REG_PRINCETON_RESET);

	/* no one knows timing, for safety add some delay */
	mdelay(5);
}

bool darwin_iwi2100::uploadUCode(const unsigned char * data, UInt16 len)
{
	
}



void inline darwin_iwi2100::ipw2100_write32(UInt32 offset, UInt32 data)
{
	//OSWriteLittleInt32((void*)memBase, offset, data);
	_ipw_write32(memBase, offset, data);
}

UInt32 inline darwin_iwi2100::ipw2100_read32(UInt32 offset)
{
	//return OSReadLittleInt32((void*)memBase, offset);
	return _ipw_read32(memBase,offset);
}

void inline darwin_iwi2100::ipw2100_clear_bit(UInt32 reg, UInt32 mask)
{
	ipw2100_write32(reg, ipw2100_read32(reg) & ~mask);
}

void inline darwin_iwi2100::ipw2100_set_bit(UInt32 reg, UInt32 mask)
{
	ipw2100_write32(reg, ipw2100_read32(reg) | mask);
}

int darwin_iwi2100::ipw2100_fw_dma_add_command_block(
					UInt32 src_address,
					UInt32 dest_address,
					UInt32 length,
					int interrupt_enabled, int is_last)
{

	return 0;
}

void darwin_iwi2100::ipw2100_zero_memory(UInt32 start, UInt32 count)
{
	count >>= 2;
	if (!count)
		return;
	_ipw_write32(memBase,IPW_AUTOINC_ADDR, start);
	while (count--)
		_ipw_write32(memBase,IPW_AUTOINC_DATA, 0);
}

void darwin_iwi2100::ipw2100_fw_dma_reset_command_blocks()
{

}

void darwin_iwi2100::ipw2100_write_reg32( UInt32 reg, UInt32 value)
{
	_ipw_write32(memBase,IPW_INDIRECT_ADDR, reg);
	_ipw_write32(memBase,IPW_INDIRECT_DATA, value);
}

int darwin_iwi2100::ipw2100_fw_dma_enable()
{				/* start dma engine but no transfers yet */

	ipw2100_fw_dma_reset_command_blocks();
	ipw2100_write_reg32(IPW_DMA_I_CB_BASE, IPW_SHARED_SRAM_DMA_CONTROL);
	return 0;
}

void darwin_iwi2100::ipw2100_write_indirect(UInt32 addr, UInt8 * buf,
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


int darwin_iwi2100::ipw2100_fw_dma_add_buffer(UInt32 src_phys, UInt32 dest_address, UInt32 length)
{
	UInt32 bytes_left = length;
	UInt32 src_offset = 0;
	UInt32 dest_offset = 0;
	int status = 0;

	while (bytes_left > CB_MAX_LENGTH) {
		status = ipw2100_fw_dma_add_command_block(
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
		    ipw2100_fw_dma_add_command_block( src_phys + src_offset,
						 dest_address + dest_offset,
						 bytes_left, 0, 0);
		if (status) {
			return -1;
		};
	}

	return 0;
}

int darwin_iwi2100::ipw2100_fw_dma_write_command_block(int index,
					  struct command_block *cb)
{
		return 0;

}

int darwin_iwi2100::ipw2100_fw_dma_kick()
{
	
	return 0;
}

UInt32 darwin_iwi2100::ipw2100_read_reg32( UInt32 reg)
{
	UInt32 value;


	_ipw_write32(memBase, IPW_INDIRECT_ADDR, reg);
	value = _ipw_read32(memBase, IPW_INDIRECT_DATA);
	return value;
}

int darwin_iwi2100::ipw2100_fw_dma_command_block_index()
{

}

void darwin_iwi2100::ipw2100_fw_dma_dump_command_block()
{
	UInt32 address;
	UInt32 register_value = 0;
	UInt32 cb_fields_address = 0;

	address = ipw2100_read_reg32(IPW_DMA_I_CURRENT_CB);

	/* Read the DMA Controlor register */
	register_value = ipw2100_read_reg32(IPW_DMA_I_DMA_CONTROL);

	/* Print the CB values */
	cb_fields_address = address;
	register_value = ipw2100_read_reg32( cb_fields_address);

	cb_fields_address += sizeof(UInt32);
	register_value = ipw2100_read_reg32( cb_fields_address);

	cb_fields_address += sizeof(UInt32);
	register_value = ipw2100_read_reg32( cb_fields_address);

	cb_fields_address += sizeof(UInt32);
	register_value = ipw2100_read_reg32( cb_fields_address);

}

void darwin_iwi2100::ipw2100_fw_dma_abort()
{

}

int darwin_iwi2100::ipw2100_fw_dma_wait()
{
	
}


bool darwin_iwi2100::uploadFirmware(u8 * data, size_t len)
{	
	
}

bool darwin_iwi2100::uploadUCode2(UInt16 *base, const unsigned char *uc, UInt16 size, int offset)
{
	
}


bool darwin_iwi2100::uploadFirmware2(UInt16 *base, const unsigned char *fw, UInt32 size, int offset)
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


int darwin_iwi2100::ipw2100_get_fw(const struct firmware **fw, const char *name)
{
		
}

IOBufferMemoryDescriptor*
darwin_iwi2100::MemoryDmaAlloc(UInt32 buf_size, dma_addr_t *phys_add, void *virt_add)
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


int darwin_iwi2100::sendCommand(UInt8 type,void *data,UInt8 len,bool async)
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

const struct ieee80211_geo* darwin_iwi2100::ipw2100_get_geo(struct ieee80211_device *ieee)
{
	return &ieee->geo;
}

int darwin_iwi2100::ipw2100_set_tx_power(struct ipw2100_priv *priv)
{

}

void darwin_iwi2100::init_sys_config(struct ipw2100_sys_config *sys_config)
{
	
}

void darwin_iwi2100::ipw2100_add_cck_scan_rates(struct ipw2100_supported_rates *rates,
				   u8 modulation, u32 rate_mask)
{
	
}

void darwin_iwi2100::ipw2100_add_ofdm_scan_rates(struct ipw2100_supported_rates *rates,
				    u8 modulation, u32 rate_mask)
{
	
}

int darwin_iwi2100::init_supported_rates(struct ipw2100_priv *priv,
				struct ipw2100_supported_rates *rates)
{
	
}

void darwin_iwi2100::ipw2100_send_tgi_tx_key(struct ipw2100_priv *priv, int type, int index)
{

}

void darwin_iwi2100::ipw2100_send_wep_keys(struct ipw2100_priv *priv, int type)
{
	
}

void darwin_iwi2100::ipw2100_set_hw_decrypt_unicast(struct ipw2100_priv *priv, int level)
{
	
}

void darwin_iwi2100::ipw2100_set_hw_decrypt_multicast(struct ipw2100_priv *priv, int level)
{
	
}

void darwin_iwi2100::ipw2100_set_hwcrypto_keys(struct ipw2100_priv *priv)
{
	
}

bool darwin_iwi2100::configureInterface(IONetworkInterface * netif)
 {
    IONetworkData * data;
    IOLog("configureInterface\n");
    if (super::configureInterface(netif) == false)
            return false;

    return true;
}

int darwin_iwi2100::configu(struct ipw2100_priv *priv)
{
	
}

u8 darwin_iwi2100::ipw2100_qos_current_mode(struct ipw2100_priv *priv)
{
	
}

u32 darwin_iwi2100::ipw2100_qos_get_burst_duration(struct ipw2100_priv *priv)
{
	
}

int darwin_iwi2100::ipw2100_qos_activate(struct ipw2100_priv *priv,
			    struct ieee80211_qos_data *qos_network_data)
{
	
}

void darwin_iwi2100::ipw2100_led_link_on(struct ipw2100_priv *priv)
{
	
}

void darwin_iwi2100::ipw2100_led_init(struct ipw2100_priv *priv)
{
	
}


void darwin_iwi2100::ipw2100_led_band_on(struct ipw2100_priv *priv)
{
	
}

int darwin_iwi2100::ipw2100_channel_to_index(struct ieee80211_device *ieee, u8 channel)
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

void darwin_iwi2100::ipw2100_add_scan_channels(struct ipw2100_priv *priv,
				  struct ipw2100_scan_request_ext *scan,
				  int scan_type)
{
	
}

int darwin_iwi2100::ipw2100_scan(struct ipw2100_priv *priv, int type)
{
		
/*	
	struct ipw2100_scan_request_ext scan;
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
		ipw2100_add_scan_channels(priv, &scan, scan_type);
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

		switch (ipw2100_is_valid_channel(priv->ieee, priv->channel)) {
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
		ipw2100_set_scan_type(&scan, 1, IPW_SCAN_PASSIVE_FULL_DWELL_SCAN);


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

		ipw2100_add_scan_channels(priv, &scan, scan_type);
	}

      send_request:
	  struct ipw2100_scan_request_ext *rq=&scan;
	err = sendCommand(IPW_CMD_SCAN_REQUEST_EXT, &rq,sizeof(rq), 1);

	if (err) {
		IOLog("Sending scan command failed: %08X\n", err);
		goto done;
	}

	priv->status |= STATUS_SCANNING;
	priv->status &= ~STATUS_SCAN_PENDING;
	queue_te(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_scan_check),priv,5,true);

 
	  done:
	return err;
*/
}

void darwin_iwi2100::ipw2100_scan_check(ipw2100_priv *priv)
{
	if (priv->status & (STATUS_SCANNING | STATUS_SCAN_ABORTING)) {
		IOLog("Scan completion resetting\n");
		queue_te(1,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_adapter_restart),priv,NULL,true);
	}
}

int darwin_iwi2100::initCmdQueue()
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

int darwin_iwi2100::resetCmdQueue()
{
	cmdq.queued=0;
	cmdq.cur=0;
	cmdq.next=0;
	
	return 0;
}


int darwin_iwi2100::initRxQueue()
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


int darwin_iwi2100::resetRxQueue()
{
	rxq.cur=0;
	return 0;
}


void darwin_iwi2100::RxQueueIntr()
{
	
}


int darwin_iwi2100::initTxQueue()
{
	txq.count = IWI_TX_RING_COUNT;
	txq.queued = 0;
	txq.cur = 0;

	txq.memD = MemoryDmaAlloc(txq.count * IWI_TX_DESC_SIZE, &txq.physaddr, &txq.desc);
	txq.data = IONew(iwi_tx_data, txq.count);

	return true;
}

int darwin_iwi2100::resetTxQueue()
{
	rxq.cur=0;
	return 0;
}


void darwin_iwi2100::free(void)
{
	IOLog("TODO: free\n");
	return;
	IOLog("%s Freeing\n", getName());
	if (pl==0)
	{
		stop(NULL);
		super::free();
	}
}

void darwin_iwi2100::stop(IOService *provider)
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

IOReturn darwin_iwi2100::disable( IONetworkInterface * netif )
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


/*const char * darwin_iwi2100::getNamePrefix() const
{
	return "wlan";
}*/

void inline
darwin_iwi2100::eeprom_write_reg(UInt32 data)
{
	OSWriteLittleInt32((void*)memBase, IPW_INDIRECT_ADDR, FW_MEM_REG_EEPROM_ACCESS);
	OSWriteLittleInt32((void*)memBase, IPW_INDIRECT_DATA, data);
	
	// Sleep for 1 uS to hold the data there
	IODelay(1);
}

/* EEPROM Chip Select */
void inline
darwin_iwi2100::eeprom_cs(bool sel)
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
darwin_iwi2100::eeprom_write_bit(UInt8 bit)
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
darwin_iwi2100::eeprom_op(UInt8 op, UInt8 addr)
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
darwin_iwi2100::eeprom_read_UInt16(UInt8 addr)
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
		data = ipw2100_read_reg32(FW_MEM_REG_EEPROM_ACCESS);
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
darwin_iwi2100::cacheEEPROM(struct ipw2100_priv *priv)
{

}


UInt32
darwin_iwi2100::read_reg_UInt32(UInt32 reg)
{
	UInt32 value;
	
	OSWriteLittleInt32((void*)memBase, IPW_INDIRECT_ADDR, reg);
	value = OSReadLittleInt32((void*)memBase, IPW_INDIRECT_DATA);
	return value;
}

int
darwin_iwi2100::ipw2100_poll_bit(UInt32 reg, UInt32 mask, int timeout)
{
		int i = 0;

	do {
		if ((ipw2100_read32(reg) & mask) == mask)
			return i;
		mdelay(10);
		i += 10;
	} while (i < timeout);

	return -ETIME;}



/******************************************************************************* 
 * Functions which MUST be implemented by any class which inherits
 * from IO80211Controller.
 ******************************************************************************/
SInt32
darwin_iwi2100::getSSID(IO80211Interface *interface,
						struct apple80211_ssid_data *sd)
{
	IOLog("getSSID %s l:%d\n",escape_essid((const char*)sd->ssid_bytes, sd->ssid_len));
	return 0;
}

SInt32
darwin_iwi2100::getCHANNEL(IO80211Interface *interface,
						  struct apple80211_channel_data *cd)
{
	IOLog("getCHANNEL c:%d f:%d\n",cd->channel.channel,cd->channel.flags);
	return 0;
}

SInt32
darwin_iwi2100::getBSSID(IO80211Interface *interface,
						struct apple80211_bssid_data *bd)
{
	IOLog("getBSSID %s\n",escape_essid((const char*)bd->bssid.octet,sizeof(bd->bssid.octet)));
	return 0;
}

SInt32
darwin_iwi2100::getCARD_CAPABILITIES(IO80211Interface *interface,
									  struct apple80211_capability_data *cd)
{
	IOLog("getCARD_CAPABILITIES %d\n",sizeof(cd->capabilities));
	publishProperties();
	return 0;
}

SInt32
darwin_iwi2100::getSTATE(IO80211Interface *interface,
						  struct apple80211_state_data *sd)
{
	IOLog("getSTATE %d\n",sd->state);
	return 0;
}

SInt32
darwin_iwi2100::getRSSI(IO80211Interface *interface,
					   struct apple80211_rssi_data *rd)
{
	IOLog("getRSSI \n");
	return 0;
}

SInt32
darwin_iwi2100::getPOWER(IO80211Interface *interface,
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
darwin_iwi2100::getSCAN_RESULT(IO80211Interface *interface,
							  struct apple80211_scan_result **scan_result)
{
	IOLog("getSCAN_RESULT \n");
	return 0;
}

/*SInt32
darwin_iwi2100::getASSOCIATE_RESULT(IO80211Interface *interface,
								   struct apple80211_assoc_result_data *ard)
{
	IOLog("getASSOCIATE_RESULT \n");
	return 0;
}*/

SInt32
darwin_iwi2100::getRATE(IO80211Interface *interface,
					   struct apple80211_rate_data *rd)
{
	IOLog("getRATE %d\n",rd->rate);
	return 0;
}

SInt32
darwin_iwi2100::getSTATUS_DEV(IO80211Interface *interface,
							 struct apple80211_status_dev_data *dd)
{
	char i[4];
	int n=interface->getUnitNumber();
	sprintf(i,"en%d",n);
	IOLog("getSTATUS_DEV %s\n",dd->dev_name);
	ifnet_find_by_name(i,&fifnet);
	IOLog("ifnet_t %s%d = %x\n",ifnet_name(fifnet),ifnet_unit(fifnet),fifnet);
	//ifnet_set_mtu(fifnet,IPW_RX_BUF_SIZE); //>=IPW_RX_BUF_SIZE
	//ipw2100_sw_reset(1);
	memcpy(&priv->ieee->dev->name,i,sizeof(i));

	super::enable(fNetif);
	interface->setPoweredOnByUser(true);
	ipw2100_up(priv,0);
	return 0;
}

SInt32
darwin_iwi2100::getRATE_SET(IO80211Interface	*interface,
						   struct apple80211_rate_set_data *rd)
{
	IOLog("getRATE_SET %d r0:%d f0:%d\n",rd->num_rates, rd->rates[0].rate,rd->rates[0].flags);
	return 0;
}

SInt32	darwin_iwi2100::getASSOCIATION_STATUS( IO80211Interface * interface, struct apple80211_assoc_status_data * asd )
{
	IOLog("getASSOCIATION_STATUS %d\n",asd->status);
	return 0;
}

SInt32
darwin_iwi2100::setSCAN_REQ(IO80211Interface *interface,
						   struct apple80211_scan_data *sd)
{
	IOLog("setSCAN_REQ \n");
	return 0;
}

SInt32
darwin_iwi2100::setASSOCIATE(IO80211Interface *interface,
							struct apple80211_assoc_data *ad)
{
	IOLog("setASSOCIATE \n");
	return 0;
}

SInt32
darwin_iwi2100::setPOWER(IO80211Interface *interface,
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
darwin_iwi2100::setCIPHER_KEY(IO80211Interface *interface,
							 struct apple80211_key *key)
{
	IOLog("setCIPHER_KEY \n");
	return 0;
}

SInt32
darwin_iwi2100::setAUTH_TYPE(IO80211Interface *interface,
							struct apple80211_authtype_data *ad)
{
	IOLog("setAUTH_TYPE \n");
	return 0;
}

SInt32
darwin_iwi2100::setDISASSOCIATE(IO80211Interface	*interface)
{
	IOLog("setDISASSOCIATE \n");
	return 0;
}

SInt32
darwin_iwi2100::setSSID(IO80211Interface *interface,
					   struct apple80211_ssid_data *sd)
{
	IOLog("setSSID \n");
	return 0;
}

SInt32
darwin_iwi2100::setAP_MODE(IO80211Interface *interface,
						  struct apple80211_apmode_data *ad)
{
	IOLog("setAP_MODE \n");
	return 0;
}

bool darwin_iwi2100::attachInterfaceWithMacAddress( void * macAddr, 
												UInt32 macLen, 
												IONetworkInterface ** interface, 
												bool doRegister ,
												UInt32 timeout  )
{
	IOLog("attachInterfaceWithMacAddress \n");
	return super::attachInterfaceWithMacAddress(macAddr,macLen,interface,doRegister,timeout);
}												
												
void darwin_iwi2100::dataLinkLayerAttachComplete( IO80211Interface * interface )											
{
	IOLog("dataLinkLayerAttachComplete \n");
	super::dataLinkLayerAttachComplete(interface);
}


void darwin_iwi2100::queue_te(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, bool start)
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

void darwin_iwi2100::queue_td(int num , thread_call_func_t func)
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

IOReturn darwin_iwi2100::message( UInt32 type, IOService * provider,
                              void * argument)
{
	IOLog("message %8x\n",type);
	return 0;

}

int darwin_iwi2100::ipw2100_is_valid_channel(struct ieee80211_device *ieee, u8 channel)
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

void darwin_iwi2100::ipw2100_create_bssid(struct ipw2100_priv *priv, u8 * bssid)
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

void darwin_iwi2100::ipw2100_adhoc_create(struct ipw2100_priv *priv,
			     struct ieee80211_network *network)
{
	
}

int darwin_iwi2100::ipw2100_is_rate_in_mask(struct ipw2100_priv *priv, int ieee_mode, u8 rate)
{

}

int darwin_iwi2100::ipw2100_compatible_rates(struct ipw2100_priv *priv,
				const struct ieee80211_network *network,
				struct ipw2100_supported_rates *rates)
{
	
}

void darwin_iwi2100::ipw2100_copy_rates(struct ipw2100_supported_rates *dest,
			   const struct ipw2100_supported_rates *src)
{
	
}

int darwin_iwi2100::ipw2100_best_network(struct ipw2100_priv *priv,
			    struct ipw2100_network_match *match,
			    struct ieee80211_network *network, int roaming)
{
	
}

int darwin_iwi2100::ipw2100_associate(ipw2100_priv *data)
{
	
}

void darwin_iwi2100::ipw2100_set_fixed_rate(struct ipw2100_priv *priv, int mode)
{
	
}

int darwin_iwi2100::ipw2100_associate_network(struct ipw2100_priv *priv,
				 struct ieee80211_network *network,
				 struct ipw2100_supported_rates *rates, int roaming)
{

}

void darwin_iwi2100::ipw2100_reset_stats(struct ipw2100_priv *priv)
{
	
}

void darwin_iwi2100::ipw2100_read_indirect(struct ipw2100_priv *priv, u32 addr, u8 * buf,
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
		ipw2100_write32( IPW_INDIRECT_ADDR, aligned_addr);
		/* Start reading at aligned_addr + dif_len */
		for (i = dif_len; ((i < 4) && (num > 0)); i++, num--)
			*buf++ = _ipw_read8(memBase, IPW_INDIRECT_DATA + i);
		aligned_addr += 4;
	}

	/* Read all of the middle dwords as dwords, with auto-increment */
	ipw2100_write32( IPW_AUTOINC_ADDR, aligned_addr);
	for (; num >= 4; buf += 4, aligned_addr += 4, num -= 4)
		*(u32 *) buf = ipw2100_read32( IPW_AUTOINC_DATA);

	/* Read the last dword (or portion) byte by byte */
	if (unlikely(num)) {
		ipw2100_write32( IPW_INDIRECT_ADDR, aligned_addr);
		for (i = 0; num > 0; i++, num--)
			*buf++ = _ipw_read8(memBase, IPW_INDIRECT_DATA + i);
	}
}

void darwin_iwi2100::ipw2100_link_up(struct ipw2100_priv *priv)
{
	
}

void darwin_iwi2100::average_add(struct average *avg, s16 val)
{
	
}

void darwin_iwi2100::ipw2100_gather_stats(struct ipw2100_priv *priv)
{

}

u32 darwin_iwi2100::ipw2100_get_max_rate(struct ipw2100_priv *priv)
{
	
}

u32 darwin_iwi2100::ipw2100_get_current_rate(struct ipw2100_priv *priv)
{
	
}

void darwin_iwi2100::ipw2100_link_down(struct ipw2100_priv *priv)
{
	ipw2100_led_link_down(priv);
	fNetif->setLinkState(kIO80211NetworkLinkDown);
	//netif_carrier_off(priv->net_dev);
	//netif_stop_queue(priv->net_dev);
	//notify_wx_assoc_event(priv);

	/* Cancel any queued work ... */
	queue_td(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_scan));
	queue_td(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_scan_check));
	//cancel_delayed_work(&priv->adhoc_check);
	//cancel_delayed_work(&priv->gather_stats);

	ipw2100_reset_stats(priv);

	if (!(priv->status & STATUS_EXIT_PENDING)) {
		/* Queue up another scan... */
		queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_scan),priv,3,true);
	}
}

const char* darwin_iwi2100::ipw2100_get_status_code(u16 status)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(ipw2100_status_codes); i++)
		if (ipw2100_status_codes[i].status == (status & 0xff))
			return ipw2100_status_codes[i].reason;
	return "Unknown status value.";
}

void darwin_iwi2100::notifIntr(struct ipw2100_priv *priv,
				struct ipw2100_rx_notification *notif)
{
	
}

void darwin_iwi2100::write_nic_memory(struct net_device *dev, u32 addr, u32 len,
			     const u8 * buf)
{
	u32 aligned_addr;
	u32 aligned_len;
	u32 dif_len;
	u32 i;

	/* read first nibble byte by byte */
	aligned_addr = addr & (~0x3);
	dif_len = addr - aligned_addr;
	if (dif_len) {
		/* Start reading at aligned_addr + dif_len */
		write_register(dev, IPW_REG_INDIRECT_ACCESS_ADDRESS,
			       aligned_addr);
		for (i = dif_len; i < 4; i++, buf++)
			write_register_byte(dev,
					    IPW_REG_INDIRECT_ACCESS_DATA + i,
					    *buf);

		len -= dif_len;
		aligned_addr += 4;
	}

	/* read DWs through autoincrement registers */
	write_register(dev, IPW_REG_AUTOINCREMENT_ADDRESS, aligned_addr);
	aligned_len = len & (~0x3);
	for (i = 0; i < aligned_len; i += 4, buf += 4, aligned_addr += 4)
		write_register(dev, IPW_REG_AUTOINCREMENT_DATA, *(u32 *) buf);

	/* copy the last nibble */
	dif_len = len - aligned_len;
	write_register(dev, IPW_REG_INDIRECT_ACCESS_ADDRESS, aligned_addr);
	for (i = 0; i < dif_len; i++, buf++)
		write_register_byte(dev, IPW_REG_INDIRECT_ACCESS_DATA + i,
				    *buf);
}

void darwin_iwi2100::read_register_word(struct net_device *dev, u32 reg,
				      u16 * val)
{
	//*val = readw((void __iomem *)(memBase + reg));
	*val=OSReadLittleInt16(memBase,reg);
	//IOLog("r: 0x%08X => %04X\n", reg, *val);
}

void darwin_iwi2100::read_nic_word(struct net_device *dev, u32 addr, u16 * val)
{
	write_register(dev, IPW_REG_INDIRECT_ACCESS_ADDRESS,
		       addr & IPW_REG_INDIRECT_ADDR_MASK);
	read_register_word(dev, IPW_REG_INDIRECT_ACCESS_DATA, val);
}

void darwin_iwi2100::read_nic_byte(struct net_device *dev, u32 addr, u8 * val)
{
	write_register(dev, IPW_REG_INDIRECT_ACCESS_ADDRESS,
		       addr & IPW_REG_INDIRECT_ADDR_MASK);
	read_register_byte(dev, IPW_REG_INDIRECT_ACCESS_DATA, val);
}

void darwin_iwi2100::write_register_byte(struct net_device *dev, u32 reg, u8 val)
{
	//writeb(val, (void __iomem *)(memBase + reg));
	*((UInt8 *)memBase + reg) = (UInt8)val;
	//IOLog("w: 0x%08X =< %02X\n", reg, val);
}

void darwin_iwi2100::write_nic_byte(struct net_device *dev, u32 addr, u8 val)
{
	write_register(dev, IPW_REG_INDIRECT_ACCESS_ADDRESS,
		       addr & IPW_REG_INDIRECT_ADDR_MASK);
	write_register_byte(dev, IPW_REG_INDIRECT_ACCESS_DATA, val);
}

void darwin_iwi2100::write_nic_word(struct net_device *dev, u32 addr, u16 val)
{
	write_register(dev, IPW_REG_INDIRECT_ACCESS_ADDRESS,
		       addr & IPW_REG_INDIRECT_ADDR_MASK);
	write_register_word(dev, IPW_REG_INDIRECT_ACCESS_DATA, val);
}

void darwin_iwi2100::write_register_word(struct net_device *dev, u32 reg, u16 val)
{
	//writew(val, (void __iomem *)(memBase + reg));
	OSWriteLittleInt16(memBase,reg,val);
	//IOLog("w: 0x%08X <= %04X\n", reg, val);
}

void darwin_iwi2100::write_nic_dword(struct net_device *dev, u32 addr, u32 val)
{
	write_register(dev, IPW_REG_INDIRECT_ACCESS_ADDRESS,
		       addr & IPW_REG_INDIRECT_ADDR_MASK);
	write_register(dev, IPW_REG_INDIRECT_ACCESS_DATA, val);
}

void darwin_iwi2100::read_register(struct net_device *dev, u32 reg, u32 * val)
{
	//*val = readl((void __iomem *)(memBase + reg));
	*val=OSReadLittleInt32(memBase,reg);
	//IOLog("r: 0x%08X => 0x%08X\n", reg, *val);
}

void darwin_iwi2100::write_register(struct net_device *dev, u32 reg, u32 val)
{
	//writel(val, (void __iomem *)(memBase + reg));
	OSWriteLittleInt32(memBase,reg,val);
	//IOLog("w: 0x%08X <= 0x%08X\n", reg, val);
}

void darwin_iwi2100::read_nic_dword(struct net_device *dev, u32 addr, u32 * val)
{
	write_register(dev, IPW_REG_INDIRECT_ACCESS_ADDRESS,
		       addr & IPW_REG_INDIRECT_ADDR_MASK);
	read_register(dev, IPW_REG_INDIRECT_ACCESS_DATA, val);
}

void darwin_iwi2100::read_register_byte(struct net_device *dev, u32 reg, u8 * val)
{
	//*val = readb((void __iomem *)(memBase + reg));
	*val= (UInt8)*((UInt8 *)memBase + reg);
	//IOLog("r: 0x%08X => %02X\n", reg, *val);
}

void darwin_iwi2100::read_nic_memory(struct net_device *dev, u32 addr, u32 len, u8 * buf)
{
	u32 aligned_addr;
	u32 aligned_len;
	u32 dif_len;
	u32 i;

	/* read first nibble byte by byte */
	aligned_addr = addr & (~0x3);
	dif_len = addr - aligned_addr;
	if (dif_len) {
		/* Start reading at aligned_addr + dif_len */
		write_register(dev, IPW_REG_INDIRECT_ACCESS_ADDRESS,
			       aligned_addr);
		for (i = dif_len; i < 4; i++, buf++)
			read_register_byte(dev,
					   IPW_REG_INDIRECT_ACCESS_DATA + i,
					   buf);

		len -= dif_len;
		aligned_addr += 4;
	}

	/* read DWs through autoincrement registers */
	write_register(dev, IPW_REG_AUTOINCREMENT_ADDRESS, aligned_addr);
	aligned_len = len & (~0x3);
	for (i = 0; i < aligned_len; i += 4, buf += 4, aligned_addr += 4)
		read_register(dev, IPW_REG_AUTOINCREMENT_DATA, (u32 *) buf);

	/* copy the last nibble */
	dif_len = len - aligned_len;
	write_register(dev, IPW_REG_INDIRECT_ACCESS_ADDRESS, aligned_addr);
	for (i = 0; i < dif_len; i++, buf++)
		read_register_byte(dev, IPW_REG_INDIRECT_ACCESS_DATA + i, buf);
}

