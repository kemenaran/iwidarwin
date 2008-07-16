#include "firmware/iwi_bss.fw.h"
#include "firmware/iwi_ibss.fw.h"
#include "firmware/iwi_mon.fw.h"
#include "defines.h"

//			<string>0x25208086 0x25218086 0x25248086 0x25258086 0x25268086 0x25228086 0x25238086 0x25278086 0x25288086 0x25298086 0x252B8086 0x252C8086 0x252D8086 0x25508086 0x25518086 0x25538086 0x25548086 0x25558086 0x25608086 0x25628086 0x25638086 0x25618086 0x25658086 0x25668086 0x25678086 0x25708086 0x25808086 0x25828086 0x25838086 0x25818086 0x25858086 0x25868086 0x25878086 0x25908086 0x25928086 0x25918086 0x25938086 0x25968086 0x25988086 0x25A08086</string>
// 0x10438086

// Define my superclass
#define super IOEthernetController
//IO80211Controller
// REQUIRED! This macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires. Do NOT use super as the
// second parameter. You must use the literal name of the superclass.
OSDefineMetaClassAndStructors(darwin_iwi2100, IOEthernetController);//IO80211Controller);

//clone of the driver class, used in all the kext control functions.

static darwin_iwi2100 *clone;


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

 IWI_DEBUG("disable %d mode %d\n",disable2, mode);

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
		IWI_DEBUG_FULL
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
	}

}

int darwin_iwi2100::ipw2100_tx_allocate(struct ipw2100_priv *priv)
{
	int i, j, err = -EINVAL;
	void *v;
	dma_addr_t p;


	err = bd_queue_allocate(priv, &priv->tx_queue, TX_QUEUE_LENGTH);
	if (err) {
		IWI_DEBUG_FULL("%s: failed bd_queue_allocate\n",
				priv->net_dev->name);
		return err;
	}

	priv->tx_buffers =
	    (struct ipw2100_tx_packet *)IOMalloc(TX_PENDED_QUEUE_LENGTH *
						sizeof(struct
						       ipw2100_tx_packet));
	if (!priv->tx_buffers) {
		IWI_DEBUG_FULL( 
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
			IWI_DEBUG_FULL( 
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

	IOFree(priv->tx_buffers, TX_PENDED_QUEUE_LENGTH *
						sizeof(struct
						       ipw2100_tx_packet));
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
		IWI_DEBUG_FULL("Can not allocate status queue.\n");
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
	/*if (mbuf_getpacket(MBUF_WAITOK , &packet->skb)!=0) 
	{
		IWI_LOG("no mem for skb\n");
		return -ENOMEM; 
	}*/
	packet->skb = allocatePacket(sizeof(struct ipw2100_rx));
	if (!packet->skb)
		return -ENOMEM;
	mbuf_setlen(packet->skb,0);
	mbuf_pkthdr_setlen(packet->skb,0);
		
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
		IWI_DEBUG_FULL("failed bd_queue_allocate\n");
		return err;
	}

	err = status_queue_allocate(priv, RX_QUEUE_LENGTH);
	if (err) {
		IWI_DEBUG_FULL("failed status_queue_allocate\n");
		bd_queue_free(priv, &priv->rx_queue);
		return err;
	}

	/*
	 * allocate packets
	 */
	priv->rx_buffers = (struct ipw2100_rx_packet *)
	    IOMalloc(RX_QUEUE_LENGTH * sizeof(struct ipw2100_rx_packet)  );
	if (!priv->rx_buffers) {
		IWI_DEBUG_FULL("can't allocate rx packet buffer table\n");

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
		
		if (priv->rx_buffers[j].skb)
		if (!(mbuf_type(priv->rx_buffers[j].skb) == MBUF_TYPE_FREE) ) freePacket(priv->rx_buffers[j].skb);
		priv->rx_buffers[j].dma_addr=NULL;
		/*pci_unmap_single(priv->pci_dev, priv->rx_buffers[j].dma_addr,
				 sizeof(struct ipw2100_rx_packet),
				 PCI_DMA_FROMDEVICE);
		dev_kfree_skb(priv->rx_buffers[j].skb);*/
	}

	IOFree(priv->rx_buffers, RX_QUEUE_LENGTH * sizeof(struct ipw2100_rx_packet));
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
	    (struct ipw2100_tx_packet *)IOMalloc(IPW_COMMAND_POOL_SIZE *
						sizeof(struct
						       ipw2100_tx_packet)			);
	if (!priv->msg_buffers) {
		IWI_DEBUG_FULL(  ": %s: PCI alloc failed for msg "
		       "buffers.\n", priv->net_dev->name);
		return -ENOMEM;
	}

	for (i = 0; i < IPW_COMMAND_POOL_SIZE; i++) {
		MemoryDmaAlloc(sizeof(struct ipw2100_cmd_header), &p, &v);
		/*v = pci_alloc_consistent(priv->pci_dev,
					 sizeof(struct ipw2100_cmd_header), &p);*/
		if (!v) {
			IWI_DEBUG_FULL(  ": "
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

	IOFree(priv->msg_buffers, IPW_COMMAND_POOL_SIZE *
						sizeof(struct
						       ipw2100_tx_packet));
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
			if (!(mbuf_type(txb->fragments[i]) == MBUF_TYPE_FREE) ) freePacket(txb->fragments[i]);
			txb->fragments[i]=NULL;
			
		}
	IOFree(txb,sizeof(struct ieee80211_txb) + (sizeof(u8 *) * txb->nr_frags));
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

	IOFree(priv->tx_buffers, TX_PENDED_QUEUE_LENGTH *
						sizeof(struct
						       ipw2100_tx_packet));
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
			if (priv->rx_buffers[i].skb)
			if (!(mbuf_type(priv->rx_buffers[i].skb) == MBUF_TYPE_FREE) ) freePacket(priv->rx_buffers[i].skb);
		}
	}

	IOFree(priv->rx_buffers, RX_QUEUE_LENGTH * sizeof(struct ipw2100_rx_packet));
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

	IOFree(priv->msg_buffers,IPW_COMMAND_POOL_SIZE *
						sizeof(struct
						       ipw2100_tx_packet));
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

	IWI_DEBUG("initializing bd queue at virt=%p, phys=%08x\n", q->drv,
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
		IWI_DEBUG_FULL("Unable to network device.\n");
		return -1;
	}
	//(UInt16*)net_dev->base_addr=memBase;
	//ieee = (struct ieee80211_device*)netdev_priv(net_dev);
	ieee=&ieee2;
	ieee->dev = net_dev;

//        // if getHarwareAddress is called, put macaddress priv->mac_addr
//        for (i=0;i<6;i++){
//                if(fEnetAddr.bytes[i] == 0      ) continue;
//                memcpy(priv->mac_addr, &fEnetAddr.bytes, ETH_ALEN);
//                memcpy(priv->net_dev->dev_addr, &fEnetAddr.bytes, ETH_ALEN);
//                memcpy(priv->ieee->dev->dev_addr, &fEnetAddr.bytes, ETH_ALEN);
//                break;
//        }

	(void*)ieee->networks = IOMalloc(MAX_NETWORK_COUNT * sizeof(struct ieee80211_network));
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

	if (disable2)
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

	IWI_DEBUG_FULL("ipw2100_queues_allocate.\n");
	/* Allocate and initialize the Tx/Rx queues and lists */
	if (ipw2100_queues_allocate(priv)) {
		IWI_DEBUG_FULL(
		       "Error in ipw2100_queues_allocate.\n");
	}
	ipw2100_queues_initialize(priv);

	//ipw2100_initialize_ordinals(priv);
	
	IWI_DEBUG(": Detected Intel PRO/Wireless 2100 Network Connection\n");
	//pl=1;
	//ipw2100_up(priv,1);
	/*if (!(priv->status & STATUS_RF_KILL_MASK)) {
		if (ipw2100_enable_adapter(priv)) {
			IWI_DEBUG(
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

	IWI_DEBUG("CARD_DISABLE_PHY_OFF\n");

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
			IWI_DEBUG_FULL(
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
		IWI_DEBUG_FULL("HOST_PRE_POWER_DOWN\n");

		err = ipw2100_hw_send_command(priv, &cmd);
		if (err)
			IWI_DEBUG_FULL(  ": "
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
		IWI_DEBUG_FULL( 
		       ": %s: Could now power down adapter.\n",
		       priv->net_dev->name);

	/* assert s/w reset */
	write_register(priv->net_dev, IPW_REG_RESET_REG,
		       IPW_AUX_HOST_RESET_REG_SW_RESET);

	IWI_DEBUG_FULL( "Adapter Stopped.\n");
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

	IWI_DEBUG_FULL("START_SCAN\n");

	cmd.host_command_parameters[0] = 0;

	/* No scanning if in monitor mode */
	if (priv->ieee->iw_mode == IW_MODE_MONITOR || priv->status & STATUS_RF_KILL_SW)
		return 1;

	if (priv->status & STATUS_SCANNING) {
		IWI_DEBUG_FULL("Scan requested while already in scan...\n");
		return 0;
	}


	/* Not clearing here; doing so makes iwlist always return nothing...
	 *
	 * We should modify the table logic to use aging tables vs. clearing
	 * the table on each scan start.
	 */
	IWI_DEBUG("starting scan\n");

	priv->status |= STATUS_SCANNING;
	err = ipw2100_hw_send_command(priv, &cmd);
	if (err)
		priv->status &= ~STATUS_SCANNING;


	return err;
}

mbuf_t darwin_iwi2100::mergePacket(mbuf_t m)
{
	mbuf_t nm,nm2;
	int offset;
	if(!mbuf_next(m))
	{
		//offset = (4 - ((int)(mbuf_data(m)) & 3)) % 4;    //packet needs to be 4 byte aligned
		offset = (1 - ((int)(mbuf_data(m)) & 3)) % 1;   
		if (offset==0) return m;
		IWI_DEBUG_FULL("this packet dont have mbuf_next, merge  is not required\n");
		goto copy_packet;
	}

	/* allocate and Initialize New mbuf */
	nm = allocatePacket(mbuf_pkthdr_len(m));
	if (nm==0) return NULL;
	//if (mbuf_getpacket(MBUF_WAITOK, &nm)!=0) return NULL;
	mbuf_setlen(nm,0);
	mbuf_pkthdr_setlen(nm,0);
	if( mbuf_next(nm)) IWI_ERR("merged mbuf_next\n");
	
	/* merging chains to single mbuf */
	for (nm2 = m; nm2;  nm2 = mbuf_next(nm2)) {
		bcopy (mbuf_data(nm2), skb_put (nm, mbuf_len(nm2)), mbuf_len(nm2));
		//skb_put (nm, mbuf_len(nm2));
		//mbuf_copyback(nm, mbuf_len(nm), mbuf_len(nm2), mbuf_data(nm2), MBUF_WAITOK);
	}
	/* checking if merged or not. */
	if( mbuf_len(nm) == mbuf_pkthdr_len(m) ) 
	{
		if (m!=NULL)
		if (!(mbuf_type(m) == MBUF_TYPE_FREE)) freePacket(m);
		m=NULL;
		return nm;
	}
	/* merging is not completed. */
	IWI_WARN("mergePacket is failed: data copy dont work collectly\n");
	IWI_WARN("orig_len %d orig_pktlen %d new_len  %d new_pktlen  %d\n",
					mbuf_len(m),mbuf_pkthdr_len(m),
					mbuf_len(nm),mbuf_pkthdr_len(nm) );
	if (m!=NULL)
	if (!(mbuf_type(m) == MBUF_TYPE_FREE)) freePacket(m);
	m=NULL;
	if (nm!=NULL)
	if (!(mbuf_type(nm) == MBUF_TYPE_FREE) ) freePacket(nm);
	nm=NULL;
	return NULL;

copy_packet: 
		if (mbuf_dup(m, MBUF_WAITOK , &nm)!=0)
		{
			if (m!=NULL)
			if (!(mbuf_type(m) == MBUF_TYPE_FREE)) freePacket(m);
			m=NULL;
			return NULL;
		}
		if (m!=NULL)
		if (!(mbuf_type(m) == MBUF_TYPE_FREE) ) freePacket(m);
		m=NULL;
		return nm;
		//return copyPacket(m, 0); 
}

void darwin_iwi2100::freePacket2(mbuf_t m)
{
}

void darwin_iwi2100::getPacketBufferConstraints(IOPacketBufferConstraints * constraints) const {
    constraints->alignStart  = kIOPacketBufferAlign1;	// even word aligned.
    constraints->alignLength = kIOPacketBufferAlign1;	// no restriction.
}

int darwin_iwi2100::ipw2100_set_scan_options(struct ipw2100_priv *priv)
{
	struct host_command cmd;// = {
		cmd.host_command = SET_SCAN_OPTIONS;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = 8;
	//};
	int err;


	IWI_DEBUG_FULL("setting scan options\n");

	cmd.host_command_parameters[0] = 0;

	if (!(priv->config & CFG_ASSOCIATE))
		cmd.host_command_parameters[0] |= IPW_SCAN_NOASSOCIATE;
	if ((priv->ieee->sec.flags & SEC_ENABLED) && priv->ieee->sec.enabled)
		cmd.host_command_parameters[0] |= IPW_SCAN_MIXED_CELL;
	if (priv->config & CFG_PASSIVE_SCAN)
		cmd.host_command_parameters[0] |= IPW_SCAN_PASSIVE;

	cmd.host_command_parameters[1] = priv->channel_mask;

	err = ipw2100_hw_send_command(priv, &cmd);

	IWI_DEBUG_FULL("SET_SCAN_OPTIONS 0x%04X\n",
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

	IWI_DEBUG_FULL("table 1 size: %d\n", ord->table1_size);
	IWI_DEBUG_FULL("table 2 size: %d\n", ord->table2_size);
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
		IWI_DEBUG_FULL( ": attempt to use fw ordinals "
		       "before they have been loaded.\n");
		return -EINVAL;
	}

	if (IS_ORDINAL_TABLE_ONE(ordinals, ord)) {
		if (*len < IPW_ORD_TAB_1_ENTRY_SIZE) {
			*len = IPW_ORD_TAB_1_ENTRY_SIZE;

			IWI_DEBUG_FULL(
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

	IWI_DEBUG( ": ordinal %d neither in table 1 nor "
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
			IWI_DEBUG("Query of CARD_DISABLED ordinal "
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

	IWI_DEBUG("ipw2100_wait_for_card_state to %s state timed out\n",
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
			IWI_DEBUG("no room in tx_queue\n");
			break;
		}

		element = priv->msg_pend_list.next;
		list_del(element);
		DEC_STAT(&priv->msg_pend_stat);

		packet = list_entry(element, struct ipw2100_tx_packet, list);

		IWI_DEBUG_FULL("using TBD at virt=%p, phys=%p\n",
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
			IWI_DEBUG_FULL("%s: Maximum BD theshold exceeded.  "
				       "Increase fragmentation level.\n",
				       priv->net_dev->name);
		}

		if (txq->available <= 3 + packet->info.d_struct.txb->nr_frags) {
			IWI_DEBUG("no room in tx_queue\n");
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

		IWI_DEBUG_FULL("data header tbd TX%d P=%08x L=%d\n",
			     packet->index, tbd->host_addr, tbd->buf_length);
//#ifdef CONFIG_IPW2100_DEBUG
		if (packet->info.d_struct.txb->nr_frags > 1)
			IWI_DEBUG_FULL("fragment Tx: %d frames\n",
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
			tbd->host_addr=mbuf_data_to_physical((UInt8*)mbuf_data(packet->info.d_struct.
							txb->fragments[i])+IEEE80211_3ADDR_LEN);
			IWI_DEBUG_FULL("data frag tbd TX%d P=%08x L=%d\n",
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

	IWI_DEBUG_FULL("Sending %s command (#%d), %d bytes\n",
		     command_types[cmd->host_command], cmd->host_command,
		     cmd->host_command_length);


	//spin_lock_irqsave(&priv->low_lock, flags);

	if (priv->fatal_error) {
		IWI_DEBUG
		    ("Attempt to send command while hardware in fatal error condition.\n");
		err = -EIO;
		goto fail_unlock;
	}

	if (!(priv->status & STATUS_RUNNING)) {
		IWI_DEBUG
		    ("Attempt to send command while hardware is not running.\n");
		err = -EIO;
		goto fail_unlock;
	}

	if (priv->status & STATUS_CMD_ACTIVE) {
		IWI_DEBUG
		    ("Attempt to send command while another command is pending.\n");
		err = -EBUSY;
		goto fail_unlock;
	}

	if (list_empty(&priv->msg_free_list)) {
		IWI_DEBUG("no available msg buffers\n");
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
		IODelay(2*HZ);
		if (err==1000) break;
	}
	if (err == 1000) {
		IWI_DEBUG("Command completion failed out \n");//;after %dms.\n",
			      // 1000 * (HOST_COMPLETE_TIMEOUT / HZ));
		//priv->fatal_error = IPW2100_ERR_MSG_TIMEOUT;
		//priv->status &= ~STATUS_CMD_ACTIVE;
		//schedule_reset(priv);
		return -EIO;
	}

	if (priv->fatal_error) {
		IWI_DEBUG( ": %s: firmware fatal error\n",
		       priv->net_dev->name);
		return -EIO;
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
		IWI_DEBUG("%s: Hardware fatal error detected.\n",
			       priv->net_dev->name);

		restart = 1;
	} else if (ipw2100_get_ordinal(priv, IPW_ORD_RTC_TIME, &rtc, &len) ||
		   (rtc == priv->last_rtc)) {
		/* Check if firmware is hung */
		IWI_DEBUG("%s: Firmware RTC stalled.\n",
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
	queue_te(7,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_hang_check),priv,1000,true);
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

	IWI_DEBUG_FULL("HOST_COMPLETE\n");

	if (priv->status & STATUS_ENABLED)
		return 0;


	if (rf_kill_active(priv)) {
		IWI_DEBUG("Command aborted due to RF kill active.\n");
		goto fail_up;
	}

	err = ipw2100_hw_send_command(priv, &cmd);
	if (err) {
		IWI_DEBUG("Failed to send HOST_COMPLETE command\n");
		goto fail_up;
	}

	err = ipw2100_wait_for_card_state(priv, IPW_HW_STATE_ENABLED);
	if (err) {
		IWI_DEBUG("%s: card not responding to init command.\n",
			       priv->net_dev->name);
		goto fail_up;
	}

	if (priv->stop_hang_check) {
		priv->stop_hang_check = 0;
		queue_te(7,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_hang_check),priv,1000,true);
		//queue_delayed_work(priv->workqueue, &priv->hang_check, HZ / 2);
	}

      fail_up:
	return err;
}

IOOptionBits darwin_iwi2100::getState( void ) const
{
	IOOptionBits r=super::getState();
	IWI_DEBUG("getState = %x\n",r);
	return r;
}

bool darwin_iwi2100::start(IOService *provider)
{
	UInt16	reg;
	//linking the kext control clone to the driver:
		clone=this;
	firstifup=0;
	do {
				
		if ( super::start(provider) == 0) {
			IWI_DEBUG("%s ERR: super::start failed\n", getName());
			break;
		}
			
		if ( (fPCIDevice = OSDynamicCast(IOPCIDevice, provider)) == 0) {
			IWI_DEBUG("%s ERR: fPCIDevice == 0 :(\n", getName());
			break;
		}

		fPCIDevice->retain();
		
		if (fPCIDevice->open(this) == 0) {
			IWI_DEBUG("%s ERR: fPCIDevice->open(this) failed\n", getName());
			break;
		}
		
		// Request domain power.
        	// Without this, the PCIDevice may be in state 0, and the
        	// PCI config space may be invalid if the machine has been
       		// sleeping.
		if (fPCIDevice->requestPowerDomainState(kIOPMPowerOn, 
			(IOPowerConnection *) getParentEntry(gIOPowerPlane),
			IOPMLowestState ) != IOPMNoErr) {
				IWI_DEBUG("%s Power thingi failed\n", getName());
				break;
       		}

		UInt16 reg16;
		
		reg16 = fPCIDevice->configRead16(kIOPCIConfigCommand);
		reg16 |= (kIOPCICommandBusMaster      | 
				  kIOPCICommandMemorySpace    |
				  kIOPCICommandMemWrInvalidate);

		reg16 &= ~kIOPCICommandIOSpace;  // disable I/O space
		fPCIDevice->configWrite16(kIOPCIConfigCommand,reg16);
		
		irqNumber = fPCIDevice->configRead8(kIOPCIConfigInterruptLine);
		vendorID = fPCIDevice->configRead16(kIOPCIConfigVendorID);
		deviceID = fPCIDevice->configRead16(kIOPCIConfigDeviceID);		
		pciReg = fPCIDevice->configRead16(kIOPCIConfigRevisionID);

  		map = fPCIDevice->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0, kIOMapInhibitCache);
  		if (map == 0) {
			IWI_DEBUG("%s map is zero\n", getName());
			break;
		}
		//ioBase = map->getPhysicalAddress();
		memBase = (UInt16 *)map->getVirtualAddress();
		//memDes = map->getMemoryDescriptor();
		//mem = fPCIDevice->getDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0);
		
		//memDes->initWithPhysicalAddress(ioBase, map->getLength(), kIODirectionOutIn);
		
		/* We disable the RETRY_TIMEOUT register (0x41) to keep
		 * PCI Tx retries from interfering with C3 CPU state */
		reg = fPCIDevice->configRead16(0x40);
		if((reg & 0x0000ff00) != 0)
			fPCIDevice->configWrite16(0x40, reg & 0xffff00ff);
			

		//IWI_DEBUG("%s iomemory length: 0x%x @ 0x%x\n", getName(), map->getLength(), ioBase);
		//IWI_DEBUG("%s virt: 0x%x physical: 0x%x\n", getName(), memBase, ioBase);
		//IWI_DEBUG("%s IRQ: %d, Vendor ID: %04x, Product ID: %04x\n", getName(), irqNumber, vendorID, deviceID);
		
		fWorkLoop = (IOWorkLoop *) getWorkLoop();
		if (!fWorkLoop) {
			IWI_DEBUG("%s ERR: start - getWorkLoop failed\n", getName());
			break;
		}
		fInterruptSrc = IOInterruptEventSource::interruptEventSource(
			this, (IOInterruptEventAction) &darwin_iwi2100::interruptOccurred,
			provider);
		if(!fInterruptSrc || (fWorkLoop->addEventSource(fInterruptSrc) != kIOReturnSuccess)) {
			IWI_DEBUG("%s fInterruptSrc error\n", getName());
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
		//ipw2100_initialize_ordinals(priv);
		//ipw2100_reset_nic(priv);
		//ipw2100_stop_nic();
		pl=1;
		ipw2100_up(priv,1);
		//ipw2100_initialize_ordinals(priv);
		
		if (attachInterface((IONetworkInterface **) &fNetif, false) == false) {
			IWI_DEBUG("%s attach failed\n", getName());
			break;
		}
		setProperty(kIOMinPacketSize,12);
		setProperty(kIOMaxPacketSize, IPW_RX_BUF_SIZE);
	
		fNetif->registerOutputHandler(this,getOutputHandler());

		fNetif->registerService();
				
		registerService();

		
		mediumDict = OSDictionary::withCapacity(MEDIUM_TYPE_INVALID + 1);
		addMediumType(kIOMediumIEEE80211None,  0,  MEDIUM_TYPE_NONE);
		addMediumType(kIOMediumIEEE80211Auto,  0,  MEDIUM_TYPE_AUTO);


		publishMediumDictionary(mediumDict);
		setCurrentMedium(mediumTable[MEDIUM_TYPE_AUTO]);
		setSelectedMedium(mediumTable[MEDIUM_TYPE_AUTO]);
		setLinkStatus(kIONetworkLinkValid, mediumTable[MEDIUM_TYPE_AUTO]);
		
		
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
		queue_te(8,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_reset_adapter),NULL,NULL,false);
		queue_te(9,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_wx_event_work),NULL,NULL,false);
		queue_te(10,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::check_firstup),NULL,NULL,false);
		
		//ipw2100_sw_reset(1);

		queue_te(10,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::check_firstup),priv,1000,true);
		return true;			// end start successfully
	} while (false);
		
	//stop(provider);
	free();
	return false;			// end start insuccessfully
}

void darwin_iwi2100::check_firstup(struct ipw2100_priv *priv)
{
	if (firstifup==0) 
	{
		queue_te(10,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::check_firstup),priv,1000,true);
		return;
	}
	disable(fNetif);
	pl=1;
	ipw2100_up(priv,0);
	
}

IOReturn darwin_iwi2100::selectMedium(const IONetworkMedium * medium)
{
	bool  r;

	if ( OSDynamicCast(IONetworkMedium, medium) == 0 )
    {
        // Defaults to Auto.
		medium = mediumTable[MEDIUM_TYPE_AUTO];
        if ( medium == 0 ) {
		IWI_DEBUG("selectMedium failed\n");
		return kIOReturnError;
	}
    }

	// Program PHY to select the desired medium.
	//r = _phySetMedium( (mediumType_t) medium->getIndex() );

	if ( r && !setCurrentMedium(medium) )
		IWI_DEBUG("%s: setCurrentMedium error\n", getName());

	IWI_DEBUG("Medium is set to: %s\n", medium->getName()->getCStringNoCopy());
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
		IWI_DEBUG("wait for reg master disabled failed after 500ms\n");
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
		IWI_DEBUG("FAILED wait for clock stablization\n");

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
	priv->status &= ~STATUS_CMD_ACTIVE;
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
	write_register(priv->net_dev, IPW_REG_INTA_MASK, IPW_INTERRUPT_MASK);
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
	unsigned long now = jiffies;//get_seconds();

	IWI_DEBUG_FULL("schedule_reset\n");
	if (priv->reset_backoff &&
	    (now - priv->last_reset > priv->reset_backoff))
		priv->reset_backoff = 0;

	priv->last_reset = jiffies;//get_seconds();

	if (!(priv->status & STATUS_RESET_PENDING)) {
		IWI_DEBUG("%s: Scheduling firmware restart (%ds).\n",
			       priv->net_dev->name, priv->reset_backoff);
		//netif_carrier_off(priv->net_dev);
		setLinkStatus(kIONetworkLinkValid);
		//fTransmitQueue->stop();
		//netif_stop_queue(priv->net_dev);
		priv->status |= STATUS_RESET_PENDING;
		if (priv->reset_backoff)
			//queue_delayed_work(priv->workqueue, &priv->reset_work,  priv->reset_backoff * HZ);
			queue_te(8,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_reset_adapter),priv,1000,true);
		else
			//queue_delayed_work(priv->workqueue, &priv->reset_work,  0);
			queue_te(8,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_reset_adapter),priv,NULL,true);

		if (priv->reset_backoff < MAX_RESET_BACKOFF)
			priv->reset_backoff++;

		//wake_up_interruptible(&priv->wait_command_queue);
	} else
		IWI_DEBUG("%s: Firmware restart already in progress.\n",
			       priv->net_dev->name);

}

void darwin_iwi2100::ipw2100_reset_adapter(struct ipw2100_priv *priv)
{
	unsigned long flags;
	/*union iwreq_data wrqu = {
		.ap_addr = {
			    .sa_family = ARPHRD_ETHER}
	};*/
	int associated = priv->status & STATUS_ASSOCIATED;

	//spin_lock_irqsave(&priv->low_lock, flags);
	IWI_DEBUG(": %s: Restarting adapter.\n", priv->net_dev->name);
	priv->resets++;
	priv->status &= ~(STATUS_ASSOCIATED | STATUS_ASSOCIATING);
	priv->status |= STATUS_SECURITY_UPDATED;

	/* Force a power cycle even if interface hasn't been opened
	 * yet */
	//cancel_delayed_work(&priv->reset_work);
	//queue_td(8,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_reset_adapter));
	priv->status |= STATUS_RESET_PENDING;
	//spin_unlock_irqrestore(&priv->low_lock, flags);

	//mutex_lock(&priv->action_mutex);
	/* stop timed checks so that they don't interfere with reset */
	priv->stop_hang_check = 1;
	//cancel_delayed_work(&priv->hang_check);
	queue_td(7,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_hang_check));

	/* We have to signal any supplicant if we are disassociating */
	//if (associated)
	//	wireless_send_event(priv->net_dev, SIOCGIWAP, &wrqu, NULL);
	pl=1;
	
	ipw2100_up(priv, 0);
	//mutex_unlock(&priv->action_mutex);

}

void darwin_iwi2100::ipw2100_rf_kill(ipw2100_priv *priv)
{
	unsigned long flags;

	//spin_lock_irqsave(&priv->low_lock, flags);

	if (rf_kill_active(priv) || (priv->status & STATUS_RF_KILL_SW)) {
		IWI_DEBUG("RF Kill active, rescheduling GPIO check\n");
		if (!priv->stop_rf_kill)
		queue_te(3,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_rf_kill),priv,2000,true);
		//	queue_delayed_work(priv->workqueue, &priv->rf_kill, HZ);
		goto exit_unlock;
	}

	/* RF Kill is now disabled, so bring the device back up */

	if (!(priv->status & STATUS_RF_KILL_MASK)) {
		IWI_DEBUG("HW RF Kill no longer active, restarting "
				  "device\n");
		schedule_reset(priv);
	} else
		IWI_DEBUG("HW RF Kill deactivated.  SW RF Kill still "
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

/*IOReturn darwin_iwi2100::setPowerState ( unsigned long powerStateOrdinal, IOService* whatDevice )
{
	IWI_DEBUG("setPowerState to %d\n",powerStateOrdinal);
	power=powerStateOrdinal;
	return super::setPowerState(powerStateOrdinal,whatDevice);
}*/

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

	IWI_DEBUG("Power cycling the hardware.\n");

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
		IWI_DEBUG
		    ("exit - waited too long for master assert stop\n");
		return -EIO;
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
	//return 0;
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
		IWI_DEBUG( ": %s: Error initializing Symbol\n",
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
		IWI_DEBUG( 
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
			IWI_DEBUG( ": "
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
		IWI_DEBUG("%s: ipw2100_download_firmware called after "
				"fatal error %d.  Interface must be brought down.\n",
				priv->net_dev->name, priv->fatal_error);
		//return -EINVAL;
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
		IWI_DEBUG(  ": Firmware image not compatible "
		       "(detected version id of %d). "
		       "See Documentation/networking/README.ipw2100\n",
		       h->version);
		//return 1;
	}

	ipw2100_firmware->version = h->version;
	ipw2100_firmware->fw.data = ipw2100_firmware->fw_entry->data + sizeof(struct ipw2100_fw_header);
	ipw2100_firmware->fw.size = h->fw_size;
	ipw2100_firmware->uc.data = (UInt8*)ipw2100_firmware->fw.data + h->fw_size;
	ipw2100_firmware->uc.size = h->uc_size;

	IWI_DEBUG("fw version %d s: %d uc s:%d\n",ipw2100_firmware->version,ipw2100_firmware->fw.size,ipw2100_firmware->uc.size );
	/*err = ipw2100_get_firmware(priv, &ipw2100_firmware);
	if (err) {
		IWI_DEBUG("%s: ipw2100_get_firmware failed: %d\n",
				priv->net_dev->name, err);
		priv->fatal_error = IPW2100_ERR_FW_LOAD;
		goto fail;
	}*/
	priv->firmware_version = ipw2100_firmware->version;

	/* s/w reset and clock stabilization */
	err = sw_reset_and_clock(priv);
	if (err) {
		IWI_DEBUG("%s: sw_reset_and_clock failed: %d\n",
				priv->net_dev->name, err);
		//goto fail;
	}
	err = ipw2100_verify(priv);
	if (err) {
		IWI_DEBUG("%s: ipw2100_verify failed: %d\n",
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
		IWI_DEBUG(": %s: Error loading microcode: %d\n",
		       priv->net_dev->name, err);
		//goto fail;
	}

	/* release ARC */
	write_nic_dword(priv->net_dev,
			IPW_INTERNAL_REGISTER_HALT_AND_RESET, 0x00000000);

	/* s/w reset and clock stabilization (again!!!) */
	err = sw_reset_and_clock(priv);
	if (err) {
		IWI_DEBUG(
		       ": %s: sw_reset_and_clock failed: %d\n",
		       priv->net_dev->name, err);
		//goto fail;
	}

	/* load f/w */
	err = ipw2100_fw_download(priv, ipw2100_firmware);
	if (err) {
		IWI_DEBUG("%s: Error loading firmware: %d\n",
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
		IWI_DEBUG(
		       ": %s: Failed to power on the adapter.\n",
		       priv->net_dev->name);
		//return -EIO;
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
	IWI_DEBUG("Waiting for f/w initialization to complete...\n");
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

	IWI_DEBUG("f/w initialization complete: %s\n",
		     i ? "SUCCESS" : "FAILED");

	if (!i) {
		IWI_DEBUG(
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
		IWI_DEBUG("failed querying ordinals at line %d\n",
			       __LINE__);
		return -EIO;
	}

	IWI_DEBUG("EEPROM address: %08X\n", addr);
					   
	/*
	 * EEPROM version is the byte at offset 0xfd in firmware
	 * We read 4 bytes, then shift out the byte we actually want */
	read_nic_dword(priv->net_dev, addr + 0xFC, &val);
	priv->eeprom_version = (val >> 24) & 0xFF;
	IWI_DEBUG("EEPROM version: %d\n", priv->eeprom_version);

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

	IWI_DEBUG("HW RF Kill: %ssupported.\n",
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
			IWI_DEBUG("wrong size\n");
			return -EINVAL;
		}

		read_nic_dword(priv->net_dev,
			       ordinals->table1_addr + (ord << 2), &addr);

		write_nic_dword(priv->net_dev, addr, *val);

		*len = IPW_ORD_TAB_1_ENTRY_SIZE;

		return 0;
	}

	IWI_DEBUG("wrong table\n");
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

int darwin_iwi2100::ipw2100_disable_adapter(struct ipw2100_priv *priv)
{
	struct host_command cmd;// = {
		cmd.host_command = CARD_DISABLE;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = 0;
	//};
	int err = 0;

	IWI_DEBUG("CARD_DISABLE\n");

	if (!(priv->status & STATUS_ENABLED))
		return 0;

	/* Make sure we clear the associated state */
	priv->status &= ~(STATUS_ASSOCIATED | STATUS_ASSOCIATING);

	if (!priv->stop_hang_check) {
		priv->stop_hang_check = 1;
		//cancel_delayed_work(&priv->hang_check);
		queue_td(7,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_hang_check));
	}

	//mutex_lock(&priv->adapter_mutex);

	err = ipw2100_hw_send_command(priv, &cmd);
	if (err) {
		IWI_DEBUG( 
		       ": exit - failed to send CARD_DISABLE command\n");
		goto fail_up;
	}

	err = ipw2100_wait_for_card_state(priv, IPW_HW_STATE_DISABLED);
	if (err) {
		IWI_DEBUG( 
		       ": exit - card failed to change to DISABLED\n");
		goto fail_up;
	}

	IWI_DEBUG("TODO: implement scan state machine\n");

      fail_up:
	//mutex_unlock(&priv->adapter_mutex);
	return err;
}

int darwin_iwi2100::ipw2100_read_mac_address(struct ipw2100_priv *priv)
{
	u32 length = ETH_ALEN;
	u8 mac[ETH_ALEN];

	int err;

	err = ipw2100_get_ordinal(priv, IPW_ORD_STAT_ADAPTER_MAC, mac, &length);
	if (err) {
		IWI_DEBUG("MAC address read failed\n");
		return -EIO;
	}
	IWI_DEBUG("ipw2100_read_mac_address: card MAC is %02X:%02X:%02X:%02X:%02X:%02X\n",
		       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	memcpy(fEnetAddr.bytes, mac, ETH_ALEN);

	memcpy(priv->net_dev->dev_addr, mac, ETH_ALEN);
	memcpy(priv->mac_addr, mac, ETH_ALEN);
	memcpy(priv->ieee->dev->dev_addr, mac, ETH_ALEN);
	return 0;
}

int darwin_iwi2100::ipw2100_set_mac_address(struct ipw2100_priv *priv, int batch_mode)
{
	struct host_command cmd; 
		cmd.host_command = ADAPTER_ADDRESS;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = ETH_ALEN;
	
	int err;

	IWI_DEBUG("SET_MAC_ADDRESS\n");


	if (priv->config & CFG_CUSTOM_MAC) {
		memcpy(cmd.host_command_parameters, priv->mac_addr, ETH_ALEN);
		memcpy(priv->net_dev->dev_addr, priv->mac_addr, ETH_ALEN);
	} else
		memcpy(cmd.host_command_parameters, priv->net_dev->dev_addr,
		       ETH_ALEN);

	err = ipw2100_hw_send_command(priv, &cmd);

	return err;
}

int darwin_iwi2100::ipw2100_set_port_type(struct ipw2100_priv *priv, u32 port_type,
				 int batch_mode)
{
	struct host_command cmd;
		cmd.host_command = PORT_TYPE;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = sizeof(u32);
	
	int err;

	switch (port_type) {
	case IW_MODE_INFRA:
		cmd.host_command_parameters[0] = IPW_BSS;
		break;
	case IW_MODE_ADHOC:
		cmd.host_command_parameters[0] = IPW_IBSS;
		break;
	}

	IWI_DEBUG("PORT_TYPE: %s\n",
		     port_type == IPW_IBSS ? "Ad-Hoc" : "Managed");

	if (!batch_mode) {
		err = ipw2100_disable_adapter(priv);
		if (err) {
			IWI_DEBUG( 
			       ": %s: Could not disable adapter %d\n",
			       priv->net_dev->name, err);
			return err;
		}
	}

	/* send cmd to firmware */
	err = ipw2100_hw_send_command(priv, &cmd);

	if (!batch_mode)
		ipw2100_enable_adapter(priv);

	return err;
}

int darwin_iwi2100::ipw2100_set_channel(struct ipw2100_priv *priv, u32 channel,
			       int batch_mode)
{
	struct host_command cmd;
		cmd.host_command = CHANNEL;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = sizeof(u32);
	int err;

	cmd.host_command_parameters[0] = channel;

	IWI_DEBUG("CHANNEL: %d\n", channel);

	/* If BSS then we don't support channel selection */
	if (priv->ieee->iw_mode == IW_MODE_INFRA)
		return 0;

	if ((channel != 0) &&
	    ((channel < REG_MIN_CHANNEL) || (channel > REG_MAX_CHANNEL)))
		return -EINVAL;

	if (!batch_mode) {
		err = ipw2100_disable_adapter(priv);
		if (err)
			return err;
	}

	err = ipw2100_hw_send_command(priv, &cmd);
	if (err) {
		IWI_DEBUG("Failed to set channel to %d", channel);
		return err;
	}

	if (channel)
		priv->config |= CFG_STATIC_CHANNEL;
	else
		priv->config &= ~CFG_STATIC_CHANNEL;

	priv->channel = channel;

	if (!batch_mode) {
		err = ipw2100_enable_adapter(priv);
		if (err)
			return err;
	}

	return 0;
}

int darwin_iwi2100::ipw2100_system_config(struct ipw2100_priv *priv, int batch_mode)
{
	struct host_command cmd;
		cmd.host_command = SYSTEM_CONFIG;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = 12;
	u32 ibss_mask, len = sizeof(u32);
	int err;

	/* Set system configuration */

	if (!batch_mode) {
		err = ipw2100_disable_adapter(priv);
		if (err)
			return err;
	}

	if (priv->ieee->iw_mode == IW_MODE_ADHOC)
		cmd.host_command_parameters[0] |= IPW_CFG_IBSS_AUTO_START;

	cmd.host_command_parameters[0] |= IPW_CFG_IBSS_MASK |
	    IPW_CFG_BSS_MASK | IPW_CFG_802_1x_ENABLE;

	if (!(priv->config & CFG_LONG_PREAMBLE))
		cmd.host_command_parameters[0] |= IPW_CFG_PREAMBLE_AUTO;

	err = ipw2100_get_ordinal(priv,
				  IPW_ORD_EEPROM_IBSS_11B_CHANNELS,
				  &ibss_mask, &len);
	if (err)
		ibss_mask = IPW_IBSS_11B_DEFAULT_MASK;

	cmd.host_command_parameters[1] = REG_CHANNEL_MASK;
	cmd.host_command_parameters[2] = REG_CHANNEL_MASK & ibss_mask;

	/* 11b only */
	/*cmd.host_command_parameters[0] |= DIVERSITY_ANTENNA_A; */

	err = ipw2100_hw_send_command(priv, &cmd);
	if (err)
		return err;

/* If IPv6 is configured in the kernel then we don't want to filter out all
 * of the multicast packets as IPv6 needs some. */
#if !defined(CONFIG_IPV6) && !defined(CONFIG_IPV6_MODULE)
	cmd.host_command = ADD_MULTICAST;
	cmd.host_command_sequence = 0;
	cmd.host_command_length = 0;

	ipw2100_hw_send_command(priv, &cmd);
#endif
	if (!batch_mode) {
		err = ipw2100_enable_adapter(priv);
		if (err)
			return err;
	}

	return 0;
}

int darwin_iwi2100::ipw2100_set_tx_rates(struct ipw2100_priv *priv, u32 rate,
				int batch_mode)
{
	struct host_command cmd;
		cmd.host_command = BASIC_TX_RATES;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = 4;
	int err;

	cmd.host_command_parameters[0] = rate & TX_RATE_MASK;

	if (!batch_mode) {
		err = ipw2100_disable_adapter(priv);
		if (err)
			return err;
	}

	/* Set BASIC TX Rate first */
	ipw2100_hw_send_command(priv, &cmd);

	/* Set TX Rate */
	cmd.host_command = TX_RATES;
	ipw2100_hw_send_command(priv, &cmd);

	/* Set MSDU TX Rate */
	cmd.host_command = MSDU_TX_RATES;
	ipw2100_hw_send_command(priv, &cmd);

	if (!batch_mode) {
		err = ipw2100_enable_adapter(priv);
		if (err)
			return err;
	}

	priv->tx_rates = rate;

	return 0;
}

int darwin_iwi2100::ipw2100_set_power_mode(struct ipw2100_priv *priv, int power_level)
{
	struct host_command cmd;
		cmd.host_command = POWER_MODE;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = 4;
	int err;

	cmd.host_command_parameters[0] = power_level;

	err = ipw2100_hw_send_command(priv, &cmd);
	if (err)
		return err;

	if (power_level == IPW_POWER_MODE_CAM)
		priv->power_mode = IPW_POWER_LEVEL(priv->power_mode);
	else
		priv->power_mode = IPW_POWER_ENABLED | power_level;

#ifdef CONFIG_IPW2100_TX_POWER
	if (priv->port_type == IBSS && priv->adhoc_power != DFTL_IBSS_TX_POWER) {
		/* Set beacon interval */
		cmd.host_command = TX_POWER_INDEX;
		cmd.host_command_parameters[0] = (u32) priv->adhoc_power;

		err = ipw2100_hw_send_command(priv, &cmd);
		if (err)
			return err;
	}
#endif

	return 0;
}

int darwin_iwi2100::ipw2100_set_rts_threshold(struct ipw2100_priv *priv, u32 threshold)
{
	struct host_command cmd;
		cmd.host_command = RTS_THRESHOLD;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = 4;
	int err;

	if (threshold & RTS_DISABLED)
		cmd.host_command_parameters[0] = MAX_RTS_THRESHOLD;
	else
		cmd.host_command_parameters[0] = threshold & ~RTS_DISABLED;

	err = ipw2100_hw_send_command(priv, &cmd);
	if (err)
		return err;

	priv->rts_threshold = threshold;

	return 0;
}

int darwin_iwi2100::ipw2100_set_mandatory_bssid(struct ipw2100_priv *priv, u8 * bssid,
				       int batch_mode)
{
	struct host_command cmd;
		cmd.host_command = MANDATORY_BSSID;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = (bssid == NULL) ? 0 : ETH_ALEN;
	int err;

//#ifdef CONFIG_IPW2100_DEBUG
	if (bssid != NULL)
		IWI_DEBUG("MANDATORY_BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
			     bssid[0], bssid[1], bssid[2], bssid[3], bssid[4],
			     bssid[5]);
	else
		IWI_DEBUG("MANDATORY_BSSID: <clear>\n");
//#endif
	/* if BSSID is empty then we disable mandatory bssid mode */
	if (bssid != NULL)
		memcpy(cmd.host_command_parameters, bssid, ETH_ALEN);

	if (!batch_mode) {
		err = ipw2100_disable_adapter(priv);
		if (err)
			return err;
	}

	err = ipw2100_hw_send_command(priv, &cmd);

	if (!batch_mode)
		ipw2100_enable_adapter(priv);

	return err;
}

int darwin_iwi2100::ipw2100_set_essid(struct ipw2100_priv *priv, char *essid,
			     int length, int batch_mode)
{
	int ssid_len = min(length, IW_ESSID_MAX_SIZE);
	struct host_command cmd;
		cmd.host_command = SSID;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = ssid_len;
	int err;

	IWI_DEBUG("SSID: '%s'\n", escape_essid(essid, ssid_len));

	if (ssid_len)
		memcpy(cmd.host_command_parameters, essid, ssid_len);

	if (!batch_mode) {
		err = ipw2100_disable_adapter(priv);
		if (err)
			return err;
	}

	/* Bug in FW currently doesn't honor bit 0 in SET_SCAN_OPTIONS to
	 * disable auto association -- so we cheat by setting a bogus SSID */
	if (!ssid_len && !(priv->config & CFG_ASSOCIATE)) {
		int i;
		u8 *bogus = (u8 *) cmd.host_command_parameters;
		for (i = 0; i < IW_ESSID_MAX_SIZE; i++)
			bogus[i] = 0x18 + i;
		cmd.host_command_length = IW_ESSID_MAX_SIZE;
	}

	/* NOTE:  We always send the SSID command even if the provided ESSID is
	 * the same as what we currently think is set. */

	err = ipw2100_hw_send_command(priv, &cmd);
	if (!err) {
		memset(priv->essid + ssid_len, 0, IW_ESSID_MAX_SIZE - ssid_len);
		memcpy(priv->essid, essid, ssid_len);
		priv->essid_len = ssid_len;
	}

	if (!batch_mode) {
		if (ipw2100_enable_adapter(priv))
			err = -EIO;
	}

	return err;
}

int darwin_iwi2100::ipw2100_set_ibss_beacon_interval(struct ipw2100_priv *priv,
					    u32 interval, int batch_mode)
{
	struct host_command cmd;
		cmd.host_command = BEACON_INTERVAL;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = 4;
	int err;

	cmd.host_command_parameters[0] = interval;


	if (priv->ieee->iw_mode == IW_MODE_ADHOC) {
		if (!batch_mode) {
			err = ipw2100_disable_adapter(priv);
			if (err)
				return err;
		}

		ipw2100_hw_send_command(priv, &cmd);

		if (!batch_mode) {
			err = ipw2100_enable_adapter(priv);
			if (err)
				return err;
		}
	}


	return 0;
}

int darwin_iwi2100::ipw2100_adapter_setup(struct ipw2100_priv *priv)
{
	int err;
	int batch_mode = 1;
	u8 *bssid;


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

	/*err = ipw2100_set_power_mode(priv, IPW_POWER_MODE_CAM);
	if (err)
		return err;*/
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
		err = ipw2100_set_essid(priv, (char*)priv->essid, priv->essid_len,
					batch_mode);
	else
		err = ipw2100_set_essid(priv, NULL, 0, batch_mode);
	if (err)
		return err;

	//err = ipw2100_configure_security(priv, batch_mode);
	//if (err)
	//	return err;
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

	return 0;
}

int darwin_iwi2100::ipw2100_set_tx_power(struct ipw2100_priv *priv, u32 tx_power)
{
	struct host_command cmd;
		cmd.host_command = TX_POWER_INDEX;
		cmd.host_command_sequence = 0;
		cmd.host_command_length = 4;
	int err = 0;
	u32 tmp = tx_power;

	if (tx_power != IPW_TX_POWER_DEFAULT)
		tmp = (tx_power - IPW_TX_POWER_MIN_DBM) * 16 /
		      (IPW_TX_POWER_MAX_DBM - IPW_TX_POWER_MIN_DBM);

	cmd.host_command_parameters[0] = tmp;

	if (priv->ieee->iw_mode == IW_MODE_ADHOC)
		err = ipw2100_hw_send_command(priv, &cmd);
	if (!err)
		priv->tx_power = tx_power;

	return 0;
}

#define MAX_HW_RESTARTS 2
int darwin_iwi2100::ipw2100_up(struct ipw2100_priv *priv, int deferred)
{
	pl++;
	if (pl>MAX_HW_RESTARTS) return 0;
	unsigned long flags;
	int rc = 0;
	u32 lock;
	u32 ord_len = sizeof(lock);

	/* Quite if manually disabled. */
	if (priv->status & STATUS_RF_KILL_SW) {
		IWI_LOG("%s: Radio is disabled by Manual Disable "
			       "switch\n", priv->net_dev->name);
		return 0;
	}

	/* If the interrupt is enabled, turn it off... */
	ipw2100_disable_interrupts(priv);

	/* Reset any fatal_error conditions */
	ipw2100_reset_fatalerror(priv);
	if (priv->status & STATUS_POWERED ||
	    (priv->status & STATUS_RESET_PENDING)) {
		/* Power cycle the card ... */
		if (ipw2100_power_cycle_adapter(priv)) {
			IWI_DEBUG(
			       ": %s: Could not cycle adapter.\n",
			       priv->net_dev->name);
			rc = 1;
			goto exit;
		}
	} else
		priv->status |= STATUS_POWERED;
	/* Load the firmware, start the clocks, etc. */
	if (ipw2100_start_adapter(priv)) {
		IWI_DEBUG(
		       ": %s: Failed to start the firmware.\n",
		       priv->net_dev->name);
		rc = 1;
		goto exit;
	}

	ipw2100_initialize_ordinals(priv);

	/* Determine capabilities of this particular HW configuration */
	if (ipw2100_get_hw_features(priv)) {
		IWI_DEBUG(
		       ": %s: Failed to determine HW features.\n",
		       priv->net_dev->name);
		rc = 1;
		goto exit;
	}

	/* Initialize the geo */
	if (ipw_set_geo(priv->ieee, &ipw_geos[0])) {
		IWI_DEBUG( "Could not set geo\n");
		return 0;
	}
	priv->ieee->freq_band = IEEE80211_24GHZ_BAND;

	lock = LOCK_NONE;
	if (ipw2100_set_ordinal(priv, IPW_ORD_PERS_DB_LOCK, &lock, &ord_len)) {
		IWI_DEBUG(
		       ": %s: Failed to clear ordinal lock.\n",
		       priv->net_dev->name);
		rc = 1;
		goto exit;
	}

	priv->status &= ~STATUS_SCANNING;

//eddi: vediamo se adesso funziona
	if (rf_kill_active(priv)) {
		IWI_DEBUG( "%s: Radio is disabled by RF switch.\n",
		       priv->net_dev->name);

		if (priv->stop_rf_kill) {
			priv->stop_rf_kill = 0;
			//queue_delayed_work(priv->workqueue, &priv->rf_kill, HZ);
			queue_te(3,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_rf_kill),priv,2000,true);
		}

		deferred = 1;
	}

	/* Turn on the interrupt so that commands can be processed */
	ipw2100_enable_interrupts(priv);

	/* Send all of the commands that must be sent prior to
	 * HOST_COMPLETE */
	 if (!deferred)
	if (ipw2100_adapter_setup(priv)) {
		IWI_DEBUG( ": %s: Failed to start the card.\n",
		       priv->net_dev->name);
		rc = 1;
		goto exit;
	}

	if (!deferred) {
		/* Enable the adapter - sends HOST_COMPLETE */
		if (ipw2100_enable_adapter(priv)) {
			IWI_DEBUG( ": "
			       "%s: failed in call to enable adapter.\n",
			       priv->net_dev->name);
			ipw2100_hw_stop_adapter(priv);
			rc = 1;
			goto exit;
		}

		/* Start a scan . . . */
		//if (!(priv->config & CFG_ASSOCIATE)) return rc;
		ipw2100_set_scan_options(priv);
		ipw2100_start_scan(priv);
	}

      exit:
	return rc;

}

IOReturn darwin_iwi2100::enable( IONetworkInterface * netif ) 
{
	if (!fifnet)
	{
		char ii[4];
		sprintf(ii,"%s%d" ,fNetif->getNamePrefix(), fNetif->getUnitNumber());
		ifnet_find_by_name(ii,&fifnet);
		memcpy(&priv->ieee->dev->name,ii,sizeof(ii));
		IWI_DEBUG("ifnet_t %s%d = %x\n",ifnet_name(fifnet),ifnet_unit(fifnet),fifnet);
	}
	if (firstifup==0)
	{
		firstifup=1;
		return -1;
	}
	IWI_DEBUG("ifconfig up\n");
	if ((fNetif->getFlags() & IFF_RUNNING)==0)
	{
		IWI_DEBUG("ifconfig going up\n ");
		//super::enable(fNetif);
		//fNetif->setPoweredOnByUser(true);
		//fNetif->setLinkState(kIO80211NetworkLinkUp);

		//(if_flags & ~mask) | (new_flags & mask) if mask has IFF_UP if_updown fires up (kpi_interface.c in xnu)	
		if (priv->status & STATUS_ASSOCIATED) ifnet_set_flags(fifnet, IFF_RUNNING, IFF_RUNNING );
		//fNetif->inputEvent(kIONetworkEventTypeLinkUp,NULL);
		//fTransmitQueue->setCapacity(kTransmitQueueCapacity);
		fTransmitQueue->start();
		
		return kIOReturnSuccess;
	}
	{
		IWI_DEBUG("ifconfig already up\n");
		return kIOReturnExclusiveAccess;
	}
}

//inline int darwin_iwi2100::ipw2100_is_init(struct ipw2100_priv *priv)
//{
//	return (priv->status & STATUS_INITIALIZED) ? 1 : 0;
//}

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
		IWI_DEBUG("Ignoring concurrent scan abort request.\n");
		return;
	}
	priv->status |= STATUS_SCAN_ABORTING;
	queue_td(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_scan));
	queue_td(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_scan_check));
	err = sendCommand(IPW_CMD_SCAN_ABORT, NULL,0, 0);
	if (err)
		IWI_DEBUG("Request to abort scan failed.\n");
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

//void darwin_iwi2100::ipw2100_deinit(struct ipw2100_priv *priv)
//{
//	int i;
//
//	if (priv->status & STATUS_SCANNING) {
//		IWI_DEBUG("Aborting scan during shutdown.\n");
//		ipw2100_abort_scan(priv);
//	}
//
//	if (priv->status & STATUS_ASSOCIATED) {
//		IWI_DEBUG("Disassociating during shutdown.\n");
//		ipw2100_disassociate(priv);
//	}
//
//	ipw2100_led_shutdown(priv);
//
//	/* Wait up to 1s for status to change to not scanning and not
//	 * associated (disassociation can take a while for a ful 802.11
//	 * exchange */
//	for (i = 1000; i && (priv->status &
//			     (STATUS_DISASSOCIATING |
//			      STATUS_ASSOCIATED | STATUS_SCANNING)); i--)
//		udelay(10);
//
//	if (priv->status & (STATUS_DISASSOCIATING |
//			    STATUS_ASSOCIATED | STATUS_SCANNING))
//		IWI_DEBUG("Still associated or scanning...\n");
//	else
//		IWI_DEBUG("Took %dms to de-init\n", 1000 - i);
//
//	/* Attempt to disable the card */
//	u32 phy_off = cpu_to_le32(0);
//	sendCommand(IPW_CMD_CARD_DISABLE, &phy_off,sizeof(phy_off), 1);
//
//	priv->status &= ~STATUS_INITIALIZED;
//}

inline void darwin_iwi2100::ipw2100_disable_interrupts(struct ipw2100_priv *priv)
{
	if (!(priv->status & STATUS_INT_ENABLED))
		return;
	priv->status &= ~STATUS_INT_ENABLED;
	write_register(priv->net_dev, IPW_REG_INTA_MASK, 0x0);
}

void darwin_iwi2100::ipw2100_down(struct ipw2100_priv *priv)
{
//inizio (eddi) - This function was taken erronealy from ipw2200
//        int associated = priv->status & STATUS_ASSOCIATED;

        /* Kill the RF switch timer */
        if (!priv->stop_rf_kill) {
                priv->stop_rf_kill = 1;
                //cancel_delayed_work(&priv->rf_kill);
		queue_td(3,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_rf_kill));
        }

        /* Kill the firmare hang check timer */
        if (!priv->stop_hang_check) {
                priv->stop_hang_check = 1;
                //cancel_delayed_work(&priv->hang_check);
		queue_td(7,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_hang_check));
        }

        /* Kill any pending resets */
        if (priv->status & STATUS_RESET_PENDING)
                //cancel_delayed_work(&priv->reset_work);
		 queue_td(8,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_reset_adapter));

        /* Make sure the interrupt is on so that FW commands will be 
         * processed correctly */
//        spin_lock_irqsave(&priv->low_lock, flags);
        ipw2100_enable_interrupts(priv);
//        spin_unlock_irqrestore(&priv->low_lock, flags);

        if (ipw2100_hw_stop_adapter(priv))
//                printk(KERN_ERR DRV_NAME ": %s: Error stopping adapter.\n",
//                       priv->net_dev->name);
		IWI_DEBUG("%s: Error stopping adapter.\n",
                       priv->net_dev->name);

        /* Do not disable the interrupt until _after_ we disable 
         * the adaptor.  Otherwise the CARD_DISABLE command will never 
         * be ack'd by the firmware */
//        spin_lock_irqsave(&priv->low_lock, flags);
        ipw2100_disable_interrupts(priv);
//        spin_unlock_irqrestore(&priv->low_lock, flags);

//        /* We have to signal any supplicant if we are disassociating */
//        if (associated)
//                wireless_send_event(priv->net_dev, SIOCGIWAP, &wrqu, NULL);

        priv->status &= ~(STATUS_ASSOCIATED | STATUS_ASSOCIATING);
//        netif_carrier_off(priv->net_dev);
//        netif_stop_queue(priv->net_dev);
//fine

//	int exit_pending = priv->status & STATUS_EXIT_PENDING;
//
//	priv->status |= STATUS_EXIT_PENDING;
//
//	if (ipw2100_is_init(priv))
//		ipw2100_deinit(priv);
//
//	/* Wipe out the EXIT_PENDING status bit if we are not actually
//	 * exiting the module */
//	if (!exit_pending)
//		priv->status &= ~STATUS_EXIT_PENDING;
//
//	/* tell the device to stop sending interrupts */
//	ipw2100_disable_interrupts(priv);
//
//	/* Clear all bits but the RF Kill */
//	priv->status &= STATUS_RF_KILL_MASK | STATUS_EXIT_PENDING;
//	//fNetif->setLinkState(kIO80211NetworkLinkDown);
//	//netif_stop_queue(priv->net_dev);

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
		IWI_DEBUG_FULL("Command completed '%s (%d)'\n",
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

void darwin_iwi2100::ipw2100_wx_event_work(struct ipw2100_priv *priv)
{
	//union iwreq_data wrqu;
	int len = ETH_ALEN;

	if (priv->status & STATUS_STOPPING)
		return;

	if (!(priv->config & CFG_ASSOCIATE)) return;
	//mutex_lock(&priv->action_mutex);

	IWI_DEBUG("associating\n");

	//mutex_unlock(&priv->action_mutex);

	//wrqu.ap_addr.sa_family = ARPHRD_ETHER;

	/* Fetch BSSID from the hardware */
	if (!(priv->status & (STATUS_ASSOCIATING | STATUS_ASSOCIATED)) ||
	    priv->status & STATUS_RF_KILL_MASK ||
	    ipw2100_get_ordinal(priv, IPW_ORD_STAT_ASSN_AP_BSSID,
				&priv->bssid, (u32*)&len)) {
		//memset(wrqu.ap_addr.sa_data, 0, ETH_ALEN);
		IWI_DEBUG("Configuring BSSID\n");
	} else {
		/* We now have the BSSID, so can finish setting to the full
		 * associated state */
		//memcpy(wrqu.ap_addr.sa_data, priv->bssid, ETH_ALEN);
		IWI_DEBUG("enabling network\n");
		memcpy(priv->ieee->bssid, priv->bssid, ETH_ALEN);
		priv->status &= ~STATUS_ASSOCIATING;
		priv->status |= STATUS_ASSOCIATED;
		enable(fNetif);
		
		u32 txrate,len = sizeof(u32);
		ipw2100_get_ordinal(priv, IPW_ORD_CURRENT_TX_RATE, &txrate, (u32*)&len);
		setLinkStatus(kIONetworkLinkValid | (txrate ? kIONetworkLinkActive : 0),
		 mediumTable[MEDIUM_TYPE_AUTO], txrate);

		//netif_carrier_on(priv->net_dev);
		//netif_wake_queue(priv->net_dev);
		fTransmitQueue->start();
	}

	if (!(priv->status & STATUS_ASSOCIATED)) {
		IWI_DEBUG("Configuring ESSID\n");
		//mutex_lock(&priv->action_mutex);
		/* This is a disassociation event, so kick the firmware to
		 * look for another AP */
		if (priv->config & CFG_STATIC_ESSID)
			ipw2100_set_essid(priv, (char*)priv->essid, priv->essid_len,
					  1);
		else
			ipw2100_set_essid(priv, NULL, 0, 1);
		//mutex_unlock(&priv->action_mutex);
	}

	//wireless_send_event(priv->net_dev, SIOCGIWAP, &wrqu, NULL);
}

void darwin_iwi2100::isr_indicate_associated(struct ipw2100_priv *priv, u32 status)
{

#define MAC_ASSOCIATION_READ_DELAY (HZ)
	int ret, len, essid_len;
	char essid[IW_ESSID_MAX_SIZE];
	u32 txrate;
	u32 chan;
	char *txratename;
	u8 bssid[ETH_ALEN];

	/*
	 * TBD: BSSID is usually 00:00:00:00:00:00 here and not
	 *      an actual MAC of the AP. Seems like FW sets this
	 *      address too late. Read it later and expose through
	 *      /proc or schedule a later task to query and update
	 */

	essid_len = IW_ESSID_MAX_SIZE;
	ret = ipw2100_get_ordinal(priv, IPW_ORD_STAT_ASSN_SSID,
				  essid, (u32*)&essid_len);
	if (ret) {
		IWI_DEBUG("failed querying ordinals at line %d\n",
			       __LINE__);
		return;
	}

	len = sizeof(u32);
	ret = ipw2100_get_ordinal(priv, IPW_ORD_CURRENT_TX_RATE, &txrate, (u32*)&len);
	if (ret) {
		IWI_DEBUG("failed querying ordinals at line %d\n",
			       __LINE__);
		return;
	}

	len = sizeof(u32);
	ret = ipw2100_get_ordinal(priv, IPW_ORD_OUR_FREQ, &chan, (u32*)&len);
	if (ret) {
		IWI_DEBUG("failed querying ordinals at line %d\n",
			       __LINE__);
		return;
	}
	len = ETH_ALEN;
	ret=ipw2100_get_ordinal(priv, IPW_ORD_STAT_ASSN_AP_BSSID, &bssid, (u32*)&len);
	if (ret) {
		IWI_DEBUG("failed querying ordinals at line %d\n",
			       __LINE__);
		return;
	}
	memcpy(priv->ieee->bssid, bssid, ETH_ALEN);

	switch (txrate) {
	case TX_RATE_1_MBIT:
		txratename = "1Mbps";
		break;
	case TX_RATE_2_MBIT:
		txratename = "2Mbsp";
		break;
	case TX_RATE_5_5_MBIT:
		txratename = "5.5Mbps";
		break;
	case TX_RATE_11_MBIT:
		txratename = "11Mbps";
		break;
	default:
		IWI_DEBUG("Unknown rate: %d\n", txrate);
		txratename = "unknown rate";
		break;
	}

	IWI_DEBUG("%s: Associated with '%s' at %s, channel %d (BSSID="
		       MAC_FMT ")\n",
		       priv->net_dev->name, escape_essid(essid, essid_len),
		       txratename, chan, MAC_ARG(bssid));

	/* now we copy read ssid into dev */
	if (!(priv->config & CFG_STATIC_ESSID)) {
		priv->essid_len = min((u8) essid_len, (u8) IW_ESSID_MAX_SIZE);
		memcpy(priv->essid, essid, priv->essid_len);
	}
	priv->channel = chan;
	memcpy(priv->bssid, bssid, ETH_ALEN);

	priv->status |= STATUS_ASSOCIATING;
	priv->connect_start = jiffies;//get_seconds();

	//queue_delayed_work(priv->workqueue, &priv->wx_event_work, HZ / 10);
	queue_te(9,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_wx_event_work),priv,HZ/10,true);
}

/*struct ipw2100_status_indicator {
	int status;
	void (*cb) (struct ipw2100_priv * priv, u32 status);
};
#define IPW2100_HANDLER(v, f) { v, f }
const struct ipw2100_status_indicator status_handlers[] = {
	IPW2100_HANDLER(IPW_STATE_INITIALIZED, NULL),
	IPW2100_HANDLER(IPW_STATE_COUNTRY_FOUND, NULL),
	IPW2100_HANDLER(IPW_STATE_ASSOCIATED, isr_indicate_associated),
	IPW2100_HANDLER(IPW_STATE_ASSN_LOST, darwin_iwi2100::isr_indicate_association_lost),
	IPW2100_HANDLER(IPW_STATE_ASSN_CHANGED, NULL),
	IPW2100_HANDLER(IPW_STATE_SCAN_COMPLETE, darwin_iwi2100::isr_scan_complete),
	IPW2100_HANDLER(IPW_STATE_ENTERED_PSP, NULL),
	IPW2100_HANDLER(IPW_STATE_LEFT_PSP, NULL),
	IPW2100_HANDLER(IPW_STATE_RF_KILL, darwin_iwi2100::isr_indicate_rf_kill),
	IPW2100_HANDLER(IPW_STATE_DISABLED, NULL),
	IPW2100_HANDLER(IPW_STATE_POWER_DOWN, NULL),
	IPW2100_HANDLER(IPW_STATE_SCANNING, darwin_iwi2100::isr_indicate_scanning),
	IPW2100_HANDLER(-1, NULL)
};*/

void darwin_iwi2100::isr_status_change(struct ipw2100_priv *priv, int status)
{
	int i;

	if (status == IPW_STATE_SCANNING &&
	    priv->status & STATUS_ASSOCIATED &&
	    !(priv->status & STATUS_SCANNING)) {
		IWI_DEBUG("Scan detected while associated, with "
			       "no scan request.  Restarting firmware.\n");

		/* Wake up any sleeping jobs */
		schedule_reset(priv);
	}

	IWI_DEBUG("status received: %04x\n", status);
	
	switch (status)
	{
		case IPW_STATE_INITIALIZED:
		case IPW_STATE_COUNTRY_FOUND:
		case IPW_STATE_ASSN_CHANGED:
		case IPW_STATE_ENTERED_PSP:
		case IPW_STATE_LEFT_PSP:
		case IPW_STATE_DISABLED:
		case IPW_STATE_POWER_DOWN:
			IWI_DEBUG_FULL("status received: %04x\n", status);
			break;
		
		case IPW_STATE_ASSOCIATED:
			isr_indicate_associated(priv,status);
			break;
			
		case IPW_STATE_ASSN_LOST:
			isr_indicate_association_lost(priv,status);
			break;
			
		case IPW_STATE_SCAN_COMPLETE:
			isr_scan_complete(priv,status);
			break;
			
		case IPW_STATE_RF_KILL:
			isr_indicate_rf_kill(priv,status);
			break;
			
		case IPW_STATE_SCANNING:
			isr_indicate_scanning(priv,status);
		break;
			
		default:
			IWI_DEBUG_FULL("unknown status received: %04x\n", status);
			break;
	
	}
	/*for (i = 0; status_handlers[i].status != -1; i++) {
		if (status == status_handlers[i].status) {
			IWI_DEBUG("Status change: %d\n",status);
					//status_handlers[i].name);
			if (status_handlers[i].cb)
				status_handlers[i].cb(priv, status);
			priv->wstats.status = status;
			return;
		}
	}*/

	//IWI_DEBUG("unknown status received: %04x\n", status);
}

void darwin_iwi2100::isr_indicate_scanning(struct ipw2100_priv *priv, u32 status)
{
	IWI_DEBUG_FULL("Scanning...\n");
	priv->status |= STATUS_SCANNING;
}

void darwin_iwi2100::isr_indicate_rf_kill(struct ipw2100_priv *priv, u32 status)
{
	IWI_DEBUG("%s: RF Kill state changed to radio OFF.\n",
		       priv->net_dev->name);

	/* RF_KILL is now enabled (else we wouldn't be here) */
	priv->status |= STATUS_RF_KILL_HW;

#ifdef ACPI_CSTATE_LIMIT_DEFINED
	if (priv->config & CFG_C3_DISABLED) {
		IWI_DEBUG_FULL(": Resetting C3 transitions.\n");
		acpi_set_cstate_limit(priv->cstate_limit);
		priv->config &= ~CFG_C3_DISABLED;
	}
#endif

	/* Make sure the RF Kill check timer is running */
	priv->stop_rf_kill = 0;
	priv->config |= CFG_ASSOCIATE;
	//cancel_delayed_work(&priv->rf_kill);
	//queue_delayed_work(priv->workqueue, &priv->rf_kill, HZ);
	queue_te(3,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_rf_kill),priv,2000,true);
}

void darwin_iwi2100::isr_scan_complete(struct ipw2100_priv *priv, u32 status)
{
	IWI_DEBUG("scan complete\n");
	/* Age the scan results... */
	priv->ieee->scans++;
	priv->status &= ~STATUS_SCANNING;
}

void darwin_iwi2100::isr_indicate_association_lost(struct ipw2100_priv *priv, u32 status)
{
	IWI_DEBUG(  
		  "disassociated: '%s' " MAC_FMT " \n",
		  escape_essid((const char*)priv->essid, priv->essid_len),
		  MAC_ARG(priv->bssid));

	priv->status &= ~(STATUS_ASSOCIATED | STATUS_ASSOCIATING);

	if (priv->status & STATUS_STOPPING) {
		IWI_DEBUG("Card is stopping itself, discard ASSN_LOST.\n");
		return;
	}

	memset(priv->bssid, 0, ETH_ALEN);
	memset(priv->ieee->bssid, 0, ETH_ALEN);

	//netif_carrier_off(priv->net_dev);
	disable(fNetif);
	//netif_stop_queue(priv->net_dev);

	if (!(priv->status & STATUS_RUNNING))
		return;

	//if (priv->status & STATUS_SECURITY_UPDATED)
	//	queue_delayed_work(priv->workqueue, &priv->security_work, 0);
	queue_te(9,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_wx_event_work),priv,NULL,true);
	//queue_delayed_work(priv->workqueue, &priv->wx_event_work, 0);
}


int darwin_iwi2100::ieee80211_parse_info_param(struct ieee80211_info_element
				      *info_element, u16 length,
				      struct ieee80211_network *network)
{
	u8 i;

	while (length >= sizeof(*info_element)) {
		if (sizeof(*info_element) + info_element->len > length) {
			IWI_DEBUG_FULL("ERROR: Info elem: parse failed: "
					"info_element->len + 2 > left : "
					"info_element->len+2=%zd left=%d, id=%d.\n",
					info_element->len +
					sizeof(*info_element),
					length, info_element->id);
			/* We stop processing but don't return an error here
			 * because some misbehaviour APs break this rule. ie.
			 * Orinoco AP1000. */
			break;
		}

		switch (info_element->id) {
		case MFIE_TYPE_SSID:
			if (ieee80211_is_empty_essid((const char*)info_element->data,
						     info_element->len)) {
				network->flags |= NETWORK_EMPTY_ESSID;
				break;
			}

			network->ssid_len = min(info_element->len,
						(u8) IW_ESSID_MAX_SIZE);
			memcpy(network->ssid, info_element->data,
			       network->ssid_len);
			if (network->ssid_len < IW_ESSID_MAX_SIZE)
				memset(network->ssid + network->ssid_len, 0,
				       IW_ESSID_MAX_SIZE - network->ssid_len);

			IWI_DEBUG_FULL("MFIE_TYPE_SSID: '%s' len=%d.\n",
					     escape_essid((const char*)network->ssid, network->ssid_len), network->ssid_len);
			
			break;

		case MFIE_TYPE_RATES:
			network->rates_len = min(info_element->len,
						 MAX_RATES_LENGTH);
			for (i = 0; i < network->rates_len; i++) {
				network->rates[i] = info_element->data[i];
				if (ieee80211_is_ofdm_rate
				    (info_element->data[i])) {
					network->flags |= NETWORK_HAS_OFDM;
					if (info_element->data[i] &
					    IEEE80211_BASIC_RATE_MASK)
						network->flags &=
						    ~NETWORK_HAS_CCK;
				}
			}
			break;

		case MFIE_TYPE_RATES_EX:
			network->rates_ex_len = min(info_element->len,
						    MAX_RATES_EX_LENGTH);
			for (i = 0; i < network->rates_ex_len; i++) {
				network->rates_ex[i] = info_element->data[i];
				if (ieee80211_is_ofdm_rate
				    (info_element->data[i])) {
					network->flags |= NETWORK_HAS_OFDM;
					if (info_element->data[i] &
					    IEEE80211_BASIC_RATE_MASK)
						network->flags &=
						    ~NETWORK_HAS_CCK;
				}
			}

			break;

		case MFIE_TYPE_DS_SET:
			IEEE80211_DEBUG_MGMT("MFIE_TYPE_DS_SET: %d\n",
					     info_element->data[0]);
			network->channel = info_element->data[0];
			break;

		case MFIE_TYPE_FH_SET:
			IEEE80211_DEBUG_MGMT("MFIE_TYPE_FH_SET: ignored\n");
			break;

		case MFIE_TYPE_CF_SET:
			IEEE80211_DEBUG_MGMT("MFIE_TYPE_CF_SET: ignored\n");
			break;

		case MFIE_TYPE_TIM:
			network->tim.tim_count = info_element->data[0];
			network->tim.tim_period = info_element->data[1];
			IEEE80211_DEBUG_MGMT("MFIE_TYPE_TIM: partially ignored\n");
			break;

		case MFIE_TYPE_ERP_INFO:
			network->erp_value = info_element->data[0];
			network->flags |= NETWORK_HAS_ERP_VALUE;
			IEEE80211_DEBUG_MGMT("MFIE_TYPE_ERP_SET: %d\n",
					     network->erp_value);
			break;

		case MFIE_TYPE_IBSS_SET:
			network->atim_window = info_element->data[0];
			//IEEE80211_DEBUG_MGMT("MFIE_TYPE_IBSS_SET: %d\n",network->atim_window);
			IWI_DEBUG_FULL("MFIE_TYPE_IBSS_SET (%02x:%02x:%02x:%02x:%02x:%02x)\n",
					MAC_ARG(network->atim_window));
			break;

		case MFIE_TYPE_CHALLENGE:
			IEEE80211_DEBUG_MGMT("MFIE_TYPE_CHALLENGE: ignored\n");
			break;

		case MFIE_TYPE_GENERIC:
			IEEE80211_DEBUG_MGMT("MFIE_TYPE_GENERIC: %d bytes\n",
					     info_element->len);
						 
			//if (qos_enable)
			//if (!ieee80211_parse_qos_info_param_IE(info_element,
			//				       network))
			//	break;

			if (info_element->len >= 4 &&
			    info_element->data[0] == 0x00 &&
			    info_element->data[1] == 0x50 &&
			    info_element->data[2] == 0xf2 &&
			    info_element->data[3] == 0x01) {
				network->wpa_ie_len = min(info_element->len + 2,
							  MAX_WPA_IE_LEN);
				memcpy(network->wpa_ie, info_element,
				       network->wpa_ie_len);
			}
			break;

		case MFIE_TYPE_RSN:
			IEEE80211_DEBUG_MGMT("MFIE_TYPE_RSN: %d bytes\n",
					     info_element->len);
			network->rsn_ie_len = min(info_element->len + 2,
						  MAX_WPA_IE_LEN);
			memcpy(network->rsn_ie, info_element,
			       network->rsn_ie_len);
			break;

		case MFIE_TYPE_QOS_PARAMETER:
			IWI_DEBUG_FULL(
			       "ERROR: QoS Error need to parse QOS_PARAMETER IE\n");
			break;
			/* 802.11h */
		case MFIE_TYPE_POWER_CONSTRAINT:
			network->power_constraint = info_element->data[0];
			network->flags |= NETWORK_HAS_POWER_CONSTRAINT;
			break;

		case MFIE_TYPE_CSA:
			network->power_constraint = info_element->data[0];
			network->flags |= NETWORK_HAS_CSA;
			break;

		case MFIE_TYPE_QUIET:
			network->quiet.count = info_element->data[0];
			network->quiet.period = info_element->data[1];
			network->quiet.duration = info_element->data[2];
			network->quiet.offset = info_element->data[3];
			network->flags |= NETWORK_HAS_QUIET;
			break;

		case MFIE_TYPE_IBSS_DFS:
		    IEEE80211_DEBUG_MGMT("MFIE_TYPE_IBSS_DFS:\n");
			 
			if (network->ibss_dfs)
				break;
			network->ibss_dfs = (struct ieee80211_ibss_dfs*)IOMalloc(info_element->len);
			if (!network->ibss_dfs)
				return 1;
			memcpy(network->ibss_dfs, info_element->data,
			       info_element->len);
			network->flags |= NETWORK_HAS_IBSS_DFS;
			
			break;

		case MFIE_TYPE_TPC_REPORT:
			network->tpc_report.transmit_power =
			    info_element->data[0];
			network->tpc_report.link_margin = info_element->data[1];
			network->flags |= NETWORK_HAS_TPC_REPORT;
			break;

		default:
			IWI_DEBUG_FULL
			    ("Unsupported info element: %d\n",0);
				return 0; // hack
			   //  get_info_element_string(info_element->id),
			     //info_element->id);
			break;
		}

		length -= sizeof(*info_element) + info_element->len;
		info_element =
		    (struct ieee80211_info_element *)&info_element->
		    data[info_element->len];
	}

	return 0;
}

int darwin_iwi2100::ieee80211_handle_assoc_resp(struct ieee80211_device *ieee, struct ieee80211_assoc_response
				       *frame, struct ieee80211_rx_stats *stats)
{
	IWI_DEBUG("ieee80211_handle_assoc_resp\n");
	struct ieee80211_network network_resp; 
		network_resp.ibss_dfs = NULL;
	
	struct ieee80211_network *network = &network_resp;
	struct net_device *dev = ieee->dev;

	network->flags = 0;
	network->qos_data.active = 0;
	network->qos_data.supported = 0;
	network->qos_data.param_count = 0;
	network->qos_data.old_param_count = 0;

	//network->atim_window = le16_to_cpu(frame->aid) & (0x3FFF);
	network->atim_window = le16_to_cpu(frame->aid);
	network->listen_interval = le16_to_cpu(frame->status);
	memcpy(network->bssid, frame->header.addr3, ETH_ALEN);
	network->capability = le16_to_cpu(frame->capability);
	network->last_scanned = jiffies;
	network->rates_len = network->rates_ex_len = 0;
	network->last_associate = 0;
	network->ssid_len = 0;
	network->erp_value =
	    (network->capability & WLAN_CAPABILITY_IBSS) ? 0x3 : 0x0;

	if (stats->freq == IEEE80211_52GHZ_BAND) {
		/* for A band (No DS info) */
		network->channel = stats->received_channel;
	} else
		network->flags |= NETWORK_HAS_CCK;

	network->wpa_ie_len = 0;
	network->rsn_ie_len = 0;

	if (ieee80211_parse_info_param
	    (frame->info_element, stats->len - sizeof(*frame), network))
		return 1;

	network->mode = 0;
	if (stats->freq == IEEE80211_52GHZ_BAND)
		network->mode = IEEE_A;
	else {
		if (network->flags & NETWORK_HAS_OFDM)
			network->mode |= IEEE_G;
		if (network->flags & NETWORK_HAS_CCK)
			network->mode |= IEEE_B;
	}

	if (ieee80211_is_empty_essid((const char*)network->ssid, network->ssid_len))
		network->flags |= NETWORK_EMPTY_ESSID;

	memcpy(&network->stats, stats, sizeof(network->stats));

	//if (ieee->handle_assoc_response != NULL)
	//	ieee->handle_assoc_response(dev, frame, network);
	//ipw_handle_assoc_response(dev, frame, network);
	return 0;
}

int darwin_iwi2100::ieee80211_network_init(struct ieee80211_device *ieee, struct ieee80211_probe_response
					 *beacon,
					 struct ieee80211_network *network,
					 struct ieee80211_rx_stats *stats)
{
   IWI_DEBUG_FULL("ieee80211_network_init\n");
	 // add by kazu expire qos routine
	network->qos_data.active = 0;
	network->qos_data.supported = 0;
	network->qos_data.param_count = 0;
	network->qos_data.old_param_count = 0;
    

	/* Pull out fixed field data */
	memcpy(network->bssid, beacon->header.addr3, ETH_ALEN);
	network->capability = le16_to_cpu(beacon->capability);
	network->last_scanned = ieee->scans;
	network->time_stamp[0] = le32_to_cpu(beacon->time_stamp[0]);
	network->time_stamp[1] = le32_to_cpu(beacon->time_stamp[1]);
	network->beacon_interval = le16_to_cpu(beacon->beacon_interval);
	/* Where to pull this? beacon->listen_interval; */
	network->listen_interval = 0x0A;
	network->rates_len = network->rates_ex_len = 0;
	network->last_associate = 0;
	network->ssid_len = 0;
	network->flags = 0;
	network->atim_window = 0;
	network->erp_value = (network->capability & WLAN_CAPABILITY_IBSS) ?
	    0x3 : 0x0;

	if (stats->freq == IEEE80211_52GHZ_BAND) {
		/* for A band (No DS info) */
		network->channel = stats->received_channel;
	} else
		network->flags |= NETWORK_HAS_CCK;

	network->wpa_ie_len = 0;
	network->rsn_ie_len = 0;

     
	if (ieee80211_parse_info_param
	    (beacon->info_element, stats->len - sizeof(*beacon), network))
		return 1;
    
	
	
	network->mode = 0;
	if (stats->freq == IEEE80211_52GHZ_BAND)
		network->mode = IEEE_A;
	else {
		if (network->flags & NETWORK_HAS_OFDM)
			network->mode |= IEEE_G;
		if (network->flags & NETWORK_HAS_CCK)
			network->mode |= IEEE_B;
	}

	if (network->mode == 0) {
		IEEE80211_DEBUG_SCAN("Filtered out '%s (" MAC_FMT ")' "
				     "network.\n",
				     escape_essid((const char *)network->ssid,
						  network->ssid_len),
				     MAC_ARG(network->bssid));
		return 1;
	}
   
	if (ieee80211_is_empty_essid((const char *)network->ssid, network->ssid_len))
		network->flags |= NETWORK_EMPTY_ESSID;

	memcpy(&network->stats, stats, sizeof(network->stats));

	return 0;
}

void darwin_iwi2100::update_network(struct ieee80211_network *dst,
				  struct ieee80211_network *src)
{
	int qos_active;
	u8 old_param;

	ieee80211_network_reset(dst);
	dst->ibss_dfs = src->ibss_dfs;

	/* We only update the statistics if they were created by receiving
	 * the network information on the actual channel the network is on.
	 *
	 * This keeps beacons received on neighbor channels from bringing
	 * down the signal level of an AP. */
	if (dst->channel == src->stats.received_channel)
		memcpy(&dst->stats, &src->stats,
		       sizeof(struct ieee80211_rx_stats));
	else
		IEEE80211_DEBUG_SCAN("Network " MAC_FMT " info received "
			"off channel (%d vs. %d)\n", MAC_ARG(src->bssid),
			dst->channel, src->stats.received_channel);

	dst->capability = src->capability;
	memcpy(dst->rates, src->rates, src->rates_len);
	dst->rates_len = src->rates_len;
	memcpy(dst->rates_ex, src->rates_ex, src->rates_ex_len);
	dst->rates_ex_len = src->rates_ex_len;

	dst->mode = src->mode;
	dst->flags = src->flags;
	dst->time_stamp[0] = src->time_stamp[0];
	dst->time_stamp[1] = src->time_stamp[1];

	dst->beacon_interval = src->beacon_interval;
	dst->listen_interval = src->listen_interval;
	dst->atim_window = src->atim_window;
	dst->erp_value = src->erp_value;
	dst->tim = src->tim;

	memcpy(dst->wpa_ie, src->wpa_ie, src->wpa_ie_len);
	dst->wpa_ie_len = src->wpa_ie_len;
	memcpy(dst->rsn_ie, src->rsn_ie, src->rsn_ie_len);
	dst->rsn_ie_len = src->rsn_ie_len;

	dst->last_scanned = jiffies;
	qos_active = src->qos_data.active;
	old_param = dst->qos_data.old_param_count;
	if (dst->flags & NETWORK_HAS_QOS_MASK)
		memcpy(&dst->qos_data, &src->qos_data,
		       sizeof(struct ieee80211_qos_data));
	else {
		dst->qos_data.supported = src->qos_data.supported;
		dst->qos_data.param_count = src->qos_data.param_count;
	}

	if (dst->qos_data.supported == 1) {
		if (dst->ssid_len)
			IEEE80211_DEBUG_QOS
			    ("QoS the network %s is QoS supported\n",
			     dst->ssid);
		else
			IEEE80211_DEBUG_QOS
			    ("QoS the network is QoS supported\n");
	}
	dst->qos_data.active = qos_active;
	dst->qos_data.old_param_count = old_param;

	/* dst->last_associate is not overwritten */
}

void darwin_iwi2100::ieee80211_process_probe_response(struct ieee80211_device *ieee,
        struct ieee80211_probe_response *beacon,
        struct ieee80211_rx_stats *stats)
{
	struct net_device *dev = ieee->dev;
	struct ieee80211_network network;
		network.ibss_dfs = NULL;
	struct ieee80211_network *target;
	struct ieee80211_network *oldest = NULL;
	
	IWI_DEBUG_FULL("'%s' (" MAC_FMT
			     "): %c%c%c%c %c%c%c%c-%c%c%c%c %c%c%c%c\n",
			     escape_essid((const char*)beacon->info_element->data,
					  beacon->info_element->len),
			     MAC_ARG(beacon->header.addr3),
			     (beacon->capability & (1 << 0xf)) ? '1' : '0',
			     (beacon->capability & (1 << 0xe)) ? '1' : '0',
			     (beacon->capability & (1 << 0xd)) ? '1' : '0',
			     (beacon->capability & (1 << 0xc)) ? '1' : '0',
			     (beacon->capability & (1 << 0xb)) ? '1' : '0',
			     (beacon->capability & (1 << 0xa)) ? '1' : '0',
			     (beacon->capability & (1 << 0x9)) ? '1' : '0',
			     (beacon->capability & (1 << 0x8)) ? '1' : '0',
			     (beacon->capability & (1 << 0x7)) ? '1' : '0',
			     (beacon->capability & (1 << 0x6)) ? '1' : '0',
			     (beacon->capability & (1 << 0x5)) ? '1' : '0',
			     (beacon->capability & (1 << 0x4)) ? '1' : '0',
			     (beacon->capability & (1 << 0x3)) ? '1' : '0',
			     (beacon->capability & (1 << 0x2)) ? '1' : '0',
			     (beacon->capability & (1 << 0x1)) ? '1' : '0',
			     (beacon->capability & (1 << 0x0)) ? '1' : '0');

	if (ieee80211_network_init(ieee, beacon, &network, stats)) {
		IWI_DEBUG_FULL("Dropped '%s' (" MAC_FMT ") via %s.\n",
				     escape_essid((const char*)beacon->info_element->data,
						  beacon->info_element->len),
				     MAC_ARG(beacon->header.addr3),
				     is_beacon(beacon->header.frame_ctl) ?
				     "BEACON" : "PROBE RESPONSE");
		return;
	}

	/* The network parsed correctly -- so now we scan our known networks
	 * to see if we can find it in our list.
	 *
	 * NOTE:  This search is definitely not optimized.  Once its doing
	 *        the "right thing" we'll optimize it for efficiency if
	 *        necessary */

	/* Search for this entry in the list and update it if it is
	 * already there. */

	//spin_lock_irqsave(&ieee->lock, flags);
	//IOLockLock(mutex);
	list_for_each_entry(target, &ieee->network_list, list) {
		if (is_same_network(target, &network))
			break;

		if ((oldest == NULL) ||
		    (target->last_scanned < oldest->last_scanned))
			oldest = target;
	}

	/* If we didn't find a match, then get a new network slot to initialize
	 * with this beacon's information */
	if (&target->list == &ieee->network_list) {
		if (list_empty(&ieee->network_free_list)) {
			/* If there are no more slots, expire the oldest */
			list_del(&oldest->list);
			target = oldest;
			IWI_DEBUG_FULL("Expired '%s' (" MAC_FMT ") from "
					     "network list.\n",
					     escape_essid((const char*)target->ssid,
							  target->ssid_len),
					     MAC_ARG(target->bssid));
			ieee80211_network_reset(target);
		} else {
			/* Otherwise just pull from the free list */
			target = list_entry(ieee->network_free_list.next,
					    struct ieee80211_network, list);
			list_del(ieee->network_free_list.next);
		}

		memcpy(target, &network, sizeof(*target));
		network.ibss_dfs = NULL;
		list_add_tail(&target->list, &ieee->network_list);
	} else {
		IWI_DEBUG_FULL("Updating '%s' (" MAC_FMT ") via %s.\n",
				     escape_essid((const char*)target->ssid,
						  target->ssid_len),
				     MAC_ARG(target->bssid),
				     is_beacon(beacon->header.frame_ctl) ?
				     "BEACON" : "PROBE RESPONSE");
		update_network(target, &network);
		network.ibss_dfs = NULL;
	}

	//spin_unlock_irqrestore(&ieee->lock, flags);
	//IOLockUnlock(mutex);
	
	/*if (is_beacon(beacon->header.frame_ctl)) {
				ipw_handle_probe_response(dev, beacon, target);
		//if (ieee->handle_beacon != NULL)
		//	ieee->handle_beacon(dev, beacon, target);
	} else {
				ipw_handle_beacon(dev, beacon, target);
		//if (ieee->handle_probe_response != NULL)
		//	ieee->handle_probe_response(dev, beacon, target);
	}*/
}

UInt32 darwin_iwi2100::outputPacket(mbuf_t m, void * param)
{
	if((fNetif->getFlags() & IFF_RUNNING)==0 || m==NULL)
	{
		if (m)
		if (!(mbuf_type(m) == MBUF_TYPE_FREE) ) freePacket(m);
		m=NULL;
		netStats->outputErrors++;
		return kIOReturnOutputDropped;
	}
	
	
	mbuf_t nm;
	int ret = kIOReturnOutputDropped;

	//checking supported packet
	
	IWI_DEBUG_FULL("outputPacket t: %d f:%04x\n",mbuf_type(m),mbuf_flags(m));
	
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
	ret  = ieee80211_xmit(nm,priv->net_dev);

finish:	
	
	/* free finished packet */
	/*if (m)
	if (!(mbuf_type(m) == MBUF_TYPE_FREE) ) freePacket(m);
	m=NULL;
	if (ret ==  kIOReturnOutputDropped) { 
	if (nm)
		if (!(mbuf_type(nm) == MBUF_TYPE_FREE) ) freePacket(nm);
		//nm=NULL;
	}*/
	return ret;	
}

u8 P802_1H_OUI[P80211_OUI_LEN] = { 0x00, 0x00, 0xf8 };
u8 RFC1042_OUI[P80211_OUI_LEN] = { 0x00, 0x00, 0x00 };

int darwin_iwi2100::ieee80211_copy_snap(u8 * data, u16 h_proto)
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

struct ieee80211_txb *darwin_iwi2100::ieee80211_alloc_txb(int nr_frags, int txb_size,
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
		//mbuf_getpacket(MBUF_WAITOK , &txb->fragments[i]);
		//__dev_alloc_skb(txb_size + headroom,						    gfp_mask);
		if (unlikely(!txb->fragments[i])) {
			i--;
			break;
		}
		// default m_len is alocated size in mbuf
		// must set 0 m_len , pkthdr.len . 
		mbuf_setlen(txb->fragments[i],0);
		mbuf_pkthdr_setlen(txb->fragments[i],0);

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

int darwin_iwi2100::ieee80211_xmit(mbuf_t skb, struct net_device *dev)
{
	struct ieee80211_device *ieee = priv->ieee;//netdev_priv(dev);
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
		IWI_WARN( " tx queue is full \n");
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
			//freePacket(skb);
			if (skb_new!=NULL) freePacket(skb_new);
			skb_new=NULL;
			goto failed;
		}
		//dev_kfree_skb_any(skb);
		 if (skb!=NULL) freePacket(skb);
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
	     if (!(mbuf_type(skb) == MBUF_TYPE_FREE) )freePacket(skb);
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
		//if (skb_frag)
		//if (!(mbuf_type(skb_frag) == MBUF_TYPE_FREE) ) freePacket(skb_frag);
		//skb_frag=NULL;
	}

	return ret;

      failed:
	//spin_unlock_irqrestore(&ieee->lock, flags);
	//IOLockUnlock(mutex);
	//netif_stop_queue(dev);
	IWI_WARN("TX drop\n");
	if (skb)
	if (!(mbuf_type(skb) == MBUF_TYPE_FREE) ) freePacket(skb);
	skb=NULL;
	ieee80211_txb_free(txb);
	//if (skb_frag)
	//if (!(mbuf_type(skb_frag) == MBUF_TYPE_FREE) ) freePacket(skb_frag);
	//skb_frag=NULL;
	////fTransmitQueue->stop();
	//////fTransmitQueue->setCapacity(0);
	////fTransmitQueue->flush();
	stats->tx_errors++;
	netStats->outputErrors++;
	return kIOReturnOutputDropped;
}

int darwin_iwi2100::ipw_net_hard_start_xmit(struct ieee80211_txb *txb,
				   struct net_device *dev, int pri)
{
	//struct ipw_priv *priv = ieee80211_priv(dev);
	int ret;
	//IOInterruptState	instate;

	IWI_DEBUG_FULL("dev->xmit(%d bytes)\n", txb->payload_size);
	//spin_lock_irqsave(&priv->lock, flags);
	//IOLockLock(mutex);
	//instate = IOSimpleLockLockDisableInterrupt( spin);
	
	if (!(priv->status & STATUS_ASSOCIATED)) {
		IWI_ERR("Tx attempt while not associated.\n");
		priv->ieee->stats.tx_carrier_errors++;
		//netif_stop_queue(dev);
		////fTransmitQueue->stop();
		//////fTransmitQueue->setCapacity(0);
		////fTransmitQueue->flush();
		goto fail_unlock;
	}
	if (txb->payload_size==0) goto fail_unlock;
	
	ret = ipw_tx_skb(priv, txb, pri);
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

int darwin_iwi2100::ipw_tx_skb(struct ipw2100_priv *priv, struct ieee80211_txb *txb, int pri)
{
	//struct ipw2100_priv *priv = ieee80211_priv(dev);
	struct list_head *element;
	struct ipw2100_tx_packet *packet;
	unsigned long flags;

	//spin_lock_irqsave(&priv->low_lock, flags);

	if (!(priv->status & STATUS_ASSOCIATED)) {
		IWI_DEBUG("Can not transmit when not connected.\n");
		priv->ieee->stats.tx_carrier_errors++;
		//netif_stop_queue(dev);
		goto fail_unlock;
	}

	if (list_empty(&priv->tx_free_list))
		goto fail_unlock;

	element = priv->tx_free_list.next;
	packet = list_entry(element, struct ipw2100_tx_packet, list);

	packet->info.d_struct.txb = txb;

	//IWI_DEBUG("Sending fragment (%d bytes):\n", mbuf_len(txb->fragments[0]));
	//printk_buf(IPW_DL_TX, txb->fragments[0]->data, txb->fragments[0]->len);

	packet->jiffy_start = jiffies;

	list_del(element);
	DEC_STAT(&priv->tx_free_stat);

	list_add_tail(element, &priv->tx_pend_list);
	INC_STAT(&priv->tx_pend_stat);

	ipw2100_tx_send_data(priv);

	//spin_unlock_irqrestore(&priv->low_lock, flags);
	return kIOReturnOutputSuccess;

      fail_unlock:
	//netif_stop_queue(dev);
	//spin_unlock_irqrestore(&priv->low_lock, flags);
	//fTransmitQueue->stop();
	return kIOReturnOutputDropped;
}

void darwin_iwi2100::ieee80211_rx_mgt(struct ieee80211_device *ieee, 
        struct ieee80211_hdr_4addr *header,struct ieee80211_rx_stats *stats)
{
	// copy from ieee80211_rx.c ieee80211_rx_mgt
	switch (WLAN_FC_GET_STYPE(le16_to_cpu(header->frame_ctl))) {
	case IEEE80211_STYPE_ASSOC_RESP:
		IWI_DEBUG_FULL("received ASSOCIATION RESPONSE (%d)\n",
				WLAN_FC_GET_STYPE(le16_to_cpu(header->frame_ctl)));
		ieee80211_handle_assoc_resp(ieee,
				                    (struct ieee80211_assoc_response *)
									header, stats); 
		break;
	case IEEE80211_STYPE_REASSOC_RESP:
			IWI_DEBUG_FULL("received REASSOCIATION RESPONSE (%d)\n",
								 WLAN_FC_GET_STYPE(le16_to_cpu
													(header->frame_ctl)));
		break;
	case IEEE80211_STYPE_PROBE_REQ:
			IWI_DEBUG_FULL("received auth (%d)\n",
                                     WLAN_FC_GET_STYPE(le16_to_cpu
                                                       (header->frame_ctl)));
			IWI_DEBUG_FULL("but not impletented \n");										   
            /*
			if (ieee->handle_probe_request != NULL)
                        ieee->handle_probe_request(ieee->dev,
                                                   (struct
                                                    ieee80211_probe_request *)
                                                   header, stats); */
		break;
	case IEEE80211_STYPE_PROBE_RESP:
			IWI_DEBUG_FULL("received PROBE RESPONSE (%d)\n",
                                     WLAN_FC_GET_STYPE(le16_to_cpu
                                                       (header->frame_ctl)));	
			/*ipw_handle_probe_request(ieee->dev, (struct
                                                    ieee80211_probe_request *)
                                                   header, stats);*/
                ieee80211_process_probe_response(ieee,
                                                 (struct
                                                  ieee80211_probe_response *)
                                                 header, stats); 
		break;
	case IEEE80211_STYPE_BEACON:
                IWI_DEBUG_FULL("received BEACON (%d)\n",
                                     WLAN_FC_GET_STYPE(le16_to_cpu
                                                       (header->frame_ctl)));
                ieee80211_process_probe_response(ieee,
                                                 (struct
                                                  ieee80211_probe_response *)
                                                 header, stats); 
                break;
	case IEEE80211_STYPE_AUTH:

                IWI_DEBUG_FULL("received auth (%d)\n",
                                     WLAN_FC_GET_STYPE(le16_to_cpu
                                                       (header->frame_ctl)));
                IWI_DEBUG_FULL("but not impletented \n"); 
				/*
                if (ieee->handle_auth != NULL)
                        ieee->handle_auth(ieee->dev,
                                          (struct ieee80211_auth *)header); */
                break;

	case IEEE80211_STYPE_DISASSOC:
		        IWI_DEBUG_FULL("DISASSOC: not impletented \n");
				/* 
                if (ieee->handle_disassoc != NULL)
                        ieee->handle_disassoc(ieee->dev,
                                              (struct ieee80211_disassoc *)
                                              header); */
                break;
	case IEEE80211_STYPE_ACTION:
                IWI_DEBUG_FULL("ACTION\n");
				IWI_DEBUG_FULL("ACTION: but not impletented \n");
				/* 
                if (ieee->handle_action)
                        ieee->handle_action(ieee->dev,
                                            (struct ieee80211_action *)
                                            header, stats); */
                break;

	case IEEE80211_STYPE_REASSOC_REQ:
                IWI_DEBUG_FULL("received reassoc (%d)\n",
                                     WLAN_FC_GET_STYPE(le16_to_cpu
                                                       (header->frame_ctl)));

                IWI_DEBUG_FULL("%s: IEEE80211_REASSOC_REQ received\n",
									 ieee->dev->name);
				IWI_DEBUG_FULL("REASSOC: but not impletented \n");
				/*
                if (ieee->handle_reassoc_request != NULL)
                        ieee->handle_reassoc_request(ieee->dev,
                                                    (struct ieee80211_reassoc_request *)
                                                     header); */
                break;
	case IEEE80211_STYPE_ASSOC_REQ:
                IWI_DEBUG_FULL("received assoc (%d)\n",
                                     WLAN_FC_GET_STYPE(le16_to_cpu
                                                       (header->frame_ctl)));
				ieee80211_handle_assoc_resp(ieee,
				                    (struct ieee80211_assoc_response *)
									header, stats); 
				/*ieee80211_process_probe_response(ieee,
                                                 (struct
                                                  ieee80211_probe_response *)
                                                 header, stats);*/
                /* if (ieee->handle_assoc_request != NULL)
                        ieee->handle_assoc_request(ieee->dev); */
                break;

	case IEEE80211_STYPE_DEAUTH:
                IWI_DEBUG_FULL("DEAUTH\n");
				IWI_DEBUG_FULL("DEAUTH: but not impletented \n");
                /*if (ieee->handle_deauth != NULL)
                        ieee->handle_deauth(ieee->dev,
                                            (struct ieee80211_deauth *)
                                            header); */
                break;
	default:
                IWI_DEBUG_FULL("received UNKNOWN (%d)\n",
                                     WLAN_FC_GET_STYPE(le16_to_cpu
                                                       (header->frame_ctl)));
                IWI_DEBUG_FULL("%s: Unknown management packet: %d\n",
									ieee->dev->name,
                                     WLAN_FC_GET_STYPE(le16_to_cpu
                                                       (header->frame_ctl)));
                break;
	}
}

void darwin_iwi2100::isr_rx(struct ipw2100_priv *priv, int i,
			  struct ieee80211_rx_stats *stats)
{
	struct ipw2100_status *status = &priv->status_queue.drv[i];
	struct ipw2100_rx_packet *packet = &priv->rx_buffers[i];

	//mbuf_setlen(packet->skb,sizeof(struct ipw2100_rx));
	//mbuf_pkthdr_setlen(packet->skb,sizeof(struct ipw2100_rx));
			 
	if (unlikely(status->frame_size > mbuf_trailingspace(packet->skb))) {
		IWI_DEBUG("%s: frame_size (%u) > mbuf_trailingspace (%u)!"
			       "  Dropping.\n",
			       priv->net_dev->name,
			       status->frame_size, mbuf_trailingspace(packet->skb));
		priv->ieee->stats.rx_errors++;
		return;
	}
	if ((fNetif->getFlags() & IFF_RUNNING)==0) {
		priv->ieee->stats.rx_errors++;
		//priv->wstats.discard.misc++;
		IWI_DEBUG("Dropping packet while interface is not up.\n");
		return;
	}

	if (unlikely(priv->ieee->iw_mode != IW_MODE_MONITOR &&
		     !(priv->status & STATUS_ASSOCIATED))) {
		IWI_DEBUG("Dropping packet while not associated.\n");
		//priv->wstats.discard.misc++;
		return;
	}

	//pci_unmap_single(priv->pci_dev,
	//		 packet->dma_addr,
	//		 sizeof(struct ipw2100_rx), PCI_DMA_FROMDEVICE);

	//todo: check if works
	packet->dma_addr=NULL;
	
	//skb_reserve(packet->skb, offsetof(struct ipw2100_rx_packet, rxp->rx_data));
	skb_put(packet->skb, le16_to_cpu(status->frame_size));
	
	
	//skb_put(packet->skb, status->frame_size);
	/*mbuf_setdata(packet->skb, (UInt8*)mbuf_data(packet->skb) + offsetof(struct ipw2100_rx_packet, rxp->rx_data), status->frame_size);
	if( mbuf_flags(packet->skb) & MBUF_PKTHDR)
			mbuf_pkthdr_setlen(packet->skb, status->frame_size);*/
			
	if (!ieee80211_rx(priv->ieee, packet->skb, stats)) {
		IWI_DEBUG("%s: Non consumed packet:\n",
			       priv->net_dev->name);
		//printk_buf(IPW_DL_DROP, packet_data, status->frame_size);
		priv->ieee->stats.rx_errors++;

		/* ieee80211_rx failed, so it didn't free the SKB */
		if (packet->skb)
		if (!(mbuf_type(packet->skb) == MBUF_TYPE_FREE) ) freePacket(packet->skb);
		packet->skb = NULL;
	}

	/* We need to allocate a new SKB and attach it to the RDB. */
	if (unlikely(ipw2100_alloc_skb(priv, packet))) {
		IWI_DEBUG(  ": "
		       "%s: Unable to allocate SKB onto RBD ring - disabling "
		       "adapter.\n", priv->net_dev->name);
		/* TODO: schedule adapter shutdown */
		IWI_DEBUG("TODO: Shutdown adapter...\n");
	}

	/* Update the RDB entry */
	priv->rx_queue.drv[i].host_addr = packet->dma_addr;
}

int darwin_iwi2100::ieee80211_rx(struct ieee80211_device *ieee, mbuf_t skb,
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
	stats = &ieee->stats;

	if (mbuf_pkthdr_len(skb) < 10) {
		IWI_DEBUG_FULL( "%s: SKB length < 10\n", ieee->dev->name);
		goto rx_dropped;
	}

	fc = le16_to_cpu(hdr->frame_ctl);
	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);
	sc = le16_to_cpu(hdr->seq_ctl);
	frag = WLAN_GET_SEQ_FRAG(sc);
	hdrlen = ieee80211_get_hdrlen(fc);


	if (ieee->iw_mode == IW_MODE_MONITOR) {
		stats->rx_packets++;
		stats->rx_bytes += mbuf_pkthdr_len(skb);
		//ieee80211_monitor_rx(ieee, skb, rx_stats);
		return 1;
	}

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
			IWI_DEBUG_FULL("RX: dropped data frame "
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
			freePacket(skb);
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
	stats->rx_packets++;
	stats->rx_bytes += mbuf_pkthdr_len(skb);


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
	IWI_DEBUG_FULL("rx dropped %d\n",stats->rx_dropped);
	stats->rx_dropped++;
	netStats->inputErrors++;
	/* Returning 0 indicates to caller that we have not handled the SKB--
	 * so it is still allocated and can be used again by underlying
	 * hardware as a DMA target */
	return 0;
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
		IWI_DEBUG("exit - bad read index\n");
		return;
	}

	i = (rxq->next + 1) % rxq->entries;
	s = i;
	while (i != r) {
		 IWI_DEBUG_FULL("r = %d : w = %d : processing = %d\n",
		   r, rxq->next, i); 

		packet = &priv->rx_buffers[i];

		//mbuf_setlen(packet->skb,sizeof(struct ipw2100_status));
		//mbuf_pkthdr_setlen(packet->skb,sizeof(struct ipw2100_status));
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

		IWI_DEBUG_FULL("%s: '%s' frame type received (%d).\n",
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
				isr_rx(priv, i, &stats);
				break;

			}
			break;
		}

	      increment:
		/* clear status field associated with this RBD */
		rxq->drv[i].status.info.field = 0;

		i = (i + 1) % rxq->entries;
	}

	//if(doFlushQueue){
		IWI_DEBUG_FULL("flushing Input Queue\n");
		fNetif->flushInputQueue();		
		//fTransmitQueue->service(IOBasicOutputQueue::kServiceAsync);
		//}
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
	IWI_DEBUG_FULL("__ipw2100_tx_process\n");
	
	
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
		IWI_DEBUG_FULL(  ": %s: Bad fw_pend_list entry!\n",
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
		IWI_DEBUG_FULL(  ": %s: write index mismatch\n",
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
		IWI_DEBUG_FULL("exit - no processed packets ready to release.\n");
		return 0;
	}

	list_del(element);
	DEC_STAT(&priv->fw_pend_stat);
/*
#ifdef CONFIG_IPW2100_DEBUG
	{
		int i = txq->oldest;
		IWI_DEBUG("TX%d V=%p P=%04X T=%04X L=%d\n", i,
			     &txq->drv[i],
			     (u32) (txq->nic + i * sizeof(struct ipw2100_bd)),
			     txq->drv[i].host_addr, txq->drv[i].buf_length);

		if (packet->type == DATA) {
			i = (i + 1) % txq->entries;

			IWI_DEBUG("TX%d V=%p P=%04X T=%04X L=%d\n", i,
				     &txq->drv[i],
				     (u32) (txq->nic + i *
					    sizeof(struct ipw2100_bd)),
				     (u32) txq->drv[i].host_addr,
				     txq->drv[i].buf_length);
		}
	}
#endif
*/
	switch (packet->type) {
	case DATA:
		if (txq->drv[txq->oldest].status.info.fields.txType != 0)
			IWI_DEBUG_FULL(  ": %s: Queue mismatch.  "
			       "Expecting DATA TBD but pulled "
			       "something else: ids %d=%d.\n",
			       priv->net_dev->name, txq->oldest, packet->index);

		/* DATA packet; we have to unmap and free the SKB */
		for (i = 0; i < frag_num; i++) {
			tbd = &txq->drv[(packet->index + 1 + i) % txq->entries];

			IWI_DEBUG_FULL("TX%d P=%08x L=%d\n",
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
			IWI_DEBUG_FULL(  ": %s: Queue mismatch.  "
			       "Expecting COMMAND TBD but pulled "
			       "something else: ids %d=%d.\n",
			       priv->net_dev->name, txq->oldest, packet->index);

#ifdef CONFIG_IPW2100_DEBUG
		if (packet->info.c_struct.cmd->host_command_reg <
		    sizeof(command_types) / sizeof(*command_types))
			IWI_DEBUG_FULL("Command '%s (%d)' processed: %d.\n",
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

	IWI_DEBUG_FULL("packet latency (send to process)  %ld jiffies\n",
		     jiffies - packet->jiffy_start);

	return (!list_empty(&priv->fw_pend_list));
}

void darwin_iwi2100::__ipw2100_tx_complete(struct ipw2100_priv *priv)
{
	int i = 0;

	while (__ipw2100_tx_process(priv) && i < 200)
		i++;

	if (i == 200) {
		IWI_DEBUG_FULL(  ": "
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

	if ((inta & IPW_INTERRUPT_MASK )== 0) goto skipi;
	
	//IWI_DEBUG("enter - INTA: 0x%08lX\n",
	//	      (unsigned long)inta & IPW_INTERRUPT_MASK);

	priv->in_isr++;
	priv->interrupts++;

	/* We do not loop and keep polling for more interrupts as this
	 * is frowned upon and doesn't play nicely with other potentially
	 * chained IRQs */
	IWI_DEBUG_FULL("INTA: 0x%08lX\n",
		      (unsigned long)inta & IPW_INTERRUPT_MASK);

	if (inta & IPW2100_INTA_FATAL_ERROR) {
		IWI_DEBUG( 
		       ": Fatal interrupt. Scheduling firmware restart.\n");
		priv->inta_other++;
		write_register(dev, IPW_REG_INTA, IPW2100_INTA_FATAL_ERROR);

		read_nic_dword(dev, IPW_NIC_FATAL_ERROR, &priv->fatal_error);
		IWI_DEBUG("%s: Fatal error value: 0x%08X\n",
			       priv->net_dev->name, priv->fatal_error);

		read_nic_dword(dev, IPW_ERROR_ADDR(priv->fatal_error), &tmp);
		IWI_DEBUG("%s: Fatal error address value: 0x%08X\n",
			       priv->net_dev->name, tmp);

		/* Wake up any sleeping jobs */
		schedule_reset(priv);
	}

	if (inta & IPW2100_INTA_PARITY_ERROR) {
		IWI_DEBUG_FULL( 
		       ": ***** PARITY ERROR INTERRUPT !!!! \n");
		priv->inta_other++;
		write_register(dev, IPW_REG_INTA, IPW2100_INTA_PARITY_ERROR);
	}

	if (inta & IPW2100_INTA_RX_TRANSFER) {
		IWI_DEBUG_FULL("RX interrupt\n");

		priv->rx_interrupts++;

		write_register(dev, IPW_REG_INTA, IPW2100_INTA_RX_TRANSFER);

		__ipw2100_rx_process(priv);
		__ipw2100_tx_complete(priv);
	}

	if (inta & IPW2100_INTA_TX_TRANSFER) {
		IWI_DEBUG_FULL("TX interrupt\n");

		priv->tx_interrupts++;

		write_register(dev, IPW_REG_INTA, IPW2100_INTA_TX_TRANSFER);

		__ipw2100_tx_complete(priv);
		ipw2100_tx_send_commands(priv);
		ipw2100_tx_send_data(priv);
	}

	if (inta & IPW2100_INTA_TX_COMPLETE) {
		IWI_DEBUG_FULL("TX complete\n");
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
		IWI_DEBUG_FULL("FW init done interrupt\n");
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
		IWI_DEBUG_FULL("Status change interrupt\n");
		priv->inta_other++;
		write_register(dev, IPW_REG_INTA, IPW2100_INTA_STATUS_CHANGE);
	}

	if (inta & IPW2100_INTA_SLAVE_MODE_HOST_COMMAND_DONE) {
		IWI_DEBUG_FULL("slave host mode interrupt\n");
		priv->inta_other++;
		write_register(dev, IPW_REG_INTA,
			       IPW2100_INTA_SLAVE_MODE_HOST_COMMAND_DONE);
	}

	priv->in_isr--;
	
skipi:
	ipw2100_enable_interrupts(priv);
	//fTransmitQueue->service(IOBasicOutputQueue::kServiceAsync);
	//fTransmitQueue->start();
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

//   486: IOReturn WiFiController::setHardwareAddress(const void * addr, UInt32 addrBytes) {
//   487:     IOReturn ret;
//   488:     if (addrBytes != kIOEthernetAddressSize) return kIOReturnBadArgument;
//   489:     
//   490:     ret = setHardwareAddressHardware((UInt8*)addr);
//   491:     if (ret == kIOReturnSuccess) {
//   492:         bcopy(addr, &_myAddress, addrBytes);
//   493:     }
//   494:     return ret;
//   495: }

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
				IWI_DEBUG("MAC address read failed\n");
				return -EIO;
			}
			IWI_DEBUG("card MAC is %02X:%02X:%02X:%02X:%02X:%02X\n",
					   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

			memcpy(fEnetAddr.bytes, mac, ETH_ALEN);
			IWI_DEBUG("copy add done\n");
		}
	}
	memcpy(addr, &fEnetAddr, sizeof(*addr));
	if (priv)
	{
		memcpy(priv->mac_addr, &fEnetAddr.bytes, ETH_ALEN);
		memcpy(priv->net_dev->dev_addr, &fEnetAddr.bytes, ETH_ALEN);
		memcpy(priv->ieee->dev->dev_addr, &fEnetAddr.bytes, ETH_ALEN);
		//IWI_DEBUG("getHardwareAddress " MAC_FMT "\n",MAC_ARG(priv->mac_addr));
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
		IWI_DEBUG("%s timeout waiting for master\n", getName());

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
		IWI_DEBUG("%s timeout waiting for clock stabilization\n", getName());
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
		IWI_DEBUG("wait for stop master failed after 100ms\n");
		return -1;
	}

	//IWI_DEBUG("stop master %dms\n", rc);

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
		IWI_DEBUG("%s: dma_mem_alloc failer\n", getName());
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

	//	IWI_DEBUG("dst: 0x%8x    len: 0x%8x\n",dst,len);
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
		IWI_DEBUG("timeout processing command blocks\n");
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
		IWI_DEBUG("Memory Allocation failed - RLC");

		return NULL;
	}

	memMap = memBuffer->map();

	if (memMap == NULL) {
		IWI_DEBUG("mapping failed\n");
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
	priv->status |= STATUS_CMD_ACTIVE;
	
	desc = &this->cmdq.desc[cmdq.cur];
	desc->hdr.type = IWI_HDR_TYPE_COMMAND;
	desc->hdr.flags = IWI_HDR_FLAG_IRQ;
	desc->type = type;
	desc->len = len;
	memcpy(desc->data, data, len);
	
//	bus_dmamap_sync(sc->cmdq.desc_dmat, sc->cmdq.desc_map,
//	    BUS_DMASYNC_PREWRITE);

//	IWI_DEBUG("sending command idx=%u type=%u len=%u\n", cmdq.cur, type, len);

	cmdq.cur = (cmdq.cur + 1) % IWI_CMD_RING_COUNT;
	CSR_WRITE_4(memBase, IWI_CSR_CMD_WIDX, cmdq.cur);
	
	int r=0;
	if (async) 
	while (priv->status & STATUS_CMD_ACTIVE) 
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

void darwin_iwi2100::ipw2100_add_cck_scan_rates(struct ipw_supported_rates *rates,
				   u8 modulation, u32 rate_mask)
{
	
}

void darwin_iwi2100::ipw2100_add_ofdm_scan_rates(struct ipw_supported_rates *rates,
				    u8 modulation, u32 rate_mask)
{
	
}

int darwin_iwi2100::init_supported_rates(struct ipw2100_priv *priv,
				struct ipw_supported_rates *rates)
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
	 IWI_DEBUG("configureInterface done\n");
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
	IWI_DEBUG("scanning...\n");
	if (!(priv->status & STATUS_INITIALIZED) ||
	    (priv->status & STATUS_EXIT_PENDING))
		return 0;


	if (priv->status & STATUS_SCANNING) {
		IWI_DEBUG("Concurrent scan requested.  Ignoring.\n");
		priv->status |= STATUS_SCAN_PENDING;
		goto done;
	}

	if (!(priv->status & STATUS_SCAN_FORCED) &&
	    priv->status & STATUS_SCAN_ABORTING) {
		IWI_DEBUG("Scan request while abort pending.  Queuing.\n");
		priv->status |= STATUS_SCAN_PENDING;
		goto done;
	}

	if (priv->status & STATUS_RF_KILL_MASK) {
		IWI_DEBUG("Aborting scan due to RF Kill activation\n");
		priv->status |= STATUS_SCAN_PENDING;
		goto done;
	}

	memset(&scan, 0, sizeof(scan));
	scan.full_scan_index = cpu_to_le32(ieee80211_get_scans(priv->ieee));

	if (type == IW_SCAN_TYPE_PASSIVE) {
		IWI_DEBUG("use passive scanning\n");
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
				IWI_DEBUG("Attempt to send SSID command "
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
		IWI_DEBUG("Sending scan command failed: %08X\n", err);
		goto done;
	}

	priv->status |= STATUS_SCANNING;
	priv->status &= ~STATUS_SCAN_PENDING;
	queue_te(4,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_scan_check),priv,5000,true);

 
	  done:
	return err;
*/
}

void darwin_iwi2100::ipw2100_scan_check(ipw2100_priv *priv)
{
	if (priv->status & (STATUS_SCANNING | STATUS_SCAN_ABORTING)) {
		IWI_DEBUG("Scan completion resetting\n");
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
		IWI_DEBUG("dma_mem_alloc failer (initCmdQueue)\n");
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
		IWI_DEBUG("failed to allocate RX Queue data\n");
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
			IWI_DEBUG("failed to alloc rx mem\n");
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
			IWI_DEBUG("alloc failure\n");
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
	IWI_DEBUG("TODO: free\n");
	return;
	IWI_DEBUG("%s Freeing\n", getName());
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
	IWI_DEBUG("ifconfig down\n");
	if ((fNetif->getFlags() & IFF_RUNNING)!=0)
	{
		IWI_DEBUG("ifconfig going down\n");
		//super::disable(fNetif);
		//fNetif->setPoweredOnByUser(false);
		fTransmitQueue->stop();
		setLinkStatus(kIONetworkLinkValid);
		//fNetif->setLinkState(kIO80211NetworkLinkDown);
		//fNetif->syncSIOCSIFFLAGS( /*IONetworkController * */this);
		//(if_flags & ~mask) | (new_flags & mask) if mask has IFF_UP if_updown fires up (kpi_interface.c in xnu)
		if (priv->status & STATUS_ASSOCIATED) ifnet_set_flags(fifnet, IFF_RUNNING, IFF_RUNNING );
		
		
		//fTransmitQueue->setCapacity(0);
		fTransmitQueue->flush();
		
				
		//if ((priv->status & STATUS_ASSOCIATED)) enable(fNetif);
		
		return kIOReturnSuccess;
		
	}
	{
		IWI_DEBUG("ifconfig already down\n");
		return -1;
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
/*SInt32
darwin_iwi2100::getSSID(IO80211Interface *interface,
						struct apple80211_ssid_data *sd)
{
	IWI_DEBUG("getSSID %s l:%d\n",escape_essid((const char*)sd->ssid_bytes, sd->ssid_len));
	return 0;
}

SInt32
darwin_iwi2100::getCHANNEL(IO80211Interface *interface,
						  struct apple80211_channel_data *cd)
{
	IWI_DEBUG("getCHANNEL c:%d f:%d\n",cd->channel.channel,cd->channel.flags);
	return 0;
}

SInt32
darwin_iwi2100::getBSSID(IO80211Interface *interface,
						struct apple80211_bssid_data *bd)
{
	IWI_DEBUG("getBSSID %s\n",escape_essid((const char*)bd->bssid.octet,sizeof(bd->bssid.octet)));
	return 0;
}

SInt32
darwin_iwi2100::getCARD_CAPABILITIES(IO80211Interface *interface,
									  struct apple80211_capability_data *cd)
{
	IWI_DEBUG("getCARD_CAPABILITIES %d\n",sizeof(cd->capabilities));
	publishProperties();
	return 0;
}

SInt32
darwin_iwi2100::getSTATE(IO80211Interface *interface,
						  struct apple80211_state_data *sd)
{
	IWI_DEBUG("getSTATE %d\n",sd->state);
	return 0;
}

SInt32
darwin_iwi2100::getRSSI(IO80211Interface *interface,
					   struct apple80211_rssi_data *rd)
{
	IWI_DEBUG("getRSSI \n");
	return 0;
}

SInt32
darwin_iwi2100::getPOWER(IO80211Interface *interface,
						struct apple80211_power_data *pd)
{
	IWI_DEBUG("getPOWER %d, %d %d %d %d\n",pd->num_radios, pd->power_state[0],pd->power_state[1],pd->power_state[2],pd->power_state[3]);
	return 0;
}

SInt32
darwin_iwi2100::getSCAN_RESULT(IO80211Interface *interface,
							  struct apple80211_scan_result **scan_result)
{
	IWI_DEBUG("getSCAN_RESULT \n");
	return 0;
}


SInt32
darwin_iwi2100::getRATE(IO80211Interface *interface,
					   struct apple80211_rate_data *rd)
{
	IWI_DEBUG("getRATE %d\n",rd->rate);
	return 0;
}

SInt32
darwin_iwi2100::getSTATUS_DEV(IO80211Interface *interface,
							 struct apple80211_status_dev_data *dd)
{
	char i[4];
	int n=interface->getUnitNumber();
	sprintf(i,"en%d",n);
	IWI_DEBUG("getSTATUS_DEV %s\n",dd->dev_name);
	ifnet_find_by_name(i,&fifnet);
	IWI_DEBUG("ifnet_t %s%d = %x\n",ifnet_name(fifnet),ifnet_unit(fifnet),fifnet);
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
	IWI_DEBUG("getRATE_SET %d r0:%d f0:%d\n",rd->num_rates, rd->rates[0].rate,rd->rates[0].flags);
	return 0;
}

SInt32	darwin_iwi2100::getASSOCIATION_STATUS( IO80211Interface * interface, struct apple80211_assoc_status_data * asd )
{
	IWI_DEBUG("getASSOCIATION_STATUS %d\n",asd->status);
	return 0;
}

SInt32
darwin_iwi2100::setSCAN_REQ(IO80211Interface *interface,
						   struct apple80211_scan_data *sd)
{
	IWI_DEBUG("setSCAN_REQ \n");
	return 0;
}

SInt32
darwin_iwi2100::setASSOCIATE(IO80211Interface *interface,
							struct apple80211_assoc_data *ad)
{
	IWI_DEBUG("setASSOCIATE \n");
	return 0;
}

SInt32
darwin_iwi2100::setPOWER(IO80211Interface *interface,
						struct apple80211_power_data *pd)
{
	IWI_DEBUG("setPOWER %d, %d %d %d %d\n",pd->num_radios, pd->power_state[0],pd->power_state[1],pd->power_state[2],pd->power_state[3]);
	if (pd->power_state[pd->num_radios]==1)
	{
		IWI_DEBUG("power on\n");
	}
	else
	{
		IWI_DEBUG("power off ignored\n");
		return -1;
	}
	return 0;
}

SInt32
darwin_iwi2100::setCIPHER_KEY(IO80211Interface *interface,
							 struct apple80211_key *key)
{
	IWI_DEBUG("setCIPHER_KEY \n");
	return 0;
}

SInt32
darwin_iwi2100::setAUTH_TYPE(IO80211Interface *interface,
							struct apple80211_authtype_data *ad)
{
	IWI_DEBUG("setAUTH_TYPE \n");
	return 0;
}

SInt32
darwin_iwi2100::setDISASSOCIATE(IO80211Interface	*interface)
{
	IWI_DEBUG("setDISASSOCIATE \n");
	return 0;
}

SInt32
darwin_iwi2100::setSSID(IO80211Interface *interface,
					   struct apple80211_ssid_data *sd)
{
	IWI_DEBUG("setSSID \n");
	return 0;
}

SInt32
darwin_iwi2100::setAP_MODE(IO80211Interface *interface,
						  struct apple80211_apmode_data *ad)
{
	IWI_DEBUG("setAP_MODE \n");
	return 0;
}

bool darwin_iwi2100::attachInterfaceWithMacAddress( void * macAddr, 
												UInt32 macLen, 
												IONetworkInterface ** interface, 
												bool doRegister ,
												UInt32 timeout  )
{
	IWI_DEBUG("attachInterfaceWithMacAddress \n");
	return super::attachInterfaceWithMacAddress(macAddr,macLen,interface,doRegister,timeout);
}												
												
void darwin_iwi2100::dataLinkLayerAttachComplete( IO80211Interface * interface )											
{
	IWI_DEBUG("dataLinkLayerAttachComplete \n");
	super::dataLinkLayerAttachComplete(interface);
}
*/

void darwin_iwi2100::queue_te(int num, thread_call_func_t func, thread_call_param_t par, UInt32 timei, bool start)
{
	if (tlink[num]) queue_td(num,NULL);
	//IWI_DEBUG("queue_te0 %d\n",tlink[num]);
	if (!tlink[num]) tlink[num]=thread_call_allocate(func,this);
	//IWI_DEBUG("queue_te1 %d\n",tlink[num]);
	uint64_t timei2;
	if (timei) clock_interval_to_deadline(timei,kMillisecondScale,&timei2);
	//IWI_DEBUG("queue_te time %d %d\n",timei,timei2);
	int r;
	if (start==true && tlink[num])
	{
		if (!par && !timei)	r=thread_call_enter(tlink[num]);
		if (!par && timei)	r=thread_call_enter_delayed(tlink[num],timei2);
		if (par && !timei)	r=thread_call_enter1(tlink[num],par);
		if (par && timei)	r=thread_call_enter1_delayed(tlink[num],par,timei2);
	}
	//IWI_DEBUG("queue_te result %d\n",r);
}

void darwin_iwi2100::queue_td(int num , thread_call_func_t func)
{
	//IWI_DEBUG("queue_td0 %d\n",tlink[num]);
	//IWI_DEBUG("queue_td0 %d\n",tlink[num]);
	if (tlink[num])
	{
		thread_call_cancel(tlink[num]);
		/*if (thread_call_cancel(tlink[num])==0)
			thread_call_free(tlink[num]);
		tlink[num]=NULL;*/
	}
	//IWI_DEBUG("queue_td1-%d , %d %d\n",num,r,r1);
}

IOReturn darwin_iwi2100::message( UInt32 type, IOService * provider,
                              void * argument)
{
	IWI_DEBUG("message %8x\n",type);
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
				struct ipw_supported_rates *rates)
{
	
}

void darwin_iwi2100::ipw2100_copy_rates(struct ipw_supported_rates *dest,
			   const struct ipw_supported_rates *src)
{
	
}



int darwin_iwi2100::ipw2100_best_network(struct ipw2100_priv *priv,
			    struct ipw_network_match *match,
			    struct ieee80211_network *network, int roaming)
{
	struct ipw_supported_rates rates;
	IWI_DEBUG("ipw_best_network\n");
	
	/* dump information */
	IWI_DEBUG("iw_mode[%d] capability[%d] flag[%d] scan_age[%d]\n",priv->ieee->iw_mode,
	  network->capability,network->flags,priv->ieee->scan_age);
	IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' \n",
	  escape_essid((const char*)network->ssid, network->ssid_len),
	  MAC_ARG(network->bssid));


	//check if the network should be excluded
	/*if (priv->ieee->iw_mode == IW_MODE_INFRA)
	if (network->bssid)
	{
		for (int i=0;i<20;i++) 
		{
			if (nonets[i].bssid)
			if (!memcmp(nonets[i].bssid, network->bssid, ETH_ALEN)) 
			{
				IWI_LOG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' in exclude list. "
				"restart card to include.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid));
				//return 0;
			}
		}
	}*/

	/* Verify that this network's capability is compatible with the
	 * current mode (AdHoc or Infrastructure) */

	 //BUG: kernel panic - the driver attach to a bss network when p_mode=0 !!
	if ((priv->ieee->iw_mode == IW_MODE_INFRA &&
	     !(network->capability & WLAN_CAPABILITY_ESS)) ||
	    (priv->ieee->iw_mode == IW_MODE_ADHOC &&
	     !(network->capability & WLAN_CAPABILITY_IBSS))) {
		IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded due to "
				"capability mismatch.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid));
		return 0;
	}

	/* If we do not have an ESSID for this AP, we can not associate with
	 * it */
	if (network->flags & NETWORK_EMPTY_ESSID) {
		IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of hidden ESSID.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid));
		return 0;
	}

	if (unlikely(roaming)) {
		/* If we are roaming, then ensure check if this is a valid
		 * network to try and roam to */
		if ((network->ssid_len != match->network->ssid_len) ||
		    memcmp(network->ssid, match->network->ssid,
			   network->ssid_len)) {
			IWI_DEBUG("Netowrk '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
					"because of non-network ESSID.\n",
					escape_essid((const char*)network->ssid,
						     network->ssid_len),
					MAC_ARG(network->bssid));
			return 0;
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
			IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
					"because of ESSID mismatch: '%s'.\n",
					escaped, MAC_ARG(network->bssid),
					escape_essid((const char*)priv->essid,
						     priv->essid_len));
			return 0;
		}
	}

	/* If the old network rate is better than this one, don't bother
	 * testing everything else. */
	if (match->network && match->network->stats.rssi > network->stats.rssi) {
		char escaped[IW_ESSID_MAX_SIZE * 2 + 1];
		strncpy(escaped,
			escape_essid((const char*)network->ssid, network->ssid_len),
			sizeof(escaped));
		IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded because "
				"'%s (%02x:%02x:%02x:%02x:%02x:%02x)' has a stronger signal.\n",
				escaped, MAC_ARG(network->bssid),
				escape_essid((const char*)match->network->ssid,
					     match->network->ssid_len),
				MAC_ARG(match->network->bssid));
		//return 0;
	}

	/* If this network has already had an association attempt within the
	 * last 3 seconds, do not try and associate again... */
	if (network->last_associate &&
	    time_after(network->last_associate + (HZ * 3UL), jiffies)) {
		IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of storming (%ums since last "
				"assoc attempt).\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid),
				jiffies_to_msecs(jiffies -
						 network->last_associate));
		//return 0;
	}

	/* Now go through and see if the requested network is valid... */
	if (priv->ieee->scan_age != 0 &&
	    time_after(jiffies, network->last_scanned + priv->ieee->scan_age)) {
		IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of age: %ums.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid),
				jiffies_to_msecs(jiffies -
						 network->last_scanned));
		//return 0;
	}

	if ((priv->config & CFG_STATIC_CHANNEL) &&
	    (network->channel != priv->channel)) {
		IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of channel mismatch: %d != %d.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid),
				network->channel, priv->channel);
		//return 0;
	}

	/* Verify privacy compatability */
	if (((priv->capability & CAP_PRIVACY_ON) ? 1 : 0) !=
	    ((network->capability & WLAN_CAPABILITY_PRIVACY) ? 1 : 0)) {
		IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of privacy mismatch: %s != %s.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid),
				priv->capability & CAP_PRIVACY_ON ? "on" :
				"off",
				network->capability &
				WLAN_CAPABILITY_PRIVACY ? "on" : "off");
		return 0;
	}

	if ((priv->config & CFG_STATIC_BSSID) &&
	    memcmp(network->bssid, priv->bssid, ETH_ALEN)) {
		IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of BSSID mismatch: %02x:%02x:%02x:%02x:%02x:%02x.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid), MAC_ARG(priv->bssid));
		return 0;
	}

	/* Filter out any incompatible freq / mode combinations */
	if (!ieee80211_is_valid_mode(priv->ieee, network->mode)) {
		IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of invalid frequency/mode "
				"combination.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid));
		//return 0;
	}

	/* Filter out invalid channel in current GEO */
	// if ignored the association can be done
	// we should build a list of excluded networks and allow the user to choose the desired network -> interface
	if (!ipw2100_is_valid_channel(priv->ieee, network->channel)) {
		IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of invalid channel in current GEO\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid));
		//return 0;
	}

	/* Ensure that the rates supported by the driver are compatible with
	 * this AP, including verification of basic rates (mandatory) */
	if (!ipw2100_compatible_rates(priv, network, &rates)) {
		IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because configured rate mask excludes "
				"AP mandatory rate.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid));
		//return 0;
	}

	if (rates.num_rates == 0) {
		IWI_DEBUG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' excluded "
				"because of no compatible rates.\n",
				escape_essid((const char*)network->ssid, network->ssid_len),
				MAC_ARG(network->bssid));
		//return 0;
	}

	/* TODO: Perform any further minimal comparititive tests.  We do not
	 * want to put too much policy logic here; intelligent scan selection
	 * should occur within a generic IEEE 802.11 user space tool.  */

	/* Set up 'new' AP to this network */
	ipw2100_copy_rates(&match->rates, &rates);
	match->network = network;

	IWI_LOG("Network '%s (%02x:%02x:%02x:%02x:%02x:%02x)' is a viable match.\n",
			escape_essid((const char*)network->ssid, network->ssid_len),
			MAC_ARG(network->bssid));

	return 1;	
}

int darwin_iwi2100::ipw2100_associate(ipw2100_priv *data)
{
	
}

void darwin_iwi2100::ipw2100_set_fixed_rate(struct ipw2100_priv *priv, int mode)
{
	
}

int darwin_iwi2100::ipw2100_associate_network(struct ipw2100_priv *priv,
				 struct ieee80211_network *network,
				 struct ipw_supported_rates *rates, int roaming)
{
	IWI_DEBUG("ipw2100_associate_network\n");
	
	int ret, len, essid_len;
	char essid[IW_ESSID_MAX_SIZE];
	u32 txrate;
	u32 chan;
	char *txratename;
	u8 bssid[ETH_ALEN];

	//priv->config |= CFG_ASSOCIATE;
	IWI_DEBUG("set ssid\n");
	if (network->ssid_len>0)
	ipw2100_set_essid(priv, (char*)network->ssid, network->ssid_len,1);
	IWI_DEBUG("set txrate\n");	
	txrate=TX_RATE_11_MBIT;//network->rates[network->rates_len];
	if (txrate!=0)
	ipw2100_set_tx_rates(priv, txrate, 1);
	IWI_DEBUG("set channel\n");
	chan=network->channel;
	ipw2100_set_channel(priv, chan, 1);
	
	IWI_DEBUG("set bssid\n");
	ret=ipw2100_get_ordinal(priv, IPW_ORD_STAT_ASSN_AP_BSSID, &bssid, (u32*)&len);
	/*if (ret) {
		IWI_DEBUG("failed querying ordinals at line %d\n",
			       __LINE__);
		return 0;
	}*/
	memcpy(&bssid, network->bssid, ETH_ALEN);
	memcpy(priv->ieee->bssid, &bssid, ETH_ALEN);

	
	switch (txrate) {
	case TX_RATE_1_MBIT:
		txratename = "1Mbps";
		break;
	case TX_RATE_2_MBIT:
		txratename = "2Mbsp";
		break;
	case TX_RATE_5_5_MBIT:
		txratename = "5.5Mbps";
		break;
	case TX_RATE_11_MBIT:
		txratename = "11Mbps";
		break;
	default:
		IWI_DEBUG("Unknown rate: %d\n", txrate);
		txratename = "unknown rate";
		break;
	}

	IWI_DEBUG("%s: Associated with '%s' at %s, channel %d (BSSID="
		       MAC_FMT ")\n",
		       priv->net_dev->name, escape_essid((char*)network->ssid, network->ssid_len),
		       txratename, chan, MAC_ARG(bssid));

	/* now we copy read ssid into dev */
	if (!(priv->config & CFG_STATIC_ESSID)) {
		priv->essid_len = min((u8) network->ssid_len, (u8) IW_ESSID_MAX_SIZE);
		memcpy(priv->essid, network->ssid, priv->essid_len);
	}
	priv->channel = chan;
	memcpy(priv->bssid, &bssid, ETH_ALEN);

	priv->status |= STATUS_ASSOCIATING;
	priv->connect_start = jiffies;//get_seconds();

	//queue_delayed_work(priv->workqueue, &priv->wx_event_work, HZ / 10);
	queue_te(9,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_wx_event_work),priv,HZ/10,true);
	//ipw2100_wx_event_work(priv);
	
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

	IWI_DEBUG_FULL("addr = %d, buf = %p, num = %d\n", addr, buf, num);

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
	//fNetif->setLinkState(kIO80211NetworkLinkDown);
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
		queue_te(0,OSMemberFunctionCast(thread_call_func_t,this,&darwin_iwi2100::ipw2100_scan),priv,3000,true);
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
	//IWI_DEBUG("r: 0x%08X => %04X\n", reg, *val);
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
	//IWI_DEBUG("w: 0x%08X =< %02X\n", reg, val);
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
	//IWI_DEBUG("w: 0x%08X <= %04X\n", reg, val);
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
	//IWI_DEBUG("r: 0x%08X => 0x%08X\n", reg, *val);
}

void darwin_iwi2100::write_register(struct net_device *dev, u32 reg, u32 val)
{
	//writel(val, (void __iomem *)(memBase + reg));
	OSWriteLittleInt32(memBase,reg,val);
	//IWI_DEBUG("w: 0x%08X <= 0x%08X\n", reg, val);
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
	//IWI_DEBUG("r: 0x%08X => %02X\n", reg, *val);
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
	IWI_DEBUG_FULL("configureConnection op %d\n",opt);
	//int i=*((int*)data);
	if (opt==4)// mode
	{
		int m=*((int*)data);
		m=m-1;
		IWI_LOG("setting mode to %d\n",m);
		if (clone->priv->config & CFG_NO_LED) clone->led=0; else clone->led=1;
		clone->associate=0;
		clone->mode=m;
		clone->ipw2100_sw_reset(0);
		clone->schedule_reset(clone->priv);
	}
	if (opt==3)// led
	{
		if (clone->priv->config & CFG_NO_LED)
			clone->priv->config &= ~CFG_NO_LED;
		else
			clone->priv->config |= CFG_NO_LED;
			
		//if (clone->priv->config & CFG_NO_LED) clone->ipw_led_shutdown(clone->priv);
		//else clone->ipw_led_link_on(clone->priv);
	}
	if (opt==2) //associate network.
	{
		struct ieee80211_network *network = NULL;	
		struct ipw_network_match match = {NULL};
		struct ipw_supported_rates *rates;
		
		list_for_each_entry(network, &clone->priv->ieee->network_list, list) 
		{
			if (!memcmp(network->bssid,((struct ieee80211_network *)data)->bssid,sizeof(network->bssid)))
			{
				clone->ipw2100_best_network(clone->priv, &match, network, 0);
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
		clone->priv->config |= CFG_ASSOCIATE;
		clone->priv->config |= CFG_STATIC_ESSID;
		clone->priv->config |= CFG_STATIC_BSSID;
		bcopy(network->bssid,clone->priv->bssid,6);
		bcopy(network->ssid,clone->priv->essid,network->ssid_len);
		clone->priv->essid_len=network->ssid_len;
		clone->ipw2100_reset_adapter(clone->priv);
		
		while (!(clone->priv->status & STATUS_ASSOCIATED)) 
		{
			IOSleep(1000);
			rep++;
			if (rep==10) break;
		}
		clone->priv->config &= ~CFG_ASSOCIATE;
		clone->priv->config &= ~CFG_STATIC_BSSID;
		clone->priv->config &= ~CFG_STATIC_ESSID;
		if (rep == 10)
		{
			IWI_LOG("failed when associating to this network\n");
			clone->ipw2100_reset_adapter(clone->priv);
			return 1;
		}
	}
	if (opt==1) //HACK: start/stop the nic
	{
		//return 0;
		
		u32 reg=0;
		clone->priv->stop_rf_kill = 0;
		if (clone->priv->status & (STATUS_RF_KILL_SW | STATUS_RF_KILL_HW)) // off -> on
		{
			clone->priv->config &= ~CFG_ASSOCIATE;
			clone->priv->config &= ~CFG_STATIC_BSSID;
			clone->priv->config &= ~CFG_STATIC_ESSID;
			/*int q=0;
			if (clone->rf_kill_active(clone->priv)) 
			{	
				clone->read_register(clone->priv->net_dev, IPW_REG_GPIO, &reg);
				reg = reg &~ IPW_BIT_GPIO_RF_KILL;
				clone->write_register(clone->priv->net_dev, IPW_REG_GPIO, reg);			
			} else q=1;*/
			//clone->priv->status &= ~STATUS_RF_KILL_HW;
			clone->priv->status &= ~STATUS_RF_KILL_SW;
			clone->priv->status &= ~(STATUS_ASSOCIATED | STATUS_ASSOCIATING);
			//if (q==1) 
			clone->queue_te(3,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi2100::ipw2100_rf_kill),clone->priv,2000,true);
			IWI_LOG("radio on IPW_REG_GPIO = 0x%x\n",reg);
		}
		else
		{
			/*if (!(clone->rf_kill_active(clone->priv))) 
			{
				clone->read_register(clone->priv->net_dev, IPW_REG_GPIO, &reg);
				reg = reg | IPW_BIT_GPIO_RF_KILL;
				clone->write_register(clone->priv->net_dev, IPW_REG_GPIO, reg);
			}*/
			//clone->priv->status |= STATUS_RF_KILL_HW;
			clone->priv->status |= STATUS_RF_KILL_SW;
			clone->priv->status &= ~(STATUS_ASSOCIATED | STATUS_ASSOCIATING);
			clone->setLinkStatus(kIONetworkLinkValid);
			IOSleep(5000);
			//if ((clone->fNetif->getFlags() & IFF_RUNNING)) clone->ipw_link_down(clone->priv); else clone->ipw_led_link_off(clone->priv);
			//clone->schedule_reset(clone->priv);
			clone->queue_te(3,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi2100::ipw2100_rf_kill),clone->priv,2000,true);
			IWI_LOG("radio off IPW_REG_GPIO = 0x%x\n",reg);
		}	
	}

	return(0);
}

int sendNetworkList(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,int opt, void *data, size_t *len)
{
	IWI_DEBUG_FULL("sendNetworkList op %d\n",opt);
	if (opt==0) memcpy(data,clone->priv,*len);
	if (opt==1) memcpy(data,clone->priv->ieee,*len);
	if (opt==2)
	{
		struct ieee80211_network *n=NULL,*n2=(struct ieee80211_network*)data;
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
		IWI_DEBUG_FULL("found %d networks\n",i);
	}
	//if (opt==3) memcpy(data,clone->priv->assoc_network,*len);
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
	if (opt==5) memcpy(data,clone->priv->ieee->dev,*len);
	return (0);
}

int setSelectedNetwork(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,mbuf_t m, int flags)
{
return 0;
}
