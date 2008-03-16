/******************************************************************************
 *
 * Copyright(c) 2003 - 2007 Intel Corporation. All rights reserved.
 *
 * Portions of this file are derived from the ipw3945 project, as well
 * as portions of the ieee80211 subsystem header files.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110, USA
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *
 * Contact Information:
 * James P. Ketrenos <ipw2100-admin@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 *****************************************************************************/

/*
 * NOTE:  This file (base.c) is used to build to multiple hardware targets
 * by defining IWL to either 3945 or 4965.  The Makefile used when building
 * the base targets will create base-3945.o and base-4965.o
 *
 * The eventual goal is to move as many of the #if IWL / #endif blocks out of
 * this file and into the hardware specific implementation files (iwl-XXXX.c)
 * and leave only the common (non #ifdef sprinkled) code in this file
 */

/*#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/wireless.h>
#include <linux/firmware.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>

#include <net/ieee80211_radiotap.h>
#include <net/mac80211.h>

#include <asm/div64.h>*/

//iwlwifi-3945-ucode-2.14.4
#include "firmware/ipw3945.ucode.h"
#include "defines.h"
#include "iwlwifi.h"
#include "iwl-helpers.h"
#include "iwi3945.h"

/******************************************************************************
 *
 * module boiler plate
 *
 ******************************************************************************/
darwin_iwi3945 *clone;

#ifdef CONFIG_IWLWIFI_DEBUG
	u32 iwl_debug_level;
#endif


	/* module parameters */
	int param_disable_hw_scan;
	int param_debug;
	int param_disable;      /* def: enable radio */
	int param_antenna;      /* def: 0 = both antennas (use diversity) */
	int param_hwcrypto;     /* def: using software encryption */
	int param_qos_enable;

/*
 * module name, copyright, version, etc.
 * NOTE: DRV_NAME is defined in iwlwifi.h for use by iwl-debug.h and printf
 */

#if IWL == 3945
#define DRV_DESCRIPTION	\
"Intel(R) PRO/Wireless 3945ABG/BG Network Connection driver for Mac OS X"
#elif IWL == 4965
#define DRV_DESCRIPTION	\
"Intel(R) Wireless WiFi Link 4965AGN driver for Mac OS X"
#endif

#ifdef CONFIG_IWLWIFI_DEBUG
#define VD "d"
#else
#define VD
#endif

#ifdef CONFIG_IWLWIFI_SPECTRUM_MEASUREMENY
#define VS "s"
#else
#define VS
#endif

#define IWLWIFI_VERSION "1.0.0-1" VD VS
#define DRV_COPYRIGHT	"Copyright(c) 2003-2007 Intel Corporation"
#define DRV_VERSION     IWLWIFI_VERSION

/*************** DMA-QUEUE-GENERAL-FUNCTIONS  *****
 * DMA services
 *
 * Theory of operation
 *
 * A queue is a circular buffers with 'Read' and 'Write' pointers.
 * 2 empty entries always kept in the buffer to protect from overflow.
 *
 * For Tx queue, there are low mark and high mark limits. If, after queuing
 * the packet for Tx, free space become < low mark, Tx queue stopped. When
 * reclaiming packets (on 'tx done IRQ), if free space become > high mark,
 * Tx queue resumed.
 *
 * The IPW operates with six queues, one receive queue in the device's
 * sram, one transmit queue for sending commands to the device firmware,
 * and four transmit queues for data.
 *
 * The four transmit queues allow for performing quality of service (qos)
 * transmissions as per the 802.11 protocol.  Currently Linux does not
 * provide a mechanism to the user for utilizing prioritized queues, so
 * we only utilize the first data transmit queue (queue1).
 ***************************************************/

static int iwl_queue_space(const struct iwl_queue *q)
{
	int s = q->last_used - q->first_empty;
	if (q->last_used > q->first_empty)
		s -= q->n_bd;

	if (s <= 0)
		s += q->n_window;
	/* keep some reserve to not confuse empty and full situations */
	s -= 2;
	if (s < 0)
		s = 0;
	return s;
}

static inline int iwl_queue_inc_wrap(int index, int n_bd)
{
	return (++index == n_bd) ? 0 : index;
}

static inline int iwl_queue_dec_wrap(int index, int n_bd)
{
	return (index == 0) ? n_bd - 1 : index - 1;
}

static inline int x2_queue_used(const struct iwl_queue *q, int i)
{
	return q->first_empty > q->last_used ?
	    (i >= q->last_used && i < q->first_empty) :
	    !(i < q->last_used && i >= q->first_empty);
}

static inline u8 get_next_cmd_index(struct iwl_queue *q, u32 index, int is_huge)
{
	if (is_huge)
		return q->n_window;

	return index & (q->n_window -1);
}

static int iwl_queue_init(struct iwl_priv *priv, struct iwl_queue *q,
			  int count, int size, u32 id)
{
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

	return 0;
}

static int iwl_tx_queue_alloc(struct iwl_priv *priv,
			      struct iwl_tx_queue *txq, int count, u32 id)
{
	//struct pci_dev *dev = priv->pci_dev;

	if (id != IWL_CMD_QUEUE_NUM) {
		txq->txb = (struct iwl_tx_info*)IOMalloc(sizeof(txq->txb[0]) *
				   TFD_QUEUE_SIZE_MAX);
		memset(txq->txb,0,sizeof(txq->txb[0]) *  TFD_QUEUE_SIZE_MAX);
		if (!txq->txb) {
			IWL_ERROR("kmalloc for auxilary BD "
				  "structures failed\n");
			goto error;
		}
	} else
		txq->txb = NULL;

	//txq->bd = pci_alloc_consistent(dev,
	//		sizeof(struct iwl_tfd_frame) * TFD_QUEUE_SIZE_MAX,
	//		&txq->q.dma_addr);
	MemoryDmaAlloc(sizeof(struct iwl_tfd_frame) * TFD_QUEUE_SIZE_MAX, &txq->q.dma_addr, &txq->bd);
	//txq->bd=(struct iwl_tfd_frame*)IOMallocContiguous(sizeof(struct iwl_tfd_frame) * TFD_QUEUE_SIZE_MAX, sizeof(struct iwl_tfd_frame*), &txq->q.dma_addr);
	txq->q.element_size = sizeof(struct iwl_tfd_frame);
	if (!txq->bd) {
		IWL_ERROR("pci_alloc_consistent(%zd) failed\n",
			  sizeof(txq->bd[0]) * count);
		goto error;
	}
	txq->q.id = id;

	return 0;

 error:
	if (txq->txb) {
		IOFree(txq->txb,sizeof(txq->txb[0]) *
				   TFD_QUEUE_SIZE_MAX);
		txq->txb = NULL;
	}

	return -ENOMEM;
}

int iwl_tx_queue_init(struct iwl_priv *priv,
		      struct iwl_tx_queue *txq, int count, u32 txq_id)
{
	//struct pci_dev *dev = priv->pci_dev;
	int len;
	int rc = 0;

	/* alocate command space + one big command for scan since scan
	 * command is very huge the system will not have two scan at the
	 * same time */
	len = sizeof(struct iwl_cmd) * count;
	if (txq_id == IWL_CMD_QUEUE_NUM) len +=  IWL_MAX_SCAN_SIZE;
	//txq->cmd = pci_alloc_consistent(dev, len, &txq->dma_addr_cmd);
	MemoryDmaAlloc(len, &txq->dma_addr_cmd, &txq->cmd);
	//txq->cmd=(struct iwl_cmd*)IOMallocContiguous(len, sizeof(struct iwl_cmd*), &txq->dma_addr_cmd);
	if (!txq->cmd)
		return -ENOMEM;

	rc = iwl_tx_queue_alloc(priv, txq, count, txq_id);
	if (rc) {
		pci_free_consistent(dev, len, txq->cmd, txq->dma_addr_cmd);
		IOFreeContiguous(txq->cmd,len);
		txq->dma_addr_cmd=NULL;
		//txq->cmd=NULL;
		return -ENOMEM;
	}

	txq->need_update = 0;
	iwl_queue_init(priv, &txq->q, TFD_QUEUE_SIZE_MAX, count, txq_id);
	iwl_hw_tx_queue_init(priv, txq);

	return 0;
}

/**
 * iwl_tx_queue_free - Deallocate DMA queue.
 * @txq: Transmit queue to deallocate.
 *
 * Empty queue by removing and destroying all BD's.
 * Free all buffers.  txq itself is not freed.
 *
 */
void iwl_tx_queue_free(struct iwl_priv *priv, struct iwl_tx_queue *txq)
{
	struct iwl_queue *q = &txq->q;
	//struct pci_dev *dev = priv->pci_dev;
	int len;

	if (q->n_bd == 0)
		return;

	/* first, empty all BD's */
	for (; q->first_empty != q->last_used;
	     q->last_used = iwl_queue_inc_wrap(q->last_used, q->n_bd)) {
		iwl_hw_tx_queue_free_tfd(priv, txq);
	}

	len = sizeof(txq->cmd[0]) * q->n_window;
	if (q->id == IWL_CMD_QUEUE_NUM) len +=  IWL_MAX_SCAN_SIZE;
	pci_free_consistent(dev, len, txq->cmd, txq->dma_addr_cmd);
	IOFreeContiguous(txq->cmd,len);
	txq->dma_addr_cmd=NULL;
	//txq->cmd=NULL;

	/* free buffers belonging to queue itself */
	if (txq->q.n_bd)
	{
		pci_free_consistent(dev, sizeof(struct iwl_tfd_frame) *
				    txq->q.n_bd, txq->bd, txq->q.dma_addr);
		IOFreeContiguous(txq->bd, sizeof(struct iwl_tfd_frame) * txq->q.n_bd);
		txq->q.dma_addr=NULL;
		//txq->bd=NULL;
	}
	if (txq->txb) {
		IOFree(txq->txb,sizeof(txq->txb[0]) *
				   TFD_QUEUE_SIZE_MAX);
		txq->txb = NULL;
	}

	/* 0 fill whole structure */
	memset(txq, 0, sizeof(*txq));
}

const u8 BROADCAST_ADDR[ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/*************** STATION TABLE MANAGEMENT ****
 *
 * NOTE:  This needs to be overhauled to better synchronize between
 * how the iwl-4965.c is using iwl_hw_find_station vs. iwl-3945.c
 *
 * mac80211 should also be examined to determine if sta_info is duplicating
 * the functionality provided here
 */

/**************************************************************/

static u8 iwl_remove_station(struct iwl_priv *priv, const u8 * bssid, int is_ap)
{
	int index = IWL_INVALID_STATION;
	int i;
	unsigned long flags;

	spin_lock_irqsave(&priv->sta_lock, flags);
	if (is_ap) {
		index = IWL_AP_ID;
		if ((priv->stations[index].used))
			priv->stations[index].used = 0;
	} else if (is_broadcast_ether_addr(bssid)) {
		index = IWL_BROADCAST_ID;
		if ((priv->stations[index].used))
			priv->stations[index].used = 0;
	} else
		for (i = IWL_STA_ID; i < priv->num_stations + IWL_STA_ID; i++) {
			if (priv->stations[i].used &&
			    !compare_ether_addr(
				    priv->stations[i].sta.sta.addr, bssid)) {
				index = i;
				priv->stations[index].used = 0;
				break;
			}
		}

	if (index != IWL_INVALID_STATION) {
		if (priv->num_stations > 0)
			priv->num_stations--;
	}

	spin_unlock_irqrestore(&priv->sta_lock, flags);
	return 0;
}

static void iwl_clear_stations_table(struct iwl_priv *priv)
{
	unsigned long flags;

	spin_lock_irqsave(&priv->sta_lock, flags);

	priv->num_stations = 0;
	memset(priv->stations, 0,
	       IWL_STATION_COUNT * sizeof(struct iwl_station_entry));
	spin_unlock_irqrestore(&priv->sta_lock, flags);
}

u8 iwl_add_station(struct iwl_priv *priv, const u8 * bssid, int is_ap, u8 flags)
{
	int i = IWL_STATION_COUNT;
	int index = IWL_INVALID_STATION;
	struct iwl_station_entry *station;
	unsigned long flags_spin;

	spin_lock_irqsave(&priv->sta_lock, flags_spin);
	if (is_ap) {
		index = IWL_AP_ID;
		if (priv->stations[index].used &&
		    !compare_ether_addr(priv->stations[index].sta.sta.addr,
					bssid))
			goto done;
	} else if (is_broadcast_ether_addr(bssid)) {
		index = IWL_BROADCAST_ID;
		if (priv->stations[index].used &&
		    !compare_ether_addr(priv->stations[index].sta.sta.addr,
					bssid))
			goto done;
	} else
		for (i = IWL_STA_ID; i < priv->num_stations + IWL_STA_ID; i++) {
			if (priv->stations[i].used &&
			    !compare_ether_addr(priv->stations[i].sta.sta.addr,
						bssid))
				goto done;

			if (!priv->stations[i].used &&
			    index == IWL_INVALID_STATION)
				index = i;
		}

	if (index != IWL_INVALID_STATION)
		i = index;

	if (i == IWL_STATION_COUNT) {
		index = IWL_INVALID_STATION;
		goto done;
	}

	IWL_DEBUG_ASSOC("Adding STA ID %d: " MAC_FMT "\n", i, MAC_ARG(bssid));
	station = &priv->stations[i];

	station->used = 1;
	station->current_rate.s.rate = IWL_RATE_1M_PLCP;
	memset(&station->sta, 0, sizeof(struct iwl_addsta_cmd));
	memcpy(station->sta.sta.addr, bssid, ETH_ALEN);
	station->sta.mode = 0;
	station->sta.sta.sta_id = i;
	station->sta.station_flags = 0;

	/* todoG do we need this
	 * all TID's disabled
	 *  priv->stations[i].sta.tid_disable_tx = 0xffff;
	 */
	if ((priv->phymode == MODE_IEEE80211A) ||
	    (priv->phymode == MODE_ATHEROS_TURBO))
		station->sta.tx_rate.rate_n_flags = IWL_RATE_6M_PLCP;
	else
		station->sta.tx_rate.rate_n_flags = IWL_RATE_1M_PLCP |
						    priv->hw_setting.cck_flag;

	/* Turn on both antennas for the station... */
	station->sta.tx_rate.rate_n_flags |= RATE_MCS_ANT_AB_MSK;

	/*
	 * priv->stations[i].sta.tx_rate.rate_n_flags |= RATE_MCS_ANT_B_MSK;
	 * priv->stations[i].sta.tx_rate.rate_n_flags &= ~RATE_MCS_ANT_A_MSK;
	 */

	station->sta.station_flags |= STA_MODIFY_TX_RATE_MSK;
#if IWL == 4965
#ifdef CONFIG_IWLWIFI_HT
	if (is_ap) {
		iwl4965_set_ht_add_station(priv, i, 0);
		iwl4965_set_rxon_chain(priv);
	}
#endif /*CONFIG_IWLWIFI_HT*/
#endif
	station->current_rate.rate_n_flags = station->sta.tx_rate.rate_n_flags;

	priv->num_stations++;
	spin_unlock_irqrestore(&priv->sta_lock, flags_spin);
	iwl_send_add_station(priv, &station->sta, flags);
	return i;

 done:
	spin_unlock_irqrestore(&priv->sta_lock, flags_spin);
	return index;
}

/* iwl_hw_find_station is implemented in iwl-3945 and iwl-4965 for now... */

u8 iwl_sync_station(struct iwl_priv * priv, int sta_id, u16 tx_rate, u8 flags)
{
	unsigned long flags_spin;
	struct iwl_station_entry *station;

	if (sta_id == IWL_INVALID_STATION)
		return IWL_INVALID_STATION;

	spin_lock_irqsave(&priv->sta_lock, flags_spin);
	station = &priv->stations[sta_id];

	station->sta.sta.modify_mask = STA_CONTROL_MODIFY_MSK;
	station->sta.tx_rate.rate_n_flags = tx_rate;
	station->current_rate.rate_n_flags = tx_rate;
	station->sta.mode = STA_CONTROL_MODIFY_MSK;

	spin_unlock_irqrestore(&priv->sta_lock, flags_spin);

	iwl_send_add_station(priv, &station->sta, flags);
	IWL_DEBUG_RATE("SCALE sync station %d to rate %d\n",
			sta_id, tx_rate);
	return sta_id;
}

/*************** DRIVER STATUS FUNCTIONS   *****/

static inline int iwl_is_ready(struct iwl_priv *priv)
{
	/* The adapter is 'ready' if READY and GEO_CONFIGURED bits are
	 * set but EXIT_PENDING is not */
	return ((priv->status & (STATUS_READY |
				 STATUS_GEO_CONFIGURED |
				 STATUS_EXIT_PENDING)) ==
		(STATUS_READY | STATUS_GEO_CONFIGURED)) ? 1 : 0;
}

static inline int iwl_is_alive(struct iwl_priv *priv)
{
	return (priv->status & STATUS_ALIVE) ? 1 : 0;
}

static inline int iwl_is_init(struct iwl_priv *priv)
{
	return (priv->status & STATUS_INIT) ? 1 : 0;
}

static inline int iwl_is_ready_rf(struct iwl_priv *priv)
{

	if (priv->status & STATUS_RF_KILL_MASK)
		return 0;

	return iwl_is_ready(priv);
}

/*************** HOST COMMAND QUEUE FUNCTIONS   *****/

#define IWL_CMD(x) case x : return #x

const char *get_cmd_string(u8 cmd)
{
	switch (cmd) {
		IWL_CMD(SCAN_START_NOTIFICATION);
		IWL_CMD(SCAN_RESULTS_NOTIFICATION);
		IWL_CMD(SCAN_COMPLETE_NOTIFICATION);
		IWL_CMD(STATISTICS_NOTIFICATION);
		IWL_CMD(REPLY_ALIVE);
		IWL_CMD(REPLY_ERROR);
		IWL_CMD(REPLY_RXON_ASSOC);
		IWL_CMD(REPLY_RXON);
		IWL_CMD(REPLY_QOS_PARAM);
		IWL_CMD(REPLY_RXON_TIMING);
		IWL_CMD(REPLY_ADD_STA);
		IWL_CMD(REPLY_TX);
		IWL_CMD(REPLY_BCON);
		IWL_CMD(REPLY_RATE_SCALE);
		IWL_CMD(REPLY_LEDS_CMD);
		IWL_CMD(REPLY_SCAN_ABORT_CMD);
		IWL_CMD(REPLY_TX_BEACON);
		IWL_CMD(REPLY_BT_CONFIG);
		IWL_CMD(REPLY_SCAN_CMD);
		IWL_CMD(REPLY_TX_PWR_TABLE_CMD);
		IWL_CMD(REPLY_STATISTICS_CMD);
		IWL_CMD(REPLY_CARD_STATE_CMD);
		IWL_CMD(REPLY_TX_LINK_QUALITY_CMD);
#if IWL == 3945
		IWL_CMD(REPLY_3945_RX);
#elif IWL == 4965
		IWL_CMD(MISSED_BEACONS_NOTIFICATION_TH_CMD);
		IWL_CMD(REPLY_CT_KILL_CONFIG_CMD);
		IWL_CMD(SENSITIVITY_CMD);
		IWL_CMD(REPLY_RX_MPDU_CMD);
		IWL_CMD(REPLY_RX_PHY_CMD);
		IWL_CMD(REPLY_4965_RX);
#endif
	case POWER_TABLE_CMD:
		return "POWER_TABLE_CMD";
	default:
		return "UNKNOWN";

	}
}

#define HOST_COMPLETE_TIMEOUT (HZ / 2)

int is_cmd_sync(struct iwl_host_cmd *cmd)
{
	return !(cmd->meta.flags & CMD_ASYNC);
}

static inline int is_cmd_small(struct iwl_host_cmd *cmd)
{
	return !(cmd->meta.flags & CMD_SIZE_HUGE);
}

int cmd_needs_lock(struct iwl_host_cmd *cmd)
{
	return !(cmd->meta.flags & CMD_NO_LOCK);
}

int iwl_enqueue_hcmd(struct iwl_priv *priv, struct iwl_host_cmd *cmd)
{
	struct iwl_tx_queue *txq = &priv->txq[IWL_CMD_QUEUE_NUM];
	struct iwl_queue *q = &txq->q;
	struct iwl_tfd_frame* tfd;
	u32 *control_flags;
	struct iwl_cmd *out_cmd;
	u32 idx = 0;
	u16 fix_size = (u16) (cmd->meta.len + sizeof(out_cmd->hdr));
	dma_addr_t phys_addr;
#if IWL == 3945
	int pad;
	u16 count;
#elif IWL == 4965
	int rc;
#endif

	/* If any of the command structures end up being larger than
	 * the TFD_MAX_PAYLOAD_SIZE, and it sent as a 'small' command then
	 * we will need to increase the size of the TFD entries */
	if((fix_size > TFD_MAX_PAYLOAD_SIZE) && is_cmd_small(cmd)) 
	{
		IWL_ERROR("fix_size > TFD_MAX_PAYLOAD_SIZE\n");
		return -1;
	}
	if (iwl_queue_space(q) < (is_cmd_sync(cmd) ? 1 : 2)) {
		IWL_ERROR("No space for Tx\n");
		return -ENOSPC;
	}
	tfd = &txq->bd[q->first_empty * q->element_size];
	memset(tfd, 0, sizeof(*tfd));

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
	out_cmd->hdr.sequence = QUEUE_TO_SEQ(IWL_CMD_QUEUE_NUM) |
	    INDEX_TO_SEQ(q->first_empty);
	if (out_cmd->meta.flags & CMD_SIZE_HUGE)
		out_cmd->hdr.sequence |= SEQ_HUGE_FRAME;

	phys_addr = txq->dma_addr_cmd + sizeof(txq->cmd[0]) * idx + offsetof(struct iwl_cmd, hdr);

	//phys_addr =IOMemoryDescriptor::withAddress((u8*)txq->cmd+ sizeof(txq->cmd[0]) * idx 
	//+ offsetof(struct iwl_cmd, hdr), fix_size, kIODirectionNone)->getPhysicalAddress();
	
	iwl_hw_tx_queue_attach_buffer_to_tfd(priv, tfd, phys_addr, fix_size);

#if IWL == 3945
	pad = U32_PAD(out_cmd->meta.len);
	count = TFD_CTL_COUNT_GET(*control_flags);
	*control_flags = TFD_CTL_COUNT_SET(count) | TFD_CTL_PAD_SET(pad);
#endif

	IWL_DEBUG_HC("Sending command %s (#%x), seq: 0x%04X, "
		     "%d bytes at %d[%d]:%d\n",
		     get_cmd_string(out_cmd->hdr.cmd),
		     out_cmd->hdr.cmd, out_cmd->hdr.sequence,
		     fix_size, q->first_empty, idx, IWL_CMD_QUEUE_NUM);

	txq->need_update = 1;
//#if IWL == 4965
//	rc = iwl4965_tx_queue_update_wr_ptr(priv, txq, 0);
//	q->first_empty = iwl_queue_inc_wrap(q->first_empty, q->n_bd);
//	iwl_tx_queue_update_write_ptr(priv, txq);
//	return rc;
//#elif IWL == 3945
	q->first_empty = iwl_queue_inc_wrap(q->first_empty, q->n_bd);

	return iwl_tx_queue_update_write_ptr(priv, txq);
//#endif
}

int iwl_send_cmd(struct iwl_priv *priv, struct iwl_host_cmd *cmd)
{
	int rc;
	unsigned long flags = 0;

	/* If this is an asynchronous command, and we are in a shutdown
	 * process then don't let it start */
	if (!is_cmd_sync(cmd) && (priv->status & STATUS_EXIT_PENDING))
		return -EBUSY;

	/*
	 * The following checks are meant to catch programming API misuse
	 * and not run-time failures due to timing, resource constraint, etc.
	 */

	/* A command can not be asynchronous AND expect an SKB to be set */
	if ((cmd->meta.flags & CMD_ASYNC) && (cmd->meta.flags & CMD_WANT_SKB)) {
		IWL_ERROR("ASYNC && WANT_SKB\n");
		return -EINVAL;
	}

	/* The skb/callback union must be NULL if an SKB is requested */
	if (cmd->meta.u.skb && (cmd->meta.flags & CMD_WANT_SKB)) {
		IWL_ERROR("skb != null && WANT_SKB\n");
		return -EINVAL;
	}

	/* A command can not be synchronous AND have a callback set */
	if (is_cmd_sync(cmd) && cmd->meta.u.callback) {
		IWL_ERROR("callback != null && SYNC\n");
		return -EINVAL;
	}

	/* An asynchronous command MUST have a callback */
	if ((cmd->meta.flags & CMD_ASYNC) && !cmd->meta.u.callback) {
		IWL_ERROR("callback == null && ASYNC\n");
		return -EINVAL;
	}

	/* A command can not be synchronous AND not use locks */
	if (is_cmd_sync(cmd) && (cmd->meta.flags & CMD_NO_LOCK)) {
		IWL_ERROR("SYNC && NO_LOCK\n");
		return -EINVAL;
	}

	if (cmd_needs_lock(cmd))
		spin_lock_irqsave(&priv->lock, flags);

	if (is_cmd_sync(cmd) && (priv->status & STATUS_HCMD_ACTIVE)) {
		IWL_ERROR("Error sending %s: "
			  "Already sending a host command\n",
			  get_cmd_string(cmd->id));
		if (cmd_needs_lock(cmd))
			spin_unlock_irqrestore(&priv->lock, flags);
		return -EBUSY;
	}

	if (is_cmd_sync(cmd))
		priv->status |= STATUS_HCMD_ACTIVE;

	/* When the SKB is provided in the tasklet, it needs
	 * a backpointer to the originating caller so it can
	 * actually copy the skb there */
	if (cmd->meta.flags & CMD_WANT_SKB) {
		cmd->meta.source = &cmd->meta;
		cmd->meta.magic = CMD_VAR_MAGIC;
	}

	cmd->meta.len = cmd->len;

	// CRAPPY =p rc =iwl_enqueue_hcmd(priv, cmd);
	rc = iwl_enqueue_hcmd(priv, cmd);
	if (rc) {
		if (is_cmd_sync(cmd))
			priv->status &= ~STATUS_HCMD_ACTIVE;
		if (cmd_needs_lock(cmd))
			spin_unlock_irqrestore(&priv->lock, flags);

		IWL_ERROR("Error sending %s: "
			  "iwl_queue_tx_hcmd failed: %d\n",
			  get_cmd_string(cmd->id), rc);

		return -ENOSPC;
	}
	if (cmd_needs_lock(cmd))
		spin_unlock_irqrestore(&priv->lock, flags);

	if (is_cmd_sync(cmd)) 
	{
		rc = 0;/*wait_event_interruptible_timeout(priv->wait_command_queue,
						      !(priv->status &
							STATUS_HCMD_ACTIVE),
						      HOST_COMPLETE_TIMEOUT);*/
		while (priv->status & STATUS_HCMD_ACTIVE) 
		{
			rc++;
			IODelay(HOST_COMPLETE_TIMEOUT);
			if (rc==HOST_COMPLETE_TIMEOUT) break;
		}
		if (rc==HOST_COMPLETE_TIMEOUT) priv->status &= ~STATUS_HCMD_ACTIVE;//hack
		
		if (cmd_needs_lock(cmd))
			spin_lock_irqsave(&priv->lock, flags);

		if (priv->status & STATUS_HCMD_ACTIVE) 
		{
			IWL_ERROR("Error sending %s: "
				  "time out after %dms. \n",
				  get_cmd_string(cmd->id),
				  jiffies_to_msecs
				  (HOST_COMPLETE_TIMEOUT));
			priv->status &= ~STATUS_HCMD_ACTIVE;
			if ((cmd->meta.flags & CMD_WANT_SKB)
				&& cmd->meta.u.skb) 
			{
				if (!(mbuf_type(cmd->meta.u.skb) == MBUF_TYPE_FREE)) 
				mbuf_freem(cmd->meta.u.skb);
				cmd->meta.u.skb = NULL;
			}

			if (cmd_needs_lock(cmd))
				spin_unlock_irqrestore(
					&priv->lock, flags);
			cmd->meta.magic = 0;
			return -ETIMEDOUT;
		}
		if (cmd_needs_lock(cmd))
			spin_unlock_irqrestore(&priv->lock, flags);
	}

	if (priv->status & STATUS_RF_KILL_HW) {
		if ((cmd->meta.flags & CMD_WANT_SKB)
		    && cmd->meta.u.skb) {
			if (!(mbuf_type(cmd->meta.u.skb) == MBUF_TYPE_FREE)) 
			mbuf_freem(cmd->meta.u.skb);
			cmd->meta.u.skb = NULL;
		}

		IWL_DEBUG_INFO("Command %s aborted: RF KILL Switch\n",
			       get_cmd_string(cmd->id));

		return -ECANCELED;
	}

	if (priv->status & STATUS_FW_ERROR) {
		if ((cmd->meta.flags & CMD_WANT_SKB)
		    && cmd->meta.u.skb) {
			if (!(mbuf_type(cmd->meta.u.skb) == MBUF_TYPE_FREE)) 
			mbuf_freem(cmd->meta.u.skb);
			cmd->meta.u.skb = NULL;
		}

		IWL_DEBUG_INFO("Command %s failed: FW Error\n",
			       get_cmd_string(cmd->id));

		return -EIO;
	}

	if ((cmd->meta.flags & CMD_WANT_SKB) && !cmd->meta.u.skb) {
		IWL_ERROR("Error: Response NULL in '%s'\n",
			  get_cmd_string(cmd->id));
		return -EIO;
	}

	return 0;
}

int iwl_send_cmd_pdu(struct iwl_priv *priv, u8 id, u16 len, const void *data)
{
	struct iwl_host_cmd cmd;
	memset(&cmd,0,sizeof(struct iwl_host_cmd));
		cmd.id = id;
		cmd.len = len;
		cmd.data = data;

	return iwl_send_cmd(priv,  &cmd);
}

static int iwl_send_cmd_u32(struct iwl_priv *priv, u8 id, u32 val)
{
	struct iwl_host_cmd cmd;// = {
	memset(&cmd,0,sizeof(struct iwl_host_cmd));
		cmd.id = id;
		cmd.len = sizeof(val);
		cmd.data = &val;

	return iwl_send_cmd(priv,  &cmd);
}

int iwl_send_statistics_request(struct iwl_priv *priv)
{
	return iwl_send_cmd_u32(priv, REPLY_STATISTICS_CMD, 0);
}

/**
 * iwl_rxon_add_station - add station into station table.
 *
 * there is only one AP station with id= IWL_AP_ID
 * NOTE: mutex must be held before calling the this fnction
*/
static int iwl_rxon_add_station(struct iwl_priv *priv,
				const u8 * addr, int is_ap)
{
	u8 i;

	/* Remove this station if it happens to already exist */
	iwl_remove_station(priv, addr, is_ap);

	i = iwl_add_station(priv, addr, is_ap, 0);

	iwl4965_add_station(priv, addr, is_ap);

	return i;
}

/**
 * iwl_set_rxon_channel - Set the phymode and channel values in staging RXON
 * @phymode: MODE_IEEE80211A sets to 5.2GHz; all else set to 2.4GHz
 * @channel: Any channel valid for the requested phymode

 * In addition to setting the staging RXON, priv->phymode is also set.
 *
 * NOTE:  Does not commit to the hardware; it sets appropriate bit fields
 * in the staging RXON flag structure based on the phymode
 */
static int iwl_set_rxon_channel(struct iwl_priv *priv, u8 phymode, u8 channel)
{
	if (!iwl_get_channel_info(priv, phymode, channel)) {
		IWL_DEBUG_INFO("Could not set channel to %d [%d]\n",
			       channel, phymode);
		return -EINVAL;
	}

	if ((priv->staging_rxon.channel == channel) &&
	    (priv->phymode == phymode))
		return 0;

	priv->staging_rxon.channel = channel;
	if ((phymode == MODE_IEEE80211A) ||
	    (phymode == MODE_ATHEROS_TURBO))
		priv->staging_rxon.flags &= ~RXON_FLG_BAND_24G_MSK;
	else
		priv->staging_rxon.flags |= RXON_FLG_BAND_24G_MSK;

	priv->phymode = phymode;

	IWL_DEBUG_INFO("Staging channel set to %d [%d]\n", channel, phymode);

	return 0;
}

/**
 * iwl_check_rxon_cmd - validate RXON structure is valid
 *
 * NOTE:  This is really only useful during development and can eventually
 * be #ifdef'd out once the driver is stable and folks aren't actively
 * making changes
 */
static int iwl_check_rxon_cmd(struct iwl_rxon_cmd *rxon)
{
	int error = 0;
	int counter = 1;

	if (rxon->flags & RXON_FLG_BAND_24G_MSK) {
		error |= (rxon->flags & RXON_FLG_TGJ_NARROW_BAND_MSK);
		error |= (rxon->flags & RXON_FLG_RADAR_DETECT_MSK);
		if (error)
			IWL_WARNING("check 24G fields %d | %d\n",
				    counter++, error);
	} else {
		error |= ((rxon->flags & RXON_FLG_SHORT_SLOT_MSK) !=
			  RXON_FLG_SHORT_SLOT_MSK);
		if (error)
			IWL_WARNING("check 52 fields %d | %d\n",
				    counter++, error);
		error |= (rxon->flags & RXON_FLG_CCK_MSK);
		if (error)
			IWL_WARNING("check 52 CCK %d | %d\n",
				    counter++, error);

	}
	error |= (rxon->node_addr[0] | rxon->bssid_addr[0]) & 0x1;
	if (error)
		IWL_WARNING("check mac addr %d | %d\n", counter++, error);

	/* make sure basic rates 6Mbps and 1Mbps are supported */
	error |= (((rxon->ofdm_basic_rates & IWL_RATE_6M_MASK) == 0) &&
		  ((rxon->cck_basic_rates & IWL_RATE_1M_MASK) == 0));
	if (error)
		IWL_WARNING("check basic rate %d | %d\n", counter++, error);

	error |= (rxon->assoc_id > 2007);
	if (error)
		IWL_WARNING("check assoc id %d | %d\n", counter++, error);

	error |= ((rxon->flags &
		   (RXON_FLG_CCK_MSK | RXON_FLG_SHORT_SLOT_MSK)) ==
		  (RXON_FLG_CCK_MSK | RXON_FLG_SHORT_SLOT_MSK));
	if (error)
		IWL_WARNING("check CCK and short slot %d | %d\n",
			    counter++, error);

	error |= ((rxon->flags & (RXON_FLG_CCK_MSK | RXON_FLG_AUTO_DETECT_MSK))
		  == (RXON_FLG_CCK_MSK | RXON_FLG_AUTO_DETECT_MSK));
	if (error)
		IWL_WARNING("check CCK & auto detect %d | %d\n",
			    counter++, error);

	error |= ((rxon->flags &
		   (RXON_FLG_AUTO_DETECT_MSK | RXON_FLG_TGG_PROTECT_MSK)) ==
		  RXON_FLG_TGG_PROTECT_MSK);
	if (error)
		IWL_WARNING("check TGG %d | %d\n", counter++, error);

#if IWL == 3945
	if ((rxon->flags & RXON_FLG_DIS_DIV_MSK))
		error |= ((rxon->flags &
			   (RXON_FLG_ANT_B_MSK | RXON_FLG_ANT_A_MSK)) == 0);
	if (error)
		IWL_WARNING("check antenna %d %d\n", counter++, error);
#endif

	if (error)
		IWL_WARNING("Tuning to channel %d\n",
			    le16_to_cpu(rxon->channel));

	if (error) {
		IWL_ERROR
		    ("Error not a valid iwl_rxon_assoc_cmd field values\n");
		return -1;
	}

	return 0;
}

/**
 * iwl_full_rxon_required - determine if RXON_ASSOC can be used in RXON commit
 * @priv: staging_rxon is comapred to active_rxon
 *
 * If the RXON structure is changing sufficient to require a new
 * tune or to clear and reset the RXON_FILTER_ASSOC_MSK then return 1
 * to indicate a new tune is required.
 */
static int iwl_full_rxon_required(struct iwl_priv *priv)
{

	/* These items are only settable from the full RXON command */
	if (!(priv->active_rxon.filter_flags & RXON_FILTER_ASSOC_MSK) ||
	    compare_ether_addr(priv->staging_rxon.bssid_addr,
			       priv->active_rxon.bssid_addr) ||
	    compare_ether_addr(priv->staging_rxon.node_addr,
			       priv->active_rxon.node_addr) ||
	    compare_ether_addr(priv->staging_rxon.wlap_bssid_addr,
			       priv->active_rxon.wlap_bssid_addr) ||
	    (priv->staging_rxon.dev_type != priv->active_rxon.dev_type) ||
	    (priv->staging_rxon.channel != priv->active_rxon.channel) ||
	    (priv->staging_rxon.air_propagation !=
	     priv->active_rxon.air_propagation) ||
#if IWL == 4965
	    (priv->staging_rxon.ofdm_ht_single_stream_basic_rates !=
	     priv->active_rxon.ofdm_ht_single_stream_basic_rates) ||
	    (priv->staging_rxon.ofdm_ht_dual_stream_basic_rates !=
	     priv->active_rxon.ofdm_ht_dual_stream_basic_rates) ||
	    (priv->staging_rxon.rx_chain != priv->active_rxon.rx_chain) ||
#endif
	    (priv->staging_rxon.assoc_id != priv->active_rxon.assoc_id))
		return 1;

	/* flags, filter_flags, ofdm_basic_rates, and cck_basic_rates can
	 * be updated with the RXON_ASSOC command -- however only some
	 * flag transitions are allowed using RXON_ASSOC */

	/* Check if we are not switching bands */
	if (iwl_check_bits(priv->staging_rxon.flags, RXON_FLG_BAND_24G_MSK) !=
	    iwl_check_bits(priv->active_rxon.flags, RXON_FLG_BAND_24G_MSK))
		return 1;

	/* Check if we are switching association toggle */
	if (iwl_check_bits(priv->staging_rxon.filter_flags,
			   RXON_FILTER_ASSOC_MSK) !=
	    iwl_check_bits(priv->active_rxon.filter_flags,
			   RXON_FILTER_ASSOC_MSK))
		return 1;

	return 0;
}

static int iwl_send_rxon_assoc(struct iwl_priv *priv)
{
	int rc = 0;
	struct iwl_rx_packet *res = NULL;
	struct iwl_rxon_assoc_cmd rxon_assoc;
	struct iwl_host_cmd cmd;
	memset(&cmd,0,sizeof(struct iwl_host_cmd));
	memset(&rxon_assoc,0,sizeof(struct iwl_rxon_assoc_cmd));
		cmd.id = REPLY_RXON_ASSOC;
		cmd.len = sizeof(rxon_assoc);
		cmd.meta.flags = CMD_WANT_SKB;
		cmd.data = &rxon_assoc;

	const struct iwl_rxon_cmd *rxon1 = &priv->staging_rxon;
	const struct iwl_rxon_cmd *rxon2 = &priv->active_rxon;

	if ((rxon1->flags == rxon2->flags) &&
	    (rxon1->filter_flags == rxon2->filter_flags) &&
	    (rxon1->cck_basic_rates == rxon2->cck_basic_rates) &&
#if IWL == 4965
	    (rxon1->ofdm_ht_single_stream_basic_rates ==
	     rxon2->ofdm_ht_single_stream_basic_rates) &&
	    (rxon1->ofdm_ht_dual_stream_basic_rates ==
	     rxon2->ofdm_ht_dual_stream_basic_rates) &&
	    (rxon1->rx_chain == rxon2->rx_chain) &&
#endif
	    (rxon1->ofdm_basic_rates == rxon2->ofdm_basic_rates)) {
		IWL_DEBUG_INFO("Using current RXON_ASSOC.  Not resending.\n");
		return 0;
	}

	rxon_assoc.flags = priv->staging_rxon.flags;
	rxon_assoc.filter_flags = priv->staging_rxon.filter_flags;
	rxon_assoc.ofdm_basic_rates = priv->staging_rxon.ofdm_basic_rates;
	rxon_assoc.cck_basic_rates = priv->staging_rxon.cck_basic_rates;
	rxon_assoc.reserved = 0;
#if IWL == 4965
	rxon_assoc.ofdm_ht_single_stream_basic_rates =
	    priv->staging_rxon.ofdm_ht_single_stream_basic_rates;
	rxon_assoc.ofdm_ht_dual_stream_basic_rates =
	    priv->staging_rxon.ofdm_ht_dual_stream_basic_rates;
	rxon_assoc.rx_chain_select_flags = priv->staging_rxon.rx_chain;
#endif

	rc = iwl_send_cmd(priv,  &cmd);
	if (rc)
		return rc;

	res = (struct iwl_rx_packet *)mbuf_data(cmd.meta.u.skb);
	if (res->hdr.flags & IWL_CMD_FAILED_MSK) {
		IWL_ERROR("Bad return from REPLY_RXON_ASSOC command\n");
		rc = -EIO;
	}

	priv->alloc_rxb_skb--;
	if (cmd.meta.u.skb)
	if (!(mbuf_type(cmd.meta.u.skb) == MBUF_TYPE_FREE)) 
	mbuf_freem(cmd.meta.u.skb);
	cmd.meta.u.skb=NULL;
	return rc;
}

/**
 * iwl_commit_rxon - commit staging_rxon to hardware
 *
 * The RXON command in staging_rxon is commited to the hardware and
 * the active_rxon structure is updated with the new data.  This
 * function correctly transitions out of the RXON_ASSOC_MSK state if
 * a HW tune is required based on the RXON structure changes.
 */
static int iwl_commit_rxon(struct iwl_priv *priv)
{
	/* cast away the const for active_rxon in this function */
	struct iwl_rxon_cmd *active_rxon = (struct iwl_rxon_cmd *)&priv->active_rxon;
	int rc = 0;

	if (!iwl_is_alive(priv))
		return -1;

	/* always get timestamp with Rx frame */
	priv->staging_rxon.flags |= RXON_FLG_TSF2HOST_MSK;

#if IWL == 3945
	/* select antenna */
	priv->staging_rxon.flags &=
	    ~(RXON_FLG_DIS_DIV_MSK | RXON_FLG_ANT_SEL_MSK);
	priv->staging_rxon.flags |= iwl3945_get_antenna_flags(priv);
#endif

	rc = iwl_check_rxon_cmd(&priv->staging_rxon);
	if (rc) {
		IWL_ERROR("Invalid RXON configuration.  Not committing.\n");
		return -EINVAL;
	}

	/* If we don't need to send a full RXON, we can use
	 * iwl_rxon_assoc_cmd which is used to reconfigure filter
	 * and other flags for the current radio configuration. */
	if (!iwl_full_rxon_required(priv)) {
		rc = iwl_send_rxon_assoc(priv);
		if (rc) {
			IWL_ERROR("Error setting RXON_ASSOC "
				  "configuration (%d).\n", rc);
			return rc;
		}

		memcpy(active_rxon, &priv->staging_rxon, sizeof(*active_rxon));

		return 0;
	}

	/* station table will be caleared */
	priv->assoc_station_added = 0;
#if IWL == 4965
#ifdef CONFIG_IWLWIFI_SENSITIVITY
	priv->sensitivity_data.state = IWL_SENS_CALIB_NEED_REINIT;
	if (!priv->error_recovering)
		priv->start_calib = 0;

	iwl4965_init_sensitivity(priv, CMD_ASYNC, 1);
#endif /* CONFIG_IWLWIFI_SENSITIVITY */
#endif /* IWL == 4965 */

	/* If we are currently associated and the new config requires
	 * an RXON_ASSOC and the new config wants the associated mask enabled,
	 * we must clear the associated from the active configuration
	 * before we apply the new config */
	if (iwl_is_associated(priv) &&
	    (priv->staging_rxon.filter_flags & RXON_FILTER_ASSOC_MSK)) {
		IWL_DEBUG_INFO("Toggling associated bit on current RXON\n");
		active_rxon->filter_flags &= ~RXON_FILTER_ASSOC_MSK;

		rc = iwl_send_cmd_pdu(priv, REPLY_RXON,
				      sizeof(struct iwl_rxon_cmd),
				      &priv->active_rxon);

		/* If the mask clearing failed then we set
		 * active_rxon back to what it was previously */
		if (rc) {
			active_rxon->filter_flags |= RXON_FILTER_ASSOC_MSK;
			IWL_ERROR("Error clearing ASSOC_MSK on current "
				  "configuration (%d).\n", rc);
			return rc;
		}

		/* The RXON bit toggling will have cleared out the
		 * station table in the uCode, so blank it in the driver
		 * as well */
		iwl_clear_stations_table(priv);
	} else if (priv->staging_rxon.filter_flags & RXON_FILTER_ASSOC_MSK) {
		/* When switching from non-associated to associated, the
		 * uCode clears out the station table; so clear it in the
		 * driver as well */
		iwl_clear_stations_table(priv);
	}

	IWL_DEBUG_INFO("Sending RXON\n"
		       "* with%s RXON_FILTER_ASSOC_MSK\n"
		       "* channel = %d\n"
		       "* bssid = " MAC_FMT "\n",
		       ((priv->staging_rxon.filter_flags &
			 RXON_FILTER_ASSOC_MSK) ? "" : "out"),
		       priv->staging_rxon.channel,
		       MAC_ARG(priv->staging_rxon.bssid_addr));

	/* Apply the new configuration */
	rc = iwl_send_cmd_pdu(priv, REPLY_RXON,
			      sizeof(struct iwl_rxon_cmd), &priv->staging_rxon);
	if (rc) {
		IWL_ERROR("Error setting new configuration (%d).\n", rc);
		return rc;
	}

#if IWL == 4965
#ifdef CONFIG_IWLWIFI_SENSITIVITY
	if (!priv->error_recovering)
		priv->start_calib = 0;

	priv->sensitivity_data.state = IWL_SENS_CALIB_NEED_REINIT;
	iwl4965_init_sensitivity(priv, CMD_ASYNC, 1);
#endif /* CONFIG_IWLWIFI_SENSITIVITY */
#endif /* IWL == 4965 */

	memcpy(active_rxon, &priv->staging_rxon, sizeof(*active_rxon));

	/* If we issue a new RXON command which required a tune then we must
	 * send a new TXPOWER command or we won't be able to Tx any frames */
	rc = iwl_hw_reg_send_txpower(priv);
	if (rc) {
		IWL_ERROR("Error setting Tx power (%d).\n", rc);
		return rc;
	}

	/* Add the broadcast address so we can send broadcast frames */
	if (iwl_rxon_add_station(priv, BROADCAST_ADDR, 0) ==
	    IWL_INVALID_STATION) {
		IWL_ERROR("Error adding BROADCAST address for transmit.\n");
		return -EIO;
	}

	/* If we have set the ASSOC_MSK and we are in BSS mode then
	 * add the IWL_AP_ID to the station rate table */
	if (iwl_is_associated(priv) &&
	    (priv->iw_mode == IEEE80211_IF_TYPE_STA)) {
		if (iwl_rxon_add_station(priv, priv->active_rxon.bssid_addr, 1)
		    == IWL_INVALID_STATION) {
			IWL_ERROR("Error adding AP address for transmit.\n");
			return -EIO;
		}
		priv->assoc_station_added = 1;
	}

	/* Init the hardware's rate fallback order based on the
	 * phymode */
	rc = iwl3945_init_hw_rate_table(priv);
	if (rc) {
		IWL_ERROR("Error setting HW rate table: %02X\n", rc);
		return -EIO;
	}

	return 0;
}

static int iwl_send_bt_config(struct iwl_priv *priv)
{
	struct iwl_bt_cmd bt_cmd;
	memset(&bt_cmd,0,sizeof(struct iwl_bt_cmd));
		bt_cmd.flags = 3;
		bt_cmd.lead_time = 0xAA;
		bt_cmd.max_kill = 1;
		bt_cmd.kill_ack_mask = 0;
		bt_cmd.kill_cts_mask = 0;

	return iwl_send_cmd_pdu(priv, REPLY_BT_CONFIG,
				sizeof(struct iwl_bt_cmd), &bt_cmd);
}

static int iwl_send_scan_abort(struct iwl_priv *priv)
{
	int rc = 0;
	struct iwl_rx_packet *res;
	struct iwl_host_cmd cmd;
	memset(&cmd,0,sizeof(struct iwl_host_cmd));
		cmd.id = REPLY_SCAN_ABORT_CMD;
		cmd.meta.flags = CMD_WANT_SKB;


	/* If there isn't a scan actively going on in the hardware
	 * then we are in between scan bands and not actually
	 * actively scanning, so don't send the abort command */
	if (!(priv->status & STATUS_SCAN_HW)) {
		priv->status &= ~STATUS_SCAN_ABORTING;
		return 0;
	}

	rc = iwl_send_cmd(priv,  &cmd);
	if (rc) {
		priv->status &= ~STATUS_SCAN_ABORTING;
		return rc;
	}

	res = (struct iwl_rx_packet *)mbuf_data(cmd.meta.u.skb);
	if (res->u.status != CAN_ABORT_STATUS) {
		/* The scan abort will return 1 for success or
		 * 2 for "failure".  A failure condition can be
		 * due to simply not being in an active scan which
		 * can occur if we send the scan abort before we
		 * the microcode has notified us that a scan is
		 * completed. */
		IWL_DEBUG_INFO("SCAN_ABORT returned %d.\n", res->u.status);
		priv->status &= ~(STATUS_SCAN_ABORTING | STATUS_SCAN_HW);
	}

	if (cmd.meta.u.skb)
	if (!(mbuf_type(cmd.meta.u.skb) == MBUF_TYPE_FREE)) 
	mbuf_freem(cmd.meta.u.skb);
	cmd.meta.u.skb=NULL;

	return rc;
}

static int iwl_card_state_sync_callback(struct iwl_priv *priv,
					struct iwl_cmd *cmd,
					mbuf_t skb)
{
	return 1;
}

/*
 * CARD_STATE_CMD
 *
 * Use: Sets the internal card state to enable, disable, or halt
 *
 * When in the 'enable' state the card operates as normal.
 * When in the 'disable' state, the card enters into a low power mode.
 * When in the 'halt' state, the card is shut down and must be fully
 * restarted to come back on.
 */
static int iwl_send_card_state(struct iwl_priv *priv, u32 flags, u8 meta_flag)
{
	struct iwl_host_cmd cmd;
	memset(&cmd,0,sizeof(struct iwl_host_cmd));
		cmd.id = REPLY_CARD_STATE_CMD;
		cmd.len = sizeof(u32);
		cmd.data = &flags;
		cmd.meta.flags = meta_flag;


	if (meta_flag & CMD_ASYNC)
		cmd.meta.u.callback = iwl_card_state_sync_callback;

	return iwl_send_cmd(priv,  &cmd);
}

static int iwl_add_sta_sync_callback(struct iwl_priv *priv,
				     struct iwl_cmd *cmd, mbuf_t skb)
{
	struct iwl_rx_packet *res = NULL;

	if (!skb) {
		IWL_ERROR("Error: Response NULL in " "REPLY_ADD_STA.\n");
		return 1;
	}

	res = (struct iwl_rx_packet *)mbuf_data(skb);
	if (res->hdr.flags & IWL_CMD_FAILED_MSK) {
		IWL_ERROR("Bad return from REPLY_ADD_STA (0x%08X)\n",
			  res->hdr.flags);
		return 1;
	}

	switch (res->u.add_sta.status) {
	case ADD_STA_SUCCESS_MSK:
		break;
	default:
		break;
	}

	/* We didn't cache the SKB; let the caller free it */
	return 1;
}

int iwl_send_add_station(struct iwl_priv *priv,
			 struct iwl_addsta_cmd *sta, u8 flags)
{
	struct iwl_rx_packet *res = NULL;
	int rc = 0;
	struct iwl_host_cmd cmd;// = {
	memset(&cmd,0,sizeof(struct iwl_host_cmd));
		cmd.id = REPLY_ADD_STA;
		cmd.len = sizeof(struct iwl_addsta_cmd);
		cmd.meta.flags = flags;
		cmd.data = sta;
	//};

	if (flags & CMD_ASYNC)
		cmd.meta.u.callback = iwl_add_sta_sync_callback;
	else
		cmd.meta.flags |= CMD_WANT_SKB;

	rc = iwl_send_cmd(priv,  &cmd);

	if (rc || (flags & CMD_ASYNC))
		return rc;

	res = (struct iwl_rx_packet *)mbuf_data(cmd.meta.u.skb);
	if (res->hdr.flags & IWL_CMD_FAILED_MSK) {
		IWL_ERROR("Bad return from REPLY_ADD_STA (0x%08X)\n",
			  res->hdr.flags);
		rc = -EIO;
	}

	if (rc == 0) {
		switch (res->u.add_sta.status) {
		case ADD_STA_SUCCESS_MSK:
			IWL_DEBUG_INFO("REPLY_ADD_STA PASSED\n");
			break;
		default:
			rc = -EIO;
			IWL_WARNING("REPLY_ADD_STA failed\n");
			break;
		}
	}

	priv->alloc_rxb_skb--;
	if (cmd.meta.u.skb)
	if (!(mbuf_type(cmd.meta.u.skb) == MBUF_TYPE_FREE)) 
	mbuf_freem(cmd.meta.u.skb);
	cmd.meta.u.skb=NULL;

	return rc;
}

static int iwl_update_sta_key_info(struct iwl_priv *priv,
				   struct ieee80211_key_conf *keyconf,
				   u8 sta_id)
{
	unsigned long flags;
	u16 key_flags = 0;

	switch (keyconf->alg) {
	case ALG_CCMP:
		key_flags |= STA_KEY_FLG_CCMP;
		key_flags |= keyconf->keyidx << STA_KEY_FLG_KEYID_POS;
		key_flags &= ~STA_KEY_FLG_INVALID;
		break;
	case ALG_TKIP:
	case ALG_WEP:
		return -EINVAL;
	default:
		return -EINVAL;
	}
	spin_lock_irqsave(&priv->sta_lock, flags);
	priv->stations[sta_id].keyinfo.alg = keyconf->alg;
	priv->stations[sta_id].keyinfo.keylen = keyconf->keylen;
	memcpy(priv->stations[sta_id].keyinfo.key, keyconf->key,
	       keyconf->keylen);

	memcpy(priv->stations[sta_id].sta.key.key, keyconf->key,
	       keyconf->keylen);
	priv->stations[sta_id].sta.key.key_flags = key_flags;
	priv->stations[sta_id].sta.sta.modify_mask |= STA_MODIFY_KEY_MASK;
	priv->stations[sta_id].sta.mode |= STA_CONTROL_MODIFY_MSK;

	spin_unlock_irqrestore(&priv->sta_lock, flags);

	IWL_DEBUG_INFO("hwcrypto: modify ucode station key info\n");
	iwl_send_add_station(priv, &priv->stations[sta_id].sta, 0);
	return 0;
}

static void iwl_clear_free_frames(struct iwl_priv *priv)
{
	struct list_head *element;

	IWL_DEBUG_INFO("%d frames on pre-allocated heap on clear.\n",
		       priv->frames_count);

	while (!list_empty(&priv->free_frames)) {
		element = priv->free_frames.next;
		list_del(element);
		if (list_entry(element, struct iwl_frame, list))
		IOFree(list_entry(element, struct iwl_frame, list),sizeof(struct iwl_frame));
		priv->frames_count--;
	}

	if (priv->frames_count) {
		IWL_WARNING("%d frames still in use.  Did we lose one?\n",
			    priv->frames_count);
		priv->frames_count = 0;
	}
}

static struct iwl_frame *iwl_get_free_frame(struct iwl_priv *priv)
{
	struct iwl_frame *frame;
	struct list_head *element;
	if (list_empty(&priv->free_frames)) {
		frame = (struct iwl_frame*)IOMalloc(sizeof(*frame));
		memset(frame,0,sizeof(*frame));
		if (!frame) {
			IWL_ERROR("Could not allocate frame!\n");
			return NULL;
		}

		priv->frames_count++;
		return frame;
	}

	element = priv->free_frames.next;
	list_del(element);
	return list_entry(element, struct iwl_frame, list);
}

static void iwl_free_frame(struct iwl_priv *priv, struct iwl_frame *frame)
{
	memset(frame, 0, sizeof(*frame));
	list_add(&frame->list, &priv->free_frames);
}

int iwl_fill_beacon_frame(struct iwl_priv *priv,
			  struct ieee80211_hdr *hdr, const u8 * dest, int left)
{

	if (!iwl_is_associated(priv) || !priv->ibss_beacon ||
	    ((priv->iw_mode != IEEE80211_IF_TYPE_IBSS) &&
	     (priv->iw_mode != IEEE80211_IF_TYPE_AP)))
		return 0;

	if (mbuf_len(priv->ibss_beacon) > left)
		return 0;

	memcpy(hdr, mbuf_data(priv->ibss_beacon), mbuf_len(priv->ibss_beacon));

	return mbuf_len(priv->ibss_beacon);
}

static int iwl_send_beacon_cmd(struct iwl_priv *priv)
{
	struct iwl_frame *frame;
	int frame_size, rc;
	u16 rate;

	frame = iwl_get_free_frame(priv);

	if (!frame) {
		IWL_ERROR("Coult not obtain free frame buffer for beacon "
			  "command.\n");
		return -ENOMEM;
	}

	if (!(priv->staging_rxon.flags & RXON_FLG_BAND_24G_MSK)) {
		rate = iwl_rate_get_lowest_plcp(priv->active_rate_basic &
						0xFF0);
		if (rate <= 0)
			rate = IWL_RATE_6M_PLCP;
	} else {
		rate = iwl_rate_get_lowest_plcp(priv->active_rate_basic & 0xF);
		if (rate <= 0)
			rate = IWL_RATE_1M_PLCP;
	}

	frame_size = iwl_hw_get_beacon_cmd(priv, frame, rate);

	rc = iwl_send_cmd_pdu(priv, REPLY_TX_BEACON, frame_size,
			      &frame->u.cmd[0]);

	iwl_free_frame(priv, frame);

	return rc;
}

/******************************************************************************
 *
 * EEPROM related functions
 *
 ******************************************************************************/

static void get_eeprom_mac(struct iwl_priv *priv, u8 * mac)
{
	memcpy(mac, priv->eeprom.mac_address, 6);
}

/**
 * iwl_eeprom_init - read EEPROM contents
 *
 * Load the EEPROM from adapter into priv->eeprom
 *
 * NOTE:  This routine uses the non-debug IO access functions.
 */
int iwl_eeprom_init(struct iwl_priv *priv)
{
	u16 *e = (u16 *) & priv->eeprom;
	u32 r;
	int to;
	u32 gp = iwl_read32(priv, CSR_EEPROM_GP);
	u16 sz = sizeof(priv->eeprom);
	int rc;
	u16 addr;

	/* The EEPROM structure has several padding buffers within it
	 * and when adding new EEPROM maps is subject to programmer errors
	 * which may be very difficult to identify without explicitly
	 * checking the resulting size of the eeprom map. */
	if(sizeof(priv->eeprom) != IWL_EEPROM_IMAGE_SIZE) return -1;

	if ((gp & CSR_EEPROM_GP_VALID_MSK) == CSR_EEPROM_GP_BAD_SIGNATURE) {
		IWL_ERROR("EEPROM not found, EEPROM_GP=0x%08x\n", gp);
		return -ENOENT;
	}
#if IWL == 3945
	_iwl_clear_bit(priv, CSR_EEPROM_GP, CSR_EEPROM_GP_OWNER);
#endif

	for (addr = 0, r = 0; addr < sz; addr += 2) {
		_iwl_write32(priv, CSR_EEPROM_REG, addr << 1);
		_iwl_clear_bit(priv, CSR_EEPROM_REG, 0x00000002);
		rc = _iwl_grab_restricted_access(priv);
		if (rc)
			return rc;

		for (to = 0; to < 10; to++) {
			r = _iwl_read_restricted(priv, CSR_EEPROM_REG);
			if (r & 1)
				break;
			udelay(5);
		}

		_iwl_release_restricted_access(priv);

		if (!(r & 1)) {
			IWL_ERROR("Time out reading EEPROM[%d]\n", addr);
			return -ETIMEDOUT;
		}

		e[addr / 2] = le16_to_cpu(r >> 16);
	}

	return 0;
}

/******************************************************************************
 *
 * Misc. internal state and helper functions
 *
 ******************************************************************************/
#ifdef CONFIG_IWLWIFI_DEBUG

/**
 * iwl_report_frame - dump frame to syslog during debug sessions
 *
 * hack this function to show different aspects of received frames,
 * including selective frame dumps.
 * group100 parameter selects whether to show 1 out of 100 good frames.
 *
 * TODO:  ieee80211_hdr stuff is common to 3945 and 4965, so frame type
 *        info output is okay, but some of this stuff (e.g. iwl_rx_frame_stats)
 *        is 3945-specific and gives bad output for 4965.  Need to split the
 *        functionality, keep common stuff here.
 */
void iwl_report_frame(struct iwl_priv *priv,
		      struct iwl_rx_packet *pkt,
		      struct ieee80211_hdr *header, int group100)
{
	u32 to_us;
	u32 print_summary = 0;
	u32 print_dump = 0;	/* set to 1 to dump all frames' contents */
	u32 hundred = 0;
	u32 dataframe = 0;

	/* these are declared without "=" to avoid compiler warnings if we
	 *   don't use them in the debug messages below */
	u16 frame_ctl;
	u16 seq_ctl;
	u16 channel;
	u16 phy_flags;
	int rate_sym;
	u16 length;
	u16 status;
	u16 bcn_tmr;
	u32 tsf_low;
	u64 tsf;
	u8 rssi;
	u8 agc;
	u16 sig_avg;
	u16 noise_diff;

	struct iwl_rx_frame_stats *rx_stats = IWL_RX_STATS(pkt);
	struct iwl_rx_frame_hdr *rx_hdr = IWL_RX_HDR(pkt);
	struct iwl_rx_frame_end *rx_end = IWL_RX_END(pkt);
	u8 *data = IWL_RX_DATA(pkt);

	/* MAC header */
	frame_ctl = le16_to_cpu(header->frame_control);
	seq_ctl = le16_to_cpu(header->seq_ctrl);

	/* metadata */
	channel = le16_to_cpu(rx_hdr->channel);
	phy_flags = le16_to_cpu(rx_hdr->phy_flags);
	rate_sym = rx_hdr->rate;
	length = le16_to_cpu(rx_hdr->len);

	/* end-of-frame status and timestamp */
	status = le32_to_cpu(rx_end->status);
	bcn_tmr = le32_to_cpu(rx_end->beacon_timestamp);
	tsf_low = le64_to_cpu(rx_end->timestamp) & 0x0ffffffff;
	tsf = le64_to_cpu(rx_end->timestamp);

	/* signal statistics */
	rssi = rx_stats->rssi;
	agc = rx_stats->agc;
	sig_avg = le16_to_cpu(rx_stats->sig_avg);
	noise_diff = le16_to_cpu(rx_stats->noise_diff);

	to_us = !compare_ether_addr(header->addr1, priv->mac_addr);

	/* if data frame is to us and all is good,
	 *   (optionally) print summary for only 1 out of every 100 */
	if (to_us && (frame_ctl & ~IEEE80211_FCTL_PROTECTED) ==
	    (IEEE80211_FCTL_FROMDS | IEEE80211_FTYPE_DATA)) {
		dataframe = 1;
		if (!group100) {
			print_summary = 1;	/* print each frame */
		} else if (priv->framecnt_to_us < 100) {
			priv->framecnt_to_us++;
			print_summary = 0;
		} else {
			priv->framecnt_to_us = 0;
			print_summary = 1;
			hundred = 1;
		}
	} else {
		/* print summary for all other frames */
		print_summary = 1;
	}

	if (print_summary) {
		char *title;
		u32 rate;

		if (hundred)
			title = "100Frames";
		else if (frame_ctl & IEEE80211_FCTL_RETRY)
			title = "Retry";
		else if (ieee80211_is_assoc_response(frame_ctl))
			title = "AscRsp";
		else if (ieee80211_is_reassoc_response(frame_ctl))
			title = "RasRsp";
		else if (ieee80211_is_probe_response(frame_ctl)) {
			title = "PrbRsp";
			print_dump = 1;	/* dump frame contents */
		} else if (ieee80211_is_beacon(frame_ctl)) {
			title = "Beacon";
			print_dump = 1;	/* dump frame contents */
		} else if (ieee80211_is_atim(frame_ctl))
			title = "ATIM";
		else if (ieee80211_is_auth(frame_ctl))
			title = "Auth";
		else if (ieee80211_is_deauth(frame_ctl))
			title = "DeAuth";
		else if (ieee80211_is_disassoc(frame_ctl))
			title = "DisAssoc";
		else
			title = "Frame";

		rate = iwl_rate_index_from_plcp(rate_sym);
		if (rate == -1)
			rate = 0;
		else
			rate = iwl_rates[rate].ieee / 2;

		/* print frame summary.
		 * MAC addresses show just the last byte (for brevity),
		 *    but you can hack it to show more, if you'd like to. */
		if (dataframe) {
			IWL_DEBUG_RX("%s: mhd=0x%04x, dst=0x%02x, "
				     "len=%u, rssi=%d, chnl=%d, rate=%u, \n",
				     title, frame_ctl, header->addr1[5],
				     length, rssi, channel, rate);
		} else {
			/* src/dst addresses assume managed mode */
			IWL_DEBUG_RX("%s: 0x%04x, dst=0x%02x, "
				     "src=0x%02x, rssi=%u, tim=%lu usec, "
				     "phy=0x%02x, chnl=%d\n",
				     title, frame_ctl, header->addr1[5],
				     header->addr3[5], rssi,
				     tsf_low - priv->scan_start_tsf,
				     phy_flags, channel);
		}
	}
	if (print_dump)
		printk_buf(IWL_DL_RX, data, length);
}
#endif

static void iwl_unset_hw_setting(struct iwl_priv *priv)
{
	if (priv->hw_setting.shared_virt)
	{
		IOFreeContiguous( priv->hw_setting.shared_virt, sizeof(struct iwl_shared));
		pci_free_consistent(priv->pci_dev,
				    sizeof(struct iwl_shared),
				    priv->hw_setting.shared_virt,
				    priv->hw_setting.shared_phys);
		priv->hw_setting.shared_phys=NULL;
	}
}

/**
 * iwl_supported_rate_to_ie - fill in the supported rate in IE field
 *
 * return : set the bit for each supported rate insert in ie
 */
static u16 iwl_supported_rate_to_ie(u8 * ie, u16 supported_rate,
				    u16 basic_rate, int max_count)
{
	u16 ret_rates = 0, bit;
	int i;
	u8 *rates;

	rates = &(ie[1]);

	for (bit = 1, i = 0; i < IWL_RATE_COUNT; i++, bit <<= 1) {
		if (bit & supported_rate) {
			ret_rates |= bit;
			rates[*ie] = iwl_rates[i].ieee |
			    ((bit & basic_rate) ? 0x80 : 0x00);
			*ie = *ie + 1;
			if (*ie >= max_count)
				break;
		}
	}

	return ret_rates;
}

#if IWL == 4965
#ifdef CONFIG_IWLWIFI_HT
void static d_get_ht_capab (struct ieee80211_hw *hw,
		     struct ieee80211_ht_capability *ht_cap_param);
#endif
#endif

/**
 * iwl_fill_probe_req - fill in all required fields and IE for probe request
 */
static int iwl_fill_probe_req(struct iwl_priv *priv,
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

	frame->frame_control = cpu_to_le16(IEEE80211_STYPE_PROBE_REQ);
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
	ret_rates = priv->active_rate = priv->rates_mask;
	priv->active_rate_basic = priv->rates_mask & IWL_BASIC_RATES_MASK;

	iwl_supported_rate_to_ie(pos, priv->active_rate,
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
	iwl_supported_rate_to_ie(pos, ret_rates, priv->active_rate_basic, left);
	if (*pos > 0)
		len += 2 + *pos;
#if IWL == 4965
#ifdef CONFIG_IWLWIFI_HT
	if (is_direct && priv->is_ht_enabled) {
		pos += (*pos) + 1;
		*pos++ = WLAN_EID_HT_CAPABILITY;
		*pos++ = sizeof(struct ieee80211_ht_capability);
		d_get_ht_capab(NULL, (struct ieee80211_ht_capability *)pos);
		len += 2 + sizeof(struct ieee80211_ht_capability);
	}
#endif  /*CONFIG_IWLWIFI_HT */
#endif

 fill_end:
	return len;
}

/*
 * Power management (not Tx power!) functions
 */
#define MSEC_TO_USEC 1024

#if IWL == 3945
#define NOSLP 0
#define SLP IWL_POWER_DRIVER_ALLOW_SLEEP_MSK
#elif IWL == 4965
#define NOSLP 0, 0, 0
#define SLP IWL_POWER_DRIVER_ALLOW_SLEEP_MSK, 0, 0
#endif

/* default power management (not Tx power) table values */
/* for tim  0-10 */
static struct iwl_power_vec_entry range_0[IWL_POWER_AC] = {
	{{NOSLP, 0 * MSEC_TO_USEC, 0 * MSEC_TO_USEC, {0, 0, 0, 0, 0}}, 0},
	{{SLP, 200 * MSEC_TO_USEC, 500 * MSEC_TO_USEC, {1, 2, 3, 4, 4}}, 0},
	{{SLP, 200 * MSEC_TO_USEC, 300 * MSEC_TO_USEC, {2, 4, 6, 7, 7}}, 0},
	{{SLP, 50 * MSEC_TO_USEC, 100 * MSEC_TO_USEC, {2, 6, 9, 9, 10}}, 0},
	{{SLP, 50 * MSEC_TO_USEC, 25 * MSEC_TO_USEC, {2, 7, 9, 9, 10}}, 1},
	{{SLP, 25 * MSEC_TO_USEC, 25 * MSEC_TO_USEC, {4, 7, 10, 10, 10}}, 1}
};

/* for tim > 10 */
static struct iwl_power_vec_entry range_1[IWL_POWER_AC] = {
	{{NOSLP, 0 * MSEC_TO_USEC, 0 * MSEC_TO_USEC, {0, 0, 0, 0, 0}}, 0},
	{{SLP, 200 * MSEC_TO_USEC, 500 * MSEC_TO_USEC, {1, 2, 3, 4, 0xFF}}, 0},
	{{SLP, 200 * MSEC_TO_USEC, 300 * MSEC_TO_USEC, {2, 4, 6, 7, 0xFF}}, 0},
	{{SLP, 50 * MSEC_TO_USEC, 100 * MSEC_TO_USEC, {2, 6, 9, 9, 0xFF}}, 0},
	{{SLP, 50 * MSEC_TO_USEC, 25 * MSEC_TO_USEC, {2, 7, 9, 9, 0xFF}}, 0},
	{{SLP, 25 * MSEC_TO_USEC, 25 * MSEC_TO_USEC, {4, 7, 10, 10, 0xFF}}, 0}
};

int iwl_power_init_handle(struct iwl_priv *priv)
{
	int rc = 0, i;
	struct iwl_power_mgr *pow_data;
	int size = sizeof(struct iwl_power_vec_entry) * IWL_POWER_AC;
	u16 pci_pm;

	IWL_DEBUG_POWER("Initialize power \n");

	pow_data = &(priv->power_data);

	memset(pow_data, 0, sizeof(*pow_data));

	pow_data->active_index = IWL_POWER_RANGE_0;
	pow_data->dtim_val = 0xffff;

	memcpy(&pow_data->pwr_range_0[0], &range_0[0], size);
	memcpy(&pow_data->pwr_range_1[0], &range_1[0], size);

	rc = 0;
	pci_pm= clone->fPCIDevice->configRead16(PCI_LINK_CTRL);
	//pci_read_config_word(priv->pci_dev, PCI_LINK_CTRL, &pci_pm);
	if (rc != 0)
		return 0;
	else {
		struct iwl_powertable_cmd *cmd;

		IWL_DEBUG_POWER("adjust power command flags\n");

		for (i = 0; i < IWL_POWER_AC; i++) {
			cmd = &pow_data->pwr_range_0[i].cmd;

			if (pci_pm & 0x1)
				cmd->flags &= ~IWL_POWER_PCI_PM_MSK;
			else
				cmd->flags |= IWL_POWER_PCI_PM_MSK;
		}
	}
	return rc;
}

static int iwl_update_power_cmd(struct iwl_priv *priv,
				struct iwl_powertable_cmd *cmd, u32 mode)
{
	int rc = 0, i;
	u8 skip;
	u32 max_sleep = 0;
	struct iwl_power_vec_entry *range;
	u8 period = 0;
	struct iwl_power_mgr *pow_data;

	if (mode > IWL_POWER_INDEX_5) {
		IWL_DEBUG_POWER("Error invalid power mode \n");
		return -1;
	}
	pow_data = &(priv->power_data);

	if (pow_data->active_index == IWL_POWER_RANGE_0)
		range = &pow_data->pwr_range_0[0];
	else
		range = &pow_data->pwr_range_1[1];

	memcpy(cmd, &range[mode].cmd, sizeof(struct iwl_powertable_cmd));

#ifdef IWL_MAC80211_DISABLE
	if (priv->assoc_network != NULL) {
		unsigned long flags;

		period = priv->assoc_network->tim.tim_period;
	}
#endif	/*IWL_MAC80211_DISABLE */
	skip = range[mode].no_dtim;

	if (period == 0) {
		period = 1;
		skip = 0;
	}

	if (skip == 0) {
		max_sleep = period;
		cmd->flags &= ~IWL_POWER_SLEEP_OVER_DTIM_MSK;
	} else {
		__le32 slp_itrvl = cmd->sleep_interval[IWL_POWER_VEC_SIZE - 1];
		max_sleep = (le32_to_cpu(slp_itrvl) / period) * period;
		cmd->flags |= IWL_POWER_SLEEP_OVER_DTIM_MSK;
	}

	for (i = 0; i < IWL_POWER_VEC_SIZE; i++) {
		if (le32_to_cpu(cmd->sleep_interval[i]) > max_sleep)
			cmd->sleep_interval[i] = cpu_to_le32(max_sleep);
	}
	
	IWL_DEBUG_POWER("Flags value = 0x%08X\n", cmd->flags);
	IWL_DEBUG_POWER("Tx timeout = %u\n", cmd->tx_data_timeout);
	IWL_DEBUG_POWER("Rx timeout = %u\n", cmd->rx_data_timeout);
	IWL_DEBUG_POWER
	    ("Sleep interval vector = { %d , %d , %d , %d , %d }\n",
	     cmd->sleep_interval[0], cmd->sleep_interval[1],
	     cmd->sleep_interval[2], cmd->sleep_interval[3],
	     cmd->sleep_interval[4]);

	return rc;
}

static int iwl_send_power_mode(struct iwl_priv *priv, u32 mode)
{
	u32 final_mode = mode;
	int rc;
	unsigned long flags;
	struct iwl_powertable_cmd cmd;
	memset(&cmd,0,sizeof(struct iwl_powertable_cmd));
	/* If on battery, set to 3,
	 * if plugged into AC power, set to CAM ("continuosly aware mode"),
	 * else user level */
	switch (mode) {
	case IWL_POWER_BATTERY:
		final_mode = IWL_POWER_INDEX_3;
		break;
	case IWL_POWER_AC:
		final_mode = IWL_POWER_MODE_CAM;
		break;
	default:
		final_mode = mode;
		break;
	}

#if IWL == 4965
	cmd.keep_alive_beacons = 0;
#endif

	iwl_update_power_cmd(priv, &cmd, final_mode);

	rc = iwl_send_cmd_pdu(priv, POWER_TABLE_CMD, sizeof(cmd), &cmd);

	spin_lock_irqsave(&priv->lock, flags);

	if (final_mode == IWL_POWER_MODE_CAM) {
		priv->status &= ~STATUS_POWER_PMI;
	} else {
		priv->status |= STATUS_POWER_PMI;
	}

	spin_unlock_irqrestore(&priv->lock, flags);
	return rc;
}

int iwl_is_network_packet(struct iwl_priv *priv, struct ieee80211_hdr *header)
{
	/* Filter incoming packets to determine if they are targeted toward
	 * this network, discarding packets coming from ourselves */
	switch (priv->iw_mode) {
	case IEEE80211_IF_TYPE_IBSS: /* Header: Dest. | Source    | BSSID */
		/* packets from our adapter are dropped (echo) */
		if (!compare_ether_addr(header->addr2, priv->mac_addr))
			return 0;
		/* {broad,multi}cast packets to our IBSS go through */
		if (is_multicast_ether_addr(header->addr1))
			return !compare_ether_addr(header->addr3, priv->bssid);
		/* packets to our adapter go through */
		return !compare_ether_addr(header->addr1, priv->mac_addr);
	case IEEE80211_IF_TYPE_STA: /* Header: Dest. | AP{BSSID} | Source */
		/* packets from our adapter are dropped (echo) */
		if (!compare_ether_addr(header->addr3, priv->mac_addr))
			return 0;
		/* {broad,multi}cast packets to our BSS go through */
		if (is_multicast_ether_addr(header->addr1))
			return !compare_ether_addr(header->addr2, priv->bssid);
		/* packets to our adapter go through */
		return !compare_ether_addr(header->addr1, priv->mac_addr);
	}

	return 1;
}

#define TX_STATUS_ENTRY(x) case TX_STATUS_FAIL_ ## x: return #x

const char *iwl_get_tx_fail_reason(u32 status)
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

/**
 * iwl_scan_cancel - Cancel any currently executing HW scan
 * @ms: amount of time to wait (in milliseconds) for scan to abort
 *
 * NOTE: priv->mutex must be held before calling this function
 */
static int iwl_scan_cancel(struct iwl_priv *priv, unsigned long ms)
{
	unsigned long now = jiffies;

	if (!(priv->status & STATUS_SCAN_HW)) {
		priv->status &= ~STATUS_SCANNING;
		return 0;
	}

	if (priv->status & STATUS_SCAN_PENDING) {
		IWL_DEBUG_SCAN("Canceling pending scan request.\n");
		priv->status &= ~STATUS_SCAN_PENDING;
	}

	if (priv->status & STATUS_SCANNING) {
		if (!(priv->status & STATUS_SCAN_ABORTING)) {
			IWL_DEBUG_SCAN("Queuing scan abort.\n");
			priv->status |= STATUS_SCAN_ABORTING;
			//queue_work(priv->workqueue, &priv->abort_scan);
			clone->queue_te(5,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_abort_scan),priv,NULL,true);


		} else {
			IWL_DEBUG_SCAN("Scan abort already in progress.\n");
		}

		mutex_unlock(&priv->mutex);
		if (ms)
			while (!time_after(jiffies,
					   now + msecs_to_jiffies(ms)) &&
			       priv->status & STATUS_SCANNING)
				udelay(1);

		mutex_lock(&priv->mutex);
	}

	return (priv->status & STATUS_SCANNING);
}

static void iwl_sequence_reset(struct iwl_priv *priv)
{
	/* Reset ieee stats */

	/* We don't reset the net_device_stats (ieee->stats) on
	 * re-association */

	priv->last_seq_num = -1;
	priv->last_frag_num = -1;
	priv->last_packet_time = 0;

	iwl_scan_cancel(priv, 0);
}

#if IWL == 4965
#define MAX_UCODE_BEACON_INTERVAL	4096
#else
#define MAX_UCODE_BEACON_INTERVAL	1024
#endif
#define INTEL_CONN_LISTEN_INTERVAL	0xA

static u16 iwl_adjust_beacon_interval(u16 beacon_val)
{
	u16 new_val = 0;
	u16 beacon_factor = 0;

	beacon_factor =
	    (beacon_val +
	     MAX_UCODE_BEACON_INTERVAL) / MAX_UCODE_BEACON_INTERVAL;
	new_val = beacon_val / beacon_factor;

	return new_val;
}

static void iwl_setup_rxon_timing(struct iwl_priv *priv)
{
	u64 interval_tm_unit;
	u64 tsf, result;
	unsigned long flags;
	struct ieee80211_conf *conf = NULL;
	u16 beacon_int = 0;

	conf = ieee80211_get_hw_conf(priv->hw);

	spin_lock_irqsave(&priv->lock, flags);
	priv->rxon_timing.timestamp.dw[1] = priv->timestamp1;
	priv->rxon_timing.timestamp.dw[0] = priv->timestamp0;

	priv->rxon_timing.listen_interval = INTEL_CONN_LISTEN_INTERVAL;

	tsf = priv->timestamp1;
	tsf = ((tsf << 32) | priv->timestamp0);

	beacon_int = priv->beacon_int;
	spin_unlock_irqrestore(&priv->lock, flags);

	if (priv->iw_mode == IEEE80211_IF_TYPE_STA) {
		if (beacon_int == 0) {
			priv->rxon_timing.beacon_interval = 100;
			priv->rxon_timing.beacon_init_val = 102400;
		} else {
			priv->rxon_timing.beacon_interval = beacon_int;
			priv->rxon_timing.beacon_interval =
			    iwl_adjust_beacon_interval(
				    priv->rxon_timing.beacon_interval);
		}

		priv->rxon_timing.atim_window = 0;
	} else {
		priv->rxon_timing.beacon_interval =
			iwl_adjust_beacon_interval(conf->beacon_int);
		/* TODO: we need to get atim_window from upper stack
		 * for now we set to 0 */
		priv->rxon_timing.atim_window = 0;
	}

	interval_tm_unit = (priv->rxon_timing.beacon_interval * 1024);
	result = (tsf/ interval_tm_unit);//do_div
	priv->rxon_timing.beacon_init_val =
	    (u32) ((u64) interval_tm_unit - result);

	IWL_DEBUG_ASSOC
	    ("beacon interval %d beacon timer %d beacon tim %d\n",
	     priv->rxon_timing.beacon_interval,
	     priv->rxon_timing.beacon_init_val, priv->rxon_timing.atim_window);
}

int iwl_scan_initiate(struct iwl_priv *priv)
{
	if (priv->iw_mode == IEEE80211_IF_TYPE_AP) {
		IWL_ERROR("APs don't scan.\n");
		return 0;
	}

	if (!iwl_is_ready_rf(priv)) {
		IWL_DEBUG_SCAN("Aborting scan due to not ready.\n");
		return -EIO;
	}

	if (priv->status & STATUS_SCANNING) {
		IWL_DEBUG_SCAN("Scan already in progress.\n");
		return -EAGAIN;
	}

	if (priv->status & STATUS_SCAN_ABORTING) {
		IWL_DEBUG_SCAN("Scan request while abort pending.  "
			       "Queuing.\n");
		return -EAGAIN;
	}

	IWL_DEBUG_INFO("Starting scan...\n");
	priv->scan_bands = 2;
	priv->status |= STATUS_SCANNING;
	priv->scan_start = jiffies;
	priv->scan_pass_start = priv->scan_start;

	//queue_work(priv->workqueue, &priv->request_scan);
	clone->queue_te(4,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_request_scan),priv,NULL,true);

	return 0;
}

static int iwl_set_rxon_hwcrypto(struct iwl_priv *priv, int hw_decrypt)
{
	struct iwl_rxon_cmd *rxon = &priv->staging_rxon;

	if (hw_decrypt)
		rxon->filter_flags &= ~RXON_FILTER_DIS_DECRYPT_MSK;
	else
		rxon->filter_flags |= RXON_FILTER_DIS_DECRYPT_MSK;

	return 0;
}

static void iwl_set_flags_for_phymode(struct iwl_priv *priv, u8 phymode)
{
	if ((phymode == MODE_IEEE80211A) ||
	    (phymode == MODE_ATHEROS_TURBO)) {
		priv->staging_rxon.flags &=
		    ~(RXON_FLG_BAND_24G_MSK | RXON_FLG_AUTO_DETECT_MSK
		      | RXON_FLG_CCK_MSK);
		priv->staging_rxon.flags |= RXON_FLG_SHORT_SLOT_MSK;
	} else {
		/* Copied from iwl_bg_post_associate() */
		if (priv->assoc_capability & WLAN_CAPABILITY_SHORT_SLOT_TIME)
			priv->staging_rxon.flags |= RXON_FLG_SHORT_SLOT_MSK;
		else
			priv->staging_rxon.flags &= ~RXON_FLG_SHORT_SLOT_MSK;

		if (priv->iw_mode == IEEE80211_IF_TYPE_IBSS)
			priv->staging_rxon.flags &= ~RXON_FLG_SHORT_SLOT_MSK;

		priv->staging_rxon.flags |= RXON_FLG_BAND_24G_MSK;
		priv->staging_rxon.flags |= RXON_FLG_AUTO_DETECT_MSK;
		priv->staging_rxon.flags &= ~RXON_FLG_CCK_MSK;
	}
}

/*
 * initilize rxon structure with default values fromm eeprom
 */
static void iwl_connection_init_rx_config(struct iwl_priv *priv)
{
	const struct iwl_channel_info *ch_info;
	memset(&priv->staging_rxon, 0, sizeof(priv->staging_rxon));

	switch (priv->iw_mode) {
	case IEEE80211_IF_TYPE_AP:
		priv->staging_rxon.dev_type = RXON_DEV_TYPE_AP;
		break;

	case IEEE80211_IF_TYPE_STA:
		priv->staging_rxon.dev_type = RXON_DEV_TYPE_ESS;
		priv->staging_rxon.filter_flags = RXON_FILTER_ACCEPT_GRP_MSK;
		break;

	case IEEE80211_IF_TYPE_IBSS:
		priv->staging_rxon.dev_type = RXON_DEV_TYPE_IBSS;
		priv->staging_rxon.flags = RXON_FLG_SHORT_PREAMBLE_MSK;
		priv->staging_rxon.filter_flags = RXON_FILTER_BCON_AWARE_MSK |
						  RXON_FILTER_ACCEPT_GRP_MSK;
		break;

	case IEEE80211_IF_TYPE_MNTR:
		priv->staging_rxon.dev_type = RXON_DEV_TYPE_SNIFFER;
		priv->staging_rxon.filter_flags = RXON_FILTER_PROMISC_MSK |
		    RXON_FILTER_CTL2HOST_MSK | RXON_FILTER_ACCEPT_GRP_MSK;
		break;
	}

#if 0
	/* TODO:  Figure out when short_preamble would be set and cache from
	 * that */
	if (!hw_to_local(priv->hw)->short_preamble)
		priv->staging_rxon.flags &= ~RXON_FLG_SHORT_PREAMBLE_MSK;
	else
		priv->staging_rxon.flags |= RXON_FLG_SHORT_PREAMBLE_MSK;
#endif
	ch_info = iwl_get_channel_info(priv, priv->phymode,
				       priv->staging_rxon.channel);

	if (!ch_info)
		ch_info = &priv->channel_info[0];

	/*
	 * in some case A channels are all non IBSS
	 * in this case force B/G channel
	 */
	if ((priv->iw_mode == IEEE80211_IF_TYPE_IBSS) &&
	    !(is_channel_ibss(ch_info)))
		ch_info = &priv->channel_info[0];

if (ch_info)
{
	priv->staging_rxon.channel = ch_info->channel;
	if (is_channel_a_band(ch_info))
		priv->phymode = MODE_IEEE80211A;
	else
		priv->phymode = MODE_IEEE80211G;
}
	iwl_set_flags_for_phymode(priv, priv->phymode);
	priv->staging_rxon.ofdm_basic_rates =
	    (IWL_OFDM_RATES_MASK >> IWL_FIRST_OFDM_RATE) & 0xFF;
	priv->staging_rxon.cck_basic_rates =
	    (IWL_CCK_RATES_MASK >> IWL_FIRST_CCK_RATE) & 0xF;

#if IWL == 4965
	priv->staging_rxon.flags |= RXON_FLG_CHANNEL_MODE_LEGACY_MSK;
	memcpy(priv->staging_rxon.node_addr, priv->mac_addr, ETH_ALEN);
	memcpy(priv->staging_rxon.wlap_bssid_addr, priv->mac_addr, ETH_ALEN);
	priv->staging_rxon.ofdm_ht_single_stream_basic_rates = 0xff;
	priv->staging_rxon.ofdm_ht_dual_stream_basic_rates = 0xff;
	iwl4965_set_rxon_chain(priv);
#endif
}

static int iwl_set_mode(struct iwl_priv *priv, int mode)
{
	if (!iwl_is_ready_rf(priv))
		return -EAGAIN;

	if (mode == IEEE80211_IF_TYPE_IBSS) {
		const struct iwl_channel_info *ch_info;

		ch_info = iwl_get_channel_info(priv,
					       priv->phymode,
					       priv->staging_rxon.channel);

		if (!ch_info || !is_channel_ibss(ch_info)) {
			IWL_ERROR("channel %d not IBSS channel\n",
				  priv->staging_rxon.channel);
			return -EINVAL;
		}
	}

	//cancel_delayed_work(&priv->scan_check);
	clone->queue_td(10,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_scan_check));

	priv->status &= ~STATUS_SCAN_PENDING;
	if (iwl_scan_cancel(priv, 100)) {
		IWL_WARNING("Aborted scan still in progress " "after 100ms\n");
		IWL_DEBUG_MAC80211("leaving - scan abort " "failed.\n");
		return -EAGAIN;
	}

	priv->iw_mode = mode;

	iwl_connection_init_rx_config(priv);
	memcpy(priv->staging_rxon.node_addr, priv->mac_addr, ETH_ALEN);

	iwl_clear_stations_table(priv);

	iwl_commit_rxon(priv);

	return 0;
}

static void iwl_build_tx_cmd_hwcrypto(struct iwl_priv *priv,
				      struct ieee80211_tx_control *ctl,
				      struct iwl_cmd *cmd,
				      mbuf_t skb_frag,
				      int last_frag)
{
	struct iwl_hw_key *keyinfo = &priv->stations[ctl->key_idx].keyinfo;

	switch ((int)keyinfo->alg) {
	case ALG_CCMP:
		cmd->cmd.tx.sec_ctl = TX_CMD_SEC_CCM;

		cmd->cmd.tx.hdr[0].frame_control |=
		    cpu_to_le16(IEEE80211_FCTL_PROTECTED);
		/* XXX: ACK flag must be set for CCMP even if it
		 * is a multicast/broadcast packet, because CCMP
		 * group communication encrypted by GTK is
		 * actually done by the AP. */
		cmd->cmd.tx.tx_flags |= TX_CMD_FLG_ACK_MSK;
		memcpy(cmd->cmd.tx.key, keyinfo->key, keyinfo->keylen);
		IWL_DEBUG_TX("tx_cmd with aes  hwcrypto\n");
		break;
	case ALG_TKIP:
#if 0
		cmd->cmd.tx.sec_ctl = TX_CMD_SEC_TKIP;

		if (last_frag)
			memcpy(cmd->cmd.tx.tkip_mic.byte, skb_frag->tail - 8,
			       8);
		else
			memset(cmd->cmd.tx.tkip_mic.byte, 0, 8);

		cmd->cmd.tx.hdr[0].frame_control |=
		    cpu_to_le16(IEEE80211_FCTL_PROTECTED);
		/* XXX: ACK flag must be set for CCMP even if it
		 * is a multicast/broadcast packet, because CCMP
		 * group communication encrypted by GTK is
		 * actually done by the AP. */
		cmd->cmd.tx.tx_flags |= TX_CMD_FLG_ACK_MSK;
#endif
		break;
	case ALG_WEP:
		cmd->cmd.tx.sec_ctl = 1 |	/* WEP */
		    (ctl->key_idx & 0x3) << 6;

		if (keyinfo->keylen == 13)
			cmd->cmd.tx.sec_ctl |= (1 << 3);	/* 128-bit */

		memcpy(&cmd->cmd.tx.key[3], keyinfo->key, keyinfo->keylen);

		cmd->cmd.tx.hdr[0].frame_control |=
		    cpu_to_le16(IEEE80211_FCTL_PROTECTED);

		IWL_DEBUG_TX("Configuring packet for WEP encryption "
			     "with key %d\n", ctl->key_idx);
		break;

	case ALG_NONE:
		IWL_DEBUG_TX("Tx packet in the clear "
			     "(encrypt requested).\n");
		break;

	default:
		printk(KERN_ERR "Unknown encode alg %d\n", keyinfo->alg);
		break;
	}

}

/*
 * handle build REPLY_TX command notification.
 */
static void iwl_build_tx_cmd_basic(struct iwl_priv *priv,
				  struct iwl_cmd *cmd,
				  struct ieee80211_tx_control *ctrl,
				  struct ieee80211_hdr *hdr,
				  int is_unicast, u8 std_id)
{
	u32 tx_flags;
	u16 fc = le16_to_cpu(hdr->frame_control);
	u16 *qc;

	tx_flags = cmd->cmd.tx.tx_flags;

	cmd->cmd.tx.stop_time.life_time = 0xFFFFFFFF;
	if (!(ctrl->flags & IEEE80211_TXCTL_NO_ACK)) {
		tx_flags |= TX_CMD_FLG_ACK_MSK;
		if (WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT)
			tx_flags |= TX_CMD_FLG_SEQ_CTL_MSK;
		if (ieee80211_is_probe_response(fc) &&
		    !(le16_to_cpu(hdr->seq_ctrl) & 0xf))
			tx_flags |= TX_CMD_FLG_TSF_MSK;
	} else {
		tx_flags &= (~TX_CMD_FLG_ACK_MSK);
		tx_flags |= TX_CMD_FLG_SEQ_CTL_MSK;
	}

	cmd->cmd.tx.sta_id = std_id;
	if (ieee80211_get_morefrag(hdr))
		tx_flags |= TX_CMD_FLG_MORE_FRAG_MSK;

	qc = ieee80211_get_qos_ctrl(hdr);
	if (qc) {
		cmd->cmd.tx.tid_tspec = (u8) (*qc & 0xf);
		tx_flags &= ~TX_CMD_FLG_SEQ_CTL_MSK;
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
	if (WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_MGMT) {
		if (((WLAN_FC_GET_STYPE(fc)) == IEEE80211_STYPE_ASSOC_REQ) ||
		    ((WLAN_FC_GET_STYPE(fc)) == IEEE80211_STYPE_REASSOC_REQ))
			cmd->cmd.tx.timeout.pm_frame_timeout = 3;
		else
			cmd->cmd.tx.timeout.pm_frame_timeout = 2;
	} else
		cmd->cmd.tx.timeout.pm_frame_timeout = 0;

	cmd->cmd.tx.driver_txop = 0;
	cmd->cmd.tx.tx_flags = tx_flags;
	cmd->cmd.tx.next_frame_len = 0;
}

static int iwl_get_sta_id(struct iwl_priv *priv, struct ieee80211_hdr *hdr)
{
	int sta_id;
	u16 fc = le16_to_cpu(hdr->frame_control);

	/* If this frame is broadcast or not data then use the broadcast
	 * station id */
	if ((WLAN_FC_GET_TYPE(fc) != IEEE80211_FTYPE_DATA) ||
	    is_multicast_ether_addr(hdr->addr1))
		return IWL_BROADCAST_ID;

	/* If this frame is part of a BSS network (we're a station), then
	 * we use the AP's station id */
	if (priv->iw_mode == IEEE80211_IF_TYPE_STA)
		return IWL_AP_ID;

	/* If this frame is part of a IBSS network, then we use the
	 * target specific station id */
	if (priv->iw_mode == IEEE80211_IF_TYPE_IBSS) {
		sta_id = iwl_hw_find_station(priv, hdr->addr1);
		if (sta_id != IWL_INVALID_STATION)
			return sta_id;

		sta_id = iwl_add_station(priv, hdr->addr1, 0,
					 (CMD_ASYNC | CMD_NO_LOCK));

		if (sta_id != IWL_INVALID_STATION)
			return sta_id;

		IWL_DEBUG_DROP("Station " MAC_FMT " not in station map. "
			       "Defaulting to broadcast...\n",
			       MAC_ARG(hdr->addr1));
		printk_buf(IWL_DL_DROP, (u8 *) hdr, sizeof(*hdr));
		return IWL_BROADCAST_ID;
	}

	/* Otherwise we default to the broadcast station id */
	return IWL_BROADCAST_ID;
}

/*
 * start REPLY_TX command process
 */
static int iwl_tx_skb(struct iwl_priv *priv,
		      mbuf_t skb, struct ieee80211_tx_control *ctl)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)mbuf_data(skb);
	struct iwl_tfd_frame *tfd;
	u32 *control_flags;
	int txq_id = ctl->queue;
	struct iwl_tx_queue *txq = &priv->txq[txq_id];
	struct iwl_queue *q = &txq->q;
	dma_addr_t phys_addr;
	dma_addr_t txcmd_phys;
	struct iwl_cmd *out_cmd = NULL;
	u16 len, idx, len_org;
	u8 id, hdr_len, unicast;
	u8 sta_id;
	u16 seq_number = 0;
	u16 fc;
	u16 *qc;
	u8 wait_write_ptr = 0;
	unsigned long flags;
	int rc;

	spin_lock_irqsave(&priv->lock, flags);
	if (priv->status & STATUS_RF_KILL_MASK) {
		IWL_DEBUG_DROP("Dropping - RF KILL\n");
		goto drop;
	}

	if (!priv->interface_id) {
		IWL_DEBUG_DROP("Dropping - !priv->interface_id\n");
		goto drop;
	}

	if ((ctl->tx_rate & 0xFF) == IWL_INVALID_RATE) {
		IWL_ERROR("ERROR: No TX rate available.\n");
		goto drop;
	}

	unicast = !is_multicast_ether_addr(hdr->addr1);
	id = 0;

	fc = le16_to_cpu(hdr->frame_control);

#ifdef CONFIG_IWLWIFI_DEBUG
	if (ieee80211_is_auth(fc))
		IWL_DEBUG_TX("Sending AUTH frame\n");
	else if (ieee80211_is_assoc_request(fc))
		IWL_DEBUG_TX("Sending ASSOC frame\n");
	else if (ieee80211_is_reassoc_request(fc))
		IWL_DEBUG_TX("Sending REASSOC frame\n");
#endif

	if (!iwl_is_associated(priv) &&
	    (WLAN_FC_GET_TYPE(fc) == IEEE80211_FTYPE_DATA)) {
		IWL_DEBUG_DROP("Dropping - !iwl_is_associated\n");
		goto drop;
	}

	spin_unlock_irqrestore(&priv->lock, flags);

	hdr_len = ieee80211_get_hdrlen(fc);
	sta_id = iwl_get_sta_id(priv, hdr);
	if (sta_id == IWL_INVALID_STATION) {
		IWL_DEBUG_DROP("Dropping - INVALID STATION: " MAC_FMT "\n",
			       MAC_ARG(hdr->addr1));
		spin_lock_irqsave(&priv->lock, flags);
		goto drop;
	}

	IWL_DEBUG_RATE("station Id %d\n", sta_id);

	qc = ieee80211_get_qos_ctrl(hdr);
	if (qc) {
		u8 tid = (u8)(*qc & 0xf);
		seq_number = priv->stations[sta_id].tid[tid].seq_number &
			IEEE80211_SCTL_SEQ;
		hdr->seq_ctrl = cpu_to_le16(seq_number) |
			(hdr->seq_ctrl & IEEE80211_SCTL_FRAG);
		seq_number += 0x10;
	}

	spin_lock_irqsave(&priv->lock, flags);
	tfd = &txq->bd[q->first_empty * q->element_size];
	memset(tfd, 0, q->element_size);
	control_flags = (u32 *) tfd;
	idx = get_next_cmd_index(q, q->first_empty, 0);

	memset(&(txq->txb[q->first_empty]), 0, sizeof(struct iwl_tx_info));
	txq->txb[q->first_empty].skb[0] = skb;
	memcpy(&(txq->txb[q->first_empty].status.control),
	       ctl, sizeof(struct ieee80211_tx_control));
	out_cmd = &txq->cmd[idx];
	memset(&out_cmd->hdr, 0, sizeof(out_cmd->hdr));
	memset(&out_cmd->cmd.tx, 0, sizeof(out_cmd->cmd.tx));
	out_cmd->hdr.cmd = REPLY_TX;
	out_cmd->hdr.sequence = QUEUE_TO_SEQ(txq_id) |
		INDEX_TO_SEQ(q->first_empty);
	/* copy frags header */
	memcpy(out_cmd->cmd.tx.hdr, hdr, hdr_len);

	/* hdr = (struct ieee80211_hdr *)out_cmd->cmd.tx.hdr; */
	len = priv->hw_setting.tx_cmd_len +
		sizeof(struct iwl_cmd_header) + hdr_len;

	len_org = len;
	len = (len + 3) & ~3;

	if (len_org != len) {
		len_org = 1;
	} else
		len_org = 0;
	txcmd_phys =
		txq->dma_addr_cmd + sizeof(struct iwl_cmd) * idx +	offsetof(struct iwl_cmd, hdr);

	iwl_hw_tx_queue_attach_buffer_to_tfd(priv, tfd, txcmd_phys,
					     cpu_to_le16(len));

	if (ctl->key_idx != -1)
		iwl_build_tx_cmd_hwcrypto(priv, ctl, out_cmd, skb, 0);

	/* 802.11 null functions have no payload... */
	len = mbuf_len(skb) - hdr_len;
	if (len) {
		phys_addr = cpu_to_le32(mbuf_data_to_physical((u8*)mbuf_data(skb)+hdr_len));
		//pci_map_single(priv->pci_dev,
		//				       skb->data + hdr_len,
		//				       len, PCI_DMA_TODEVICE));
		iwl_hw_tx_queue_attach_buffer_to_tfd(priv, tfd, phys_addr,
						     cpu_to_le16(len));
	}

	out_cmd->cmd.tx.len = mbuf_len(skb);

#if IWL == 3945
	/* If there is no payload, then only one TFD is used */
	if (!len)
		*control_flags = TFD_CTL_COUNT_SET(1);
	else
		*control_flags = TFD_CTL_COUNT_SET(2) |
			TFD_CTL_PAD_SET(U32_PAD(len));
#else
	if (len_org)
		out_cmd->cmd.tx.tx_flags |= TX_CMD_FLG_MH_PAD_MSK;
#endif

	/* todoG need this for burst mode later on */
	iwl_build_tx_cmd_basic(priv, out_cmd, ctl, hdr, unicast, sta_id);

	/* set is_hcca to 0; it probably will never be implemented */
	iwl_hw_build_tx_cmd_rate(priv, out_cmd, ctl, hdr, sta_id, 0);

	len = out_cmd->cmd.tx.len;

#if IWL == 4965
	iwl4965_tx_cmd(priv, out_cmd, sta_id, txcmd_phys,
		       hdr, hdr_len, ctl, NULL);
#elif IWL == 3945
	out_cmd->cmd.tx.tx_flags &= ~TX_CMD_FLG_ANT_A_MSK;
	out_cmd->cmd.tx.tx_flags &= ~TX_CMD_FLG_ANT_B_MSK;
#endif

	if (!(ieee80211_get_morefrag(hdr))) {
		txq->need_update = 1;
		if ( qc ) {
			u8 tid = (u8)(*qc & 0xf);
			priv->stations[sta_id].tid[tid].seq_number =
				seq_number;
		}
	} else {
		wait_write_ptr = 1;
		txq->need_update = 0;
	}

	printk_buf(IWL_DL_TX, out_cmd->cmd.payload, sizeof(out_cmd->cmd.tx));

	printk_buf(IWL_DL_TX, (u8 *) out_cmd->cmd.tx.hdr,
		   ieee80211_get_hdrlen(out_cmd->cmd.tx.hdr->frame_control));

	//iwl4965_tx_queue_update_wr_ptr(priv, txq, len); //fixme

	q->first_empty = iwl_queue_inc_wrap(q->first_empty, q->n_bd);
	rc = iwl_tx_queue_update_write_ptr(priv, txq);
	spin_unlock_irqrestore(&priv->lock, flags);
	if (rc)
		return rc;

	if ((iwl_queue_space(q) < q->high_mark)
	    && priv->mac80211_registered) {
		if (wait_write_ptr) {
			spin_lock_irqsave(&priv->lock, flags);
			txq->need_update = 1;
			iwl_tx_queue_update_write_ptr(priv, txq);
			spin_unlock_irqrestore(&priv->lock, flags);
		}

		ieee80211_stop_queue(priv->hw, ctl->queue);
	}

	return 0;

 drop:
	spin_unlock_irqrestore(&priv->lock, flags);

	return -1;
}

static void iwl_set_rate(struct iwl_priv *priv)
{
	const struct ieee80211_hw_mode *hw = NULL;
	struct ieee80211_rate *rate;
	int i;

	hw = iwl_get_hw_mode(priv, priv->phymode);

	priv->active_rate = 0;
	priv->active_rate_basic = 0;

	IWL_DEBUG_RATE("Setting rates for 802.11%c\n",
		       ((hw->mode == MODE_IEEE80211A) ||
			(hw->mode == MODE_ATHEROS_TURBO)) ?
		       'a' : ((hw->mode == MODE_IEEE80211B) ? 'b' : 'g'));

	for (i = 0; i < hw->num_rates; i++) {
		rate = &(hw->rates[i]);
		if ((rate->val < IWL_RATE_COUNT) &&
		    (rate->flags & IEEE80211_RATE_SUPPORTED)) {
			IWL_DEBUG_RATE("Adding rate index %d (plcp %d)%s\n",
				       rate->val, iwl_rates[rate->val].plcp,
				       (rate->flags & IEEE80211_RATE_BASIC) ?
				       "*" : "");
			priv->active_rate |= (1 << rate->val);
			if (rate->flags & IEEE80211_RATE_BASIC)
				priv->active_rate_basic |= (1 << rate->val);
		} else {
			IWL_DEBUG_RATE("Not adding rate %d (plcp %d)\n",
				       rate->val, iwl_rates[rate->val].plcp);
		}
	}

	IWL_DEBUG_RATE("Set active_rate = %0x, active_rate_basic = %0x\n",
		       priv->active_rate, priv->active_rate_basic);

	/*
	 * If a basic rate is configured, then use it (adding IWL_RATE_1M_MASK)
	 * otherwise set it to the default of all CCK rates and 6, 12, 24 for
	 * OFDM
	 */
	if (priv->active_rate_basic & IWL_CCK_BASIC_RATES_MASK)
		priv->staging_rxon.cck_basic_rates =
		    ((priv->active_rate_basic &
		      IWL_CCK_RATES_MASK) >> IWL_FIRST_CCK_RATE) & 0xF;
	else
		priv->staging_rxon.cck_basic_rates =
		    (IWL_CCK_BASIC_RATES_MASK >> IWL_FIRST_CCK_RATE) & 0xF;

	if (priv->active_rate_basic & IWL_OFDM_BASIC_RATES_MASK)
		priv->staging_rxon.ofdm_basic_rates =
		    ((priv->active_rate_basic &
		      (IWL_OFDM_BASIC_RATES_MASK | IWL_RATE_6M_MASK)) >>
		      IWL_FIRST_OFDM_RATE) & 0xFF;
	else
		priv->staging_rxon.ofdm_basic_rates =
		   (IWL_OFDM_BASIC_RATES_MASK >> IWL_FIRST_OFDM_RATE) & 0xFF;
}

static void iwl_radio_kill_sw(struct iwl_priv *priv, int disable_radio)
{
	unsigned long flags;

	if ((disable_radio ? 1 : 0) ==
	    ((priv->status & STATUS_RF_KILL_SW) ? 1 : 0))
		return;

	IWL_DEBUG_RF_KILL("Manual SW RF KILL set to: RADIO %s\n",
			  disable_radio ? "OFF" : "ON");

	if (disable_radio) {
		iwl_scan_cancel(priv, 0);
		/* FIXME: This is a workaround for AP */
		if (priv->iw_mode != IEEE80211_IF_TYPE_AP) {
			spin_lock_irqsave(&priv->lock, flags);
			iwl_write32(priv, CSR_UCODE_DRV_GP1_SET,
				    CSR_UCODE_SW_BIT_RFKILL);
			spin_unlock_irqrestore(&priv->lock, flags);
			iwl_send_card_state(priv, CARD_STATE_CMD_DISABLE, 0);
			priv->status |= STATUS_RF_KILL_SW;
			IWL_WARNING("STATUS_RF_KILL_SW enabled\n");
		}
		return;
	}

	spin_lock_irqsave(&priv->lock, flags);
	iwl_write32(priv, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);

	priv->status &= ~STATUS_RF_KILL_SW;
	spin_unlock_irqrestore(&priv->lock, flags);

	/* wake up ucode */
	//msleep
	udelay(10);

	spin_lock_irqsave(&priv->lock, flags);
	iwl_read32(priv, CSR_UCODE_DRV_GP1);
	if (!iwl_grab_restricted_access(priv))
		iwl_release_restricted_access(priv);
	spin_unlock_irqrestore(&priv->lock, flags);

	if (priv->status & STATUS_RF_KILL_HW) {
		IWL_DEBUG_RF_KILL("Can not turn radio back on - "
				  "disabled by HW switch\n");
		return;
	}

	//queue_work(priv->workqueue, &priv->restart);
	clone->queue_te(1,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_restart),priv,NULL,true);
	return;
}

void iwl_set_decrypted_flag(struct iwl_priv *priv, mbuf_t skb,
			    u32 decrypt_res, struct ieee80211_rx_status *stats)
{
	u16 fc =
	    le16_to_cpu(((struct ieee80211_hdr *)mbuf_data(skb))->frame_control);

	if (priv->active_rxon.filter_flags & RXON_FILTER_DIS_DECRYPT_MSK)
		return;

	if (!(fc & IEEE80211_FCTL_PROTECTED))
		return;

	IWL_DEBUG_RX("decrypt_res:0x%x\n", decrypt_res);
	switch (decrypt_res & RX_RES_STATUS_SEC_TYPE_MSK) {
	case RX_RES_STATUS_SEC_TYPE_TKIP:
		if ((decrypt_res & RX_RES_STATUS_DECRYPT_TYPE_MSK) ==
		    RX_RES_STATUS_BAD_ICV_MIC)
			stats->flag |= RX_FLAG_MMIC_ERROR;
	case RX_RES_STATUS_SEC_TYPE_WEP:
	case RX_RES_STATUS_SEC_TYPE_CCMP:
		if ((decrypt_res & RX_RES_STATUS_DECRYPT_TYPE_MSK) ==
		    RX_RES_STATUS_DECRYPT_OK) {
			IWL_DEBUG_RX("hw decrypt successfully!!!\n");
			stats->flag |= RX_FLAG_DECRYPTED;
		}
		break;

	default:
		break;
	}
}

void iwl_handle_data_packet_monitor(struct iwl_priv *priv,
				    struct iwl_rx_mem_buffer *rxb,
				    void *data, short len,
				    struct ieee80211_rx_status *stats,
				    u16 phy_flags)
{
	struct iwl_rt_rx_hdr *iwl_rt;

	/* First cache any information we need before we overwrite
	 * the information provided in the skb from the hardware */
	s8 signal = stats->ssi;
	s8 noise = 0;
	u16 channel = stats->channel;
	int rate = stats->rate;
	u64 tsf = stats->mactime;

	/* We received data from the HW, so stop the watchdog */
	if (len > IWL_RX_BUF_SIZE - sizeof(*iwl_rt)) {
		IWL_DEBUG_DROP("Dropping too large packet in monitor\n");
		return;
	}

	/* copy the frame data to write after where the radiotap header goes */
	iwl_rt = (struct iwl_rt_rx_hdr *)mbuf_data(rxb->skb);
	memmove(iwl_rt->payload, data, len);

	iwl_rt->rt_hdr.it_version = PKTHDR_RADIOTAP_VERSION;
	iwl_rt->rt_hdr.it_pad = 0; /* always good to zero */

	/* total header + data */
	iwl_rt->rt_hdr.it_len = cpu_to_le16(sizeof(*iwl_rt));

	/* Set the size of the skb to the size of the frame */
	skb_put(rxb->skb, sizeof(*iwl_rt) + len);

	/* Big bitfield of all the fields we provide in radiotap */
	iwl_rt->rt_hdr.it_present =
	    cpu_to_le32((1 << IEEE80211_RADIOTAP_TSFT) |
			(1 << IEEE80211_RADIOTAP_FLAGS) |
			(1 << IEEE80211_RADIOTAP_RATE) |
			(1 << IEEE80211_RADIOTAP_CHANNEL) |
			(1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL) |
			(1 << IEEE80211_RADIOTAP_DBM_ANTNOISE) |
			(1 << IEEE80211_RADIOTAP_ANTENNA));

	/* Zero the flags, we'll add to them as we go */
	iwl_rt->rt_flags = 0;

	iwl_rt->rt_tsf = tsf;//cpu_to_le64(tsf);

	/* Convert to dBm */
	iwl_rt->rt_dbmsignal = signal;
	iwl_rt->rt_dbmnoise = noise;

	/* Convert the channel data and set the flags */
	iwl_rt->rt_channel = cpu_to_le16(channel);
	if (!(phy_flags & RX_RES_PHY_FLAGS_BAND_24_MSK)) {
		iwl_rt->rt_chbitmask =
		    cpu_to_le16((IEEE80211_CHAN_OFDM | IEEE80211_CHAN_5GHZ));
	} else if (phy_flags & RX_RES_PHY_FLAGS_MOD_CCK_MSK) {
		iwl_rt->rt_chbitmask =
		    cpu_to_le16((IEEE80211_CHAN_CCK | IEEE80211_CHAN_2GHZ));
	} else {		/* 802.11g */
		iwl_rt->rt_chbitmask =
		    cpu_to_le16((IEEE80211_CHAN_OFDM | IEEE80211_CHAN_2GHZ));
	}

	rate = iwl_rate_index_from_plcp(rate);
	if (rate == -1)
		iwl_rt->rt_rate = 0;
	else
		iwl_rt->rt_rate = iwl_rates[rate].ieee;

	/* antenna number */
	iwl_rt->rt_antenna = (phy_flags & RX_RES_PHY_FLAGS_ANTENNA_MSK) >> 4;

	/* set the preamble flag if we have it */
	if (phy_flags & RX_RES_PHY_FLAGS_SHORT_PREAMBLE_MSK)
		iwl_rt->rt_flags |= IEEE80211_RADIOTAP_F_SHORTPRE;

	IWL_DEBUG_RX("Rx packet of %d bytes.\n", mbuf_len(rxb->skb));

	stats->flag |= RX_FLAG_RADIOTAP;
	//ieee80211_rx_irqsafe(priv->hw, rxb->skb, stats);
	rxb->skb = NULL;
}


#define IWL_PACKET_RETRY_TIME HZ

int is_duplicate_packet(struct iwl_priv *priv, struct ieee80211_hdr *header)
{
	u16 sc = le16_to_cpu(header->seq_ctrl);
	u16 seq = WLAN_GET_SEQ_SEQ(sc);
	u16 frag = WLAN_GET_SEQ_FRAG(sc);
	u16 *last_seq, *last_frag;
	unsigned long *last_time;

	switch (priv->iw_mode) {
	case IEEE80211_IF_TYPE_IBSS:{
		struct list_head *p,*q;
		struct iwl_ibss_seq *entry = NULL;
		u8 *mac = header->addr2;
		int index = mac[5] % IWL_IBSS_MAC_HASH_SIZE;

		list_for_each_safe(p,q,&priv->ibss_mac_hash[index]){
		//__list_for_each(p, &priv->ibss_mac_hash[index]) {
			entry =	list_entry(p, struct iwl_ibss_seq, list);
			if (!compare_ether_addr(entry->mac, mac))
				break;
		}
		if (p == &priv->ibss_mac_hash[index]) {
			entry = (struct iwl_ibss_seq*)IOMalloc(sizeof(*entry));
			memset(entry,0,sizeof(*entry));
			if (!entry) {
				IWL_ERROR
					("Cannot malloc new mac entry\n");
				return 0;
			}
			memcpy(entry->mac, mac, ETH_ALEN);
			entry->seq_num = seq;
			entry->frag_num = frag;
			entry->packet_time = jiffies;
			list_add(&entry->list, &priv->ibss_mac_hash[index]);
			return 0;
		}
		last_seq = &entry->seq_num;
		last_frag = &entry->frag_num;
		last_time = &entry->packet_time;
		break;
	}
	case IEEE80211_IF_TYPE_STA:
		last_seq = &priv->last_seq_num;
		last_frag = &priv->last_frag_num;
		last_time = &priv->last_packet_time;
		break;
	default:
		return 0;
	}
	if ((*last_seq == seq) &&
	    time_after(*last_time + IWL_PACKET_RETRY_TIME, jiffies)) {
		if (*last_frag == frag)
			goto drop;
		if (*last_frag + 1 != frag)
			/* out-of-order fragment */
			goto drop;
	} else
		*last_seq = seq;

	*last_frag = frag;
	*last_time = jiffies;
	return 0;

 drop:
	return 1;
}

#ifdef CONFIG_IWLWIFI_SPECTRUM_MEASUREMENT

#include "iwl-spectrum.h"

#define BEACON_TIME_MASK_LOW	0x00FFFFFF
#define BEACON_TIME_MASK_HIGH	0xFF000000
#define TIME_UNIT		1024

/*
 * extended beacon time format
 * time in usec will be changed into a 32-bit value in 8:24 format
 * the high 1 byte is the beacon counts
 * the lower 3 bytes is the time in usec within one beacon interval
 */

static u32 iwl_usecs_to_beacons(u32 usec, u32 beacon_interval)
{
	u32 quot;
	u32 rem;
	u32 interval = beacon_interval * 1024;

	if (!interval || !usec)
		return 0;

	quot = (usec / interval) % 0x100;
	rem = (usec % interval) % BEACON_TIME_MASK_LOW;

	return (quot << 24) + rem;
}

/* base is usually what we get from ucode with each received frame,
 * the same as HW timer counter counting down
 */

static u32 iwl_add_beacon_time(u32 base, u32 addon, u32 beacon_interval)
{
	u32 base_low = base & BEACON_TIME_MASK_LOW;
	u32 addon_low = addon & BEACON_TIME_MASK_LOW;
	u32 interval = beacon_interval * TIME_UNIT;
	u32 res = (base & BEACON_TIME_MASK_HIGH) +
	    (addon & BEACON_TIME_MASK_HIGH);

	if (base_low > addon_low)
		res += base_low - addon_low;
	else if (base_low < addon_low) {
		res += interval + base_low - addon_low;
		res += (1 << 24);
	} else
		res += (1 << 24);

	return res;
}

static int iwl_get_measurement(struct iwl_priv *priv,
			       struct ieee80211_measurement_params *params,
			       u8 type)
{
	struct iwl_spectrum_cmd spectrum;
	struct iwl_rx_packet *res;
	struct iwl_host_cmd cmd;// = {
	memset(&cmd,0,sizeof(struct iwl_host_cmd));
		cmd.id = REPLY_SPECTRUM_MEASUREMENT_CMD;
		cmd.data = (void *)&spectrum;
		cmd.meta.flags = CMD_WANT_SKB;
	//};
	u32 add_time = params->start_time;
	int rc;

	if (iwl_is_associated(priv))
		add_time =
		    iwl_usecs_to_beacons(params->start_time - priv->last_tsf,
					 priv->rxon_timing.beacon_interval);

	memset(&spectrum, 0, sizeof(spectrum));

	spectrum.channel_count = 1;
	spectrum.flags =
	    RXON_FLG_TSF2HOST_MSK | RXON_FLG_ANT_A_MSK | RXON_FLG_DIS_DIV_MSK;
	spectrum.filter_flags = MEASUREMENT_FILTER_FLAG;
	cmd.len = sizeof(spectrum);
	spectrum.len = cmd.len - sizeof(spectrum.len);

	if (iwl_is_associated(priv))
		spectrum.start_time =
		    iwl_add_beacon_time(priv->last_beacon_time,
					add_time,
					priv->rxon_timing.beacon_interval);
	else
		spectrum.start_time = params->start_time;

	spectrum.channels[0].duration = params->duration * TIME_UNIT;
	spectrum.channels[0].channel = params->channel;
	spectrum.channels[0].type = type;
	if (priv->active_rxon.flags & RXON_FLG_BAND_24G_MSK)
		spectrum.flags |= RXON_FLG_BAND_24G_MSK |
		    RXON_FLG_AUTO_DETECT_MSK | RXON_FLG_TGG_PROTECT_MSK;

	rc = iwl_send_cmd(priv,&cmd);
	if (rc)
		return rc;

	res = (struct iwl_rx_packet *)cmd.meta.u.skb->data;
	if (res->hdr.flags & IWL_CMD_FAILED_MSK) {
		IWL_ERROR("Bad return from REPLY_RX_ON_ASSOC command\n");
		rc = -EIO;
	}

	switch (res->u.spectrum.status) {
	case 0:		
		if (res->u.spectrum.id != 0xff) {
			IWL_DEBUG_INFO
			    ("Replaced existing measurement: %d\n",
			     res->u.spectrum.id);
			priv->measurement_status &= ~MEASUREMENT_READY;
		}
		priv->measurement_status |= MEASUREMENT_ACTIVE;
		rc = 0;
		break;

	case 1:		
		rc = -EAGAIN;
		break;
	}

	if (cmd.meta.u.skb)
	if (!(mbuf_type(cmd.meta.u.skb) == MBUF_TYPE_FREE) ) mbuf_freem(cmd.meta.u.skb);
	cmd.meta.u.skb=NULL;
	//dev_kfree_skb_any(cmd.meta.u.skb);

	return rc;
}
#endif

void ieee80211_tx_status(struct ieee80211_hw *hw, mbuf_t skb,
			 struct ieee80211_tx_status *status)
{
	if (!skb) return;
	mbuf_t skb2;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) mbuf_data(skb);
	struct ieee80211_local *local = hw_to_local(hw);
	u16 frag, type;
	u32 msg_type;
	struct ieee80211_tx_status_rtap_hdr *rthdr;
	struct ieee80211_sub_if_data *sdata;
	int monitors;

	if (!status) {
		printk(
		       "%s: ieee80211_tx_status called with NULL status\n",
		       local->mdev->name);
		//dev_kfree_skb(skb);
		if (skb)
		if (!(mbuf_type(skb) == MBUF_TYPE_FREE) ) mbuf_freem(skb);
		skb=NULL;
		return;
	}

	if (status->excessive_retries) {
		struct sta_info *sta;
		sta = sta_info_get(local, hdr->addr1);
		if (sta) {
			if (sta->flags & WLAN_STA_PS) {

				status->excessive_retries = 0;
				status->flags |= IEEE80211_TX_STATUS_TX_FILTERED;
			}
			sta_info_put(sta);
		}
	}

	if (status->flags & IEEE80211_TX_STATUS_TX_FILTERED) {
		struct sta_info *sta;
		sta = sta_info_get(local, hdr->addr1);
		if (sta) {
			sta->tx_filtered_count++;


			sta->clear_dst_mask = 1;

			if (sta->flags & WLAN_STA_PS
			// &&
			  //  skb_queue_len(&sta->tx_filtered) <
			    //STA_MAX_TX_BUFFER
				) {
				IOLog("todo ieee80211_remove_tx_extra\n");
				//ieee80211_remove_tx_extra(local, sta->key,
				//			  skb,
				//			  &status->control);
				//skb_queue_tail(&sta->tx_filtered, skb);
			} else if (!(sta->flags & WLAN_STA_PS) &&
				   !(status->control.flags & IEEE80211_TXCTL_REQUEUE)) {
				// Software retry the packet once 
				status->control.flags |= IEEE80211_TXCTL_REQUEUE;
				IOLog("todo ieee80211_remove_tx_extra\n");
				//ieee80211_remove_tx_extra(local, sta->key,
				//			  skb,
				//			  &status->control);
				//dev_queue_xmit(skb);
				clone->outputPacket(skb,0);
			} else {
				//if (net_ratelimit()) {
					printk( "%s: dropped TX "
					       "filtered frame queue_len=%d "
					       "PS=%d @%lu\n",
					       local->mdev->name,0,
					    //   skb_queue_len(
						  //     &sta->tx_filtered),
					       !!(sta->flags & WLAN_STA_PS),
					       jiffies);
				//}
				//dev_kfree_skb(skb);
				if (skb)
				if (!(mbuf_type(skb) == MBUF_TYPE_FREE) ) mbuf_freem(skb);
				skb=NULL;
			}
			sta_info_put(sta);
			return;
		}
	} else {
		IOLog("todo rate_control_tx_status\n");
		//rate_control_tx_status(local, local->mdev, skb, status);
	}

	//ieee80211_led_tx(local, 0);
	IOLog("todo ieee80211_led_tx\n");


	frag = le16_to_cpu(hdr->seq_ctrl) & IEEE80211_SCTL_FRAG;
	type = le16_to_cpu(hdr->frame_control) & IEEE80211_FCTL_FTYPE;

	if (status->flags & IEEE80211_TX_STATUS_ACK) {
		if (frag == 0) {
			local->dot11TransmittedFrameCount++;
			if (is_multicast_ether_addr(hdr->addr1))
				local->dot11MulticastTransmittedFrameCount++;
			if (status->retry_count > 0)
				local->dot11RetryCount++;
			if (status->retry_count > 1)
				local->dot11MultipleRetryCount++;
		}

		if (!is_multicast_ether_addr(hdr->addr1) ||
		    type == IEEE80211_FTYPE_DATA ||
		    type == IEEE80211_FTYPE_MGMT)
			local->dot11TransmittedFragmentCount++;
	} else {
		if (frag == 0)
			local->dot11FailedCount++;
	}

	msg_type = (status->flags & IEEE80211_TX_STATUS_ACK) ? 1:2;
	//	ieee80211_msg_tx_callback_ack : ieee80211_msg_tx_callback_fail;

	// this was a transmitted frame, but now we want to reuse it 
	//skb_orphan(skb);

	if ((status->control.flags & IEEE80211_TXCTL_REQ_TX_STATUS) 
	//&&  local->apdev
	) {
		if (local->monitors) {
			//skb2 = skb_clone(skb, GFP_ATOMIC);
			mbuf_dup(skb, MBUF_WAITOK , &skb2);
		} else {
			skb2 = skb;
			skb = NULL;
		}

		if (skb2)
			// Send frame to hostapd 
			IOLog("todo ieee80211_rx_mgmt\n");
			//ieee80211_rx_mgmt(local, skb2, NULL, msg_type);

		if (!skb)
			return;
	}

	if (!local->monitors) {
		//dev_kfree_skb(skb);
		if (skb)
		if (!(mbuf_type(skb) == MBUF_TYPE_FREE) ) mbuf_freem(skb);
		skb=NULL;
		return;
	}

	// send frame to monitor interfaces now 

	if (mbuf_trailingspace(skb) < sizeof(*rthdr)) {
		printk(KERN_ERR "ieee80211_tx_status: headroom too small\n");
		//dev_kfree_skb(skb);
		if (skb)
		if (!(mbuf_type(skb) == MBUF_TYPE_FREE) ) mbuf_freem(skb);
		skb=NULL;
		return;
	}

	rthdr = (struct ieee80211_tx_status_rtap_hdr*)
				skb_push(skb, sizeof(*rthdr));

	memset(rthdr, 0, sizeof(*rthdr));
	rthdr->hdr.it_len = cpu_to_le16(sizeof(*rthdr));
	rthdr->hdr.it_present =
		cpu_to_le32((1 << IEEE80211_RADIOTAP_TX_FLAGS) |
			    (1 << IEEE80211_RADIOTAP_DATA_RETRIES));

	if (!(status->flags & IEEE80211_TX_STATUS_ACK) &&
	    !is_multicast_ether_addr(hdr->addr1))
		rthdr->tx_flags |= cpu_to_le16(IEEE80211_RADIOTAP_F_TX_FAIL);

	if ((status->control.flags & IEEE80211_TXCTL_USE_RTS_CTS) &&
	    (status->control.flags & IEEE80211_TXCTL_USE_CTS_PROTECT))
		rthdr->tx_flags |= cpu_to_le16(IEEE80211_RADIOTAP_F_TX_CTS);
	else if (status->control.flags & IEEE80211_TXCTL_USE_RTS_CTS)
		rthdr->tx_flags |= cpu_to_le16(IEEE80211_RADIOTAP_F_TX_RTS);

	rthdr->data_retries = status->retry_count;

	//read_lock(&local->sub_if_lock);
	monitors = local->monitors;
	list_for_each_entry(sdata, &local->sub_if_list, list) {
		// Using the monitors counter is possibly racy, but
		if (!monitors || !skb)
			goto out;

		if (sdata->type == IEEE80211_IF_TYPE_MNTR) {
			//if (!netif_running(sdata->dev))
			if((clone->fNetif->getFlags() & IFF_RUNNING)!=0)
				continue;
			monitors--;
			if (monitors)
				//skb2 = skb_clone(skb, GFP_KERNEL);
				mbuf_dup(skb, MBUF_WAITOK , &skb2);
			else
				skb2 = NULL;
			//skb->dev = sdata->dev;
			// XXX: is this sufficient for BPF? 
			//skb_set_mac_header(skb, 0);
			//skb->ip_summed = CHECKSUM_UNNECESSARY;
			//skb->pkt_type = PACKET_OTHERHOST;
			//skb->protocol = htons(ETH_P_802_2);
			//memset(skb->cb, 0, sizeof(skb->cb));
			//netif_rx(skb);
			clone->fNetif->inputPacket(skb,mbuf_len(skb));
			skb = skb2;
		}
	}
 out:
	//read_unlock(&local->sub_if_lock);
	if (skb)
	if (!(mbuf_type(skb) == MBUF_TYPE_FREE) ) mbuf_freem(skb);
	skb=NULL;
}


static void iwl_txstatus_to_ieee(struct iwl_priv *priv,
				 struct iwl_tx_info *tx_sta)
{

	tx_sta->status.ack_signal = 0;
	tx_sta->status.excessive_retries = 0;
	tx_sta->status.queue_length = 0;
	tx_sta->status.queue_number = 0;
IOLog("ieee80211_tx_status\n");
//	if (in_interrupt())
//		//ieee80211_tx_status_irqsafe(priv->hw, tx_sta->skb[0], &(tx_sta->status));
//	else
		ieee80211_tx_status(priv->hw, tx_sta->skb[0], &(tx_sta->status));

	tx_sta->skb[0] = NULL;
}

/**
 * iwl_tx_queue_reclaim - Reclaim Tx queue entries no more used by NIC.
 *
 * When FW advances 'R' index, all entries between old and
 * new 'R' index need to be reclaimed. As result, some free space
 * forms. If there is enough free space (> low mark), wake Tx queue.
 */
static int iwl_tx_queue_reclaim(struct iwl_priv *priv, int txq_id, int index)
{
	struct iwl_tx_queue *txq = &priv->txq[txq_id];
	struct iwl_queue *q = &txq->q;
	u8 is_next = 0;
	int used;
	if ((index >= q->n_bd) || (x2_queue_used(q, index) == 0)) {
		IWL_ERROR("Read index for DMA queue (%d) is out of "
			  "range [0-%d) %d %d\n",
			  index, q->n_bd, q->first_empty, q->last_used);
		goto done;
	}
	index = iwl_queue_inc_wrap(index, q->n_bd);
	for (; q->last_used != index;
	     q->last_used = iwl_queue_inc_wrap(q->last_used, q->n_bd)) {
		if (is_next) {
			IWL_ERROR("command skipped\n");
			//queue_work(priv->workqueue, &priv->restart);
			clone->queue_te(1,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_restart),priv,NULL,true);
		}
		if (txq_id != IWL_CMD_QUEUE_NUM) {
			iwl_txstatus_to_ieee(priv,
					     &(txq->txb[txq->q.last_used]));
			iwl_hw_tx_queue_free_tfd(priv, txq);
		} else
			is_next = 1;
	}
 done:
	if (iwl_queue_space(q) > q->low_mark && (txq_id >= 0)
	    && (txq_id != IWL_CMD_QUEUE_NUM)
	    && priv->mac80211_registered)
		{
			IWL_ERROR("todo ieee80211_wake_queue\n");
			//ieee80211_wake_queue(priv->hw, txq_id);
		}
	used = q->first_empty - q->last_used;
	if (used < 0)
		used += q->n_window;
	return used;
}

static int iwl_is_tx_success(u32 status)
{
#if IWL == 3945
	return (status & 0xFF) == 0x1;
#elif IWL == 4965
	status &= TX_STATUS_MSK;
	return (status == TX_STATUS_SUCCESS)
	    || (status == TX_STATUS_DIRECT_DONE);
#endif
}

/******************************************************************************
 *
 * Generic RX handler implementations
 *
 ******************************************************************************/

static void iwl_rx_reply_tx(struct iwl_priv *priv,
			    struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	u16 sequence = pkt->hdr.sequence;
	int txq_id = SEQ_TO_QUEUE(sequence);
	int index = SEQ_TO_INDEX(sequence);
	struct iwl_tx_queue *txq = &priv->txq[txq_id];
	struct ieee80211_tx_status *status;
	struct iwl_tx_resp *resp = (struct iwl_tx_resp *)&pkt->u.raw[0];

	if ((index >= txq->q.n_bd) || (x2_queue_used(&txq->q, index) == 0)) {
		IWL_ERROR("Read index for DMA queue (%d) "
			  "is out of range [0-%d) %d %d\n",
			  index, txq->q.n_bd, txq->q.first_empty,
			  txq->q.last_used);
		return;
	}

	status = &(txq->txb[txq->q.last_used].status);

	status->retry_count = resp->failure_frame;
	status->queue_number = resp->status;
	status->queue_length = resp->bt_kill_count;
	status->queue_length |= resp->failure_rts;

	status->flags =
	    iwl_is_tx_success(resp->status) ? IEEE80211_TX_STATUS_ACK : 0;

#if IWL == 3945

	status->control.tx_rate = iwl_rate_index_from_plcp(resp->rate);

	IWL_DEBUG_TX("Tx queue %d Status %s (0x%08x) plcp rate %d retries %d\n",
		     txq_id, iwl_get_tx_fail_reason(resp->status),
		     resp->status, resp->rate, resp->failure_frame);

#elif IWL == 4965

	status->control.tx_rate = resp->rate.s.rate | (resp->rate.s.flags << 8);

	IWL_DEBUG_TX("Tx queue %d Status %s (0x%08x) plcp rate %d retries %d\n",
		     txq_id, iwl_get_tx_fail_reason(resp->status),
		     resp->status, resp->rate.s.rate, resp->failure_frame);
#endif

	IWL_DEBUG_TX_REPLY("Tx queue reclaim %d\n", index);
	if (index != -1)
		iwl_tx_queue_reclaim(priv, txq_id, index);

	if (iwl_check_bits(resp->status, TX_ABORT_REQUIRED_MSK))
		IWL_ERROR("TODO:  Implement Tx ABORT REQUIRED!!!\n");
}


static void iwl_rx_reply_alive(struct iwl_priv *priv,
			   struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	struct iwl_alive_resp *palive;
	//struct delayed_work *pwork;
	int pwork=-1;
	palive = &pkt->u.alive_frame;

	IWL_DEBUG_INFO("Alive ucode status 0x%08X revision "
		       "0x%01X 0x%01X\n",
		       palive->is_valid, palive->ver_type,
		       palive->ver_subtype);

	if (palive->ver_subtype == INITIALIZE_SUBTYPE) {
		IWL_DEBUG_INFO("Initialization Alive received.\n");
		memcpy(&priv->card_alive_init,&pkt->u.alive_frame,sizeof(struct iwl_init_alive_resp));
		pwork=1;
		//pwork = &priv->init_alive_start;
	} else {
		IWL_DEBUG_INFO("Runtime Alive received.\n");
		memcpy(&priv->card_alive, &pkt->u.alive_frame, sizeof(struct iwl_alive_resp));
		pwork=0;
		//pwork = &priv->alive_start;
#if IWL == 3945
		/* For debugging (selective disable not supported in 4965) */
		iwl_disable_events(priv);
#endif
	}

	/* We delay the ALIVE response by 5ms to
	 * give the HW RF Kill time to activate... */
	if (palive->is_valid == UCODE_VALID_OK && pwork!=-1)
		//queue_delayed_work(priv->workqueue, pwork, msecs_to_jiffies(5));
	{
		if (pwork==1) clone->queue_te(8,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_init_alive_start),priv,5,true);
		if (pwork==0) clone->queue_te(9,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_alive_start),priv,5,true);
	}
	else
		IWL_WARNING("uCode did not respond OK.\n");
}

static void iwl_rx_reply_add_sta(struct iwl_priv *priv,
				 struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	IWL_DEBUG_RX("Received REPLY_ADD_STA: 0x%02X\n", pkt->u.status);
	return;
}

static void iwl_rx_reply_error(struct iwl_priv *priv,
			       struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	u32 err_type = pkt->u.err_resp.error_type;
	u8 cmd_id = pkt->u.err_resp.cmd_id;
	u16 seq = pkt->u.err_resp.bad_cmd_seq_num;
	u32 ser = pkt->u.err_resp.error_info;
	IWL_ERROR("Error Reply type 0x%08X cmd %s (0x%02X) "
		  "seq 0x%04X ser 0x%08X\n",
		  err_type, get_cmd_string(cmd_id), cmd_id, seq, ser);
	return;
}

//#define TX_STATUS_ENTRY(x) case TX_STATUS_FAIL_ ## x: return #x

static void iwl_rx_csa(struct iwl_priv *priv, struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	struct iwl_rxon_cmd *rxon = (struct iwl_rxon_cmd *)&priv->active_rxon;
	struct iwl_csa_notification *csa = &(pkt->u.csa_notif);
	IWL_DEBUG_11H("CSA notif: channel %d, status %d\n",
		      csa->channel, csa->status);
	rxon->channel = priv->staging_rxon.channel = cpu_to_le16(csa->channel);
}

static void iwl_rx_spectrum_measure_notif(struct iwl_priv *priv,
					  struct iwl_rx_mem_buffer *rxb)
{
#ifdef CONFIG_IWLWIFI_SPECTRUM_MEASUREMENT
	struct iwl_rx_packet *pkt = (void *)mbuf_data(rxb->skb);
	struct iwl_spectrum_notification *report = &(pkt->u.spectrum_notif);

	if (!report->state) {
		IWL_DEBUG(IWL_DL_11H | IWL_DL_INFO,
			  "Spectrum Measure Notification: Start\n");
		return;
	}

	memcpy(&priv->measure_report, report, sizeof(*report));
	priv->measurement_status |= MEASUREMENT_READY;
#endif
}

static void iwl_rx_pm_sleep_notif(struct iwl_priv *priv,
				  struct iwl_rx_mem_buffer *rxb)
{
#ifdef CONFIG_IWLWIFI_DEBUG
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	struct iwl_sleep_notification *sleep = &(pkt->u.sleep_notif);
	IWL_DEBUG_RX("sleep mode: %d, src: %d\n",
		     sleep->pm_sleep_mode, sleep->pm_wakeup_src);
#endif
}

static void iwl_rx_pm_debug_statistics_notif(struct iwl_priv *priv,
					     struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	IWL_DEBUG_RADIO("Dumping %d bytes of unhandled "
			"notification for %s:\n",
			le32_to_cpu(pkt->len), get_cmd_string(pkt->hdr.cmd));
	//printk_buf(IWL_DL_RADIO, pkt->u.raw, le32_to_cpu(pkt->len));
}

static void iwl_rx_beacon_notif(struct iwl_priv *priv,
				struct iwl_rx_mem_buffer *rxb)
{
#ifdef CONFIG_IWLWIFI_DEBUG
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	struct iwl_beacon_notif *beacon = &(pkt->u.beacon_status);
#if IWL == 3945
	u8 rate = beacon->beacon_notify_hdr.rate;
#elif IWL == 4965
	u8 rate = beacon->beacon_notify_hdr.rate.s.rate;
#endif
	IWL_DEBUG_RX("beacon status %x retries %d iss %d "
		     "tsf %d %d rate %d\n",
		     beacon->beacon_notify_hdr.status & TX_STATUS_MSK,
		     beacon->beacon_notify_hdr.failure_frame,
		     beacon->ibss_mgr_status,
		     beacon->high_tsf, beacon->low_tsf, rate);
#endif
}

static void iwl_rx_reply_scan(struct iwl_priv *priv,
			      struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	struct iwl_scanreq_notification *notif =
	    (struct iwl_scanreq_notification *)pkt->u.raw;
	IWL_DEBUG_RX("Scan request status = 0x%x\n", notif->status);
}

static void iwl_rx_scan_start_notif(struct iwl_priv *priv,
				    struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	struct iwl_scanstart_notification *notif =
	    (struct iwl_scanstart_notification *)pkt->u.raw;
	priv->scan_start_tsf = notif->tsf_low;
	IWL_DEBUG_SCAN("Scan start: "
		       "%d [802.11%s] "
		       "(TSF: 0x%08X:%08X) - %d (beacon timer %u)\n",
		       notif->channel,
		       notif->band ? "bg" : "a",
		       notif->tsf_high,
		       notif->tsf_low, notif->status, notif->beacon_timer);
}

static void iwl_rx_scan_results_notif(struct iwl_priv *priv,
				      struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	struct iwl_scanresults_notification *notif =
	    (struct iwl_scanresults_notification *)pkt->u.raw;

	IWL_DEBUG_SCAN("Scan ch.res: "
		       "%d [802.11%s] "
		       "(TSF: 0x%08X:%08X) - %d "
		       "elapsed=%lu usec (%dms since last)\n",
		       notif->channel,
		       notif->band ? "bg" : "a",
		       notif->tsf_high,
		       notif->tsf_low,
		       notif->statistics[0],
		       notif->tsf_low - priv->scan_start_tsf,
		       jiffies_to_msecs(elapsed_jiffies
					(priv->last_scan_jiffies, jiffies)));

	priv->last_scan_jiffies = jiffies;
}

static void iwl_rx_scan_complete_notif(struct iwl_priv *priv,
				       struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	struct iwl_scancomplete_notification *scan_notif =
	    (struct iwl_scancomplete_notification *)pkt->u.raw;
	IWL_DEBUG_SCAN("Scan complete: %d channels (TSF 0x%08X:%08X) - %d\n",
		       scan_notif->scanned_channels,
		       scan_notif->tsf_low,
		       scan_notif->tsf_high, scan_notif->status);

	/* The HW is no longer scanning */
	priv->status &= ~STATUS_SCAN_HW;

	/* The scan completion notification came in, so kill that timer... */
	//cancel_delayed_work(&priv->scan_check);
	clone->queue_td(10,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_scan_check));


	IWL_DEBUG_INFO("Scan pass on %sGHz took %dms\n",
		       (priv->scan_bands == 2) ? "2.4" : "5.2",
		       jiffies_to_msecs(elapsed_jiffies
					(priv->scan_pass_start, jiffies)));

	/* Remove this scanned band from the list
	 * of pending bands to scan */
	priv->scan_bands--;

	/* If a request to abort was given, or the scan did not succeed
	 * then we reset the scan state machine and terminate,
	 * re-queuing another scan if one has been requested */
	if (priv->status & STATUS_SCAN_ABORTING) {
		IWL_DEBUG_INFO("Aborted scan completed.\n");
		priv->status &= ~STATUS_SCAN_ABORTING;
	} else {
		/* If there are more bands on this scan pass reschedule */
		if (priv->scan_bands > 0)
			goto reschedule;
	}

	priv->last_scan_jiffies = jiffies;
	IWL_DEBUG_INFO("Setting scan to off\n");

	priv->status &= ~STATUS_SCANNING;

	IWL_DEBUG_INFO("Scan took %dms\n",
		       jiffies_to_msecs(elapsed_jiffies
					(priv->scan_start, jiffies)));

	//queue_work(priv->workqueue, &priv->scan_completed);
	clone->queue_te(3,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_scan_completed),priv,NULL,true);
	
	return;

 reschedule:
	priv->scan_pass_start = jiffies;
	//queue_work(priv->workqueue, &priv->request_scan);
	clone->queue_te(4,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_request_scan),priv,NULL,true);
}

/* Handle notification from uCode that card's power state is changing
 * due to software, hardware, or critical temperature RFKILL */
static void iwl_rx_card_state_notif(struct iwl_priv *priv,
				    struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	u32 flags = le32_to_cpu(pkt->u.card_state_notif.flags);
	u32 status = priv->status;
	IWL_DEBUG_RF_KILL("Card state received: HW:%s SW:%s\n",
			  (flags & HW_CARD_DISABLED) ? "Kill" : "On",
			  (flags & SW_CARD_DISABLED) ? "Kill" : "On");
#if IWL == 4965
	if (flags & (SW_CARD_DISABLED | HW_CARD_DISABLED |
		     RF_CARD_DISABLED)) {

		iwl_write32(priv, CSR_UCODE_DRV_GP1_SET,
			    CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);

		if (!iwl_grab_restricted_access(priv)) {
			iwl_write_restricted(
				priv, HBUS_TARG_MBX_C,
				HBUS_TARG_MBX_C_REG_BIT_CMD_BLOCKED);

			iwl_release_restricted_access(priv);
		}

		if (!(flags & RXON_CARD_DISABLED)) {
			iwl_write32(priv, CSR_UCODE_DRV_GP1_CLR,
				    CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);
			if (!iwl_grab_restricted_access(priv)) {
				iwl_write_restricted(
					priv, HBUS_TARG_MBX_C,
					HBUS_TARG_MBX_C_REG_BIT_CMD_BLOCKED);

				iwl_release_restricted_access(priv);
			}
		}

		if (flags & RF_CARD_DISABLED) {
			iwl_write32(priv, CSR_UCODE_DRV_GP1_SET,
				    CSR_UCODE_DRV_GP1_REG_BIT_CT_KILL_EXIT);
			iwl_read32(priv, CSR_UCODE_DRV_GP1);
			if (!iwl_grab_restricted_access(priv))
				iwl_release_restricted_access(priv);
		}
	}
#else
	iwl_write32(priv, CSR_UCODE_DRV_GP1_SET,
		    CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);
#endif
	if (flags & HW_CARD_DISABLED)
	{
		priv->status |= STATUS_RF_KILL_HW;
			IWL_WARNING("STATUS_RF_KILL_HW enabled\n");
	}
	else
		priv->status &= ~STATUS_RF_KILL_HW;


	if (flags & SW_CARD_DISABLED)
	{
		priv->status |= STATUS_RF_KILL_SW;
		IWL_WARNING("STATUS_RF_KILL_SW enabled\n");
	}
	else
		priv->status &= ~STATUS_RF_KILL_SW;

#if IWL == 4965
	if (!(flags & RXON_CARD_DISABLED))
		iwl_scan_cancel(priv, 0);
#else
		iwl_scan_cancel(priv, 0);
#endif

	if (((status & STATUS_RF_KILL_HW) != (priv->status & STATUS_RF_KILL_HW))
	    || ((status & STATUS_RF_KILL_SW) !=
		(priv->status & STATUS_RF_KILL_SW)))
		//queue_work(priv->workqueue, &priv->rf_kill);
		clone->queue_te(6,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_rf_kill),priv,NULL,true);
	else
		wake_up_interruptible(&priv->wait_command_queue);
}

/**
 * iwl_setup_rx_handlers - Initialize Rx handler callbacks
 *
 * Setup the RX handlers for each of the reply types sent from the uCode
 * to the host.
 *
 * This function chains into the hardware specific files for them to setup
 * any hardware specific handlers as well.
 */
static void iwl_setup_rx_handlers(struct iwl_priv *priv)
{
	priv->rx_handlers[REPLY_ALIVE] = iwl_rx_reply_alive;
	priv->rx_handlers[REPLY_ADD_STA] = iwl_rx_reply_add_sta;
	priv->rx_handlers[REPLY_ERROR] = iwl_rx_reply_error;
	priv->rx_handlers[CHANNEL_SWITCH_NOTIFICATION] = iwl_rx_csa;
	priv->rx_handlers[SPECTRUM_MEASURE_NOTIFICATION] = iwl_rx_spectrum_measure_notif;
	priv->rx_handlers[PM_SLEEP_NOTIFICATION] = iwl_rx_pm_sleep_notif;
	priv->rx_handlers[PM_DEBUG_STATISTIC_NOTIFIC] = iwl_rx_pm_debug_statistics_notif;
	priv->rx_handlers[BEACON_NOTIFICATION] = iwl_rx_beacon_notif;

	/* NOTE:  iwl_rx_statistics is different based on whether
	 * the build is for the 3945 or the 4965.  See the
	 * corresponding implementation in iwl-XXXX.c
	 *
	 * The same handler is used for both the REPLY to a
	 * discrete statistics request from the host as well as
	 * for the periodic statistics notification from the uCode
	 */
	priv->rx_handlers[REPLY_STATISTICS_CMD] = iwl_hw_rx_statistics;
	priv->rx_handlers[STATISTICS_NOTIFICATION] = iwl_hw_rx_statistics;
	priv->rx_handlers[REPLY_SCAN_CMD] = iwl_rx_reply_scan;
	priv->rx_handlers[SCAN_START_NOTIFICATION] = iwl_rx_scan_start_notif;
	priv->rx_handlers[SCAN_RESULTS_NOTIFICATION] = iwl_rx_scan_results_notif;
	priv->rx_handlers[SCAN_COMPLETE_NOTIFICATION] = iwl_rx_scan_complete_notif;
	priv->rx_handlers[CARD_STATE_NOTIFICATION] = iwl_rx_card_state_notif;
	priv->rx_handlers[REPLY_TX] = iwl_rx_reply_tx;

	/* Setup hardware specific Rx handlers */
	iwl_hw_rx_handler_setup(priv);
}

/**
 * iwl_tx_cmd_complete - Pull unused buffers off the queue and reclaim them
 * @rxb: Rx buffer to reclaim
 *
 * If an Rx buffer has an async callback associated with it the callback
 * will be executed.  The attached skb (if present) will only be freed
 * if the callback returns 1
 */
static void iwl_tx_cmd_complete(struct iwl_priv *priv,
				struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);
	int txq_id = SEQ_TO_QUEUE(pkt->hdr.sequence);
	int index = SEQ_TO_INDEX(pkt->hdr.sequence);
	int is_huge = (pkt->hdr.sequence & SEQ_HUGE_FRAME);
	int cmd_index;
	struct iwl_cmd *cmd;

	/* If a Tx command is being handled and it isn't in the actual
	 * command queue then there a command routing bug has been introduced
	 * in the queue management code. */
	//WARN_ON(txq_id != IWL_CMD_QUEUE_NUM);
	if (txq_id != IWL_CMD_QUEUE_NUM) {
		//IWL_ERROR("Kernel BUG! Please report below info:\n");
		IWL_ERROR("Error wrong command queue %d command id 0x%X\n",
			  txq_id, pkt->hdr.cmd);
		//dump_stack();
	}

	cmd_index = get_next_cmd_index(&priv->txq[IWL_CMD_QUEUE_NUM].q, index,
				       is_huge);
	cmd = &priv->txq[IWL_CMD_QUEUE_NUM].cmd[cmd_index];

	/* Input error checking is done when commands are added to queue. */
	if (cmd->meta.flags & CMD_WANT_SKB) {
		/* FIXME: we use cmd->meta.magic to indicate the
		 * memory cmd->meta.source points to is still valid or
		 * not at this point since caller may pass a local
		 * variable to us and returned before we get here.
		 * In this case, caller must ensure the ->magic field
		 * is set correctly to indicate the availability of the
		 * pointer cmd->meta.source. */
		if (cmd->meta.source->magic == CMD_VAR_MAGIC) {
			cmd->meta.source->u.skb = rxb->skb;
			cmd->meta.source->magic = 0;
			rxb->skb = NULL;
		}
	} else if (cmd->meta.u.callback &&
		   !cmd->meta.u.callback(priv, cmd, rxb->skb))
		rxb->skb = NULL;

	iwl_tx_queue_reclaim(priv, txq_id, index);

	if (!(cmd->meta.flags & CMD_ASYNC)) {
		priv->status &= ~STATUS_HCMD_ACTIVE;
		wake_up_interruptible(&priv->wait_command_queue);
	}
}

/************************** RX-FUNCTIONS ****************************/
/*
 * Rx theory of operation
 *
 * The host allocates 32 DMA target addresses and passes the host address
 * to the firmware at register IWL_RFDS_TABLE_LOWER + N * RFD_SIZE where N is
 * 0 to 31
 *
 * Rx Queue Indexes
 * The host/firmware share two index registers for managing the Rx buffers.
 *
 * The READ index maps to the first position that the firmware may be writing
 * to -- the driver can read up to (but not including) this position and get
 * good data.
 * The READ index is managed by the firmware once the card is enabled.
 *
 * The WRITE index maps to the last position the driver has read from -- the
 * position preceding WRITE is the last slot the firmware can place a packet.
 *
 * The queue is empty (no good data) if WRITE = READ - 1, and is full if
 * WRITE = READ.
 *
 * During initialization the host sets up the READ queue position to the first
 * INDEX position, and WRITE to the last (READ - 1 wrapped)
 *
 * When the firmware places a packet in a buffer it will advance the READ index
 * and fire the RX interrupt.  The driver can then query the READ index and
 * process as many packets as possible, moving the WRITE index forward as it
 * resets the Rx queue buffers with new memory.
 *
 * The management in the driver is as follows:
 * + A list of pre-allocated SKBs is stored in ipw->rxq->rx_free.  When
 *   ipw->rxq->free_count drops to or below RX_LOW_WATERMARK, work is scheduled
 *   to replensish the ipw->rxq->rx_free.
 * + In iwl_rx_replenish (scheduled) if 'processed' != 'read' then the
 *   ipw->rxq is replenished and the READ INDEX is updated (updating the
 *   'processed' and 'read' driver indexes as well)
 * + A received packet is processed and handed to the kernel network stack,
 *   detached from the ipw->rxq.  The driver 'processed' index is updated.
 * + The Host/Firmware ipw->rxq is replenished at tasklet time from the rx_free
 *   list. If there are no allocated buffers in ipw->rxq->rx_free, the READ
 *   INDEX is not incremented and ipw->status(RX_STALLED) is set.  If there
 *   were enough free buffers and RX_STALLED is set it is cleared.
 *
 *
 * Driver sequence:
 *
 * iwl_rx_queue_alloc()       Allocates rx_free
 * iwl_rx_replenish()         Replenishes rx_free list from rx_used, and calls
 *                            iwl_rx_queue_restock
 * iwl_rx_queue_restock()     Moves available buffers from rx_free into Rx
 *                            queue, updates firmware pointers, and updates
 *                            the WRITE index.  If insufficient rx_free buffers
 *                            are available, schedules iwl_rx_replenish
 *
 * -- enable interrupts --
 * ISR - iwl_rx()             Detach iwl_rx_mem_buffers from pool up to the
 *                            READ INDEX, detaching the SKB from the pool.
 *                            Moves the packet buffer from queue to rx_used.
 *                            Calls iwl_rx_queue_restock to refill any empty
 *                            slots.
 * ...
 *
 */

/**
 * iwl_rx_queue_space - Return number of free slots available in queue.
 */
static int iwl_rx_queue_space(const struct iwl_rx_queue *q)
{
	int s = q->read - q->write;
	if (s <= 0)
		s += RX_QUEUE_SIZE;
	/* keep some buffer to not confuse full and empty queue */
	s -= 2;
	if (s < 0)
		s = 0;
	return s;
}

/**
 * iwl_rx_queue_update_write_ptr - Update the write pointer for the RX queue
 *
 * NOTE: This function has 3945 and 4965 specific code sections
 * but is declared in base due to the majority of the
 * implementation being the same (only a numeric constant is
 * different)
 *
 */
int iwl_rx_queue_update_write_ptr(struct iwl_priv *priv, struct iwl_rx_queue *q)
{
	u32 reg = 0;
	int rc = 0;
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);

	if (q->need_update == 0)
		goto exit_unlock;

	if (priv->status & STATUS_POWER_PMI) {
		reg = iwl_read32(priv, CSR_UCODE_DRV_GP1);

		if (reg & CSR_UCODE_DRV_GP1_BIT_MAC_SLEEP) {
			iwl_set_bit(priv, CSR_GP_CNTRL,
				    CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
			goto exit_unlock;
		}

		rc = iwl_grab_restricted_access(priv);
		if (rc)
			goto exit_unlock;

		iwl_write_restricted(priv,
				     FH_RSCSR_CHNL0_WPTR, q->write & ~0x7);
		iwl_release_restricted_access(priv);
	} else {
		iwl_write32(priv, FH_RSCSR_CHNL0_WPTR, q->write & ~0x7);
	}

	q->need_update = 0;

 exit_unlock:
	spin_unlock_irqrestore(&q->lock, flags);
	return rc;
}

/**
 * iwl_rx_queue_restock - refill RX queue from pre-allocated pool
 *
 * If there are slots in the RX queue that  need to be restocked,
 * and we have free pre-allocated buffers, fill the ranks as much
 * as we can pulling from rx_free.
 *
 * This moves the 'write' index forward to catch up with 'processed', and
 * also updates the memory address in the firmware to reference the new
 * target buffer.
 */
int iwl_rx_queue_restock(struct iwl_priv *priv)
{
	struct iwl_rx_queue *rxq = &priv->rxq;
	struct list_head *element;
	struct iwl_rx_mem_buffer *rxb;
	unsigned long flags;
	int counter = 0, write, rc;

	spin_lock_irqsave(&rxq->lock, flags);
	write = rxq->write & ~0x7;
	while ((iwl_rx_queue_space(rxq) > 0) && (rxq->free_count)) {
	
		element = rxq->rx_free.next;
		rxb = list_entry(element, struct iwl_rx_mem_buffer, list);
		list_del(element);
		rxq->bd[rxq->write] =iwl_dma_addr2rbd_ptr(priv, rxb->dma_addr);
		rxq->queue[rxq->write] = rxb;
		rxq->write = (rxq->write + 1) % RX_QUEUE_SIZE;
		rxq->free_count--;
		counter++;
	}
	spin_unlock_irqrestore(&rxq->lock, flags);
	/* If the pre-allocated buffer pool is dropping low, schedule to
	 * refill it */

	if (rxq->free_count <= RX_LOW_WATERMARK)
		//queue_work(priv->workqueue, &priv->rx_replenish);
		clone->queue_te(2,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_rx_replenish),priv,NULL,true);

	counter = iwl_rx_queue_space(rxq);
	/* If we've added more space for the firmware to place data, tell it */
	if ((write != (rxq->write & ~0x7) || (rxq->write < write))
	    || ((rxq->write - rxq->read) > 7)
		|| ((-rxq->write + rxq->read) > 7)
		) {
		spin_lock_irqsave(&rxq->lock, flags);
		rxq->need_update = 1;
		spin_unlock_irqrestore(&rxq->lock, flags);
		rc = iwl_rx_queue_update_write_ptr(priv, rxq);
		if (rc)
			return rc;
	}

	return 0;
}

/**
 * iwl_rx_replensih - Move all used packet from rx_used to rx_free
 *
 * When moving to rx_free an SKB is allocated for the slot.
 *
 * Also restock the Rx queue via iwl_rx_queue_restock.
 * This is called as a scheduled work item (except for during intialization)
 */
void iwl_rx_replenish(void *data, u8 do_lock)
{
	struct iwl_priv *priv = (struct iwl_priv*)data;
	struct iwl_rx_queue *rxq = &priv->rxq;
	struct list_head *element;
	struct iwl_rx_mem_buffer *rxb;
	unsigned long flags = 0;

	spin_lock_irqsave(&rxq->lock, flags);
	while (!list_empty(&rxq->rx_used)) {
		if(!rxq->rx_used.next)
			break;
		element = rxq->rx_used.next;
		rxb = list_entry(element, struct iwl_rx_mem_buffer, list);
		//rxb->skb = alloc_skb(IWL_RX_BUF_SIZE, __GFP_NOWARN | GFP_ATOMIC);
		rxb->skb = clone->allocatePacket(IWL_RX_BUF_SIZE);
		
		if (!rxb->skb) {
		//	if (net_ratelimit())
				printk(KERN_CRIT DRV_NAME
				       ": Can not allocate SKB buffers\n");
			/* We don't reschedule replenish work here -- we will
			 * call the restock method and if it still needs
			 * more buffers it will schedule replenish */
			break;
		}
		priv->alloc_rxb_skb++;
		list_del(element);
		mbuf_setlen(rxb->skb,0);
		mbuf_pkthdr_setlen(rxb->skb,0);
		rxb->dma_addr =mbuf_data_to_physical(mbuf_data(rxb->skb));
	//	    pci_map_single(priv->pci_dev, mbuf_data(rxb->skb),
	//			   IWL_RX_BUF_SIZE, PCI_DMA_FROMDEVICE);
		
		list_add_tail(&rxb->list, &rxq->rx_free);
		rxq->free_count++;
	}
	spin_unlock_irqrestore(&rxq->lock, flags);

	if (do_lock)
		spin_lock_irqsave(&priv->lock, flags);
	iwl_rx_queue_restock(priv);
	if (do_lock)
		spin_unlock_irqrestore(&priv->lock, flags);
}

/* Assumes that the skb field of the buffers in 'pool' is kept accurate.
 * If an SKB has been detached, the POOL needs to have it's SKB set to NULL
 * This free routine walks the list of POOL entries and if SKB is set to
 * non NULL it is unmapped and freed
 */
void iwl_rx_queue_free(struct iwl_priv *priv, struct iwl_rx_queue *rxq)
{
	int i;
	for (i = 0; i < RX_QUEUE_SIZE + RX_FREE_BUFFERS; i++) {
		if (rxq->pool[i].skb != NULL) {
			pci_unmap_single(priv->pci_dev,
					 rxq->pool[i].dma_addr,
					 IWL_RX_BUF_SIZE, PCI_DMA_FROMDEVICE);
			if (!(mbuf_type(rxq->pool[i].skb) == MBUF_TYPE_FREE)) 		 
			mbuf_freem(rxq->pool[i].skb);
			rxq->pool[i].skb=NULL;
			rxq->pool[i].dma_addr=NULL;
		}
	}

	pci_free_consistent(priv->pci_dev, 4 * RX_QUEUE_SIZE, rxq->bd,
			    rxq->dma_addr);
	IOFreeContiguous(rxq->bd, 4 * RX_QUEUE_SIZE);
	rxq->dma_addr=NULL;
	//rxq->bd = NULL;
}

int iwl_rx_queue_alloc(struct iwl_priv *priv)
{
	struct iwl_rx_queue *rxq = &priv->rxq;
	//struct pci_dev *dev = priv->pci_dev;
	int i;

	spin_lock_init(&rxq->lock);
	INIT_LIST_HEAD(&rxq->rx_free);
	INIT_LIST_HEAD(&rxq->rx_used);
	//rxq->bd = pci_alloc_consistent(dev, 4 * RX_QUEUE_SIZE, &rxq->dma_addr);
	//MemoryDmaAlloc(4 * RX_QUEUE_SIZE, &rxq->dma_addr, &rxq->bd);
	rxq->bd=(__le32*)IOMallocContiguous(4 * RX_QUEUE_SIZE, sizeof(__le32*), &rxq->dma_addr);
	if (!rxq->bd)
		return -ENOMEM;
	/* Fill the rx_used queue with _all_ of the Rx buffers */
	for (i = 0; i < RX_FREE_BUFFERS + RX_QUEUE_SIZE; i++)
		list_add_tail(&rxq->pool[i].list, &rxq->rx_used);
	/* Set us so that we have processed and used all buffers, but have
	 * not restocked the Rx queue with fresh buffers */
	rxq->read = rxq->write = 0;
	rxq->free_count = 0;
	rxq->need_update = 0;
	return 0;
}

void iwl_rx_queue_reset(struct iwl_priv *priv, struct iwl_rx_queue *rxq)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&rxq->lock, flags);
	INIT_LIST_HEAD(&rxq->rx_free);
	INIT_LIST_HEAD(&rxq->rx_used);
	/* Fill the rx_used queue with _all_ of the Rx buffers */
	for (i = 0; i < RX_FREE_BUFFERS + RX_QUEUE_SIZE; i++) {
		/* In the reset function, these buffers may have been allocated
		 * to an SKB, so we need to unmap and free potential storage */
		if (rxq->pool[i].skb != NULL) {
			pci_unmap_single(priv->pci_dev,
					 rxq->pool[i].dma_addr,
					 IWL_RX_BUF_SIZE, PCI_DMA_FROMDEVICE);
			priv->alloc_rxb_skb--;
			if (!(mbuf_type(rxq->pool[i].skb) == MBUF_TYPE_FREE)) 
			mbuf_freem(rxq->pool[i].skb);
			rxq->pool[i].skb = NULL;
			rxq->pool[i].dma_addr=NULL;
		}
		list_add_tail(&rxq->pool[i].list, &rxq->rx_used);
	}

	/* Set us so that we have processed and used all buffers, but have
	 * not restocked the Rx queue with fresh buffers */
	rxq->read = rxq->write = 0;
	rxq->free_count = 0;
	spin_unlock_irqrestore(&rxq->lock, flags);
}

/* Convert linear signal-to-noise ratio into dB */
u8 ratio2dB[100] = {
/*	 0   1   2   3   4   5   6   7   8   9 */
	 0,  0,  6, 10, 12, 14, 16, 17, 18, 19, /* 00 - 09 */
	20, 21, 22, 22, 23, 23, 24, 25, 26, 26, /* 10 - 19 */
	26, 26, 26, 27, 27, 28, 28, 28, 29, 29, /* 20 - 29 */
	29, 30, 30, 30, 31, 31, 31, 31, 32, 32, /* 30 - 39 */
	32, 32, 32, 33, 33, 33, 33, 33, 34, 34, /* 40 - 49 */
	34, 34, 34, 34, 35, 35, 35, 35, 35, 35, /* 50 - 59 */
	36, 36, 36, 36, 36, 36, 36, 37, 37, 37, /* 60 - 69 */
	37, 37, 37, 37, 37, 38, 38, 38, 38, 38, /* 70 - 79 */
	38, 38, 38, 38, 38, 39, 39, 39, 39, 39, /* 80 - 89 */
	39, 39, 39, 39, 39, 40, 40, 40, 40, 40  /* 90 - 99 */
};

/* Calculates a relative dB value from a ratio of linear
 *   (i.e. not dB) signal levels.
 * Conversion assumes that levels are voltages (20*log), not powers (10*log). */
int iwl_calc_db_from_ratio(int sig_ratio)
{
	/* Anything above 1000:1 just report as 60 dB */
	if (sig_ratio > 1000)
		return 60;

	/* Above 100:1, divide by 10 and use table,
	 *   add 20 dB to make up for divide by 10 */
	if (sig_ratio > 100)
		return (20 + (int)ratio2dB[sig_ratio/10]);

	/* We shouldn't see this */
	if (sig_ratio < 1)
		return 0;

	/* Use table for ratios 1:1 - 99:1 */
	return (int)ratio2dB[sig_ratio];
}

#define PERFECT_RSSI (-20) /* dBm */
#define WORST_RSSI (-95)   /* dBm */
#define RSSI_RANGE (PERFECT_RSSI - WORST_RSSI)

/* Calculate an indication of rx signal quality (a percentage, not dBm!).
 * See http://www.ces.clemson.edu/linux/signal_quality.shtml for info
 *   about formulas used below. */
int iwl_calc_sig_qual(int rssi_dbm, int noise_dbm)
{
	int sig_qual;
	int degradation = PERFECT_RSSI - rssi_dbm;

	/* If we get a noise measurement, use signal-to-noise ratio (SNR)
	 * as indicator; formula is (signal dbm - noise dbm).
	 * SNR at or above 40 is a great signal (100%).
	 * Below that, scale to fit SNR of 0 - 40 dB within 0 - 100% indicator.
	 * Weakest usable signal is usually 10 - 15 dB SNR. */
	if (noise_dbm) {
		if (rssi_dbm - noise_dbm >= 40)
			return 100;
		else if (rssi_dbm < noise_dbm)
			return 0;
		sig_qual = ((rssi_dbm - noise_dbm) * 5) / 2;

	/* Else use just the signal level.
	 * This formula is a least squares fit of data points collected and
	 *   compared with a reference system that had a percentage (%) display
	 *   for signal quality. */
	} else {
		sig_qual =
			(100 * (RSSI_RANGE * RSSI_RANGE) -
			degradation * (15 * RSSI_RANGE + 62 * degradation)) /
			(RSSI_RANGE * RSSI_RANGE);
	}
	if (sig_qual > 100)
		sig_qual = 100;
	else if (sig_qual < 1)
		sig_qual = 0;
	return sig_qual;
}

/**
 * iwl_rx_handle - Main entry function for receiving responses from the uCode
 *
 * Uses the priv->rx_handlers callback function array to invoke
 * the appropriate handlers including command response and 802.11
 * frame availability.
 */
static void iwl_rx_handle(struct iwl_priv *priv)
{
	struct iwl_rx_mem_buffer *rxb;
	struct iwl_rx_packet *pkt;
	struct iwl_rx_queue *rxq = &priv->rxq;
	u32 r, i;
	int reclaim;
	unsigned long flags;

	r = iwl_hw_get_rx_read(priv);
	i = rxq->read;

	while (i != r) {
		rxb = rxq->queue[i];

		/* If an RXB doesn't have a queue slot associated with it
		 * then a bug has been introduced in the queue refilling
		 * routines -- catch it here */

		rxq->queue[i] = NULL;

		if (rxb == NULL) {
			IWL_ERROR( "Queue not allocated!\n");
			break;
		}
		
		if (rxb->skb == NULL) {
			IWL_ERROR( "mbuf Queue not allocated!\n");
			break;
		}
		if (mbuf_data(rxb->skb)==NULL){
			IWL_ERROR( "null mbuf Queue not allocated!\n");
			break;
		}

		if( mbuf_next(rxb->skb)) 
		{
			IWL_ERROR("rx mbuf_next\n");
			break;
		}
		
		if((mbuf_flags(rxb->skb) & MBUF_PKTHDR)==0)
		{
			IWL_ERROR("pkt without header\n");
			break;
		}
		
		pci_dma_sync_single_for_cpu(priv->pci_dev, rxb->dma_addr,
					    IWL_RX_BUF_SIZE,
					    PCI_DMA_FROMDEVICE);
		//mbuf_setlen(rxb->skb, IWL_RX_BUF_SIZE);
		//mbuf_pkthdr_setlen(rxb->skb, IWL_RX_BUF_SIZE);
		pkt = (struct iwl_rx_packet *)mbuf_data(rxb->skb);

		/* need to reclaim cmd buffer(s) */
		reclaim = !(pkt->hdr.sequence & SEQ_RX_FRAME) &&
#if IWL == 4965
			(pkt->hdr.cmd != REPLY_RX_PHY_CMD) &&
#endif
			(pkt->hdr.cmd != STATISTICS_NOTIFICATION) &&
			(pkt->hdr.cmd != REPLY_TX);

		/* Based on type of command response or notification,
		 *   handle those that need handling via function in
		 *   rx_handlers table.  See iwl_setup_rx_handlers() */
		if (priv->rx_handlers[pkt->hdr.cmd]) {
			priv->rx_handlers[pkt->hdr.cmd] (priv, rxb);
			IWL_DEBUG(IWL_DL_RX | IWL_DL_ISR,
				"r = %d, i = %d, rx_handler %s\n", r, i,
				get_cmd_string(pkt->hdr.cmd));
		} else {
			/* No handling needed */
			//if (!strcmp( get_cmd_string(pkt->hdr.cmd),"UNKNOWN")) 
			reclaim=0;
			IWL_DEBUG_HC("UNHANDLED - #0x%02x %s reclaim? %d\n",
				     pkt->hdr.cmd,
				     get_cmd_string(pkt->hdr.cmd),reclaim);
		}

		if (reclaim) {
			/* Invoke any callbacks, transfer the skb to
			 * caller, and fire off the (possibly) blocking
			 * iwl_send_cmd() via as we reclaim the queue... */
			if (rxb && rxb->skb)
				iwl_tx_cmd_complete(priv, rxb);
			else
				IWL_WARNING("Claim null rxb?\n");
		}

		/* For now we just don't re-use anything.  We can tweak this
		 * later to try and re-use notification packets and SKBs that
		 * fail to Rx correctly */
		if (rxb->skb != NULL) {
			priv->alloc_rxb_skb--;
			if (!(mbuf_type(rxb->skb) == MBUF_TYPE_FREE)) 
			mbuf_freem(rxb->skb);
			rxb->skb = NULL;
		}
		rxb->dma_addr=NULL;
		pci_unmap_single(priv->pci_dev, rxb->dma_addr,
				 IWL_RX_BUF_SIZE, PCI_DMA_FROMDEVICE);
		spin_lock_irqsave(&rxq->lock, flags);
		list_add_tail(&rxb->list, &priv->rxq.rx_used);
		spin_unlock_irqrestore(&rxq->lock, flags);
		i = (i + 1) % RX_QUEUE_SIZE;
	}

	/* Backtrack one entry */
	priv->rxq.read = i;

	/* is a lot of queue space refill up right away
	 * so ucode wont assert */
	if (iwl_rx_queue_space(rxq) > RX_SPACE_HIGH_MARK)
		iwl_rx_replenish(priv, 0);
	else
		iwl_rx_queue_restock(priv);
}

int iwl_tx_queue_update_write_ptr(struct iwl_priv *priv,
				  struct iwl_tx_queue *txq)
{
	u32 reg = 0;
	int rc = 0;
	int txq_id = txq->q.id;

	if (txq->need_update == 0)
		return 0;

	/* if we're trying to save power */
	if (priv->status & STATUS_POWER_PMI) {
		/* wake up nic if it's powered down ...
		 * uCode will wake up, and interrupt us again, so next
		 * time we'll skip this part. */
		reg = iwl_read32(priv, CSR_UCODE_DRV_GP1);

		if (reg & CSR_UCODE_DRV_GP1_BIT_MAC_SLEEP) {
			IWL_DEBUG_INFO("Requesting wakeup, GP1 = 0x%x\n", reg);
			iwl_set_bit(priv, CSR_GP_CNTRL,
				    CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
			return 0;
		}

		/* restore this queue's parameters in nic hardware. */
		rc = iwl_grab_restricted_access(priv);
		if (rc)
			return rc;
		iwl_write_restricted(priv, HBUS_TARG_WRPTR,
				     txq->q.first_empty | (txq_id << 8));
		iwl_release_restricted_access(priv);

	/* else not in power-save mode, uCode will never sleep when we're
	 * trying to tx (during RFKILL, we're not trying to tx). */
	} else {
		iwl_write32(priv, HBUS_TARG_WRPTR,
			    txq->q.first_empty | (txq_id << 8));
	}

	txq->need_update = 0;

	return 0;
}

#ifdef CONFIG_IWLWIFI_DEBUG

static void iwl_print_rx_config_cmd(struct iwl_rxon_cmd *rxon)
{
	IWL_DEBUG_RADIO("RX CONFIG:\n");
	printk_buf(IWL_DL_RADIO, (u8 *) rxon, sizeof(*rxon));
	IWL_DEBUG_RADIO("u16 channel: 0x%x\n", rxon->channel);
	IWL_DEBUG_RADIO("u32 flags: 0x%08X " BIT_FMT32 "\n",
			rxon->flags, BIT_ARG32(rxon->flags));
	IWL_DEBUG_RADIO("u32 filter_flags: 0x%08x " BIT_FMT32 "\n",
			rxon->filter_flags, BIT_ARG32(rxon->filter_flags));
	IWL_DEBUG_RADIO("u8 dev_type: 0x%x\n", rxon->dev_type);
	IWL_DEBUG_RADIO("u8 ofdm_basic_rates: 0x%02x " BIT_FMT8 "\n",
			rxon->ofdm_basic_rates,
			BIT_ARG8(rxon->ofdm_basic_rates));
	IWL_DEBUG_RADIO("u8 cck_basic_rates: 0x%02x " BIT_FMT8 "\n",
			rxon->cck_basic_rates, BIT_ARG8(rxon->cck_basic_rates));
	IWL_DEBUG_RADIO("u8[6] node_addr: " MAC_FMT "\n",
			MAC_ARG(rxon->node_addr));
	IWL_DEBUG_RADIO("u8[6] bssid_addr: " MAC_FMT "\n",
			MAC_ARG(rxon->bssid_addr));
	IWL_DEBUG_RADIO("u16 assoc_id: 0x%x\n", rxon->assoc_id);
}

#endif

static void iwl_enable_interrupts(struct iwl_priv *priv)
{
	IWL_DEBUG_ISR("Enabling interrupts\n");
	priv->status |= STATUS_INT_ENABLED;
	iwl_write32(priv, CSR_INT_MASK, CSR_INI_SET_MASK);
}

static inline void iwl_disable_interrupts(struct iwl_priv *priv)
{
	priv->status &= ~STATUS_INT_ENABLED;

	/* disable interrupts from uCode/NIC to host */
	iwl_write32(priv, CSR_INT_MASK, 0x00000000);

	/* acknowledge/clear/reset any interrupts still pending
	 * from uCode or flow handler (Rx/Tx DMA) */
	iwl_write32(priv, CSR_INT, 0xffffffff);
	iwl_write32(priv, CSR_FH_INT_STATUS, 0xffffffff);
	IWL_DEBUG_ISR("Disabled interrupts\n");
}

static const char *desc_lookup(int i)
{
	switch (i) {
	case 1:
		return "FAIL";
	case 2:
		return "BAD_PARAM";
	case 3:
		return "BAD_CHECKSUM";
	case 4:
		return "NMI_INTERRUPT";
	case 5:
		return "SYSASSERT";
	case 6:
		return "FATAL_ERROR";
	}

	return "UNKNOWN";
}

#define ERROR_START_OFFSET  (1 * sizeof(u32))
#define ERROR_ELEM_SIZE     (7 * sizeof(u32))

static void iwl_dump_nic_error_log(struct iwl_priv *priv)
{
#if IWL == 3945
	u32 i;
#else /* IWL == 4965 */
	u32 data2, line;
#endif
	u32 desc, time, count, base, data1;
	u32 blink1, blink2, ilink1, ilink2;
	int rc;

	base = priv->card_alive.error_event_table_ptr;

	if (!VALID_RTC_DATA_ADDR(base)) {
		IWL_ERROR("Not valid error log pointer 0x%08X\n", base);
		return;
	}

	rc = iwl_grab_restricted_access(priv);
	if (rc) {
		IWL_WARNING("Can not read from adapter at this time.\n");
		return;
	}

	count = iwl_read_restricted_mem(priv, base);

	if (ERROR_START_OFFSET <= count * ERROR_ELEM_SIZE) {
		IWL_ERROR("Start IWL Error Log Dump:\n");
		IWL_ERROR("Status: 0x%08X, Config: %08X count: %d\n",
			  priv->status, priv->config, count);
	}

#if IWL == 3945
	IWL_ERROR("Desc       Time       asrtPC  blink2 "
		  "ilink1  nmiPC   Line\n");
	for (i = ERROR_START_OFFSET;
	     i < (count * ERROR_ELEM_SIZE) + ERROR_START_OFFSET;
	     i += ERROR_ELEM_SIZE) {
		desc = iwl_read_restricted_mem(priv, base + i);
		time =
		    iwl_read_restricted_mem(priv, base + i + 1 * sizeof(u32));
		blink1 =
		    iwl_read_restricted_mem(priv, base + i + 2 * sizeof(u32));
		blink2 =
		    iwl_read_restricted_mem(priv, base + i + 3 * sizeof(u32));
		ilink1 =
		    iwl_read_restricted_mem(priv, base + i + 4 * sizeof(u32));
		ilink2 =
		    iwl_read_restricted_mem(priv, base + i + 5 * sizeof(u32));
		data1 =
		    iwl_read_restricted_mem(priv, base + i + 6 * sizeof(u32));

		IWL_ERROR
		    ("%-13s (#%d) %010u 0x%05X 0x%05X 0x%05X 0x%05X %u\n\n",
		     desc_lookup(desc), desc, time, blink1, blink2,
		     ilink1, ilink2, data1);
	}
#else  /* 4965 Error format */
	desc = iwl_read_restricted_mem(priv, base + 1 * sizeof(u32));
	blink1 = iwl_read_restricted_mem(priv, base + 3 * sizeof(u32));
	blink2 = iwl_read_restricted_mem(priv, base + 4 * sizeof(u32));
	ilink1 = iwl_read_restricted_mem(priv, base + 5 * sizeof(u32));
	ilink2 = iwl_read_restricted_mem(priv, base + 6 * sizeof(u32));
	data1 = iwl_read_restricted_mem(priv, base + 7 * sizeof(u32));
	data2 = iwl_read_restricted_mem(priv, base + 8 * sizeof(u32));
	line = iwl_read_restricted_mem(priv, base + 9 * sizeof(u32));
	time = iwl_read_restricted_mem(priv, base + 11 * sizeof(u32));

	IWL_ERROR("Desc               Time       "
		  "data1      data2      line\n");
	IWL_ERROR
	    ("%-13s (#%d) %010u 0x%08X 0x%08X %u\n",
	     desc_lookup(desc), desc, time, data1, data2, line);
	IWL_ERROR("blink1  blink2  ilink1  ilink2\n");
	IWL_ERROR
	    ("0x%05X 0x%05X 0x%05X 0x%05X\n", blink1, blink2, ilink1, ilink2);

#endif  /* IWL 3945 */

	iwl_release_restricted_access(priv);

}

#define EVENT_START_OFFSET  (4 * sizeof(u32))

/**
 * iwl_print_event_log - Dump error event log to syslog
 *
 * NOTE: Must be called with iwl_grab_restricted_access() already obtained!
 */
static void iwl_print_event_log(struct iwl_priv *priv, u32 start_idx,
				u32 num_events, u32 mode)
{
	u32 i;
	u32 base;       /* SRAM byte address of event log header */
	u32 event_size;	/* 2 u32s, or 3 u32s if timestamp recorded */
	u32 ptr;        /* SRAM byte address of log data */
	u32 ev, time, data; /* event log data */

	if (num_events == 0)
		return;

	base = priv->card_alive.log_event_table_ptr;

	if (mode == 0)
		event_size = 2 * sizeof(u32);
	else
		event_size = 3 * sizeof(u32);

	ptr = base + EVENT_START_OFFSET + (start_idx * event_size);

	/* "time" is actually "data" for mode 0 (no timestamp).
	 * place event id # at far right for easier visual parsing. */
	for (i = 0; i < num_events; i++) {
		ev = iwl_read_restricted_mem(priv, ptr);
		ptr += sizeof(u32);
		time = iwl_read_restricted_mem(priv, ptr);
		ptr += sizeof(u32);
		if (mode == 0) {
			IWL_ERROR("0x%08x\t%04u\n", time, ev); /* data, ev */
		} else {
			data = iwl_read_restricted_mem(priv, ptr);
			ptr += sizeof(u32);
			IWL_ERROR("%010u\t0x%08x\t%04u\n", time, data, ev);
		}
	}
}

static void iwl_dump_nic_event_log(struct iwl_priv *priv)
{
	int rc;
	u32 base;       /* SRAM byte address of event log header */
	u32 capacity;   /* event log capacity in # entries */
	u32 mode;       /* 0 - no timestamp, 1 - timestamp recorded */
	u32 num_wraps;  /* # times uCode wrapped to top of log */
	u32 next_entry; /* index of next entry to be written by uCode */
	u32 size;       /* # entries that we'll print */

	base = priv->card_alive.log_event_table_ptr;
	if (!VALID_RTC_DATA_ADDR(base)) {
		IWL_ERROR("Invalid event log pointer 0x%08X\n", base);
		return;
	}

	rc = iwl_grab_restricted_access(priv);
	if (rc) {
		IWL_WARNING("Can not read from adapter at this time.\n");
		return;
	}

	/* event log header */
	capacity = iwl_read_restricted_mem(priv, base);
	mode = iwl_read_restricted_mem(priv, base + (1 * sizeof(u32)));
	num_wraps = iwl_read_restricted_mem(priv, base + (2 * sizeof(u32)));
	next_entry = iwl_read_restricted_mem(priv, base + (3 * sizeof(u32)));

	size = num_wraps ? capacity : next_entry;

	/* bail out if nothing in log */
	if (size == 0) {
		IWL_ERROR("Start IPW Event Log Dump: nothing in log\n");
		iwl_release_restricted_access(priv);
		return;
	}

	IWL_ERROR("Start IPW Event Log Dump: display count %d, wraps %d\n",
		  size, num_wraps);

	/* if uCode has wrapped back to top of log, start at the oldest entry,
	 *    i.e the next one that uCode would fill. */
	if (num_wraps) {
		iwl_print_event_log(priv, next_entry,
				    capacity - next_entry, mode);
	}

	/* (then/else) start at top of log */
	iwl_print_event_log(priv, 0, next_entry, mode);

	iwl_release_restricted_access(priv);
}

/**
 * iwl_irq_handle_error - called for HW or SW error interrupt from card
 */
static void iwl_irq_handle_error(struct iwl_priv *priv)
{
	/* Set the FW error flag -- cleared on iwl_down */
	priv->status |= STATUS_FW_ERROR;

	/* Cancel currently queued command. */
	priv->status &= ~STATUS_HCMD_ACTIVE;

	IWL_WARNING("RX write index: %d read index %d\n",
		     priv->rxq.write, priv->rxq.read);

#ifdef CONFIG_IWLWIFI_DEBUG
	if (iwl_debug_level & IWL_DL_FW_ERRORS) {
		//iwl_dump_nic_error_log(priv);
		//iwl_dump_nic_event_log(priv);
		//iwl_print_rx_config_cmd(&priv->staging_rxon);
	}
#endif

	wake_up_interruptible(&priv->wait_command_queue);

	/* Keep the restart process from trying to send host
	 * commands by clearing the INIT status bit */
	priv->status &= ~STATUS_READY;
	if (!(priv->status & STATUS_EXIT_PENDING)) {
		IWL_DEBUG(IWL_DL_INFO | IWL_DL_FW_ERRORS,
			  "Restarting adapter due to uCode error.\n");
		if (iwl_is_associated(priv)) {
			memcpy(&priv->recovery_rxon, &priv->active_rxon,
			       sizeof(priv->recovery_rxon));
			priv->error_recovering = 1;
		}

		//queue_work(priv->workqueue, &priv->restart);
		clone->queue_te(1,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_restart),priv,NULL,true);
	}
}

static void iwl_error_recovery(struct iwl_priv *priv)
{
	unsigned long flags;

	memcpy(&priv->staging_rxon, &priv->recovery_rxon,
	       sizeof(priv->staging_rxon));
	priv->staging_rxon.filter_flags &= ~RXON_FILTER_ASSOC_MSK;
	iwl_commit_rxon(priv);

	iwl_rxon_add_station(priv, priv->bssid, 1);

	spin_lock_irqsave(&priv->lock, flags);
	priv->assoc_id = priv->staging_rxon.assoc_id;
	priv->error_recovering = 0;
	spin_unlock_irqrestore(&priv->lock, flags);
}

void darwin_iwi3945::iwl_irq_tasklet(struct iwl_priv *priv)
{
	u32 inta, inta_mask, handled = 0;
	u32 inta_fh;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);

	/* Ack/clear/reset pending uCode interrupts.
	 * Note:  Some bits in CSR_INT are "OR" of bits in CSR_FH_INT_STATUS,
	 *  and will clear only when CSR_FH_INT_STATUS gets cleared. */
	inta = iwl_read32(priv, CSR_INT);
	iwl_write32(priv, CSR_INT, inta);

	/* Ack/clear/reset pending flow-handler (DMA) interrupts.
	 * Any new interrupts that happen after this, either while we're
	 * in this tasklet, or later, will show up in next ISR/tasklet. */
	inta_fh = iwl_read32(priv, CSR_FH_INT_STATUS);
	iwl_write32(priv, CSR_FH_INT_STATUS, inta_fh);

	inta_mask = iwl_read32(priv, CSR_INT_MASK); /* just for debug */
	printf("inta 0x%08x, enabled 0x%08x, fh 0x%08x\n",inta, inta_mask, inta_fh);

	/* Since CSR_INT and CSR_FH_INT_STATUS reads and clears are not
	 * atomic, make sure that inta covers all the interrupts that
	 * we've discovered, even if FH interrupt came in just after
	 * reading CSR_INT. */
	if (inta_fh & FH_INT_RX_MASK)
		inta |= BIT_INT_FH_RX;
	if (inta_fh & FH_INT_TX_MASK)
		inta |= BIT_INT_FH_TX;

	/* Now service all interrupt bits discovered above. */
	if (inta & BIT_INT_ERR) {
		IWL_ERROR("Microcode HW error detected.  Restarting.\n");

		/* Tell the device to stop sending interrupts */
		iwl_disable_interrupts(priv);

		iwl_irq_handle_error(priv);

		handled |= BIT_INT_ERR;

		spin_unlock_irqrestore(&priv->lock, flags);

		return;
	}

	inta &= ~(1<<26 | 1<<0);
	
	if (inta & BIT_INT_RF_KILL) {
		int hw_rf_kill = 0;
		if (!(iwl_read32(priv, CSR_GP_CNTRL) &
				CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW))
			hw_rf_kill = 1;

		IWL_DEBUG(IWL_DL_INFO | IWL_DL_RF_KILL | IWL_DL_ISR,
				"RF_KILL bit toggled to %s.\n",
				hw_rf_kill ? "disable radio":"enable radio");

		/* Queue restart only if RF_KILL switch was set to "kill"
		 *   when we loaded driver, and is now set to "enable".
		 * After we're Alive, RF_KILL gets handled by
		 *   iwl_rx_card_state_notif() */
		if (!hw_rf_kill && !(priv->status & STATUS_ALIVE))
			//queue_work(priv->workqueue, &priv->restart);
			clone->queue_te(1,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_restart),priv,NULL,true);

		handled |= BIT_INT_RF_KILL;
	}

	if (inta & BIT_INT_CT_KILL) {
		IWL_ERROR("Microcode CT kill error detected.\n");
		handled |= BIT_INT_CT_KILL;
	}

	if (inta & BIT_INT_SWERROR) {
		IWL_ERROR("Microcode SW error detected.  Restarting 0x%X.\n",inta);
		iwl_irq_handle_error(priv);
		handled |= BIT_INT_SWERROR;
	}

	if (inta & BIT_INT_WAKEUP) {
		IWL_DEBUG_ISR("Wakeup interrupt\n");
		iwl_rx_queue_update_write_ptr(priv, &priv->rxq);
		iwl_tx_queue_update_write_ptr(priv, &priv->txq[0]);
		iwl_tx_queue_update_write_ptr(priv, &priv->txq[1]);
		iwl_tx_queue_update_write_ptr(priv, &priv->txq[2]);
		iwl_tx_queue_update_write_ptr(priv, &priv->txq[3]);
		iwl_tx_queue_update_write_ptr(priv, &priv->txq[4]);
		iwl_tx_queue_update_write_ptr(priv, &priv->txq[5]);

		handled |= BIT_INT_WAKEUP;
	}

	/* Alive notification via Rx interrupt will do the real work */
	if (inta & BIT_INT_ALIVE) {
		IWL_DEBUG_ISR("Alive interrupt\n");
		handled |= BIT_INT_ALIVE;
	}

	/* All uCode command responses, including Tx command responses,
	 * Rx "responses" (frame-received notification), and other
	 * notifications from uCode come through here*/
	if (inta & (BIT_INT_FH_RX | BIT_INT_SW_RX)) {
		iwl_rx_handle(priv);
		handled |= (BIT_INT_FH_RX | BIT_INT_SW_RX);
	}

	if (inta & BIT_INT_FH_TX) {
		IWL_DEBUG_ISR("Tx interrupt\n");

#if IWL == 3945
		iwl_write32(priv, CSR_FH_INT_STATUS, (1 << 6));
		if (!iwl_grab_restricted_access(priv)) {
			iwl_write_restricted(priv,
					     FH_TCSR_CREDIT
					     (ALM_FH_SRVC_CHNL), 0x0);
			iwl_release_restricted_access(priv);
		}
#endif /* IWL == 3945 */
		handled |= BIT_INT_FH_TX;
	}

	if (inta & ~handled)
		IWL_ERROR("Unhandled INTA bits 0x%08x\n", inta & ~handled);

	if (inta & ~CSR_INI_SET_MASK) {
		IWL_WARNING("Disabled INTA bits 0x%08x were pending\n",
			 inta & ~CSR_INI_SET_MASK);
		IWL_WARNING("   with FH_INT = 0x%08x\n", inta_fh);
	}

	/* Re-enable all interrupts */
	iwl_enable_interrupts(priv);

#ifdef CONFIG_IWLWIFI_DEBUG
	if (iwl_debug_level & (IWL_DL_ISR)) {
		inta = iwl_read32(priv, CSR_INT);
		inta_mask = iwl_read32(priv, CSR_INT_MASK);
		inta_fh = iwl_read32(priv, CSR_FH_INT_STATUS);
		IWL_DEBUG_ISR("End inta 0x%08x, enabled 0x%08x, fh 0x%08x, "
			"flags 0x%08lx\n", inta, inta_mask, inta_fh, flags);
	}
#endif
	spin_unlock_irqrestore(&priv->lock, flags);
}

void iwl_isr(struct iwl_priv *priv)
{
//	struct iwl_priv *priv = (struct iwl_priv*)data;
	u32 inta, inta_mask;
	u32 inta_fh;
	if (!priv)
	{
		IWL_ERROR("no priv defined\n");
			return;//IRQ_NONE;
	}
	spin_lock(&priv->lock);

	/* Disable (but don't clear!) interrupts here to avoid
	 *    back-to-back ISRs and sporadic interrupts from our NIC.
	 * If we have something to service, the tasklet will re-enable ints.
	 * If we *don't* have something, we'll re-enable before leaving here. */
	inta_mask = iwl_read32(priv, CSR_INT_MASK);  /* just for debug */
	iwl_write32(priv, CSR_INT_MASK, 0x00000000);

	/* Discover which interrupts are active/pending */
	inta = iwl_read32(priv, CSR_INT);
	inta_fh = iwl_read32(priv, CSR_FH_INT_STATUS);

	/* Ignore interrupt if there's nothing in NIC to service.
	 * This may be due to IRQ shared with another device,
	 * or due to sporadic interrupts thrown from our NIC. */
	if (!inta && !inta_fh) {
		IWL_DEBUG_ISR("Ignore interrupt, inta == 0, inta_fh == 0\n");
		goto none;
	}

	if ((inta == 0xFFFFFFFF) || (inta == 0xa5a5a5a5)
	    || (inta == 0x5a5a5a5a)) {
		/* Hardware disappeared */
		IWL_WARNING("HARDWARE GONE?? INTA == 0x%080x\n", inta);
		goto none;
	}

	IWL_DEBUG_ISR ("ISR inta 0x%08x, enabled 0x%08x, fh 0x%08x\n",
	     inta, inta_mask, inta_fh);

	/* iwl_irq_tasklet() will service interrupts and re-enable them */
	tasklet_schedule(&priv->irq_tasklet);
	clone->queue_te(13,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_irq_tasklet),priv,NULL,true);
	
	spin_unlock(&priv->lock);
	
	return;

 none:
	/* re-enable interrupts here since we don't have anything to service. */
	iwl_enable_interrupts(priv);
	spin_unlock(&priv->lock);
	return;
}

/************************** EEPROM BANDS ****************************
 *
 * The iwl_eeprom_band definitions below provide the mapping from the
 * EEPROM contents to the specific channel number supported for each
 * band.
 *
 * For example, iwl_priv->eeprom.band_3_channels[4] from the band_3
 * definition below maps to physical channel 42 in the 5.2GHz spectrum.
 * The specific geography and calibration information for that channel
 * is contained in the eeprom map itself.
 *
 * During init, we copy the eeprom information and channel map
 * information into priv->channel_info_24/52 and priv->channel_map_24/52
 *
 * channel_map_24/52 provides the index in the channel_info array for a
 * given channel.  We have to have two separate maps as there is channel
 * overlap with the 2.4GHz and 5.2GHz spectrum as seen in band_1 and
 * band_2
 *
 * A value of 0xff stored in the channel_map indicates that the channel
 * is not supported by the hardware at all.
 *
 * A value of 0xfe in the channel_map indicates that the channel is not
 * valid for Tx with the current hardware.  This means that
 * while the system can tune and receive on a given channel, it may not
 * be able to associate or transmit any frames on that
 * channel.  There is no corresponding channel information for that
 * entry.
 *
 *********************************************************************/

/* 2.4 GHz */
static const u8 iwl_eeprom_band_1[14] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
};

/* 5.2 GHz bands */
static const u8 iwl_eeprom_band_2[] = {
	183, 184, 185, 187, 188, 189, 192, 196, 7, 8, 11, 12, 16
};

static const u8 iwl_eeprom_band_3[] = {	/* 5205-5320MHz */
	34, 36, 38, 40, 42, 44, 46, 48, 52, 56, 60, 64
};

static const u8 iwl_eeprom_band_4[] = {	/* 5500-5700MHz */
	100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140
};

static const u8 iwl_eeprom_band_5[] = {	/* 5725-5825MHz */
	145, 149, 153, 157, 161, 165
};

#if IWL == 4965
static u8 iwl_eeprom_band_6[] = {       /* 2.4 FAT channel */
	1, 2, 3, 4, 5, 6, 7
};

static u8 iwl_eeprom_band_7[] = {       /* 5.2 FAT channel */
	36, 44, 52, 60, 100, 108, 116, 124, 132, 149, 157
};
#endif

static void iwl_init_band_reference(const struct iwl_priv *priv, int band,
				    int *eeprom_ch_count,
				    const struct iwl_eeprom_channel
				    **eeprom_ch_info,
				    const u8 **eeprom_ch_index)
{
	switch (band) {
	case 1:		/* 2.4GHz band */
		*eeprom_ch_count = /*GLOBAL_*/ARRAY_SIZE(iwl_eeprom_band_1);
		*eeprom_ch_info = priv->eeprom.band_1_channels;
		*eeprom_ch_index = iwl_eeprom_band_1;
		break;
	case 2:		/* 5.2GHz band */
		*eeprom_ch_count = /*GLOBAL_*/ARRAY_SIZE(iwl_eeprom_band_2);
		*eeprom_ch_info = priv->eeprom.band_2_channels;
		*eeprom_ch_index = iwl_eeprom_band_2;
		break;
	case 3:		/* 5.2GHz band */
		*eeprom_ch_count = /*GLOBAL_*/ARRAY_SIZE(iwl_eeprom_band_3);
		*eeprom_ch_info = priv->eeprom.band_3_channels;
		*eeprom_ch_index = iwl_eeprom_band_3;
		break;
	case 4:		/* 5.2GHz band */
		*eeprom_ch_count = /*GLOBAL_*/ARRAY_SIZE(iwl_eeprom_band_4);
		*eeprom_ch_info = priv->eeprom.band_4_channels;
		*eeprom_ch_index = iwl_eeprom_band_4;
		break;
	case 5:		/* 5.2GHz band */
		*eeprom_ch_count = /*GLOBAL_*/ARRAY_SIZE(iwl_eeprom_band_5);
		*eeprom_ch_info = priv->eeprom.band_5_channels;
		*eeprom_ch_index = iwl_eeprom_band_5;
		break;
#if IWL == 4965
	case 6:
		*eeprom_ch_count = ARRAY_SIZE(iwl_eeprom_band_6);
		*eeprom_ch_info = priv->eeprom.band_24_channels;
		*eeprom_ch_index = iwl_eeprom_band_6;
		break;
	case 7:
		*eeprom_ch_count = ARRAY_SIZE(iwl_eeprom_band_7);
		*eeprom_ch_info = priv->eeprom.band_52_channels;
		*eeprom_ch_index = iwl_eeprom_band_7;
		break;
#endif
	default:
		return;
	}
}

const struct iwl_channel_info *iwl_get_channel_info(const struct iwl_priv *priv,
						    int phymode, int channel)
{
	int i;

	switch (phymode) {
	case MODE_ATHEROS_TURBO:
	case MODE_IEEE80211A:
		for (i = 14; i < priv->channel_count; i++) {
			if (priv->channel_info[i].channel == channel)
				return &priv->channel_info[i];
		}
		break;

	case MODE_IEEE80211B:
	case MODE_IEEE80211G:
	case MODE_ATHEROS_TURBOG:
		if (channel >= 1 && channel <= 14)
			return &priv->channel_info[channel - 1];
		break;

	}

	return NULL;
}

#define CHECK_AND_PRINT(x) ((eeprom_ch_info[ch].flags & EEPROM_CHANNEL_##x) \
			    ? # x " " : "")

static int iwl_init_channel_map(struct iwl_priv *priv)
{
	int eeprom_ch_count = 0;
	const u8 *eeprom_ch_index = NULL;
	const struct iwl_eeprom_channel *eeprom_ch_info = NULL;
	int band, ch;
	struct iwl_channel_info *ch_info;

	if (priv->channel_count) {
		IWL_DEBUG_INFO("Channel map already initialized.\n");
		return 0;
	}

	if (priv->eeprom.version < 0x2f) {
		IWL_WARNING("Unsupported EEPROM version: 0x%04X\n",
			    priv->eeprom.version);
		return -EINVAL;
	}

	IWL_DEBUG_INFO("Initializing regulatory info from EEPROM\n");

	priv->channel_count =
	    /*GLOBAL_*/ARRAY_SIZE(iwl_eeprom_band_1) +
	    /*GLOBAL_*/ARRAY_SIZE(iwl_eeprom_band_2) +
	    /*GLOBAL_*/ARRAY_SIZE(iwl_eeprom_band_3) +
	    /*GLOBAL_*/ARRAY_SIZE(iwl_eeprom_band_4) +
	    /*GLOBAL_*/ARRAY_SIZE(iwl_eeprom_band_5);

	IWL_DEBUG_INFO("Parsing data for %d channels.\n", priv->channel_count);
	//if (priv->channel_count==0) priv->channel_count=1;
	priv->channel_info = (struct iwl_channel_info*)IOMalloc(sizeof(struct iwl_channel_info) *
				     priv->channel_count);
	memset(priv->channel_info,0,sizeof(struct iwl_channel_info) * priv->channel_count);
	if (!priv->channel_info) {
		IWL_ERROR("Could not allocate channel_info\n");
		priv->channel_count = 0;
		return -ENOMEM;
	}

	ch_info = priv->channel_info;

	/* Loop through the 5 EEPROM bands adding them in order to the
	 * channel map we maintain (that contains additional information than
	 * what just in the EEPROM) */
	for (band = 1; band <= 5; band++) {

		iwl_init_band_reference(priv, band, &eeprom_ch_count,
					&eeprom_ch_info, &eeprom_ch_index);

		/* Loop through each band adding each of the channels */
		for (ch = 0; ch < eeprom_ch_count; ch++) {
			ch_info->channel = eeprom_ch_index[ch];
			ch_info->phymode = (band == 1) ? MODE_IEEE80211B :
			    MODE_IEEE80211A;

			/* permanently store EEPROM's channel regulatory flags
			 *   and max power in channel info database. */
			ch_info->eeprom = eeprom_ch_info[ch];

			/* Copy the run-time flags so they are there even on
			 * invalid channels */
			ch_info->flags = eeprom_ch_info[ch].flags;

			if (!(is_channel_valid(ch_info))) {
				/*IWL_DEBUG_INFO("Ch. %d Flags %x [%sGHz] - "
					       "No Tx\n",
					       ch_info->channel,
					       ch_info->flags,
					       is_channel_a_band(ch_info) ?
					       "5.2" : "2.4");*/
				ch_info++;
				continue;
			}

			/* Initialize regulatory-based run-time data */
			ch_info->max_power_avg = ch_info->curr_txpow =
			    eeprom_ch_info[ch].max_power_avg;
			ch_info->scan_power = eeprom_ch_info[ch].max_power_avg;
			ch_info->min_power = 0;

			/*IWL_DEBUG_INFO("Ch. %d [%sGHz] %s%s%s%s%s%s(" BIT_FMT8
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
				       BIT_ARG8(eeprom_ch_info[ch].flags),
				       eeprom_ch_info[ch].
				       max_power_avg,
				       ((eeprom_ch_info[ch].
					 flags & EEPROM_CHANNEL_IBSS)
					&& !(eeprom_ch_info[ch].
					     flags & EEPROM_CHANNEL_RADAR))
				       ? "" : "not ");*/

			/* Set the user_txpower_limit to the highest power
			 * supported by any channel */
			if (eeprom_ch_info[ch].max_power_avg >
			    priv->user_txpower_limit)
				priv->user_txpower_limit =
				    eeprom_ch_info[ch].max_power_avg;

			ch_info++;
		}
	}
#if IWL == 4965
	for (band = 6; band <= 7; band++) {
		int phymode;
		u8 fat_extension_chan;

		iwl_init_band_reference(priv, band, &eeprom_ch_count,
					&eeprom_ch_info, &eeprom_ch_index);

		phymode = (band == 6) ? MODE_IEEE80211B : MODE_IEEE80211A;
		/* Loop through each band adding each of the channels */
		for (ch = 0; ch < eeprom_ch_count; ch++) {

			if ((band == 6) &&
			    ((eeprom_ch_index[ch] == 5) ||
			    (eeprom_ch_index[ch] == 6) ||
			    (eeprom_ch_index[ch] == 7)))
			       fat_extension_chan = HT_IE_EXT_CHANNEL_MAX;
			else
				fat_extension_chan = HT_IE_EXT_CHANNEL_ABOVE;

			iwl4965_set_fat_chan_info(priv, phymode,
						  eeprom_ch_index[ch],
						  &(eeprom_ch_info[ch]),
						  fat_extension_chan);

			iwl4965_set_fat_chan_info(priv, phymode,
						  (eeprom_ch_index[ch] + 4),
						  &(eeprom_ch_info[ch]),
						  HT_IE_EXT_CHANNEL_BELOW);
		}
	}
#endif

	if (iwl3945_txpower_set_from_eeprom(priv))
		return -EIO;

	return 0;
}

/* For active scan, listen ACTIVE_DWELL_TIME (msec) on each channel after
 * sending probe req.  This should be set long enough to hear probe responses
 * from more than one AP.  */
#define IWL_ACTIVE_DWELL_TIME_24    (20)	/* all times in msec */
#define IWL_ACTIVE_DWELL_TIME_52    (10)

/* For faster active scanning, scan will move to the next channel if fewer than
 * PLCP_QUIET_THRESH packets are heard on this channel within
 * ACTIVE_QUIET_TIME after sending probe request.  This shortens the dwell
 * time if it's a quiet channel (nothing responded to our probe, and there's
 * no other traffic).
 * Disable "quiet" feature by setting PLCP_QUIET_THRESH to 0. */
#define IWL_PLCP_QUIET_THRESH       (1)	/* packets */
#define IWL_ACTIVE_QUIET_TIME       (5)	/* msec */

/* For passive scan, listen PASSIVE_DWELL_TIME (msec) on each channel.
 * Must be set longer than active dwell time.
 * For the most reliable scan, set > AP beacon interval (typically 100msec). */
#define IWL_PASSIVE_DWELL_TIME_24   (20)	/* all times in msec */
#define IWL_PASSIVE_DWELL_TIME_52   (10)
#define IWL_PASSIVE_DWELL_BASE      (100)
#define IWL_CHANNEL_TUNE_TIME       5

static inline u16 iwl_get_active_dwell_time(struct iwl_priv *priv, int phymode)
{
	if ((phymode == MODE_IEEE80211A) ||
	    (phymode == MODE_ATHEROS_TURBO))
		return IWL_ACTIVE_DWELL_TIME_52;
	else
		return IWL_ACTIVE_DWELL_TIME_24;
}

static u16 iwl_get_passive_dwell_time(struct iwl_priv *priv, int phymode)
{
	u16 active = iwl_get_active_dwell_time(priv, phymode);
	u16 passive = ((phymode != MODE_IEEE80211A) &&
		       (phymode != MODE_ATHEROS_TURBO)) ?
	    IWL_PASSIVE_DWELL_BASE + IWL_PASSIVE_DWELL_TIME_24 :
	    IWL_PASSIVE_DWELL_BASE + IWL_PASSIVE_DWELL_TIME_52;

	if (iwl_is_associated(priv)) {
		/* If we're associated, we clamp the maximum passive
		 * dwell time to be 98% of the beacon interval (minus
		 * 2 * channel tune time) */
		passive = priv->beacon_int;
		if ((passive > IWL_PASSIVE_DWELL_BASE) || !passive)
			passive = IWL_PASSIVE_DWELL_BASE;
		passive = (passive * 98) / 100 - IWL_CHANNEL_TUNE_TIME * 2;
	}

	if (passive <= active)
		passive = active + 1;

	return passive;
}

static int iwl_get_channels_for_scan(struct iwl_priv *priv, int phymode,
				     u8 is_active, u8 direct_mask,
				     struct iwl_scan_channel *scan_ch)
{
	const struct ieee80211_channel *channels = NULL;
	const struct ieee80211_hw_mode *hw_mode;
	const struct iwl_channel_info *ch_info;
	u16 passive_dwell = 0;
	u16 active_dwell = 0;
	int added, i;

	hw_mode = iwl_get_hw_mode(priv, phymode);
	if (!hw_mode)
		return 0;

	channels = hw_mode->channels;

	active_dwell = iwl_get_active_dwell_time(priv, phymode);
	passive_dwell = iwl_get_passive_dwell_time(priv, phymode);

	for (i = 0, added = 0; i < hw_mode->num_channels; i++) {
		if (channels[i].chan ==
		    le16_to_cpu(priv->active_rxon.channel)) {
			if (iwl_is_associated(priv)) {
				IWL_DEBUG_SCAN
				    ("Skipping current channel %d\n",
				     le16_to_cpu(priv->active_rxon.channel));
				continue;
			}
		} else if (priv->only_active_channel)
			continue;

		scan_ch->channel = channels[i].chan;

		ch_info = iwl_get_channel_info(priv, phymode, scan_ch->channel);
		if (!is_channel_valid(ch_info)) {
			IWL_DEBUG_SCAN("Channel %d is INVALID for this SKU.\n",
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
		scan_ch->tpc.dsp_atten = 110;
		/* scan_pwr_info->tpc.dsp_atten; */

		/*scan_pwr_info->tpc.tx_gain; */
		if ((phymode == MODE_IEEE80211A) ||
		    (phymode == MODE_ATHEROS_TURBO)) {
			scan_ch->tpc.tx_gain = ((1 << 5) | (3 << 3)) | 3;
		} else {
			scan_ch->tpc.tx_gain = ((1 << 5) | (5 << 3));
			/* NOTE: if we were doing 6Mb OFDM for scans we'd use
			 * power level
			 scan_ch->tpc.tx_gain = ((1<<5) | (2 << 3)) | 3;
			 */
		}

		IWL_DEBUG_SCAN("Scanning %d [%s %d]\n",
			       scan_ch->channel,
			       (scan_ch->type & 1) ? "ACTIVE" : "PASSIVE",
			       (scan_ch->type & 1) ?
			       active_dwell : passive_dwell);

		scan_ch++;
		added++;
	}

	IWL_DEBUG_SCAN("total channels to scan %d \n", added);
	return added;
}

static void iwl_reset_channel_flag(struct iwl_priv *priv)
{
	int i, j;
	for (i = 0; i < 3; i++) {
		struct ieee80211_hw_mode *hw_mode = (struct ieee80211_hw_mode *)&priv->modes[i];
		for (j = 0; j < hw_mode->num_channels; j++)
			hw_mode->channels[j].flag = hw_mode->channels[j].val;
	}
}

static void iwl_init_hw_rates(struct iwl_priv *priv,
			      struct ieee80211_rate *rates)
{
	int i;

	for (i = 0; i < IWL_RATE_COUNT; i++) {
		rates[i].rate = iwl_rates[i].ieee * 5;
		rates[i].val = i; /* Rate scaling will work on indexes */
		rates[i].val2 = i;
		rates[i].flags = IEEE80211_RATE_SUPPORTED;
		/* Only OFDM have the bits-per-symbol set */
		if ((i <= IWL_LAST_OFDM_RATE) && (i >= IWL_FIRST_OFDM_RATE))
			rates[i].flags |= IEEE80211_RATE_OFDM;
		else {
			/*
			 * If CCK 1M then set rate flag to CCK else CCK_2
			 * which is CCK | PREAMBLE2
			 */
			rates[i].flags |= (iwl_rates[i].plcp == 10) ?
			    IEEE80211_RATE_CCK : IEEE80211_RATE_CCK_2;
		}

		/* Set up which ones are basic rates... */
		if (IWL_BASIC_RATES_MASK & (1 << i))
			rates[i].flags |= IEEE80211_RATE_BASIC;
	}

#if IWL == 4965
	iwl4965_init_hw_rates(priv, rates);
#endif
}

/**
 * iwl_init_geos - Initialize mac80211's geo/channel info based from eeprom
 */
static int iwl_init_geos(struct iwl_priv *priv)
{
	struct iwl_channel_info *ch;
	struct ieee80211_hw_mode *modes;
	struct ieee80211_channel *channels;
	struct ieee80211_channel *geo_ch;
	struct ieee80211_rate *rates;
	int i = 0;
#if IWL == 4965
	enum {
		A = 0,
		B = 1,
		G = 2,
		A_11N = 3,
		G_11N = 4,
	};
	int mode_count = 5;
#else
	enum {
		A = 0,
		B = 1,
		G = 2,
	};
	int mode_count = 3;
#endif

	if (priv->modes) {
		IWL_DEBUG_INFO("Geography modes already initialized.\n");
		priv->status |= STATUS_GEO_CONFIGURED;
		return 0;
	}

	modes = (struct ieee80211_hw_mode*)IOMalloc(sizeof(struct ieee80211_hw_mode) * mode_count
			);
	memset(modes,0,sizeof(struct ieee80211_hw_mode) * mode_count);
	if (!modes)
		return -ENOMEM;

	channels = (struct ieee80211_channel*)IOMalloc(sizeof(struct ieee80211_channel) * priv->channel_count);
	memset(channels,0,sizeof(struct ieee80211_channel) * priv->channel_count);
	if (!channels) {
		IOFree(modes,sizeof(struct ieee80211_hw_mode) * mode_count);
		return -ENOMEM;
	}

	rates = (struct ieee80211_rate*)IOMalloc((sizeof(struct ieee80211_rate) * (IWL_MAX_RATES + 1))
			);
	memset(rates,0,(sizeof(struct ieee80211_rate) * (IWL_MAX_RATES + 1)));
	if (!rates) {
		IOFree(modes,sizeof(struct ieee80211_hw_mode) * mode_count);
		IOFree(channels,sizeof(struct ieee80211_hw_mode) * mode_count);
		return -ENOMEM;
	}

	/* 0 = 802.11a
	 * 1 = 802.11b
	 * 2 = 802.11g
	 */

	/* 5.2GHz channels start after the 2.4GHz channels */
	modes[A].mode = MODE_IEEE80211A;
	modes[A].channels = &channels[/*GLOBAL_*/ARRAY_SIZE(iwl_eeprom_band_1)];
	modes[A].rates = rates;
	modes[A].num_rates = 8;	/* just OFDM */
#if IWL == 4965
	modes[A].rates = &rates[4];
#endif
	modes[A].num_channels = 0;

	modes[B].mode = MODE_IEEE80211B;
	modes[B].channels = channels;
#if IWL == 3945
	modes[B].rates = &rates[8];
#elif IWL == 4965
	modes[B].rates = rates;
#endif
	modes[B].num_rates = 4;	/* just CCK */
	modes[B].num_channels = 0;

	modes[G].mode = MODE_IEEE80211G;
	modes[G].channels = channels;
	modes[G].rates = rates;
	modes[G].num_rates = 12;	/* OFDM & CCK */
	modes[G].num_channels = 0;

#if IWL == 4965
	modes[G_11N].mode = MODE_ATHEROS_TURBOG;
	modes[G_11N].channels = channels;
	modes[G_11N].num_rates = 13;        /* OFDM & CCK */
	modes[G_11N].rates = rates;
	modes[G_11N].num_channels = 0;

	modes[A_11N].mode = MODE_ATHEROS_TURBO;
	modes[A_11N].channels = &channels[/*GLOBAL_*/ARRAY_SIZE(iwl_eeprom_band_1)];
	modes[A_11N].rates = &rates[4];
	modes[A_11N].num_rates = 9; /* just OFDM */
	modes[A_11N].num_channels = 0;
#endif
	priv->ieee_channels = channels;
	priv->ieee_rates = rates;

	iwl_init_hw_rates(priv, rates);

	for (i = 0, geo_ch = channels; i < priv->channel_count; i++) {
		ch = &priv->channel_info[i];

		if (!is_channel_valid(ch)) {
			/*IWL_WARNING("Channel %d [%sGHz] is Tx only -- "
				    "skipping.\n",
				    ch->channel, is_channel_a_band(ch) ?
				    "5.2" : "2.4");*/
			continue;
		}

		if (is_channel_a_band(ch)) {
			geo_ch = &modes[A].channels[modes[A].num_channels++];
#if IWL == 4965
			modes[A_11N].num_channels++;
#endif
		} else {
			geo_ch = &modes[B].channels[modes[B].num_channels++];
			modes[G].num_channels++;
#if IWL == 4965
			modes[G_11N].num_channels++;
#endif
		}

		geo_ch->freq = ieee80211chan2mhz(ch->channel);
		geo_ch->chan = ch->channel;
		geo_ch->power_level = ch->max_power_avg;
		geo_ch->antenna_max = 0xff;

		if (is_channel_valid(ch)) {
			geo_ch->flag = IEEE80211_CHAN_W_SCAN;
			if (ch->flags & EEPROM_CHANNEL_IBSS)
				geo_ch->flag |= IEEE80211_CHAN_W_IBSS;

			if (ch->flags & EEPROM_CHANNEL_ACTIVE)
				geo_ch->flag |= IEEE80211_CHAN_W_ACTIVE_SCAN;

			if (ch->flags & EEPROM_CHANNEL_RADAR)
				geo_ch->flag |= IEEE80211_CHAN_W_RADAR_DETECT;

			if (ch->max_power_avg > priv->max_channel_txpower_limit)
				priv->max_channel_txpower_limit =
				    ch->max_power_avg;
		}

		geo_ch->val = geo_ch->flag;
	}

	if ((modes[A].num_channels == 0) && priv->is_abg) {
		/*printk(KERN_INFO DRV_NAME
		       ": Incorrectly detected BG card as ABG.  Please send "
		       "your PCI ID 0x%04X:0x%04X to maintainer.\n",
		       priv->pci_dev->device, priv->pci_dev->subsystem_device);*/
		priv->is_abg = 0;
	}

	printk(KERN_INFO DRV_NAME
	       ": Tunable channels: %d 802.11bg, %d 802.11a channels\n",
	       modes[G].num_channels, modes[A].num_channels);

	/*
	 * NOTE:  We register these in preference of order -- the
	 * stack doesn't currently (as of 7.0.6 / Apr 24 '07) pick
	 * a phymode based on rates or AP capabilities but seems to
	 * configure it purely on if the channel being configured
	 * is supported by a mode -- and the first match is taken
	 */

	if (modes[G].num_channels>0)
		ieee80211_register_hwmode(priv->hw, &modes[G]);
	if (modes[B].num_channels>0)
		ieee80211_register_hwmode(priv->hw, &modes[B]);
	if (modes[A].num_channels>0)
		ieee80211_register_hwmode(priv->hw, &modes[A]);

	priv->modes = modes;
	priv->status |= STATUS_GEO_CONFIGURED;

	return 0;
}

/******************************************************************************
 *
 * uCode download functions
 *
 ******************************************************************************/

static void iwl_dealloc_ucode_pci(struct iwl_priv *priv)
{
	if (priv->ucode_code.v_addr != NULL) {
		pci_free_consistent(priv->pci_dev,
				    priv->ucode_code.len,
				    priv->ucode_code.v_addr,
				    priv->ucode_code.p_addr);
		priv->ucode_code.v_addr = NULL;
	}
	if (priv->ucode_data.v_addr != NULL) {
		pci_free_consistent(priv->pci_dev,
				    priv->ucode_data.len,
				    priv->ucode_data.v_addr,
				    priv->ucode_data.p_addr);
		priv->ucode_data.v_addr = NULL;
	}
	if (priv->ucode_data_backup.v_addr != NULL) {
		pci_free_consistent(priv->pci_dev,
				    priv->ucode_data_backup.len,
				    priv->ucode_data_backup.v_addr,
				    priv->ucode_data_backup.p_addr);
		priv->ucode_data_backup.v_addr = NULL;
	}
	if (priv->ucode_init.v_addr != NULL) {
		pci_free_consistent(priv->pci_dev,
				    priv->ucode_init.len,
				    priv->ucode_init.v_addr,
				    priv->ucode_init.p_addr);
		priv->ucode_init.v_addr = NULL;
	}
	if (priv->ucode_init_data.v_addr != NULL) {
		pci_free_consistent(priv->pci_dev,
				    priv->ucode_init_data.len,
				    priv->ucode_init_data.v_addr,
				    priv->ucode_init_data.p_addr);
		priv->ucode_init_data.v_addr = NULL;
	}
	if (priv->ucode_boot.v_addr != NULL) {
		pci_free_consistent(priv->pci_dev,
				    priv->ucode_boot.len,
				    priv->ucode_boot.v_addr,
				    priv->ucode_boot.p_addr);
		priv->ucode_boot.v_addr = NULL;
	}
}

/**
 * iwl_verify_inst_full - verify runtime uCode image in card vs. host,
 *     looking at all data.
 */
static int iwl_verify_inst_full(struct iwl_priv *priv, __le32* image, u32 len)
{
	u32 val;
	u32 save_len = len;
	int rc = 0;
	u32 errcnt;

	IWL_DEBUG_INFO("ucode inst image size is %u\n", len);

	rc = iwl_grab_restricted_access(priv);
	if (rc)
		return rc;

	iwl_write_restricted(priv, HBUS_TARG_MEM_RADDR, RTC_INST_LOWER_BOUND);

	errcnt = 0;
	for (; len > 0; len -= sizeof(u32), image++) {
		/* read data comes through single port, auto-incr addr */
		/* NOTE: Use the debugless read so we don't flood kernel log
		 * if IWL_DL_IO is set */
		val = _iwl_read_restricted(priv, HBUS_TARG_MEM_RDAT);
		if (val != le32_to_cpu(*image)) {
			IWL_ERROR("uCode INST section is invalid at "
				  "offset 0x%x, is 0x%x, s/b 0x%x\n",
				  save_len - len, val, le32_to_cpu(*image));
			rc = -EIO;
			errcnt++;
			if (errcnt >= 20)
				break;
		}
	}

	iwl_release_restricted_access(priv);

	if (!errcnt)
		IWL_DEBUG_INFO
		    ("ucode image in INSTRUCTION memory is good\n");

	return rc;
}


/**
 * iwl_verify_inst_sparse - verify runtime uCode image in card vs. host,
 *   using sample data 100 bytes apart.  If these sample points are good,
 *   it's a pretty good bet that everything between them is good, too.
 */
static int iwl_verify_inst_sparse(struct iwl_priv *priv, __le32* image, u32 len)
{
	u32 val;
	int rc = 0;
	u32 errcnt = 0;
	u32 i;

	IWL_DEBUG_INFO("ucode inst image size is %u\n", len);

	rc = iwl_grab_restricted_access(priv);
	if (rc)
		return rc;

	for (i = 0; i < len; i += 100, image += 100/sizeof(u32)) {
		/* read data comes through single port, auto-incr addr */
		/* NOTE: Use the debugless read so we don't flood kernel log
		 * if IWL_DL_IO is set */
		iwl_write_restricted(priv, HBUS_TARG_MEM_RADDR,
			i + RTC_INST_LOWER_BOUND);
		val = _iwl_read_restricted(priv, HBUS_TARG_MEM_RDAT);
		if (val != le32_to_cpu(*image)) {
#if 0 /* Enable this if you want to see details */
			IWL_ERROR("uCode INST section is invalid at "
				  "offset 0x%x, is 0x%x, s/b 0x%x\n",
				  i, val, *image);
#endif
			rc = -EIO;
			errcnt++;
			if (errcnt >= 3)
				break;
		}
	}

	iwl_release_restricted_access(priv);

	return rc;
}


/**
 * iwl_verify_ucode - determine which instruction image is in SRAM,
 *    and verify its contents
 */
static int iwl_verify_ucode(struct iwl_priv *priv)
{
	__le32 *image;
	u32 len;
	int rc = 0;

	/* Try bootstrap */
	image = (__le32*)priv->ucode_boot.v_addr;
	len = priv->ucode_boot.len;
	rc = iwl_verify_inst_sparse(priv, image, len);
	if (rc == 0) {
		IWL_DEBUG_INFO("Bootstrap uCode is good in inst SRAM\n");
		return 0;
	}

	/* Try initialize */
	image = (__le32*)priv->ucode_init.v_addr;
	len = priv->ucode_init.len;
	rc = iwl_verify_inst_sparse(priv, image, len);
	if (rc == 0) {
		IWL_DEBUG_INFO("Initialize uCode is good in inst SRAM\n");
		return 0;
	}

	/* Try runtime/protocol */
	image = (__le32*)priv->ucode_code.v_addr;
	len = priv->ucode_code.len;
	rc = iwl_verify_inst_sparse(priv, image, len);
	if (rc == 0) {
		IWL_DEBUG_INFO("Runtime uCode is good in inst SRAM\n");
		return 0;
	}

	IWL_ERROR("NO VALID UCODE IMAGE IN INSTRUCTION SRAM!!\n");

	/* Show first several data entries in instruction SRAM.
	 * Selection of bootstrap image is arbitrary. */
	image = (__le32*)priv->ucode_boot.v_addr;
	len = priv->ucode_boot.len;
	rc = iwl_verify_inst_full(priv, image, len);

	return rc;
}


/* check contents of special bootstrap uCode SRAM */
static int iwl_verify_bsm(struct iwl_priv *priv)
{
	__le32 *image = (__le32*)priv->ucode_boot.v_addr;
	u32 len = priv->ucode_boot.len;
	u32 reg;
	u32 val;

	IWL_DEBUG_INFO("Begin verify bsm\n");

	/* verify BSM SRAM contents */
	val = iwl_read_restricted_reg(priv, BSM_WR_DWCOUNT_REG);
	for (reg = BSM_SRAM_LOWER_BOUND;
	     reg < BSM_SRAM_LOWER_BOUND + len;
	     reg += sizeof(u32), image ++) {
		val = iwl_read_restricted_reg(priv, reg);
		if (val != le32_to_cpu(*image)) {
			IWL_ERROR("BSM uCode verification failed at "
				  "addr 0x%08X+%u (of %u), is 0x%x, s/b 0x%x\n",
				  BSM_SRAM_LOWER_BOUND,
				  reg - BSM_SRAM_LOWER_BOUND, len,
				  val, le32_to_cpu(* image));
			return -EIO;
		}
	}

	IWL_DEBUG_INFO("BSM bootstrap uCode image OK\n");

	return 0;
}

/**
 * iwl_load_bsm - Load bootstrap instructions
 *
 * BSM operation:
 *
 * The Bootstrap State Machine (BSM) stores a short bootstrap uCode program
 * in special SRAM that does not power down during RFKILL.  When powering back
 * up after power-saving sleeps (or during initial uCode load), the BSM loads
 * the bootstrap program into the on-board processor, and starts it.
 *
 * The bootstrap program loads (via DMA) instructions and data for a new
 * program from host DRAM locations indicated by the host driver in the
 * BSM_DRAM_* registers.  Once the new program is loaded, it starts
 * automatically.
 *
 * When initializing the NIC, the host driver points the BSM to the
 * "initialize" uCode image.  This uCode sets up some internal data, then
 * notifies host via "initialize alive" that it is complete.
 *
 * The host then replaces the BSM_DRAM_* pointer values to point to the
 * normal runtime uCode instructions and a backup uCode data cache buffer
 * (filled initially with starting data values for the on-board processor),
 * then triggers the "initialize" uCode to load and launch the runtime uCode,
 * which begins normal operation.
 *
 * When doing a power-save shutdown, runtime uCode saves data SRAM into
 * the backup data cache in DRAM before SRAM is powered down.
 *
 * When powering back up, the BSM loads the bootstrap program.  This reloads
 * the runtime uCode instructions and the backup data cache into SRAM,
 * and re-launches the runtime uCode from where it left off.
 */
static int iwl_load_bsm(struct iwl_priv *priv)
{
	__le32 *image = (__le32*)priv->ucode_boot.v_addr;
	u32 len = priv->ucode_boot.len;
	dma_addr_t pinst;
	dma_addr_t pdata;
	u32 inst_len;
	u32 data_len;
	int rc;
	int i;
	u32 done;
	u32 reg_offset;

	IWL_DEBUG_INFO("Begin load bsm\n");

	/* make sure bootstrap program is no larger than BSM's SRAM size */
	if (len > IWL_MAX_BSM_SIZE)
		return -EINVAL;

	/* Tell bootstrap uCode where to find the "Initialize" uCode
	 *   in host DRAM ... bits 31:0 for 3945, bits 35:4 for 4965.
	 * NOTE:  iwl_initialize_alive_start() will replace these values,
	 *        after the "initialize" uCode has run, to point to
	 *        runtime/protocol instructions and backup data cache. */
#if IWL == 3945
	pinst = priv->ucode_init.p_addr;
	pdata = priv->ucode_init_data.p_addr;
#elif IWL == 4965
	pinst = priv->ucode_init.p_addr >> 4;
	pdata = priv->ucode_init_data.p_addr >> 4;
#endif
	inst_len = priv->ucode_init.len;
	data_len = priv->ucode_init_data.len;

	rc = iwl_grab_restricted_access(priv);
	if (rc)
		return rc;

	iwl_write_restricted_reg(priv, BSM_DRAM_INST_PTR_REG, pinst);
	iwl_write_restricted_reg(priv, BSM_DRAM_DATA_PTR_REG, pdata);
	iwl_write_restricted_reg(priv, BSM_DRAM_INST_BYTECOUNT_REG, inst_len);
	iwl_write_restricted_reg(priv, BSM_DRAM_DATA_BYTECOUNT_REG, data_len);

	/* Fill BSM memory with bootstrap instructions */
	for (reg_offset = BSM_SRAM_LOWER_BOUND;reg_offset < BSM_SRAM_LOWER_BOUND + len;reg_offset += sizeof(u32), image++)
		_iwl_write_restricted_reg(priv, reg_offset, le32_to_cpu(*image));

	rc = iwl_verify_bsm(priv);
	if (rc){
		iwl_release_restricted_access(priv);
		return rc;
	}

	/* Tell BSM to copy from BSM SRAM into instruction SRAM, when asked */
	iwl_write_restricted_reg(priv, BSM_WR_MEM_SRC_REG, 0x0);
	iwl_write_restricted_reg(priv, BSM_WR_MEM_DST_REG, RTC_INST_LOWER_BOUND);
	iwl_write_restricted_reg(priv, BSM_WR_DWCOUNT_REG, len / sizeof(u32));

	/* Load bootstrap code into instruction SRAM now,
	 *   to prepare to load "initialize" uCode */
	iwl_write_restricted_reg(priv, BSM_WR_CTRL_REG,
		BSM_WR_CTRL_REG_BIT_START);

	/* Wait for load of bootstrap uCode to finish */
	for (i = 0; i < 100; i++) {
		done = iwl_read_restricted_reg(priv, BSM_WR_CTRL_REG);
		if (!(done & BSM_WR_CTRL_REG_BIT_START))
			break;
		udelay(10);
	}
	if (i < 100)
		IWL_DEBUG_INFO("BSM write complete, poll %d iterations\n", i);
	else {
		IWL_ERROR("BSM write did not complete!\n");
		return -EIO;
	}

	/* Enable future boot loads whenever power management unit triggers it
	 *   (e.g. when powering back up after power-save shutdown) */
	iwl_write_restricted_reg(priv, BSM_WR_CTRL_REG,
		BSM_WR_CTRL_REG_BIT_START_EN);

	iwl_release_restricted_access(priv);

	return 0;
}

static void iwl_nic_start(struct iwl_priv *priv)
{
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);

	/* Remove all resets to allow NIC to operate */
	iwl_write32(priv, CSR_RESET, 0);

	spin_unlock_irqrestore(&priv->lock, flags);
}

/**
 * iwl_read_ucode - Read uCode images from disk file.
 *
 * Copy into buffers for card to fetch via bus-mastering
 */
struct firmware {
	size_t size;
	u8 data[0];
};

static int iwl_read_ucode(struct iwl_priv *priv)
{
	struct iwl_ucode *ucode;
	int rc = 0;
	//struct firmware *ucode_raw;
	const char *name = "iwlwifi-3945.ucode";	
	u8 *src;
	size_t len;
	u32 ver,inst_size,data_size,init_size,init_data_size,boot_size;

	/* data from ucode file:  header followed by uCode images */
	ucode = (struct iwl_ucode*)ipw_ucode_raw;
	ver = le32_to_cpu(ucode->ver);
	inst_size = le32_to_cpu(ucode->inst_size);
	data_size = le32_to_cpu(ucode->data_size);
	init_size = le32_to_cpu(ucode->init_size);
	init_data_size = le32_to_cpu(ucode->init_data_size);
	boot_size = le32_to_cpu(ucode->boot_size);

	IWL_DEBUG_INFO("f/w package hdr ucode version = 0x%x\n", ver);
	IWL_DEBUG_INFO("f/w package hdr runtime inst size = %u\n",inst_size);
	IWL_DEBUG_INFO("f/w package hdr runtime data size = %u\n",  data_size);
	IWL_DEBUG_INFO("f/w package hdr init inst size = %u\n", init_size);
	IWL_DEBUG_INFO("f/w package hdr init data size = %u\n", init_data_size);
	IWL_DEBUG_INFO("f/w package hdr boot inst size = %u\n", boot_size);

	/* Verify size of file vs. image size info in file's header */
	/*if (ucode_raw->size < sizeof(*ucode) +
		inst_size + data_size + init_size +
		init_data_size + boot_size) {

		IWL_DEBUG_INFO("uCode file size %d too small\n",
			       (int)ucode_raw->size);
		rc = -EINVAL;
		goto err_release;
	}*/

	/* Verify that uCode images will fit in card's SRAM */
	if (inst_size > IWL_MAX_INST_SIZE) {
		IWL_DEBUG_INFO("uCode instr len %d too large to fit in card\n",
			       (int)inst_size);
		rc = -EINVAL;
		goto err_release;
	}

	if (data_size > IWL_MAX_DATA_SIZE) {
		IWL_DEBUG_INFO("uCode data len %d too large to fit in card\n",
			       (int)data_size);
		rc = -EINVAL;
		goto err_release;
	}
	if (init_size > IWL_MAX_INST_SIZE) {
		IWL_DEBUG_INFO
		    ("uCode init instr len %d too large to fit in card\n",
		     (int)init_size);
		rc = -EINVAL;
		goto err_release;
	}
	if (init_data_size > IWL_MAX_DATA_SIZE) {
		IWL_DEBUG_INFO
		    ("uCode init data len %d too large to fit in card\n",
		     (int)init_data_size);
		rc = -EINVAL;
		goto err_release;
	}
	if (boot_size > IWL_MAX_BSM_SIZE) {
		IWL_DEBUG_INFO("uCode boot instr len %d too large to fit in bsm\n",(int)boot_size);
		rc = -EINVAL;
		goto err_release;
	}

	/* Allocate ucode buffers for card's bus-master loading ... */

	/* Runtime instructions and 2 copies of data:
	 * 1) unmodified from disk
	 * 2) backup cache for save/restore during power-downs */
	priv->ucode_code.len = inst_size;
	/*priv->ucode_code.v_addr =
	    pci_alloc_consistent(priv->pci_dev,
				 priv->ucode_code.len,
				 &(priv->ucode_code.p_addr));*/
	MemoryDmaAlloc(priv->ucode_code.len, &(priv->ucode_code.p_addr), &(priv->ucode_code.v_addr));
	//priv->ucode_code.v_addr=IOMallocContiguous( priv->ucode_code.len, sizeof(__le32), &priv->ucode_code.p_addr);
	priv->ucode_data.len = data_size;
	/*priv->ucode_data.v_addr =
	    pci_alloc_consistent(priv->pci_dev,
				 priv->ucode_data.len,
				 &(priv->ucode_data.p_addr));*/
	MemoryDmaAlloc(priv->ucode_data.len, &(priv->ucode_data.p_addr), &(priv->ucode_data.v_addr));
	//priv->ucode_data.v_addr=IOMallocContiguous(priv->ucode_data.len, sizeof(__le32), &priv->ucode_data.p_addr);
	priv->ucode_data_backup.len = data_size;
	/*priv->ucode_data_backup.v_addr =
	    pci_alloc_consistent(priv->pci_dev,
				 priv->ucode_data_backup.len,
				 &(priv->ucode_data_backup.p_addr));*/
	MemoryDmaAlloc(priv->ucode_data_backup.len, &(priv->ucode_data_backup.p_addr), &(priv->ucode_data_backup.v_addr));
	//priv->ucode_data_backup.v_addr=IOMallocContiguous(priv->ucode_data_backup.len, sizeof(__le32), &priv->ucode_data_backup.p_addr);
	/* Initialization instructions and data */
	priv->ucode_init.len = init_size;
	/*priv->ucode_init.v_addr =
	    pci_alloc_consistent(priv->pci_dev,
				 priv->ucode_init.len,
				 &(priv->ucode_init.p_addr));*/
	MemoryDmaAlloc(priv->ucode_init.len, &(priv->ucode_init.p_addr), &(priv->ucode_init.v_addr));
	//priv->ucode_init.v_addr=IOMallocContiguous(priv->ucode_init.len, sizeof(__le32), &priv->ucode_init.p_addr);
	priv->ucode_init_data.len = init_data_size;
	/*priv->ucode_init_data.v_addr =
	    pci_alloc_consistent(priv->pci_dev,
				 priv->ucode_init_data.len,
				 &(priv->ucode_init_data.p_addr));*/
	MemoryDmaAlloc(priv->ucode_init_data.len, &(priv->ucode_init_data.p_addr), &(priv->ucode_init_data.v_addr));
	//priv->ucode_init_data.v_addr=IOMallocContiguous(priv->ucode_init_data.len, sizeof(__le32), &priv->ucode_init_data.p_addr);
	/* Bootstrap (instructions only, no data) */
	priv->ucode_boot.len = boot_size;
	/*priv->ucode_boot.v_addr =
	    pci_alloc_consistent(priv->pci_dev,
				 priv->ucode_boot.len,
				 &(priv->ucode_boot.p_addr));*/
	MemoryDmaAlloc(priv->ucode_boot.len, &(priv->ucode_boot.p_addr), &(priv->ucode_boot.v_addr));
	//priv->ucode_boot.v_addr=IOMallocContiguous(priv->ucode_boot.len, sizeof(__le32), &priv->ucode_boot.p_addr);
	if (!priv->ucode_code.v_addr || !priv->ucode_data.v_addr ||
	    !priv->ucode_init.v_addr || !priv->ucode_init_data.v_addr ||
	    !priv->ucode_boot.v_addr || !priv->ucode_data_backup.v_addr)
		goto err_pci_alloc;

	/* Copy images into buffers for card's bus-master reads ... */

	/* Runtime instructions (first block of data in file) */
	src = &ucode->data[0];
	len = priv->ucode_code.len;
	IWL_DEBUG_INFO("Copying (but not loading) uCode instr len %d\n",
		       (int)len);
	memcpy(priv->ucode_code.v_addr, src, len);
	IWL_DEBUG_INFO("uCode instr buf vaddr = 0x%p, paddr = 0x%08x\n",
		priv->ucode_code.v_addr, (u32)priv->ucode_code.p_addr);

	/* Runtime data (2nd block)
	 * NOTE:  Copy into backup buffer will be done in iwl_up()  */
	src = &ucode->data[inst_size];
	len = priv->ucode_data.len;
	IWL_DEBUG_INFO("Copying (but not loading) uCode data len %d\n",
		       (int)len);
	memcpy(priv->ucode_data.v_addr, src, len);
	memcpy(priv->ucode_data_backup.v_addr, src, len);

	/* Initialization instructions (3rd block) */
	if (init_size) {
		src = &ucode->data[inst_size + data_size];
		len = priv->ucode_init.len;
		IWL_DEBUG_INFO("Copying (but not loading) init instr len %d\n",
			       (int)len);
		memcpy(priv->ucode_init.v_addr, src, len);
	}

	/* Initialization data (4th block) */
	if (init_data_size) {
		src = &ucode->data[inst_size + data_size + init_size];
		len = priv->ucode_init_data.len;
		IWL_DEBUG_INFO("Copying (but not loading) init data len %d\n",
			       (int)len);
		memcpy(priv->ucode_init_data.v_addr, src, len);
	}

	/* Bootstrap instructions (5th block) */
	src = &ucode->data[inst_size + data_size + init_size + init_data_size];
	len = priv->ucode_boot.len;
	IWL_DEBUG_INFO("Copying (but not loading) boot instr len %d\n",
		       (int)len);
	memcpy(priv->ucode_boot.v_addr, src, len);

	/* We have our copies now, allow OS release its copies */
	return 0;

 err_pci_alloc:


 err_release:
	//release_firmware(ucode_raw);

 error:
	return rc;
}


/**
 * iwl_set_ucode_ptrs - Set uCode address location
 *
 * Tell initialization uCode where to find runtime uCode.
 *
 * BSM registers initially contain pointers to initialization uCode.
 * We need to replace them to load runtime uCode inst and data,
 * and to save runtime data when powering down.
 */
static int iwl_set_ucode_ptrs(struct iwl_priv *priv)
{
	dma_addr_t pinst;
	dma_addr_t pdata;
	int rc = 0;
	unsigned long flags;

#if IWL == 3945
	/* bits 31:0 for 3945 */
	pinst = priv->ucode_code.p_addr;
	pdata = priv->ucode_data_backup.p_addr;
#else
	/* bits 35:4 for 4965 */
	pinst = priv->ucode_code.p_addr >> 4;
	pdata = priv->ucode_data_backup.p_addr >> 4;
#endif

	spin_lock_irqsave(&priv->lock, flags);
	rc = iwl_grab_restricted_access(priv);
	if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}

	/* Tell bootstrap uCode where to find image to load */
	iwl_write_restricted_reg(priv, BSM_DRAM_INST_PTR_REG, pinst);
	iwl_write_restricted_reg(priv, BSM_DRAM_DATA_PTR_REG, pdata);
	iwl_write_restricted_reg(priv, BSM_DRAM_DATA_BYTECOUNT_REG,
				 priv->ucode_data.len);

	/* Inst bytecount must be last to set up, bit 31 signals uCode
	 *   that all new ptr/size info is in place */
	iwl_write_restricted_reg(priv, BSM_DRAM_INST_BYTECOUNT_REG,
				 priv->ucode_code.len | 0x80000000);

	iwl_release_restricted_access(priv);

	spin_unlock_irqrestore(&priv->lock, flags);

	IWL_DEBUG_INFO("Runtime uCode pointers are set.\n");

	return rc;
}

/**
 * iwl_init_alive_start - Called after REPLY_ALIVE notification receieved
 *
 * Called after REPLY_ALIVE notification received from "initialize" uCode.
 *
 * The 4965 "initialize" ALIVE reply contains calibration data for:
 *   Voltage, temperature, and MIMO tx gain correction, now stored in priv
 *   (3945 does not contain this data).
 *
 * Tell "initialize" uCode to go ahead and load the runtime uCode.
*/
static void iwl_init_alive_start(struct iwl_priv *priv)
{
	/* Check alive response for "valid" sign from uCode */
	if (priv->card_alive_init.is_valid != 1) {
		/* We had an error bringing up the hardware, so take it
		 * all the way back down so we can try again */
		IWL_ERROR("Initialize Alive failed.\n");
		goto restart;
	}

	/* Bootstrap uCode has loaded initialize uCode ... verify inst image.
	 * This is a paranoid check, because we would not have gotten the
	 * "initialize" alive if code weren't properly loaded.  */
	if (iwl_verify_ucode(priv)) {
		/* Runtime instruction load was bad;
		 * take it all the way back down so we can try again */
		IWL_ERROR("Bad \"initialize\" uCode load.\n");
		goto restart;
	}

#if IWL == 4965
	/* Calculate temperature */
	priv->temperature = iwl4965_get_temperature(priv);
#endif

	/* Send pointers to protocol/runtime uCode image ... init code will
	 * load and launch runtime uCode, which will send us another "Alive"
	 * notification. */
	IWL_DEBUG_INFO("Initialization Alive received.\n");
	if (iwl_set_ucode_ptrs(priv)) {
		/* Runtime instruction load won't happen;
		 * take it all the way back down so we can try again */
		IWL_ERROR("Couldn't set up uCode pointers.\n");
		goto restart;
	}
	return;

 restart:
	//queue_work(priv->workqueue, &priv->restart);
	clone->queue_te(1,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_restart),priv,NULL,true);
}


/**
 * iwl_alive_start - called after REPLY_ALIVE notification received
 *                   from protocol/runtime uCode (initialization uCode's
 *                   Alive gets handled by iwl_init_alive_start()).
 */
static void iwl_alive_start(struct iwl_priv *priv)
{
	int rc = 0;
#if IWL == 3945
	int thermal_spin = 0;
	u32 rfkill;
#endif

	IWL_DEBUG_INFO("Runtime Alive received.\n");

	if (priv->card_alive.is_valid != 1) {
		/* We had an error bringing up the hardware, so take it
		 * all the way back down so we can try again */
		IWL_ERROR("Alive failed.\n");
		goto restart;
	}

	/* Initialize uCode has loaded Runtime uCode ... verify inst image.
	 * This is a paranoid check, because we would not have gotten the
	 * "runtime" alive if code weren't properly loaded.  */
	if (iwl_verify_ucode(priv)) {
		IWL_ERROR("Bad runtime uCode load.\n");
		goto restart;
	}

	iwl_clear_stations_table(priv);

#if IWL == 4965
	rc = iwl4965_alive_notify(priv);
	if (rc) {
		IWL_WARNING("Could not complete ALIVE transition [ntf]: %d\n",
			    rc);
		goto restart;
	}
#elif IWL == 3945
	rc = iwl_grab_restricted_access(priv);
	if (rc) {
		IWL_WARNING("Can not read rfkill status from adapter\n");
		return;
	}

	rfkill = iwl_read_restricted_reg(priv, ALM_APMG_RFKILL);
	IWL_DEBUG_INFO("RFKILL status: 0x%x\n", rfkill);
	iwl_release_restricted_access(priv);

	if (rfkill & 0x1) {
		priv->status &= ~STATUS_RF_KILL_HW;
		/* if rfkill is not on, then wait for thermal
		 * sensor in adapter to kick in */
		while (iwl_hw_get_temperature(priv) == 0) {
			thermal_spin++;
			udelay(10);
		}

		if (thermal_spin)
			IWL_DEBUG_INFO("Thermal calibration took %dus\n",
				       thermal_spin * 10);
	} else
	{
		priv->status |= STATUS_RF_KILL_HW;
		IWL_WARNING("STATUS_RF_KILL_HW enabled\n");
	}
#endif

	/* After the ALIVE response, we can process host commands */
	priv->status |= STATUS_ALIVE;

	/* Clear out the uCode error bit if it is set */
	priv->status &= ~STATUS_FW_ERROR;
	rc = iwl_init_channel_map(priv);
	if (rc) {
		IWL_ERROR("initializing regulatory failed: %d\n", rc);
		return;
	}
	iwl_init_geos(priv);

	if (priv->status & STATUS_RF_KILL_MASK)
	{
		IWL_WARNING("STATUS_RF_KILL_MASK enabled - cancel iwl_alive_start\n");
		return;
	}

	if (!priv->mac80211_registered) {
		/* Unlock so any user space entry points can call back into
		 * the driver without a deadlock... */
		mutex_unlock(&priv->mutex);
		iwl_rate_control_register();
		rc = ieee80211_register_hw(priv->hw);
		priv->hw->conf.beacon_int = 100;
		mutex_lock(&priv->mutex);

		if (rc) {
			IWL_ERROR("Failed to register network "
				  "device (error %d)\n", rc);
			return;
		}

		priv->mac80211_registered = 1;
		iwl_reset_channel_flag(priv);
	} else
		ieee80211_start_queues(priv->hw);

	priv->active_rate = priv->rates_mask;
	priv->active_rate_basic = priv->rates_mask & IWL_BASIC_RATES_MASK;
	//iwl_send_power_mode(priv, IWL_POWER_LEVEL(priv->power_mode));
	//priv->status &= ~STATUS_POWER_PMI;//hack iwl_send_power_mode
	
        if (iwl_is_associated(priv)) {
		struct iwl_rxon_cmd *active_rxon =
				(struct iwl_rxon_cmd *)(&priv->active_rxon);

		memcpy(&priv->staging_rxon, &priv->active_rxon,
			sizeof(priv->staging_rxon));
		active_rxon->filter_flags &= ~RXON_FILTER_ASSOC_MSK;
	} else {
		/* Initialize our rx_config data */
		iwl_connection_init_rx_config(priv);
		memcpy(priv->staging_rxon.node_addr, priv->mac_addr, ETH_ALEN);
	}
	/* Configure BT coexistence */
	iwl_send_bt_config(priv);
	/* Configure the adapter for unassociated operation */
	iwl_commit_rxon(priv);

	/* At this point, the NIC is initialized and operational */
	priv->notif_missed_beacons = 0;
	priv->status |= STATUS_READY;
	iwl3945_reg_txpower_periodic(priv);

#if IWL == 4965
	iwl4965_rf_kill_ct_config(priv);
#endif
	IWL_DEBUG_INFO("ALIVE processing complete.\n");
	if (priv->error_recovering)	iwl_error_recovery(priv);
	
	return;

 restart:
	//queue_work(priv->workqueue, &priv->restart);
	clone->queue_te(1,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_restart),priv,NULL,true);
}



void iwl_down(struct iwl_priv *priv)
{
	unsigned long flags;
	int exit_pending = priv->status & STATUS_EXIT_PENDING;
	struct ieee80211_conf *conf = NULL;

	IWL_WARNING("ipw going down \n");

	conf = ieee80211_get_hw_conf(priv->hw);

	priv->status |= STATUS_EXIT_PENDING;

	iwl_clear_stations_table(priv);

	/* Unblock any waiting calls */
	//wake_up_interruptible_all(&priv->wait_command_queue);

	iwl_cancel_deferred_work(priv);

	/* Wipe out the EXIT_PENDING status bit if we are not actually
	 * exiting the module */
	if (!exit_pending)
		priv->status &= ~STATUS_EXIT_PENDING;

	/* stop and reset the on-board processor */
	iwl_write32(priv, CSR_RESET, CSR_RESET_REG_FLAG_NEVO_RESET);

	/* tell the device to stop sending interrupts */
	iwl_disable_interrupts(priv);

	if (priv->mac80211_registered)
	ieee80211_stop_queues(priv->hw);

	/* If we have not previously called iwl_init() then
	 * clear all bits but the RF Kill and SUSPEND bits and return */
	if (!iwl_is_init(priv)) {
		priv->status &= (STATUS_RF_KILL_MASK | STATUS_IN_SUSPEND);
		goto exit;
	}

	/* ...otherwise clear out all the status bits but the RF Kill and
	 * SUSPEND bits and continue taking the NIC down. */
	priv->status &=
	    (STATUS_RF_KILL_MASK | STATUS_IN_SUSPEND | STATUS_FW_ERROR);

	spin_lock_irqsave(&priv->lock, flags);
	iwl_clear_bit(priv, CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
	spin_unlock_irqrestore(&priv->lock, flags);

	iwl_hw_txq_ctx_stop(priv);
	iwl_hw_rxq_stop(priv);

	spin_lock_irqsave(&priv->lock, flags);
	if (!iwl_grab_restricted_access(priv)) {
		iwl_write_restricted_reg(priv, ALM_APMG_CLK_DIS,
					 APMG_CLK_REG_VAL_DMA_CLK_RQT);
		iwl_release_restricted_access(priv);
	}
	spin_unlock_irqrestore(&priv->lock, flags);

	udelay(5);

	iwl_hw_nic_stop_master(priv);

	spin_lock_irqsave(&priv->lock, flags);
	iwl_set_bit(priv, CSR_RESET, CSR_RESET_REG_FLAG_SW_RESET);
	spin_unlock_irqrestore(&priv->lock, flags);

	iwl_hw_nic_reset(priv);

 exit:
	memset(&priv->card_alive, 0, sizeof(struct iwl_alive_resp));

	if (priv->ibss_beacon)
	if (!(mbuf_type(priv->ibss_beacon) == MBUF_TYPE_FREE)) 
		mbuf_freem(priv->ibss_beacon);
	priv->ibss_beacon = NULL;

	/* clear out any free frames */
	iwl_clear_free_frames(priv);
}

#define MAX_HW_RESTARTS 5

int iwl_up(struct iwl_priv *priv)
{
	int rc, i;
	u32 hw_rf_kill = 0;

	if (priv->status & STATUS_EXIT_PENDING) {
		IWL_WARNING("Exit pending; will not bring the NIC up\n");
		return -EIO;
	}

	if (priv->status & STATUS_RF_KILL_SW) {
		IWL_WARNING("Radio disabled by SW RF kill (module "
			    "parameter)\n");
		return 0;
	}


	iwl_write32(priv, CSR_INT, 0xFFFFFFFF);


	rc = iwl_hw_nic_init(priv);
	if (rc) {
		IWL_ERROR("Unable to int nic\n");
		return rc;
	}

	/* make sure rfkill handshake bits are cleared */
	iwl_write32(priv, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	iwl_write32(priv, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);

	/* clear (again), then enable host interrupts */
	iwl_write32(priv, CSR_INT, 0xFFFFFFFF);
	iwl_enable_interrupts(priv);

	/* really make sure rfkill handshake bits are cleared */
	iwl_write32(priv, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	iwl_write32(priv, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);

	/* Copy original ucode data image from disk into backup cache.
	 * This will be used to initialize the on-board processor's
	 * data SRAM for a clean start when the runtime program first loads. */
	memcpy(priv->ucode_data_backup.v_addr, priv->ucode_data.v_addr,priv->ucode_data.len);

	/* If platform's RF_KILL switch is set to KILL, wait for BIT_INT_RF_KILL
	 *   interrupt before loading uCode and getting things started */
	if (!(iwl_read32(priv, CSR_GP_CNTRL) &
	     CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW))
		hw_rf_kill = 1;

	if ((priv->status & STATUS_RF_KILL_HW) || hw_rf_kill) {
		IWL_WARNING("Radio disabled by HW RF Kill switch -> REBOOT FROM WINDOWS WITH CARD POWERED ON\n");
		return 0;
	}

	for (i = 0; i < MAX_HW_RESTARTS; i++) {

		iwl_clear_stations_table(priv);

		/* load bootstrap state machine,
		 * load bootstrap program into processor's memory,
		 * prepare to load the "initialize" uCode */
		rc = iwl_load_bsm(priv);
		if (rc) {
			IWL_ERROR("Unable to set up bootstrap uCode: %d\n", rc);
			continue;
		}

		/* start card; "initialize" will load runtime ucode */
		iwl_nic_start(priv);

		/* MAC Address location in EEPROM same for 3945/4965 */
		get_eeprom_mac(priv, priv->mac_addr);
		IWL_DEBUG_INFO("MAC address: " MAC_FMT "\n",
			       MAC_ARG(priv->mac_addr));

		//SET_IEEE80211_PERM_ADDR(priv->hw, priv->mac_addr);
		return 0;
	}

	priv->status |= STATUS_EXIT_PENDING;
	iwl_down(priv);

	/* tried to restart and config the device for as long as our
	 * patience could withstand */
	IWL_ERROR("Unable to initialize device after %d attempts.\n", i);
	return -EIO;
}


/*****************************************************************************
 *
 * Workqueue callbacks
 *
 *****************************************************************************/

void darwin_iwi3945::iwl_bg_init_alive_start(struct iwl_priv *priv)
{
	//struct iwl_priv *priv =
	//    container_of(data, struct iwl_priv, init_alive_start.work);

	if (priv->status & STATUS_EXIT_PENDING)
		return;

	mutex_lock(&priv->mutex);
	iwl_init_alive_start(priv);
	mutex_unlock(&priv->mutex);
}

void darwin_iwi3945::iwl_bg_alive_start(struct iwl_priv *priv)
{
	//struct iwl_priv *priv =
	//    container_of(data, struct iwl_priv, alive_start.work);

	if (priv->status & STATUS_EXIT_PENDING)
		return;

	mutex_lock(&priv->mutex);
	iwl_alive_start(priv);
	mutex_unlock(&priv->mutex);
}

void darwin_iwi3945::iwl_bg_rf_kill(struct iwl_priv *priv)
{
	//struct iwl_priv *priv = container_of(work, struct iwl_priv, rf_kill);

	wake_up_interruptible(&priv->wait_command_queue);

	if (priv->status & STATUS_EXIT_PENDING)
		return;

	mutex_lock(&priv->mutex);

	if (!(priv->status & STATUS_RF_KILL_MASK)) {
		IWL_DEBUG(IWL_DL_INFO | IWL_DL_RF_KILL,
			  "HW and/or SW RF Kill no longer active, restarting "
			  "device\n");
		if (!(priv->status & STATUS_EXIT_PENDING))
			//queue_work(priv->workqueue, &priv->restart);
			clone->queue_te(1,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_restart),priv,NULL,true);
	} else {

		if (!(priv->status & STATUS_RF_KILL_HW))
			IWL_DEBUG_RF_KILL
			    ("Can not turn radio back on - "
			     "disabled by SW switch\n");
		else
			IWL_WARNING
			    ("Radio Frequency Kill Switch is On:\n"
			     "Kill switch must be turned off for "
			     "wireless networking to work.\n");
	}
	mutex_unlock(&priv->mutex);
}

#define IWL_SCAN_CHECK_WATCHDOG (7 * HZ)

void darwin_iwi3945::iwl_bg_scan_check(struct iwl_priv *priv)
{
	//struct iwl_priv *priv =
	//    container_of(data, struct iwl_priv, scan_check.work);

	if (priv->status & STATUS_EXIT_PENDING)
		return;

	mutex_lock(&priv->mutex);
	if (priv->status & (STATUS_SCANNING | STATUS_SCAN_ABORTING)) {
		IWL_DEBUG(IWL_DL_INFO | IWL_DL_SCAN,
			  "Scan completion watchdog resetting "
			  "adapter (%dms).\n",
			  jiffies_to_msecs(IWL_SCAN_CHECK_WATCHDOG));
		if (!(priv->status & STATUS_EXIT_PENDING))
			//queue_work(priv->workqueue, &priv->restart);
			clone->queue_te(1,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_restart),priv,NULL,true);
	}
	mutex_unlock(&priv->mutex);
}

void darwin_iwi3945::iwl_bg_request_scan(struct iwl_priv *priv)
{
	//struct iwl_priv *priv =
	//    container_of(data, struct iwl_priv, request_scan);
	struct iwl_host_cmd cmd;// = {
	memset(&cmd,0,sizeof(struct iwl_host_cmd));
		cmd.id = REPLY_SCAN_CMD;
		cmd.len = sizeof(struct iwl_scan_cmd);
		cmd.meta.flags = CMD_SIZE_HUGE;

	int rc = 0;
	struct iwl_scan_cmd *scan;
	struct ieee80211_conf *conf = NULL;
	u8 direct_mask;
	int phymode;

	conf = ieee80211_get_hw_conf(priv->hw);

	mutex_lock(&priv->mutex);

	if (!iwl_is_ready(priv)) {
		IWL_WARNING("request scan called when driver not ready.\n");
		goto done;
	}

	/* Make sure the scan wasn't cancelled before this queued work
	 * was given the chance to run... */
	if (!(priv->status & STATUS_SCANNING))
		goto done;

	/* This should never be called or scheduled if there is currently
	 * a scan active in the hardware. */
	if (priv->status & STATUS_SCAN_HW) {
		IWL_DEBUG_INFO
		    ("Multiple concurrent scan requests in parallel. "
		     "Ignoring second request.\n");
		rc = -EIO;
		goto done;
	}

	if (priv->status & STATUS_EXIT_PENDING) {
		IWL_DEBUG_SCAN("Aborting scan due to device shutdown\n");
		goto done;
	}

	if (priv->status & STATUS_SCAN_ABORTING) {
		IWL_DEBUG_HC("Scan request while abort pending.  Queuing.\n");
		goto done;
	}

	if (priv->status & STATUS_RF_KILL_MASK) {
		IWL_DEBUG_HC("Aborting scan due to RF Kill activation\n");
		goto done;
	}

	if (!(priv->status & STATUS_READY)) {
		IWL_DEBUG_HC("Scan request while uninitialized.  Queuing.\n");
		goto done;
	}

	if (!priv->scan_bands) {
		IWL_DEBUG_HC("Aborting scan due to no requested bands\n");
		goto done;
	}

	if (!priv->scan) {
		priv->scan = (struct iwl_scan_cmd*)IOMalloc(sizeof(struct iwl_scan_cmd) +IWL_MAX_SCAN_SIZE);
		memset(priv->scan,0,sizeof(struct iwl_scan_cmd) +IWL_MAX_SCAN_SIZE);
		if (!priv->scan) {
			rc = -ENOMEM;
			goto done;
		}
	}
	scan = priv->scan;
	memset(scan, 0, sizeof(struct iwl_scan_cmd) + IWL_MAX_SCAN_SIZE);

	scan->quiet_plcp_th = IWL_PLCP_QUIET_THRESH;
	scan->quiet_time = IWL_ACTIVE_QUIET_TIME;

	if (iwl_is_associated(priv)) {
		u16 interval = 0;
		u32 extra;
		u32 suspend_time = 100;
		unsigned long flags;

		IWL_DEBUG_INFO("Scanning while associated...\n");

		spin_lock_irqsave(&priv->lock, flags);
		interval = priv->beacon_int;
		spin_unlock_irqrestore(&priv->lock, flags);

		scan->suspend_time = 0;
		scan->max_out_time = 600 * 1024;
		if (interval) {
#if IWL == 3945
			/*
			 * suspend time format:
			 *  0-19: beacon interval in usec (time before exec.)
			 * 20-23: 0
			 * 24-31: number of beacons (suspend between channels)
			 */

			extra = (suspend_time / interval) << 24;
			scan->suspend_time = 0xFF0FFFFF &
			    (extra | ((suspend_time % interval) * 1024));
#else
			extra = (suspend_time / interval) << 22;
			scan->suspend_time = (extra |
			    ((suspend_time % interval) * 1024));
			IWL_DEBUG_SCAN("suspend_time 0x%X beacon interval %d\n",
				       scan->suspend_time, interval);
#endif
		}
	}

	/* We should add the ability for user to lock to PASSIVE ONLY */
	if (priv->one_direct_scan) {
		IWL_DEBUG_SCAN
		    ("Kicking off one direct scan for '%s'\n",
		     iwl_escape_essid((const char *)priv->direct_ssid,
				      priv->direct_ssid_len));
		scan->direct_scan[0].id = WLAN_EID_SSID;
		scan->direct_scan[0].len = priv->direct_ssid_len;
		memcpy(scan->direct_scan[0].ssid,
		       priv->direct_ssid, priv->direct_ssid_len);
		direct_mask = 1;
	} else if (!iwl_is_associated(priv)) {
		scan->direct_scan[0].id = WLAN_EID_SSID;
		scan->direct_scan[0].len = priv->essid_len;
		memcpy(scan->direct_scan[0].ssid, priv->essid, priv->essid_len);
		direct_mask = 1;
	} else {
		direct_mask = 0;
	}

	/* We don't build a direct scan probe request; the uCode will do
	 * that based on the direct_mask added to each channel entry */
	scan->tx_cmd.len =
	    iwl_fill_probe_req(priv, (struct ieee80211_mgmt *)scan->data,
			       IWL_MAX_SCAN_SIZE - sizeof(scan), 0);
	scan->tx_cmd.tx_flags = TX_CMD_FLG_SEQ_CTL_MSK;
	scan->tx_cmd.sta_id = IWL_BROADCAST_ID;
	scan->tx_cmd.stop_time.life_time = TX_CMD_LIFE_TIME_INFINITE;

	/* flags + rate selection */

#if IWL == 4965
	scan->tx_cmd.tx_flags |= 0x200;
#endif

	switch (priv->scan_bands) {
	case 2:
		scan->flags = RXON_FLG_BAND_24G_MSK | RXON_FLG_AUTO_DETECT_MSK;
#if IWL == 3945
		scan->tx_cmd.rate = IWL_RATE_1M_PLCP;
#elif IWL == 4965
		scan->tx_cmd.rate.s.rate = IWL_RATE_1M_PLCP;
		scan->tx_cmd.rate.s.flags = 0x80 | 0x2;
#endif
		scan->good_CRC_th = 0;
		phymode = MODE_IEEE80211G;
		break;

	case 1:
#if IWL == 3945
		scan->tx_cmd.rate = IWL_RATE_6M_PLCP;
#elif IWL == 4965
		scan->tx_cmd.rate.s.rate = IWL_RATE_6M_PLCP;
		scan->tx_cmd.rate.s.flags = 0x80;
#endif
		scan->good_CRC_th = IWL_GOOD_CRC_TH;
		phymode = MODE_IEEE80211A;
		break;

	default:
		IWL_WARNING("Invalid scan band count\n");
		goto done;
	}

	/* select Rx antennas/chains */
#if IWL == 3945
	scan->flags |= iwl3945_get_antenna_flags(priv);

#elif IWL == 4965
	/* Force use of chains B and C (0x6) for scan Rx.
	 * Avoid A (0x1) because of its off-channel reception on A-band.
	 * MIMO is not used here, but value is required to make uCode happy. */
	scan->rx_chain = RXON_RX_CHAIN_DRIVER_FORCE_MSK |
			(0x7 << RXON_RX_CHAIN_VALID_POS) |
			(0x6 << RXON_RX_CHAIN_FORCE_SEL_POS) |
			(0x7 << RXON_RX_CHAIN_FORCE_MIMO_SEL_POS);
#endif

	if (priv->iw_mode == IEEE80211_IF_TYPE_MNTR)
		scan->filter_flags = RXON_FILTER_PROMISC_MSK;

	if (direct_mask)
		IWL_DEBUG_SCAN
		    ("Initiating direct scan for %s.\n",
		     iwl_escape_essid((const char *)priv->essid, priv->essid_len));
	else
		IWL_DEBUG_SCAN("Initiating indirect scan.\n");

	scan->channel_count =
		iwl_get_channels_for_scan(
			priv, phymode, 1, /* active */
			direct_mask, (struct iwl_scan_channel *)&scan->data[scan->tx_cmd.len]);

	cmd.len += scan->tx_cmd.len +
	    scan->channel_count * sizeof(struct iwl_scan_channel);
	cmd.data = scan;
	scan->len = cmd.len;

	priv->status |= STATUS_SCAN_HW;
	rc = iwl_send_cmd(priv, &cmd);
	if (rc)
		goto done;

	//queue_delayed_work(priv->workqueue, &priv->scan_check, IWL_SCAN_CHECK_WATCHDOG);
	clone->queue_te(10,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_scan_check),priv,IWL_SCAN_CHECK_WATCHDOG,true);

	priv->status &= ~STATUS_SCAN_PENDING;

	mutex_unlock(&priv->mutex);
	return;

 done:
	/* inform mac80211 sacn aborted */
	//queue_work(priv->workqueue, &priv->scan_completed);
	clone->queue_te(3,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_scan_completed),priv,NULL,true);
	mutex_unlock(&priv->mutex);
}

void darwin_iwi3945::iwl_bg_up(struct iwl_priv *priv)
{
	//struct iwl_priv *priv = container_of(data, struct iwl_priv, up);

	if (priv->status & STATUS_EXIT_PENDING)
		return;

	mutex_lock(&priv->mutex);
	iwl_up(priv);
	mutex_unlock(&priv->mutex);
}

void darwin_iwi3945::iwl_bg_restart(struct iwl_priv *priv)
{
	//struct iwl_priv *priv = container_of(data, struct iwl_priv, restart);

	if (priv->status & STATUS_EXIT_PENDING)
		return;

	mutex_lock(&priv->mutex);
	iwl_down(priv);
	mutex_unlock(&priv->mutex);

	//queue_work(priv->workqueue, &priv->up);
	IWL_WARNING("iwl_bg_restart -> going up cause kernel panic \n");
	iwl_bg_up(priv);
	//clone->queue_te(0,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_up),priv,NULL,true);
}

void darwin_iwi3945::iwl_bg_rx_replenish(struct iwl_priv *priv)
{
	//struct iwl_priv *priv =
	//    container_of(data, struct iwl_priv, rx_replenish);

	if (priv->status & STATUS_EXIT_PENDING)
		return;

	mutex_lock(&priv->mutex);
	iwl_rx_replenish(priv, 1);
	mutex_unlock(&priv->mutex);
}

void darwin_iwi3945::iwl_bg_post_associate(struct iwl_priv *priv)
{
	//struct iwl_priv *priv = container_of(data, struct iwl_priv,
	//				     post_associate.work);

	int rc = 0;
	struct ieee80211_conf *conf = NULL;

	IWL_DEBUG_ASSOC("Associated as %d to: " MAC_FMT "\n",
			priv->assoc_id, MAC_ARG(priv->active_rxon.bssid_addr));

	if (priv->status & STATUS_EXIT_PENDING)
		return;

	mutex_lock(&priv->mutex);

	conf = ieee80211_get_hw_conf(priv->hw);

	priv->staging_rxon.filter_flags &= ~RXON_FILTER_ASSOC_MSK;
	iwl_commit_rxon(priv);

	memset(&priv->rxon_timing, 0, sizeof(struct iwl_rxon_time_cmd));
	iwl_setup_rxon_timing(priv);
	rc = iwl_send_cmd_pdu(priv, REPLY_RXON_TIMING,
			      sizeof(priv->rxon_timing), &priv->rxon_timing);
	if (rc)
		IWL_WARNING("REPLY_RXON_TIMING failed - "
			    "Attempting to continue.\n");

	priv->staging_rxon.filter_flags |= RXON_FILTER_ASSOC_MSK;

#if IWL == 4965
#ifdef CONFIG_IWLWIFI_HT
	if (priv->is_ht_enabled && priv->current_assoc_ht.is_ht)
		iwl4965_set_rxon_ht(priv, &priv->current_assoc_ht);
	else {
		priv->active_rate_ht[0] = 0;
		priv->active_rate_ht[1] = 0;
		priv->current_channel_width = IWL_CHANNEL_WIDTH_20MHZ;
	}
#endif /* CONFIG_IWLWIFI_HT*/
	iwl4965_set_rxon_chain(priv);
#endif
	priv->staging_rxon.assoc_id = priv->assoc_id;

	IWL_DEBUG_ASSOC("assoc id %d beacon interval %d\n",
			priv->assoc_id, priv->beacon_int);

	if (priv->assoc_capability & WLAN_CAPABILITY_SHORT_PREAMBLE)
		priv->staging_rxon.flags |= RXON_FLG_SHORT_PREAMBLE_MSK;
	else
		priv->staging_rxon.flags &= ~RXON_FLG_SHORT_PREAMBLE_MSK;

	if (priv->staging_rxon.flags & RXON_FLG_BAND_24G_MSK) {
		if (priv->assoc_capability & WLAN_CAPABILITY_SHORT_SLOT_TIME)
			priv->staging_rxon.flags |= RXON_FLG_SHORT_SLOT_MSK;
		else
			priv->staging_rxon.flags &= ~RXON_FLG_SHORT_SLOT_MSK;

		if (priv->iw_mode == IEEE80211_IF_TYPE_IBSS)
			priv->staging_rxon.flags &= ~RXON_FLG_SHORT_SLOT_MSK;

	}

	iwl_commit_rxon(priv);

	switch (priv->iw_mode) {
	case IEEE80211_IF_TYPE_STA:
		iwl_sync_station(priv, IWL_AP_ID,
				 ((priv->phymode == MODE_IEEE80211A) ||
				  (priv->phymode == MODE_ATHEROS_TURBO)) ?
				 IWL_RATE_6M_PLCP : IWL_RATE_1M_PLCP,
				 CMD_ASYNC);
		iwl_rate_scale_init(priv->hw, IWL_AP_ID);

		break;

	case IEEE80211_IF_TYPE_IBSS:

		/* clear out the station table */
		iwl_clear_stations_table(priv);

		iwl_rxon_add_station(priv, BROADCAST_ADDR, 0);
		iwl_rxon_add_station(priv, priv->bssid, 0);

		iwl_sync_station(priv, IWL_STA_ID,
				 ((priv->phymode == MODE_IEEE80211A) ||
				  (priv->phymode == MODE_ATHEROS_TURBO)) ?
				 IWL_RATE_6M_PLCP : IWL_RATE_1M_PLCP,
				 CMD_ASYNC);
		iwl_rate_scale_init(priv->hw, IWL_STA_ID);
		iwl_send_beacon_cmd(priv);

		break;

	case IEEE80211_IF_TYPE_AP:

		/* clear out the station table */
		iwl_clear_stations_table(priv);

		iwl_rxon_add_station(priv, BROADCAST_ADDR, 0);
		iwl_send_beacon_cmd(priv);

		break;
	}

	/* FIXME: not sure why this doesn't work in AP mode */
	if (priv->iw_mode != IEEE80211_IF_TYPE_AP)
		iwl_sequence_reset(priv);

#if IWL == 4965
#ifdef CONFIG_IWLWIFI_SENSITIVITY
	/* Enable Rx differential gain and sensitivity calibrations */
	iwl4965_chain_noise_reset(priv);
	priv->start_calib = 1;
#endif /* CONFIG_IWLWIFI_SENSITIVITY */
#endif /* IWL == 4965 */

	if (priv->iw_mode == IEEE80211_IF_TYPE_IBSS)
		priv->assoc_station_added = 1;

	mutex_unlock(&priv->mutex);
}

void darwin_iwi3945::iwl_bg_abort_scan(struct iwl_priv *priv)
{
	//struct iwl_priv *priv = container_of(work, struct iwl_priv,
	//				     abort_scan);

	if (!iwl_is_ready(priv))
		return;

	mutex_lock(&priv->mutex);
	priv->status &= ~STATUS_SCAN_PENDING;
	priv->status |= STATUS_SCAN_ABORTING;

	iwl_send_scan_abort(priv);

	mutex_unlock(&priv->mutex);
}

void darwin_iwi3945::iwl_bg_scan_completed(struct iwl_priv *priv)
{
	//struct iwl_priv *priv =
	  //  container_of(work, struct iwl_priv, scan_completed);

	IWL_DEBUG(IWL_DL_INFO | IWL_DL_SCAN, "SCAN complete scan\n");

	if (priv->status & STATUS_EXIT_PENDING)
		return;

	ieee80211_scan_completed(priv->hw);

	/* Since setting the TXPOWER may have been deferred while
	 * performing the scan, fire one off */
	mutex_lock(&priv->mutex);
	iwl_hw_reg_send_txpower(priv);
	mutex_unlock(&priv->mutex);
}

/*****************************************************************************
 *
 * mac80211 entry point functions
 *
 *****************************************************************************/

static int d_open(struct ieee80211_hw *hw)
{
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;

	IWL_DEBUG_MAC80211("enter\n");

	/* we should be verifying the device is ready to be opened */
	mutex_lock(&priv->mutex);

	priv->is_open = 1;

	if (!(priv->status & STATUS_RF_KILL_MASK))
	ieee80211_start_queues(priv->hw);

	mutex_unlock(&priv->mutex);
	IWL_DEBUG_MAC80211("leave\n");
	return 0;
}

static int d_stop(struct ieee80211_hw *hw)
{
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;

	IWL_DEBUG_MAC80211("enter\n");
	priv->is_open = 0;
	/*netif_stop_queue(dev); */
	flush_workqueue(priv->workqueue);
	IWL_DEBUG_MAC80211("leave\n");

	return 0;
}

static int d_tx(struct ieee80211_hw *hw,
		mbuf_t skb, struct ieee80211_tx_control *ctl)
{
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;

	IWL_DEBUG_MAC80211("enter\n");

	if (priv->iw_mode == IEEE80211_IF_TYPE_MNTR) {
		IWL_DEBUG_MAC80211("leave - monitor\n");
		return -1;
	}

	IWL_DEBUG_TX("dev->xmit(%d bytes) at rate 0x%02x\n", mbuf_len(skb),
		     ctl->tx_rate);

	if (iwl_tx_skb(priv, skb, ctl))
	if (skb)
	if (!(mbuf_type(skb) == MBUF_TYPE_FREE)) 
		mbuf_freem(skb);
	skb=NULL;
	IWL_DEBUG_MAC80211("leave\n");
	return 0;
}

static int d_add_interface(struct ieee80211_hw *hw,
			   struct ieee80211_if_init_conf *conf)
{
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;
	unsigned long flags;

	IWL_DEBUG_MAC80211("enter - id %d, type %d, MAC " MAC_FMT "\n",
			   conf->if_id, conf->type, MAC_ARG(conf->mac_addr));

	if (priv->interface_id) {
		IWL_DEBUG_MAC80211("leave - interface_id != 0\n");
		return 0;
	}

	spin_lock_irqsave(&priv->lock, flags);
	priv->interface_id = conf->if_id;

	spin_unlock_irqrestore(&priv->lock, flags);

	mutex_lock(&priv->mutex);
	iwl_set_mode(priv, conf->type);

	IWL_DEBUG_MAC80211("leave\n");
	mutex_unlock(&priv->mutex);

	return 0;
}

/**
 * d_config - mac80211 config callback
 *
 * We ignore conf->flags & IEEE80211_CONF_SHORT_SLOT_TIME since it seems to
 * be set inappropriately and the driver currently sets the hardware up to
 * use it whenever needed.
 */
static int d_config(struct ieee80211_hw *hw, struct ieee80211_conf *conf)
{
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;
	const struct iwl_channel_info *ch_info;
	unsigned long flags;

	mutex_lock(&priv->mutex);
	IWL_DEBUG_MAC80211("enter to channel %d\n", conf->channel);

	if (!iwl_is_ready(priv)) {
		IWL_DEBUG_MAC80211("leave - not ready\n");
		mutex_unlock(&priv->mutex);
		return -EIO;
	}

	/* TODO: Figure out how to get ieee80211_local->sta_scanning w/ only
	 * what is exposed through include/ declrations */
	if (unlikely
	    (!param_disable_hw_scan && (priv->status & STATUS_SCANNING))) {
		IWL_DEBUG_MAC80211("leave - scanning\n");
		mutex_unlock(&priv->mutex);
		return 0;
	}

	spin_lock_irqsave(&priv->lock, flags);

	ch_info = iwl_get_channel_info(priv, conf->phymode, conf->channel);
	if (!is_channel_valid(ch_info)) {
		IWL_DEBUG_SCAN("Channel %d [%d] is INVALID for this SKU.\n",
			       conf->channel, conf->phymode);
		IWL_DEBUG_MAC80211("leave - invalid channel\n");
		spin_unlock_irqrestore(&priv->lock, flags);
		mutex_unlock(&priv->mutex);
		return -EINVAL;
	}

#if IWL == 4965
#ifdef CONFIG_IWLWIFI_HT
	/* if we are switching fron ht to 2.4 clear flags
	 * from any ht related info since 2.4 does not
	 * support ht */
	if (is_channel_bg_band(ch_info) &&
	    (priv->staging_rxon.channel != conf->channel))
		priv->staging_rxon.flags = 0;
#endif /* CONFIG_IWLWIFI_HT */
#endif /* IWL == 4965 */

	iwl_set_rxon_channel(priv, conf->phymode, conf->channel);

	iwl_set_flags_for_phymode(priv, conf->phymode);

	/* The list of supported rates and rate mask can be different
	 * for each phymode; since the phymode may have changed, reset
	 * the rate mask to what mac80211 lists */
	iwl_set_rate(priv);

	spin_unlock_irqrestore(&priv->lock, flags);

	iwl_radio_kill_sw(priv, !conf->radio_enabled);

	if (!conf->radio_enabled) {
		IWL_DEBUG_MAC80211("leave - radio disabled\n");
		mutex_unlock(&priv->mutex);
		return 0;
	}

	if (priv->status & STATUS_RF_KILL_MASK) {
		IWL_DEBUG_MAC80211("leave - RF kill\n");
		mutex_unlock(&priv->mutex);
		return -EIO;
	}

	iwl_set_rate(priv);

	if (memcmp(&priv->active_rxon,
		   &priv->staging_rxon, sizeof(priv->staging_rxon)))
		iwl_commit_rxon(priv);
	else
		IWL_DEBUG_INFO("No re-sending same RXON configuration.\n");

	IWL_DEBUG_MAC80211("leave\n");

	mutex_unlock(&priv->mutex);

	return 0;
}

static int d_config_interface(struct ieee80211_hw *hw,
			      int if_id, struct ieee80211_if_conf *conf)
{
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;
	unsigned long flags;

	if (conf == NULL)
		return -EIO;

	if ((priv->iw_mode == IEEE80211_IF_TYPE_AP) &&
	    (!conf->beacon || !conf->ssid_len)) {
		IWL_DEBUG_MAC80211
		    ("Leaving in AP mode because HostAPD is not ready.\n");
		return 0;
	}

	mutex_lock(&priv->mutex);
	
	if_id=priv->interface_id;//hack
	
	IWL_DEBUG_MAC80211("enter: interface id %d\n", if_id);
	if (conf->bssid)
		IWL_DEBUG_MAC80211("bssid: " MAC_FMT "\n",
				   MAC_ARG(conf->bssid));

	if (unlikely(priv->status & STATUS_SCANNING) &&
	    !(priv->hw->flags & IEEE80211_HW_NO_PROBE_FILTERING)) {
		IWL_DEBUG_MAC80211("leave - scanning\n");
		mutex_unlock(&priv->mutex);
		return 0;
	}

	if (priv->interface_id != if_id) {
		IWL_DEBUG_MAC80211("leave - interface_id != if_id\n");
		mutex_unlock(&priv->mutex);
		return 0;
	}

	if (priv->iw_mode == IEEE80211_IF_TYPE_AP) {
		if (!conf->bssid) {
			conf->bssid = priv->mac_addr;
			memcpy(priv->bssid, priv->mac_addr, ETH_ALEN);
			IWL_DEBUG_MAC80211("bssid was set to: " MAC_FMT "\n",
					   MAC_ARG(conf->bssid));
		}
		if (priv->ibss_beacon) {
		if (!(mbuf_type(priv->ibss_beacon) == MBUF_TYPE_FREE)) 
			mbuf_freem(priv->ibss_beacon);
			priv->ibss_beacon=NULL;
		}
		priv->ibss_beacon = conf->beacon;
	}

	if (conf->bssid && 
	conf->bssid[0]==0 &&
	conf->bssid[1]==0 &&
	conf->bssid[2]==0 &&
	conf->bssid[3]==0 &&
	conf->bssid[4]==0 &&
	conf->bssid[5]==0 &&
	//!is_zero_ether_addr(conf->bssid) &&
	    !is_multicast_ether_addr(conf->bssid)) 
	{
		/* If there is currently a HW scan going on in the background
		 * then we need to cancel it else the RXON below will fail. */
		if (iwl_scan_cancel(priv, 100)) {
			IWL_WARNING("Aborted scan still in progress "
				    "after 100ms\n");
			IWL_DEBUG_MAC80211("leaving - scan abort " "failed.\n");
			mutex_unlock(&priv->mutex);
			return -EAGAIN;
		}
		memcpy(priv->staging_rxon.bssid_addr, conf->bssid, ETH_ALEN);
		priv->staging_rxon.filter_flags |= RXON_FILTER_ASSOC_MSK;

		/* TODO: Audit driver for usage of these members and see
		 * if mac80211 deprecates them (priv->bssid looks like it
		 * shouldn't be there, but I haven't scanned the IBSS code
		 * to verify) - jpk */
		memcpy(priv->bssid, conf->bssid, ETH_ALEN);

		iwl_commit_rxon(priv);
		if (priv->iw_mode == IEEE80211_IF_TYPE_STA)
			iwl_rxon_add_station(
				priv, priv->active_rxon.bssid_addr, 1);

		if (priv->iw_mode == IEEE80211_IF_TYPE_AP) {
			/* FIXME: The unlock here is a patch. the Locks
			 * should be moved out of iwl_bg_post_associate */
			mutex_unlock(&priv->mutex);
			//iwl_bg_post_associate(priv);//&priv->post_associate.work);
			clone->queue_te(7,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_post_associate),priv,NULL,true);

			mutex_lock(&priv->mutex);
		}
	} else {
		priv->staging_rxon.filter_flags &= ~RXON_FILTER_ASSOC_MSK;
		iwl_commit_rxon(priv);
	}

	spin_lock_irqsave(&priv->lock, flags);
	if (!conf->ssid_len)
		memset(priv->essid, 0, IW_ESSID_MAX_SIZE);
	else
		memcpy(priv->essid, conf->ssid, conf->ssid_len);

	priv->essid_len = conf->ssid_len;
	spin_unlock_irqrestore(&priv->lock, flags);

	IWL_DEBUG_MAC80211("leave\n");
	mutex_unlock(&priv->mutex);

	return 0;
}

static void d_remove_interface(struct ieee80211_hw *hw,
			       struct ieee80211_if_init_conf *conf)
{
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;

	IWL_DEBUG_MAC80211("enter\n");

	mutex_lock(&priv->mutex);
	if (priv->interface_id == conf->if_id) {
		priv->interface_id = 0;
		memset(priv->bssid, 0, ETH_ALEN);
		memset(priv->essid, 0, IW_ESSID_MAX_SIZE);
		priv->essid_len = 0;
	}
	mutex_unlock(&priv->mutex);

	IWL_DEBUG_MAC80211("leave\n");

}

#define IWL_DELAY_NEXT_SCAN (HZ*2)
static int d_hw_scan(struct ieee80211_hw *hw, u8 * ssid, size_t len)
{
	int rc = 0;
	unsigned long flags;
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;

	IWL_DEBUG_MAC80211("enter\n");

	spin_lock_irqsave(&priv->lock, flags);

	if (!iwl_is_ready_rf(priv)) {
		rc = -EIO;
		IWL_DEBUG_MAC80211("leave - not ready or exit pending\n");
		goto out_unlock;
	}

	if (priv->iw_mode == IEEE80211_IF_TYPE_AP) {	/* APs don't scan */
		rc = -EIO;
		IWL_ERROR("ERROR: APs don't scan\n");
		goto out_unlock;
	}

	/* if we just finished scan ask for delay */
	if (priv->last_scan_jiffies &&
	    time_after(priv->last_scan_jiffies + IWL_DELAY_NEXT_SCAN,
		       jiffies)) {
		rc = -EAGAIN;
		goto out_unlock;
	}
	if (len) {
		IWL_DEBUG_SCAN("direct scan for  "
			       "%s [%d]\n ",
			       iwl_escape_essid((const char *)ssid, len), (int)len);

		priv->one_direct_scan = 1;
		priv->direct_ssid_len = (u8)
		    min((u8) len, (u8) IW_ESSID_MAX_SIZE);
		memcpy(priv->direct_ssid, ssid, priv->direct_ssid_len);
	}

	rc = iwl_scan_initiate(priv);

	IWL_DEBUG_MAC80211("leave\n");

 out_unlock:
	spin_unlock_irqrestore(&priv->lock, flags);

	return rc;
}

static int d_set_key(struct ieee80211_hw *hw,
		     set_key_cmd cmd,
		     u8 * addr, struct ieee80211_key_conf *key, int aid)
{
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;
	int rc = 0;
	u8 sta_id;

	IWL_DEBUG_MAC80211("enter\n");

	if (!param_hwcrypto) {
		IWL_DEBUG_MAC80211("leave - hwcrypto disabled\n");
		return -EOPNOTSUPP;
	}

	sta_id = iwl_hw_find_station(priv, addr);
	if (sta_id == IWL_INVALID_STATION) {
		IWL_DEBUG_MAC80211("leave - " MAC_FMT
				   " not in station map.\n", MAC_ARG(addr));
		return -EINVAL;
	}

	mutex_lock(&priv->mutex);

	if (cmd == SET_KEY)
		rc = iwl_update_sta_key_info(priv, key, sta_id);
	else
		rc = -EINVAL;

	if (!rc) {
		iwl_set_rxon_hwcrypto(priv, 1);
		iwl_commit_rxon(priv);
		key->flags &= (u32)
			(~IEEE80211_KEY_FORCE_SW_ENCRYPT);
		key->hw_key_idx = sta_id;
		/* TODO do we need below */
		/*
		 * conf->sw_encrypt = 0;
		 * conf->sw_decrypt = 0;
		 */
		IWL_DEBUG_MAC80211("set_key success, using hwcrypto\n");
	}

	IWL_DEBUG_MAC80211("leave\n");
	mutex_unlock(&priv->mutex);

	return rc;
}

static int d_conf_tx(struct ieee80211_hw *hw, int queue,
		     const struct ieee80211_tx_queue_params *params)
{
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;

	IWL_DEBUG_MAC80211("enter\n");

	if (!iwl_is_ready_rf(priv)) {
		IWL_DEBUG_MAC80211("leave - RF not ready\n");
		return -EIO;
	}

	if (queue >= AC_NUM) {
		IWL_DEBUG_MAC80211("leave - queue >= AC_NUM\n");
		return 0;
	}
	IWL_DEBUG_MAC80211("leave\n");
	return 0;
}

static int d_get_tx_stats(struct ieee80211_hw *hw,
			  struct ieee80211_tx_queue_stats *stats)
{
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;
	int i, avail;
	struct iwl_tx_queue *txq;
	struct iwl_queue *q;
	unsigned long flags;

	IWL_DEBUG_MAC80211("enter\n");

	if (!iwl_is_ready_rf(priv)) {
		IWL_DEBUG_MAC80211("leave - RF not ready\n");
		return -EIO;
	}

	spin_lock_irqsave(&priv->lock, flags);

	for (i = 0; i < AC_NUM; i++) {
		txq = &priv->txq[i];
		q = &txq->q;
		avail = iwl_queue_space(q);

		stats->data[i].len = q->n_window - avail;
		stats->data[i].limit = q->n_window - q->high_mark;
		stats->data[i].count = q->n_window;

	}
	spin_unlock_irqrestore(&priv->lock, flags);

	IWL_DEBUG_MAC80211("leave\n");

	return 0;
}

static int d_get_stats(struct ieee80211_hw *hw,
		       struct ieee80211_low_level_stats *stats)
{
	IWL_DEBUG_MAC80211("enter\n");
	IWL_DEBUG_MAC80211("leave\n");

	return 0;
}

static u64 d_get_tsf(struct ieee80211_hw *hw)
{
	IWL_DEBUG_MAC80211("enter\n");
	IWL_DEBUG_MAC80211("leave\n");

	return 0;
}

static void d_reset_tsf(struct ieee80211_hw *hw)
{
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;
	unsigned long flags;

	mutex_lock(&priv->mutex);
	IWL_DEBUG_MAC80211("enter\n");

#if IWL == 4965
#ifdef CONFIG_IWLWIFI_HT
	spin_lock_irqsave(&priv->lock, flags);
	memset(&priv->current_assoc_ht, 0, sizeof(struct sta_ht_info));
	spin_unlock_irqrestore(&priv->lock, flags);
#endif /* CONFIG_IWLWIFI_HT */
#endif /* IWL == 4965 */

	//cancel_delayed_work(&priv->post_associate);
	clone->queue_td(7,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_post_associate));

	spin_lock_irqsave(&priv->lock, flags);
	priv->assoc_id = 0;
	priv->assoc_capability = 0;
	priv->call_post_assoc_from_beacon = 0;
	priv->assoc_station_added = 0;

	/* new association get rid of ibss beacon skb */
	if (priv->ibss_beacon)
	if (!(mbuf_type(priv->ibss_beacon) == MBUF_TYPE_FREE)) 
		mbuf_freem(priv->ibss_beacon);

	priv->ibss_beacon = NULL;

	priv->beacon_int = priv->hw->conf.beacon_int;
	priv->timestamp1 = 0;
	priv->timestamp0 = 0;
	if ((priv->iw_mode == IEEE80211_IF_TYPE_STA))
		priv->beacon_int = 0;
	
	spin_unlock_irqrestore(&priv->lock, flags);

	/* Per mac80211.h: This is only used in IBSS mode... */
	if (priv->iw_mode != IEEE80211_IF_TYPE_IBSS) {
		IWL_DEBUG_MAC80211("leave - not in IBSS\n");
		mutex_unlock(&priv->mutex);
		return;
	}

	if (!iwl_is_ready_rf(priv)) {
		IWL_DEBUG_MAC80211("leave - not ready\n");
		mutex_unlock(&priv->mutex);
		return;
	}

	priv->only_active_channel = 0;

	iwl_set_rate(priv);

	mutex_unlock(&priv->mutex);

	IWL_DEBUG_MAC80211("leave\n");

}

static int d_beacon_update(struct ieee80211_hw *hw,
			   mbuf_t skb,
			   struct ieee80211_tx_control *control)
{
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;
	unsigned long flags;

	mutex_lock(&priv->mutex);
	IWL_DEBUG_MAC80211("enter\n");

	if (!iwl_is_ready_rf(priv)) {
		IWL_DEBUG_MAC80211("leave - RF not ready\n");
		mutex_unlock(&priv->mutex);
		return -EIO;
	}

	if (priv->iw_mode != IEEE80211_IF_TYPE_IBSS) {
		IWL_DEBUG_MAC80211("leave - not IBSS\n");
		mutex_unlock(&priv->mutex);
		return -EIO;
	}

	spin_lock_irqsave(&priv->lock, flags);

	if (priv->ibss_beacon)
	if (!(mbuf_type(priv->ibss_beacon) == MBUF_TYPE_FREE)) 
		mbuf_freem(priv->ibss_beacon);
	priv->ibss_beacon=NULL;
	priv->ibss_beacon = skb;

	priv->assoc_id = 0;

	IWL_DEBUG_MAC80211("leave\n");
	spin_unlock_irqrestore(&priv->lock, flags);

	//queue_work(priv->workqueue, &priv->post_associate.work);
	clone->queue_te(7,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_post_associate),priv,NULL,true);

	mutex_unlock(&priv->mutex);

	return 0;
}

#if IWL == 4965
#ifdef CONFIG_IWLWIFI_HT
union ht_cap_info {
	struct {
		u16 advanced_coding_cap		:1;
		u16 supported_chan_width_set	:1;
		u16 mimo_power_save_mode	:2;
		u16 green_field			:1;
		u16 short_GI20			:1;
		u16 short_GI40			:1;
		u16 tx_stbc			:1;
		u16 rx_stbc			:1;
		u16 beam_forming		:1;
		u16 delayed_ba			:1;
		u16 maximal_amsdu_size		:1;
		u16 cck_mode_at_40MHz		:1;
		u16 psmp_support		:1;
		u16 stbc_ctrl_frame_support	:1;
		u16 sig_txop_protection_support	:1;
	};
	u16 val;
}__attribute__ ((packed));

union ht_param_info{
	struct {
		u8 max_rx_ampdu_factor	:2;
		u8 mpdu_density		:3;
		u8 reserved		:3;
	};
	u8 val;
}__attribute__ ((packed));

union ht_exra_param_info{
	struct {
		u8 ext_chan_offset		:2;
		u8 tx_chan_width		:1;
		u8 rifs_mode			:1;
		u8 controlled_access_only	:1;
		u8 service_interval_granularity	:3;
	};
	u8 val;
}__attribute__ ((packed));

union ht_operation_mode{
	struct {
		u16 op_mode	:2;
		u16 non_GF	:1;
		u16 reserved	:13;
	};
	u16 val;
}__attribute__ ((packed));

static int d_conf_ht(struct ieee80211_hw *hw,
		     struct ieee80211_ht_capability *ht_cap_param,
		     struct ieee80211_ht_additional_info *ht_extra_param)
{
	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;
	struct sta_ht_info *ht_info = &priv->current_assoc_ht;
	union ht_cap_info cap;
	union ht_operation_mode op_mode;
	union ht_param_info param_info;
	union ht_exra_param_info extra_param_info;

	IWL_DEBUG_MAC80211("enter: \n");
	cap.val = (u16) le16_to_cpu(ht_cap_param->capabilities_info);
	op_mode.val = (u16) le16_to_cpu(ht_extra_param->operation_mode);
	param_info.val = ht_cap_param->mac_ht_params_info;
	extra_param_info.val = ht_extra_param->ht_param;

	ht_info->is_ht = 1;
	ht_info->ampdu_factor = param_info.max_rx_ampdu_factor;
	ht_info->control_chan = ht_extra_param->control_chan;
	ht_info->is_green_field = cap.green_field;
	if (cap.short_GI20)
		ht_info->sgf |= 0x1;
	if (cap.short_GI40)
		ht_info->sgf |= 0x2;
	ht_info->operating_mode = op_mode.op_mode;
	ht_info->mpdu_density = param_info.mpdu_density;
	ht_info->max_amsdu_size = cap.maximal_amsdu_size;
	ht_info->supported_chan_width = cap.supported_chan_width_set;
	ht_info->extension_chan_offset = extra_param_info.ext_chan_offset;
	ht_info->tx_mimo_ps_mode = cap.mimo_power_save_mode;

	memcpy(ht_info->supp_rates, ht_cap_param->supported_mcs_set, 16);

	priv->active_rate_ht[0] = ht_info->supp_rates[0];
	priv->active_rate_ht[1] = ht_info->supp_rates[1];

	iwl4965_set_rxon_chain(priv);

	if (priv && priv->assoc_id &&
	    (priv->iw_mode == IEEE80211_IF_TYPE_STA)) {
		unsigned long flags;

		spin_lock_irqsave(&priv->lock, flags);
		if (priv->beacon_int)
			//queue_work(priv->workqueue, &priv->post_associate.work);
			clone->queue_te(7,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_post_associate),priv,NULL,true);
		else
			priv->call_post_assoc_from_beacon = 1;
		spin_unlock_irqrestore(&priv->lock, flags);
	}

	IWL_DEBUG_MAC80211("leave: control channel %d\n",
			    ht_extra_param->control_chan);
	return 0;
}

static void d_get_ht_capab(struct ieee80211_hw *hw,
			   struct ieee80211_ht_capability *ht_cap_param)
{
	union ht_cap_info cap;
	union ht_param_info param_info;

	IWL_DEBUG_MAC80211("enter: \n");
	cap.maximal_amsdu_size = HT_IE_MAX_AMSDU_SIZE_4K;
	cap.green_field = 1;
	cap.short_GI20 = 1;
	cap.short_GI40 = 1;
	cap.supported_chan_width_set = 1;
	cap.mimo_power_save_mode = 0x3;

	param_info.max_rx_ampdu_factor = CFG_HT_RX_AMPDU_FACTOR_DEF;
	param_info.mpdu_density = CFG_HT_MPDU_DENSITY_DEF;
	ht_cap_param->capabilities_info = (__le16) cpu_to_le16(cap.val);
	ht_cap_param->mac_ht_params_info = (u8) param_info.val;

	ht_cap_param->supported_mcs_set[0] = 0xff;
	ht_cap_param->supported_mcs_set[1] = 0xff;
	ht_cap_param->supported_mcs_set[4] =
				(cap.supported_chan_width_set) ? 0x1: 0x0;

	IWL_DEBUG_MAC80211("leave: \n");
}



#endif /*CONFIG_IWLWIFI_HT*/

#ifdef CONFIG_IWLWIFI_HT_AGG

static int kdrn_txq_ctx_activate_free(struct iwl_priv *priv);
static int d_ht_tx_agg_start(struct ieee80211_hw *hw, u8 *da, u16 tid,
			     u16 *start_seq_num)
{

	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;
	int sta_id;
	int tx_fifo;
	int txq_id;
	int ssn = -1;
	unsigned long flags;
	struct ipw_tid_data *tid_data;

	if (likely(tid < ARRAY_SIZE(default_tid_to_ac)))
		tx_fifo = default_tid_to_ac[tid];
	else
		return -EINVAL;

	IWL_DEBUG_MAC80211("iwl-AGG d_ht_tx_agg_start on da=" MAC_FMT " tid="
			   "%d\n", MAC_ARG(da), tid);

	sta_id = ipw_find_station(priv, da);
	if (sta_id == IPW_INVALID_STATION)
		return -ENXIO;

	txq_id = kdrn_txq_ctx_activate_free(priv);
	if (txq_id == -1)
		return -ENXIO;

	spin_lock_irqsave(&priv->sta_lock, flags);
	tid_data = &priv->stations[sta_id].tid[tid];
	ssn = SEQ_TO_SN(tid_data->seq_number);
	tid_data->txq_id = txq_id;
	spin_unlock_irqrestore(&priv->sta_lock, flags);

	*start_seq_num = ssn;
	return kdrn_tx_queue_agg_enable(priv, txq_id, tx_fifo, sta_id, tid,
					ssn);
}


static int d_ht_tx_agg_stop(struct ieee80211_hw *hw,
				u8 *da, u16 tid, int generator)
{

	struct iwl_priv *priv = (struct iwl_priv*)hw->priv;
	int tx_fifo_id, sta_id, ssn = -1;
	if (!da) {
		IWL_ERROR("%s: da = NULL\n", __func__);
		return -EINVAL;
	}

	if (likely(tid < ARRAY_SIZE(default_tid_to_ac)))
		tx_fifo_id = default_tid_to_ac[tid];
	else
		return -EINVAL;

	sta_id = ipw_find_station(priv, da);

	if (sta_id == IPW_INVALID_STATION)
		return -ENXIO;

	ssn = (priv->stations[sta_id].tid[tid].seq_number &
	       IEEE80211_SCTL_SEQ) >> 4;

	kdrn_tx_queue_agg_disable(priv, 7, ssn, tx_fifo_id);
	IWL_DEBUG_MAC80211("iwl-AGG d_ht_tx_agg_stop on da=" MAC_FMT " tid="
			   "%d\n", MAC_ARG(da), tid);

	return 0;
}

#endif /*CONFIG_IWLWIFI_HT_AGG*/
#endif /*IWL == 4965*/
/*****************************************************************************
 *
 * sysfs attributes
 *
 *****************************************************************************/

#ifdef CONFIG_IWLWIFI_DEBUG

/*
 * The following adds a new attribute to the sysfs representation
 * of this device driver (i.e. a new file in /sys/bus/pci/drivers/ipw/)
 * used for controlling the debug level.
 *
 * See the level definitions in ipw for details.
 */

static ssize_t show_debug_level(struct device_driver *d, char *buf)
{
	return sprintf(buf, "0x%08X\n", iwl_debug_level);
}
static ssize_t store_debug_level(struct device_driver *d,
				 const char *buf, size_t count)
{
	char *p = (char *)buf;
	u32 val;

	val = strtoul(p, &p, 0);
	if (p == buf)
		printk(KERN_INFO DRV_NAME
		       ": %s is not in hex or decimal form.\n", buf);
	else
		iwl_debug_level = val;

	return strlen(buf);
}

//static DRIVER_ATTR(debug_level, S_IWUSR | S_IRUGO,
//		   show_debug_level, store_debug_level);

#endif /* CONFIG_IWLWIFI_DEBUG */

static ssize_t show_rf_kill(struct iwl_priv *d,
			    struct device_attribute *attr, char *buf)
{
	/*
	 * 0 - RF kill not enabled
	 * 1 - SW based RF kill active (sysfs)
	 * 2 - HW based RF kill active
	 * 3 - Both HW and SW based RF kill active
	 */
	struct iwl_priv *priv = (struct iwl_priv *)d;
	int val = ((priv->status & STATUS_RF_KILL_SW) ? 0x1 : 0x0) |
	    ((priv->status & STATUS_RF_KILL_HW) ? 0x2 : 0x0);

	return sprintf(buf, "%i\n", val);
}

static ssize_t store_rf_kill(struct iwl_priv *d,
			     struct device_attribute *attr,
			     const char *buf, size_t count)
{
	struct iwl_priv *priv = (struct iwl_priv *)d;

	mutex_lock(&priv->mutex);
	iwl_radio_kill_sw(priv, buf[0] == '1');
	mutex_unlock(&priv->mutex);

	return count;
}

//static DEVICE_ATTR(rf_kill, S_IWUSR | S_IRUGO, show_rf_kill, store_rf_kill);

static ssize_t show_temperature(struct iwl_priv *d,
				struct device_attribute *attr, char *buf)
{
	struct iwl_priv *priv = (struct iwl_priv *)d;

	if (!iwl_is_alive(priv))
		return -EAGAIN;

	return sprintf(buf, "%d\n", iwl_hw_get_temperature(priv));
}

//static DEVICE_ATTR(temperature, S_IRUGO, show_temperature, NULL);

static ssize_t show_rs_window(struct iwl_priv *d,
			      struct device_attribute *attr,
			      char *buf)
{
	struct iwl_priv *priv = d;
	return iwl_fill_rs_info(priv->hw, buf, IWL_AP_ID);
}
//static DEVICE_ATTR(rs_window, S_IRUGO, show_rs_window, NULL);

static ssize_t show_tx_power(struct iwl_priv *d,
			     struct device_attribute *attr, char *buf)
{
	struct iwl_priv *priv = (struct iwl_priv *)d;
	return sprintf(buf, "%d\n", priv->user_txpower_limit);
}

static ssize_t store_tx_power(struct iwl_priv *d,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct iwl_priv *priv = (struct iwl_priv *)d;
	char *p = (char *)buf;
	u32 val;

	val = strtoul(p, &p, 10);
	if (p == buf)
		printk(KERN_INFO DRV_NAME
		       ": %s is not in decimal form.\n", buf);
	else
		iwl_hw_reg_set_txpower(priv, val);

	return count;
}

//static DEVICE_ATTR(tx_power, S_IWUSR | S_IRUGO, show_tx_power, store_tx_power);

static ssize_t show_flags(struct iwl_priv *d,
			  struct device_attribute *attr, char *buf)
{
	struct iwl_priv *priv = (struct iwl_priv *)d;

	return sprintf(buf, "0x%04X\n", priv->active_rxon.flags);
}

static ssize_t store_flags(struct iwl_priv *d,
			   struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct iwl_priv *priv = (struct iwl_priv *)d;
	u16 flags = strtoul(buf, NULL, 0);

	mutex_lock(&priv->mutex);
	if (priv->staging_rxon.flags != flags) {
		/* Cancel any currently running scans... */
		if (iwl_scan_cancel(priv, 100)) {
			IWL_WARNING("Could not cancel scan.\n");
		} else {
			IWL_DEBUG_INFO("Committing rxon.flags = 0x%04X\n",
				       flags);
			priv->staging_rxon.flags = flags;
			iwl_commit_rxon(priv);
		}
	}
	mutex_unlock(&priv->mutex);

	return count;
}

//static DEVICE_ATTR(flags, S_IWUSR | S_IRUGO, show_flags, store_flags);

static ssize_t show_filter_flags(struct iwl_priv *d,
				 struct device_attribute *attr, char *buf)
{
	struct iwl_priv *priv = (struct iwl_priv *)d;

	return sprintf(buf, "0x%04X\n", priv->active_rxon.filter_flags);
}

static ssize_t store_filter_flags(struct iwl_priv *d,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct iwl_priv *priv = (struct iwl_priv *)d;
	u16 filter_flags = strtoul(buf, NULL, 0);

	mutex_lock(&priv->mutex);
	if (priv->staging_rxon.filter_flags != filter_flags) {
		/* Cancel any currently running scans... */
		if (iwl_scan_cancel(priv, 100)) {
			IWL_WARNING("Could not cancel scan.\n");
		} else {
			IWL_DEBUG_INFO("Committing rxon.filter_flags = "
				       "0x%04X\n", filter_flags);
			priv->staging_rxon.filter_flags = filter_flags;
			iwl_commit_rxon(priv);
		}
	}
	mutex_unlock(&priv->mutex);

	return count;
}

//static DEVICE_ATTR(filter_flags, S_IWUSR | S_IRUGO, show_filter_flags,
	//	   store_filter_flags);

static ssize_t show_tune(struct iwl_priv *d,
			 struct device_attribute *attr, char *buf)
{
	struct iwl_priv *priv = (struct iwl_priv *)d;

	return sprintf(buf, "0x%04X\n",
		       (priv->phymode << 8) | priv->active_rxon.channel);
}

//static void iwl_set_flags_for_phymode(struct iwl_priv *priv, u8 phymode);

static ssize_t store_tune(struct iwl_priv *d,
			  struct device_attribute *attr,
			  const char *buf, size_t count)
{
	struct iwl_priv *priv = (struct iwl_priv *)d;
	char *p = (char *)buf;
	u16 tune = strtoul(p, &p, 0);
	u8 phymode = (tune >> 8) & 0xff;
	u8 channel = tune & 0xff;

	IWL_DEBUG_INFO("Tune request to:%d channel:%d\n", phymode, channel);

	mutex_lock(&priv->mutex);
	if ((priv->staging_rxon.channel != channel) ||
	    (priv->phymode != phymode)) {
		const struct iwl_channel_info *ch_info;

		ch_info = iwl_get_channel_info(priv, phymode, channel);
		if (!ch_info) {
			IWL_WARNING("Requested invalid phymode/channel "
				    "combination: %d %d\n", phymode, channel);
			mutex_unlock(&priv->mutex);
			return -EINVAL;
		}

		/* Cancel any currently running scans... */
		if (iwl_scan_cancel(priv, 100)) {
			IWL_WARNING("Could not cancel scan.\n");
		} else {
			IWL_DEBUG_INFO("Committing phymode and "
				       "rxon.channel = %d %d\n",
				       phymode, channel);

			iwl_set_rxon_channel(priv, phymode, channel);
			iwl_set_flags_for_phymode(priv, phymode);

			iwl_set_rate(priv);
			iwl_commit_rxon(priv);
		}
	}
	mutex_unlock(&priv->mutex);

	return count;
}

//static DEVICE_ATTR(tune, S_IWUSR | S_IRUGO, show_tune, store_tune);

#ifdef CONFIG_IWLWIFI_SPECTRUM_MEASUREMENT

static ssize_t show_measurement(struct iwl_priv *d,
				struct device_attribute *attr, char *buf)
{
	struct iwl_priv *priv = d;
	struct iwl_spectrum_notification measure_report;

	u32 size = sizeof(measure_report), len = 0, ofs = 0;
	u8 *data = (u8 *) & measure_report;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	if (!(priv->measurement_status & MEASUREMENT_READY)) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return 0;
	}
	memcpy(&measure_report, &priv->measure_report, size);
	priv->measurement_status = 0;
	spin_unlock_irqrestore(&priv->lock, flags);

	while (size && (PAGE_SIZE - len)) {
		len +=
		    snprint_line(&buf[len], PAGE_SIZE - len,
				 &data[ofs], min(size, 16U), ofs);
		if (PAGE_SIZE - len)
			buf[len++] = '\n';

		ofs += 16;
		size -= min(size, 16U);
	}

	return len;
}

static ssize_t store_measurement(struct iwl_priv *d,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct iwl_priv *priv = d;
	struct ieee80211_measurement_params params = {
		.channel = priv->active_rxon.channel,
		.start_time = priv->last_tsf,
		.duration = 1,
	};
	u8 type = IWL_MEASURE_BASIC;
	u8 buffer[32];
	u8 channel;

	if (count) {
		char *p = buffer;
		strncpy(buffer, buf, min(sizeof(buffer), count));
		channel = strtoul(p, NULL, 0);
		if (channel)
			params.channel = channel;

		p = buffer;
		while (*p && *p != ' ')
			p++;
		if (*p)
			type = strtoul(p + 1, NULL, 0);
	}

	IWL_DEBUG_INFO("Invoking measurement of type %d on "
		       "channel %d (for '%s')\n", type, params.channel, buf);
	iwl_get_measurement(priv, &params, type);

	return count;
}

//static DEVICE_ATTR(measurement, S_IRUSR | S_IWUSR,
		   show_measurement, store_measurement);
#endif /* CONFIG_IWLWIFI_SPECTRUM_MEASUREMENT */

static ssize_t show_rate(struct iwl_priv *d,
			 struct device_attribute *attr, char *buf)
{
	struct iwl_priv *priv = d;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&priv->sta_lock, flags);
	if (priv->iw_mode == IEEE80211_IF_TYPE_IBSS)
		i = priv->stations[IWL_STA_ID].current_rate.s.rate;
	else
		i = priv->stations[IWL_AP_ID].current_rate.s.rate;
	spin_unlock_irqrestore(&priv->sta_lock, flags);

	i = iwl_rate_index_from_plcp(i);
	if (i == -1)
		return sprintf(buf, "0\n");

	return sprintf(buf, "%d%s\n",
		       (iwl_rates[i].ieee >> 1),
		       (iwl_rates[i].ieee % 2) ? ".5" : "");
}

//static DEVICE_ATTR(rate, S_IRUSR, show_rate, NULL);

static ssize_t store_retry_rate(struct iwl_priv *d,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct iwl_priv *priv = d;

	priv->retry_rate = strtoul(buf, NULL, 0);
	if (priv->retry_rate <= 0)
		priv->retry_rate = 1;

	return count;
}

static ssize_t show_retry_rate(struct iwl_priv *d,
			       struct device_attribute *attr, char *buf)
{
	struct iwl_priv *priv = d;
	return sprintf(buf, "%d", priv->retry_rate);
}

//static DEVICE_ATTR(retry_rate, S_IWUSR | S_IRUSR, show_retry_rate,
//		   store_retry_rate);

static ssize_t store_power_level(struct iwl_priv *d,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct iwl_priv *priv = d;
	int rc;
	int mode;

	mode = strtoul(buf, NULL,0);
	mutex_lock(&priv->mutex);

	if (!iwl_is_ready(priv)) {
		rc = -EAGAIN;
		goto out;
	}

	if ((mode < 1) || (mode > IWL_POWER_LIMIT) || (mode == IWL_POWER_AC))
		mode = IWL_POWER_AC;
	else
		mode |= IWL_POWER_ENABLED;

	if (mode != priv->power_mode) {
		rc = iwl_send_power_mode(priv, IWL_POWER_LEVEL(mode));
		if (rc) {
			IWL_DEBUG_MAC80211("failed setting power mode.\n");
			goto out;
		}
		priv->power_mode = mode;
	}

	rc = count;

 out:
	mutex_unlock(&priv->mutex);
	return rc;
}

#define MAX_WX_STRING 80

/* Values are in microsecond */
static const s32 timeout_duration[] = {
	350000,
	250000,
	75000,
	37000,
	25000,
};
static const s32 period_duration[] = {
	400000,
	700000,
	1000000,
	1000000,
	1000000
};

static ssize_t show_power_level(struct iwl_priv *d,
				struct device_attribute *attr, char *buf)
{
	struct iwl_priv *priv = d;
	int level = IWL_POWER_LEVEL(priv->power_mode);
	char *p = buf;

	p += sprintf(p, "%d ", level);
	switch (level) {
	case IWL_POWER_MODE_CAM:
	case IWL_POWER_AC:
		p += sprintf(p, "(AC)");
		break;
	case IWL_POWER_BATTERY:
		p += sprintf(p, "(BATTERY)");
		break;
	default:
		p += sprintf(p,
			     "(Timeout %dms, Period %dms)",
			     timeout_duration[level - 1] / 1000,
			     period_duration[level - 1] / 1000);
	}

	if (!(priv->power_mode & IWL_POWER_ENABLED))
		p += sprintf(p, " OFF\n");
	else
		p += sprintf(p, " \n");

	return (p - buf + 1);

}

//static DEVICE_ATTR(power_level, S_IWUSR | S_IRUSR, show_power_level,
//		   store_power_level);

static ssize_t show_channels(struct iwl_priv *d,
			     struct device_attribute *attr, char *buf)
{
	struct iwl_priv *priv = d;
	int len = 0, i;
	struct ieee80211_channel *channels = NULL;
	const struct ieee80211_hw_mode *hw_mode = NULL;
	int count = 0;

	if (!iwl_is_ready(priv))
		return -EAGAIN;

	hw_mode = iwl_get_hw_mode(priv, MODE_IEEE80211G);
	if (!hw_mode)
		hw_mode = iwl_get_hw_mode(priv, MODE_IEEE80211B);
	if (hw_mode) {
		channels = hw_mode->channels;
		count = hw_mode->num_channels;
	}

	len +=
	    sprintf(&buf[len],
		    "Displaying %d channels in 2.4GHz band "
		    "(802.11bg):\n", count);

	for (i = 0; i < count; i++) {
		len += sprintf(&buf[len], "%d: %ddBm: BSS%s%s, %s.\n",
			       channels[i].chan,
			       channels[i].power_level,
			       channels[i].
			       flag & IEEE80211_CHAN_W_RADAR_DETECT ?
			       " (IEEE 802.11h required)" : "",
			       (!(channels[i].flag & IEEE80211_CHAN_W_IBSS)
				|| (channels[i].
				    flag &
				    IEEE80211_CHAN_W_RADAR_DETECT)) ? "" :
			       ", IBSS",
			       channels[i].
			       flag & IEEE80211_CHAN_W_ACTIVE_SCAN ?
			       "active/passive" : "passive only");
	}

	hw_mode = iwl_get_hw_mode(priv, MODE_IEEE80211A);
	if (hw_mode) {
		channels = hw_mode->channels;
		count = hw_mode->num_channels;
	} else {
		channels = NULL;
		count = 0;
	}

	len +=
	    sprintf(&buf[len],
		    "Displaying %d channels in 5.2GHz band "
		    "(802.11a):\n", count);

	for (i = 0; i < count; i++) {
		len += sprintf(&buf[len], "%d: %ddBm: BSS%s%s, %s.\n",
			       channels[i].chan,
			       channels[i].power_level,
			       channels[i].
			       flag & IEEE80211_CHAN_W_RADAR_DETECT ?
			       " (IEEE 802.11h required)" : "",
			       (!(channels[i].flag & IEEE80211_CHAN_W_IBSS)
				|| (channels[i].
				    flag &
				    IEEE80211_CHAN_W_RADAR_DETECT)) ? "" :
			       ", IBSS",
			       channels[i].
			       flag & IEEE80211_CHAN_W_ACTIVE_SCAN ?
			       "active/passive" : "passive only");
	}

	return len;
}

//static DEVICE_ATTR(channels, S_IRUSR, show_channels, NULL);

static ssize_t show_statistics(struct iwl_priv *d,
			       struct device_attribute *attr, char *buf)
{
	struct iwl_priv *priv = d;
	u32 size = sizeof(struct iwl_notif_statistics);
	u32 len = 0, ofs = 0;
	u8 *data = (u8 *) & priv->statistics;
	int rc = 0;

	if (!iwl_is_alive(priv))
		return -EAGAIN;

	mutex_lock(&priv->mutex);
	rc = iwl_send_statistics_request(priv);
	mutex_unlock(&priv->mutex);

	if (rc) {
		len = sprintf(buf,
			      "Error sending statistics request: 0x%08X\n", rc);
		return len;
	}

	while (size && (PAGE_SIZE - len)) {
		len +=
		    snprint_line(&buf[len], PAGE_SIZE - len,
				 &data[ofs], min(size, 16U), ofs);
		if (PAGE_SIZE - len)
			buf[len++] = '\n';

		ofs += 16;
		size -= min(size, 16U);
	}

	return len;
}

//static DEVICE_ATTR(statistics, S_IRUGO, show_statistics, NULL);

static ssize_t show_antenna(struct iwl_priv *d,
			    struct device_attribute *attr, char *buf)
{
	struct iwl_priv *priv = d;

	if (!iwl_is_alive(priv))
		return -EAGAIN;

	return sprintf(buf, "%d\n", priv->antenna);
}

static ssize_t store_antenna(struct iwl_priv *d,
			     struct device_attribute *attr,
			     const char *buf, size_t count)
{
	int ant;
	struct iwl_priv *priv = d;

	if (count == 0)
		return 0;

	if (sscanf(buf, "%1i", &ant) != 1) {
		IWL_DEBUG_INFO("not in hex or decimal form.\n");
		return count;
	}

	if ((ant >= 0) && (ant <= 2)) {
		IWL_DEBUG_INFO("Setting antenna select to %d.\n", ant);
		priv->antenna = (enum iwl_antenna)ant;
	} else {
		IWL_DEBUG_INFO("Bad antenna select value %d.\n", ant);
	}

	return count;
}

//static DEVICE_ATTR(antenna, S_IWUSR | S_IRUGO, show_antenna, store_antenna);

static ssize_t show_status(struct iwl_priv *d,
			   struct device_attribute *attr, char *buf)
{
	struct iwl_priv *priv = (struct iwl_priv *)d;
	if (!iwl_is_alive(priv))
		return -EAGAIN;
	return sprintf(buf, "0x%08x\n", (int)priv->status);
}

//static DEVICE_ATTR(status, S_IRUGO, show_status, NULL);

static ssize_t dump_error_log(struct iwl_priv *d,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	char *p = (char *)buf;

	if (p[0] == '1')
		iwl_dump_nic_error_log((struct iwl_priv *)d);

	return strlen(buf);
}

////static DEVICE_ATTR(dump_errors, S_IWUSR, NULL, dump_error_log);

static ssize_t dump_event_log(struct iwl_priv *d,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	char *p = (char *)buf;

	if (p[0] == '1')
		iwl_dump_nic_event_log((struct iwl_priv *)d);

	return strlen(buf);
}

////static DEVICE_ATTR(dump_events, S_IWUSR, NULL, dump_event_log);

/*****************************************************************************
 *
 * driver setup and teardown
 *
 *****************************************************************************/

static void iwl_setup_deferred_work(struct iwl_priv *priv)
{
	//priv->workqueue = create_workqueue(DRV_NAME);
//	init_waitqueue_head(&priv->wait_command_queue);
		clone->queue_te(0,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_up),NULL,NULL,false);
		clone->queue_te(1,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_restart),NULL,NULL,false);
		clone->queue_te(2,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_rx_replenish),NULL,NULL,false);
		clone->queue_te(3,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_scan_completed),NULL,NULL,false);
		clone->queue_te(4,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_request_scan),NULL,NULL,false);
		clone->queue_te(5,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_abort_scan),NULL,NULL,false);
		clone->queue_te(6,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_rf_kill),NULL,NULL,false);
		clone->queue_te(7,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_post_associate),NULL,NULL,false);
		clone->queue_te(8,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_init_alive_start),NULL,NULL,false);
		clone->queue_te(9,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_alive_start),NULL,NULL,false);
		clone->queue_te(10,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_scan_check),NULL,NULL,false);
		clone->queue_te(11,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl3945_bg_reg_txpower_periodic),NULL,NULL,false);
		clone->queue_te(13,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_irq_tasklet),NULL,NULL,false);

	INIT_WORK(&priv->up, iwl_bg_up);
	INIT_WORK(&priv->restart, iwl_bg_restart);
	INIT_WORK(&priv->rx_replenish, iwl_bg_rx_replenish);
	INIT_WORK(&priv->scan_completed, iwl_bg_scan_completed);
	INIT_WORK(&priv->request_scan, iwl_bg_request_scan);
	INIT_WORK(&priv->abort_scan, iwl_bg_abort_scan);
	INIT_WORK(&priv->rf_kill, iwl_bg_rf_kill);
	INIT_DELAYED_WORK(&priv->post_associate, iwl_bg_post_associate);
	INIT_DELAYED_WORK(&priv->init_alive_start, iwl_bg_init_alive_start);
	INIT_DELAYED_WORK(&priv->alive_start, iwl_bg_alive_start);
	INIT_DELAYED_WORK(&priv->scan_check, iwl_bg_scan_check);

	iwl_hw_setup_deferred_work(priv);

	tasklet_init(&priv->irq_tasklet, (void (*)(unsigned long))iwl_irq_tasklet, (unsigned long)priv);
			 
}

void iwl_cancel_deferred_work(struct iwl_priv *priv)
{
	iwl_hw_cancel_deferred_work(priv);
	clone->queue_td(10,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_scan_check));
	clone->queue_td(9,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_alive_start));
	clone->queue_td(7,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_post_associate));

	//cancel_delayed_work(&priv->scan_check);
	//cancel_delayed_work(&priv->alive_start);
	//cancel_delayed_work(&priv->post_associate);
}

/*static struct attribute *iwl_sysfs_entries[] = {
	&dev_attr_antenna.attr,
	&dev_attr_channels.attr,
	&dev_attr_dump_errors.attr,
	&dev_attr_dump_events.attr,
	&dev_attr_flags.attr,
	&dev_attr_filter_flags.attr,
#ifdef CONFIG_IWLWIFI_SPECTRUM_MEASUREMENT
	&dev_attr_measurement.attr,
#endif
	&dev_attr_power_level.attr,
	&dev_attr_rate.attr,
	&dev_attr_retry_rate.attr,
	&dev_attr_rf_kill.attr,
	&dev_attr_rs_window.attr,
	&dev_attr_statistics.attr,
	&dev_attr_status.attr,
	&dev_attr_temperature.attr,
	&dev_attr_tune.attr,
	&dev_attr_tx_power.attr,

	NULL
};*/

//static struct attribute_group iwl_attribute_group;// = {
//	iwl_attribute_group.name = NULL;		
//	iwl_attribute_group.attrs = iwl_sysfs_entries;

static struct ieee80211_ops iwl_hw_ops = {
	d_tx,
	NULL,
	d_open,
	d_stop,
	d_add_interface,
	d_remove_interface,
	d_config,
	d_config_interface,
	NULL,
	NULL,
	d_set_key,
	NULL,
	NULL,
	NULL,
	d_hw_scan,
	d_get_stats,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	d_conf_tx,
	d_get_tx_stats,
	d_get_tsf,
	d_reset_tsf,
	d_beacon_update,
	NULL

#if IWL == 4965
#ifdef CONFIG_IWLWIFI_HT
	.conf_ht = d_conf_ht,
	.get_ht_capab = d_get_ht_capab,
#ifdef CONFIG_IWLWIFI_HT_AGG
	.ht_tx_agg_start = d_ht_tx_agg_start,
	.ht_tx_agg_stop = d_ht_tx_agg_stop,
#endif  
#endif  
#endif

	
};

int darwin_iwi3945::iwl_pci_probe()
{
	int err = 0;
	void *base;
	u32 length;
	u32 pci_id;
	struct ieee80211_hw *hw;
	int i;

#ifdef CONFIG_IWLWIFI_DEBUG
	iwl_debug_level = param_debug;
#endif

	if (param_disable_hw_scan) {
		IWL_DEBUG_INFO("Disabling hw_scan\n");
		iwl_hw_ops.hw_scan = NULL;
	}

	/* mac80211 allocates memory for this device instance, including
	 *   space for this driver's private structure */
	 
	hw = (struct ieee80211_hw*)ieee80211_alloc_hw(sizeof(struct iwl_priv), &iwl_hw_ops);
	if (hw == NULL) {
		IWL_ERROR("Can not allocate network device\n");
		err = -ENOMEM;
		goto out;
	}
	//SET_IEEE80211_DEV(hw, &pdev->dev);
	IWL_DEBUG_INFO("*** LOAD DRIVER ***\n");
	priv = (struct iwl_priv*)hw->priv;
	//memset(priv,0,sizeof(*priv));

	priv->hw = hw;

	//priv->pci_dev = pdev;
	priv->antenna = (enum iwl_antenna)param_antenna;

	priv->retry_rate = 1;

	priv->ibss_beacon = NULL;

	/* Tell mac80211 and its clients (e.g. Wireless Extensions)
	 *   the range of signal quality values that we'll provide.
	 * Negative values for level/noise indicate that we'll provide dBm.
	 * For WE, at least, non-0 values here *enable* display of values
	 *   in app (iwconfig). */
	hw->max_rssi = -20;	/* signal level, negative indicates dBm */
	hw->max_noise = -20;	/* noise level, negative indicates dBm */
	hw->max_signal = 100;	/* link quality indication (%) */

	/* Tell mac80211 our Tx characteristics */
	hw->flags = IEEE80211_HW_WEP_INCLUDE_IV |
	    IEEE80211_HW_HOST_GEN_BEACON_TEMPLATE;
	hw->queues = 4;

	spin_lock_init(&priv->lock);
	spin_lock_init(&priv->power_data.lock);
	spin_lock_init(&priv->sta_lock);
#if IWL == 4965
	spin_lock_init(&priv->lq_mngr.lock);
#endif

	for (i = 0; i < IWL_IBSS_MAC_HASH_SIZE; i++)
		INIT_LIST_HEAD(&priv->ibss_mac_hash[i]);

	INIT_LIST_HEAD(&priv->free_frames);

/*	mutex_init(&priv->mutex);
	if (pci_enable_device(pdev)) {
		err = -ENODEV;
		goto out_ieee80211_free_hw;
	}

	pci_set_master(pdev);*/

	iwl_clear_stations_table(priv);

	memset(&(priv->txq[0]), 0, sizeof(struct iwl_tx_queue) * IWL_MAX_NUM_QUEUES);
	memset(&priv->card_alive, 0, sizeof(struct iwl_alive_resp));
	priv->data_retry_limit = -1;
	priv->ieee_channels = NULL;
	priv->ieee_rates = NULL;
	priv->phymode = -1;

	/*err = pci_set_dma_mask(pdev, DMA_32BIT_MASK);
	if (!err)
		err = pci_set_consistent_dma_mask(pdev, DMA_32BIT_MASK);
	if (err) {
		printk(KERN_WARNING DRV_NAME ": No suitable DMA available.\n");
		goto out_pci_disable_device;
	}*/

	//pci_set_drvdata(pdev, priv);
	//err = pci_request_regions(pdev, DRV_NAME);
	//if (err)		goto out_pci_disable_device;
	/* We disable the RETRY_TIMEOUT register (0x41) to keep
	 * PCI Tx retries from interfering with C3 CPU state */
	//pci_write_config_byte(pdev, 0x41, 0x00);

	//length = pci_resource_len(pdev, 0);
	//priv->hw_len = length;
	/*base = ioremap_nocache(pci_resource_start(pdev, 0), length);
	if (!base) {
		err = -ENODEV;
		goto out_pci_release_regions;
	}*/

	priv->hw_base = memBase;
	//IWL_DEBUG_INFO("pci_resource_len = 0x%08x\n", length);
	//IWL_DEBUG_INFO("pci_resource_base = %p\n", base);

	/* Initialize module parameter values here */

	if (param_disable) {
		priv->status |= STATUS_RF_KILL_SW;
		IWL_WARNING("STATUS_RF_KILL_SW enabled\n");
	}

	priv->iw_mode = IEEE80211_IF_TYPE_STA;
	pci_id= (fPCIDevice->configRead16(kIOPCIConfigDeviceID) << 16) | fPCIDevice->configRead16(kIOPCIConfigSubSystemID);

	//pci_id = (priv->pci_dev->device << 16) | priv->pci_dev->subsystem_device;

#if IWL == 4965
	priv->ps_mode = 0;
	priv->use_ant_b_for_management_frame = 1; /* start with ant B */
	priv->is_ht_enabled = 1;
	priv->channel_width = IWL_CHANNEL_WIDTH_40MHZ;
	priv->valid_antenna = 0x7;	/* assume all 3 connected */
	priv->ps_mode = IWL_MIMO_PS_NONE;
	priv->cck_power_index_compensation = iwl_read32(
		priv, CSR_HW_REV_WA_REG);

	iwl4965_set_rxon_chain(priv);

	printk(KERN_INFO DRV_NAME
	       ": Detected Intel Wireless WiFi Link 4965AGN\n");
#else
	switch (pci_id) {
	case 0x42221005:	/* 0x4222 0x8086 0x1005 is BG SKU */
	case 0x42221034:	/* 0x4222 0x8086 0x1034 is BG SKU */
	case 0x42271014:	/* 0x4227 0x8086 0x1014 is BG SKU */
	case 0x42221044:	/* 0x4222 0x8086 0x1044 is BG SKU */
		priv->is_abg = 0;
		break;

	/*
	 * Rest are assumed ABG SKU -- if this is not the
	 * case then the card will get the wrong 'Detected'
	 * line in the kernel log however the code that
	 * initializes the GEO table will detect no A-band
	 * channels and remove the is_abg mask.
	 */
	default:
		priv->is_abg = 1;
		break;
	}

	IWL_DEBUG_INFO(KERN_INFO DRV_NAME
	       ": Detected Intel PRO/Wireless 3945%sBG Network Connection\n",
	       priv->is_abg ? "A" : "");
#endif

	/* Device-specific setup */
	if (iwl_hw_set_hw_setting(priv)) {
		IWL_ERROR("failed to set hw settings\n");
		mutex_unlock(&priv->mutex);
		goto out_iounmap;
	}

	iwl_set_rxon_channel(priv, MODE_IEEE80211G, 6);
	iwl_setup_deferred_work(priv);
	iwl_setup_rx_handlers(priv);
	priv->rates_mask = IWL_RATES_MASK;
	/* If power management is turned on, default to AC mode */
	priv->power_mode = IWL_POWER_AC;
	priv->user_txpower_limit = IWL_DEFAULT_TX_POWER;
	/*err = request_irq(pdev->irq, iwl_isr, IRQF_SHARED, DRV_NAME, priv);
	if (err) {
		IWL_ERROR("Error allocating IRQ %d\n", pdev->irq);
		goto out_destroy_workqueue;
	}*/

	mutex_lock(&priv->mutex);

	//priv->rxq.bd = NULL;
	/*err = sysfs_create_group(&pdev->dev.kobj, &iwl_attribute_group);
	if (err) {
		IWL_ERROR("failed to create sysfs device attributes\n");
		mutex_unlock(&priv->mutex);
		goto out_release_irq;
	}*/
	/* fetch ucode file from disk, alloc and copy to bus-master buffers ...
	 * ucode filename and max sizes are card-specific. */
	err = iwl_read_ucode(priv);
	if (err) {
		IWL_ERROR("Could not read microcode: %d\n", err);
		mutex_unlock(&priv->mutex);
		goto out_pci_alloc;
	}

	mutex_unlock(&priv->mutex);

	IWL_DEBUG_INFO("Queing UP work.\n");
	//iwl_bg_up(priv);
	//queue_work(priv->workqueue, &priv->up);
	//clone->queue_te(0,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_up),priv,NULL,true);
	return 0;

 out_pci_alloc:
	//iwl_dealloc_ucode_pci(priv);

	//sysfs_remove_group(&pdev->dev.kobj, &iwl_attribute_group);

 out_release_irq:
	//free_irq(pdev->irq, priv);

 out_destroy_workqueue:
	//destroy_workqueue(priv->workqueue);
	//priv->workqueue = NULL;
	//iwl_unset_hw_setting(priv);

 out_iounmap:
	//iounmap(priv->hw_base);
 out_pci_release_regions:
	//pci_release_regions(pdev);
 out_pci_disable_device:
	//pci_disable_device(pdev);
	//pci_set_drvdata(pdev, NULL);
 out_ieee80211_free_hw:
	// ieee80211_free_hw(priv->hw);
 out:
	return err;
}

static void iwl_pci_remove(struct pci_dev *pdev)
{
/*	struct iwl_priv *priv = pci_get_drvdata(pdev);
	struct list_head *p, *q;
	int i;

	if (!priv)
		return;

	IWL_DEBUG_INFO("*** UNLOAD DRIVER ***\n");

	mutex_lock(&priv->mutex);

	priv->status |= STATUS_EXIT_PENDING;

	iwl_down(priv);

	mutex_unlock(&priv->mutex);

	for (i = 0; i < IWL_IBSS_MAC_HASH_SIZE; i++) {
		list_for_each_safe(p, q, &priv->ibss_mac_hash[i]) {
			list_del(p);
			IOFree(list_entry(p, struct iwl_ibss_seq, list));
		}
	}

	sysfs_remove_group(&pdev->dev.kobj, &iwl_attribute_group);

	iwl_dealloc_ucode_pci(priv);

	if (priv->rxq.bd)
		iwl_rx_queue_free(priv, &priv->rxq);
	iwl_hw_txq_ctx_free(priv);

	iwl_unset_hw_setting(priv);
	iwl_clear_stations_table(priv);

	if (priv->mac80211_registered) {
		// ieee80211_unregister_hw(priv->hw);
		iwl_rate_control_unregister();
	}


	destroy_workqueue(priv->workqueue);
	priv->workqueue = NULL;

	free_irq(pdev->irq, priv);
	iounmap(priv->hw_base);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);

	IOFree(priv->channel_info);

	IOFree(priv->ieee_channels);
	IOFree(priv->ieee_rates);

	if (priv->ibss_beacon)
		dev_kfree_skb(priv->ibss_beacon);

	// ieee80211_free_hw(priv->hw);*/
}

#ifdef CONFIG_PM

static int iwl_pci_suspend(struct pci_dev *pdev, pm_message_t state)
{
	struct iwl_priv *priv = pci_get_drvdata(pdev);

	mutex_lock(&priv->mutex);

	priv->status |= STATUS_IN_SUSPEND;

	/* Take down the device; powers it off, etc. */
	iwl_down(priv);

	if (priv->mac80211_registered)
		ieee80211_stop_queues(priv->hw);

	pci_save_state(pdev);
	pci_disable_device(pdev);
	pci_set_power_state(pdev, PCI_D3hot);

	mutex_unlock(&priv->mutex);

	return 0;
}

void iwl_resume(struct iwl_priv *priv)
{
	unsigned long flags;

	/* The following it a temporary work around due to the
	 * suspend / resume not fully initializing the NIC correctly.
	 * Without all of the following, resume will not attempt to take
	 * down the NIC (it shouldn't really need to) and will just try
	 * and bring the NIC back up.  However that fails during the
	 * ucode verification process.  This then causes iwl_down to be
	 * called *after* iwl_hw_nic_init() has succeeded -- which
	 * then lets the next init sequence succeed.  So, we've
	 * replicated all of that NIC init code here... */

	iwl_write32(priv, CSR_INT, 0xFFFFFFFF);

	iwl_hw_nic_init(priv);

	iwl_write32(priv, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	iwl_write32(priv, CSR_UCODE_DRV_GP1_CLR,
		    CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);
	iwl_write32(priv, CSR_INT, 0xFFFFFFFF);
	iwl_write32(priv, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	iwl_write32(priv, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);

	/* tell the device to stop sending interrupts */
	iwl_disable_interrupts(priv);

	spin_lock_irqsave(&priv->lock, flags);
	iwl_clear_bit(priv, CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
	spin_unlock_irqrestore(&priv->lock, flags);

	spin_lock_irqsave(&priv->lock, flags);
	if (!iwl_grab_restricted_access(priv)) {
		iwl_write_restricted_reg(priv, ALM_APMG_CLK_DIS,
					 APMG_CLK_REG_VAL_DMA_CLK_RQT);
		iwl_release_restricted_access(priv);
	}
	spin_unlock_irqrestore(&priv->lock, flags);

	udelay(5);

	iwl_hw_nic_reset(priv);

	/* Bring the device back up */
	priv->status &= ~STATUS_IN_SUSPEND;
	//queue_work(priv->workqueue, &priv->up);
	iwl_bg_up(priv);
	//clone->queue_te(0,OSMemberFunctionCast(thread_call_func_t,clone,&darwin_iwi3945::iwl_bg_up),priv,NULL,true);
}

static int iwl_pci_resume(struct pci_dev *pdev)
{
	struct iwl_priv *priv = pci_get_drvdata(pdev);
	int err;

	printk(KERN_INFO "Coming out of suspend...\n");

	mutex_lock(&priv->mutex);

	pci_set_power_state(pdev, PCI_D0);
	err = pci_enable_device(pdev);
	pci_restore_state(pdev);

	/*
	 * Suspend/Resume resets the PCI configuration space, so we have to
	 * re-disable the RETRY_TIMEOUT register (0x41) to keep PCI Tx retries
	 * from interfering with C3 CPU state. pci_restore_state won't help
	 * here since it only restores the first 64 bytes pci config header.
	 */
	pci_write_config_byte(pdev, 0x41, 0x00);

	iwl_resume(priv);
	mutex_unlock(&priv->mutex);

	return 0;
}

#endif /* CONFIG_PM */

/*****************************************************************************
 *
 * driver and module entry point
 *
 *****************************************************************************/

/*static struct pci_driver iwl_driver = {
	.name = DRV_NAME,
	.id_table = iwl_hw_card_ids,
	.probe = iwl_pci_probe,
	.remove = __devexit_p(iwl_pci_remove),
#ifdef CONFIG_PM
	.suspend = iwl_pci_suspend,
	.resume = iwl_pci_resume,
#endif
};*/

/*static int __init iwl_init(void)
{

	int ret;
	printk(KERN_INFO DRV_NAME ": " DRV_DESCRIPTION ", " DRV_VERSION "\n");
	printk(KERN_INFO DRV_NAME ": " DRV_COPYRIGHT "\n");
	ret = pci_register_driver(&iwl_driver);
	if (ret) {
		IWL_ERROR("Unable to initialize PCI module\n");
		return ret;
	}
#ifdef CONFIG_IWLWIFI_DEBUG
	ret = driver_create_file(&iwl_driver.driver, &driver_attr_debug_level);
	if (ret) {
		IWL_ERROR("Unable to create driver sysfs file\n");
		pci_unregister_driver(&iwl_driver);
		return ret;
	}
#endif

	return ret;
}

static void __exit iwl_exit(void)
{
#ifdef CONFIG_IWLWIFI_DEBUG
	driver_remove_file(&iwl_driver.driver, &driver_attr_debug_level);
#endif
	pci_unregister_driver(&iwl_driver);
}

module_param_named(antenna, param_antenna, int, 0444);
MODULE_PARM_DESC(antenna, "select antenna (1=Main, 2=Aux, default 0 [both])");
module_param_named(disable, param_disable, int, 0444);
MODULE_PARM_DESC(disable, "manually disable the radio (default 0 [radio on])");
module_param_named(hwcrypto, param_hwcrypto, int, 0444);
MODULE_PARM_DESC(hwcrypto,
		 "using hardware crypto engine (default 0 [software])\n");
module_param_named(debug, param_debug, int, 0444);
MODULE_PARM_DESC(debug, "debug output mask");
module_param_named(disable_hw_scan, param_disable_hw_scan, int, 0444);
MODULE_PARM_DESC(disable_hw_scan, "disable hardware scanning (default 0)");

module_param_named(qos_enable, param_qos_enable, int, 0444);
MODULE_PARM_DESC(qos_enable, "enable all QoS functionality");

module_exit(iwl_exit);
module_init(iwl_init);
*/


