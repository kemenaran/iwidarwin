/******************************************************************************
 *
 * Copyright(c) 2003 - 2007 Intel Corporation. All rights reserved.
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

#ifndef __iwl_3945_h__
#define __iwl_3945_h__
#include "defines.h"

#define RATE_MCS_CCK_MSK 0x200

#define  LINK_QUAL_FLAGS_SET_STA_TLC_RTS_MSK	(1<<0)

#define  LINK_QUAL_AC_NUM AC_NUM
#define  LINK_QUAL_MAX_RETRY_NUM 16

#define  LINK_QUAL_ANT_A_MSK (1<<0)
#define  LINK_QUAL_ANT_B_MSK (1<<1)
#define  LINK_QUAL_ANT_MSK   (LINK_QUAL_ANT_A_MSK|LINK_QUAL_ANT_B_MSK)





#if IWL != 3945
/*
 * In non IWL == 3945 builds, these must build to nothing in order to allow
 * the common code to not have several #if IWL == XXXX / #endif blocks
 */
static inline int iwl3945_get_antenna_flags(const struct iwl_priv *priv)
{ return 0; }
static inline int iwl3945_init_hw_rate_table(struct iwl_priv *priv)
{ return 0; }
static inline void iwl3945_reg_txpower_periodic(struct iwl_priv *priv) {}
static inline void iwl3945_bg_reg_txpower_periodic(void* *work)
{}
static inline int iwl3945_txpower_set_from_eeprom(struct iwl_priv *priv)
{ return 0; }
#else				/* IWL == 3945 */
/*
 * Forward declare iwl-3945.c functions for base.c
 */
extern int iwl3945_get_antenna_flags(const struct iwl_priv *priv);
extern int iwl3945_init_hw_rate_table(struct iwl_priv *priv);
extern void iwl3945_reg_txpower_periodic(struct iwl_priv *priv);
extern void iwl3945_bg_reg_txpower_periodic(void* *work);
extern int iwl3945_txpower_set_from_eeprom(struct iwl_priv *priv);
#endif				/* IWL == 3945 */

extern void iwl4965_add_station(struct iwl_priv *priv, const u8 * addr, int is_ap);

#endif
