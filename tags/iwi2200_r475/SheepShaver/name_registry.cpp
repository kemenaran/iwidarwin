/*
 *  name_registry.cpp - Name Registry handling
 *
 *  SheepShaver (C) 1997-2005 Christian Bauer and Marc Hellwig
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <string.h>

#include "sysdeps.h"
#include "name_registry.h"
#include "main.h"
#include "macos_util.h"
#include "user_strings.h"
#include "emul_op.h"
#include "thunks.h"

#define DEBUG 0
#include "debug.h"


// Function pointers
typedef int16 (*rcec_ptr)(const RegEntryID *, const char *, RegEntryID *);
static uint32 rcec_tvect = 0;
static inline int16 RegistryCStrEntryCreate(uintptr arg1, const char *arg2, uint32 arg3)
{
	SheepString arg2str(arg2);
	return (int16)CallMacOS3(rcec_ptr, rcec_tvect, (const RegEntryID *)arg1, arg2str.addr(), arg3);
}
typedef int16 (*rpc_ptr)(const RegEntryID *, const char *, const void *, uint32);
static uint32 rpc_tvect = 0;
static inline int16 RegistryPropertyCreate(uintptr arg1, const char *arg2, uintptr arg3, uint32 arg4)
{
	SheepString arg2str(arg2);
	return (int16)CallMacOS4(rpc_ptr, rpc_tvect, (const RegEntryID *)arg1, arg2str.addr(), (const void *)arg3, arg4);
}
static inline int16 RegistryPropertyCreateStr(uintptr arg1, const char *arg2, const char *arg3)
{
	SheepString arg3str(arg3);
	return RegistryPropertyCreate(arg1, arg2, arg3str.addr(), strlen(arg3) + 1);
}

// Video driver stub
static const uint8 video_driver[] = {
#include "VideoDriverStub.i"
};

// Ethernet driver stub
static const uint8 ethernet_driver[] = {
#ifdef USE_ETHER_FULL_DRIVER
#include "EthernetDriverFull.i"
#else
#include "EthernetDriverStub.i"
#endif
};

// Helper for RegEntryID
typedef SheepArray<sizeof(RegEntryID)> SheepRegEntryID;

// Helper for a <uint32, uint32> pair
struct SheepPair : public SheepArray<8> {
	SheepPair(uint32 base, uint32 size) : SheepArray<8>()
		{ WriteMacInt32(addr(), base); WriteMacInt32(addr() + 4, size); }
};


/*
 *  Patch Name Registry during startup
 */

void DoPatchNameRegistry(void)
{
	SheepVar32 u32;
	D(bug("Patching Name Registry..."));

	// Create "device-tree"
	SheepRegEntryID device_tree;
	if (!RegistryCStrEntryCreate(0, "Devices:device-tree", device_tree.addr())) {
		u32.set_value(BusClockSpeed);
		RegistryPropertyCreate(device_tree.addr(), "clock-frequency", u32.addr(), 4);
		RegistryPropertyCreateStr(device_tree.addr(), "model", "Power Macintosh");
					
		// Create "AAPL,ROM"
		SheepRegEntryID aapl_rom;
		if (!RegistryCStrEntryCreate(device_tree.addr(), "AAPL,ROM", aapl_rom.addr())) {
			RegistryPropertyCreateStr(aapl_rom.addr(), "device_type", "rom");
			SheepPair reg(ROM_BASE, ROM_SIZE);
			RegistryPropertyCreate(aapl_rom.addr(), "reg", reg.addr(), 8);
		}

		// Create "PowerPC,60x"
		SheepRegEntryID power_pc;
		//printf("pvr %x\n",PVR);
		char *str;
		switch (PVR >> 16) {
			case 1:		// 601
				str = "PowerPC,601";
				break;
			case 3:		// 603
				str = "PowerPC,603";
				break;
			case 4:		// 604
				str = "PowerPC,604";
				break;
			case 6:		// 603e
				str = "PowerPC,603e";
				break;
			case 7:		// 603ev
				str = "PowerPC,603ev";
				break;
			case 8:		// 750
				str = "PowerPC,750";
				break;
			case 9:		// 604e
				str = "PowerPC,604e";
				break;
			case 10:	// 604ev5
				str = "PowerPC,604ev";
				break;
			case 50:	// 821
				str = "PowerPC,821";
				break;
			case 80:	// 860
				str = "PowerPC,860";
				break;
			case 12:	// 7400, 7410, 7450, 7455, 7457
			case 0x800c:
			case 0x8000:
			case 0x8001:
			case 0x8002:
				str = "PowerPC,G4";
				break;
			default:
				str = "PowerPC,???";
				break;
		}
		if (!RegistryCStrEntryCreate(device_tree.addr(), str, power_pc.addr())) {
			u32.set_value(CPUClockSpeed);
			RegistryPropertyCreate(power_pc.addr(), "clock-frequency", u32.addr(), 4);
			u32.set_value(BusClockSpeed);
			RegistryPropertyCreate(power_pc.addr(), "bus-frequency", u32.addr(), 4);
			u32.set_value(TimebaseSpeed);
			RegistryPropertyCreate(power_pc.addr(), "timebase-frequency", u32.addr(), 4);
			u32.set_value(PVR);
			RegistryPropertyCreate(power_pc.addr(), "cpu-version", u32.addr(), 4);
			RegistryPropertyCreateStr(power_pc.addr(), "device_type", "cpu");
			switch (PVR >> 16) {
				case 1:		// 601
					u32.set_value(64);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-block-size", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-sets", u32.addr(), 4);
					u32.set_value(0x8000);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-size", u32.addr(), 4);
					u32.set_value(64);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-block-size", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-sets", u32.addr(), 4);
					u32.set_value(0x8000);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-size", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "tlb-sets", u32.addr(), 4);
					u32.set_value(256);
					RegistryPropertyCreate(power_pc.addr(), "tlb-size", u32.addr(), 4);
					break;
				case 3:		// 603
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-block-size", u32.addr(), 4);
					u32.set_value(64);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-sets", u32.addr(), 4);
					u32.set_value(0x2000);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-size", u32.addr(), 4);
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-block-size", u32.addr(), 4);
					u32.set_value(64);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-sets", u32.addr(), 4);
					u32.set_value(0x2000);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-size", u32.addr(), 4);
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "tlb-sets", u32.addr(), 4);
					u32.set_value(64);
					RegistryPropertyCreate(power_pc.addr(), "tlb-size", u32.addr(), 4);
					break;
				case 4:		// 604
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-block-size", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-sets", u32.addr(), 4);
					u32.set_value(0x4000);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-size", u32.addr(), 4);
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-block-size", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-sets", u32.addr(), 4);
					u32.set_value(0x4000);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-size", u32.addr(), 4);
					u32.set_value(64);
					RegistryPropertyCreate(power_pc.addr(), "tlb-sets", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "tlb-size", u32.addr(), 4);
					break;
				case 6:		// 603e
				case 7:		// 603ev
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-block-size", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-sets", u32.addr(), 4);
					u32.set_value(0x4000);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-size", u32.addr(), 4);
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-block-size", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-sets", u32.addr(), 4);
					u32.set_value(0x4000);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-size", u32.addr(), 4);
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "tlb-sets", u32.addr(), 4);
					u32.set_value(64);
					RegistryPropertyCreate(power_pc.addr(), "tlb-size", u32.addr(), 4);
					break;
				case 8:		// 750, 750FX
				case 0x7000:
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-block-size", u32.addr(), 4);
					u32.set_value(256);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-sets", u32.addr(), 4);
					u32.set_value(0x8000);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-size", u32.addr(), 4);
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-block-size", u32.addr(), 4);
					u32.set_value(256);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-sets", u32.addr(), 4);
					u32.set_value(0x8000);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-size", u32.addr(), 4);
					u32.set_value(64);
					RegistryPropertyCreate(power_pc.addr(), "tlb-sets", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "tlb-size", u32.addr(), 4);
					break;
				case 9:		// 604e
				case 10:	// 604ev5
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-block-size", u32.addr(), 4);
					u32.set_value(256);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-sets", u32.addr(), 4);
					u32.set_value(0x8000);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-size", u32.addr(), 4);
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-block-size", u32.addr(), 4);
					u32.set_value(256);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-sets", u32.addr(), 4);
					u32.set_value(0x8000);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-size", u32.addr(), 4);
					u32.set_value(64);
					RegistryPropertyCreate(power_pc.addr(), "tlb-sets", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "tlb-size", u32.addr(), 4);
					break;
				case 12:	// 7400, 7410, 7450, 7455, 7457
				case 0x800c:
				case 0x8000:
				case 0x8001:
				case 0x8002:
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-block-size", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-sets", u32.addr(), 4);
					u32.set_value(0x8000);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-size", u32.addr(), 4);
					u32.set_value(32);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-block-size", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-sets", u32.addr(), 4);
					u32.set_value(0x8000);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-size", u32.addr(), 4);
					u32.set_value(64);
					RegistryPropertyCreate(power_pc.addr(), "tlb-sets", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "tlb-size", u32.addr(), 4);
					break;
				case 0x39:	// 970
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-block-size", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-sets", u32.addr(), 4);
					u32.set_value(0x8000);
					RegistryPropertyCreate(power_pc.addr(), "d-cache-size", u32.addr(), 4);
					u32.set_value(128);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-block-size", u32.addr(), 4);
					u32.set_value(512);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-sets", u32.addr(), 4);
					u32.set_value(0x10000);
					RegistryPropertyCreate(power_pc.addr(), "i-cache-size", u32.addr(), 4);
					u32.set_value(256);
					RegistryPropertyCreate(power_pc.addr(), "tlb-sets", u32.addr(), 4);
					u32.set_value(0x1000);
					RegistryPropertyCreate(power_pc.addr(), "tlb-size", u32.addr(), 4);
					break;
				default:
					break;
			}
			u32.set_value(32);
			RegistryPropertyCreate(power_pc.addr(), "reservation-granularity", u32.addr(), 4);
			SheepPair reg(0, 0);
			RegistryPropertyCreate(power_pc.addr(), "reg", reg.addr(), 8);
		}

		// Create "memory"
		SheepRegEntryID memory;
		if (!RegistryCStrEntryCreate(device_tree.addr(), "memory", memory.addr())) {
			SheepPair reg(RAMBase, RAMSize);
			RegistryPropertyCreateStr(memory.addr(), "device_type", "memory");
			RegistryPropertyCreate(memory.addr(), "reg", reg.addr(), 8);
		}

		// Create "video"
		SheepRegEntryID video;
		if (!RegistryCStrEntryCreate(device_tree.addr(), "video", video.addr())) {
			RegistryPropertyCreateStr(video.addr(), "name","ATY,Rage128P2ks");
			RegistryPropertyCreateStr(video.addr(), "AAPL,connector", "monitor");
			RegistryPropertyCreateStr(video.addr(), "device_type", "display");
			SheepArray<sizeof(video_driver)> the_video_driver;
			Host2Mac_memcpy(the_video_driver.addr(), video_driver, sizeof(video_driver));
			RegistryPropertyCreate(video.addr(), "driver,AAPL,MacOS,PowerPC", the_video_driver.addr(), sizeof(video_driver));
			RegistryPropertyCreateStr(video.addr(), "model", "ATY,Rage128Pro2");
			u32.set_value(0x1002);
			RegistryPropertyCreate(video.addr(), "vendor-id", u32.addr(), 8);
			u32.set_value(0x5452);
			RegistryPropertyCreate(video.addr(), "device-id", u32.addr(), 8);
			u32.set_value(0x1002);
			RegistryPropertyCreate(video.addr(), "subsystem-vendor-id", u32.addr(), 8);
			u32.set_value(0x5452);
			RegistryPropertyCreate(video.addr(), "subsystem-id", u32.addr(), 8);
			u32.set_value(0);
			RegistryPropertyCreate(video.addr(), "revision-id", u32.addr(), 8);
			u32.set_value(0x38000);
			RegistryPropertyCreate(video.addr(), "class-code", u32.addr(), 8);
			u32.set_value(1);
			RegistryPropertyCreate(video.addr(), "interrupts", u32.addr(), 8);
			u32.set_value(0x8);
			RegistryPropertyCreate(video.addr(), "min-grant", u32.addr(), 8);
			u32.set_value(0);
			RegistryPropertyCreate(video.addr(), "max-latency", u32.addr(), 8);
			u32.set_value(0x1);
			RegistryPropertyCreate(video.addr(), "devsel-speed", u32.addr(), 8);
			u32.set_value(0x43525400);
			RegistryPropertyCreate(video.addr(), "display-type", u32.addr(), 8);
			u32.set_value(0);
			RegistryPropertyCreate(video.addr(), "ATY,Status", u32.addr(), 8);
			u32.set_value(0x10ff019b);
			RegistryPropertyCreate(video.addr(), "ATY,Flags", u32.addr(), 8);
			u32.set_value(0x733c);
			RegistryPropertyCreate(video.addr(), "ATY,RefCLK", u32.addr(), 8);
			u32.set_value(0x1fbd0);
			RegistryPropertyCreate(video.addr(), "ATY,MCLK", u32.addr(), 8);
			u32.set_value(0x1fbd0);
			RegistryPropertyCreate(video.addr(), "ATY,SCLK", u32.addr(), 8);
			const uint32 dat0[] = {htonl(0x3131332d), htonl(0x58585858), htonl(0x582d3130), htons(0x3400)};
			const uint32 dat[] = {htonl(0x3131332d), htonl(0x58585858), htonl(0x582d3130), htons(0x3400)};
			RegistryPropertyCreateStr(video.addr(), "ATY,Rom#", (const char*)dat);
			const uint32 dat2[] = {htonl(0x312e3737), 0x00};
			RegistryPropertyCreateStr(video.addr(), "ATY,FCode", (const char*)dat2);
			const uint32 dat3[] = {htonl(0x001b0000), htonl(0x00811000)};
			RegistryPropertyCreateStr(video.addr(), "Sime", (const char*)dat3);
			RegistryPropertyCreateStr(video.addr(), "AGP_Master","");
			RegistryPropertyCreateStr(video.addr(), "fast-back-to-back","");
			RegistryPropertyCreateStr(video.addr(), "iso6429-1983-color","");
			RegistryPropertyCreateStr(video.addr(), "character-set","ISO8859-1");
			u32.set_value(0x400);
			RegistryPropertyCreate(video.addr(), "widht", u32.addr(), 8);
			u32.set_value(0x300);
			RegistryPropertyCreate(video.addr(), "height", u32.addr(), 8);
			u32.set_value(0x8);
			RegistryPropertyCreate(video.addr(), "depth", u32.addr(), 8);
			u32.set_value(0x400);
			RegistryPropertyCreate(video.addr(), "linebytes", u32.addr(), 8);
			const uint32 dat4[] = {0, 0xffffffff};
			RegistryPropertyCreateStr(video.addr(), "AGP_Address_Range", (const char*)dat4);
			u32.set_value(0x02000000);
			RegistryPropertyCreate(video.addr(), "AGP_Address_Block", u32.addr(), 8);
			u32.set_value(1);
			RegistryPropertyCreate(video.addr(), "AGP_AllowOverlap", u32.addr(), 8);
			//u32.set_value(0x8c);
			//RegistryPropertyCreate(video.addr(), "iic-address", u32.addr(), 8);
			const uint32 dat55[] = {htonl(0xc2008010), 0,htonl(0x94000000),0,htonl(0x04000000),
			htonl(0x82008030),0,htonl(0x90020000),0,htonl(0x00020000),
			htonl(82008018),0,htonl(90000000),0,htons(0x4000)};
			RegistryPropertyCreateStr(video.addr(), "iic-addresses", (const char*)dat55);
			u32.set_value(1);
			RegistryPropertyCreate(video.addr(), "slot-names", u32.addr(), 8);
			u32.set_value(1);
			RegistryPropertyCreate(video.addr(), "#address-cells", u32.addr(), 8);
			u32.set_value(0);
			RegistryPropertyCreate(video.addr(), "#size-cells", u32.addr(), 8);
			u32.set_value(0x96008000);
			RegistryPropertyCreate(video.addr(), "address", u32.addr(), 8);
			const uint32 dat5[] = {htonl(0xc2008010), 0,htonl(0x94000000),0,htonl(0x04000000),
			htonl(0x82008030),0,htonl(0x90020000),0,htonl(0x00020000),
			htonl(82008018),0,htonl(90000000),0,htons(0x4000)};
			RegistryPropertyCreateStr(video.addr(), "assigned-addresses", (const char*)dat5);
			const uint32 dat6[] = {htonl(0x00ffffff), htonl(0xffffff00),htonl(0x0610069d), htonl(0x01010101),htonl(0x00080101),htonl(0x081b1496), htonl(0xe866e99c),htonl(0x574c9626),
			htonl(0x10484c00), htonl(0x02000101),htonl(0x01010101), htonl(0x01010101),htonl(0x01010101),htonl(0x01018813), htonl(0x80c020e0),htonl(0x22101040),
			htonl(0x13000ec8), htonl(0x1000001e),htonl(0x601820f0), htonl(0x30582020),htonl(0x10501300),htonl(0x0ec81000), htonl(0x001e0000),htonl(0x00fd004b),
			htonl(0x753c3c08), htonl(0x000a2020),htonl(0x20202020), htonl(0x000000fc),htonl(0x00694d61),htonl(0x630a2020), htonl(0x20202020),htonl(0x202000c8)};
			RegistryPropertyCreateStr(video.addr(), "EDID", (const char*)dat6);
			const uint32 dat7[] = {htons(0x8000), 0,0,0,0,
			htonl(0x02008030),0,0,0,htonl(0x00020000),
			htonl(0x42008010),0,0,0,htonl(0x04000000),
			htonl(0x02008018),0,0,0,htons(0x4000)};
			RegistryPropertyCreateStr(video.addr(), "reg", (const char*)dat7);
		}
	
		SheepRegEntryID agp;
		if (!RegistryCStrEntryCreate(device_tree.addr(), "agp", agp.addr())) {
		RegistryPropertyCreateStr(agp.addr(), "AAPL,connector", "uni-north-agp");
		u32.set_value(0x106b);
		RegistryPropertyCreate(agp.addr(), "vendor-id", u32.addr(), 8);
		u32.set_value(0x27);
		RegistryPropertyCreate(agp.addr(), "device-id", u32.addr(), 8);
		u32.set_value(0);
		RegistryPropertyCreate(agp.addr(), "revision-id", u32.addr(), 8);
		RegistryPropertyCreateStr(agp.addr(), "device_type", "uni-north-agp");
		RegistryPropertyCreateStr(agp.addr(), "compatible", "uni-north-agp");
		RegistryPropertyCreateStr(agp.addr(), "name", "uni-north-agp");
		RegistryPropertyCreateStr(agp.addr(), "AGP_Target", "");
		RegistryPropertyCreateStr(agp.addr(), "assigned-address", "");
		u32.set_value(0x00060000);
		RegistryPropertyCreate(agp.addr(), "class-code", u32.addr(), 8);
		u32.set_value(0);
		RegistryPropertyCreate(agp.addr(), "min-grant", u32.addr(), 8);
		u32.set_value(0);
		RegistryPropertyCreate(agp.addr(), "max-latency", u32.addr(), 8);
		u32.set_value(1);
		RegistryPropertyCreate(agp.addr(), "devsel-speed", u32.addr(), 8);
		const uint32 dat8[] = {htons(0x5800), 0,0,0,0};
		RegistryPropertyCreateStr(agp.addr(), "reg", (const char*)dat8);
		}
		
		// Create "ethernet"
		SheepRegEntryID ethernet;
		if (!RegistryCStrEntryCreate(device_tree.addr(), "ethernet", ethernet.addr())) {
			RegistryPropertyCreateStr(ethernet.addr(), "AAPL,connector", "ethernet");
			RegistryPropertyCreateStr(ethernet.addr(), "device_type", "network");
			SheepArray<sizeof(ethernet_driver)> the_ethernet_driver;
			Host2Mac_memcpy(the_ethernet_driver.addr(), ethernet_driver, sizeof(ethernet_driver));
			RegistryPropertyCreate(ethernet.addr(), "driver,AAPL,MacOS,PowerPC", the_ethernet_driver.addr(), sizeof(ethernet_driver));
			// local-mac-address
			// max-frame-size 2048
		}
	}
	D(bug("done.\n"));
}

void PatchNameRegistry(void)
{
	// Find RegistryCStrEntryCreate() and RegistryPropertyCreate() TVECTs
	rcec_tvect = FindLibSymbol("\017NameRegistryLib", "\027RegistryCStrEntryCreate");
	D(bug("RegistryCStrEntryCreate TVECT at %08x\n", rcec_tvect));
	rpc_tvect = FindLibSymbol("\017NameRegistryLib", "\026RegistryPropertyCreate");
	D(bug("RegistryPropertyCreate TVECT at %08x\n", rpc_tvect));
	if (rcec_tvect == 0 || rpc_tvect == 0) {
		ErrorAlert(GetString(STR_NO_NAME_REGISTRY_ERR));
		QuitEmulator();
	}

	// Main routine must be executed in PPC mode
	ExecuteNative(NATIVE_PATCH_NAME_REGISTRY);
}
