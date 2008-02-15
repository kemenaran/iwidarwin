/*
 *  iwi3945.cpp
 *  iwi3945
 *
 *  Created by Sean Cross on 1/19/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */

#include "iwi3945.h"
#include "defines.h"
#include "compatibility.h"

// Define my superclass
#define super IO80211Controller
//IO80211Controller
// REQUIRED! This macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires. Do NOT use super as the
// second parameter. You must use the literal name of the superclass.
OSDefineMetaClassAndStructors(darwin_iwi3945, IO80211Controller);




// Magic to make the init/exit routines public.
extern "C" {
    extern int (*init_routine)();
    extern void (*exit_routine)();
	
	
}
extern void setCurController(IONetworkController * tmp);
extern IOWorkLoop * getWorkLoop();
extern IOInterruptEventSource * getInterruptEventSource();
extern int if_down();

IOService * my_provider;
#pragma mark -
#pragma mark Overrides required for implementation

IOService *darwin_iwi3945::getProvider() {
/*	if(!provider)
		return NULL;*/
    return my_provider;
}

bool darwin_iwi3945::addMediumType(UInt32 type, UInt32 speed, UInt32 code, char* name) {
    return false;
}

UInt32 darwin_iwi3945::handleInterrupt() {
    return 0;
}

int darwin_iwi3945::outputRaw80211Packet( IO80211Interface * interface, mbuf_t m )
{
    return ENXIO;
}


#pragma mark -
#pragma mark Setup and teardown
bool darwin_iwi3945::init(OSDictionary *dict)
{
	return super::init(dict);
}


bool darwin_iwi3945::start(IOService *provider)
{
	UInt16	reg;
    IOLog("iwi3945: Starting\n");
    int err = 0;
    
	do {
        
        // Note: super::start() calls createWorkLoop & getWorkLoop
		if ( super::start(provider) == 0) {
			IOLog("%s ERR: super::start failed\n", getName());
			break;
		}
		
		setCurController(this);
		my_provider=provider;
		if( init_routine() )
			return false;
        //currentController=this;

        return true;
    } while(false);
    
    free();
    return false;
}



void darwin_iwi3945::free(void)
{
	if_down();
	IOLog("iwi3945: Freeing\n");
	IOInterruptEventSource * fInterruptSrc = getInterruptEventSource();
	if( fInterruptSrc ){
		printf("INT OK\n");
		fInterruptSrc->disable();
		fInterruptSrc->release();
		super::free();
	}
    
}


void darwin_iwi3945::stop(IOService *provider)
{
	IOLog("iwi3945: Stopping\n");
	IOWorkLoop * workqueue = getWorkLoop();
	IOInterruptEventSource * fInterruptSrc = getInterruptEventSource();
	if (fInterruptSrc && workqueue){
		printf("Stopping OK\n");
        workqueue->removeEventSource(fInterruptSrc);
		super::stop(provider);
	}
}