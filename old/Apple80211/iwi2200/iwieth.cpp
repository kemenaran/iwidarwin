

#include "iwieth.h"

#define super IONetworkInterface
// REQUIRED! This macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires. Do NOT use super as the
// second parameter. You must use the literal name of the superclass.
OSDefineMetaClassAndStructors(IONetworkInterface2, IONetworkInterface);


const char * IONetworkInterface2::getNamePrefix() const
{
	return "wlan";
}

ifnet_t IONetworkInterface2::getIfnet() const
{
	IOLog("getIfnet \n");
	return super::getIfnet();
	
}

