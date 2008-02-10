/*
 *  iwi3945.cpp
 *  iwi3945
 *
 *  Created by Sean Cross on 1/19/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */

#include "iwi3945.h"

// Define my superclass
#define super IOEthernetController
//IO80211Controller
// REQUIRED! This macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires. Do NOT use super as the
// second parameter. You must use the literal name of the superclass.
OSDefineMetaClassAndStructors(darwin_iwi3945, IOEthernetController);//IO80211Controller);


	
bool darwin_iwi3945::init(OSDictionary *dict)
{
	return super::init(dict);
}