#ifndef HEADERSETUP
#define HEADERSETUP


#include "defines.h"

//_____________
/*  SETUP */
//_____________
int snaplen = 100;			// 64*1024 ~= all packets. 40 is enough for beacon! 40 for intial buffer + SSID length.

// Filter parameters 
// NOTE: If we dont compile a filter, snaplen will have on effect. (I think).
// However, we need a filter here to filter out beacons and avoid "Not a beacon"-alerts

// NOTE: filter expr is overwritten in case of BEACON_PROC_TYPE
//const char * filter_expr = "link[0]!=0x50 and link[0]!=0x80 and link[0]!=0x40"; // No beacons and probe requests
//const char * filter_expr = "host 10.66.195.10"; // Filter out host
// const char * filter_expr = "link[0]==0x80"; // Filter out beacons. Avoid "Not a beacon prints"
const char * filter_expr = "greater 0"; // All


#endif