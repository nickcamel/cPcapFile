#ifndef HEADERLIVETAP
#define HEADERLIVETAP

#include "defines.h"
#include "setup.h"

#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

int parse_file_header();
int setup_pcap_session();
void close_session();
int parse_input(int, char * argv[]);
void print_help();
void print_err_help(char * argv);
void dev_parse_file_hdr(char * buf);
/* 	Declare packet-processing function.
	Body of function is defined by developer, however, pcap-lib defines the inputs.
*/
void process_simple_packet(u_char *, const struct pcap_pkthdr *, const u_char * usr_defined_str);


//_____________
/*  SETUP */
//_____________
int flags = 1;								// Promiscouos mode. capture all packets  
int timeout = 0;							// In [ms]. 0 = wait for ever for packet to arrive

// Filter parameters 
// NOTE: If we dont compile a filter, snaplen will have on effect. (I think).
// However, we need a filter here to filter out beacons and avoid "Not a beacon"-alerts
int optim = 0;								//? "Optimize resulting code from pcap_compile" ?
bpf_u_int32 dev_netmask;					// Netmask
bpf_u_int32 dev_ipn;						// Ip number. Ipaddr&Netmask

//__________________________
/*  DECLARATION AND INIT */
//__________________________

// How many packets to try and capture. "Try" since a packet is not always caught when e.g using pcap-dispatch.
int n_pkts_rcv = DEFAULT_N_PACKETS;
int i_pkt = 0;
// File handles
char * file_in_loc;
FILE * file_in;
char * file_out_loc = "output.txt";
FILE * file_out;



//_________________________________________________________
/* Handles and other variables necessary for computation */
//_________________________________________________________

pcap_t *hdl_pcap;					/* PCAP-Session handle */
struct bpf_program mybpf;			/* Filter program */ // Should be "struct bpf_program * mybpf"  ??;
char errbuf[PCAP_ERRBUF_SIZE];		/* Error string */


bool has_radiotap_hdr = false;
bool has_radiotap_hdr_file = false;
int radiotap_byte_idx;

unsigned int data_offs = 0;

bool file_hdr_print = false;

#endif