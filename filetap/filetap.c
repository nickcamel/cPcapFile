#include "inc/filetap.h"
#include <stdlib.h> // atoi


//#include <unistd.h>
int main(int argc, char *argv[]) {
	
	/*
	foreach(key, asci_d) {
		printf("KEY: %d\n", *key);
	};
	*/
	
	// Parse input arguments	
	if (parse_input(argc, argv)!=0) {
		return 1;		
	}	
	
	if (file_hdr_print && (parse_file_header()!=0) ) {
		return 1;
	}
	
	// Setup PCAP session (PCAP-session handle, snaplen, filter etc..)
	if (setup_pcap_session()!=0){
		return 1;
	}
	
	//_______________________
	/* Start sniffing packets */
	//_______________________
	printf("\nWaiting for packets...\n\n");
	
	// Loop through n_pkts_rcv packets
	pcap_loop(hdl_pcap, n_pkts_rcv, process_simple_packet, (u_char *) "Filetap!");
	
	printf("No more packets\n");

	//_______________________
	/* Close program */
	//_______________________
	close_session();
	
	return 0;
}


int parse_file_header() {
	
	// Get the header size, in bytes
	int size_buf = FILE_HDR_SIZE;
	
	// Allocate buffer array
	char buffer[size_buf];
	
	// Open input file
	file_in = fopen(file_in_loc, "r");
	
	if (file_in==NULL) {
		printf("Error opening file: %s\n", file_in_loc);
		return 1;
	}
	
	// Read in bytes in to buffer
	fread(buffer, size_buf, 1, file_in);	
		
	printf("______________\nFile Header. magic number etc...\n");
	
	// Do some dev stuff
	if (DO_DEV==1) {
		dev_parse_file_hdr(buffer);	
	}
	
	// Print the header bytes
	int ibyte;
	for (ibyte=0; ibyte<size_buf; ibyte+=4) {
		if ((ibyte)%4 == 0) {
			printf("\n");
		}
		// Print per 4 bytes
		printf("0x%08x ", ((buffer[ibyte]&0xFF)<<24) + 
			((buffer[ibyte+1]&0xFF)<<16) + 
			((buffer[ibyte+2]&0xFF)<<8) +
			((buffer[ibyte+3]&0xFF)));
	}
	printf("\n______________\n");
	
	// Close file
	fclose(file_in);
	
	return 0;
}


void process_simple_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
	
	i_pkt++;
	printf("Packet no: %d\n", i_pkt);
	// Print out header info
	long int hdr_time = header->ts.tv_sec/1000000 + header->ts.tv_usec;
	unsigned int caplen = header->caplen;
	
	printf("Header.\n Timestamp: %ld\n Length: %d\n CapLen: %d\n", hdr_time, header->len, caplen);
	
	if (has_radiotap_hdr) {
		printf(" Includes: %d bytes Radio Tap Header", buffer[2]);
		data_offs = buffer[2];
	}
	
	// Print out Captured Buffer (in HEX and STRING)
	// Looping to caplen since caplen<=snaplen. I.e if caplen is less than snaplen, no need to print nulls.
	int ibyte;
	int ichar;
	
	if (HEXDUMP==1) {
		printf("\n\t\t____________________\n\t\t\tHex dump\n\t\t____________________\n");
		
		if (has_radiotap_hdr) {
			printf("Radio Tap Header:\n");
			for (ibyte = 0; ibyte<data_offs; ibyte++) {
					printf("0x%02x ", buffer[ibyte]);
					if ((ibyte+1)%16==0) {
						printf("\n");
						
						for (ichar = ibyte-15; ichar<=ibyte; ichar++) {					
							printf("%4c ", (char) buffer[ichar]);
						}
						
						printf("\n");
					}
			}
			printf("\n802.11 Data:\n");
		}
		
		for (ibyte = data_offs; ibyte<caplen; ibyte++) {
				printf("0x%02x ", buffer[ibyte]);
				if ((ibyte+1)%16==0) {
					printf("\n");
					
					for (ichar = ibyte-15; ichar<=ibyte; ichar++) {					
						printf("%4c ", (char) buffer[ichar]);
					}
					
					printf("\n");
				}
		}
	}
	
	if (STRINGDUMP==1) {
		printf("\n\n\t\t____________________\n\t\t\tString dump\n\t\t____________________\n");
		for (ichar = 0; ichar<caplen; ichar++) {
			
			// Make a linebreak every 32 bytes
			if ((ichar+1)%32==0) {
				printf("\n");
			}
			
			// This section picks out the ascii chars we want to print, else it prints a . (dot).
			
			// Print this byte if char is NOT in our ascii range
			u_char false_char = (u_char) 46;
			
			// Print this byte if char is in our ascii range
			u_char true_char = (u_char) buffer[ichar];
			
			u_char t_char = (buffer[ichar]>=asci_d[0] && buffer[ichar]<=asci_d[1]) || 
							(buffer[ichar]>=asci_d[2] && buffer[ichar]<=asci_d[3]) || 
							(buffer[ichar]>=asci_d[4] && buffer[ichar]<=asci_d[5]) ? true_char/*buffer[ichar]*/ : false_char;
			printf("%c", t_char);
			
		}

		printf("\n\n");
	}
	
}


int setup_pcap_session() {
	
	//____________________________________
	/* Initialize and setup PCAP session */
	//____________________________________
	
	
	/* Open pcap session using inputted file */
	hdl_pcap = pcap_open_offline(file_in_loc, errbuf);
	
	if (hdl_pcap==NULL) {
		printf("Error! %s\n", errbuf);
		return 1;
	}		
	
	/* Compile and set the filter */
	// Compile the filter for this pcap session/handle	
	if (pcap_compile(hdl_pcap, &mybpf, filter_expr, optim, dev_netmask) != 0) {
		printf("Couldn't compile filter. %s\n", errbuf);
		pcap_perror(hdl_pcap, "Err \n");
		return 1;
	}
	
	// Check if filter can be set
	if ( pcap_setfilter(hdl_pcap, &mybpf) != 0) {
		printf("Couldn't set filter. %s\n", errbuf);
		pcap_perror(hdl_pcap, "Err \n");
		return 1;
	}
	
	// Check link layer type
	if (pcap_datalink(hdl_pcap)==LINKTYPE_IEEE802_11_RADIOTAP) {
		printf("\nFound LINKTYPE_IEEE802_11_RADIOTAP\n");
		has_radiotap_hdr = true;
	}	
	
	if ( (DO_DEV==1) && file_hdr_print && (has_radiotap_hdr!=has_radiotap_hdr_file) ) {
		// This link layer mismatch error is a dev operation, where we manually read
		// the link layer type value from the file header which sets the variable
		// 'has_radiotap_hdr_file'. Built in pcap_datalink() does the same thing, though
		// setting 'has_radiotap_hdr'.
		// So, just wanting to verify our job in extracting the data link type manually.
		printf("\n\nLink Layer found mismatch!!! \n\n");
		printf("has_hdr %d\nhas_hdr_file %d\n", has_radiotap_hdr, has_radiotap_hdr_file);
	}
	
	// Open file handles to empty, writable (w) and updatable (+) files.
	if (PRNTTOFILE==1) {
		file_out = fopen(file_out_loc, "w+");	
	}
	
	
	return 0;
	
}


void close_session() {
	
	// Close file handles	
	if (PRNTTOFILE==1) {
		fclose(file_out);
	}

	
	// Close the PCAP-session handle
	pcap_close(hdl_pcap);
	
}


int parse_input(int argc, char * argv[]) {
	
	// Used for checking file input options, which is mandatory
	bool file_chk = false;

	int iar;
	for (iar=1; iar<argc; iar+=2) {
				
		if (*argv[iar]=='-') { // catch the option tag '-'
			
			switch (*(argv[iar]+1)) { // the immediate (+1) address after should contain a valid option
				case 'n':
					// Number of packets to receive
					n_pkts_rcv = atoi((argv[iar+1])); // the immediate (+1) pointer after should contain a value
					printf("-n Packet count: %d\n", n_pkts_rcv);
					break;
					
				case 'f':
					file_chk = true;
					// File to processing
					printf("-f File: ");
					file_in_loc = argv[iar+1];
					printf("%s\n", file_in_loc);
					
					break;
					
				case 'i':
					// Print File header
					file_hdr_print = true;
					iar--;					
					printf("-i Include file header\n");
					break;
				
					
				case 'h':
					print_help();
					return 1;
					break;
					
				default:
					print_err_help(argv[iar]);
					return 1;
					break;
			}
			
		}
		else {
			print_err_help(argv[iar]);
			return 1;
		}
		
		
	}
	
	if (!file_chk) {
		// File input is mandatory
		printf("Error! No inputted file\n");
		return 1;
	}
	return 0;
}


void print_help() {
	printf("\n______________________________________________________________\n");
	printf("\nSynopsis: \n\t filetap -option [-option-val]\ne.g\t filetap -n 20 -f mypcap.pcap -i \n\n");
	printf("options:\n");
	printf("-n [count]\tCount. Number of packets to process. DEFAULT %d=ALL \n\n", DEFAULT_N_PACKETS);
	printf("-f [file]\tFilename. Filename to parse.\n\n");
	printf("-i \t\tInclude file header in print \n\n");
	printf("-h \t\tHelp. Print this help message\n\n");
					
}


void print_err_help(char * argin) {
	printf("\n\nOption '%s' not valid\n\n", argin);
	print_help();
}

void dev_parse_file_hdr(char * buffer) {
	
	// Byte order endianess
	if ( ((int) (buffer[0]&0xFF) == 0xd4) && ((int)(buffer[3]&0xFF) == 0xa1)) {
		
		// At least now we know that byte order is reverse in file header.
		// TODO: Maybe add support for checking middle nibbles aswell (for us and ns check)
		
		// Set where to look for radiotap_link_layer type byte
		radiotap_byte_idx = 20;		
		
	} else {
		
		radiotap_byte_idx = 23;
	}
	
	if ( (buffer[radiotap_byte_idx]&0xFF) == 0x7f) {
		has_radiotap_hdr_file = true;
	}
	
}