#ifndef HEADERDEFINES
#define HEADERDEFINES

//_____________
/*  DEFINES */
//_____________
#define DO_DEV 0					// To do dev stuff or not to do dev stuff. That is the question.
#define PRNTTOFILE 0				// Print results to files
#define HEXDUMP 1					// Print HEX dump
#define STRINGDUMP 1				// Print String dump. Only 0-9, a-z and A-Z
#define DEFAULT_N_PACKETS 0			// 0=all Number of packets to receive if no user input.
#define N_BITS_PER_BYTE 8			// Define number of bits per byte. 
#define FILE_HDR_SIZE 40			// File header size. Defined!
#define LINKTYPE_IEEE802_11_RADIOTAP 127 // RADIOTAP Header value. Defined!


// ASCII ranges 

// (letters and numbers only)
char asci_d[] = {48, 57, 65, 90, 97, 122};

// all human friendly chars
// int asci_d[] = {32, 126, 0, 0, 0, 0};



//#define foreach( intpvar, intary ) int* intpvar; for( intpvar=intary; intpvar < (intary + (sizeof(intary)/sizeof(intary[0]))) ; intpvar++)


#endif