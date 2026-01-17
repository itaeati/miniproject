#include "header.h"

int capturedPacket(u_char* fp, const u_char* pkt_data, const struct pcap_pkthdr* header)
{
	FILE* pit = (FILE*)fp;

	fprintf(pit, "Timstamp: %ld.%06ld | CapLen : %u | Len : %u\n\n", header->ts.tv_sec, header->ts.tv_usec, header->caplen, header->len);
	
	fprintf(pit, "Data : ");
	
	for (unsigned int i = 0; i < header->caplen; i++)
	{
		fprintf(pit, "%02X ", pkt_data[i]);
		if ((i + 1) % 16 == 0) fprintf(pit, "\n ");
	}

	fprintf(pit, "\n\n---------------------------------------------\n\n");

	fflush(pit);

	return 0;
}
