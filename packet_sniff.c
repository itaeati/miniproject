#include "header.h"

pcap_t* adhandle = NULL;

void stop_capturing(int signo)
{
	printf("detected exit sinal\n");
	printf("closing appication\n");
	if (adhandle != NULL)
		pcap_breakloop(adhandle);
}

void packet_dispatch(u_char* temp1, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	Frame* pEther = (Frame*)pkt_data;
	savehandles* handle = (savehandles*)temp1;
	/////////////////////////////////////////////////////////////////
	int status = 0;

	unsigned short cap_len = header->caplen;

	if (handle->dumper != NULL)
	{
		pcap_dump((u_char*)handle->dumper, header, pkt_data);
	}

	if ((status = capturedPacket((u_char*)handle->txt_fp, pkt_data, header)) == -1)
	{
		printf("Error : failed write file");
		return;
	}
	////////////////////////////////////////////////////////////////

	if (ntohs(pEther->type) != 0x0800 && ntohs(pEther->type) != 0x0806 && ntohs(pEther->type) != 0x86dd) return;

	Ptr_Ether(pEther);

	printf("\n\n");

	if (ntohs(pEther->type) == 0x0800) //// IPv4Header
	{
		printf("\n\nIPv4Header\n\n");

		Packet* pIp = (Packet*)(pkt_data + sizeof(Frame));

		unsigned short ver = (pIp->verihl & 0xF0) >> 4;
		unsigned short ipLen = (pIp->verihl & 0x0F) * 4;
		unsigned int PayloadLength = ntohs(pIp->length) - ipLen;

		Ptr_Ip(pIp, ver, ipLen, PayloadLength);

		putchar('\n');

		if (pIp->protocol == 1)//// ICMPHeader
		{
		    printf("\n\nICMPHeader\n\n");
		    icmpheader* picmp = (icmpheader*)(pkt_data + sizeof(Frame) + ipLen);

		    Ptr_ICMP(picmp, PayloadLength); 

		    return;
		}
		else if(pIp->protocol == 6)//// TCPHeader
		{
		    printf("\n\nTCPHeader\n\n");
		    tcpheader* ptcp = (tcpheader*)(pkt_data + sizeof(Frame) + ipLen);

		    unsigned int tcpLen = ((ntohs(ptcp->data_flag) & 0xF000) >> 12) * 4;

		    Ptr_TCP(ptcp, tcpLen, PayloadLength);
		    return;
		}
		else if (pIp->protocol == 17)//// UDPHeader
		{
		    printf("\n\nUDPHeader\n\n");
		    udpheader* pudp = (udpheader*)(pkt_data + sizeof(Frame) + ipLen);

		    Ptr_UDP(pudp, PayloadLength, pkt_data, ipLen);

		    return;
		}
	}

	else if (ntohs(pEther->type) == 0x0806)//// ARPHeader
	{
		printf("\n\nARPHeader\n\n");
		arpheader* parp = (arpheader*)(pkt_data + sizeof(Frame));

		Ptr_ARP(parp);

		return;
	}

	else if (ntohs(pEther->type) == 0x86DD)//// IPv6Header
	{
		printf("\n\nIPv6Header\n\n");

		IPv6* pipv6 = (IPv6*)(pkt_data + sizeof(Frame));
		unsigned short version = (pipv6->vtf[0] & 0xF0) >> 4;
		unsigned short traffic = ((pipv6->vtf[0] & 0x0F) << 4) | ((pipv6->vtf[1] & 0xF0) >> 4);
		unsigned int flow = ((pipv6->vtf[1] & 0x0F) << 16) | (pipv6->vtf[2] << 8) | (pipv6->vtf[3]);
		unsigned int PayloadLength = (ntohs(pipv6->length));

		Ptr_Ipv6(pipv6, version, traffic, flow);

		putchar('\n');

		if (pipv6->protocol == 6)//// TCPHeader
		{
			printf("\n\nTCPHeader\n\n");
			tcpheader* ptcp = (tcpheader*)(pkt_data + sizeof(Frame) + sizeof(IPv6));
			unsigned int tcpLen = ((ntohs(ptcp->data_flag) & 0xF000) >> 12) * 4;

			Ptr_TCP(ptcp, tcpLen, PayloadLength);
			return;
		}

		else if (pipv6->protocol == 58)//// ICMPv6Header
		{
			ICMPv6_CM* picmpv6 = (ICMPv6_CM*)(pkt_data + sizeof(Frame) + sizeof(IPv6));
			printf("\n\nICMPv6Header\n\n");

			Ptr_Icmpv6(picmpv6, PayloadLength);
			return;
		}
		
		else if(pipv6->protocol == 17)//// UDPHeader
		{
			printf("\n\nUDPHeader\n\n");
			unsigned short ipLen = sizeof(IPv6);

			udpheader* pudp = (udpheader*)(pkt_data + sizeof(Frame) + ipLen);
			Ptr_UDP(pudp, PayloadLength, pkt_data, ipLen);

			return;
		}


	}

	return;
}

int main(int argc, char* argv[])
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_dumper_t* dumper;
	////////////////////////////////////////////
	FILE* fp = fopen("./pcapfile/log.txt", "wb+");

	if (fp == NULL)
	{
		printf("Error : create file handler\n");
		return -1;
	}
	////////////////////////////////////////////

	savehandles myhandle;

	char errbuf[PCAP_ERRBUF_SIZE];

	int i = 0, inum;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		printf("ERROR : can't find devs\n");
		exit(1);
	}

	for (d = alldevs; d; d = d->next)
	{
		printf("%d.%s", ++i, d->name);

		if(d->description)
		    printf(" (%s)\n", d->description);
		else
		    printf(" (No description available)\n");
	}

	if (i <= 0)
	{
		printf("\nNo interface found!\n");
		pcap_freealldevs(alldevs);
	}

	printf("Enter interface number(1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("out of range\n");
		pcap_freealldevs(alldevs);
		exit(1);
	}

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
	{
		printf("Unable to open the adapter\n");
		pcap_freealldevs(alldevs);
		exit(1);
	}

	dumper = pcap_dump_open(adhandle, "./pcapfile/captured.pcap");
	if (dumper == NULL) return -1;

	signal(SIGINT, stop_capturing);

	printf("\ncapturing Packets (IPv4, ARP, IPv6, ICMP, DNS)\n");

	myhandle.dumper = dumper;
	myhandle.txt_fp = fp;

	pcap_loop(adhandle, 0, packet_dispatch, (u_char*)&myhandle);
	pcap_freealldevs(alldevs);

	if(dumper != NULL)
	{
		pcap_dump_close(dumper);
		printf("pcap file saved\n");
	}
	if (adhandle != NULL)
	{
		pcap_close(adhandle);
		printf("handle returned\n");
	}
	//////////////////
	fclose(fp);
	//////////////////
	return 0;
}
