#include "header.h"
void Ptr_Payload(char* temp, unsigned int num)
{
	if (num == 0) return;

	printf("Payload : ");

	for (int i = 0; i < num; i++)
	printf("%02X ", (unsigned char)temp[i]);

	printf("\n\n");

	return;
}

void Ptr_Ether(Frame* pEther)
{
	printf("*********************************************************************");
	printf("\n\nEthernet Header\n\n");
	printf("dstMac : %02X:%02X:%02X:%02X:%02X:%02X\nsrcMac : %02X:%02X:%02X:%02X:%02X:%02X\ntype : %04X\n", 
	pEther->dstMac[0], pEther->dstMac[1], pEther->dstMac[2], pEther->dstMac[3], pEther->dstMac[4], pEther->dstMac[5], 
	pEther->srcMac[0], pEther->srcMac[1], pEther->srcMac[2], pEther->srcMac[3], pEther->srcMac[4], pEther->srcMac[5], 
	ntohs(pEther->type));
}

void Ptr_Ip(Packet* pIp, unsigned short ver, unsigned short ipLen, unsigned int PayloadLength)
{
	printf("IP version : %hu\tIpHeaderLength : %hu\nPayloadLength : %u\nIdentification : %04X\nFlag : %04X\n", ver, ipLen, PayloadLength, ntohs(pIp->id), ntohs(pIp->flags));

	if ((ntohs(pIp->flags) & 0x8000)) printf("flag->Reserved flag on\n");
	else printf("flag->Reserved flag off\n");
	if ((ntohs(pIp->flags) & 0x4000)) printf("flag->Don't Fragment on\n");
	else printf("flag->Don't Fragment off\n");
	if ((ntohs(pIp->flags) & 0x2000)) printf("flag->More Fragment on\n");
	else printf("flag->More Fragment off\n");
	if ((ntohs(pIp->flags) & 0x1FFF)) printf("offset : %hu", ntohs(pIp->flags) & 0x1FFF);
	else printf("offset empty\n");

	printf("Time To Live : %u\nProtocol : %u\nChecksum : %04X\n", pIp->ttl, pIp->protocol, ntohs(pIp->checksum));
	printf("SrcIp : %u.%u.%u.%u\nDstIp : %u.%u.%u.%u\n", pIp->srcIp[0], pIp->srcIp[1], pIp->srcIp[2], pIp->srcIp[3], pIp->dstIp[0], pIp->dstIp[1], pIp->dstIp[2], pIp->dstIp[3]);
}

void Ptr_ICMP(icmpheader* picmp, unsigned int PayloadLength)
{
	printf("Packet Type : %u\nPacket code : %u\nChecksum : %04X\nIdentification : %04X\nSequence : %hu\n", picmp->type, picmp->code, ntohs(picmp->checksum), ntohs(picmp->id), ntohs(picmp->seq));
	Ptr_Payload((char*)picmp + sizeof(icmpheader), PayloadLength - sizeof(icmpheader));

	printf("*********************************************************************");
}

void Ptr_TCP(tcpheader* ptcp, unsigned int tcpLen, unsigned int PayloadLength)
{
	printf("srcPort : %hu\tdstPort : %hu\nSequence Num : %u\nAcknowledgment : %u\nData : %u\nflgas : %04X\n", ntohs(ptcp->srcPort), ntohs(ptcp->dstPort), ntohl(ptcp->seq), ntohl(ptcp->ack), tcpLen, ntohs(ptcp->data_flag) & 0x0FFF);
	if (ntohs(ptcp->data_flag) & 0x0001) printf("FIN flag on\n");
	else printf("FIN flag off\n");
	if (ntohs(ptcp->data_flag) & 0x0002) printf("SYN flag on\n");
	else printf("SYN flag off\n");
	if (ntohs(ptcp->data_flag) & 0x0004) printf("RST flag on\n");
	else printf("rst flag off\n");
	if (ntohs(ptcp->data_flag) & 0x0008) printf("psh flag on\n");
	else printf("psh flag off\n");
	if (ntohs(ptcp->data_flag) & 0x0010) printf("ack flag on\n");
	else printf("ack flag off\n");

	printf("windowsize : %hu\nchecksum : %04x\n", ntohs(ptcp->windowsize), ntohs(ptcp->checksum));
	if (ntohs(ptcp->data_flag) & 0x0020) printf("urg flag on urgent_ptr : %u", ntohs(ptcp->urgent));

	Ptr_Payload((char*)((unsigned char*)ptcp + tcpLen), PayloadLength - tcpLen);

	printf("*********************************************************************");
}

void Ptr_UDP(udpheader* pudp, unsigned int PayloadLength,  const u_char* pkt_data, unsigned short ipLen)
{
	printf("srcport : %hu\ndstport : %hu\nlength : %hu\nchecksum : %04x\n", ntohs(pudp->srcPort), ntohs(pudp->dstPort), ntohs(pudp->length), ntohs(pudp->checksum));

	if (ntohs(pudp->dstPort) == 53 || ntohs(pudp->srcPort) == 53)//// dnsheader
	{

		dnsheader* pdns = (dnsheader*)(pkt_data + sizeof(Frame) + ipLen + sizeof(udpheader));
		unsigned short opcode = (ntohs(pdns->flags) & 0x7800) >> 11;
		unsigned short recode = (ntohs(pdns->flags) & 0x000f);

		printf("\n\nDNSHeader\n\n");

		Ptr_DNS(pdns, opcode, recode, PayloadLength);

		return;
	}

	Ptr_Payload((char*)pudp + sizeof(udpheader), PayloadLength - sizeof(udpheader));

}

void Ptr_DNS(dnsheader* pdns, unsigned short opcode, unsigned short recode, unsigned int PayloadLength)
{
	printf("transcation id : %04x\nflags : %04x\n", ntohs(pdns->trans_id), ntohs(pdns->flags));

	if ((ntohs(pdns->flags) & 0x8000)) printf("query/response flag on ->  response\n");
	else printf("query/response flag off -> query\n");

	if (opcode == 0) printf("operation code flag off[0] -> standard query\n");
	else if (opcode == 1) printf("operation code flag on [1] -> inverse query\n");
	else if (opcode == 2) printf("operation code flag on [2] -> server status\n");
	else if (opcode == 4) printf("operation code flag on [4] -> notify\n");
	else if (opcode == 5) printf("operation code flag on [5] -> update\n");
	else printf("warning : werid packet[disconnect right now]\n");

	if (ntohs(pdns->flags) & 0x0400) printf("Authoritative Answer flag on ->  Real-DNS Server Answered\n");
	else printf("Authoritative Answer flag off -> Cashe Server Answered\n");

	if (ntohs(pdns->flags) & 0x0200) printf("Truncated flag on -> Packet-Loss[Request By TCP]\n");

	if (ntohs(pdns->flags) & 0x0100) printf("Recursion Desired flag on -> Ask Recursion\n");
	else printf("Recursion Desired flag off -> Ask server know\n");
	if (ntohs(pdns->flags) & 0x0080) printf("Recursion Available flag on -> Supported\n");
	else printf("Recursion Availbale flag off -> Not Supported\n");
	if (ntohs(pdns->flags) & 0x0070) printf("Warning : Werid Packet[Someone Try to hacking]\n");

	if (recode == 0) printf("Response Code flag off[0] -> Success\n");
	else if (recode == 1) printf("Response Code flag on [1] -> Format Error[Query Weird]\n");
	else if (recode == 2) printf("Response Code flag on [2] -> Server Failure\n");
	else if (recode == 3) printf("Response Code flag on [3] -> NXDOMAIN\n");
	else if (recode == 5) printf("Response Code flag on [5] -> Refused\n");

	printf("Number of Questions : %hu\t Number of Answer RRs : %hu\nAuthority RRs : %hu\tAdditional RRs : %hu\n", ntohs(pdns->questions), ntohs(pdns->answer_rrs), ntohs(pdns->authority_rrs), ntohs(pdns->additional_rrs));

	Ptr_Payload((char*)pdns + sizeof(dnsheader), PayloadLength - sizeof(udpheader) - sizeof(dnsheader));

	printf("*********************************************************************");
}

void Ptr_ARP(arpheader* parp)
{
	printf("MacType : %hu\nProtocol : %04X\nMacLen : %u\t, IpLen : %u\tRequest : %hu\nsrcMac : %02X:%02X:%02X:%02X:%02X:%02X\nsrcIp : %u.%u.%u.%u\ndstMac : %02X:%02X:%02X:%02X:%02X%02X\ndstIp : %u.%u.%u.%u\n", ntohs(parp->MacType), ntohs(parp->Protocol), parp->MacLen, parp->IpLen, ntohs(parp->request), parp->srcMac[0], parp->srcMac[1], parp->srcMac[2], parp->srcMac[3], parp->srcMac[4], parp->srcMac[5], parp->srcIp[0], parp->srcIp[1], parp->srcIp[2], parp->srcIp[3], parp->dstMac[0], parp->dstMac[1], parp->dstMac[2], parp->dstMac[3], parp->dstMac[4], parp->dstMac[5], parp->dstIp[0], parp->dstIp[1], parp->dstIp[2], parp->dstIp[3]);
	printf("*********************************************************************");
}

void Ptr_Ipv6(IPv6* pipv6, unsigned short version, unsigned short traffic, unsigned int flow)
{
	printf("Version : %hu\tTraffic Class : %hu\nFlow Label : %u\nPayloadLength : %hu\nProtocol : %u\nTTL : %u\n", version, traffic, flow, ntohs(pipv6->length), pipv6->protocol, pipv6->ttl);
	printf("srcIp : ");
	
	for (int i = 0; i < 16; i += 2)
	{
		unsigned short srcIp = pipv6->srcIp[i] << 8 | pipv6->srcIp[i + 1];
		printf("%X", srcIp);
		if (i < 14) printf(":");
	}
	
	printf("\n");

	printf("dstIp : ");

	for (int i = 0; i <16; i +=2)
	{
		unsigned short dstIp = pipv6->dstIp[i] << 8 | pipv6->dstIp[i + 1];
		printf("%X", dstIp);
		
		if (i < 14) printf(":");
	};

}

void Ptr_Icmpv6(ICMPv6_CM* picmpv6, unsigned int PayloadLength)
{
	printf("Type : %u\t\tCode : %u\nChecksum : %04X\n",picmpv6->type, picmpv6->code, ntohs(picmpv6->checksum));

	if (picmpv6->type == 135)
	{
		ICMPv6_NS* temp = (ICMPv6_NS*)picmpv6;
		printf("Reserved : %08X\n", ntohl(temp->reserved));

		printf("TargetIp : ");

		for (int i = 0; i < 16; i += 2)
		{
			unsigned short tempIp = temp->targetIp[i] << 8 | temp->targetIp[i+1];
			printf("%X", tempIp);
			if (i < 14) printf(":");
		}

		putchar('\n');

		printf("flag : %02X\nLength : %02X\n", temp->type_flag, temp->length);

		
		printf("TargetMac : %02X:%02X:%02X:%02X:%02X:%02X", temp->LinkMac[0], temp->LinkMac[1], temp->LinkMac[2], temp->LinkMac[3], temp->LinkMac[4], temp->LinkMac[5]);

		putchar('\n');
		return;
	}

	if (picmpv6->type == 136)
	{
		ICMPv6_NA* temp = (ICMPv6_NA*)picmpv6;
		printf("flag : %02X%02X%02X%02X\n", temp->flag[0], temp->flag[1], temp->flag[2], temp->flag[3]);

		printf("TargetIp : ");

		for (int i = 0; i < 16; i += 2)
		{
			unsigned short tempIp = temp->TargetIp[i] << 8 | temp->TargetIp[i+1];
			printf("%X", tempIp);
			if (i < 14) printf(":");
		}

		putchar('\n');
		return;
	}

	Ptr_Payload((char*)picmpv6 + sizeof(ICMPv6_CM), PayloadLength - sizeof(ICMPv6_CM));
}


