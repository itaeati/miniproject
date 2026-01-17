#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <signal.h>

#pragma pack(push, 1)
typedef struct EtherHeader {
	unsigned char dstMac[6];
	unsigned char srcMac[6];
	unsigned short type;
}Frame;

typedef struct IPHeader {
	unsigned char verihl;
	unsigned char tos;
	unsigned short length;
	unsigned short id;
	unsigned short flags;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;

	unsigned char srcIp[4];
	unsigned char dstIp[4];
}Packet;

typedef struct TCPHeader {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned int seq;
	unsigned int ack;
	unsigned short data_flag;
	unsigned short windowsize;
	unsigned short checksum;
	unsigned short urgent;
}tcpheader;

typedef struct UDPHeader {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned short length;
	unsigned short checksum;
}udpheader;

typedef struct ARPHeader{
	unsigned short MacType;
	unsigned short Protocol;
	unsigned char MacLen;
	unsigned char IpLen;
	unsigned short request;
	unsigned char srcMac[6];
	unsigned char srcIp[4];
	unsigned char dstMac[6];
	unsigned char dstIp[4];
}arpheader;

typedef struct DNSHeader{
	unsigned short trans_id;
	unsigned short flags;
	unsigned short questions;
	unsigned short answer_rrs;
	unsigned short authority_rrs;
	unsigned short additional_rrs;
}dnsheader;

typedef struct ICMPHeader {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short id;
	unsigned short seq;
}icmpheader;

typedef struct IPv6Header {
	unsigned char vtf[4];
	unsigned short length;
	unsigned char protocol;
	unsigned char ttl;
	unsigned char srcIp[16];
	unsigned char dstIp[16];

}IPv6;

typedef struct ICMPv6 {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
}ICMPv6_CM;

typedef struct ICMPv6Header_Ping {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short id;
	unsigned short seq;
}ICMPv6;

typedef struct ICMPv6_NS {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned int reserved;
	unsigned char targetIp[16];
	unsigned char type_flag;
	unsigned char length;
	unsigned char LinkMac[6];
}ICMPv6_NS;

typedef struct ICMPv6_NA {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned char flag[4];
	unsigned char TargetIp[16];
}ICMPv6_NA;
#pragma pack(pop)

typedef struct {
	pcap_dumper_t* dumper;
	FILE* txt_fp;
}savehandles;

void Ptr_Ether(Frame* pEther);
void Ptr_Ip(Packet* pIp, unsigned short ver, unsigned short ipLen, unsigned int PayloadLength);
void Ptr_TCP(tcpheader* ptcp, unsigned int tcpLen, unsigned int PayloadLength);
void Ptr_ICMP(icmpheader* picmp, unsigned int PayloadLength);
void Ptr_ARP(arpheader* parp);
void Ptr_UDP(udpheader* pudp, unsigned int PayloadLength, const u_char* pkt_data, unsigned short ipLen);
void Ptr_DNS(dnsheader* pdns, unsigned short opcode, unsigned short recode, unsigned int PayloadLength);
void Ptr_Ipv6(IPv6* pipv6, unsigned short version, unsigned short traffic, unsigned int flow);
void Ptr_Icmpv6(ICMPv6_CM* picmpv6, unsigned int PayloadLength);
void Ptr_Payload(char* temp, unsigned int num);

int capturedPacket (u_char* fp, const u_char* pkt_data, const struct pcap_pkthdr* header);
