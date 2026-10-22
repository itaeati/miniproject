#ifndef HEADER_H
#define HEADER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct EtherHeader {
	unsigned char dstMac[6];
	unsigned char srcMac[6];
	unsigned short type;
} Frame;

typedef struct IPv4Header {
	unsigned char verihl;
	unsigned char tos;
	unsigned short length;
	unsigned short id;
	unsigned short offset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	
	unsigned char srcip[4];
	unsigned char dstip[4];
} Packet;

typedef struct IPv6Header {
	unsigned int ver_tc_fl;
	unsigned short length;
	unsigned char nextheader;
	unsigned char hlimit;
	unsigned char srcip[16];
	unsigned char dstip[16];
} Packet_Jumbo;

#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

typedef struct TCPHeader {
	unsigned short srcport;
	unsigned short dstport;
	unsigned int seq;
	unsigned int ack;
	unsigned char offset_res; /* Data offset (4 bits) + Reserved (4 bits) */
	unsigned char flags;      /* TCP Flags (FIN, SYN, RST, PSH, ACK, URG) */
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent;
} tcpheader;

typedef struct UDPHeader {
	unsigned short srcport;
	unsigned short dstport;
	unsigned short length;
	unsigned short checksum;
} udpheader;
#pragma pack(pop)

#endif /* HEADER_H */
