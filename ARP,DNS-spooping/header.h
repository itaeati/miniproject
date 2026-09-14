#pragma once
// 소켓 프로그래밍을 위한 라이브러리 링크 (WinPcap, Winsock)
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "wpcap")

#include <pcap.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 구조체 패딩 방지 (1바이트 단위로 정렬하여 네트워크 패킷 구조와 딱 맞게 함)
#pragma pack(push, 1)

// 이더넷 헤더 (14 bytes)
typedef struct EtherHeader {
	unsigned char dstMac[6]; // 목적지 MAC 주소
	unsigned char srcMac[6]; // 출발지 MAC 주소
	unsigned short type;     // 상위 프로토콜 타입 (IP: 0x0800, ARP: 0x0806 등)
}Frame;

// ARP 헤더 (28 bytes)
typedef struct ARPHeader {
	unsigned short MacType;  // 하드웨어 타입 (이더넷: 1)
	unsigned short protocol; // 프로토콜 타입 (IPv4: 0x0800)
	unsigned char MacLen;    // MAC 주소 길이 (6)
	unsigned char IpLen;     // IP 주소 길이 (4)
	unsigned short request;  // 동작 (요청: 1, 응답: 2)
	unsigned char srcMac[6]; // 보내는 사람 MAC
	unsigned char srcIp[4];  // 보내는 사람 IP
	unsigned char dstMac[6]; // 받는 사람 MAC
	unsigned char dstIp[4];  // 받는 사람 IP
}arpheader;

// IP 헤더 (20 bytes - 옵션 제외)
typedef struct IPHeader {
	unsigned char verihl;    // 버전(4bit) + 헤더길이(4bit)
	unsigned char tos;       // 서비스 타입
	unsigned short length;   // 전체 길이
	unsigned short id;       // 패킷 ID (단편화 식별용)
	unsigned short flags;    // 플래그 및 오프셋
	unsigned char ttl;       // Time To Live
	unsigned char protocol;  // 상위 프로토콜 (TCP: 6, UDP: 17)
	unsigned short checksum; // 헤더 체크섬

	unsigned char srcIp[4];  // 출발지 IP
	unsigned char dstIp[4];  // 목적지 IP
}Packet;

// UDP 헤더 (8 bytes)
typedef struct UDPHeader {
	unsigned short srcPort;  // 출발 포트
	unsigned short dstPort;  // 목적 포트
	unsigned short length;   // UDP 길이 (헤더+데이터)
	unsigned short checksum; // UDP 체크섬
}Segment;

// DNS 헤더 (12 bytes - 가변 길이 질문/응답 제외)
typedef struct DNSHeader {
	unsigned short trans_id;       // 트랜잭션 ID (요청/응답 매칭용)
	unsigned short flags;          // 플래그 (QR, Opcode, AA, TC, RD, RA, Rcode 등)
	unsigned short Questions;      // 질문 개수
	unsigned short Answer_rrs;     // 응답 개수
	unsigned short Authority_rrs;  // 권한(NS) 개수
	unsigned short Additional_rrs; // 추가 정보 개수
}Dnsheader;

// UDP/TCP 체크섬 계산을 위한 가상 헤더 (Pseudo Header)
typedef struct PseudoHeader {
	unsigned int srcip;    // 출발 IP
	unsigned int dstip;    // 목적 IP
	unsigned char zero;    // 0으로 채움
	unsigned char protocol;// 프로토콜 번호 (UDP: 17)
	unsigned short length; // UDP/TCP 헤더+데이터 길이
}pseudo;

#pragma pack(pop) // 패딩 설정 복구

// 함수 원형 선언
unsigned short CalchecksumIp(Packet* pip);
unsigned short CalchecksumUdp(Packet* pip, Segment* pUdp);