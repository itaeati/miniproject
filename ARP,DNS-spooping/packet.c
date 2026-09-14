#include "header.h"

// IP 헤더 체크섬 계산 함수
unsigned short CalchecksumIp(Packet* pip)
{
	// IHL(Internet Header Length) 추출: 하위 4비트 * 4 (byte 단위)
	unsigned char ihl = (pip->verihl & 0x0F) * 4;
	unsigned char wdata[30] = { 0 }; // 헤더 복사 버퍼
	unsigned int dwsum = 0; // 합계 저장 변수 (오버플로우 처리 위해 32비트 사용)

	// 헤더 내용을 버퍼에 복사
	memcpy(wdata, (BYTE*)pip, ihl);

	// 16비트 단위로 모두 더함
	for (int i = 0; i < ihl / 2; i++)
	{
		// 체크섬 필드 자체는 계산에서 제외 (보통 0으로 두고 계산하므로 생략 가능)
		if (i != 5)
			dwsum += wdata[i];

		// 캐리(올림수) 발생 시 하위 16비트에 더해줌 (1의 보수 덧셈)
		if (dwsum & 0xFFFF0000)
		{
			dwsum &= 0x0000FFFF;
			dwsum++;
		}
	}
	// 비트 반전(NOT)하여 결과 반환
	return ~(dwsum & 0x0000FFFF);
}

// UDP 체크섬 계산 함수 (가상 헤더 + UDP 헤더 + 데이터)
unsigned short CalchecksumUdp(Packet* pip, Segment* pUdp)
{
	pseudo pseudo = { 0 }; // 가상 헤더 선언

	unsigned short* pwpseudo = (unsigned short*)&pseudo;
	unsigned short* pwdatagram = (unsigned short*)pUdp; // 주의: 포인터 캐스팅

	int npseudosize = 6; // 가상 헤더 크기 (word 단위: 12 bytes / 2 = 6)
	int ndatagramsize = 0;

	UINT32 dwsum = 0;
	int Arraylength = 0;

	// 가상 헤더 값 채우기
	pseudo.srcip = *(unsigned int*)pip->srcIp;
	pseudo.dstip = *(unsigned int*)pip->dstIp;
	pseudo.protocol = 17; // UDP
	pseudo.zero = 0;
	pseudo.length = pUdp->length;

	ndatagramsize = ntohs(pseudo.length); // 실제 UDP 전체 길이

	// 홀수 바이트일 경우 패딩 처리 계산
	if (ndatagramsize % 2)
		Arraylength = ndatagramsize % 2 + 1;
	else
		Arraylength = ndatagramsize % 2;

	// 1. 가상 헤더 합산
	for (int i = 0; i < npseudosize; i++)
	{
		dwsum += pwpseudo[i];
		// 캐리 처리
		if (dwsum & 0xFFFF0000)
		{
			dwsum &= 0x0000FFFF;
			dwsum++;
		}
	}

	// 2. UDP 헤더 + 데이터 합산
	for (int i = 0; i < Arraylength; i++)
	{
		// 체크섬 필드 위치(4번째 워드)는 제외하고 합산
		if (i != 3)
			dwsum += pwdatagram[i];

		// 캐리 처리
		if (dwsum & 0xFFFF0000)
		{
			dwsum &= 0x0000FFFF;
			dwsum++;
		}
	}

	// 비트 반전하여 반환
	return (USHORT)~(dwsum & 0x0000FFFF);
}