// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        printf("[DLL] DllMain: DLL이 성공적으로 로드되었습니다!\n");

        // 1. 프로세스 내의 모든 힙(Heap) 핸들을 가져옵니다.
        // 메인 프로세스의 default 힙과 CRT 힙 등을 모두 포함하여 가져옵니다.
        HANDLE heaps[100];
        DWORD numheap = GetProcessHeaps(100, heaps);
        DWORD i = 0;
        BOOL found = FALSE; // 우리가 찾는 대상 힙 블록을 발견했는지 여부 기록용 플래그

        // 2. 힙 리스트를 돌며 대상을 탐색합니다.
        while (i < numheap && !found)
        {
            HANDLE theap = heaps[i];
            PROCESS_HEAP_ENTRY entry;
            entry.lpData = NULL;

            // 탐색 중에 힙 구조가 다른 스레드에 의해 수정되지 않도록 락을 겁니다.
            // 락 획득 실패 시, 에러 방지를 위해 다음 힙으로 넘어갑니다.
            if (!HeapLock(theap))
            {
                i++;
                continue;
            }

            // 3. 해당 힙 내부의 모든 메모리 블록을 하나씩 조회(Walk)합니다.
            while (HeapWalk(theap, &entry))
            {
                // wFlags에 PROCESS_HEAP_ENTRY_BUSY가 세팅되어 있다면 현재 할당되어 사용 중인 메모리 블록입니다.
                // 메인 프로세스에서 malloc(1024)를 했으므로, 디버그 모드 오버헤드를 고려하여 크기 범위를 1024~1200바이트로 필터링합니다.
                if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) &&
                    (entry.cbData >= 1024 && entry.cbData <= 1200))
                {
                    char* rawBlockPtr = (char*)entry.lpData;

                    // 4. Debug 모드 오프셋 적용
                    // Debug 빌드 시 힙 블록 맨 앞에 붙는 48바이트(0x30)의 CRT 디버그 헤더를 건너뛰어
                    // 실제 메인 프로세스의 heap 변수가 반환받은 사용자 데이터 영역의 포인터 주소를 구합니다.
                    char* targetAddress = rawBlockPtr + 0x30;

                    // 5. 메모리가 비어있지 않은지 검사합니다.
                    if (targetAddress != NULL && targetAddress[0] != '\0')
                    {
                        // 6. fgets 입력 문자열의 고유 특징 패턴 매칭
                        // fgets는 입력 데이터 맨 끝에 줄바꿈 문자('\n')를 붙이고, 그 바로 뒤에 NULL('\0')을 붙입니다.
                        char* newline = strchr(targetAddress, '\n');

                        // 문자열 내에 '\n'이 존재하고, 그 바로 뒷바이트가 '\0'인 경우 
                        // 메인 프로세스의 fgets 전용 힙 버퍼로 확정 지을 수 있습니다.
                        if (newline != NULL && *(newline + 1) == '\0')
                        {
                            printf("\n============================================\n");
                            printf("[DLL] Found target fgets buffer!\n");
                            printf("[DLL] Exact Heap Address: %p\n", targetAddress);
                            printf("[DLL] Content: %s", targetAddress);

                            // 7. 데이터 조작 (메모리 변조 실행)
                            // 찾은 정확한 사용자 데이터 영역 주소에 원하는 문자열을 덮어씁니다.
                            strcpy_s(targetAddress, 1024, "Modified dynamically!");

                            printf("[DLL] Overwrite Completed!\n");
                            printf("============================================\n\n");

                            found = TRUE; // 대상을 찾았으므로 플래그를 세우고 루프 탈출 설정
                            break; // HeapWalk 루프 탈출
                        }
                    }
                }
            }

            // 8. 중요: 사용한 힙은 메인 프로세스에서 다시 사용할 수 있도록 반드시 잠금을 해제(Unlock)해 줍니다.
            HeapUnlock(theap);
            i++;
        }

        // 대상 힙을 탐색하지 못한 경우 오류 알림 출력
        if (!found)
        {
            printf("[DLL] Target Heap Block Not Found.\n");
        }

        // DllMain 로드 처리를 정상 완료하기 위해 TRUE를 반환
        return TRUE;
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        printf("[DLL] DllMain: DLL이 언로드됩니다.\n");
        return TRUE;
    }
    return TRUE;
}