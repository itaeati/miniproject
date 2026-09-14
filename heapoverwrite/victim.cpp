// victim.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.
//

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <sddl.h> // SID 변환 함수(ConvertSidToStringSidW)를 사용하기 위한 헤더

int main(void)
{
    // 1. 현재 프로세스의 액세스 토큰을 엽니다.
    // 액세스 토큰은 해당 프로세스가 실행 중인 사용자 권한 정보(SID 등)를 담고 있습니다.
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed (%lu)\n", GetLastError());
        return 1;
    }

    // 2. 사용자 정보(TokenUser) 크기를 먼저 구해 메모리를 할당합니다.
    // GetTokenInformation을 크기인자 0으로 호출하여 필요한 버퍼 크기(len)를 구합니다.
    DWORD len = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(len);

    // 3. 실제로 토큰에서 현재 사용자 SID 정보를 가져옵니다.
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, len, &len)) {
        printf("GetTokenInformation failed (%lu)\n", GetLastError());
        CloseHandle(hToken);
        free(pTokenUser);
        return 1;
    }

    // 4. 이진 바이너리 형태의 SID(보안 식별자)를 읽기 쉬운 문자열 형태로 변환하여 출력합니다.
    LPWSTR sidString = NULL;
    if (ConvertSidToStringSidW(pTokenUser->User.Sid, &sidString)) {

        // 유니코드(Wide Character)로 SID 출력
        wprintf(L"현재 사용자 SID: %ls\n", sidString);

        // ANSI 문자열로 포맷 변환하여 출력
        printf("현재 사용자 SID (ANSI 변환): %S\n", sidString);

        // 사용한 SID 문자열 리소스 해제
        LocalFree(sidString);
    }
    else {
        printf("ConvertSidToStringSidW failed (%lu)\n", GetLastError());
    }

    // 5. 힙 메모리 공간을 1024바이트 만큼 동적 할당합니다.
    int size = 1024;

    char* heap = (char*)malloc(size);
    if (heap == NULL)
    {
        printf("Error : Malloc Failed (%d)\n", GetLastError());
        free(pTokenUser);
        CloseHandle(hToken);
        return -1;
    }
    // 할당받은 메모리를 0으로 초기화
    memset(heap, 0, size);

    // 6. 사용자로부터 데이터를 콘솔창으로 입력받아 힙 영역에 저장합니다.
    printf("Input Data : ");
    fgets((char*)heap, size, stdin);

    // 7. 메인 프로세스 측에서 할당한 힙 영역의 실제 시작 주소를 출력합니다.
    printf("Address : %p\n", heap);

    // 8. 대상 DLL(heapoverflow.dll)을 프로세스 가상 메모리에 로드(Attach)합니다.
    // 주의: 파일명 뒤에 공백("heapoverflow.dll ")이 들어있으므로, 로드가 실패하면 공백을 제거해보세요.
    HMODULE dllcall = LoadLibrary(L"heapoverflow.dll ");
    if (dllcall == NULL)
    {
        printf("Error : LoadLibrary (%d)\n", GetLastError());
        free(pTokenUser);
        CloseHandle(hToken);
        free(heap);
        return -1;
    }

    // 9. DLL 로드 및 작동 완료 후, 힙 영역의 데이터 변화 상태와 주소를 다시 출력해봅니다.
    putchar('\n');
    printf("Data : %s\nAddress : %p", heap, heap);

    // 10. 프로그램 종료 전 사용한 토큰 핸들 및 동적 할당된 힙 메모리 자원들을 반환합니다.
    free(pTokenUser);
    CloseHandle(hToken);
    free(heap);
    FreeLibrary(dllcall);

    // 디버깅 상태 관찰을 위해 1,000초 동안 대기(Sleep)합니다.
    Sleep(1000000);
    return 0;
}