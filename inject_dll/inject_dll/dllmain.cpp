// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"

// B.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"

DWORD WINAPI ThreadProc(LPVOID lpParaneter) {
    for (;;) {
        Sleep(1000);
        printf("DLL RUNNING...");
    }
}

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
                     )
{   // ������ִ��LoadLibraryʱ����һ���̣߳�ִ��ThreadProc�߳�
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
        break;
    }
    return TRUE;
}

