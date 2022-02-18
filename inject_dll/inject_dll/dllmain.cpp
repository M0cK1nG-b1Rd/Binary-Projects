// dllmain.cpp : 定义 DLL 应用程序的入口点。
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
{   // 当进程执行LoadLibrary时创建一个线程，执行ThreadProc线程
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
        break;
    }
    return TRUE;
}

