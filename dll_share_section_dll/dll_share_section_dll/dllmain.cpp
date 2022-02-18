// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

#pragma data_seg("Shared")

char g_buffer[0x1000] = {0};

#pragma data_seg()
#pragma comment(linker,"/section:Shared,rws")

extern "C"  __declspec(dllexport) void SetData(char *buf, DWORD dwDataLen)
{
	ZeroMemory(g_buffer, 0x1000);
	memcpy(g_buffer, buf, dwDataLen);
}

extern "C"  __declspec(dllexport) void GetData(char *buf)
{    
	memcpy(buf, g_buffer, 0x1000);
}

BOOL APIENTRY DllMain( HMODULE hModule,
					  DWORD  ul_reason_for_call,
					  LPVOID lpReserved
					  )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			// 区分是目标进程（游戏）还是控制进程（WG）
			// 如果是扫雷进程(winmine.exe)则开始接收数据
			char szModule[MAX_PATH] = { 0 };
			GetModuleFileNameA(NULL, szModule, MAX_PATH);
			if (strstr(szModule, "winmine") != NULL)
			{            
				MessageBoxA(NULL, "扫雷程序注入DLL成功", "", MB_OK);
				while (1)
				{
					if (strcmp(g_buffer, "quit") == 0) break; // 控制程序给的退出信号
					MessageBoxA(NULL, g_buffer, szModule, MB_OK);
				}
			}
			break;
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}


