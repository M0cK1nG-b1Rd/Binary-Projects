#include "stdafx.h"

// 远程线程注入
BOOL InjectDLL()
{
	// 提权(win10)
	EnableDebugPrivilege();
	// 根据窗口名获取进程句柄
	HWND hWnd = FindWindow(NULL, "扫雷");
	if (hWnd == NULL)
	{
		OutputDebugString("获取窗口句柄失败\n");
		return FALSE;
	}
	DWORD dwPid = -1;
	GetWindowThreadProcessId(hWnd, &dwPid);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		OutputDebugString("打开进程失败\n");
		return FALSE;
	}
	// 在要注入的进程中申请一块内存，作为LoadLibrary的参数
	char szDllName[MAX_PATH] = "DLLShareSection-DLL.dll";
	LPVOID pAddress = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pAddress, szDllName, strlen(szDllName), NULL);
	// 创建远程线程，线程入口设置为LoadLibrary，这样就可以自动加载dll
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, pAddress, 0, NULL);	
	//VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return TRUE;
}

// 提权函数：提升为DEBUG权限
BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}


int main()
{
	if (FALSE == InjectDLL())
	{
		printf("注入DLL失败\n");
		return -1;
	}
	else
	{
		printf("注入DLL成功\n");
	}

	HMODULE hModule = LoadLibrary("DLLShareSection-DLL.dll");
	if (hModule == NULL)
	{
		printf("获取DLL句柄失败\n");
		return -1;
	}
	typedef void (*PFNSETDATA)(char *, DWORD);
	typedef void (*PFNGETDATA)(char *);
	PFNSETDATA pFnSetData = (PFNSETDATA)GetProcAddress(hModule, "SetData");
	PFNGETDATA pFnGetData = (PFNGETDATA)GetProcAddress(hModule, "GetData");
	char szBuffer[0x1000];	
	while (1)
	{
		printf("输入要发送的数据: ");
		ZeroMemory(szBuffer, 0x1000);
		scanf("%s", szBuffer);
		pFnSetData(szBuffer, strlen(szBuffer));
		//pFnGetData(szBuffer);
		//printf("修改数据成功，当前数据: %s\n", szBuffer);
		if (strcmp(szBuffer, "quit") == 0) break;
	}

	return 0;
}

