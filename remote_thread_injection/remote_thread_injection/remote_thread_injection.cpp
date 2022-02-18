// remote_thread_injection.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


//int main(int argc, _TCHAR* argv[])
//{
//	HANDLE hProcess;
//	LPTSTR szDllName;
//	DWORD dwDllLength;
//	LPVOID lpAllocAddr;
//	HMODULE hModule;
//	DWORD dwLoadAddr;
//	DWORD dwThreadID;
//	HANDLE hThread;
//	// 1.获取进程句柄
//	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 7156);
//	// 2.获取dll文件名长度
//	szDllName = _T("inject_dll.dll");
//	dwDllLength = lstrlen(szDllName) + 1;
//	// 3.在要注入的进程内存空间中分配空间
//	lpAllocAddr = VirtualAllocEx(hProcess, NULL, dwDllLength, MEM_COMMIT, PAGE_READWRITE);
//	// 4.在要注入的进程中写入字符串
//	WriteProcessMemory(hProcess, lpAllocAddr, szDllName, dwDllLength, NULL);
//	// 5.获得LoadLibrary的函数地址
//	hModule = GetModuleHandle(_T("kernel32.dll"));
//	dwLoadAddr = (DWORD)GetProcAddress(hModule, _T("LoadLibraryA"));
//	// 6.创建远程线程
//	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)dwLoadAddr, lpAllocAddr, 0, &dwThreadID);
//
//
//	// 7. 关闭进程句柄
//    CloseHandle(hThread);
//    CloseHandle(hProcess);
//
//	getchar(); 
//
//	return 0;
//}


// Test.cpp : Defines the entry point for the console application.
//

#include "StdAfx.h"

// LoadDll需要两个参数一个参数是进程ID，一个是DLL文件的路径
BOOL LoadDll(DWORD dwProcessID, char* szDllPathName) {
    
    BOOL bRet;
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwLength;
    DWORD dwLoadAddr;
    LPVOID lpAllocAddr;
    DWORD dwThreadID;
    HMODULE hModule;
    
    bRet = 0;
    dwLoadAddr = 0;
    hProcess = 0;
    
    // 1. 获取进程句柄
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
    if (hProcess == NULL) {
        OutputDebugString("OpenProcess failed! \n");
        return FALSE;
    }
    
    // 2. 获取DLL文件路径的长度，并在最后+1，因为要加上0结尾的长度
    dwLength = strlen(szDllPathName) + 1;
    
    // 3. 在目标进程分配用于存储DLL字符串的内存
    lpAllocAddr = VirtualAllocEx(hProcess, NULL, dwLength, MEM_COMMIT, PAGE_READWRITE);
    if (lpAllocAddr == NULL) {
        OutputDebugString("VirtualAllocEx failed! \n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 4. 拷贝DLL路径名字到目标进程的内存
    bRet = WriteProcessMemory(hProcess, lpAllocAddr, szDllPathName, dwLength, NULL);
    if (!bRet) {
        OutputDebugString("WriteProcessMemory failed! \n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 5. 获取模块句柄
    // LoadLibrary这个函数是在kernel32.dll这个模块中的，所以需要先获取kernel32.dll这个模块的句柄
    hModule = GetModuleHandle("kernel32.dll");
    if (!hModule) {
        OutputDebugString("GetModuleHandle failed! \n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 6. 获取LoadLibraryA函数地址
    dwLoadAddr = (DWORD)GetProcAddress(hModule, "LoadLibraryA");
    if (!dwLoadAddr){
        OutputDebugString("GetProcAddress failed! \n");
        CloseHandle(hModule);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 7. 创建远程线程，加载DLL
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)dwLoadAddr, lpAllocAddr, 0, &dwThreadID);
    if (!hThread){
        OutputDebugString("CreateRemoteThread failed! \n");
        CloseHandle(hModule);
        CloseHandle(hProcess);
        return FALSE;
    }
    
	OutputDebugString("Thread inject success! \n");

    // 8. 关闭进程句柄
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    return TRUE;
}

int main(int argc, char* argv[]) {
    
    LoadDll(4668, "C:\\Users\\admin\\Desktop\\inject_dll.dll");
    getchar();
    return 0;
}

