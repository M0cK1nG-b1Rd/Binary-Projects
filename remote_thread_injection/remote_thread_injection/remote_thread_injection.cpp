// remote_thread_injection.cpp : �������̨Ӧ�ó������ڵ㡣
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
//	// 1.��ȡ���̾��
//	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 7156);
//	// 2.��ȡdll�ļ�������
//	szDllName = _T("inject_dll.dll");
//	dwDllLength = lstrlen(szDllName) + 1;
//	// 3.��Ҫע��Ľ����ڴ�ռ��з���ռ�
//	lpAllocAddr = VirtualAllocEx(hProcess, NULL, dwDllLength, MEM_COMMIT, PAGE_READWRITE);
//	// 4.��Ҫע��Ľ�����д���ַ���
//	WriteProcessMemory(hProcess, lpAllocAddr, szDllName, dwDllLength, NULL);
//	// 5.���LoadLibrary�ĺ�����ַ
//	hModule = GetModuleHandle(_T("kernel32.dll"));
//	dwLoadAddr = (DWORD)GetProcAddress(hModule, _T("LoadLibraryA"));
//	// 6.����Զ���߳�
//	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)dwLoadAddr, lpAllocAddr, 0, &dwThreadID);
//
//
//	// 7. �رս��̾��
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

// LoadDll��Ҫ��������һ�������ǽ���ID��һ����DLL�ļ���·��
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
    
    // 1. ��ȡ���̾��
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
    if (hProcess == NULL) {
        OutputDebugString("OpenProcess failed! \n");
        return FALSE;
    }
    
    // 2. ��ȡDLL�ļ�·���ĳ��ȣ��������+1����ΪҪ����0��β�ĳ���
    dwLength = strlen(szDllPathName) + 1;
    
    // 3. ��Ŀ����̷������ڴ洢DLL�ַ������ڴ�
    lpAllocAddr = VirtualAllocEx(hProcess, NULL, dwLength, MEM_COMMIT, PAGE_READWRITE);
    if (lpAllocAddr == NULL) {
        OutputDebugString("VirtualAllocEx failed! \n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 4. ����DLL·�����ֵ�Ŀ����̵��ڴ�
    bRet = WriteProcessMemory(hProcess, lpAllocAddr, szDllPathName, dwLength, NULL);
    if (!bRet) {
        OutputDebugString("WriteProcessMemory failed! \n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 5. ��ȡģ����
    // LoadLibrary�����������kernel32.dll���ģ���еģ�������Ҫ�Ȼ�ȡkernel32.dll���ģ��ľ��
    hModule = GetModuleHandle("kernel32.dll");
    if (!hModule) {
        OutputDebugString("GetModuleHandle failed! \n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 6. ��ȡLoadLibraryA������ַ
    dwLoadAddr = (DWORD)GetProcAddress(hModule, "LoadLibraryA");
    if (!dwLoadAddr){
        OutputDebugString("GetProcAddress failed! \n");
        CloseHandle(hModule);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 7. ����Զ���̣߳�����DLL
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)dwLoadAddr, lpAllocAddr, 0, &dwThreadID);
    if (!hThread){
        OutputDebugString("CreateRemoteThread failed! \n");
        CloseHandle(hModule);
        CloseHandle(hProcess);
        return FALSE;
    }
    
	OutputDebugString("Thread inject success! \n");

    // 8. �رս��̾��
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    return TRUE;
}

int main(int argc, char* argv[]) {
    
    LoadDll(4668, "C:\\Users\\admin\\Desktop\\inject_dll.dll");
    getchar();
    return 0;
}

