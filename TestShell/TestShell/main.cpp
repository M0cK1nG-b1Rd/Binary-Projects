// �����ܣ�����һ���Լ��Ŀ��ܽ��̲�ж���ڴ澵������һ�������imagebuffer�滻
// 32λ ���ֽ��ַ���

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <WINDOWS.H>
#include <STRING.h>
#include <MALLOC.H>
#include "PE.hpp"

BOOL EnableDebugPrivilege();

int main(int argc, char *argv[])
{
	// ��Ȩ
	EnableDebugPrivilege();
	// ��ȡԴ�ļ�
	LPVOID pSrcFileBuffer = NULL;
	DWORD dwSrcFileSize = FileToMemory("C:\\Users\\admin\\Desktop\\notepad.exe", &pSrcFileBuffer);
	if (dwSrcFileSize == 0)
	{
		printf("��ȡ�ļ�ʧ��\n");
		return -1;
	}
	// ������ڴ澵��
	LPVOID pSrcImageBuffer = NULL;
	DWORD dwSrcImageBufferSize = FileBufferToImageBuffer(pSrcFileBuffer, &pSrcImageBuffer);
	// ��ȡ��ǰ������ģ��·��
	char szCurrentPaths[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, szCurrentPaths, MAX_PATH);
	// �Թ���ʽ����һ����ǰ���̵Ŀ��ܽ��̣�����ֻ��Ҫ����4GB�ռ�
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi;
	CreateProcess(NULL, szCurrentPaths, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	// ��ȡ�½������߳�������
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &context);
	// ��ȡ ZwUnmapViewOfSection ����ָ��
	HMODULE hModuleNt = LoadLibrary("ntdll.dll");
	if (hModuleNt == NULL)
	{
		printf("��ȡntdll���ʧ��\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}
	typedef DWORD(WINAPI *_TZwUnmapViewOfSection)(HANDLE, PVOID);
	_TZwUnmapViewOfSection pZwUnmapViewOfSection = (_TZwUnmapViewOfSection)GetProcAddress(hModuleNt, "ZwUnmapViewOfSection");
	if (pZwUnmapViewOfSection == NULL)
	{
		printf("��ȡ ZwUnmapViewOfSection ����ָ��ʧ��\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}
	// ���� ZwUnmapViewOfSection ж���½����ڴ澵��
	pZwUnmapViewOfSection(pi.hProcess, GetModuleHandle(NULL));
	// ��ȡԴ�����ImageBase
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSrcImageBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	DWORD dwSrcImageBase = pOptionHeader->ImageBase;
	// �ڿ��ܽ��̵�Դ�����ImageBase������SizeOfImage��С���ڴ�	
	LPVOID pImageBase = VirtualAllocEx(
		pi.hProcess, (LPVOID)dwSrcImageBase, dwSrcImageBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if ((DWORD)pImageBase != dwSrcImageBase)
	{
		printf("VirtualAllocEx ������: 0x%X\n", GetLastError()); // 0x1e7 ��ͼ������Ч��ַ
		printf("���뵽��ָ��: 0x%X, �����ĵ�ַ: 0x%X\n", (DWORD)pImageBase, dwSrcImageBase);
		TerminateThread(pi.hThread, 0);
		return -1;
	}	
	
	// ��Դ�����ڴ澵���Ƶ����ܽ���4GB��	
	if (0 == WriteProcessMemory(
		pi.hProcess, (LPVOID)dwSrcImageBase, pSrcImageBuffer, dwSrcImageBufferSize, NULL))
	{
		printf("д��Դ�����ڴ澵��ʧ��\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}

	// ������ڵ�
	context.Eax = pOptionHeader->AddressOfEntryPoint + dwSrcImageBase;
	// ���� ImageBase
	WriteProcessMemory(pi.hProcess, (LPVOID)(context.Ebx + 8), &dwSrcImageBase, 4, NULL);
	context.ContextFlags = CONTEXT_FULL;
	SetThreadContext(pi.hThread, &context);

	// �ָ��߳�	
	ResumeThread(pi.hThread);
	// �ѿǳɹ�
	printf("�ѿǳɹ���Դ�����������У��������ַ��˳�\n");

	free(pSrcFileBuffer);
	free(pSrcImageBuffer);
	system("pause");
	return 0;
}

// ��Ȩ����������ΪDEBUGȨ��
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


