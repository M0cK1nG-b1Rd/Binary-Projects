// 程序功能：创建一个自己的傀儡进程并卸载内存镜像，用另一个程序的imagebuffer替换
// 32位 多字节字符集

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <WINDOWS.H>
#include <STRING.h>
#include <MALLOC.H>
#include "PE.hpp"

BOOL EnableDebugPrivilege();

int main(int argc, char *argv[])
{
	// 提权
	EnableDebugPrivilege();
	// 读取源文件
	LPVOID pSrcFileBuffer = NULL;
	DWORD dwSrcFileSize = FileToMemory("C:\\Users\\admin\\Desktop\\notepad.exe", &pSrcFileBuffer);
	if (dwSrcFileSize == 0)
	{
		printf("读取文件失败\n");
		return -1;
	}
	// 拉伸成内存镜像
	LPVOID pSrcImageBuffer = NULL;
	DWORD dwSrcImageBufferSize = FileBufferToImageBuffer(pSrcFileBuffer, &pSrcImageBuffer);
	// 获取当前进程主模块路径
	char szCurrentPaths[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, szCurrentPaths, MAX_PATH);
	// 以挂起方式创建一个当前进程的傀儡进程，我们只需要它的4GB空间
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi;
	CreateProcess(NULL, szCurrentPaths, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	// 获取新进程主线程上下文
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &context);
	// 获取 ZwUnmapViewOfSection 函数指针
	HMODULE hModuleNt = LoadLibrary("ntdll.dll");
	if (hModuleNt == NULL)
	{
		printf("获取ntdll句柄失败\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}
	typedef DWORD(WINAPI *_TZwUnmapViewOfSection)(HANDLE, PVOID);
	_TZwUnmapViewOfSection pZwUnmapViewOfSection = (_TZwUnmapViewOfSection)GetProcAddress(hModuleNt, "ZwUnmapViewOfSection");
	if (pZwUnmapViewOfSection == NULL)
	{
		printf("获取 ZwUnmapViewOfSection 函数指针失败\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}
	// 调用 ZwUnmapViewOfSection 卸载新进程内存镜像
	pZwUnmapViewOfSection(pi.hProcess, GetModuleHandle(NULL));
	// 获取源程序的ImageBase
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pSrcImageBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	DWORD dwSrcImageBase = pOptionHeader->ImageBase;
	// 在傀儡进程的源程序的ImageBase处申请SizeOfImage大小的内存	
	LPVOID pImageBase = VirtualAllocEx(
		pi.hProcess, (LPVOID)dwSrcImageBase, dwSrcImageBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if ((DWORD)pImageBase != dwSrcImageBase)
	{
		printf("VirtualAllocEx 错误码: 0x%X\n", GetLastError()); // 0x1e7 试图访问无效地址
		printf("申请到的指针: 0x%X, 期望的地址: 0x%X\n", (DWORD)pImageBase, dwSrcImageBase);
		TerminateThread(pi.hThread, 0);
		return -1;
	}	
	
	// 将源程序内存镜像复制到傀儡进程4GB中	
	if (0 == WriteProcessMemory(
		pi.hProcess, (LPVOID)dwSrcImageBase, pSrcImageBuffer, dwSrcImageBufferSize, NULL))
	{
		printf("写入源程序内存镜像失败\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}

	// 修正入口点
	context.Eax = pOptionHeader->AddressOfEntryPoint + dwSrcImageBase;
	// 修正 ImageBase
	WriteProcessMemory(pi.hProcess, (LPVOID)(context.Ebx + 8), &dwSrcImageBase, 4, NULL);
	context.ContextFlags = CONTEXT_FULL;
	SetThreadContext(pi.hThread, &context);

	// 恢复线程	
	ResumeThread(pi.hThread);
	// 脱壳成功
	printf("脱壳成功，源程序正在运行，敲任意字符退出\n");

	free(pSrcFileBuffer);
	free(pSrcImageBuffer);
	system("pause");
	return 0;
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


