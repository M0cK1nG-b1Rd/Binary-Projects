// main.cpp : 定义控制台应用程序的入口点。
//

// 大部分代码来自 write_memory.cpp

#include "main.h"
#include "IATHook.h"
#include "InlineHook.h"

#define EXIT_THREAD 0xFF
#define WATCH_MSGBOX 0x11
#define WATCH_CREATEFILE 0x12
#define WATCH_OPENPROCESS 0x13
#define CALL_MSGBOX 0x21
#define CALL_CREATEFILE 0x22
#define CALL_OPENPROCESS 0x23


BOOL static WINAPI Entry()
{
	// 首先解决获取自身ImageBuffer起始位置的问题。
	// 这里会由注入进程进行修改。
	LPVOID pImageBuffer = NULL;

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_NT_HEADERS pImageNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pImageBuffer + pImageDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pImagePEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pImageNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER pImageOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pImagePEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 修复IAT表


	// 根据注入的EXE的导入表和当前被注入的EXE的环境，修复IAT表

	// 这里做了一些改动，dwImageBase的值是g_pImageBuffer而不是原本的ImageBase，原因是RepairReloc时已经修改了原始的ImageBase。
	DWORD dwImageBase = (DWORD)pImageBuffer;
	LPVOID pImportDir = (LPVOID)(pImageOptionHeader->DataDirectory[1].VirtualAddress + dwImageBase);

	// 解析导入表
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) pImportDir;
	//遍历数据并找到 IMAGE_IMPORT_DESCRIPTOR 的数目
	// 检查每一个字节
	int num = 0;
	BOOL break_flag = FALSE;
	PIMAGE_IMPORT_DESCRIPTOR pTemp = pImportDescriptor;
	DWORD procAddress;
	while (pTemp->Name != NULL) {
		num++;
		pTemp++;
	}
	// 遍历并处理每一块
	pTemp = pImportDescriptor;

	for (int j = 0; j < num; j++) {
		// DLL的名字
		char *dll_name = (char *) (dwImageBase + (pTemp + j)->Name);
		//printf("%s :\n", dll_name);
		//printf("----------------------------\n");

		// INT表
		PIMAGE_THUNK_DATA pThunkName = (PIMAGE_THUNK_DATA) (dwImageBase + (pTemp + j)->OriginalFirstThunk);
		// IAT表
		PIMAGE_THUNK_DATA pThunkProcAddress = (PIMAGE_THUNK_DATA) (dwImageBase + (pTemp + j)->FirstThunk);

		PIMAGE_IMPORT_BY_NAME pImageImportByName = (PIMAGE_IMPORT_BY_NAME) (dwImageBase + pThunkName->u1.Ordinal);
		// 获取该DLL的函数名或者序号名
		while (TRUE) {
			if ((pThunkName->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) // the highest bit is 0
			{ // 此时是名称导入方式，需要获取导入DLL中的函数名
				pImageImportByName = (PIMAGE_IMPORT_BY_NAME) (dwImageBase +  pThunkName->u1.Ordinal);
				//printf("%s\n", pImageImportByName->Name);	
				// 得到地址
				procAddress =  (DWORD)GetProcAddress(LoadLibrary(dll_name),pImageImportByName->Name);

				// 修复
				pThunkProcAddress->u1.Ordinal = procAddress;
			} else {//The highest bit is 1
				// 此时是序号导入方式，需要获取导入DLL中的序号
				DWORD dwOrdinal = ((pThunkName->u1.Ordinal << 1) >> 1);
				//printf("Import by ordinal: %lx\n", dwOrdinal);
				procAddress = (DWORD)GetProcAddress(LoadLibrary(dll_name),(LPCSTR)dwOrdinal);

				// 修复
				pThunkProcAddress->u1.Ordinal = procAddress;
			}
			pThunkName++;
			pThunkProcAddress++;
			if (pThunkName->u1.Ordinal == 0) { break; }
		}
	}

	// 修复后跳转到OEP执行函数入口。
	DWORD dwOEP = (DWORD)pImageBuffer + pImageOptionHeader->AddressOfEntryPoint;
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dwOEP,NULL, 0, NULL);
	return TRUE;
}

DWORD g_dwOldProcAddr;

BOOL bWatchMessageBoxFlag;
BOOL bWatchCreateFileFlag;

int _tmain(int argc, _TCHAR* argv[])
{
	HMODULE hModule;

	extern DWORD GetFuncAddr(DWORD dwFuncAddr);
	extern DWORD WINAPI LogedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
	DWORD WINAPI LogedCreateFile(LPCTSTR lpFileName,  
		DWORD dwDesiredAccess,  
		DWORD dwShareMode,  
		LPSECURITY_ATTRIBUTES lpSecurityAttributes,  
		DWORD dwCreationDistribution,  
		DWORD dwFlagsAndAttributes,  
		HANDLE hTemplateFile);

	BOOL bIATHookFlag[2] = {0};

	OutputDebugString(TEXT("成功进入主函数！"));
	// 不加这个编译器就不会生成代码。。
	DWORD dwIAT = (DWORD)Entry;

	// 使用共享内存方式和控制进程进行通信
	HANDLE hMapObject;
	HANDLE hMapView;

	//创建FileMapping对象
	hMapObject = CreateFileMapping((HANDLE)0xFFFFFFFF,NULL,PAGE_READWRITE,0,0x100,TEXT("shared"));
	if(!hMapObject)
	{
		OutputDebugString(TEXT("共享内存失败"));
		return FALSE;
	}
	//将FileMapping对象映射到自己的进程
	hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if(!hMapView)
	{
		OutputDebugString(TEXT("内存映射失败"));
		return FALSE;
	}
	//从共享内存读取测试数据
	TCHAR szBuffer[0x100] = {0};
	memcpy(szBuffer,hMapView,0x100);
	OutputDebugString(szBuffer);


	while (TRUE){
		Sleep(3000);
		TCHAR szBuffer[0x100] = {0};
		memcpy(szBuffer,hMapView,0x100);
		DWORD dwOperation = *(DWORD*)szBuffer;

		BOOL bSuccess;
		if (dwOperation != 0)
		{
			OutputDebugPrintf("从控制端接收到指令：0x%X",dwOperation);
			switch (dwOperation)
			{
			case EXIT_THREAD:
				break;
			case WATCH_MSGBOX:
				bWatchMessageBoxFlag = TRUE;
				break;
			case WATCH_CREATEFILE:
				bWatchCreateFileFlag = TRUE;
				break;
			case WATCH_OPENPROCESS:
				// 应项目要求，使用一个InlineHook
				break;
			case CALL_MSGBOX:
				break;
			case CALL_CREATEFILE:
				break;
			case CALL_OPENPROCESS:
				break;
			}
		}

		if (bWatchCreateFileFlag && !bIATHookFlag[0])
		{
			hModule = GetModuleHandle(_T("user32.dll"));
			g_dwOldProcAddr = (DWORD)GetProcAddress(hModule, _T("MessageBoxW"));
			bSuccess = SetIATHook(g_dwOldProcAddr,GetFuncAddr((DWORD)LogedMessageBox));
			if (bSuccess){
				bIATHookFlag[0] = TRUE;
				OutputDebugString("MSGBOX函数Inline Hook成功！");
			}
		}
		if (bWatchMessageBoxFlag && !bIATHookFlag[1])
		{
			bWatchCreateFileFlag = TRUE;
			hModule = GetModuleHandle(_T("kernel32.dll"));
			g_dwOldProcAddr = (DWORD)GetProcAddress(hModule, _T("CreateFileW"));
			bSuccess = SetIATHook(g_dwOldProcAddr,GetFuncAddr((DWORD)LogedCreateFile));
			if (bSuccess){
				bIATHookFlag[1] = TRUE;
				OutputDebugString("CREATEFILE函数Inline Hook成功！");
			}
		}
	}


	return 0;
}


