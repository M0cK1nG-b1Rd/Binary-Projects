// main.cpp : �������̨Ӧ�ó������ڵ㡣
//

// �󲿷ִ������� write_memory.cpp

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
	// ���Ƚ����ȡ����ImageBuffer��ʼλ�õ����⡣
	// �������ע����̽����޸ġ�
	LPVOID pImageBuffer = NULL;

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_NT_HEADERS pImageNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pImageBuffer + pImageDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pImagePEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pImageNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER pImageOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pImagePEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// �޸�IAT��


	// ����ע���EXE�ĵ����͵�ǰ��ע���EXE�Ļ������޸�IAT��

	// ��������һЩ�Ķ���dwImageBase��ֵ��g_pImageBuffer������ԭ����ImageBase��ԭ����RepairRelocʱ�Ѿ��޸���ԭʼ��ImageBase��
	DWORD dwImageBase = (DWORD)pImageBuffer;
	LPVOID pImportDir = (LPVOID)(pImageOptionHeader->DataDirectory[1].VirtualAddress + dwImageBase);

	// ���������
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) pImportDir;
	//�������ݲ��ҵ� IMAGE_IMPORT_DESCRIPTOR ����Ŀ
	// ���ÿһ���ֽ�
	int num = 0;
	BOOL break_flag = FALSE;
	PIMAGE_IMPORT_DESCRIPTOR pTemp = pImportDescriptor;
	DWORD procAddress;
	while (pTemp->Name != NULL) {
		num++;
		pTemp++;
	}
	// ����������ÿһ��
	pTemp = pImportDescriptor;

	for (int j = 0; j < num; j++) {
		// DLL������
		char *dll_name = (char *) (dwImageBase + (pTemp + j)->Name);
		//printf("%s :\n", dll_name);
		//printf("----------------------------\n");

		// INT��
		PIMAGE_THUNK_DATA pThunkName = (PIMAGE_THUNK_DATA) (dwImageBase + (pTemp + j)->OriginalFirstThunk);
		// IAT��
		PIMAGE_THUNK_DATA pThunkProcAddress = (PIMAGE_THUNK_DATA) (dwImageBase + (pTemp + j)->FirstThunk);

		PIMAGE_IMPORT_BY_NAME pImageImportByName = (PIMAGE_IMPORT_BY_NAME) (dwImageBase + pThunkName->u1.Ordinal);
		// ��ȡ��DLL�ĺ��������������
		while (TRUE) {
			if ((pThunkName->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) // the highest bit is 0
			{ // ��ʱ�����Ƶ��뷽ʽ����Ҫ��ȡ����DLL�еĺ�����
				pImageImportByName = (PIMAGE_IMPORT_BY_NAME) (dwImageBase +  pThunkName->u1.Ordinal);
				//printf("%s\n", pImageImportByName->Name);	
				// �õ���ַ
				procAddress =  (DWORD)GetProcAddress(LoadLibrary(dll_name),pImageImportByName->Name);

				// �޸�
				pThunkProcAddress->u1.Ordinal = procAddress;
			} else {//The highest bit is 1
				// ��ʱ����ŵ��뷽ʽ����Ҫ��ȡ����DLL�е����
				DWORD dwOrdinal = ((pThunkName->u1.Ordinal << 1) >> 1);
				//printf("Import by ordinal: %lx\n", dwOrdinal);
				procAddress = (DWORD)GetProcAddress(LoadLibrary(dll_name),(LPCSTR)dwOrdinal);

				// �޸�
				pThunkProcAddress->u1.Ordinal = procAddress;
			}
			pThunkName++;
			pThunkProcAddress++;
			if (pThunkName->u1.Ordinal == 0) { break; }
		}
	}

	// �޸�����ת��OEPִ�к�����ڡ�
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

	OutputDebugString(TEXT("�ɹ�������������"));
	// ��������������Ͳ������ɴ��롣��
	DWORD dwIAT = (DWORD)Entry;

	// ʹ�ù����ڴ淽ʽ�Ϳ��ƽ��̽���ͨ��
	HANDLE hMapObject;
	HANDLE hMapView;

	//����FileMapping����
	hMapObject = CreateFileMapping((HANDLE)0xFFFFFFFF,NULL,PAGE_READWRITE,0,0x100,TEXT("shared"));
	if(!hMapObject)
	{
		OutputDebugString(TEXT("�����ڴ�ʧ��"));
		return FALSE;
	}
	//��FileMapping����ӳ�䵽�Լ��Ľ���
	hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if(!hMapView)
	{
		OutputDebugString(TEXT("�ڴ�ӳ��ʧ��"));
		return FALSE;
	}
	//�ӹ����ڴ��ȡ��������
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
			OutputDebugPrintf("�ӿ��ƶ˽��յ�ָ�0x%X",dwOperation);
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
				// Ӧ��ĿҪ��ʹ��һ��InlineHook
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
				OutputDebugString("MSGBOX����Inline Hook�ɹ���");
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
				OutputDebugString("CREATEFILE����Inline Hook�ɹ���");
			}
		}
	}


	return 0;
}


