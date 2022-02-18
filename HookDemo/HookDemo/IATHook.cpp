#include "IATHook.h"
#include "stdafx.h"

BOOL g_bIATHookFlag = 0; // �Ƿ�Hook�ɹ���Flag
PDWORD pFuncAddr = NULL; // ��Ҫ���ĵ�IAT���ַ

DWORD dwImageAddr; // ����ImageBuffer��ʼ��ַ����ImageBase
PIMAGE_DOS_HEADER pDosHeader = NULL;
PIMAGE_NT_HEADERS pNTHeader = NULL;
PIMAGE_FILE_HEADER pPEHeader = NULL;
PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
PIMAGE_SECTION_HEADER pSectionHeader = NULL;
LPVOID pImportDir = NULL;

VOID init()
{
	// ������Header��ֵ
	dwImageAddr = (DWORD)::GetModuleHandle(NULL);
	pDosHeader = (PIMAGE_DOS_HEADER)dwImageAddr;
	pNTHeader = (PIMAGE_NT_HEADERS) (dwImageAddr + pDosHeader->e_lfanew);;
	pPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);;
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

	pImportDir = (LPVOID)(pOptionHeader->DataDirectory[1].VirtualAddress + dwImageAddr);


}

BOOL SetIATHook(DWORD dwOldAddr, DWORD dwNewAddr){
	init();
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) pImportDir;
	while (pImportDescriptor->FirstThunk != 0 && g_bIATHookFlag != 1) {
		pFuncAddr = (PDWORD) (dwImageAddr + pImportDescriptor->FirstThunk);
		while (*pFuncAddr){
			if (*pFuncAddr == dwOldAddr) {
				*pFuncAddr = dwNewAddr;
				g_bIATHookFlag = TRUE;
				return TRUE;
			}
			pFuncAddr ++ ;
		}
		pImportDescriptor ++ ;
	}
	return FALSE;
}

BOOL UnsetIATHook(DWORD dwOldAddr)
{
	*pFuncAddr = dwOldAddr;
	return TRUE;
}