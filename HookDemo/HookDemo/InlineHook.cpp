#include "stdafx.h"

BOOL g_bHookSuccessFlag = FALSE;
PBYTE g_pCodePatch;

// dwHookAddr : ��װHook�ĵ�ַ
// dwProcAddr ��������Ҫִ�еĺ�����ַ
BOOL SetInlineHook(DWORD dwHookAddr, DWORD dwProcAddr, DWORD dwLength, PBYTE* pOldCode){
	BOOL bRet;
	
	DWORD dwJmpCode;
	// ����У��
	if (dwHookAddr == NULL || dwProcAddr == NULL){
		OutputDebugString("SetInlineHook����ִ��ʧ�ܣ�Hook��ַ/������ַ��д����");
		return FALSE;
	}
	// ���Ȳ���С��5
	if (dwLength < 5){
		OutputDebugString("SetInlineHook����ִ��ʧ�ܣ��޸ĵ�Ӳ���볤�Ȳ���С��5��");
		return FALSE;
	}
	// ��ҪHook���ڴ��޸�Ϊ��д
	DWORD dwOldProtectionFlag;
	bRet = VirtualProtectEx(::GetCurrentProcess(),(LPVOID)dwHookAddr,dwLength,PAGE_EXECUTE_READWRITE,&dwOldProtectionFlag);
	if (!bRet){
		OutputDebugString("SetInlineHook����ִ��ʧ�ܣ��޸��ڴ�����ʧ�ܣ�");
		return FALSE;
	}
	// ����һ����ִ��Ȩ�޵������ڴ棬�洢ԭ����Ӳ����
	// +5 ��Ϊ��Ԥ���ռ�Ƕ�����������ԭ���ĵ�ַ
	LPVOID pAllocAddr = VirtualAllocEx(::GetCurrentProcess(),NULL,dwLength + 5, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(pAllocAddr,(LPVOID)dwHookAddr,dwLength);
	// �������ز�ִ��ԭ���ĵ�ַ
	*(PBYTE)((DWORD)pAllocAddr + dwLength) = 0xE9;
	// Ҫ��ת���ĵ�ַ = E9�ĵ�ַ + 5 + E9�����ֵ
	// --> E9�����ֵ = Ҫ��ת���ĵ�ַ - 5 - E9�ĵ�ַ
	*(PDWORD)((DWORD)pAllocAddr + dwLength +1) = dwHookAddr + dwLength - ((DWORD)pAllocAddr + dwLength) - 5;
	// ��pAllocAddr�ĵ�ַ���ݳ�ȥ����������HookProc���������õ�ʹ��
	*pOldCode = (PBYTE)pAllocAddr;

	// ��ת��dwProcAddr
	// Ҫ��ת���ĵ�ַ = E9�ĵ�ַ + 5 + E9�����ֵ
	// --> E9�����ֵ = Ҫ��ת���ĵ�ַ - 5 - E9�ĵ�ַ
	dwJmpCode = dwProcAddr - dwHookAddr - 5;

	// ��ҪHook���ڴ�����ȫ������ΪNOP
	memset((PBYTE)dwHookAddr,0x90,dwLength);

	// �޸�ҪHook���ڴ��Ӳ����
	*(PBYTE)dwHookAddr = 0xE9;
	*(PDWORD)((PBYTE)dwHookAddr + 1) = dwJmpCode;
	
	// �޸ı�Hook��״̬
	g_bHookSuccessFlag = TRUE;

	return TRUE;
}

BOOL UnsetInlineHook(DWORD dwHookAddr, DWORD dwPatchAddr, DWORD dwLength){
	if (g_bHookSuccessFlag){
		memcpy((LPVOID)dwHookAddr,(LPVOID)dwPatchAddr,dwLength);
		return TRUE;
	}else{
		OutputDebugString("û��Hook�ɹ�������ָ���");
		return FALSE;
	}
}