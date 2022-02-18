#include "InlineHook.h"

BOOL g_bHookSuccessFlag = FALSE;
PBYTE g_pCodePatch;

DWORD dwParamX;
DWORD dwParamY;
LPTSTR szBuffer;

typedef struct _REGISTER{
	DWORD Eax;
	DWORD Ebx;
	DWORD Ecx;
	DWORD Edx;
	DWORD Esi;
	DWORD Edi;
	DWORD Esp;
	DWORD Ebp;
}Register;


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



Register reg = {0};
PBYTE g_pOldProcAddr;

extern "C" __declspec(naked) void HookProc(){
	// ����Ĵ���
	_asm
	{
		pushad
		pushfd
	}

	// ��ȡ����
	_asm
	{
		mov reg.Eax, eax
		mov reg.Ebx, ebx
		mov reg.Ecx, ecx
		mov reg.Edx, edx
		mov reg.Esi, esi
		mov reg.Edi, edi
		mov reg.Esp, esp
		mov reg.Ebp, ebp

		// ��ȡ��������
		mov eax, dword ptr ss:[esp+0x28]
		mov dwParamX, eax
		mov eax, dword ptr ss:[esp+0x2C]
		mov dwParamY, eax
	}

	szBuffer = new TCHAR[0x200];
	memset(szBuffer,0,0x200);
	sprintf(szBuffer,"EAX: %X\nEBX: %X\nECX: %X\nEDX: %X\nESI: %X\nEDI: %X\nESP: %X\nEBP: %X",reg.Eax,reg.Ebx,reg.Ecx,reg.Edx,reg.Esi,reg.Edi,reg.Esp,reg.Ebp);
	MessageBox(NULL,szBuffer,"[Hook �Ĵ�������]",MB_OK);
	memset(szBuffer,0,0x200);
	sprintf(szBuffer,"����X��%d \n����Y: %d",dwParamX,dwParamY);
	MessageBox(NULL,szBuffer,"[Hook ��������]",MB_OK);

	// �ָ��Ĵ���
	_asm
	{
		popfd
		popad
	}

	// �����洢��CodePatch��
	_asm
	{
		jmp g_pOldProcAddr;
	}
}