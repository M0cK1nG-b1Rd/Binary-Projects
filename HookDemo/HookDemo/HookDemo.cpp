// main.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

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

DWORD GetFuncAddr(DWORD dwFuncAddr){
	DWORD dwOffset = *(PDWORD)((PBYTE)dwFuncAddr + 1);
	return dwFuncAddr + 5 + dwOffset;
}


HMODULE hModule = GetModuleHandle(_T("user32.dll"));
DWORD dwOldProcAddr = (DWORD)GetProcAddress(hModule, _T("MessageBoxA"));

// 0x411810
DWORD WINAPI MyMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType){
	// ����MessageBox ����ָ��

	typedef DWORD (WINAPI *pfnMessageBox)(HWND _hWnd, LPCSTR _lpText, LPCSTR _lpCaption, UINT _uType);

	// ��ȡ����
	printf("������ %x %s %s %x\n",hWnd, lpText, lpCaption, uType);
	// ִ�������ĺ���
	int ret = ((pfnMessageBox)dwOldProcAddr)(hWnd, lpText, lpCaption, uType);
	// ��ȡ����ֵ
	printf("����ֵ�� %x\n",ret);
	return 0;
}


VOID TestIATHook(){
	//��װIAT Hook
	BOOL bSuccess = SetIATHook(dwOldProcAddr,GetFuncAddr((DWORD)MyMessageBox));

	if (bSuccess){
		MessageBox(NULL,_T("����IAT Hook"), _T("IAT Hook"), MB_OK);

		//ж��IAT Hook
		UnsetIATHook(dwOldProcAddr);
	}
	
}

DWORD Plus(DWORD x, DWORD y){
	return x + y;
}

VOID TestInlineHook(){
	//��װInline Hook
	
	// Hook��ַ���£���Ҫ9���ֽ�
	//004119F0 55                   push        ebp  
	//004119F1 8B EC                mov         ebp,esp  
	//004119F3 81 EC C0 00 00 00    sub         esp,0C0h  
	BOOL bSuccess = SetInlineHook(GetFuncAddr((DWORD)Plus),GetFuncAddr((DWORD)HookProc),9 ,&g_pOldProcAddr);

	if (bSuccess){
		Plus(1,2);
	}
	//ж��Inline Hook
	UnsetInlineHook(GetFuncAddr((DWORD)Plus),(DWORD)g_pOldProcAddr,9);
}

int _tmain(int argc, _TCHAR* argv[]){

	//TestIATHook();
	TestInlineHook();
	getchar();
	return 0;
}

