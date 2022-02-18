// main.cpp : 定义控制台应用程序的入口点。
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
	// 保存寄存器
	_asm
	{
		pushad
		pushfd
	}

	// 获取数据
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

		// 获取参数数据
		mov eax, dword ptr ss:[esp+0x28]
		mov dwParamX, eax
		mov eax, dword ptr ss:[esp+0x2C]
		mov dwParamY, eax
	}

	szBuffer = new TCHAR[0x200];
	memset(szBuffer,0,0x200);
	sprintf(szBuffer,"EAX: %X\nEBX: %X\nECX: %X\nEDX: %X\nESI: %X\nEDI: %X\nESP: %X\nEBP: %X",reg.Eax,reg.Ebx,reg.Ecx,reg.Edx,reg.Esi,reg.Edi,reg.Esp,reg.Ebp);
	MessageBox(NULL,szBuffer,"[Hook 寄存器数据]",MB_OK);
	memset(szBuffer,0,0x200);
	sprintf(szBuffer,"参数X：%d \n参数Y: %d",dwParamX,dwParamY);
	MessageBox(NULL,szBuffer,"[Hook 参数数据]",MB_OK);

	// 恢复寄存器
	_asm
	{
		popfd
		popad
	}

	// 跳到存储的CodePatch处
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
	// 定义MessageBox 函数指针

	typedef DWORD (WINAPI *pfnMessageBox)(HWND _hWnd, LPCSTR _lpText, LPCSTR _lpCaption, UINT _uType);

	// 获取参数
	printf("参数： %x %s %s %x\n",hWnd, lpText, lpCaption, uType);
	// 执行真正的函数
	int ret = ((pfnMessageBox)dwOldProcAddr)(hWnd, lpText, lpCaption, uType);
	// 获取返回值
	printf("返回值： %x\n",ret);
	return 0;
}


VOID TestIATHook(){
	//安装IAT Hook
	BOOL bSuccess = SetIATHook(dwOldProcAddr,GetFuncAddr((DWORD)MyMessageBox));

	if (bSuccess){
		MessageBox(NULL,_T("测试IAT Hook"), _T("IAT Hook"), MB_OK);

		//卸载IAT Hook
		UnsetIATHook(dwOldProcAddr);
	}
	
}

DWORD Plus(DWORD x, DWORD y){
	return x + y;
}

VOID TestInlineHook(){
	//安装Inline Hook
	
	// Hook地址如下，需要9个字节
	//004119F0 55                   push        ebp  
	//004119F1 8B EC                mov         ebp,esp  
	//004119F3 81 EC C0 00 00 00    sub         esp,0C0h  
	BOOL bSuccess = SetInlineHook(GetFuncAddr((DWORD)Plus),GetFuncAddr((DWORD)HookProc),9 ,&g_pOldProcAddr);

	if (bSuccess){
		Plus(1,2);
	}
	//卸载Inline Hook
	UnsetInlineHook(GetFuncAddr((DWORD)Plus),(DWORD)g_pOldProcAddr,9);
}

int _tmain(int argc, _TCHAR* argv[]){

	//TestIATHook();
	TestInlineHook();
	getchar();
	return 0;
}

