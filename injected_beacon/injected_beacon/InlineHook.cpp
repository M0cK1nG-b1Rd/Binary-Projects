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


// dwHookAddr : 安装Hook的地址
// dwProcAddr ：真正需要执行的函数地址
BOOL SetInlineHook(DWORD dwHookAddr, DWORD dwProcAddr, DWORD dwLength, PBYTE* pOldCode){
	BOOL bRet;
	
	DWORD dwJmpCode;
	// 参数校验
	if (dwHookAddr == NULL || dwProcAddr == NULL){
		OutputDebugString("SetInlineHook函数执行失败：Hook地址/函数地址填写有误！");
		return FALSE;
	}
	// 长度不能小于5
	if (dwLength < 5){
		OutputDebugString("SetInlineHook函数执行失败：修改的硬编码长度不能小于5！");
		return FALSE;
	}
	// 将要Hook的内存修改为可写
	DWORD dwOldProtectionFlag;
	bRet = VirtualProtectEx(::GetCurrentProcess(),(LPVOID)dwHookAddr,dwLength,PAGE_EXECUTE_READWRITE,&dwOldProtectionFlag);
	if (!bRet){
		OutputDebugString("SetInlineHook函数执行失败：修改内存属性失败！");
		return FALSE;
	}
	// 申请一块有执行权限的虚拟内存，存储原来的硬编码
	// +5 是为了预留空间嵌入机器码跳回原来的地址
	LPVOID pAllocAddr = VirtualAllocEx(::GetCurrentProcess(),NULL,dwLength + 5, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(pAllocAddr,(LPVOID)dwHookAddr,dwLength);
	// 设置跳回并执行原来的地址
	*(PBYTE)((DWORD)pAllocAddr + dwLength) = 0xE9;
	// 要跳转到的地址 = E9的地址 + 5 + E9后面的值
	// --> E9后面的值 = 要跳转到的地址 - 5 - E9的地址
	*(PDWORD)((DWORD)pAllocAddr + dwLength +1) = dwHookAddr + dwLength - ((DWORD)pAllocAddr + dwLength) - 5;
	// 将pAllocAddr的地址传递出去，它将会在HookProc函数的最后得到使用
	*pOldCode = (PBYTE)pAllocAddr;

	// 跳转到dwProcAddr
	// 要跳转到的地址 = E9的地址 + 5 + E9后面的值
	// --> E9后面的值 = 要跳转到的地址 - 5 - E9的地址
	dwJmpCode = dwProcAddr - dwHookAddr - 5;

	// 将要Hook的内存首先全部设置为NOP
	memset((PBYTE)dwHookAddr,0x90,dwLength);

	// 修改要Hook的内存的硬编码
	*(PBYTE)dwHookAddr = 0xE9;
	*(PDWORD)((PBYTE)dwHookAddr + 1) = dwJmpCode;
	
	// 修改被Hook的状态
	g_bHookSuccessFlag = TRUE;

	return TRUE;
}

BOOL UnsetInlineHook(DWORD dwHookAddr, DWORD dwPatchAddr, DWORD dwLength){
	if (g_bHookSuccessFlag){
		memcpy((LPVOID)dwHookAddr,(LPVOID)dwPatchAddr,dwLength);
		return TRUE;
	}else{
		OutputDebugString("没有Hook成功，无需恢复！");
		return FALSE;
	}
}



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