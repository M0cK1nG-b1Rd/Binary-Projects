

#include <tchar.h>
#include <stdio.h>
#include "IATHook.h"
#include "InlineHook.h"

extern PBYTE g_pOldProcAddr;
extern "C" void HookProc();
extern DWORD g_dwOldProcAddr;

extern void OutputDebugPrintf(const char * strOutputString, ...);

DWORD GetFuncAddr(DWORD dwFuncAddr){
	DWORD dwOffset = *(PDWORD)((PBYTE)dwFuncAddr + 1);
	return dwFuncAddr + 5 + dwOffset;
}


DWORD WINAPI LogedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType){
	// 定义MessageBox 函数指针

	typedef DWORD (WINAPI *pfnMessageBox)(HWND _hWnd, LPCSTR _lpText, LPCSTR _lpCaption, UINT _uType);

	// 写入文件
	FILE *fp = NULL;
	fp = fopen("supervise.log", "w+"); 
	fprintf(fp,"参数： %x %s %s %x\n",hWnd, lpText, lpCaption, uType);
	OutputDebugPrintf("监测到MessageBox参数： %x %s %s %x\n",hWnd, lpText, lpCaption, uType);
	// 执行真正的函数
	int ret = ((pfnMessageBox)g_dwOldProcAddr)(hWnd, lpText, lpCaption, uType);
	// 获取返回值
	fprintf(fp, "监测到MessageBox返回值： %x\n",ret);
	OutputDebugPrintf("监测到MessageBox参数： %x %s %s %x\n",hWnd, lpText, lpCaption, uType);

	fclose(fp); 

	return 0;
}

DWORD WINAPI LogedCreateFile(LPCTSTR lpFileName,  
							 DWORD dwDesiredAccess,  
							 DWORD dwShareMode,  
							 LPSECURITY_ATTRIBUTES lpSecurityAttributes,  
							 DWORD dwCreationDistribution,  
							 DWORD dwFlagsAndAttributes,  
							 HANDLE hTemplateFile){
	// 定义CreateFile 函数指针

	typedef DWORD (WINAPI *pfnMessageBox)(HWND _hWnd, LPCSTR _lpText, LPCSTR _lpCaption, UINT _uType);


	CreateFile(lpFileName,
				dwDesiredAccess,  
				dwShareMode,  
				lpSecurityAttributes,  
				dwCreationDistribution,  
				dwFlagsAndAttributes,  
				hTemplateFile);
	// 获取返回值

	return 0;
}


VOID TestIATHook(){
	//安装IAT Hook
	BOOL bSuccess = SetIATHook(g_dwOldProcAddr,GetFuncAddr((DWORD)LogedMessageBox));

	if (bSuccess){
		MessageBox(NULL,_T("测试IAT Hook"), _T("IAT Hook"), MB_OK);

		//卸载IAT Hook
		UnsetIATHook(g_dwOldProcAddr);
	}
}


VOID TestInlineHook(){
	//安装Inline Hook
	
	// Hook地址如下，需要9个字节
	//004119F0 55                   push        ebp  
	//004119F1 8B EC                mov         ebp,esp  
	//004119F3 81 EC C0 00 00 00    sub         esp,0C0h  
	//BOOL bSuccess = SetInlineHook(GetFuncAddr((DWORD)Plus),GetFuncAddr((DWORD)HookProc),9 ,&g_pOldProcAddr);

	//if (bSuccess){
	//	Plus(1,2);
	//}
	//卸载Inline Hook
	//UnsetInlineHook(GetFuncAddr((DWORD)Plus),(DWORD)g_pOldProcAddr,9);
}


