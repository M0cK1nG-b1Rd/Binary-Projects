

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
	// ����MessageBox ����ָ��

	typedef DWORD (WINAPI *pfnMessageBox)(HWND _hWnd, LPCSTR _lpText, LPCSTR _lpCaption, UINT _uType);

	// д���ļ�
	FILE *fp = NULL;
	fp = fopen("supervise.log", "w+"); 
	fprintf(fp,"������ %x %s %s %x\n",hWnd, lpText, lpCaption, uType);
	OutputDebugPrintf("��⵽MessageBox������ %x %s %s %x\n",hWnd, lpText, lpCaption, uType);
	// ִ�������ĺ���
	int ret = ((pfnMessageBox)g_dwOldProcAddr)(hWnd, lpText, lpCaption, uType);
	// ��ȡ����ֵ
	fprintf(fp, "��⵽MessageBox����ֵ�� %x\n",ret);
	OutputDebugPrintf("��⵽MessageBox������ %x %s %s %x\n",hWnd, lpText, lpCaption, uType);

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
	// ����CreateFile ����ָ��

	typedef DWORD (WINAPI *pfnMessageBox)(HWND _hWnd, LPCSTR _lpText, LPCSTR _lpCaption, UINT _uType);


	CreateFile(lpFileName,
				dwDesiredAccess,  
				dwShareMode,  
				lpSecurityAttributes,  
				dwCreationDistribution,  
				dwFlagsAndAttributes,  
				hTemplateFile);
	// ��ȡ����ֵ

	return 0;
}


VOID TestIATHook(){
	//��װIAT Hook
	BOOL bSuccess = SetIATHook(g_dwOldProcAddr,GetFuncAddr((DWORD)LogedMessageBox));

	if (bSuccess){
		MessageBox(NULL,_T("����IAT Hook"), _T("IAT Hook"), MB_OK);

		//ж��IAT Hook
		UnsetIATHook(g_dwOldProcAddr);
	}
}


VOID TestInlineHook(){
	//��װInline Hook
	
	// Hook��ַ���£���Ҫ9���ֽ�
	//004119F0 55                   push        ebp  
	//004119F1 8B EC                mov         ebp,esp  
	//004119F3 81 EC C0 00 00 00    sub         esp,0C0h  
	//BOOL bSuccess = SetInlineHook(GetFuncAddr((DWORD)Plus),GetFuncAddr((DWORD)HookProc),9 ,&g_pOldProcAddr);

	//if (bSuccess){
	//	Plus(1,2);
	//}
	//ж��Inline Hook
	//UnsetInlineHook(GetFuncAddr((DWORD)Plus),(DWORD)g_pOldProcAddr,9);
}


