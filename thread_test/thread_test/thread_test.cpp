// Demo3.cpp : 定义应用程序的入口点。
//

#include "stdafx.h"
#include "thread_test.h"

HWND dlgItem;
DWORD money ;
CRITICAL_SECTION cs;
HANDLE g_hMutex;


DWORD WINAPI ThreadProc1(LPVOID id)
{
	int localId = (int)id;
	DWORD myMoney = 0;

	EnterCriticalSection(&cs);
	while ((int)money > 50)
	{	
		money -= 50;
		LeaveCriticalSection(&cs);
		
		myMoney += 50;
		SetDlgItemInt(dlgItem,IDC_EDIT1 ,money,TRUE);
		SetDlgItemInt(dlgItem,1002 + localId,myMoney,TRUE);
		Sleep(50);
		EnterCriticalSection(&cs);
	}
	return 0 ;
}


DWORD WINAPI ThreadProc2(LPVOID id)
{
	int localId = (int)id;
	DWORD myMoney = 0;

	HANDLE g_hMutex = OpenMutex(MUTEX_ALL_ACCESS,FALSE, _T("XYZ"));
	WaitForSingleObject(g_hMutex,INFINITE);
	while ((int)money > 50)
	{	
		money -= 50;
		ReleaseMutex(g_hMutex);
		
		myMoney += 50;
		SetDlgItemInt(dlgItem,IDC_EDIT1 ,money,TRUE);
		SetDlgItemInt(dlgItem,1002 + localId,myMoney,TRUE);
		Sleep(50);
		WaitForSingleObject(g_hMutex,INFINITE);
	}
	return 0 ;
}


DWORD WINAPI AssistProc1(LPVOID lpParameter)
{	
	money = GetDlgItemInt(dlgItem, IDC_EDIT1, NULL, TRUE);
	HANDLE hThread1 = ::CreateThread(NULL, 0, ThreadProc1, (LPVOID)1, 0, NULL);
	HANDLE hThread2 = ::CreateThread(NULL, 0, ThreadProc1, (LPVOID)2, 0, NULL);
	HANDLE hThread3 = ::CreateThread(NULL, 0, ThreadProc1, (LPVOID)3, 0, NULL);
	HANDLE threadArray[3] = {hThread1, hThread2, hThread3};
	WaitForMultipleObjects(3, threadArray, TRUE, INFINITE);
	return 0;
}
DWORD WINAPI AssistProc2(LPVOID lpParameter)
{	
	money = GetDlgItemInt(dlgItem, IDC_EDIT1, NULL, TRUE);
	HANDLE hThread1 = ::CreateThread(NULL, 0, ThreadProc2, (LPVOID)1, 0, NULL);
	HANDLE hThread2 = ::CreateThread(NULL, 0, ThreadProc2, (LPVOID)2, 0, NULL);
	HANDLE hThread3 = ::CreateThread(NULL, 0, ThreadProc2, (LPVOID)3, 0, NULL);
	HANDLE threadArray[3] = {hThread1, hThread2, hThread3};
	WaitForMultipleObjects(3, threadArray, TRUE, INFINITE);
	// 关闭互斥体句柄
	CloseHandle(g_hMutex);
	return 0;
}

BOOL CALLBACK MainDialogProc(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
	)
{
	
	switch(uMsg)
	{
	case  WM_COMMAND :
		{
			switch (LOWORD (wParam))
			{
			case   IDC_BUTTON1 :
				{
					dlgItem = hwndDlg;
					//HANDLE hThread1 = ::CreateThread(NULL, 0, AssistProc1, NULL, 0, NULL);
					HANDLE hThread1 = ::CreateThread(NULL, 0, AssistProc2, NULL, 0, NULL);
					return TRUE;
				}
			}
			return FALSE ;
		}


	case WM_CLOSE:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
		return FALSE ;
	}

	return FALSE;


}


int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
	InitializeCriticalSection(&cs);
	g_hMutex = CreateMutex(NULL,FALSE, _T("XYZ"));
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL ,MainDialogProc);
}

