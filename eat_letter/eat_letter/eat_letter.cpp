#include "stdafx.h"
#include "resource.h"

HANDLE hSetSemaphore;
HANDLE hGetSemaphore;
HANDLE hThread[4];

HWND hMainDlg;

HWND hEditResource;
HWND hEditBuffer1;
HWND hEditBuffer2;
HWND hEditBuffer;
HWND hEditBufferArray[2];

HWND hEditConsumer1;
HWND hEditConsumer2;
HWND hEditConsumer3;
HWND hEditConsumer4;
HWND hEditConsumer;

TCHAR rcBuffer[0x100] = {0};
BOOL bufferEmptyFlag[2] = {1,1};

DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
	TCHAR szEditBuffer1[10] = {0};
	TCHAR szEditBuffer2[10] = {0};
	TCHAR szEditBuffer[10] = {0};
	szEditBuffer[10] = {0};

	GetWindowText(hEditBuffer,szEditBuffer1,strlen(szEditBuffer1));
	GetWindowText(hEditBuffer,szEditBuffer2,strlen(szEditBuffer2));

	while(rcBuffer != _T("") && szEditBuffer1 != _T("") && szEditBuffer2 != _T(""))
	{

		WaitForSingleObject(hGetSemaphore, INFINITE);
		for (int i = 0; i < sizeof(bufferEmptyFlag); i++)
		{
			if (bufferEmptyFlag[i] == FALSE)
			{
				GetWindowText(hEditBufferArray[i],szEditBuffer,strlen(szEditBuffer));
				hEditConsumer = GetDlgItem(hMainDlg,IDC_EDIT_C1 + (int)lpParameter);
				SetWindowText(hEditConsumer,szEditBuffer);
				bufferEmptyFlag[i] = TRUE;


				Sleep(1000);

			}
		}

		ReleaseSemaphore(hSetSemaphore, 1, NULL);
	}


	return 0;
}
DWORD WINAPI ThreadBegin(LPVOID lpParameter)
{
	
	TCHAR* pointer = rcBuffer;
	TCHAR letter[2] = {0};

	hSetSemaphore = CreateSemaphore(NULL,2,2,NULL);
	hGetSemaphore = CreateSemaphore(NULL,0,4,NULL);

	hThread[0] = ::CreateThread(NULL, 0, ThreadProc,(LPVOID) 0 , 0, NULL);
	hThread[1] = ::CreateThread(NULL, 0, ThreadProc,(LPVOID) 1, 0, NULL);
	hThread[2] = ::CreateThread(NULL, 0, ThreadProc,(LPVOID) 2, 0, NULL);
	hThread[3] = ::CreateThread(NULL, 0, ThreadProc,(LPVOID) 3, 0, NULL);

	GetWindowText(hEditResource,rcBuffer,0x100);

	//开始准备资源
	while(pointer != _T(""))
	{

		for (int i = 0; i < 2; i++)
		{
			WaitForSingleObject(hSetSemaphore, INFINITE);
			GetWindowText(hEditResource,pointer,strlen(pointer));
			// 复制一个字母
			strncpy(letter, pointer, 1);
			pointer = pointer + 1 ;



			if (bufferEmptyFlag[i] == TRUE)
			{
				hEditBuffer = GetDlgItem(hMainDlg,IDC_EDIT_BUFFER1 + i);
				SetWindowText(hEditBuffer,letter);
				SetWindowText(hEditResource,pointer);
				bufferEmptyFlag[i] = FALSE;
				
				ReleaseSemaphore(hGetSemaphore, 1, NULL);

				Sleep(1000);
			}
		}

		
	}

	::WaitForMultipleObjects(3, hThread,TRUE,INFINITE);
	::CloseHandle(hSetSemaphore);
	::CloseHandle(hGetSemaphore);

	return 0;
}
BOOL CALLBACK MainDlgProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	BOOL bRet = FALSE;

	switch(uMsg)
	{
	case WM_CLOSE:
		{
			EndDialog(hDlg,0);
			break;
		}
	case WM_INITDIALOG:
		{
			hMainDlg = hDlg;
			hEditResource = GetDlgItem(hMainDlg,IDC_EDIT_RC);

			hEditBuffer1 = GetDlgItem(hMainDlg,IDC_EDIT_BUFFER1);
			hEditBuffer2 = GetDlgItem(hMainDlg,IDC_EDIT_BUFFER2);

			hEditConsumer1 = GetDlgItem(hMainDlg,IDC_EDIT_C1);
			hEditConsumer2 = GetDlgItem(hMainDlg,IDC_EDIT_C2);
			hEditConsumer3 = GetDlgItem(hMainDlg,IDC_EDIT_C3);
			hEditConsumer4 = GetDlgItem(hMainDlg,IDC_EDIT_C4);

			hEditBufferArray[0] = hEditBuffer1;
			hEditBufferArray[1] = hEditBuffer2;


			SetWindowText(hEditResource,"0");
			SetWindowText(hEditBuffer1,"0");
			SetWindowText(hEditBuffer2,"0");

			break;
		}
	case WM_COMMAND:

		switch (LOWORD (wParam))
		{
		case IDC_BUTTON_BEGIN:
			{
				CreateThread(NULL, 0, ThreadBegin,NULL, 0, NULL);

				return TRUE;
			}
		}
		break ;
	}

	return bRet;
}
int APIENTRY WinMain(HINSTANCE hInstance,
					 HINSTANCE hPrevInstance,
					 LPSTR     lpCmdLine,
					 int       nCmdShow)
{
	// TODO: Place code here.
	DialogBox(hInstance,MAKEINTRESOURCE(IDD_DIALOG1),NULL,MainDlgProc);
	return 0;
}
