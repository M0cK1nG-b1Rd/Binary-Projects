// qq_autologin.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

TCHAR path[MAX_PATH]=_T("C:\\Program Files\\Tencent\\QQ\\Bin\\QQScLauncher.exe");
BOOL bFindFlag;

BOOL CALLBACK EnumOpenWindowProc(HWND hWnd,LPARAM lParam)  						
{  						
	TCHAR szTitle[MAX_PATH] = {0};	
	RECT r;
	::GetWindowText(hWnd,szTitle,MAX_PATH); 						 						
	if(lstrcmp(szTitle,_T("QQ")) == 0)				
	{					
		// �ҵ��� 
		bFindFlag = TRUE;
		SwitchToThisWindow(hWnd,false);
		// ��ȡ�Ի������Ͻ�λ��
		::GetWindowRect(hWnd,&r);

		//��������λ��
		::SetCursorPos(r.left+250,r.top+120);
		//����������
		mouse_event(MOUSEEVENTF_LEFTDOWN,0,0,0,0);//������� 
		mouse_event(MOUSEEVENTF_LEFTUP,0,0,0,0);//�ɿ����
		//ģ����� �����˺�
		keybd_event(97,0,0,0);
		keybd_event(97,0,KEYEVENTF_KEYUP,0);

		keybd_event(66,0,0,0);
		keybd_event(66,0,KEYEVENTF_KEYUP,0);

		keybd_event(16,0,0,0);
		keybd_event(67,0,0,0);
		keybd_event(67,0,KEYEVENTF_KEYUP,0);
		keybd_event(16,0,KEYEVENTF_KEYUP,0);



		Sleep(1000);
		// ��tab
		keybd_event(9,0,0,0);
		keybd_event(9,0,KEYEVENTF_KEYUP,0);
		//ģ����� ��������
		keybd_event(97,0,0,0);
		keybd_event(97,0,KEYEVENTF_KEYUP,0);

		keybd_event(66,0,0,0);
		keybd_event(66,0,KEYEVENTF_KEYUP,0);

		keybd_event(16,0,0,0);
		keybd_event(67,0,0,0);
		keybd_event(67,0,KEYEVENTF_KEYUP,0);
		keybd_event(16,0,KEYEVENTF_KEYUP,0);



		// Enter��¼
		keybd_event(13,0,0,0);
		keybd_event(13,0,KEYEVENTF_KEYUP,0);

		return FALSE;				
	}					
	return TRUE;  						
}  		

VOID EnumOpenWindows()						
{
	while (!bFindFlag)
	{
		EnumWindows(EnumOpenWindowProc,NULL);
		Sleep(5000);
	}
	
}						


int main(int argc, _TCHAR* argv[])
{
	STARTUPINFO si = {0};
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi;
	CreateProcess(path,NULL,NULL,NULL,FALSE,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi);
	EnumOpenWindows();
	return 0;
}

