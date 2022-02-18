// qq_autologin.cpp : 定义控制台应用程序的入口点。
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
		// 找到了 
		bFindFlag = TRUE;
		SwitchToThisWindow(hWnd,false);
		// 获取对话框左上角位置
		::GetWindowRect(hWnd,&r);

		//设置鼠标的位置
		::SetCursorPos(r.left+250,r.top+120);
		//鼠标左键单击
		mouse_event(MOUSEEVENTF_LEFTDOWN,0,0,0,0);//点下左键 
		mouse_event(MOUSEEVENTF_LEFTUP,0,0,0,0);//松开左键
		//模拟键盘 输入账号
		keybd_event(97,0,0,0);
		keybd_event(97,0,KEYEVENTF_KEYUP,0);

		keybd_event(66,0,0,0);
		keybd_event(66,0,KEYEVENTF_KEYUP,0);

		keybd_event(16,0,0,0);
		keybd_event(67,0,0,0);
		keybd_event(67,0,KEYEVENTF_KEYUP,0);
		keybd_event(16,0,KEYEVENTF_KEYUP,0);



		Sleep(1000);
		// 按tab
		keybd_event(9,0,0,0);
		keybd_event(9,0,KEYEVENTF_KEYUP,0);
		//模拟键盘 输入密码
		keybd_event(97,0,0,0);
		keybd_event(97,0,KEYEVENTF_KEYUP,0);

		keybd_event(66,0,0,0);
		keybd_event(66,0,KEYEVENTF_KEYUP,0);

		keybd_event(16,0,0,0);
		keybd_event(67,0,0,0);
		keybd_event(67,0,KEYEVENTF_KEYUP,0);
		keybd_event(16,0,KEYEVENTF_KEYUP,0);



		// Enter登录
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

