// Demo3.cpp : 定义应用程序的入口点。
//

#include "stdafx.h"
#include "Demo2.h"


BOOL CALLBACK DialogProc(								
						 HWND hwndDlg,  // handle to dialog box		
						 UINT uMsg,     // message		
						 WPARAM wParam, // first message parameter		
						 LPARAM lParam  // second message parameter		
						 )		
{								
	HWND hEditUser = NULL ;
	HWND hEditPass = NULL ;
	switch(uMsg)							
	{							
	case  WM_INITDIALOG :							
								
		MessageBox(NULL,TEXT("WM_INITDIALOG"),TEXT("INIT"),MB_OK);											
		return TRUE ;

								
	case  WM_COMMAND :							
								
		switch (LOWORD (wParam))						
		{						
		case   IDC_BUTTON_OK :
			// 第一步：先获取文本框的句柄
			hEditUser = GetDlgItem(hwndDlg,IDC_EDIT_USER);
			hEditPass = GetDlgItem(hwndDlg,IDC_EDIT_PASSWORD);

			// 第二步：通过句柄获取文本框的内容
			TCHAR szUserBuff[0x50];
			TCHAR szPassBuff[0x50];
			GetWindowText(hEditUser,szUserBuff,0x50);	
			GetWindowText(hEditPass,szPassBuff,0x50);	

			MessageBox(NULL,TEXT("IDC_BUTTON_OK"),TEXT("OK"),MB_OK);					
								
			return TRUE;					
								
		case   IDC_BUTTON_CANCEL:						
								
			MessageBox(NULL,TEXT("IDC_BUTTON_OUT"),TEXT("OUT"),MB_OK);					
								
			EndDialog(hwndDlg, 0);					
								
			return TRUE;
		}						
		break ;						
    }								
								
	return FALSE ;							
}								


int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
	// 原本要做的：

	// CLASS赋值
	// 注册
	// 创建窗口
	// 消息处理函数
	// 消息循环

	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL,DialogProc);
}

