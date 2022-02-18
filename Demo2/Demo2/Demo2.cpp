// Demo3.cpp : ����Ӧ�ó������ڵ㡣
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
			// ��һ�����Ȼ�ȡ�ı���ľ��
			hEditUser = GetDlgItem(hwndDlg,IDC_EDIT_USER);
			hEditPass = GetDlgItem(hwndDlg,IDC_EDIT_PASSWORD);

			// �ڶ�����ͨ�������ȡ�ı��������
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
	// ԭ��Ҫ���ģ�

	// CLASS��ֵ
	// ע��
	// ��������
	// ��Ϣ������
	// ��Ϣѭ��

	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL,DialogProc);
}

