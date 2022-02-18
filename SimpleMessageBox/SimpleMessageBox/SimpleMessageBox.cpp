// SimpleMessageBox.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
	while (true)
	{
		Sleep(5000);
		MessageBox(NULL,_T("超了"),0,MB_OK);
	}
	return 0;
}

