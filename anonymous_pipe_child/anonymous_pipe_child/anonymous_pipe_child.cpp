// anonymous_pipe_child.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
	Sleep(1000);
	//初始化
	HANDLE hRead = GetStdHandle(STD_INPUT_HANDLE);
	HANDLE hWrite = GetStdHandle(STD_OUTPUT_HANDLE);  

	//读数据
	TCHAR szReadBuffer[100];
	DWORD dwRead;
	if(!ReadFile(hRead,szReadBuffer,100,&dwRead,NULL))
	{
		MessageBox(NULL,TEXT("子进程读取数据失败!"),TEXT("Error"),MB_OK);
	}
	else
	{
		MessageBox(NULL,szReadBuffer,TEXT("[子进程读取数据]"),MB_OK);
	}

	Sleep(3000);

	//写数据
	TCHAR szWriteBuffer[100] = "子进程：匿名管道";
	DWORD dwWrite;
	if(!WriteFile(hWrite,szWriteBuffer,strlen(szWriteBuffer)+1,&dwWrite,NULL))
	{
		MessageBox(NULL,TEXT("子进程写入数据失败!"),TEXT("Error"),MB_OK);
	}
	return 0;
}

