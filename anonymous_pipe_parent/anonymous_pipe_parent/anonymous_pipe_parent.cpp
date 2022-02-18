// anonymous_pipe_parent.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hParentRead;
	HANDLE hParentWrite;
	HANDLE hChildRead;
	HANDLE hChildWrite;

	SECURITY_ATTRIBUTES sa;

	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);

	if(!CreatePipe(&hParentRead,&hChildWrite,&sa,0))
	{
		MessageBox(0,TEXT("创建匿名管道失败!"),TEXT("Error"),MB_OK);
	}
	if(!CreatePipe(&hChildRead,&hParentWrite,&sa,0))
	{
		MessageBox(0,TEXT("创建匿名管道失败!"),TEXT("Error"),MB_OK);
	}

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si,sizeof(STARTUPINFO));

	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = hChildRead;
	si.hStdOutput = hChildWrite;
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

	LPTSTR szFileName = "C:\\Users\\admin\\Documents\\visual studio 2012\\Projects\\anonymous_pipe_child\\Debug\\anonymous_pipe_child.exe";
	if(!CreateProcess(szFileName,"child",NULL,NULL,TRUE,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi))
	{
		CloseHandle(hParentRead);
		CloseHandle(hParentWrite);
		hParentRead = NULL;
		hParentWrite = NULL;

		CloseHandle(hChildRead);
		CloseHandle(hChildWrite);
		hChildRead = NULL;
		hChildWrite = NULL;
		MessageBox(0,TEXT("创建子进程失败!"),TEXT("Error"),MB_OK);
	}
	else
	{
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}



	//写数据
	TCHAR szWriteBuffer[] = "父进程：http:\\www.dtdebug.com";
	DWORD dwWrite;
	if(!WriteFile(hParentWrite,szWriteBuffer,strlen(szWriteBuffer)+1,&dwWrite,NULL))
	{
		MessageBox(0,TEXT("父进程写数据失败!"),TEXT("Error"),MB_OK);
	}

	Sleep(5000);

	//读数据
	TCHAR szReadBuffer[100];
	DWORD dwRead;
	if(!ReadFile(hParentRead,szReadBuffer,100,&dwRead,NULL))
	{
		MessageBox(NULL,TEXT("父进程读取数据失败!"),TEXT("Error"),MB_OK);
	}
	else
	{
		MessageBox(NULL,szReadBuffer,TEXT("[父进程读取数据]"),MB_OK);
	}
	return 0;
}

