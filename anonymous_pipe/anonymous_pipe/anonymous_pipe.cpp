// anonymous_pipe.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{

	// ������Ӧ������
	if (!strcmp("parent",argv[1])){
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
			MessageBox(0,TEXT("���������ܵ�ʧ��!"),TEXT("Error"),MB_OK);
		}
		if(!CreatePipe(&hChildRead,&hParentWrite,&sa,0))
		{
			MessageBox(0,TEXT("���������ܵ�ʧ��!"),TEXT("Error"),MB_OK);
		}

		STARTUPINFO si;
		PROCESS_INFORMATION pi;

		ZeroMemory(&si,sizeof(STARTUPINFO));

		si.cb = sizeof(STARTUPINFO);
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdInput = hChildRead;
		si.hStdOutput = hChildWrite;
		si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

		LPTSTR szFileName = new TCHAR[MAX_PATH];
		::GetModuleFileName(GetModuleHandle(NULL),szFileName,MAX_PATH);
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
			MessageBox(0,TEXT("�����ӽ���ʧ��!"),TEXT("Error"),MB_OK);
		}
		else
		{
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}



		//д����
		TCHAR szWriteBuffer[] = "�����̣�http:\\www.dtdebug.com";
		DWORD dwWrite;
		if(!WriteFile(hParentWrite,szWriteBuffer,strlen(szWriteBuffer)+1,&dwWrite,NULL))
		{
			MessageBox(0,TEXT("������д����ʧ��!"),TEXT("Error"),MB_OK);
		}

		Sleep(5000);

		//������
		TCHAR szReadBuffer[100];
		DWORD dwRead;
		if(!ReadFile(hParentRead,szReadBuffer,100,&dwRead,NULL))
		{
			MessageBox(NULL,TEXT("�����̶�ȡ����ʧ��!"),TEXT("Error"),MB_OK);
		}
		else
		{
			MessageBox(NULL,szReadBuffer,TEXT("[�����̶�ȡ����]"),MB_OK);
		}
		return 0;


	// �ӽ���Ӧ������
	}else if(!strcmp("child",argv[1])) {
		Sleep(1000);
		//��ʼ��
		HANDLE hRead = GetStdHandle(STD_INPUT_HANDLE);
		HANDLE hWrite = GetStdHandle(STD_OUTPUT_HANDLE);  

		//������
		TCHAR szReadBuffer[100];
		DWORD dwRead;
		if(!ReadFile(hRead,szReadBuffer,100,&dwRead,NULL))
		{
			MessageBox(NULL,TEXT("�ӽ��̶�ȡ����ʧ��!"),TEXT("Error"),MB_OK);
		}
		else
		{
			MessageBox(NULL,szReadBuffer,TEXT("[�ӽ��̶�ȡ����]"),MB_OK);
		}

		Sleep(3000);

		//д����
		TCHAR szWriteBuffer[100] = "�ӽ��̣������ܵ�";
		DWORD dwWrite;
		if(!WriteFile(hWrite,szWriteBuffer,strlen(szWriteBuffer)+1,&dwWrite,NULL))
		{
			MessageBox(NULL,TEXT("�ӽ���д������ʧ��!"),TEXT("Error"),MB_OK);
		}
		return 0;
	
	}else{
		printf("û���㹻�Ĳ�����");
		return 1;
	}
}

