// anonymous_pipe_child.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
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
}

