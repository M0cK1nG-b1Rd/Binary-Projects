// producer_consumer3.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"


//�¼����ٽ���
HANDLE g_hSet, g_hClear;
int g_Max = 10;
int g_Number = 0;

//�������̺߳���  
DWORD WINAPI ThreadProduct(LPVOID pM)  
{  
	for (int i = 0; i < g_Max; i++)
	{  
		WaitForSingleObject(g_hSet, INFINITE);  
		g_Number = 1; 
		DWORD id = GetCurrentThreadId();
		printf("������%d������%d���뻺����\n",id, g_Number); 
		SetEvent(g_hClear);   
	}  
	return 0;  
}  
//�������̺߳���
DWORD WINAPI ThreadConsumer(LPVOID pM)  
{  
	for (int i = 0; i < g_Max; i++)
	{  
		WaitForSingleObject(g_hClear, INFINITE);  
		g_Number = 0; 
		DWORD id = GetCurrentThreadId();
		printf("----������%d������%d���뻺����\n",id, g_Number); 
		SetEvent(g_hSet);   
	}  
	return 0;  
}  

int main(int argc, char* argv[])
{

	HANDLE hThread[2]; 

	g_hSet = CreateEvent(NULL, FALSE, TRUE, NULL);  
	g_hClear = CreateEvent(NULL, FALSE, FALSE, NULL); 

	hThread[0] = ::CreateThread(NULL, 0, ThreadProduct, NULL, 0, NULL); 
	hThread[1] = ::CreateThread(NULL, 0, ThreadConsumer, NULL, 0, NULL);

	WaitForMultipleObjects(2, hThread, TRUE, INFINITE);  
	CloseHandle(hThread[0]);  
	CloseHandle(hThread[1]);

	//���� 
	CloseHandle(g_hSet);  
	CloseHandle(g_hClear);  

	return 0;
}
