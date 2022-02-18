// producer_consumer1.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

//�ٽ���		
CRITICAL_SECTION g_cs;		
int g_Max = 10;		
int g_Number = 0;                      		
//�������̺߳���  		
DWORD WINAPI ThreadProduct(LPVOID pM)  		
{  		
    for (int i = 0; i < g_Max; i++)		
    {  		
        //����ķ��ʻ�����  		
        EnterCriticalSection(&g_cs); 		
		g_Number = 1; 
		DWORD id = GetCurrentThreadId();
		printf("������%d������%d���뻺����\n",id, g_Number); 
        LeaveCriticalSection(&g_cs); 		
		
    }  		
    return 0;  		
}  		
//�������̺߳���		
DWORD WINAPI ThreadConsumer(LPVOID pM)  		
{  		
    for (int i = 0; i < g_Max; i++)		
    {  		
        //����ķ��ʻ�����  		
        EnterCriticalSection(&g_cs);  		
		g_Number = 0; 
		DWORD id = GetCurrentThreadId();
		printf("----������%d������%d���뻺����\n",id, g_Number); 
	LeaveCriticalSection(&g_cs); 	
    }  		
    return 0;  		
}  		
		
int main(int argc, char* argv[])		
{		
	InitializeCriticalSection(&g_cs);	
		
		
    HANDLE hThread[2]; 		
		
    hThread[0] = ::CreateThread(NULL, 0, ThreadProduct, NULL, 0, NULL); 		
	hThread[1] = ::CreateThread(NULL, 0, ThreadConsumer, NULL, 0, NULL);	
		
    WaitForMultipleObjects(2, hThread, TRUE, INFINITE);  		
    CloseHandle(hThread[0]);  		
    CloseHandle(hThread[1]);		
		
	//���� 	
    DeleteCriticalSection(&g_cs);  		

	return 0;	
}		
		

