// producer_consumer1.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

//临界区		
CRITICAL_SECTION g_cs;		
int g_Max = 10;		
int g_Number = 0;                      		
//生产者线程函数  		
DWORD WINAPI ThreadProduct(LPVOID pM)  		
{  		
    for (int i = 0; i < g_Max; i++)		
    {  		
        //互斥的访问缓冲区  		
        EnterCriticalSection(&g_cs); 		
		g_Number = 1; 
		DWORD id = GetCurrentThreadId();
		printf("生产者%d将数据%d放入缓冲区\n",id, g_Number); 
        LeaveCriticalSection(&g_cs); 		
		
    }  		
    return 0;  		
}  		
//消费者线程函数		
DWORD WINAPI ThreadConsumer(LPVOID pM)  		
{  		
    for (int i = 0; i < g_Max; i++)		
    {  		
        //互斥的访问缓冲区  		
        EnterCriticalSection(&g_cs);  		
		g_Number = 0; 
		DWORD id = GetCurrentThreadId();
		printf("----消费者%d将数据%d放入缓冲区\n",id, g_Number); 
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
		
	//销毁 	
    DeleteCriticalSection(&g_cs);  		

	return 0;	
}		
		

