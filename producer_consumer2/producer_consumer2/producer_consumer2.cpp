// producer_consumer2.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

//互斥体	
HANDLE hMutex;		
int g_Max = 10;		
int g_Number = 0;   

//生产者线程函数  		
DWORD WINAPI ThreadProduct(LPVOID pM)  		
{  		
    for (int i = 0; i < g_Max; i++)		
    {  		
        //互斥的访问缓冲区  		
        WaitForSingleObject(hMutex,INFINITE);		
		g_Number = 1; 
		DWORD id = GetCurrentThreadId();
		printf("生产者%d将数据%d放入缓冲区\n",id, g_Number); 
        ReleaseMutex(hMutex);		
    }  		
    return 0;  		
}  		

//消费者线程函数		
DWORD WINAPI ThreadConsumer(LPVOID pM)  		
{  		
    for (int i = 0; i < g_Max; i++)		
    {  		
        //互斥的访问缓冲区  		
        WaitForSingleObject(hMutex,INFINITE);		
		g_Number = 0; 
		DWORD id = GetCurrentThreadId();
		printf("----消费者%d将数据%d放入缓冲区\n",id, g_Number); 
		ReleaseMutex(hMutex);
    }  		
    return 0;  		
}  		
		
int main(int argc, char* argv[])		
{		
	//创建一个互斥体	
	hMutex =  CreateMutex(NULL,FALSE,NULL);	
		
		
    HANDLE hThread[2]; 		
		
    hThread[0] = ::CreateThread(NULL, 0, ThreadProduct, NULL, 0, NULL); 		
	hThread[1] = ::CreateThread(NULL, 0, ThreadConsumer, NULL, 0, NULL);	
		
    WaitForMultipleObjects(2, hThread, TRUE, INFINITE);  		
    CloseHandle(hThread[0]);  		
    CloseHandle(hThread[1]);		
		
	//销毁 	
    CloseHandle(hMutex);		
		
		
	return 0;	
}		
		


