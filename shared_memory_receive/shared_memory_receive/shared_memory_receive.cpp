// shared_memory_receive.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hMapObject;
	HANDLE hMapView;

	//创建FileMapping对象
	hMapObject = CreateFileMapping((HANDLE)0xFFFFFFFF,NULL,PAGE_READWRITE,0,0x1000,TEXT("shared"));
	if(!hMapObject)
	{
		MessageBox(NULL,TEXT("共享内存失败"),TEXT("Error"),MB_OK);
		return FALSE;
	}
	//将FileMapping对象映射到自己的进程
	hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if(!hMapView)
	{
		MessageBox(NULL,TEXT("内存映射失败"),TEXT("Error"),MB_OK);
		return FALSE;
	}
	//从共享内存读取数据
	TCHAR szBuffer[0x1000] = {0};
	memcpy(szBuffer,hMapView,10);
	MessageBox(NULL,szBuffer,TEXT("从发送端接收到数据"),MB_OK);
	getchar();
}

