// shared_memory_send.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hMapObject;
	HANDLE hMapView;

	//����FileMapping����
	hMapObject = CreateFileMapping((HANDLE)0xFFFFFFFF,NULL,PAGE_READWRITE,0,0x1000,TEXT("shared"));
	if(!hMapObject)
	{
		MessageBox(NULL,TEXT("�����ڴ�ʧ��"),TEXT("Error"),MB_OK);
		return FALSE;
	}
	//��FileMapping����ӳ�䵽�Լ��Ľ���
	hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if(!hMapView)
	{
		MessageBox(NULL,TEXT("�ڴ�ӳ��ʧ��"),TEXT("Error"),MB_OK);
		return FALSE;
	}
	//�����ڴ�д������
	strcpy((char*)hMapView,"Test Shared Memery");
	getchar();

}

