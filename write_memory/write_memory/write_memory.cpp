// write_memory.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

LPTSTR lpszCurrentModuleName;
LPVOID pFileBuffer;
LPVOID pImageBuffer;

int FileLength(FILE *fp) {
	int fileSize = 0;
	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);  //Reset the pointer
	return fileSize;
}

DWORD align(int input, int alignment) {
	int mod = input % alignment;
	double div = (double) input / (double) alignment;
	if (mod == 0) {
		return alignment * div;
	} else {
		return alignment * (int) (div + 1);
	}

}

DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID *pImageBuffer) {
	// PE
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID pTempImageBuffer = NULL;

	if (!pFileBuffer) {
		printf("Invalid buffer pointer!");
		return 0;
	}


	if (*((PWORD) pFileBuffer) != IMAGE_DOS_SIGNATURE) {//0x5A4D
		printf("Invalid DOS signature!");
		return 0;
	}


	pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;


	if (*((PDWORD) ((DWORD) pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
		printf("Invalid NT signature!");
		return 0;
	}
	pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//Apply for new block of memory
	pTempImageBuffer = malloc(pOptionHeader->SizeOfImage + 0x1000); //I don't know whether it's ok to remove the 0x1000

	if (!pTempImageBuffer) {
		printf("Unable to allocate memory!");
		return 0;
	}
	//Initialize new buffer
	memset(pTempImageBuffer, 0, pOptionHeader->SizeOfImage);
	// First copy the whole headers according to the attribute the SizeOfHeaders
	memcpy(pTempImageBuffer, pDosHeader, pOptionHeader->SizeOfHeaders);
	// Then copy the section according to the information in the section headers
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	//Copy sections
	for (int i = 0; i < pPEHeader->NumberOfSections; i++, pTempSectionHeader++) {
		memcpy((void *) ((DWORD) pTempImageBuffer + pTempSectionHeader->VirtualAddress),
			(void *) ((DWORD) pFileBuffer + pTempSectionHeader->PointerToRawData), //pDosHeader is ok
			pTempSectionHeader->SizeOfRawData);
	}

	//Assign image buffer pointer and return value
	*pImageBuffer = pTempImageBuffer;
	pTempImageBuffer = NULL;
	// Return the size of image in the memory
	return pOptionHeader->SizeOfImage;
}


DWORD ReadPEFile(IN LPTSTR lpszFile, OUT LPVOID *pFileBuffer) {

	FILE *pfile = NULL;//File pointer
	int fileSize = 0;
	LPVOID pTempFileBuffer = NULL; // Temp file buffer, points to the allocated memory

	pfile = _tfopen(lpszFile, _T("rb"));
	if (!pfile) //If can't open the file
	{
		printf("Unable to open the file!");
		return 0;
	}


	fileSize = FileLength(pfile);
	pTempFileBuffer = malloc(fileSize); // Allocate memory, return pointer
	if (!pTempFileBuffer) { // If can't allocate the memory
		printf("Unable to allocate memory!");
		fclose(pfile);
		return 0;
	}


	size_t n = fread(pTempFileBuffer, fileSize, 1, pfile); // Copy file into the buffer allocated

	if (!n) { // If can't read
		printf("Unable to read!");
		fclose(pfile);
		free(pTempFileBuffer);
		return 0;
	}
	// Assign the value to the argument and free the pointer and the memory allocated
	*pFileBuffer = pTempFileBuffer;
	pTempFileBuffer = NULL;
	return fileSize;
}


DWORD static WINAPI TestSuccess()
{
	for (int i = 0; i < 10; i++)
	{
		printf("Injected exe running!!!\n");
		Sleep(1000);
	}
	return 0;
}


DWORD static WINAPI Entry(LPVOID pImageBuffer)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_NT_HEADERS pImageNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pImageBuffer + pImageDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pImagePEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pImageNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER pImageOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pImagePEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 修复IAT表


	// 根据注入的EXE的导入表和当前被注入的EXE的环境，修复IAT表
	DWORD dwImageBase = pImageOptionHeader->ImageBase;
	LPVOID pImportDir = (LPVOID)(pImageOptionHeader->DataDirectory[1].VirtualAddress + pImageOptionHeader->ImageBase);

	// 解析导入表
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) pImportDir;
	//遍历数据并找到 IMAGE_IMPORT_DESCRIPTOR 的数目
	// 检查每一个字节
	int num = 0;
	BOOL break_flag = FALSE;
	PIMAGE_IMPORT_DESCRIPTOR pTemp = pImportDescriptor;
	DWORD procAddress;
	while (pTemp->Name != NULL) {
		num++;
		pTemp++;
	}
	// 遍历并处理每一块
	pTemp = pImportDescriptor;

	for (int j = 0; j < num; j++) {
		// DLL的名字
		char *dll_name = (char *) (dwImageBase + (pTemp + j)->Name);
		//printf("%s :\n", dll_name);
		//printf("----------------------------\n");

		// INT表
		PIMAGE_THUNK_DATA pThunkName = (PIMAGE_THUNK_DATA) (dwImageBase + (pTemp + j)->OriginalFirstThunk);
		// IAT表
		PIMAGE_THUNK_DATA pThunkProcAddress = (PIMAGE_THUNK_DATA) (dwImageBase + (pTemp + j)->FirstThunk);

		PIMAGE_IMPORT_BY_NAME pImageImportByName = (PIMAGE_IMPORT_BY_NAME) (dwImageBase + pThunkName->u1.Ordinal);
		// 获取该DLL的函数名或者序号名
		while (TRUE) {
			if ((pThunkName->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) // the highest bit is 0
			{ // 此时是名称导入方式，需要获取导入DLL中的函数名
				pImageImportByName = (PIMAGE_IMPORT_BY_NAME) (dwImageBase +  pThunkName->u1.Ordinal);
				//printf("%s\n", pImageImportByName->Name);	
				// 得到地址
				procAddress =  (DWORD)GetProcAddress(LoadLibrary(dll_name),pImageImportByName->Name);

				// 修复
				pThunkProcAddress->u1.Ordinal = procAddress;
			} else {//The highest bit is 1
				// 此时是序号导入方式，需要获取导入DLL中的序号
				DWORD dwOrdinal = ((pThunkName->u1.Ordinal << 1) >> 1);
				//printf("Import by ordinal: %lx\n", dwOrdinal);
				procAddress = (DWORD)GetProcAddress(LoadLibrary(dll_name),(LPCSTR)dwOrdinal);

				// 修复
				pThunkProcAddress->u1.Ordinal = procAddress;
			}
			pThunkName++;
			pThunkProcAddress++;
			if (pThunkName->u1.Ordinal == 0) { break; }
		}
	}



	// 跳转到A的入口处执行
	DWORD dwOEPAddr = pImageOptionHeader->ImageBase + pImageOptionHeader->AddressOfEntryPoint;
	HANDLE hThread = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)dwOEPAddr,NULL , NULL, NULL);
	printf("AnotherThread running...\n");
	WaitForSingleObject(hThread, INFINITE);
	return 0;
}

// 需要注入的进程ID
DWORD dwInjectedPid = 880;
int _tmain(int argc, _TCHAR* argv[])
{
	DWORD dwCurrentPid = GetCurrentProcessId();
	// 正确注入，执行代码
	if (dwCurrentPid == dwInjectedPid )
	{
		TestSuccess();
		return 0;
	}



	//1、获取自身句柄			
	DWORD dwImageAddr = (DWORD)::GetModuleHandle(NULL);

	// 2、获得自身的ImageBase/SizeOfImage
	PIMAGE_DOS_HEADER pSelfDosHeader  = (PIMAGE_DOS_HEADER)dwImageAddr;
	PIMAGE_NT_HEADERS pSelfNTHeader = (PIMAGE_NT_HEADERS) (dwImageAddr + pSelfDosHeader->e_lfanew);;
	PIMAGE_FILE_HEADER pSelfPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pSelfNTHeader) + 4);;
	PIMAGE_OPTIONAL_HEADER pSelfOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pSelfPEHeader + IMAGE_SIZEOF_FILE_HEADER);

	DWORD dwSelfImageBase = pSelfOptionHeader->ImageBase;
	DWORD dwSelfImageSize = pSelfOptionHeader->SizeOfImage;

	//3、创建一个新的缓冲区，将自己复制进去	
	pImageBuffer = calloc(1,dwSelfImageSize);
	ReadProcessMemory(GetCurrentProcess(),(LPCVOID)dwSelfImageBase,pImageBuffer,dwSelfImageSize,NULL);
	//4、打开要注入的A进程			
	HANDLE hInjectProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwInjectedPid);
	if (hInjectProcess == NULL)
	{
		OutputDebugString("进程不存在！");
		return 1;
	}

	//5、在A进程中申请内存，大小就是SizeOfImage		
	LPVOID lpAllocAddr = VirtualAllocEx(hInjectProcess, NULL, dwSelfImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	//6、根据B的重定位表修复值

	// 改掉ImageBase
	PIMAGE_DOS_HEADER pSelfImageDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_NT_HEADERS pSelfImageNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pImageBuffer + pSelfImageDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pSelfImagePEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pSelfImageNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER pSelfImageOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pSelfImagePEHeader + IMAGE_SIZEOF_FILE_HEADER);
	DWORD dwOriginalImageBase = pSelfImageOptionHeader->ImageBase;
	pSelfImageOptionHeader->ImageBase =(DWORD)lpAllocAddr;


	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pImageBuffer + pSelfImageOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	// 计算delta
	DWORD dwDelta;
	dwDelta = (DWORD)lpAllocAddr - dwOriginalImageBase;//实际的imageBase减去pe文件里面标识的imagebase得到“移动的距离”
	//判断是否有重定位表
	if ((char*)pReloc != (char*)pImageBuffer)
	{
		while ((pReloc->VirtualAddress + pReloc->SizeOfBlock) != 0) //开始扫描重定位表
		{
			WORD* pLocData = (WORD*)((PBYTE)pReloc + sizeof(IMAGE_BASE_RELOCATION));
			//计算需要修正的重定位项（地址）的数目
			int nNumberOfReloc = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			DWORD* pAddress;
			
			for (int i = 0; i < nNumberOfReloc; i++)
			{

				if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //这是一个需要修正的地址
				{
					pAddress = (DWORD*)((PBYTE)pImageBuffer + pReloc->VirtualAddress + (pLocData[i] & 0x0FFF));
					*pAddress += dwDelta;//把移动的距离在原地址加上去
				}
			}

			//转移到下一个节进行处理
			pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
		}
	}


	//7、将修复后的数据，复制到A的内存中			
	WriteProcessMemory(hInjectProcess, lpAllocAddr, pImageBuffer, dwSelfImageSize, NULL);
	//8、创建一个远程线程，执行Entry	
	DWORD dwFixedEntry = (DWORD)Entry + dwDelta;
	HANDLE hThread = CreateRemoteThread(hInjectProcess, NULL, 0, (LPTHREAD_START_ROUTINE)dwFixedEntry, lpAllocAddr, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	return 0;
}

