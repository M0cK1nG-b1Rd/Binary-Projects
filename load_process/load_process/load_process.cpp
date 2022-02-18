// load_process.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


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
        fclose(pfile);
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


int _tmain(int argc, _TCHAR* argv[])
{
	LPVOID pFileBuffer;
	LPVOID pImageBuffer;
	DWORD dwImageSize;
	HANDLE hCurrentProcess;
	LPVOID lpAllocAddr;

	PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	LPVOID pImportDir;
	LPVOID pImportAddressDir;


	DWORD dwImageBase;
	DWORD dwLastError;
	// 读取A.exe，拉伸到0x400000中
	ReadPEFile("C:\\Users\\admin\\Desktop\\injected_exe.exe", &pFileBuffer);
	dwImageSize = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	
	//更新PE文件信息
	pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

	dwImageBase = pOptionHeader->ImageBase;
	pImportAddressDir = (LPVOID)(pOptionHeader->DataDirectory[12].VirtualAddress + dwImageBase);

	// 获取进程自身句柄
	hCurrentProcess = GetCurrentProcess();
	// 在进程中申请空间，需要以A.exe的基址来申请
	VirtualAllocEx(hCurrentProcess, (LPVOID)dwImageBase, dwImageSize, MEM_RESET, PAGE_READWRITE);
	lpAllocAddr = VirtualAllocEx(hCurrentProcess, (LPVOID)dwImageBase, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	if (lpAllocAddr == NULL )
	{
		dwLastError = GetLastError();
		OutputDebugString("VirtualAllocEx failed!");
		CloseHandle(hCurrentProcess);
		return 1;
	}

	if (lpAllocAddr != (LPVOID)dwImageBase )
	{
		dwLastError = GetLastError();
		OutputDebugString("VirtualAllocEx address inconsist!");
		CloseHandle(hCurrentProcess);
		return 1;
	}
	// 在进程中写入ImageBuffer
	WriteProcessMemory(hCurrentProcess, lpAllocAddr, pImageBuffer, dwImageSize, NULL);


	// 根据A.exe的导入表，修复IAT表

	pImportDir = (LPVOID)(pOptionHeader->DataDirectory[1].VirtualAddress + dwImageBase);

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
	DWORD dwOEPAddr = pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint;
	HANDLE hThread = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)dwOEPAddr,NULL , NULL, NULL);
	printf("Hello World\nBelow are the loaded exe:\n");
	WaitForSingleObject(hThread, INFINITE);

	return 0;
}

