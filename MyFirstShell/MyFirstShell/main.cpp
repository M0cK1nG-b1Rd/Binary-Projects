//
// Created by MS08-067 on 2022/1/16.
//

// MyFirstShell.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

// "C:\Users\admin\Desktop\notepad.exe"


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

VOID AddSection(IN LPTSTR szShellFilePath, IN LPTSTR szDataFilePath, OUT LPTSTR szOutputFileName) {


    //Original buffer
    LPVOID pFileBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    size_t size = ReadPEFile(szShellFilePath, &pFileBuffer); //Notice that it's &pFileBuffer
    pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    pSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pOptionHeader + pPEHeader->SizeOfOptionalHeader);


    // 新的指针
    LPVOID pDataFileBuffer = NULL;
    DWORD dwSizeOfNewSection = ReadPEFile(szDataFilePath, &pDataFileBuffer);

    DWORD dwFileAlignedSizeOfNewSection = align(dwSizeOfNewSection, pOptionHeader->FileAlignment);

    //新的文件缓冲区
    LPVOID pNewFileBuffer = NULL;
    pNewFileBuffer = malloc(size + dwFileAlignedSizeOfNewSection);
    if (!pNewFileBuffer) {
        printf("Allocate dynamic memory for NewFileBuffer failed!\n");
        return;
    }
    memset(pNewFileBuffer, 0, size + dwFileAlignedSizeOfNewSection);
    memcpy(pNewFileBuffer, pFileBuffer, size);

    PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER) pNewFileBuffer;
    PIMAGE_NT_HEADERS pNewNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pNewFileBuffer + pNewDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pNewFileHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNewNTHeader) + 4);
    PIMAGE_OPTIONAL_HEADER32 pNewOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pNewFileHeader +
                                                                            IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pNewOptionHeader +
                                                                       pNewFileHeader->SizeOfOptionalHeader);

    //检查是否能插入新的节区头
    boolean flagRemain = TRUE;
    boolean flagVacant = TRUE;
    //检查是否有剩余空间，这里不需要使用RVAtoFOA函数，原因是地址都在PEHeader中
    DWORD remainSize =
            (DWORD) (pNewSectionHeader->VirtualAddress) - (DWORD) (pNewSectionHeader + pNewFileHeader->NumberOfSections);
    //这里实际上在许多程序中并没有发现为zero padding预留空间，但是按PE规范这里还是判断需要0x50的字节
    flagRemain = remainSize >= 0x28 * 2 ? TRUE : FALSE;
    //检查剩余的空间是否为空
    for (int i = 0; i < remainSize; i++) {
        PBYTE check = (PBYTE) ((DWORD) (pNewSectionHeader + pNewFileHeader->NumberOfSections - 1) + 0x28);
        if (*check != 0) {
            flagVacant = FALSE;
            break;
        }
    }
    if (flagRemain && flagVacant) {
        printf("Enough usable place for insertion! Inserting....");
    } else {
        printf("No place for insertion! Overwriting the stub area...");
        // 将除DOS Header外的所有PE头整体上移，占用原来的stub空间
        PBYTE pNewStub = (PBYTE) ((DWORD) pNewDosHeader + sizeof(IMAGE_DOS_HEADER)); //The size of dos-header is 0x40;
        DWORD sizeToCopy = sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * pPEHeader->NumberOfSections;
        memcpy(pNewStub, pNewNTHeader, sizeToCopy);
        pNewDosHeader->e_lfanew = 0x40;
        //将PE头整体上移
        DWORD shift = (DWORD) (pNewNTHeader) - (DWORD) (pNewStub); // size to shift forward
        pNewNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pNewNTHeader - shift);
        pNewFileHeader = (PIMAGE_FILE_HEADER) ((DWORD) pNewFileHeader - shift);
        pNewOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pNewOptionHeader - shift);
        pNewSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pNewSectionHeader - shift);
    }
    PIMAGE_SECTION_HEADER pInsertedSectionHeader = pNewSectionHeader + pNewFileHeader->NumberOfSections;

//    //设置新区段头物理大小与区段对齐后大小
//    LPTSTR szSectionName = TEXT(".shell");
//    memcpy(pInsertedSectionHeader,szSectionName, lstrlen(szSectionName));
//    pInsertedSectionHeader->Misc.VirtualSize = (DWORD)dwSizeOfNewSection;
//    pInsertedSectionHeader->SizeOfRawData =
//            align(dwSizeOfNewSection, pOptionHeader->FileAlignment);
//    //区段内存偏移=上一个区段的偏移+上一个区段对齐后的大小还要加0x1000
//    //否则虚拟地址与前一个区段的虚拟地址还是一样，会导致程序无法执行
//    pInsertedSectionHeader->VirtualAddress =
//            (pInsertedSectionHeader - 1)->VirtualAddress + align(
//                    (pInsertedSectionHeader - 1)->SizeOfRawData, pOptionHeader->SectionAlignment) ; //+ 0x1000 ?
//    //设置新区段数据存放位置
//    pInsertedSectionHeader->PointerToRawData =
//            (pInsertedSectionHeader - 1)->PointerToRawData + (pInsertedSectionHeader - 1)->SizeOfRawData;
//    //设置区段属性
//    pInsertedSectionHeader->Characteristics = 0xE00000E0;

    LPTSTR szSectionName = TEXT(".shell");
    memcpy(pInsertedSectionHeader,szSectionName, lstrlen(szSectionName));
    memset((LPVOID) ((DWORD) pInsertedSectionHeader + 0x28), 0, 0x28); //Zero padding for the size of 0x28
    pNewFileHeader->NumberOfSections += 1;
    pNewOptionHeader->SizeOfImage += align(dwSizeOfNewSection, pOptionHeader->SectionAlignment);

    PIMAGE_SECTION_HEADER oldLastSectionHeader = pInsertedSectionHeader - 1;
    // 这里需要注意的是有的节可能拉伸后的VirtualSize反而没有原来的SizeOfRawData大
    DWORD dwVirtualAddressUnaligned = oldLastSectionHeader->VirtualAddress +
                                      (oldLastSectionHeader->Misc.VirtualSize > oldLastSectionHeader->SizeOfRawData
                                       ? oldLastSectionHeader->Misc.VirtualSize
                                       : oldLastSectionHeader->SizeOfRawData);
    pInsertedSectionHeader->VirtualAddress = align(dwVirtualAddressUnaligned, pOptionHeader->SectionAlignment);
    pInsertedSectionHeader->Misc.VirtualSize = dwSizeOfNewSection;
    pInsertedSectionHeader->PointerToRawData = oldLastSectionHeader->PointerToRawData + oldLastSectionHeader->SizeOfRawData;
    pInsertedSectionHeader->SizeOfRawData = dwFileAlignedSizeOfNewSection;
    // Default
    //pInsertedSectionHeader->Characteristics = 0x60000020;
    // Import-Inject
    pInsertedSectionHeader->Characteristics = 0xC0000040;

	//将整个需要保护的文件内容复制到最后一个节中
	memcpy((LPVOID)((DWORD)pNewFileBuffer+(DWORD)pInsertedSectionHeader->PointerToRawData),pDataFileBuffer,dwSizeOfNewSection);

    //保存文件
    FILE *pf = fopen(szOutputFileName, "wb+");
    if (pf == NULL) {
        printf("Unable to open file!");
    }
    fwrite(pNewFileBuffer, size + dwFileAlignedSizeOfNewSection, 1, pf);
    fclose(pf);
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

DWORD RVAtoFOA(IN LPVOID pFileBuffer, IN DWORD dwRVA) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;
    PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER) (pDosHeader->e_lfanew + (DWORD) pFileBuffer + 4);
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pOptionHeader + pPEHeader->SizeOfOptionalHeader);

    // RVA在文件头中或者文件对齐==内存对齐时，RVA==FOA  错！第一句是对的，第二句是错的（比如当 Misc>SizeOfRawData）
    if (dwRVA < pOptionHeader->SizeOfHeaders) {
        return dwRVA;
    }

    // 遍历节表，确定偏移属于哪一个节
    for (int i = 0; i < pPEHeader->NumberOfSections; i++) {
        if (dwRVA >= pSectionHeader[i].VirtualAddress && dwRVA < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize) {
            int offset = dwRVA - pSectionHeader[i].VirtualAddress;
            return pSectionHeader[i].PointerToRawData + offset;
        }
    }
    printf("找不到RVA %x 对应的 FOA，转换失败\n", dwRVA);
    return 0;
}

int main(int argc, _TCHAR *argv[]) {
    // 如果能取到argv的参数值，则加壳

    if (argc == 2) {

        TCHAR szShellPath[MAX_PATH] = {0};
        GetModuleFileName(NULL, szShellPath, sizeof(szShellPath) / sizeof(TCHAR));


        // 增加节并保存文件
        AddSection(szShellPath, argv[1], _T("shelled_file.exe"));
        return 0;

    } else {
        // 没取到则解壳后运行程序


        //1、获取SHELL程序的路径
        TCHAR szShellPath[MAX_PATH] = {0};
        GetModuleFileName(NULL, szShellPath, sizeof(szShellPath) / sizeof(TCHAR));
        //2、获取src的数据
        LPVOID pShellBuffer = NULL;
        ReadPEFile(szShellPath, &pShellBuffer);
        //(1) 定位到SHELL文件的最后一个节
        PIMAGE_DOS_HEADER pDosHeader = NULL;
        PIMAGE_NT_HEADERS pNTHeader = NULL;
        PIMAGE_FILE_HEADER pFileHeader = NULL;
        PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
        PIMAGE_SECTION_HEADER pSectionHeader = NULL;
        PIMAGE_SECTION_HEADER pLastSectionHeader = NULL;
        pDosHeader = (PIMAGE_DOS_HEADER) pShellBuffer;
        pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pShellBuffer + pDosHeader->e_lfanew);
        pFileHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);
        pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
        pSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pOptionHeader + pFileHeader->SizeOfOptionalHeader);
        pLastSectionHeader = pSectionHeader + pFileHeader->NumberOfSections - 1;


        //(2) 将数据取出，并解密
        DWORD dwOriginFileAddress = (DWORD) pShellBuffer + (DWORD) pLastSectionHeader->PointerToRawData;
        LPVOID pSrcImageBuffer = NULL;



		PIMAGE_DOS_HEADER pSrcDosHeader = NULL;
        PIMAGE_NT_HEADERS pSrcNTHeader = NULL;
        PIMAGE_FILE_HEADER pSrcFileHeader = NULL;
        PIMAGE_OPTIONAL_HEADER32 pSrcOptionHeader = NULL;
        PIMAGE_SECTION_HEADER pSrcSectionHeader = NULL;
		PIMAGE_DATA_DIRECTORY pSrcDataDirectory = NULL;
        pSrcDosHeader = (PIMAGE_DOS_HEADER) dwOriginFileAddress;
        pSrcNTHeader = (PIMAGE_NT_HEADERS) (dwOriginFileAddress + pSrcDosHeader->e_lfanew);
        pSrcFileHeader = (PIMAGE_FILE_HEADER) (((DWORD) pSrcNTHeader) + 4);
        pSrcOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pSrcFileHeader + IMAGE_SIZEOF_FILE_HEADER);
        pSrcSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pSrcOptionHeader + pSrcFileHeader->SizeOfOptionalHeader);
		pSrcDataDirectory = pSrcOptionHeader->DataDirectory;

		DWORD dwSrcImageBase = pSrcOptionHeader->ImageBase;

        //3、拉伸PE
        //将解密后的PE文件在内存中拉伸，并存储到缓冲区中
        DWORD dwImageBufferSize = CopyFileBufferToImageBuffer((LPVOID) dwOriginFileAddress, &pSrcImageBuffer);

        //4、以挂起方式运行Shell进程
        //(0) 以挂起形成创建Shell进程，并得到主线程的Context
        STARTUPINFO si = {0};
		PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        CreateProcess(
                _T("C:\\Users\\admin\\Desktop\\PEView.exe"), //szShellPath
                NULL,
                NULL,
                NULL,
                FALSE,
                CREATE_SUSPENDED,
                NULL,
                NULL,
                &si,
                &pi
        );

        //(1) 卸载外壳程序的文件镜像(ZwUnmapViewOfSection)

        // 获取新进程主线程上下文
        CONTEXT context;
        //context.ContextFlags = CONTEXT_FULL;
        //GetThreadContext(pi.hThread, &context);
        //// 获取 ZwUnmapViewOfSection 函数指针
        //HMODULE hModuleNt = LoadLibrary("ntdll.dll");
        //if (hModuleNt == NULL) {
        //    printf("获取ntdll句柄失败\n");
        //    TerminateThread(pi.hThread, 0);
        //    return -1;
        //}
        //typedef DWORD(WINAPI *_TZwUnmapViewOfSection)(HANDLE, PVOID);
        //_TZwUnmapViewOfSection pZwUnmapViewOfSection = (_TZwUnmapViewOfSection) GetProcAddress(hModuleNt, "ZwUnmapViewOfSection");
        //if (pZwUnmapViewOfSection == NULL) {
        //    printf("获取 ZwUnmapViewOfSection 函数指针失败\n");
        //    TerminateThread(pi.hThread, 0);
        //    return -1;
        //}
        //// 调用 ZwUnmapViewOfSection 卸载新进程内存镜像
        //pZwUnmapViewOfSection(pi.hProcess, GetModuleHandle(NULL));

		typedef NTSTATUS (WINAPI *ZwUnmapViewOfSection)(HANDLE,LPVOID);//定义函数
		ZwUnmapViewOfSection UnmapViewOfSection = (ZwUnmapViewOfSection)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),"ZwUnmapViewOfSection");//获取函数基址
		context.ContextFlags = CONTEXT_ALL;
		GetThreadContext(pi.hThread,&context);//获取线程上下文
		DWORD base;
		ReadProcessMemory(pi.hProcess,(LPVOID)(context.Ebx+8),&base,sizeof(DWORD),NULL);//读取傀儡进程基址
		UnmapViewOfSection(pi.hProcess,(LPVOID)base);//卸载傀儡进程映射


        //(2) 在指定的位置(src的ImageBase)申请指定大小(src的SizeOfImage)的内存(VirtualAllocEx)

        // 在傀儡进程的源程序的ImageBase处申请SizeOfImage大小的内存
        LPVOID pRealImageBase = VirtualAllocEx(
                pi.hProcess,
                (LPVOID) dwSrcImageBase,
                dwImageBufferSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);

        //(3) 如果申请空间成功但是ImageBase和所期望的不同，查看src是否包含重定位表，如果包含重定位表，就修复重定位表.
        if ((DWORD) pRealImageBase != dwSrcImageBase) {
            printf("VirtualAllocEx 错误码: 0x%lX\n", GetLastError()); // 0x1e7 试图访问无效地址
            printf("申请到的指针: 0x%lX, 期望的地址: 0x%lX\n", (DWORD) pRealImageBase, dwSrcImageBase);
            printf("尝试修复重定位表...\n");
            //(4) 如果在指定位置申请内存失败，并且没有重定位表的数据，直接返回失败.
            if (pSrcDataDirectory[5].VirtualAddress == 0x0 && pSrcDataDirectory[5].Size == 0x0) {
                printf("没有重定位表，无法进行修复！运行失败\n");
                TerminateThread(pi.hThread, 0);
                return -1;
            } else {
                // 存在重定位表，修复重定位表
                DWORD dwShift = (DWORD) pRealImageBase - dwSrcImageBase;
                DWORD dwFileRelocationAddr = RVAtoFOA((LPVOID) dwOriginFileAddress, pSrcDataDirectory[5].VirtualAddress);
                PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION) dwFileRelocationAddr;
                while (pRelocation->VirtualAddress != 0x0 && pRelocation->SizeOfBlock != 0x0) {
                    pRelocation->VirtualAddress += dwShift;
                    pRelocation = (PIMAGE_BASE_RELOCATION) ((DWORD) pRelocation + pRelocation->SizeOfBlock);
                }
            }

        } else if (pRealImageBase == NULL) {
            printf("VirtualAllocEx 错误码: 0x%lX\n", GetLastError()); // 0x1e7 试图访问无效地址
            TerminateThread(pi.hThread, 0);
            return -1;
        }




        //(5) 如果内存申请成功，将新的数据复制到内存中
        // 将源程序内存镜像复制到傀儡进程4GB中
        BOOL bWriteMemorySuccessFlag = WriteProcessMemory(
                pi.hProcess,
                pRealImageBase,
                pSrcImageBuffer,
                dwImageBufferSize,
                NULL);
        if (!bWriteMemorySuccessFlag) {
            printf("写入源程序内存镜像失败\n");
            TerminateThread(pi.hThread, 0);
            return -1;
        }

        //(6) 修正运行环境的基址和入口地址
        // 修正入口点
        context.Eax = pSrcOptionHeader->AddressOfEntryPoint + (DWORD)pRealImageBase;
        // 修正 ImageBase
        WriteProcessMemory(pi.hProcess, (LPVOID) (context.Ebx + 8), &pRealImageBase, 4, NULL);
        context.ContextFlags = CONTEXT_FULL;

        SetThreadContext(pi.hThread, &context);









		////保存文件
		//FILE *pf = fopen("badBuffer", "wb+");
		//if (pf == NULL) {
		//	printf("Unable to open file!");
		//}
		//fwrite(pSrcImageBuffer, dwImageBufferSize, 1, pf);
		//fclose(pf);







        //(7) 恢复主线程执行
        ResumeThread(pi.hThread);
        // 脱壳成功
        printf("脱壳成功，源程序正在运行，敲任意字符退出\n");

        free(pShellBuffer);
        free(pSrcImageBuffer);
        system("pause");
        return 0;
    }
}


