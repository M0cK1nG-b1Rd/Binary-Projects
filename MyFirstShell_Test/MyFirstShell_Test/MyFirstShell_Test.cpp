// MyFirstShell_Test.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "MyFirstShell_Test.h"


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

    // RVA���ļ�ͷ�л����ļ�����==�ڴ����ʱ��RVA==FOA  ����һ���ǶԵģ��ڶ����Ǵ�ģ����統 Misc>SizeOfRawData��
    if (dwRVA < pOptionHeader->SizeOfHeaders) {
        return dwRVA;
    }

    // �����ڱ�ȷ��ƫ��������һ����
    for (int i = 0; i < pPEHeader->NumberOfSections; i++) {
        if (dwRVA >= pSectionHeader[i].VirtualAddress && dwRVA < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize) {
            int offset = dwRVA - pSectionHeader[i].VirtualAddress;
            return pSectionHeader[i].PointerToRawData + offset;
        }
    }
    printf("�Ҳ���RVA %x ��Ӧ�� FOA��ת��ʧ��\n", dwRVA);
    return 0;
}



int _tmain(int argc, _TCHAR* argv[])
{
	       


        //1����ȡSHELL�����·��
        TCHAR szShellPath[MAX_PATH] = _T("C:\\Users\\admin\\Desktop\\shelled_file.exe");
        //2����ȡsrc������
        LPVOID pShellBuffer = NULL;
        ReadPEFile(szShellPath, &pShellBuffer);
        //(1) ��λ��SHELL�ļ������һ����
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


        //(2) ������ȡ����������
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

        //3������PE
        //�����ܺ��PE�ļ����ڴ������죬���洢����������
        DWORD dwImageBufferSize = CopyFileBufferToImageBuffer((LPVOID) dwOriginFileAddress, &pSrcImageBuffer);

        //4���Թ���ʽ����Shell����
        //(0) �Թ����γɴ���Shell���̣����õ����̵߳�Context
        STARTUPINFO si = {0};
		PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        CreateProcess(
                szShellPath,
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

        //(1) ж����ǳ�����ļ�����(ZwUnmapViewOfSection)

        // ��ȡ�½������߳�������
        CONTEXT context;
        //context.ContextFlags = CONTEXT_FULL;
        //GetThreadContext(pi.hThread, &context);
        //// ��ȡ ZwUnmapViewOfSection ����ָ��
        //HMODULE hModuleNt = LoadLibrary("ntdll.dll");
        //if (hModuleNt == NULL) {
        //    printf("��ȡntdll���ʧ��\n");
        //    TerminateThread(pi.hThread, 0);
        //    return -1;
        //}
        //typedef DWORD(WINAPI *_TZwUnmapViewOfSection)(HANDLE, PVOID);
        //_TZwUnmapViewOfSection pZwUnmapViewOfSection = (_TZwUnmapViewOfSection) GetProcAddress(hModuleNt, "ZwUnmapViewOfSection");
        //if (pZwUnmapViewOfSection == NULL) {
        //    printf("��ȡ ZwUnmapViewOfSection ����ָ��ʧ��\n");
        //    TerminateThread(pi.hThread, 0);
        //    return -1;
        //}
        //// ���� ZwUnmapViewOfSection ж���½����ڴ澵��
        //pZwUnmapViewOfSection(pi.hProcess, GetModuleHandle(NULL));

		typedef NTSTATUS (WINAPI *ZwUnmapViewOfSection)(HANDLE,LPVOID);//���庯��
		ZwUnmapViewOfSection UnmapViewOfSection = (ZwUnmapViewOfSection)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),"ZwUnmapViewOfSection");//��ȡ������ַ
		context.ContextFlags = CONTEXT_ALL;
		GetThreadContext(pi.hThread,&context);//��ȡ�߳�������
		DWORD base;
		ReadProcessMemory(pi.hProcess,(LPVOID)(context.Ebx+8),&base,sizeof(DWORD),NULL);//��ȡ���ܽ��̻�ַ
		UnmapViewOfSection(pi.hProcess,(LPVOID)base);//ж�ؿ��ܽ���ӳ��


        //(2) ��ָ����λ��(src��ImageBase)����ָ����С(src��SizeOfImage)���ڴ�(VirtualAllocEx)

        // �ڿ��ܽ��̵�Դ�����ImageBase������SizeOfImage��С���ڴ�
        LPVOID pRealImageBase = VirtualAllocEx(
                pi.hProcess,
                (LPVOID) dwSrcImageBase,
                dwImageBufferSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);

        //(3) �������ռ�ɹ�����ImageBase���������Ĳ�ͬ���鿴src�Ƿ�����ض�λ����������ض�λ�����޸��ض�λ��.
        if ((DWORD) pRealImageBase != dwSrcImageBase) {
            printf("VirtualAllocEx ������: 0x%lX\n", GetLastError()); // 0x1e7 ��ͼ������Ч��ַ
            printf("���뵽��ָ��: 0x%lX, �����ĵ�ַ: 0x%lX\n", (DWORD) pRealImageBase, dwSrcImageBase);
            printf("�����޸��ض�λ��...\n");
            //(4) �����ָ��λ�������ڴ�ʧ�ܣ�����û���ض�λ������ݣ�ֱ�ӷ���ʧ��.
            if (pSrcDataDirectory[5].VirtualAddress == 0x0 && pSrcDataDirectory[5].Size == 0x0) {
                printf("û���ض�λ���޷������޸�������ʧ��\n");
                TerminateThread(pi.hThread, 0);
                return -1;
            } else {
                // �����ض�λ���޸��ض�λ��
                DWORD dwShift = (DWORD) pRealImageBase - dwSrcImageBase;
                DWORD dwFileRelocationAddr = RVAtoFOA((LPVOID) dwOriginFileAddress, pSrcDataDirectory[5].VirtualAddress);
                PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION) dwFileRelocationAddr;
                while (pRelocation->VirtualAddress != 0x0 && pRelocation->SizeOfBlock != 0x0) {
                    pRelocation->VirtualAddress += dwShift;
                    pRelocation = (PIMAGE_BASE_RELOCATION) ((DWORD) pRelocation + pRelocation->SizeOfBlock);
                }
            }

        } else if (pRealImageBase == NULL) {
            printf("VirtualAllocEx ������: 0x%lX\n", GetLastError()); // 0x1e7 ��ͼ������Ч��ַ
            TerminateThread(pi.hThread, 0);
            return -1;
        }




        //(5) ����ڴ�����ɹ������µ����ݸ��Ƶ��ڴ���
        // ��Դ�����ڴ澵���Ƶ����ܽ���4GB��
        BOOL bWriteMemorySuccessFlag = WriteProcessMemory(
                pi.hProcess,
                pRealImageBase,
                pSrcImageBuffer,
                dwImageBufferSize,
                NULL);
        if (!bWriteMemorySuccessFlag) {
            printf("д��Դ�����ڴ澵��ʧ��\n");
            TerminateThread(pi.hThread, 0);
            return -1;
        }

        //(6) �������л����Ļ�ַ����ڵ�ַ
        // ������ڵ�
        context.Eax = pSrcOptionHeader->AddressOfEntryPoint + (DWORD)pRealImageBase;
        // ���� ImageBase
        WriteProcessMemory(pi.hProcess, (LPVOID) (context.Ebx + 8), &pRealImageBase, 4, NULL);
        context.ContextFlags = CONTEXT_FULL;

        SetThreadContext(pi.hThread, &context);









		////�����ļ�
		//FILE *pf = fopen("badBuffer", "wb+");
		//if (pf == NULL) {
		//	printf("Unable to open file!");
		//}
		//fwrite(pSrcImageBuffer, dwImageBufferSize, 1, pf);
		//fclose(pf);







        //(7) �ָ����߳�ִ��
        ResumeThread(pi.hThread);
        // �ѿǳɹ�
        printf("�ѿǳɹ���Դ�����������У��������ַ��˳�\n");

        free(pShellBuffer);
        free(pSrcImageBuffer);
        system("pause");
        return 0;
}

