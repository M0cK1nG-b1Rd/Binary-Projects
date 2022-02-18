#include "PE_tools.h"

int FileLength(FILE *fp) {
    int fileSize = 0;
    fseek(fp, 0, SEEK_END);
    fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);  //Reset the pointer
    return fileSize;
}


DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID *pFileBuffer) {

    FILE *pfile = NULL;//File pointer
    int fileSize = 0;
    LPVOID pTempFileBuffer = NULL; // Temp file buffer, points to the allocated memory

    pfile = fopen(lpszFile, "rb");
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


DWORD CopyImageBufferToNewFileBuffer(LPVOID pImageBuffer, LPVOID *pNewFileBuffer) {
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

    LPVOID pTempNewbuffer = NULL;

    if (!pImageBuffer) {
        printf("(CopyImageBufferToNewBuffer)Can't open file!\n");
        return 0;
    }


    if (*((PWORD) pImageBuffer) != IMAGE_DOS_SIGNATURE) {
        printf("(CopyImageBufferToNewBuffer)No MZ flag, not exe file!\n");
        return 0;
    }

    pDosHeader = (PIMAGE_DOS_HEADER) pImageBuffer;
    if (*((PDWORD) ((DWORD) pImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {
        printf("(CopyImageBufferToNewBuffer)Not a valid PE flag!\n");
        return 0;
    }

    pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pImageBuffer + pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER) ((DWORD) pNTHeader + 4); // 这里必须强制类型转换
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    pSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pOptionHeader + pPEHeader->SizeOfOptionalHeader);

    //获取new_buffer的大小// 是否能用SizeOfImage代替？
    int new_buffer_size = pOptionHeader->SizeOfHeaders;

    for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++) {
        new_buffer_size += pSectionHeader[i].SizeOfRawData;  // pSectionHeader[i]另一种加法
    }
    // 分配内存（newbuffer）
    pTempNewbuffer = malloc(new_buffer_size);
    if (!pTempNewbuffer) {
        printf("(CopyImageBufferToNewBuffer)Allocate dynamic memory failed!\n");
        return 0;
    }
    memset(pTempNewbuffer, 0, new_buffer_size);
    memcpy(pTempNewbuffer, pDosHeader, pOptionHeader->SizeOfHeaders);
    // 循环拷贝节区
    PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
    //PointerToRawData节区在文件中的偏移,VirtualAddress节区在内存中的偏移地址,SizeOfRawData节在文件中对齐后的尺寸
    for (DWORD j = 0; j < pPEHeader->NumberOfSections; j++, pTempSectionHeader++) {
        memcpy((PDWORD) ((DWORD) pTempNewbuffer + pTempSectionHeader->PointerToRawData),
               (PDWORD) ((DWORD) pImageBuffer + pTempSectionHeader->VirtualAddress), pTempSectionHeader->SizeOfRawData);
    }
    //返回数据
    *pNewFileBuffer = pTempNewbuffer; //暂存的数据传给参数后释放
    pTempNewbuffer = NULL;
    return new_buffer_size;  // 返回计算得到的分配内存的大小
}

BOOL MemeryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile) {
    FILE *file = fopen(lpszFile, "wb");
    if (file == NULL) {
        printf("Unable to open file!");
        return 0;
    }
    fwrite(pMemBuffer, size, 1, file);
    fclose(file); //Always remember to close file.
    return 1;
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


DWORD FOAtoRVA(IN LPVOID pFileBuffer, IN DWORD dwFOA) {
    int RetFoaValue = 0;
    //定位节表位置,遍历节表.判断是否在节表内.
    PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER) (pFileBuffer);
    PIMAGE_NT_HEADERS pNtHead = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHead->e_lfanew);
    //定位节表.
    PIMAGE_SECTION_HEADER SectionTableAddress = IMAGE_FIRST_SECTION(pNtHead);//获得了节表的首地址

    for (int i = 0; i < pNtHead->FileHeader.NumberOfSections; i++) {
        if (dwFOA >= SectionTableAddress[i].PointerToRawData && dwFOA < (SectionTableAddress[i].PointerToRawData + SectionTableAddress[i].SizeOfRawData)) {
            //落在这个节中.
            RetFoaValue = dwFOA - SectionTableAddress[i].PointerToRawData; // 文件偏移 -文件偏移首地址 = 偏移. 偏移加上自己的VirtuallAddress 就是在内存中的RVA
            RetFoaValue = RetFoaValue + SectionTableAddress[i].VirtualAddress;
            return RetFoaValue; //返回FOA在内存中的RVA偏移.
        }
    }
    printf("找不到FOA %x 对应的RVA，转换失败\n", dwFOA);
    return 0;
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

VOID saveFile(LPVOID pFileBuffer,int size,char * file_path) {
//Save the file
    FILE *pf = fopen(file_path, "wb+");
    if (pf == NULL) {
        printf("Unable to open file!");
    }
    fwrite(pFileBuffer, size, 1, pf);
    fclose(pf); //Always remember to close file.
}