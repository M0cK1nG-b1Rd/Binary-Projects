//
// Created by MS08-067 on 2020/8/4.
//

#include "PE_addcode.h"
#include "PE_tools.h"


VOID addShellCode() {
    LPVOID pFileBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    DWORD RVA_codeBegin = 0;
    size_t size = ReadPEFile(FILEPATH_IN, &pFileBuffer);    //解析PE
    pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;//Dos头
    pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHeader->e_lfanew);//NT头
    pPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);//PE头
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);//可选PE头
    pSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pOptionHeader + pPEHeader->SizeOfOptionalHeader);//节表
//     判断代码空闲区空间
    if ((pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize) < SHELLCODELENGTH) {
        printf("代码区空闲空间不足");
        free(pFileBuffer);
        exit(0);
    }    //添加shellcode代码
    PBYTE codeBegin = (PBYTE) ((DWORD) pFileBuffer + pSectionHeader->PointerToRawData + pSectionHeader->Misc.VirtualSize + 8);
    printf("codeBegin:%x\n", *codeBegin);
    memcpy(codeBegin, shellCode, SHELLCODELENGTH);    //FOA->RVA
    if (pOptionHeader->SectionAlignment != pOptionHeader->FileAlignment) {
        RVA_codeBegin = (DWORD) codeBegin - pSectionHeader->PointerToRawData + pSectionHeader->VirtualAddress +
                        pOptionHeader->ImageBase - (DWORD) pFileBuffer;
    } else {
        RVA_codeBegin = (DWORD) codeBegin - (DWORD) pFileBuffer;
    }    //修正E8
    DWORD callAddr = MESSAGEBOXADDR - (RVA_codeBegin + 0xD);
    printf("callAddr:%x\n", callAddr);
    *(PDWORD) (codeBegin + 0x9) = callAddr;    //修正E9
    DWORD jmpAddr = (pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (RVA_codeBegin + 0x12);
    printf("ImageBase:%x\nAddressEntryPoint:%x\n", pOptionHeader->ImageBase, pOptionHeader->AddressOfEntryPoint);
    *(PDWORD) (codeBegin + 0xE) = jmpAddr;
    printf("jmpAddr:%x\n", jmpAddr);    //修正OEP
    pOptionHeader->AddressOfEntryPoint = RVA_codeBegin - pOptionHeader->ImageBase;
    printf("OEP:%x\n", RVA_codeBegin - pOptionHeader->ImageBase);    //存入文件
    FILE *fp = fopen(FILEPATH_OUT, "wb+");
    fwrite(pFileBuffer, size, 1, fp);
    fclose(fp);
}


