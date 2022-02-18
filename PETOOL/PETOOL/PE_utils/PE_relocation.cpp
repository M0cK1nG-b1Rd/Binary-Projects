//
// Created by MS08-067 on 2020/8/6.
//

#include "PE_relocation.h"

VOID PrintRelocation() {
    //Original buffer
    LPVOID pFileBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    ReadPEFile(FILEPATH_IN, &pFileBuffer);
    pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    pSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pOptionHeader + pPEHeader->SizeOfOptionalHeader);

    DWORD relocation_foa = (DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[5].VirtualAddress);
    PIMAGE_BASE_RELOCATION pimageBaseRelocation = (PIMAGE_BASE_RELOCATION) relocation_foa;
    int num = 0;
    PIMAGE_BASE_RELOCATION ptemp1ImageBaseRelocation = pimageBaseRelocation;
    PIMAGE_BASE_RELOCATION ptemp2ImageBaseRelocation;
    while (TRUE) {
        DWORD relocation_table_foa = RVAtoFOA(pFileBuffer, ptemp1ImageBaseRelocation->VirtualAddress);
        PIMAGE_BASE_RELOCATION ptemp2ImageBaseRelocation = (PIMAGE_BASE_RELOCATION) ((DWORD) ptemp1ImageBaseRelocation +
                                                                                     ptemp1ImageBaseRelocation->SizeOfBlock);
        if (ptemp2ImageBaseRelocation->SizeOfBlock == 0 && ptemp1ImageBaseRelocation->VirtualAddress == 0) { break; }
        else {
            ptemp1ImageBaseRelocation = ptemp2ImageBaseRelocation;
            num++;
        }
    }
    //Reuse ptemp1ImageBaseRelocation and ptemp2ImageBaseRelocation
    ptemp1ImageBaseRelocation = pimageBaseRelocation;
    for (int i = 0; i < num; i++) {
        ptemp2ImageBaseRelocation = (PIMAGE_BASE_RELOCATION) ((DWORD) ptemp1ImageBaseRelocation + ptemp1ImageBaseRelocation->SizeOfBlock);
        DWORD pRelocationData = (DWORD) ptemp1ImageBaseRelocation;
        WORD total_in_block = (ptemp1ImageBaseRelocation->SizeOfBlock - 8) / 2;
        printf("Section %lx h\n", ptemp1ImageBaseRelocation->VirtualAddress);
        printf("----------------------------------\n");
        for (int j = 0; j < total_in_block; j++) {
            WORD data = *(PWORD) (8 + (DWORD) (pRelocationData + j));
            // Get three bit
            int flag = data >> 12; //Flag is 3(need to be fixed) or 0
            //Remove the front 4 bits;
            WORD address = data << 4;
            address = address >> 4;
            printf("Item %d: The RVA is %x, the attribute value is %d\n", j + 1, address, flag);

        }
        ptemp1ImageBaseRelocation = ptemp2ImageBaseRelocation;
    }
}
