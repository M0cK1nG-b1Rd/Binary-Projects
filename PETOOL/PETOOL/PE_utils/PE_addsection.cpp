//
// Created by MS08-067 on 2020/8/4.
//

#include "PE_addsection.h"


VOID addSection(DWORD size_of_new_section) {
    //Original buffer
    LPVOID pFileBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    size_t size = ReadPEFile(FILEPATH_IN, &pFileBuffer); //Notice that it's &pFileBuffer
    pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    pSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pOptionHeader + pPEHeader->SizeOfOptionalHeader);


    //New buffer
    LPVOID pNewFileBuffer = NULL;
    pNewFileBuffer = malloc(size + size_of_new_section);
    if (!pNewFileBuffer) {
        printf("Allocate dynamic memory for NewFileBuffer failed!\n");
        return;
    }
    memset(pNewFileBuffer, 0, size + size_of_new_section);
    memcpy(pNewFileBuffer, pFileBuffer, size);

    PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER) pNewFileBuffer;
    PIMAGE_NT_HEADERS pNewNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pNewFileBuffer + pNewDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pNewPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNewNTHeader) + 4);
    PIMAGE_OPTIONAL_HEADER32 pNewOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pNewPEHeader +
                                                                            IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pNewOptionHeader +
                                                                       pNewPEHeader->SizeOfOptionalHeader);

    //Check whether the section-header can be put in
    boolean flag_remain = TRUE;
    boolean flag_vacant = TRUE;
    //Check flag_remain
    DWORD remain_size =
            (DWORD) (pNewSectionHeader->VirtualAddress) - (DWORD) (pNewSectionHeader + pNewPEHeader->NumberOfSections);
    flag_remain = remain_size >= 0x28 * 2 ? TRUE : FALSE; //another 0x28 for zero padding
    //Check flag_vacant
    for (int i = 0; i < remain_size; i++) {
        PBYTE check = (PBYTE) ((DWORD) (pNewSectionHeader + pNewPEHeader->NumberOfSections - 1) + 0x28);
        if (*check != 0) {
            flag_vacant = FALSE;
            break;
        }
    }
    if (flag_remain && flag_vacant) {
        printf("Enough usable place for insertion! Inserting....");
    } else {
        printf("No place for insertion! Overwriting the stub area...");


        PBYTE pNewStub = (PBYTE) ((DWORD) pNewDosHeader + sizeof(IMAGE_DOS_HEADER)); //The size of dos-header is 0x40;
        DWORD size_to_copy = sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * pPEHeader->NumberOfSections;
        memcpy(pNewStub, pNewNTHeader, size_to_copy);
        pNewDosHeader->e_lfanew = 0x40;
        //Change several headers
        DWORD shift = (DWORD) (pNewNTHeader) - (DWORD) (pNewStub); // size to shift forward
        pNewNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pNewNTHeader - shift);
        pNewPEHeader = (PIMAGE_FILE_HEADER) ((DWORD) pNewPEHeader - shift);
        pNewOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pNewOptionHeader - shift);
        pNewSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pNewSectionHeader - shift);
    }


    PIMAGE_SECTION_HEADER new_header_addr = pNewSectionHeader + pNewPEHeader->NumberOfSections;
    //Copy .text section
    memcpy(new_header_addr, SECION_HEAD_DATA, 0x28); //The size of each section-header is 0x28
    memset((LPVOID) ((DWORD) new_header_addr + 0x28), 0, 0x28); //Zero padding for the size of 0x28
    pNewPEHeader->NumberOfSections += 1;
    pNewOptionHeader->SizeOfImage += size_of_new_section;

    PIMAGE_SECTION_HEADER old_last_section_header = new_header_addr - 1;
    new_header_addr->VirtualAddress = old_last_section_header->VirtualAddress +
                                      (old_last_section_header->Misc.VirtualSize > old_last_section_header->SizeOfRawData
                                       ? old_last_section_header->Misc.VirtualSize
                                       : old_last_section_header->SizeOfRawData);
    new_header_addr->Misc.VirtualSize = size_of_new_section;
    new_header_addr->PointerToRawData = old_last_section_header->PointerToRawData + old_last_section_header->SizeOfRawData;
    new_header_addr->SizeOfRawData = size_of_new_section;
    // Default
    //new_header_addr->Characteristics = 0x60000020;
    // Import-Inject
    new_header_addr->Characteristics = 0xC0000040;
    //Save the file
    FILE *pf = fopen(FILEPATH_OUT, "wb+");
    if (pf == NULL) {
        printf("Unable to open file!");
    }
    fwrite(pNewFileBuffer, size + size_of_new_section, 1, pf);
    fclose(pf); //Always remember to close file.
}

