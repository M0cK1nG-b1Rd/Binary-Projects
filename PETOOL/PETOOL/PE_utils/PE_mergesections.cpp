//
// Created by MS08-067 on 2020/8/5.
//

#include "PE_mergesections.h"



VOID MergeSection() {
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

    //New buffer
    LPVOID pImageBuffer = NULL;
    DWORD image_size = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
    if (!pImageBuffer || image_size == 0) {
        printf("Exception!");
    }
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) pImageBuffer;
    PIMAGE_NT_HEADERS pImageNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pImageBuffer + pImageDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pImagePEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pImageNTHeader) + 4);
    PIMAGE_OPTIONAL_HEADER32 pImageOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pImagePEHeader +
                                                                              IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pImageOptionHeader +
                                                                         pImagePEHeader->SizeOfOptionalHeader);
    PIMAGE_SECTION_HEADER pImageLastSectionHeader = pImageSectionHeader + pImagePEHeader->NumberOfSections - 1;

    DWORD size_sections = pImageLastSectionHeader->VirtualAddress + (pImageLastSectionHeader->Misc.VirtualSize > pImageLastSectionHeader->SizeOfRawData
                                                                     ? pImageLastSectionHeader->Misc.VirtualSize : pImageLastSectionHeader->SizeOfRawData) -
                          align(pImageOptionHeader->SizeOfHeaders, pImageOptionHeader->SectionAlignment);
    pImageSectionHeader->Misc.VirtualSize = pImageSectionHeader->SizeOfRawData = size_sections;
    for (int i = 0; i < pImagePEHeader->NumberOfSections; i++) {
        pImageSectionHeader->Characteristics |= (pImageSectionHeader + i)->Characteristics;
    }
    pImagePEHeader->NumberOfSections = 1;
    //Save the file
    LPVOID pNewFileBuffer = NULL;
    DWORD size_save = CopyImageBufferToNewFileBuffer(pImageBuffer, &pNewFileBuffer);
    //Save the file
    FILE *pf = fopen(FILEPATH_OUT, "wb+");
    if (pf == NULL) {
        printf("Unable to open file!");
    }
    fwrite(pNewFileBuffer, size_save, 1, pf);
    fclose(pf); //Always remember to close file.
}