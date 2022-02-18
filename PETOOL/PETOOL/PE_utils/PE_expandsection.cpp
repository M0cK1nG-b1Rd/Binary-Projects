//
// Created by MS08-067 on 2020/8/5.
//

#include "PE_expandsection.h"




VOID ExpandSection() {
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
    LPVOID pImageBuffer = NULL;
    DWORD image_size = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
    if (!pImageBuffer || image_size == 0) {
        printf("Exception!");
    }
    LPVOID pNewImageBuffer = malloc(image_size + SIZE_EXPAND);
    if (!pNewImageBuffer) {
        printf("Unable to allocate memory!");
    }
    memcpy(pNewImageBuffer, pImageBuffer, image_size);
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) pNewImageBuffer;
    PIMAGE_NT_HEADERS pImageNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pNewImageBuffer + pImageDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pImagePEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pImageNTHeader) + 4);
    PIMAGE_OPTIONAL_HEADER pImageOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pImagePEHeader + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pImageOptionHeader + pImagePEHeader->SizeOfOptionalHeader);
    PIMAGE_SECTION_HEADER pLastImageSectionHeader = pImageSectionHeader + pImagePEHeader->NumberOfSections - 1;
    DWORD alignment = pImageOptionHeader->FileAlignment;
    DWORD to_align = pLastImageSectionHeader->Misc.VirtualSize > pLastImageSectionHeader->SizeOfRawData ? pLastImageSectionHeader->Misc.VirtualSize
                                                                                                        : pLastImageSectionHeader->SizeOfRawData;
    DWORD aligned = align(to_align, alignment);
    pLastImageSectionHeader->SizeOfRawData = pLastImageSectionHeader->Misc.VirtualSize = aligned + SIZE_EXPAND;
    pImageOptionHeader->SizeOfImage += SIZE_EXPAND;
    LPVOID pNewFileBuffer = NULL;
    DWORD size_save = CopyImageBufferToNewFileBuffer(pNewImageBuffer, &pNewFileBuffer);
    //Save the file
    FILE *pf = fopen(FILEPATH_OUT, "wb+");
    if (pf == NULL) {
        printf("Unable to open file!");
    }
    fwrite(pNewFileBuffer, size_save, 1, pf);
    fclose(pf); //Always remember to close file.
}