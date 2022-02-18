//
// Created by MS08-067 on 2022/1/1.
//

#include "PE_resource.h"

VOID PrintResource() {
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

    DWORD resource_foa = (DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[2].VirtualAddress);
    ParseResource(resource_foa, resource_foa, 1);
}

VOID ParseResource(DWORD resource_foa, DWORD layerBeginFoa, DWORD layerCounter){

    PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY) layerBeginFoa;
    int namedEntries = pImageResourceDirectory->NumberOfNamedEntries;
    int idEntries = pImageResourceDirectory->NumberOfIdEntries;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pImageResourceDirectoryEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (pImageResourceDirectory + 1);
    for (int i = 0; i < namedEntries + idEntries; ++i) {
        if (layerCounter == 1) {
            printf("---------------------------------\r\n");
        }
        printf("No.%d layer\r\n",layerCounter);
        // 处理Name
        if (pImageResourceDirectoryEntry[i].NameIsString) {
            // 按字符串方式处理该结构
            DWORD stringOffset =  pImageResourceDirectoryEntry[i].NameOffset;
            PIMAGE_RESOURCE_DIR_STRING_U dirString = (PIMAGE_RESOURCE_DIR_STRING_U) (layerBeginFoa + stringOffset);
            printf("Name: ");
            for (int j = 0; j < dirString->Length; ++j) {
                printf("%c",dirString->NameString[j]);
            }
            printf("\r\n");
        } else {
            // 按ID方式处理该结构
            printf("ID: %X",pImageResourceDirectoryEntry[i].NameOffset);
            printf("\r\n");
        }

        // 处理OffsetData
        DWORD directoryOffset = pImageResourceDirectoryEntry[i].OffsetToDirectory;
        if (pImageResourceDirectoryEntry[i].DataIsDirectory) {
            // 递归处理下一层的数据
            layerCounter ++ ;
            ParseResource(resource_foa, resource_foa + directoryOffset, layerCounter);
            layerCounter -- ;
        } else {
            PIMAGE_RESOURCE_DATA_ENTRY dataDirectory = (PIMAGE_RESOURCE_DATA_ENTRY) (resource_foa + directoryOffset);
            printf("RVA: %X\r\n", dataDirectory->OffsetToData);
            printf("Size: %X\r\n", dataDirectory->Size);
        }
    }

};