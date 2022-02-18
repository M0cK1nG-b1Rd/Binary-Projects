//
// Created by MS08-067 on 2020/8/9.
//

#include "PE_import.h"

VOID PrintImport() {
    LPVOID pFileBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    ReadPEFile(FILEPATH_IN, &pFileBuffer);
    pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    DWORD import_foa = (DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[1].VirtualAddress);
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) import_foa;
    //Traverse the data to find the num of blocks.
    // Check every byte in IMAGE_IMPORT_DESCRIPTOR
    int num = 0;
    boolean break_flag = FALSE;
    PIMAGE_IMPORT_DESCRIPTOR pTemp = pImportDescriptor;
    while (pTemp->Name != NULL) {
        num++;
        pTemp++;
    }
    //Traverse the data to process each block.
    pTemp = pImportDescriptor;

    for (int j = 0; j < num; j++) {
        char *dll_name = (char *) ((DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, (pTemp + j)->Name));
        printf("%s :\n", dll_name);
        printf("----------------------------\n");

        PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA) ((DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, (pTemp + j)->OriginalFirstThunk));

        PIMAGE_IMPORT_BY_NAME pImageImportByName = (PIMAGE_IMPORT_BY_NAME) ((DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, pThunkData->u1.Ordinal));
        while (TRUE) {
            if ((pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) // the highest bit is 0
            { // Fetch function name in each dll
                printf("%s\n", pImageImportByName->Name);
                pImageImportByName = (PIMAGE_IMPORT_BY_NAME) ((DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, pThunkData->u1.Ordinal));

            } else {//The highest bit is 1
                DWORD ordinal = ((pThunkData->u1.Ordinal << 1) >> 1);
                printf("Import by ordinal: %lx\n", ordinal);
            }
            pThunkData++;
            if (pThunkData->u1.Ordinal == 0) { break; }
        }
        printf("\n");
    }
}

LPSTR GetImport(LPSTR filePath) {
    LPVOID pFileBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    ReadPEFile(filePath, &pFileBuffer);
    pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    DWORD import_foa = (DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[1].VirtualAddress);
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) import_foa;
    //Traverse the data to find the num of blocks.
    // Check every byte in IMAGE_IMPORT_DESCRIPTOR
    int num = 0;
    boolean break_flag = FALSE;
    PIMAGE_IMPORT_DESCRIPTOR pTemp = pImportDescriptor;
    while (pTemp->Name != NULL) {
        num++;
        pTemp++;
    }
    //Traverse the data to process each block.
    pTemp = pImportDescriptor;

	TCHAR strBuffer[0x10000] = {0}; 

    for (int j = 0; j < num; j++) {
        TCHAR *dll_name = (TCHAR *) ((DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, (pTemp + j)->Name));
        sprintf(strBuffer + strlen(strBuffer) , "%s :\r\n", dll_name);
        sprintf(strBuffer + strlen(strBuffer) , "----------------------------\r\n");

        PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA) ((DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, (pTemp + j)->OriginalFirstThunk));

        PIMAGE_IMPORT_BY_NAME pImageImportByName = (PIMAGE_IMPORT_BY_NAME) ((DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, pThunkData->u1.Ordinal));
        while (TRUE) {
            if ((pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) // the highest bit is 0
            { // Fetch function name in each dll
                sprintf(strBuffer + strlen(strBuffer) , "%s\r\n", pImageImportByName->Name);
                pImageImportByName = (PIMAGE_IMPORT_BY_NAME) ((DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, pThunkData->u1.Ordinal));

            } else {//The highest bit is 1
                DWORD ordinal = ((pThunkData->u1.Ordinal << 1) >> 1);
                sprintf(strBuffer + strlen(strBuffer) , "Import by ordinal: %lx\r\n", ordinal);
            }
            pThunkData++;
            if (pThunkData->u1.Ordinal == 0) { break; }
        }
        sprintf(strBuffer + strlen(strBuffer) , "\r\n");
    }

	return strBuffer;
}

VOID ProcessThunk(PIMAGE_IMPORT_BY_NAME thunk) { //Thunk can be in IAT or INT

}
