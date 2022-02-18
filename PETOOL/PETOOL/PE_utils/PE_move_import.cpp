//
// Created by MS08-067 on 2020/8/10.
//
//Insert into a new section

#include "PE_move_import.h"

VOID MoveImport() {
    //Original buffer
    LPVOID pFileBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    size_t size = ReadPEFile(FILEPATH_IN, &pFileBuffer);
    pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;
    pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    pSectionHeader = (PIMAGE_SECTION_HEADER) ((DWORD) pOptionHeader + pPEHeader->SizeOfOptionalHeader);
    DWORD import_foa = (DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[1].VirtualAddress);

    PIMAGE_IMPORT_DESCRIPTOR pimageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) import_foa; //FOA of the first import-descriptor;
    //Calculate the size
    //Traverse the data to find the num of blocks.
    int num = 0;
    boolean break_flag = FALSE;
    PIMAGE_IMPORT_DESCRIPTOR pTemp = pimageImportDescriptor;
    while (TRUE) {
        PBYTE pbyte = (PBYTE) pTemp;
        for (int i = 0; i < sizeof(IMAGE_IMPORT_DESCRIPTOR); i++) {
            if (*(pbyte + i) != 0) {
                num++;
                pTemp++;
                break;
            }
            if (*(pbyte + i) == 0 && i == sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1) {
                break_flag = TRUE;
            }
        }
        if (break_flag) {
            break;
        }
    }

    int total_size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * (num + 2);//One for the zero padding ,one for the new function
    total_size += 16;// The new IAT and INT table
    int dll_name_size = strlen(DLL_NAME) + 1;
    total_size += dll_name_size;
    int func_name_size = strlen(FUNCTION_NAME) + 3;
    total_size += func_name_size;


    //To do: when the VirtualSize is bigger than the SizeOfRawData
    int last_section_index=pPEHeader->NumberOfSections-1;
    int start = (pSectionHeader + last_section_index)->PointerToRawData;
    int end = (pSectionHeader + last_section_index)->PointerToRawData + (pSectionHeader + last_section_index)->SizeOfRawData;
    if ((end - start) > total_size) {
        pOptionHeader->DataDirectory[1].VirtualAddress = FOAtoRVA(pFileBuffer, start); // Fix the value in the data directory
        pTemp = (PIMAGE_IMPORT_DESCRIPTOR) (start + (DWORD) pFileBuffer);
        memcpy((LPVOID) pTemp, pimageImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR) * (num + 1)); // The initialize value is 0
        memset((LPVOID) (pTemp + num + 1), 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
        pTemp += num;//Set to the addr of the new import-descriptor
        //Set IAT table and INT table
        memset(pTemp + 2, 0, 8);
        PDWORD new_int = (PDWORD) (pTemp + 2);
        memset((LPVOID) ((DWORD) new_int + 8), 0, 8);
        PDWORD new_iat = (PDWORD) ((DWORD) new_int + 8);
        PIMAGE_IMPORT_BY_NAME pnewImageImportByName = (PIMAGE_IMPORT_BY_NAME) ((DWORD) new_iat + 8);
        strcpy((char *) ((DWORD) pnewImageImportByName + 2), FUNCTION_NAME); //Copy function name
        *new_int = *new_iat = FOAtoRVA(pFileBuffer, (DWORD) pnewImageImportByName - (DWORD) pFileBuffer);
        char *real_dllname_addr = (char *) ((DWORD) pnewImageImportByName + 2 + strlen(FUNCTION_NAME) + 1);
        strcpy(real_dllname_addr, DLL_NAME);
        pTemp->Name = FOAtoRVA(pFileBuffer, (DWORD) real_dllname_addr - (DWORD) pFileBuffer);
        pTemp->OriginalFirstThunk = FOAtoRVA(pFileBuffer, (DWORD) new_int - (DWORD) pFileBuffer);
        pTemp->FirstThunk = FOAtoRVA(pFileBuffer, (DWORD) new_iat - (DWORD) pFileBuffer);
        saveFile(pFileBuffer, size, FILEPATH_OUT);

    }


}