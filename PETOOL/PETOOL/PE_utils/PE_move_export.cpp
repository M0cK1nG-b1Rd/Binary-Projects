//
// Created by MS08-067 on 2020/8/6.
//

#include "PE_move_export.h"

VOID MoveExport(int section_index) {
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
    DWORD export_foa = (DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[0].VirtualAddress);

    memcpy((LPVOID) ((DWORD) pFileBuffer + (DWORD) (pSectionHeader + section_index)->PointerToRawData), (LPVOID) export_foa,
           sizeof(IMAGE_EXPORT_DIRECTORY));
    memset((LPVOID) export_foa, 0, sizeof(IMAGE_EXPORT_DIRECTORY));
    PIMAGE_EXPORT_DIRECTORY export_foa_new = (PIMAGE_EXPORT_DIRECTORY) ((DWORD) pFileBuffer +
                                                                        (DWORD) (pSectionHeader + section_index)->PointerToRawData);
    LPVOID next_address = (LPVOID) (((DWORD) pFileBuffer + (DWORD) (pSectionHeader + section_index)->PointerToRawData) +
                                    sizeof(IMAGE_EXPORT_DIRECTORY));

    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
            (LPVOID) ((DWORD) pFileBuffer + (DWORD) (pSectionHeader + 4)->PointerToRawData); //AFter move
    //Copy and fix three tables
    DWORD aof_foa = (DWORD) pFileBuffer + (DWORD) RVAtoFOA(pFileBuffer, pImageExportDirectory->AddressOfFunctions);
    memcpy(next_address, (LPVOID) aof_foa, 4 * pImageExportDirectory->NumberOfFunctions);
    DWORD aof_foa_new = (DWORD) next_address;
    export_foa_new->AddressOfFunctions = FOAtoRVA(pFileBuffer, (DWORD) next_address - (DWORD) pFileBuffer);
    next_address = (LPVOID) ((DWORD) next_address + 4 * pImageExportDirectory->NumberOfFunctions);
    DWORD aon_foa = (DWORD) pFileBuffer + (DWORD) RVAtoFOA(pFileBuffer, pImageExportDirectory->AddressOfNames);
    memcpy(next_address, (LPVOID) aon_foa, 4 * pImageExportDirectory->NumberOfNames);
    DWORD aon_foa_new = (DWORD) next_address;//For copy names
    export_foa_new->AddressOfNames = FOAtoRVA(pFileBuffer, (DWORD) next_address - (DWORD) pFileBuffer);
    next_address = (LPVOID) ((DWORD) next_address + 4 * pImageExportDirectory->NumberOfNames);
    DWORD aono_foa = (DWORD) pFileBuffer + (DWORD) RVAtoFOA(pFileBuffer, pImageExportDirectory->AddressOfNameOrdinals);
    memcpy(next_address, (LPVOID) aono_foa, 2 * pImageExportDirectory->NumberOfNames);
    DWORD aono_foa_new = (DWORD) next_address;
    export_foa_new->AddressOfNameOrdinals = FOAtoRVA(pFileBuffer, (DWORD) next_address - (DWORD) pFileBuffer);
    next_address = (LPVOID) ((DWORD) next_address + 2 * pImageExportDirectory->NumberOfNames);
    //Copy the name of functions
    PDWORD aon_foa_pointer = (PDWORD) aon_foa;
    PDWORD aon_foa_new_pointer = (PDWORD) aon_foa_new;
    char *func_name;
    for (int i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
        func_name = (char *) ((DWORD) pFileBuffer + *(PDWORD) (aon_foa_pointer + i));
        strcpy((char*)next_address, func_name);
        *(PDWORD) (aon_foa_new_pointer + i) = FOAtoRVA(pFileBuffer, (DWORD) next_address - (DWORD) pFileBuffer); // Fix the new AddressOfName table
        next_address = (LPVOID) ((DWORD) next_address + strlen(func_name) + 1); // /0 at end
    }
    // The number of sections after add is 5
    pOptionHeader->DataDirectory[0].VirtualAddress = (pSectionHeader + section_index)->VirtualAddress;

    //Save the file
    FILE *pf = fopen(FILEPATH_OUT, "wb+");
    if (pf == NULL) {
        printf("Unable to open file!");
    }
    fwrite(pFileBuffer, size, 1, pf);
    fclose(pf); //Always remember to close file.
}