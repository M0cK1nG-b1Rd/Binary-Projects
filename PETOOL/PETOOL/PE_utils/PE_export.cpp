//
// Created by MS08-067 on 2020/8/6.
//

#include "PE_export.h"


VOID PrintExport() {
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
    DWORD export_foa = (DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[0].VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY) export_foa; // The real export dir
    //Convert the address
    DWORD aof_in_file =
            (DWORD) pFileBuffer + (DWORD) RVAtoFOA(pFileBuffer, pImageExportDirectory->AddressOfFunctions); //All of them are address
    DWORD aon_in_file = (DWORD) pFileBuffer + (DWORD) RVAtoFOA(pFileBuffer, pImageExportDirectory->AddressOfNames);
    DWORD aono_in_file = (DWORD) pFileBuffer + (DWORD) RVAtoFOA(pFileBuffer, pImageExportDirectory->AddressOfNameOrdinals);

    PDWORD begin_aof_foa = (PDWORD) aof_in_file;
    // Find the index
    PDWORD temp_aof_foa = begin_aof_foa;
    int aof_index;
    DWORD aono_index;
    DWORD address;
    DWORD num_of_func_by_name = (aono_in_file - aon_in_file) / 4;
    TCHAR *func_name;

    printf("------------------------------------------\n");
    printf("Ordinal\t\tRVA\t\tFunction Name\n");
    for (int i = 0; i < num_of_func_by_name; i++) {
        aof_index = i;
        address = *(PDWORD) temp_aof_foa++;
        aono_index = ValueToIndex(aof_index, (PWORD) aono_in_file, num_of_func_by_name);
        if (address != 0) {
            if (aono_index + pImageExportDirectory->Base >= pImageExportDirectory->Base) {
                // Then the aono_index is -1, no name for the function.
                PDWORD aon_pointer = (PDWORD) aon_in_file;
                func_name = (char *) (RVAtoFOA(pFileBuffer, *(aon_pointer + i)) + (DWORD) pFileBuffer);
                printf("%lu\t\t%lx\t\t%s\n", aof_index + pImageExportDirectory->Base, address, func_name);
            } else {
                printf("%lu\t\t%lx\t\t-\n", aof_index + pImageExportDirectory->Base, address);
            }
        }
    }
}

LPSTR GetExport(LPSTR filePath) {
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
    DWORD export_foa = (DWORD) pFileBuffer + RVAtoFOA(pFileBuffer, pOptionHeader->DataDirectory[0].VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY) export_foa; // The real export dir
    //Convert the address
    DWORD aof_in_file =
            (DWORD) pFileBuffer + (DWORD) RVAtoFOA(pFileBuffer, pImageExportDirectory->AddressOfFunctions); //All of them are address
    DWORD aon_in_file = (DWORD) pFileBuffer + (DWORD) RVAtoFOA(pFileBuffer, pImageExportDirectory->AddressOfNames);
    DWORD aono_in_file = (DWORD) pFileBuffer + (DWORD) RVAtoFOA(pFileBuffer, pImageExportDirectory->AddressOfNameOrdinals);

    PDWORD begin_aof_foa = (PDWORD) aof_in_file;
    // Find the index
    PDWORD temp_aof_foa = begin_aof_foa;
    int aof_index;
    DWORD aono_index;
    DWORD address;
    DWORD num_of_func_by_name = (aono_in_file - aon_in_file) / 4;
    TCHAR *func_name;

	TCHAR strBuffer[0x10000] = {0};

	sprintf(strBuffer , "------------------------------------------\r\n");
	sprintf(strBuffer + strlen(strBuffer) , "Ordinal\t\tRVA\t\tFunction Name\r\n");
	for (int i = 0; i < num_of_func_by_name; i++) {
		aof_index = i;
		address = *(PDWORD) temp_aof_foa++;
		aono_index = ValueToIndex(aof_index, (PWORD) aono_in_file, num_of_func_by_name);
		if (address != 0) {
			if (aono_index + pImageExportDirectory->Base >= pImageExportDirectory->Base) {
				// Then the aono_index is -1, no name for the function.
				PDWORD aon_pointer = (PDWORD) aon_in_file;
				func_name = (char *) (RVAtoFOA(pFileBuffer, *(aon_pointer + i)) + (DWORD) pFileBuffer);
				sprintf(strBuffer + strlen(strBuffer) , "%lu\t\t%lx\t\t%s\r\n", aof_index + pImageExportDirectory->Base, address, func_name);
			} else {
				sprintf(strBuffer + strlen(strBuffer) ,"%lu\t\t%lx\t\t-\r\n", aof_index + pImageExportDirectory->Base, address);
			}
		}
	}
	return strBuffer;
}



//Convert in the AddressOfNameOrdinals table
DWORD ValueToIndex(int value, PWORD initial_address, DWORD search) {
    for (int i = 0; i < search; i++) {
        if (value == *initial_address++) {
            return i;
        }
    }
    return -1;
}