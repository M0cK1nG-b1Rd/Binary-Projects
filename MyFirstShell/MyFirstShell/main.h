//
// Created by MS08-067 on 2022/1/16.
//

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <stdlib.h>

int FileLength(FILE *fp);
DWORD ReadPEFile(IN LPTSTR lpszFile, OUT LPVOID *pFileBuffer);
VOID AddSection(IN LPTSTR szShellFilePath, IN LPTSTR szDataFilePath, OUT LPTSTR szOutputFileName);
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID *pImageBuffer);
DWORD RVAtoFOA(IN LPVOID pFileBuffer, IN DWORD dwRVA);
DWORD align(int input, int alignment);

