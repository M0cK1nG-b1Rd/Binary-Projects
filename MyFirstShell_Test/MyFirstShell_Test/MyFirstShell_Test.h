// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

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



// TODO: 在此处引用程序需要的其他头文件
