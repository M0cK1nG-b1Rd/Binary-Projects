//
// Created by MS08-067 on 2020/8/4.
//

#ifndef PE_PRACTICE_PE_CONVERT_H
#define PE_PRACTICE_PE_CONVERT_H

#endif //PE_PRACTICE_PE_CONVERT_H

#include <stdio.h>
#include <windows.h>
#include "string.h"

#define IN
#define OUT


#define FILEPATH_IN "C:\\Users\\shinelon\\Desktop\\notepad.exe"
#define FILEPATH_OUT "C:\\Users\\shinelon\\Desktop\\notepad_new.exe"

//函数声明
//**************************************************************************
//ReadPEFile:将文件读取到缓冲区
//参数说明：
//lpszFile 文件路径
//pFileBuffer 缓冲区指针
//返回值说明：
//读取失败返回0  否则返回实际读取的大小
//**************************************************************************
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID *pFileBuffer);

//**************************************************************************
//CopyFileBufferToImageBuffer:将文件从FileBuffer复制到ImageBuffer
//参数说明：
//pFileBuffer  FileBuffer指针
//pImageBuffer ImageBuffer指针
//返回值说明：
//读取失败返回0  否则返回复制的大小
//**************************************************************************
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID *pImageBuffer);

//**************************************************************************
//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区
//参数说明：
//pImageBuffer ImageBuffer指针
//pNewBuffer NewBuffer指针
//返回值说明：
//读取失败返回0  否则返回复制的大小
//**************************************************************************
DWORD CopyImageBufferToNewFileBuffer(IN LPVOID pImageBuffer, OUT LPVOID *pNewBuffer);

//**************************************************************************
//MemeryTOFile:将内存中的数据复制到文件
//参数说明：
//pMemBuffer 内存中数据的指针
//size 要复制的大小
//lpszFile 要存储的文件路径
//返回值说明：
//读取失败返回0  否则返回复制的大小
//**************************************************************************
BOOL MemeryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile);

//**************************************************************************
//RVAtoFOA:将内存偏移转换为文件偏移
//参数说明：
//pFileBuffer FileBuffer指针
//dwRVA RVA的值
//返回值说明：
//返回转换后的FOA的值  如果失败返回0
//**************************************************************************
DWORD RVAtoFOA(IN LPVOID pFileBuffer, IN DWORD dwRVA);

//**************************************************************************
//读取文件的大小并返回
//**************************************************************************
int FileLength(FILE *fp);



DWORD FOAtoRVA(IN LPVOID pFileBuffer, IN DWORD dwFOA);

DWORD align(int input, int alignment);

VOID saveFile(LPVOID pFileBuffer,int size,char * file_path) ;