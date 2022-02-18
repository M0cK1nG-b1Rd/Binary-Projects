// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

#define WIN32_LEAN_AND_MEAN             //  从 Windows 头文件中排除极少使用的信息
// Windows 头文件:
#include <windows.h>

// C 运行时头文件
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <stdio.h>
#include <tlhelp32.h>
// TODO: 在此处引用程序需要的其他头文件
#include "PE_tools.h"


#include <stdarg.h>
 
#define IS_USE_OUTPUT_DEBUG_PRINT   1
 
#if  IS_USE_OUTPUT_DEBUG_PRINT 
 
#define  OUTPUT_DEBUG_PRINTF(str)  OutputDebugPrintf(str)
void OutputDebugPrintf(const char * strOutputString, ...)
{
#define PUT_PUT_DEBUG_BUF_LEN   1024
	char strBuffer[PUT_PUT_DEBUG_BUF_LEN] = { 0 };
	va_list vlArgs;
	va_start(vlArgs, strOutputString);
	_vsnprintf_s (strBuffer, sizeof(strBuffer) - 1, strOutputString, vlArgs);  //_vsnprintf_s  _vsnprintf
	//vsprintf(strBuffer,strOutputString,vlArgs);
	va_end(vlArgs);
	OutputDebugStringA(strBuffer);  //OutputDebugString    // OutputDebugStringW
 
}
#else 
#define  OUTPUT_DEBUG_PRINTF(str) 
#endif