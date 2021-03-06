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
#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <psapi.h>
#include <commdlg.h>
#include <commctrl.h>			
#pragma comment(lib,"comctl32.lib")			


#include "PE_utils/PE_tools.h"
#include "PE_utils/PE_import.h"
#include "PE_utils/PE_export.h"
#include "PE_utils/PE_resource.h"
#include "PE_utils/PE_relocation.h"

// TODO: 在此处引用程序需要的其他头文件
