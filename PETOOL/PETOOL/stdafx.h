// stdafx.h : ��׼ϵͳ�����ļ��İ����ļ���
// ���Ǿ���ʹ�õ��������ĵ�
// �ض�����Ŀ�İ����ļ�
//

#pragma once

#define WIN32_LEAN_AND_MEAN             //  �� Windows ͷ�ļ����ų�����ʹ�õ���Ϣ


// Windows ͷ�ļ�:
#include <windows.h>

// C ����ʱͷ�ļ�
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

// TODO: �ڴ˴����ó�����Ҫ������ͷ�ļ�
