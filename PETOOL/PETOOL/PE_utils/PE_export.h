//
// Created by MS08-067 on 2020/8/6.
//

#pragma once



#include "Windows.h"
#include "PE_tools.h"

VOID PrintExport();
LPSTR GetExport(LPSTR filePath);
DWORD ValueToIndex(int value, PWORD initial_address, DWORD search);