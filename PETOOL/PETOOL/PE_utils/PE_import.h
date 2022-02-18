//
// Created by MS08-067 on 2020/8/9.
//

#pragma once



#include "Windows.h"
#include "PE_tools.h"

VOID PrintImport();
LPSTR GetImport(LPSTR filePath);
VOID ProcessThunk(PIMAGE_IMPORT_BY_NAME thunk);