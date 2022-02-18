#include "windows.h"

BOOL SetIATHook(DWORD dwOldAddr, DWORD dwNewAddr);

BOOL UnsetIATHook(DWORD dwOldAddr);