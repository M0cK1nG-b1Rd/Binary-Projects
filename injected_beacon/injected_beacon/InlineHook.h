#include "windows.h"
#include "stdio.h"

BOOL SetInlineHook(DWORD dwHookAddr, DWORD dwProcAddr, DWORD dwLength, PBYTE* pOldCode);

BOOL UnsetInlineHook(DWORD dwHookAddr, DWORD dwPatchAddr, DWORD dwLength);
