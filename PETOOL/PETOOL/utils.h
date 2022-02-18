#pragma once

VOID InsertColumn(HWND hList, LPSTR columnData[]);
VOID ModifyColumnLength(HWND hList, int columnLength[]);
VOID InsertRow(HWND hList, LPSTR rowData[]);
BOOL SetProcessPrivilege(char *lpName, BOOL opt);
char* strrep(char* s, char* oldW, char* newW);
BOOL GetProcAllModule(DWORD dwPID);
LPSTR CutAndGetLast(LPSTR str, LPSTR delim);