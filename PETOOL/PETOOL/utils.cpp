#include "stdafx.h"
#include "utils.h"
#include "PETOOL.h"

VOID InsertRow(HWND hList, LPSTR rowData[]){
	//todo test
	HWND hWndHdr = (HWND)SendMessage(hList, LVM_GETHEADER, 0, 0);
	int count = (int)SendMessage(hWndHdr, HDM_GETITEMCOUNT, 0, 0L);

	int newRowId = (int)SendMessage(hList, LVM_GETITEMCOUNT, 0, 0L);

	LV_ITEM vitem;
	//初始化
	memset(&vitem,0,sizeof(LV_ITEM));
	vitem.mask = LVIF_TEXT;

	for (int i = 0; i < count; i++)
	{
		vitem.pszText = rowData[i];
		vitem.iItem = newRowId;
		vitem.iSubItem = i;

		if (i == 0)
		{
			ListView_InsertItem(hList, &vitem);
		}
		else
		{
			ListView_SetItem(hList, &vitem);
		}
		
	}
}


BOOL SetProcessPrivilege(char *lpName, BOOL opt)
{
    HANDLE tokenhandle;
    TOKEN_PRIVILEGES NewState;
 
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenhandle))
    {
        LookupPrivilegeValue(NULL, lpName, &NewState.Privileges[0].Luid);
        NewState.PrivilegeCount = 1;
        NewState.Privileges[0].Attributes = opt != 0 ? 2 : 0;
        AdjustTokenPrivileges(tokenhandle, FALSE, &NewState, sizeof(NewState), NULL, NULL);
        CloseHandle(tokenhandle);
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

char* strrep(char* s, char* oldW, char* newW)
{
    char* result;
    int i, cnt = 0;
    int newWlen = strlen(newW);
    int oldWlen = strlen(oldW);
  
    // Counting the number of times old word
    // occur in the string
    for (i = 0; s[i] != '\0'; i++) {
        if (strstr(&s[i], oldW) == &s[i]) {
            cnt++;
  
            // Jumping to index after the old word.
            i += oldWlen - 1;
        }
    }
  
    // Making new string of enough length
    result = (char*)malloc(i + cnt * (newWlen - oldWlen) + 1);
  
    i = 0;
    while (*s) {
        // compare the substring with the result
        if (strstr(s, oldW) == s) {
            strcpy(&result[i], newW);
            i += newWlen;
            s += oldWlen;
        }
        else
            result[i++] = *s++;
    }
  
    result[i] = '\0';
    return result;
}


// 字符串分割，取最后的结果
LPSTR CutAndGetLast(LPSTR str, LPSTR delim)
{
	// strtok 会改变原来的字符串，我们复制一份
	TCHAR strCopy[MAX_PATH];
	strcpy(strCopy,str);

	const int row = 100;
	const int cln = 100;
	TCHAR resultBuffer[cln] = {0};
	LPSTR catalog = (LPSTR)resultBuffer;

    LPSTR result = NULL;
    //char *strtok(char s[], const char *delim);
    result = strtok(strCopy, delim);
    char msg[row][cln];
    int i = 0;
    for(i = 0; result != NULL; i++)
    {
        strcpy(msg[i], result);
        result = strtok( NULL, delim );
    }
    catalog = msg[i - 1];
    //printf("catalog = %s\n", *catalog);
    return catalog;
}

