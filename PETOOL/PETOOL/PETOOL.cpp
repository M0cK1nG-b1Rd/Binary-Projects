// Demo3.cpp : 定义应用程序的入口点。
//

#include "stdafx.h"
#include "PETOOL.h"
#include "utils.h"

#define EXPORT_DETAIL 0
#define IMPORT_DETAIL 1
#define RESOURCE_DETAIL 2
#define RELOCATION_DETAIL 3

HINSTANCE hAppInstance;
TCHAR szFileName[256];
int detailDirNum;

LPVOID pFileBuffer = NULL;
PIMAGE_DOS_HEADER pDosHeader = NULL;
PIMAGE_NT_HEADERS pNTHeader = NULL;
PIMAGE_FILE_HEADER pFileHeader = NULL;
PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;


BOOL CALLBACK MainDialogProc(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
	)
{

	OPENFILENAME stopenFile;
	switch(uMsg)
	{
	case  WM_INITDIALOG :
		{
			InitProcessListView(hwndDlg);
			InitProcessModuleView(hwndDlg);
			return TRUE ;
		}

	case  WM_COMMAND :
		{
			switch (LOWORD (wParam))
			{
			case   IDC_BUTTON_QUIT :
				EndDialog(hwndDlg, 0);
				return TRUE;
			case   IDC_BUTTON_PEVIEW :
				TCHAR szPeFileExt[100] = _T("PE 文件(*.exe;*.dll;*.scr;*.drv;*.sys)\0*.exe;*.dll;*.scr;*.drv;*.sys\0All Files(*.*)\0*.*\0\0");

				memset(szFileName,0,256);
				memset(&stopenFile, 0,sizeof (OPENFILENAME));
				stopenFile.lStructSize = sizeof(OPENFILENAME);
				stopenFile.Flags = OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
				stopenFile.hwndOwner = hwndDlg;
				stopenFile.lpstrFilter = szPeFileExt;
				stopenFile.lpstrFile = szFileName;
				stopenFile.nMaxFile =MAX_PATH;
				GetOpenFileName (&stopenFile);
				//打开新的对话框
				if (szFileName != NULL)
				{
					DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_PEVIEW),hwndDlg,PeViewDialogProc);
				}

				return TRUE;
			}
			return FALSE ;
		}

	case WM_NOTIFY:
		{
			NMHDR* pNMHDR = (NMHDR*) lParam;
			if(wParam == IDC_LIST_PROCESS && pNMHDR->code == NM_CLICK){
				EnumModule(hwndDlg,wParam,lParam);
				return TRUE;
			}
			return FALSE;
		}

	case WM_CLOSE:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
		return FALSE ;
	}


	return FALSE;


}

BOOL CALLBACK PeViewDialogProc(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
	)
{
	switch(uMsg)
	{
	case  WM_INITDIALOG :
		{
			InitPeView(hwndDlg);
			return TRUE ;
		}

	case  WM_COMMAND :
		{
			switch (LOWORD (wParam))
			{
			case   IDC_BUTTON_PEVIEW_CLOSE :
				EndDialog(hwndDlg, 0);
				return TRUE;
			case   IDC_BUTTON_PEVIEW_SECTION :
				DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_SECTION),hwndDlg,SectionDialogProc);
				return TRUE;
			case   IDC_BUTTON_PEVIEW_DIR :
				DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_DIR),hwndDlg,DirDialogProc);
				return TRUE;
			}
			return FALSE ;
		}

	case WM_CLOSE:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
		return FALSE ;
	}


	return FALSE;
}

BOOL CALLBACK SectionDialogProc(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
	)
{
	switch(uMsg)
	{
	case  WM_INITDIALOG :
		{
			InitSectionView(hwndDlg);
			return TRUE ;
		}

	case WM_CLOSE:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
	}
	return FALSE;
}

BOOL CALLBACK DirDialogProc(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
	)
{
	switch(uMsg)
	{
	case  WM_INITDIALOG :
		{
			InitDirectoryView(hwndDlg);
			return TRUE ;
		}
	case  WM_COMMAND :
		{
			switch (LOWORD (wParam))
			{
			case   IDC_BUTTON_DIR_CLOSE :
				{
					EndDialog(hwndDlg, 0);
					return TRUE;
				}
			case   IDC_BUTTON_DIR_IMPORT :
				{
					detailDirNum = IMPORT_DETAIL;
					DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_DETAIL),hwndDlg,DirDetailDialogProc);
					return TRUE;
				}
			case   IDC_BUTTON_DIR_EXPORT :
				{
					detailDirNum = EXPORT_DETAIL;
					DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_DETAIL),hwndDlg,DirDetailDialogProc);
					return TRUE;
				}
			case   IDC_BUTTON_DIR_RESOURCE :
				{
					detailDirNum = RESOURCE_DETAIL;
					DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_DETAIL),hwndDlg,DirDetailDialogProc);
					return TRUE;
				}
			case   IDC_BUTTON_DIR_RELOC :
				{
					detailDirNum = RELOCATION_DETAIL;
					DialogBox(hAppInstance, MAKEINTRESOURCE(IDD_DIALOG_DETAIL),hwndDlg,DirDetailDialogProc);
					return TRUE;
				}

			}
			return FALSE;
		}
	case WM_CLOSE:
		{
			EndDialog(hwndDlg, 0);
			return TRUE;
		}
	}
	return FALSE;
}

BOOL CALLBACK DirDetailDialogProc(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
	)
{
		switch(uMsg)
		{
		case  WM_INITDIALOG :
			{
				switch(detailDirNum)
				{

				case IMPORT_DETAIL:
					{
						LPSTR detail = GetImport(szFileName);
						SetDlgItemText(hwndDlg,IDC_EDIT_DETAIL, detail);
						return TRUE ;
					}
				case EXPORT_DETAIL:
					{
						LPSTR detail = GetExport(szFileName);
						SetDlgItemText(hwndDlg,IDC_EDIT_DETAIL, detail);
						return TRUE ;
					}
				case RESOURCE_DETAIL:
					{
						LPSTR detail = GetImport(szFileName);
						SetDlgItemText(hwndDlg,IDC_EDIT_DETAIL, detail);
						return TRUE ;
					}
				case RELOCATION_DETAIL:
					{
						LPSTR detail = GetImport(szFileName);
						SetDlgItemText(hwndDlg,IDC_EDIT_DETAIL, detail);
						return TRUE ;
					}

				}

			}

		case WM_CLOSE:
			{
				EndDialog(hwndDlg, 0);
				return TRUE;
			}
		}
		return FALSE;
}

VOID EnumModule(HWND hDlg, WPARAM wParam, LPARAM lParam){
	HWND hListProcess = GetDlgItem(hDlg,IDC_LIST_PROCESS);
	DWORD dwRowId;
	TCHAR szPid[0x20];
	LV_ITEM lv;

	// 初始化
	memset(szPid, 0 ,0x20);
	memset(&lv,0,1);
	// 获取选择行
	dwRowId = SendMessage(hListProcess, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	if (dwRowId == -1)
	{
		MessageBox(NULL, _T("请选择进程"), _T("出错啦"), MB_OK);
		return ;
	}
	// 获取PID
	lv.iSubItem = 0;
	lv.pszText = szPid;
	lv.cchTextMax = 0x20;
	SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&lv);


	// 根据PID调用API获取进程模块
	HWND hListModule = GetDlgItem(hDlg,IDC_LIST_MODULE);
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	LPSTR rowData[2] = {0};
	LPSTR delim;
	LPSTR moduleName;

	// Get a handle to the process.
	DWORD processID = atoi(szPid);
	SetProcessPrivilege("SeDebugPrivilege", 1);
	hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID );
	if (NULL == hProcess)
		MessageBox(NULL, _T("无法获取进程模块信息！"), _T("出错啦"), MB_OK);

	// Get a list of all the modules in this process.

	if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.

			if ( GetModuleFileNameEx( hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				delim = _T("\\");
				moduleName = CutAndGetLast(szModName , delim);
				rowData[0] = moduleName;


				rowData[1] = szModName;
				InsertRow(hListModule, rowData);
			}
		}
	}

	// Release the handle to the process.
	SetProcessPrivilege("SeDebugPrivilege", 1);
	CloseHandle( hProcess );
}

VOID InitProcessListView(HWND hDlg){
	//1、初始化列名信息：
	LV_COLUMN lv;
	HWND hListProcess;

	//初始化
	memset(&lv,0,sizeof(LV_COLUMN));
	//获取IDC_LIST_PROCESS句柄
	hListProcess = GetDlgItem(hDlg,IDC_LIST_PROCESS);
	//设置整行选中
	SendMessage(hListProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);

	//第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = _T("PID");//列标题
	lv.cx = 50;
	lv.iSubItem = 0;
	ListView_InsertColumn(hListProcess, 0, &lv);
	//第二列
	lv.pszText = _T("进程名");
	lv.cx = 100;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListProcess, 1, &lv);
	//第三列
	lv.pszText = _T("进程地址");
	lv.cx = 100;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListProcess, 2, &lv);
	//第四列
	lv.pszText = _T("镜像基址");
	lv.cx = 100;
	lv.iSubItem = 3;
	ListView_InsertColumn(hListProcess, 3, &lv);
	//第五列
	lv.pszText = _T("镜像大小");
	lv.cx = 100;
	lv.iSubItem = 4;
	ListView_InsertColumn(hListProcess, 4, &lv);



	// 调用API获取所有的进程信息
	DWORD procPid[1024], retnBytes, procCount, retnBytes2;
	unsigned int i;
	HMODULE hMod[1024];
	HANDLE hProcess;
	TCHAR szModAbsPath[MAX_PATH];

	// 构造ListView使用的变量
	LPSTR processData[5] = {0};
	LPSTR moduleName; 
	TCHAR processId[100]; 
	TCHAR imageBase[100]; 
	TCHAR sizeOfImage[100]; 
	LPSTR delim;

	if (EnumProcesses(procPid, sizeof(procPid), &retnBytes))
	{
		procCount = retnBytes / sizeof(DWORD);
		SetProcessPrivilege("SeDebugPrivilege", 1);
		for (i = 0; i < procCount; i++)
		{
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procPid[i]);
			if (hProcess != NULL)
			{
				EnumProcessModules(hProcess, hMod, sizeof(hMod), &retnBytes2);
				GetModuleFileNameEx(hProcess, hMod[0], szModAbsPath, sizeof(szModAbsPath));

				if (strstr(szModAbsPath, _T("\\SystemRoot")) != NULL)
				{
					char* szModNameTemp = strrep(szModAbsPath,_T("\\SystemRoot"),_T("C:\\Windows"));
					strcpy(szModAbsPath, szModNameTemp);
				}

				// 打开文件，获取可选PE头
				ReadPEFile(szModAbsPath, &pFileBuffer);
				pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;
				pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHeader->e_lfanew);
				pFileHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);
				pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pFileHeader + IMAGE_SIZEOF_FILE_HEADER);


				// 插入信息到ListView中
				sprintf(processId, _T("%d"), procPid[i]);
				processData[0] = processId;

				delim = _T("\\");
				moduleName = CutAndGetLast(szModAbsPath, delim);
				processData[1] = moduleName;

				processData[2] = szModAbsPath;

				sprintf(imageBase, _T("0x%08X"),  pOptionHeader->ImageBase);
				processData[3] =imageBase;

				sprintf(sizeOfImage, _T("0x%08X"), pOptionHeader->SizeOfImage);
				processData[4] = sizeOfImage;

				InsertRow(hListProcess, processData);
				//printf("PID=%d Path=%s\n", procPid[i], szModName);

				free(pFileBuffer);
			}
			CloseHandle(hProcess);
		}
		SetProcessPrivilege("SeDebugPrivilege", 0);
	}



}


VOID InitProcessModuleView(HWND hDlg){
	//1、初始化列名信息：
	LV_COLUMN lv;
	HWND hModuleProcess;

	//初始化
	memset(&lv,0,sizeof(LV_COLUMN));
	//获取IDC_LIST_MODULE句柄
	hModuleProcess = GetDlgItem(hDlg,IDC_LIST_MODULE);
	//设置整行选中
	SendMessage(hModuleProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);

	//第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = _T("模块名称");//列标题
	lv.cx = 150;
	lv.iSubItem = 0;
	//ListView_InsertColumn(hListProcess, 0, &lv);
	SendMessage(hModuleProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//第二列
	lv.pszText = _T("模块位置");
	lv.cx = 200;
	lv.iSubItem = 1;
	// 两个函数是一样的，ListView_InsertColumn是一个宏
	//ListView_InsertColumn(hListProcess, 1, &lv);
	SendMessage(hModuleProcess,LVM_INSERTCOLUMN,1,(DWORD)&lv);
}


VOID InitPeView(HWND hwndDlg)
{
	ReadPEFile(szFileName, &pFileBuffer);
	pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pFileHeader + IMAGE_SIZEOF_FILE_HEADER);

	TCHAR strBuffer[0x20];

	sprintf(strBuffer, _T("0x%08X"), pOptionHeader->AddressOfEntryPoint);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_ENTRYPOINT, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), pOptionHeader->ImageBase);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_IMAGEBASE,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), pOptionHeader->SizeOfImage);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_IMAGESIZE,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), pOptionHeader->BaseOfCode);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_CODEBASE,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), pOptionHeader->SectionAlignment);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_MEMALIGN,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), pOptionHeader->BaseOfData);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_DATABASE,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), pOptionHeader->FileAlignment);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_FILEALIGN,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), pOptionHeader->LoaderFlags);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_FLAGS,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("%d"), pOptionHeader->Subsystem);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_SUBSYSTEM,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("%d"), pFileHeader->NumberOfSections);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_NUMOFSECTION,strBuffer);

	sprintf(strBuffer, _T("%d"), pFileHeader->TimeDateStamp);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_TIMESTAMP,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), pOptionHeader->SizeOfHeaders);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_PEHEADERSIZE,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), pOptionHeader->CheckSum);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_CHECKSUM,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), pFileHeader->Characteristics);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_CHARACTERISTIC,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), pFileHeader->SizeOfOptionalHeader);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_OPTIONALPEHEADER,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("%d"), pOptionHeader->NumberOfRvaAndSizes);
	SetDlgItemText(hwndDlg,IDC_EDIT_PEVIEW_NUMOFDIR,strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	free(pFileBuffer);
}

VOID InitSectionView(HWND hwndDlg)
{
	//1、初始化列名信息：
	LV_COLUMN lv;
	HWND hListSection;

	//初始化
	memset(&lv,0,sizeof(LV_COLUMN));
	//获取IDC_LIST_PROCESS句柄
	hListSection = GetDlgItem(hwndDlg,IDC_LIST_SECTION);
	//设置整行选中
	SendMessage(hListSection,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);

	//第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = _T("节名");//列标题
	lv.cx = 50;
	lv.iSubItem = 0;
	ListView_InsertColumn(hListSection, 0, &lv);
	//第二列
	lv.pszText = _T("文件偏移");
	lv.cx = 100;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListSection, 1, &lv);
	//第三列
	lv.pszText = _T("文件大小");
	lv.cx = 100;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListSection, 2, &lv);
	//第四列
	lv.pszText = _T("内存偏移");
	lv.cx = 100;
	lv.iSubItem = 3;
	ListView_InsertColumn(hListSection, 3, &lv);
	//第五列
	lv.pszText = _T("内存大小");
	lv.cx = 100;
	lv.iSubItem = 4;
	ListView_InsertColumn(hListSection, 4, &lv);
	//第六列
	lv.pszText = _T("节区属性");
	lv.cx = 100;
	lv.iSubItem = 4;
	ListView_InsertColumn(hListSection, 5, &lv);



	ReadPEFile(szFileName, &pFileBuffer);
	pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);

	LPSTR sectionData[6] = {0};
	TCHAR name[0x40];
	TCHAR virtualAddress[0x40];
	TCHAR sizeOfRawData[0x40];
	TCHAR pointerToRawData[0x40];
	TCHAR virtualSize[0x40];
	TCHAR characteristics[0x40];

	for (int i = 0; i < pFileHeader->NumberOfSections; i++) {
		sprintf(name, _T("%s"), pSectionHeader[i].Name);
		sectionData[0] = name;

		sprintf(virtualAddress, _T("0x%X"), pSectionHeader[i].VirtualAddress);
		sectionData[1] = virtualAddress;

		sprintf(sizeOfRawData, _T("0x%X"), pSectionHeader[i].SizeOfRawData);
		sectionData[2] = sizeOfRawData;

		sprintf(pointerToRawData, _T("0x%X"), pSectionHeader[i].PointerToRawData);
		sectionData[3] = pointerToRawData;

		sprintf(virtualSize, _T("0x%X"), pSectionHeader[i].Misc.VirtualSize);
		sectionData[4] = virtualSize;

		sprintf(characteristics, _T("0x%08X"), pSectionHeader[i].Characteristics);
		sectionData[5] = characteristics;

		InsertRow(hListSection,sectionData);
	}

	free(pFileBuffer);
}

VOID InitDirectoryView(HWND hwndDlg)
{
	ReadPEFile(szFileName, &pFileBuffer);
	pDosHeader = (PIMAGE_DOS_HEADER) pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) pFileBuffer + pDosHeader->e_lfanew);
	pFileHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32) ((DWORD) pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_DATA_DIRECTORY dirHeader = pOptionHeader->DataDirectory;

	TCHAR strBuffer[0x20];

	sprintf(strBuffer, _T("0x%08X"), dirHeader[0].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_EXPORT_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[1].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_IMPORT_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[2].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_RESOURCE_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[3].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_EXCEPTION_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[4].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_SEC_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[5].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_RELOC_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[6].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_DEBUG_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[7].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_COPYRIGHT_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[8].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_GPOINTER_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[9].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_TLS_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[10].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_IMPORTCONF_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[11].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_BINDIMPORT_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[12].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_IAT_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[13].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_POSTIMPORT_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[14].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_COM_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%08X"), dirHeader[15].VirtualAddress);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_RESERVE_RVA, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));
	//----------------------------------------------------------//
	sprintf(strBuffer, _T("0x%X"), dirHeader[0].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_EXPORT_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[1].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_IMPORT_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[2].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_RESOURCE_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[3].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_EXCEPTION_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[4].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_SEC_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[5].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_RELOC_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[6].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_DEBUG_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[7].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_COPYRIGHT_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[8].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_GPOINTER_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[9].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_TLS_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[10].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_IMPORTCONF_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[11].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_BINDIMPORT_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[12].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_IAT_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[13].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_POSTIMPORT_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[14].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_COM_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));

	sprintf(strBuffer, _T("0x%X"), dirHeader[15].Size);
	SetDlgItemText(hwndDlg,IDC_EDIT_DIR_RESERVE_SIZE, strBuffer);
	memset(strBuffer,0x20 ,sizeof(TCHAR));
}

int APIENTRY WinMain(HINSTANCE hInstance,
					 HINSTANCE hPrevInstance,
					 LPSTR     lpCmdLine,
					 int       nCmdShow)
{
	// 通用控件初始化
	INITCOMMONCONTROLSEX icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	// 可以只引入当前需要的通用控件，ICC_WIN95_CLASSES指示引入常用的通用控件
	icex.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&icex);


	hAppInstance = hInstance;
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG), NULL ,MainDialogProc);
}




