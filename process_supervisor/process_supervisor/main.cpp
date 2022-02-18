// Demo3.cpp : 定义应用程序的入口点。
//
// Todo : 异常处理函数

#include "main.h"
#include "process_supervisor.h"

#define EXIT_THREAD 0xFF
#define MSGBOX 0x01
#define CREATEFILE 0x02
#define OPENPROCESS 0x03

#define WATCH_MSGBOX 0x11
#define WATCH_CREATEFILE 0x12
#define WATCH_OPENPROCESS 0x13

#define CALL_MSGBOX 0x21
#define CALL_CREATEFILE 0x22
#define CALL_OPENPROCESS 0x23

/*

特别说明：								
								
1、使用内存写入的方式，实现模块隐藏.								
								
2、IAT表中有的API使用IAT Hook实现  不在IAT表的使用Inline Hook实现								
								
3、将监控的API参数写入到文件中								
								
4、进程间通信方式自己选择，有创新最好								
								
5、所有的HOOK能够正常卸载，不能导致进程意外结束.	

*/	


LPVOID g_lpAllocAddr = NULL;
LPVOID g_pImageBuffer = NULL;
LPTSTR g_szFilePath = "C:\\Users\\admin\\Documents\\visual studio 2012\\Projects\\injected_beacon\\Debug\\injected_beacon.exe";
HANDLE g_hInjectProcess;
DWORD g_dwOriginalImageBase;
DWORD g_dwImageSize;
DWORD g_dwOEP;
// 偏移量
DWORD dwDelta;

// 使用共享内存方式和被控进程进行通信
HANDLE hMapObject;
HANDLE hMapView;


DWORD GetProcessPidByName(LPCTSTR lpszProcessName)//根据进程名查找进程PID 
{
	DWORD dwPid = 0;
	HANDLE hSnapShot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		OutputDebugPrintf("\n获得进程快照失败,返回的GetLastError():%d", ::GetLastError());
		return dwPid;
	}
 
	PROCESSENTRY32 pe32;//声明进程入口对象 
	pe32.dwSize = sizeof(PROCESSENTRY32);//填充进程入口对象大小 
	::Process32First(hSnapShot, &pe32);//遍历进程列表 
	do
	{
		if (!lstrcmp(pe32.szExeFile, lpszProcessName))//查找指定进程名的PID 
		{
			dwPid = pe32.th32ProcessID;
			break;
		}
	} while (::Process32Next(hSnapShot, &pe32));
	::CloseHandle(hSnapShot);
	return dwPid;//返回 
}



BOOL WatchFunc(DWORD dwFuncName){
	switch (dwFuncName)
	{
	case MSGBOX:
		// 先暂时使用一个字节
		memset(hMapView, 0, sizeof(DWORD));
		memset(hMapView, WATCH_MSGBOX, 1);
		OutputDebugPrintf("发送指令：0x%X",WATCH_MSGBOX);
		break;
	case CREATEFILE:
		memset(hMapView, 0, sizeof(DWORD));
		memset(hMapView, WATCH_CREATEFILE, 1);
		OutputDebugPrintf("发送指令：0x%X",WATCH_CREATEFILE);
		break;
	case OPENPROCESS:
		memset(hMapView, WATCH_OPENPROCESS, 1);
		break;
	default:
		break;

	}
	return TRUE;
}


BOOL CallFunc(DWORD dwFuncName){
	switch (dwFuncName)
	{
	case MSGBOX:
		memset(hMapView, CALL_MSGBOX, 1);
		break;
	case CREATEFILE:
		memset(hMapView, CALL_CREATEFILE, 1);
		break;
	case OPENPROCESS:
		memset(hMapView, CALL_OPENPROCESS, 1);
		break;
	default:
		break;
	}
	return TRUE;
}

BOOL MakeBuffer(LPTSTR szFilePath, LPVOID* pImageBuffer){
	//1、获取Beacon内存镜像Buffer
	LPVOID pFileBuffer;
	ReadPEFile(szFilePath,&pFileBuffer);
	CopyFileBufferToImageBuffer(pFileBuffer,pImageBuffer);
	return TRUE;
}



BOOL RepairReloc(){
	// 2、获得ImageBase/SizeOfImage
	PIMAGE_DOS_HEADER pDosHeader  = (PIMAGE_DOS_HEADER)g_pImageBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD)g_pImageBuffer + pDosHeader->e_lfanew);;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pNTHeader) + 4);;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

	g_dwOriginalImageBase = pOptionHeader->ImageBase;
	g_dwImageSize = pOptionHeader->SizeOfImage;
	g_dwOEP = pOptionHeader->AddressOfEntryPoint;


	DWORD dwPid  = GetProcessPidByName("SimpleMessageBox.exe");
	if (dwPid == NULL)
	{
		OutputDebugString("RepairIAT：指定的进程未搜索到！");
		return FALSE;
	}
	//4、打开要注入的A进程			
	g_hInjectProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwPid);
	if (g_hInjectProcess == NULL)
	{
		OutputDebugString("RepairIAT：进程不存在！");
		return FALSE;
	}

	//5、在A进程中申请内存，大小就是SizeOfImage		
	g_lpAllocAddr = VirtualAllocEx(g_hInjectProcess, NULL, g_dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


	//6、根据B的重定位表修复值

	// 根据g_lpAllocAddr的值更改ImageBase
	pOptionHeader->ImageBase =(DWORD)g_lpAllocAddr;


	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)g_pImageBuffer + pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	// 计算delta

	dwDelta = (DWORD)g_lpAllocAddr - g_dwOriginalImageBase;//实际的imageBase减去pe文件里面标识的imagebase得到“移动的距离”
	//判断是否有重定位表
	if ((char*)pReloc != (char*)g_pImageBuffer)
	{
		while ((pReloc->VirtualAddress + pReloc->SizeOfBlock) != 0) //开始扫描重定位表
		{
			WORD* pLocData = (WORD*)((PBYTE)pReloc + sizeof(IMAGE_BASE_RELOCATION));
			//计算需要修正的重定位项（地址）的数目
			int nNumberOfReloc = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			DWORD* pAddress;
			
			for (int i = 0; i < nNumberOfReloc; i++)
			{

				if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //这是一个需要修正的地址
				{
					pAddress = (DWORD*)((PBYTE)g_pImageBuffer + pReloc->VirtualAddress + (pLocData[i] & 0x0FFF));
					*pAddress += dwDelta;//把移动的距离在原地址加上去
				}
			}

			//转移到下一个节进行处理
			pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
		}
	}
	return TRUE;
}

	

// 这里的RepairIAT函数就是write_memory项目的Entry函数，之所以和write_memory项目有区别是因为write_memory是从内存中读的ImageBuffer文件，
// 此时经过PELoader的处理IAT表已经经过了修复。我们这个是从CopyFileBufferToImageBuffer获得的，IAT表没有经过修复。

// 这里需要修复两次，第一次先本地修复，以便找到GetProcAddress的函数地址。
BOOL static WINAPI RepairIAT()
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)g_pImageBuffer;
	PIMAGE_NT_HEADERS pImageNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) g_pImageBuffer + pImageDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pImagePEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pImageNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER pImageOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pImagePEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 修复IAT表


	// 根据注入的EXE的导入表和当前被注入的EXE的环境，修复IAT表

	// 这里做了一些改动，dwImageBase的值是g_pImageBuffer而不是原本的ImageBase，原因是RepairReloc时已经修改了原始的ImageBase。
	DWORD dwImageBase = (DWORD)g_pImageBuffer;
	LPVOID pImportDir = (LPVOID)(pImageOptionHeader->DataDirectory[1].VirtualAddress + dwImageBase);

	// 解析导入表
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) pImportDir;
	//遍历数据并找到 IMAGE_IMPORT_DESCRIPTOR 的数目
	// 检查每一个字节
	int num = 0;
	BOOL break_flag = FALSE;
	PIMAGE_IMPORT_DESCRIPTOR pTemp = pImportDescriptor;
	DWORD procAddress;
	while (pTemp->Name != NULL) {
		num++;
		pTemp++;
	}
	// 遍历并处理每一块
	pTemp = pImportDescriptor;

	for (int j = 0; j < num; j++) {
		// DLL的名字
		char *dll_name = (char *) (dwImageBase + (pTemp + j)->Name);
		//printf("%s :\n", dll_name);
		//printf("----------------------------\n");

		// INT表
		PIMAGE_THUNK_DATA pThunkName = (PIMAGE_THUNK_DATA) (dwImageBase + (pTemp + j)->OriginalFirstThunk);
		// IAT表
		PIMAGE_THUNK_DATA pThunkProcAddress = (PIMAGE_THUNK_DATA) (dwImageBase + (pTemp + j)->FirstThunk);

		PIMAGE_IMPORT_BY_NAME pImageImportByName = (PIMAGE_IMPORT_BY_NAME) (dwImageBase + pThunkName->u1.Ordinal);
		// 获取该DLL的函数名或者序号名
		while (TRUE) {
			if ((pThunkName->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) // the highest bit is 0
			{ // 此时是名称导入方式，需要获取导入DLL中的函数名
				pImageImportByName = (PIMAGE_IMPORT_BY_NAME) (dwImageBase +  pThunkName->u1.Ordinal);
				//printf("%s\n", pImageImportByName->Name);	
				// 得到地址
				procAddress =  (DWORD)GetProcAddress(LoadLibrary(dll_name),pImageImportByName->Name);

				// 修复
				pThunkProcAddress->u1.Ordinal = procAddress;
			} else {//The highest bit is 1
				// 此时是序号导入方式，需要获取导入DLL中的序号
				DWORD dwOrdinal = ((pThunkName->u1.Ordinal << 1) >> 1);
				//printf("Import by ordinal: %lx\n", dwOrdinal);
				procAddress = (DWORD)GetProcAddress(LoadLibrary(dll_name),(LPCSTR)dwOrdinal);

				// 修复
				pThunkProcAddress->u1.Ordinal = procAddress;
			}
			pThunkName++;
			pThunkProcAddress++;
			if (pThunkName->u1.Ordinal == 0) { break; }
		}
	}
	return TRUE;
}

// maybe有更好的方法，但是目前我只想到这样。。
BOOL SetRemoteImageBuffer(){
	// 004120AE
	DWORD* pProcAddr = (DWORD*)((DWORD)g_pImageBuffer + 0x120AE + 3);
	*pProcAddr = (DWORD)g_lpAllocAddr;
	return TRUE;
}


BOOL InjectCode(){
	//7、将修复后的数据，复制到A的内存中			
	BOOL bRet = WriteProcessMemory(g_hInjectProcess, g_lpAllocAddr, g_pImageBuffer, g_dwImageSize, NULL);
	if (!bRet){
		return FALSE;
	}
	// 0x12090 是Entry在injected_beacon中的偏移
	HANDLE hThread = CreateRemoteThread(g_hInjectProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD)g_lpAllocAddr + 0x12090), g_lpAllocAddr, 0, NULL);
	return TRUE;
}

BOOL InitCommunication(){
	//创建FileMapping对象
	hMapObject = CreateFileMapping((HANDLE)0xFFFFFFFF,NULL,PAGE_READWRITE,0,0x100,TEXT("shared"));
	if(!hMapObject)
	{
		OutputDebugString(TEXT("共享内存失败！"));
		return FALSE;
	}
	//将FileMapping对象映射到自己的进程
	hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if(!hMapView)
	{
		OutputDebugString(TEXT("内存映射失败！"));
		return FALSE;
	}
	//向共享内存写入测试数据
	strcpy((char*)hMapView,"Communication Init Test");
	return TRUE;
}
	



BOOL CALLBACK MainDialogProc(
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
			BOOL bRet;
			bRet = MakeBuffer(g_szFilePath,&g_pImageBuffer);
			if (!bRet){
				OutputDebugPrintf("MakeBuffer失敗！");
			}
			bRet = RepairReloc();
			if (!bRet){
				OutputDebugPrintf("RepairReloc失敗！");
			}
			bRet = RepairIAT();
			if (!bRet){
				OutputDebugPrintf("RepairIAT失敗！");
			}
			bRet = SetRemoteImageBuffer();
			if (!bRet){
				OutputDebugPrintf("SetRemoteImageBuffer失敗！");
			}
			bRet = InitCommunication();
			if (!bRet){
				OutputDebugPrintf("InitCommunication失敗！");
			}
			bRet = InjectCode();
			if (!bRet){
				OutputDebugPrintf("InjectCode失敗！");
			}
			return TRUE ;
		}

	case  WM_COMMAND :
		{
			switch (LOWORD (wParam))
			{
				// MessageBox
			case   IDC_BUTTON_WATCH1 :
				WatchFunc(MSGBOX);
				SetDlgItemText(hwndDlg,IDC_BUTTON_WATCH1,"关闭监控");
				return TRUE;
				// CreateFile
			case   IDC_BUTTON_WATCH2 :
				WatchFunc(CREATEFILE);
				SetDlgItemText(hwndDlg,IDC_BUTTON_WATCH2,"关闭监控");
				return TRUE;
				// OpenProcess
			case   IDC_BUTTON_WATCH3:
				WatchFunc(OPENPROCESS);
				return TRUE;
			case   IDC_BUTTON_CALL1:
				CallFunc(MSGBOX);
				return TRUE;
			case   IDC_BUTTON_CALL2:
				CallFunc(CREATEFILE);
				return TRUE;
			case   IDC_BUTTON_CALL3:
				CallFunc(OPENPROCESS);
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

int APIENTRY WinMain(HINSTANCE hInstance,
					 HINSTANCE hPrevInstance,
					 LPSTR     lpCmdLine,
					 int       nCmdShow)
{
	HANDLE hAppInstance = hInstance;
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL ,MainDialogProc);
}