// Demo3.cpp : ����Ӧ�ó������ڵ㡣
//
// Todo : �쳣������

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

�ر�˵����								
								
1��ʹ���ڴ�д��ķ�ʽ��ʵ��ģ������.								
								
2��IAT�����е�APIʹ��IAT Hookʵ��  ����IAT���ʹ��Inline Hookʵ��								
								
3������ص�API����д�뵽�ļ���								
								
4�����̼�ͨ�ŷ�ʽ�Լ�ѡ���д������								
								
5�����е�HOOK�ܹ�����ж�أ����ܵ��½����������.	

*/	


LPVOID g_lpAllocAddr = NULL;
LPVOID g_pImageBuffer = NULL;
LPTSTR g_szFilePath = "C:\\Users\\admin\\Documents\\visual studio 2012\\Projects\\injected_beacon\\Debug\\injected_beacon.exe";
HANDLE g_hInjectProcess;
DWORD g_dwOriginalImageBase;
DWORD g_dwImageSize;
DWORD g_dwOEP;
// ƫ����
DWORD dwDelta;

// ʹ�ù����ڴ淽ʽ�ͱ��ؽ��̽���ͨ��
HANDLE hMapObject;
HANDLE hMapView;


DWORD GetProcessPidByName(LPCTSTR lpszProcessName)//���ݽ��������ҽ���PID 
{
	DWORD dwPid = 0;
	HANDLE hSnapShot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		OutputDebugPrintf("\n��ý��̿���ʧ��,���ص�GetLastError():%d", ::GetLastError());
		return dwPid;
	}
 
	PROCESSENTRY32 pe32;//����������ڶ��� 
	pe32.dwSize = sizeof(PROCESSENTRY32);//��������ڶ����С 
	::Process32First(hSnapShot, &pe32);//���������б� 
	do
	{
		if (!lstrcmp(pe32.szExeFile, lpszProcessName))//����ָ����������PID 
		{
			dwPid = pe32.th32ProcessID;
			break;
		}
	} while (::Process32Next(hSnapShot, &pe32));
	::CloseHandle(hSnapShot);
	return dwPid;//���� 
}



BOOL WatchFunc(DWORD dwFuncName){
	switch (dwFuncName)
	{
	case MSGBOX:
		// ����ʱʹ��һ���ֽ�
		memset(hMapView, 0, sizeof(DWORD));
		memset(hMapView, WATCH_MSGBOX, 1);
		OutputDebugPrintf("����ָ�0x%X",WATCH_MSGBOX);
		break;
	case CREATEFILE:
		memset(hMapView, 0, sizeof(DWORD));
		memset(hMapView, WATCH_CREATEFILE, 1);
		OutputDebugPrintf("����ָ�0x%X",WATCH_CREATEFILE);
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
	//1����ȡBeacon�ڴ澵��Buffer
	LPVOID pFileBuffer;
	ReadPEFile(szFilePath,&pFileBuffer);
	CopyFileBufferToImageBuffer(pFileBuffer,pImageBuffer);
	return TRUE;
}



BOOL RepairReloc(){
	// 2�����ImageBase/SizeOfImage
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
		OutputDebugString("RepairIAT��ָ���Ľ���δ��������");
		return FALSE;
	}
	//4����Ҫע���A����			
	g_hInjectProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwPid);
	if (g_hInjectProcess == NULL)
	{
		OutputDebugString("RepairIAT�����̲����ڣ�");
		return FALSE;
	}

	//5����A�����������ڴ棬��С����SizeOfImage		
	g_lpAllocAddr = VirtualAllocEx(g_hInjectProcess, NULL, g_dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


	//6������B���ض�λ���޸�ֵ

	// ����g_lpAllocAddr��ֵ����ImageBase
	pOptionHeader->ImageBase =(DWORD)g_lpAllocAddr;


	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)g_pImageBuffer + pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	// ����delta

	dwDelta = (DWORD)g_lpAllocAddr - g_dwOriginalImageBase;//ʵ�ʵ�imageBase��ȥpe�ļ������ʶ��imagebase�õ����ƶ��ľ��롱
	//�ж��Ƿ����ض�λ��
	if ((char*)pReloc != (char*)g_pImageBuffer)
	{
		while ((pReloc->VirtualAddress + pReloc->SizeOfBlock) != 0) //��ʼɨ���ض�λ��
		{
			WORD* pLocData = (WORD*)((PBYTE)pReloc + sizeof(IMAGE_BASE_RELOCATION));
			//������Ҫ�������ض�λ���ַ������Ŀ
			int nNumberOfReloc = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			DWORD* pAddress;
			
			for (int i = 0; i < nNumberOfReloc; i++)
			{

				if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //����һ����Ҫ�����ĵ�ַ
				{
					pAddress = (DWORD*)((PBYTE)g_pImageBuffer + pReloc->VirtualAddress + (pLocData[i] & 0x0FFF));
					*pAddress += dwDelta;//���ƶ��ľ�����ԭ��ַ����ȥ
				}
			}

			//ת�Ƶ���һ���ڽ��д���
			pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
		}
	}
	return TRUE;
}

	

// �����RepairIAT��������write_memory��Ŀ��Entry������֮���Ժ�write_memory��Ŀ����������Ϊwrite_memory�Ǵ��ڴ��ж���ImageBuffer�ļ���
// ��ʱ����PELoader�Ĵ���IAT���Ѿ��������޸�����������Ǵ�CopyFileBufferToImageBuffer��õģ�IAT��û�о����޸���

// ������Ҫ�޸����Σ���һ���ȱ����޸����Ա��ҵ�GetProcAddress�ĺ�����ַ��
BOOL static WINAPI RepairIAT()
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)g_pImageBuffer;
	PIMAGE_NT_HEADERS pImageNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) g_pImageBuffer + pImageDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pImagePEHeader = (PIMAGE_FILE_HEADER) (((DWORD) pImageNTHeader) + 4);
	PIMAGE_OPTIONAL_HEADER pImageOptionHeader = (PIMAGE_OPTIONAL_HEADER) ((DWORD) pImagePEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// �޸�IAT��


	// ����ע���EXE�ĵ����͵�ǰ��ע���EXE�Ļ������޸�IAT��

	// ��������һЩ�Ķ���dwImageBase��ֵ��g_pImageBuffer������ԭ����ImageBase��ԭ����RepairRelocʱ�Ѿ��޸���ԭʼ��ImageBase��
	DWORD dwImageBase = (DWORD)g_pImageBuffer;
	LPVOID pImportDir = (LPVOID)(pImageOptionHeader->DataDirectory[1].VirtualAddress + dwImageBase);

	// ���������
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) pImportDir;
	//�������ݲ��ҵ� IMAGE_IMPORT_DESCRIPTOR ����Ŀ
	// ���ÿһ���ֽ�
	int num = 0;
	BOOL break_flag = FALSE;
	PIMAGE_IMPORT_DESCRIPTOR pTemp = pImportDescriptor;
	DWORD procAddress;
	while (pTemp->Name != NULL) {
		num++;
		pTemp++;
	}
	// ����������ÿһ��
	pTemp = pImportDescriptor;

	for (int j = 0; j < num; j++) {
		// DLL������
		char *dll_name = (char *) (dwImageBase + (pTemp + j)->Name);
		//printf("%s :\n", dll_name);
		//printf("----------------------------\n");

		// INT��
		PIMAGE_THUNK_DATA pThunkName = (PIMAGE_THUNK_DATA) (dwImageBase + (pTemp + j)->OriginalFirstThunk);
		// IAT��
		PIMAGE_THUNK_DATA pThunkProcAddress = (PIMAGE_THUNK_DATA) (dwImageBase + (pTemp + j)->FirstThunk);

		PIMAGE_IMPORT_BY_NAME pImageImportByName = (PIMAGE_IMPORT_BY_NAME) (dwImageBase + pThunkName->u1.Ordinal);
		// ��ȡ��DLL�ĺ��������������
		while (TRUE) {
			if ((pThunkName->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) // the highest bit is 0
			{ // ��ʱ�����Ƶ��뷽ʽ����Ҫ��ȡ����DLL�еĺ�����
				pImageImportByName = (PIMAGE_IMPORT_BY_NAME) (dwImageBase +  pThunkName->u1.Ordinal);
				//printf("%s\n", pImageImportByName->Name);	
				// �õ���ַ
				procAddress =  (DWORD)GetProcAddress(LoadLibrary(dll_name),pImageImportByName->Name);

				// �޸�
				pThunkProcAddress->u1.Ordinal = procAddress;
			} else {//The highest bit is 1
				// ��ʱ����ŵ��뷽ʽ����Ҫ��ȡ����DLL�е����
				DWORD dwOrdinal = ((pThunkName->u1.Ordinal << 1) >> 1);
				//printf("Import by ordinal: %lx\n", dwOrdinal);
				procAddress = (DWORD)GetProcAddress(LoadLibrary(dll_name),(LPCSTR)dwOrdinal);

				// �޸�
				pThunkProcAddress->u1.Ordinal = procAddress;
			}
			pThunkName++;
			pThunkProcAddress++;
			if (pThunkName->u1.Ordinal == 0) { break; }
		}
	}
	return TRUE;
}

// maybe�и��õķ���������Ŀǰ��ֻ�뵽��������
BOOL SetRemoteImageBuffer(){
	// 004120AE
	DWORD* pProcAddr = (DWORD*)((DWORD)g_pImageBuffer + 0x120AE + 3);
	*pProcAddr = (DWORD)g_lpAllocAddr;
	return TRUE;
}


BOOL InjectCode(){
	//7�����޸�������ݣ����Ƶ�A���ڴ���			
	BOOL bRet = WriteProcessMemory(g_hInjectProcess, g_lpAllocAddr, g_pImageBuffer, g_dwImageSize, NULL);
	if (!bRet){
		return FALSE;
	}
	// 0x12090 ��Entry��injected_beacon�е�ƫ��
	HANDLE hThread = CreateRemoteThread(g_hInjectProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD)g_lpAllocAddr + 0x12090), g_lpAllocAddr, 0, NULL);
	return TRUE;
}

BOOL InitCommunication(){
	//����FileMapping����
	hMapObject = CreateFileMapping((HANDLE)0xFFFFFFFF,NULL,PAGE_READWRITE,0,0x100,TEXT("shared"));
	if(!hMapObject)
	{
		OutputDebugString(TEXT("�����ڴ�ʧ�ܣ�"));
		return FALSE;
	}
	//��FileMapping����ӳ�䵽�Լ��Ľ���
	hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if(!hMapView)
	{
		OutputDebugString(TEXT("�ڴ�ӳ��ʧ�ܣ�"));
		return FALSE;
	}
	//�����ڴ�д���������
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
				OutputDebugPrintf("MakeBufferʧ����");
			}
			bRet = RepairReloc();
			if (!bRet){
				OutputDebugPrintf("RepairRelocʧ����");
			}
			bRet = RepairIAT();
			if (!bRet){
				OutputDebugPrintf("RepairIATʧ����");
			}
			bRet = SetRemoteImageBuffer();
			if (!bRet){
				OutputDebugPrintf("SetRemoteImageBufferʧ����");
			}
			bRet = InitCommunication();
			if (!bRet){
				OutputDebugPrintf("InitCommunicationʧ����");
			}
			bRet = InjectCode();
			if (!bRet){
				OutputDebugPrintf("InjectCodeʧ����");
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
				SetDlgItemText(hwndDlg,IDC_BUTTON_WATCH1,"�رռ��");
				return TRUE;
				// CreateFile
			case   IDC_BUTTON_WATCH2 :
				WatchFunc(CREATEFILE);
				SetDlgItemText(hwndDlg,IDC_BUTTON_WATCH2,"�رռ��");
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