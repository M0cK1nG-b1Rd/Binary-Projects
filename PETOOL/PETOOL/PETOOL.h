#pragma once

#include "resource.h"


VOID InitProcessListView(HWND hDlg);
VOID InitProcessModuleView(HWND hDlg);
VOID EnumModule(HWND hDlg, WPARAM wParam, LPARAM lParam);

BOOL CALLBACK DialogProc(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
	);

BOOL CALLBACK PeViewDialogProc(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
	);

BOOL CALLBACK SectionDialogProc(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
	);

BOOL CALLBACK DirDialogProc(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
	);

BOOL CALLBACK DirDetailDialogProc(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
	);

VOID InitPeView(HWND hwndDlg);
VOID InitSectionView(HWND hwndDlg);
VOID InitDirectoryView(HWND hwndDlg);