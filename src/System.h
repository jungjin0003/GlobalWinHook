#pragma once
#ifndef __PROCESS_H__
#define __PROCESS_H__

#include "Common.h"

NTSTATUS NTAPI RtlGetLastNtStatus();
LPVOID GetProcessList();
void SystemProcessFilter(PSYSTEM_PROCESS_INFORMATION lpSPI);
LPVOID ProcessMemoryAlloc(PWINAPI_GLOBAL_HOOK_DATAA lpWinApi_Global_Hook_Data, HANDLE hProcess);
void AllocatedMemoryFree(PWINAPI_GLOBAL_HOOK_DATAA lpWinApi_Global_Hook_Data, HANDLE hProcess, LPVOID lpWinApi_Global_Hook_DataEx);
BOOL ProcessMemoryFree(PWINAPI_GLOBAL_HOOK_DATAA lpWinApi_Global_Hook_Data, HANDLE hProcess, LPVOID lpWinApi_Global_Hook_DataEx);
LPVOID ProcessBufferAlloc(HANDLE hProcess, SIZE_T dwSize);
WINBOOL ProcessBufferFree(HANDLE hProcess, LPVOID lpAddress);
WINBOOL WriteHookData(PWINAPI_GLOBAL_HOOK_DATAA lpWinApi_Global_Hook_Data, HANDLE hProcess, LPVOID lpWinApi_Global_Hook_DataEx);
DWORD __stdcall GetImageOfSizeA(char *username);

#endif