#pragma once
#ifndef __GLOBAL_WINHOOK_H__
#define __GLOBAL_WINHOOK_H__

#include "Common.h"

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define SetFunction(TYPE, DLL, FUNCTION) TYPE.lpOrigin = (Address)GetProcAddress(LoadLibraryA(#DLL), #FUNCTION)

typedef struct _WINAPI_BASIC_GLOBAL_HOOK_DATAA
{
    PVOID lpNewFunction;
    PVOID lpParameter;
    PVOID lpOrigin;

    DWORD dwSizeParameter;
    DWORD dwSizeNewFunction;
    DWORD CopyOrigin_Parameter_Offset;

    BOOL Parameter;
    char DllName[MAX_PATH];
} WINAPI_BASIC_GLOBAL_HOOK_DATAA, *PWINAPI_BASIC_GLOBAL_HOOK_DATAA;

BOOL HookTest(PWINAPI_BASIC_GLOBAL_HOOK_DATAA lpWinApi_Basic_Global_Hook_Data, DWORD PID);
BOOL HookA(PWINAPI_BASIC_GLOBAL_HOOK_DATAA lpWinApi_Basic_Global_Hook_Data);
BOOL SetHookStructA(PWINAPI_GLOBAL_HOOK_DATAA lpWinApi_Global_Hook_Data, PWINAPI_BASIC_GLOBAL_HOOK_DATAA lpWinApi_Basic_Global_Hook_Data);
Address AsmOverwriteOffset(LPVOID lpAddress);

#endif