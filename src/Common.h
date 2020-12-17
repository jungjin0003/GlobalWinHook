#pragma once
#ifndef __COMMON_H__
#define __COMMON_H__

#include <winternl.h>

typedef void*(__cdecl *MEMCPY)(void *, const void *, size_t);
typedef NTSTATUS(NTAPI *NTCREATEUSERPROCESS)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS, void *, void *);
typedef HANDLE(WINAPI *OPENPROCESS)(DWORD, BOOL, DWORD);
typedef BOOL(WINAPI *VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef LPVOID(WINAPI *VIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI *WRITEPROCESSMEMORY)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);
typedef HANDLE(WINAPI *CREATEREMOTETHREAD)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD(WINAPI *WAITFORSINGLEOBJECT)(HANDLE, DWORD);
typedef HMODULE(WINAPI *LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);

#ifdef _WIN64
    typedef BOOL(WINAPI *ISWOW64PROCESS)(HANDLE, PBOOL);
    #define ASM_ARRAY_JMP_INDEX 2
    typedef ULONGLONG Address;
    extern const BYTE JmpInstruction[12];
    extern const BYTE NtCreateUserProcess[24];
#else
    #define ASM_ARRAY_JMP_INDEX 1
    typedef ULONG Address;
    extern const BYTE JmpInstruction[7];
    extern const BYTE NtCreateUserProcess[15];
#endif

typedef struct _Function_Pointer_List
{
    MEMCPY Pmemcpy;
    NTCREATEUSERPROCESS PNtCreateUserProcess;
    OPENPROCESS POpenProcess;
    VIRTUALPROTECT PVirtualProtect;
    VIRTUALALLOCEX PVirtualAllocEx;
    WRITEPROCESSMEMORY PWriteProcessMemory;
    CREATEREMOTETHREAD PCreateRemoteThread;
    WAITFORSINGLEOBJECT PWaitForSingleObject;
    LOADLIBRARYA PLoadLibraryA;
    GETPROCADDRESS PGetProcAddress;
#ifdef _WIN64
    ISWOW64PROCESS PIsWow64Process;
#endif
} Function_Pointer_List, *PFunction_Pointer_List;

typedef struct _WINAPI_GLOBAL_HOOK_DATAA
{
    PVOID lpNewFunction;
    PVOID lpNewFunctionEx;
    PVOID lpNewNtCreateUserProcess;
    PVOID lpNewNtCreateUserProcessEx;
    PVOID lpHooking;
    PVOID lpHookingEx;
    PVOID lpParameter;
    PVOID lpParameterEx;
    PVOID lpCopyBaseOfCode;

    DWORD dwSizeNewFunction;
    DWORD dwSizeNewNtCreateUserProcess;
    DWORD dwSizeHooking;
    DWORD dwSizeParameter;
    DWORD dwSizeDll;
    DWORD CopyOrigin_Parameter_Offset;
    DWORD NewFuncton_Struct_Offset;
    DWORD NtCreateUserProcess_Struct_Offset;
    DWORD Origin_Function_Offset;

    BOOL Parameter;

    BYTE JmpInstruction[sizeof(JmpInstruction)];
    BYTE NtCreateUserProcess[sizeof(NtCreateUserProcess)];

    DWORD GetProcAddress_Offset;
    Function_Pointer_List FPL;

    char DllName[MAX_PATH];
    char DefaultDll[2][16];
#ifdef _WIN64
    char Function_Name_List[10][24];
#else
    char Function_Name_List[9][24];
#endif
} WINAPI_GLOBAL_HOOK_DATAA, *PWINAPI_GLOBAL_HOOK_DATAA;

void Info(char* Message, ...);
void Success(char* Message, ...);
void Fail(char* Message, ...);

#endif