#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <ntdef.h>
#include <ntdsapi.h>
#include <psapi.h>
#include "Global_WinHook.h"
#include "HookFunction.h"
#include "System.h"
#include "Common.h"

#ifdef _WIN64
#define ASM_ARRAY_JMP_INDEX 2
typedef ULONGLONG Address;
const BYTE JmpInstruction[12] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
const BYTE NtCreateUserProcess[24] = {0x4C, 0x8B, 0xD1, 0xB8, 0xC8, 0x00, 0x00, 0x00, 0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, 0x75, 0x03, 0x0F, 0x05, 0xC3, 0xCD, 0x2E, 0xC3};
#else
#define ASM_ARRAY_JMP_INDEX 1
typedef ULONG Address;
const BYTE JmpInstruction[7] = {0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
const BYTE NtCreateUserProcess[15] = {0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD2, 0xC2, 0x2C, 0x00};
#endif

BOOL HookTest(PWINAPI_BASIC_GLOBAL_HOOK_DATAA lpWinApi_Basic_Global_Hook_Data, DWORD PID)
{
    WINAPI_GLOBAL_HOOK_DATAA WinApi_Global_Hook_Data = {0, };
    PSYSTEM_PROCESS_INFORMATION spi;

    if (SetHookStructA(&WinApi_Global_Hook_Data, lpWinApi_Basic_Global_Hook_Data) == FALSE)
    {
        Fail("Set Struct Data Failed!");
        return FALSE;
    }

    Info("Getting Process List...");
    spi = GetProcessList();

    if (spi == NULL)
    {
        Fail("Hooking Failed!");
        return FALSE;
    }

    Success("Get Process List Success!");

    Info("===============================");

    while (spi->NextEntryOffset)
    {
        if (spi->UniqueProcessId != PID)
        {
            spi = (Address)spi + spi->NextEntryOffset;
            continue;
        }
        LPVOID lpWinApi_Global_Hook_DataEx = NULL;
        WINAPI_GLOBAL_HOOK_DATAA temp = WinApi_Global_Hook_Data;
        HANDLE hProcess = NULL, hThread = NULL;
        Info("Start Hooking!");
        Info("Target Process : %S", spi->ImageName.Buffer);
        Info("Process ID : %d", spi->UniqueProcessId);
        Info("Getting Process Handle...");
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, spi->UniqueProcessId);
        if (hProcess == NULL)
        {
            Fail("Hooking Failed!");
            CloseHandle(hProcess);
            continue;
        }
        Success("Get process handle!");
        Info("Handle value is %p", hProcess);
        Info("Allocating memory in target process...");
        lpWinApi_Global_Hook_DataEx = ProcessMemoryAlloc(&temp, hProcess);
        if (lpWinApi_Global_Hook_DataEx == NULL)
        {
            Fail("Hooking Failed!");
            CloseHandle(hProcess);
            continue;
        }
        Success("Memory allocation success for target process");

        Info("Address is %p", temp.lpCopyBaseOfCode);
        Info("Address is %p", temp.lpNewFunctionEx);
        Info("Address is %p", temp.lpNewNtCreateUserProcessEx);
        Info("Address is %p", temp.lpHookingEx);
        Info("Address is %p", lpWinApi_Global_Hook_DataEx);

        if (temp.Parameter)
        {
            Info("Address is %p", temp.lpParameterEx);
        }

        Info("Writing Hook Data in Process Buffer...");
        if (WriteHookData(&temp, hProcess, lpWinApi_Global_Hook_DataEx) == FALSE)
        {
            Fail("Hooking Failed!");
            CloseHandle(hProcess);
            continue;
        }

        Success("Hook data write success!");

        Info("CreateRemoteThread Call...");
        hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)temp.lpHookingEx, lpWinApi_Global_Hook_DataEx, 0, NULL);

        if (hThread == NULL)
        {
            Fail("CreateRemoteThread Call Failed!");
            AllocatedMemoryFree(&temp, hProcess, lpWinApi_Global_Hook_DataEx);
            CloseHandle(hProcess);
            continue;
        }

        Success("Hooking Attempting...");
        WaitForSingleObject(hThread, INFINITE);
        Success("Hooking Success");
        spi = (Address)spi + spi->NextEntryOffset;
        break;
    }
}

BOOL HookA(PWINAPI_BASIC_GLOBAL_HOOK_DATAA lpWinApi_Basic_Global_Hook_Data)
{
    WINAPI_GLOBAL_HOOK_DATAA WinApi_Global_Hook_Data = {0, };
    PSYSTEM_PROCESS_INFORMATION spi;

    if (SetHookStructA(&WinApi_Global_Hook_Data, lpWinApi_Basic_Global_Hook_Data) == FALSE)
    {
        Fail("Set Struct Data Failed!");
        return FALSE;
    }

    Info("Getting Process List...");
    spi = GetProcessList();

    if (spi == NULL)
    {
        Fail("Hooking Failed!");
        return FALSE;
    }

    Success("Get Process List Success!");

    Info("===============================");

    while (TRUE)
    {
        spi = (Address)spi + spi->NextEntryOffset;
        LPVOID lpWinApi_Global_Hook_DataEx = NULL;
        WINAPI_GLOBAL_HOOK_DATAA temp = WinApi_Global_Hook_Data;
        HANDLE hProcess = NULL, hThread = NULL;
        BOOL Wow64;
        Info("Start Hooking!");
        Info("Target Process : %S", spi->ImageName.Buffer);
        Info("Process ID : %d", spi->UniqueProcessId);
        Info("Getting Process Handle...");
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, spi->UniqueProcessId);
        if (hProcess == NULL)
        {
            Fail("Hooking Failed!");
            CloseHandle(hProcess);
            continue;
        }
    #ifdef _WIN64
        IsWow64Process(hProcess, &Wow64);
        if (Wow64)
        {
            Fail("This process is 32bit!");
            CloseHandle(hProcess);
            continue;
        }
    #endif
        Success("Get process handle!");
        Info("Handle value is %p", hProcess);
        Info("Allocating memory in target process...");
        lpWinApi_Global_Hook_DataEx = ProcessMemoryAlloc(&temp, hProcess);
        if (lpWinApi_Global_Hook_DataEx == NULL)
        {
            Fail("Hooking Failed!");
            CloseHandle(hProcess);
            continue;
        }
        Success("Memory allocation success for target process");

        Info("Address is %p", temp.lpCopyBaseOfCode);
        Info("Address is %p", temp.lpNewFunctionEx);
        Info("Address is %p", temp.lpNewNtCreateUserProcessEx);
        Info("Address is %p", temp.lpHookingEx);
        Info("Address is %p", lpWinApi_Global_Hook_DataEx);

        if (temp.Parameter)
        {
            Info("Address is %p", temp.lpParameterEx);
        }

        Info("Writing Hook Data in Process Buffer...");
        if (WriteHookData(&temp, hProcess, lpWinApi_Global_Hook_DataEx) == FALSE)
        {
            Fail("Hooking Failed!");
            CloseHandle(hProcess);
            continue;
        }

        Success("Hook data write success!");

        Info("CreateRemoteThread Call...");
        hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)temp.lpHookingEx, lpWinApi_Global_Hook_DataEx, 0, NULL);

        if (hThread == NULL)
        {
            Fail("CreateRemoteThread Call Failed!");
            AllocatedMemoryFree(&temp, hProcess, lpWinApi_Global_Hook_DataEx);
            CloseHandle(hProcess);
            continue;
        }

        Info("Hooking Attempting...");
        //WaitForSingleObject(hThread, INFINITE);
        //Success("Hooking Success");
        Info("===============================");

        if (spi->NextEntryOffset == 0)
        {
            break;
        }
    }
}

BOOL SetHookStructA(PWINAPI_GLOBAL_HOOK_DATAA lpWinApi_Global_Hook_Data, PWINAPI_BASIC_GLOBAL_HOOK_DATAA lpWinApi_Basic_Global_Hook_Data)
{
    lpWinApi_Global_Hook_Data->lpNewFunction = lpWinApi_Basic_Global_Hook_Data->lpNewFunction;
    lpWinApi_Global_Hook_Data->lpNewNtCreateUserProcess = NewNtCreateUserProcess;
    lpWinApi_Global_Hook_Data->lpHooking = Hooking;
    lpWinApi_Global_Hook_Data->lpParameter = lpWinApi_Basic_Global_Hook_Data->lpParameter;
    lpWinApi_Global_Hook_Data->Parameter = lpWinApi_Basic_Global_Hook_Data->Parameter;
    lpWinApi_Global_Hook_Data->dwSizeParameter = lpWinApi_Basic_Global_Hook_Data->dwSizeParameter;
    lpWinApi_Global_Hook_Data->dwSizeNewFunction = lpWinApi_Basic_Global_Hook_Data->dwSizeNewFunction;
    lpWinApi_Global_Hook_Data->dwSizeNewNtCreateUserProcess = NewNtCreateUserProcessSize;
    lpWinApi_Global_Hook_Data->dwSizeHooking = HookingSize;
    lpWinApi_Global_Hook_Data->dwSizeDll = GetImageOfSizeA(lpWinApi_Basic_Global_Hook_Data->DllName);
    lpWinApi_Global_Hook_Data->GetProcAddress_Offset = (Address)GetProcAddress - (Address)GetModuleHandleA("kernel32.dll");
    lpWinApi_Global_Hook_Data->Origin_Function_Offset = (Address)lpWinApi_Basic_Global_Hook_Data->lpOrigin - (Address)LoadLibraryA(lpWinApi_Basic_Global_Hook_Data->DllName);
    lpWinApi_Global_Hook_Data->CopyOrigin_Parameter_Offset = lpWinApi_Basic_Global_Hook_Data->CopyOrigin_Parameter_Offset;
    strcpy(lpWinApi_Global_Hook_Data->DllName, lpWinApi_Basic_Global_Hook_Data->DllName);
    strcpy(lpWinApi_Global_Hook_Data->DefaultDll[0], "kernel32.dll");
    strcpy(lpWinApi_Global_Hook_Data->DefaultDll[1], "ntdll.dll");
    strcpy(lpWinApi_Global_Hook_Data->Function_Name_List[0], "memcpy");
    strcpy(lpWinApi_Global_Hook_Data->Function_Name_List[1], "NtCreateUserProcess");
    strcpy(lpWinApi_Global_Hook_Data->Function_Name_List[2], "OpenProcess");
    strcpy(lpWinApi_Global_Hook_Data->Function_Name_List[3], "VirtualProtect");
    strcpy(lpWinApi_Global_Hook_Data->Function_Name_List[4], "VirtualAllocEx");
    strcpy(lpWinApi_Global_Hook_Data->Function_Name_List[5], "WriteProcessMemory");
    strcpy(lpWinApi_Global_Hook_Data->Function_Name_List[6], "CreateRemoteThread");
    strcpy(lpWinApi_Global_Hook_Data->Function_Name_List[7], "WaitForSingleObject");
    strcpy(lpWinApi_Global_Hook_Data->Function_Name_List[8], "LoadLibraryA");
#ifdef _WIN64
    strcpy(lpWinApi_Global_Hook_Data->Function_Name_List[9], "IsWow64Process");
#endif
    memcpy(lpWinApi_Global_Hook_Data->JmpInstruction, JmpInstruction, sizeof(JmpInstruction));
    memcpy(lpWinApi_Global_Hook_Data->NtCreateUserProcess, NtCreateUserProcess, sizeof(NtCreateUserProcess));

    Info("Search Assembly overwrite offset...");

    lpWinApi_Global_Hook_Data->NtCreateUserProcess_Struct_Offset = AsmOverwriteOffset(lpWinApi_Global_Hook_Data->lpNewNtCreateUserProcess);

    if (lpWinApi_Global_Hook_Data->NtCreateUserProcess_Struct_Offset == NULL)
    {
        Fail("Not found assembly overwrite offset");
        return FALSE;
    }

    if (lpWinApi_Global_Hook_Data->Parameter)
    {   
        lpWinApi_Global_Hook_Data->NewFuncton_Struct_Offset = AsmOverwriteOffset(lpWinApi_Global_Hook_Data->lpNewFunction);
        
        if (lpWinApi_Global_Hook_Data->NewFuncton_Struct_Offset == NULL)
        {
            Fail("Not found assembly overwrite offset");
            return FALSE;
        }
    }

    Success("Found assembly overwrite offset");

    return TRUE;
}

Address AsmOverwriteOffset(LPVOID lpAddress)
{
    int i = 0;

    for (; i < INFINITE; i++)
    {
        if (*(BYTE *)((Address)lpAddress + i) == 0xCC)
            return i;
    }

    return NULL;
}