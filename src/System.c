#include <windows.h>
#include "System.h"
#include "Common.h"
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

const wchar_t const FilterList[11][13] = {
    L"System",
    L"Registry",
    L"smss.exe",
    L"csrss.exe",
    L"wininit.exe",
    L"services.exe",
    L"lsass.exe",
    L"LMS.exe",
    L"dllhost.exe",
    L"dwm.exe",
    L"winlogon.exe"
};

LPVOID GetProcessList()
{
    PSYSTEM_PROCESS_INFORMATION spi;
    ULONG ReturnLength;

    Info("NtQuerySystemInformation Call...");

    if (NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &ReturnLength) != STATUS_INFO_LENGTH_MISMATCH)
    {
        return NULL;
    }

    Info("Allocating Process List Buffer...");

    spi = VirtualAlloc(NULL, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (spi == NULL)
    {
        Fail("VirtualAlloc Call Failed!");
        return NULL;
    }

    Success("Allocated Buffer!");

    if (!NT_SUCCESS(NtQuerySystemInformation(SystemProcessInformation, spi, ReturnLength, &ReturnLength)))
    {
        VirtualFree(spi, 0, MEM_RELEASE);
        Fail("NtQuerySystemInformation Call Failed!");
        return NULL;
    }

    Success("NtQuerySystemInformation call success!");

    SystemProcessFilter(spi);
    Success("System Process Filtered Success!");

    return spi;
}

void SystemProcessFilter(PSYSTEM_PROCESS_INFORMATION lpSPI)
{
    PSYSTEM_PROCESS_INFORMATION temp = NULL;
    temp = lpSPI;
    lpSPI = (Address)lpSPI + lpSPI->NextEntryOffset;

    while (TRUE)
    {
        for (int i = 0; i < 11; i++)
        {
            if (_wcsicmp(FilterList[i], lpSPI->ImageName.Buffer) == 0)
            {
                temp->NextEntryOffset += lpSPI->NextEntryOffset;
                break;
            }
            else if (i == 10)
            {
                temp = lpSPI;
            }
        }

        if (lpSPI->NextEntryOffset == 0)
        {
            break;
        }

        lpSPI = (Address)lpSPI + lpSPI->NextEntryOffset;
    }
}

LPVOID ProcessMemoryAlloc(PWINAPI_GLOBAL_HOOK_DATAA lpWinApi_Global_Hook_Data, HANDLE hProcess)
{
    LPVOID lpWinApi_Global_Hook_DataEx = NULL;

    lpWinApi_Global_Hook_Data->lpCopyBaseOfCode = ProcessBufferAlloc(hProcess, lpWinApi_Global_Hook_Data->dwSizeDll);

    if (lpWinApi_Global_Hook_Data->lpCopyBaseOfCode == NULL)
    {
        goto Fail;
    }

    lpWinApi_Global_Hook_Data->lpNewFunctionEx = ProcessBufferAlloc(hProcess, lpWinApi_Global_Hook_Data->dwSizeNewFunction);

    if (lpWinApi_Global_Hook_Data->lpNewFunctionEx == NULL)
    {
        goto Fail;
    }

    lpWinApi_Global_Hook_Data->lpNewNtCreateUserProcessEx = ProcessBufferAlloc(hProcess, lpWinApi_Global_Hook_Data->dwSizeNewNtCreateUserProcess);

    if (lpWinApi_Global_Hook_Data->lpNewNtCreateUserProcessEx == NULL)
    {
        goto Fail;
    }

    lpWinApi_Global_Hook_Data->lpHookingEx = ProcessBufferAlloc(hProcess, lpWinApi_Global_Hook_Data->dwSizeHooking);

    if (lpWinApi_Global_Hook_Data->lpHookingEx == NULL)
    {
        goto Fail;
    }

    lpWinApi_Global_Hook_DataEx = ProcessBufferAlloc(hProcess, sizeof(*lpWinApi_Global_Hook_Data));

    if (lpWinApi_Global_Hook_Data->Parameter)
    {
        lpWinApi_Global_Hook_Data->lpParameterEx = ProcessBufferAlloc(hProcess, lpWinApi_Global_Hook_Data->dwSizeParameter);

        if (lpWinApi_Global_Hook_Data->lpParameterEx == NULL)
        {
            goto Fail;
        }
    }

    return lpWinApi_Global_Hook_DataEx;

Fail:

    Fail("VirtualAllocEx Call Failed!");
    AllocatedMemoryFree(lpWinApi_Global_Hook_Data, hProcess, lpWinApi_Global_Hook_DataEx);
    return NULL;
}

void AllocatedMemoryFree(PWINAPI_GLOBAL_HOOK_DATAA lpWinApi_Global_Hook_Data, HANDLE hProcess, LPVOID lpWinApi_Global_Hook_DataEx)
{
    Info("Allocated memory free for target process...");
    if (ProcessMemoryFree(lpWinApi_Global_Hook_Data, hProcess, lpWinApi_Global_Hook_DataEx))
    {
        Success("All allocated memory free success");
    }
    else
    {
        Success("Some allocated memory free success or not free");
    }
}

BOOL ProcessMemoryFree(PWINAPI_GLOBAL_HOOK_DATAA lpWinApi_Global_Hook_Data, HANDLE hProcess, LPVOID lpWinApi_Global_Hook_DataEx)
{
    BOOL ret = TRUE;
    if (ProcessBufferFree(hProcess, lpWinApi_Global_Hook_Data->lpCopyBaseOfCode))
    {
        Success("VirtualFreeEx Call Success!");
    }
    else
    {
        Fail("Pointer %p Free Failed!\n", lpWinApi_Global_Hook_Data->lpCopyBaseOfCode);
        ret = FALSE;
    }

    if (ProcessBufferFree(hProcess, lpWinApi_Global_Hook_Data->lpNewFunctionEx))
    {
        Success("VirtualFreeEx Call Success!");
    }
    else
    {
        Fail("Pointer %p Free Failed!\n", lpWinApi_Global_Hook_Data->lpNewFunctionEx);
        ret = FALSE;
    }

    if (ProcessBufferFree(hProcess, lpWinApi_Global_Hook_Data->lpNewNtCreateUserProcessEx))
    {
        Success("VirtualFreeEx Call Success!");
    }
    else
    {
        Fail("Pointer %p Free Failed!\n", lpWinApi_Global_Hook_Data->lpNewNtCreateUserProcessEx);
        ret = FALSE;
    }

    if (ProcessBufferFree(hProcess, lpWinApi_Global_Hook_Data->lpHookingEx))
    {
        Success("VirtualFreeEx Call Success!");
    }
    else
    {
        Fail("Pointer %p Free Failed!\n", lpWinApi_Global_Hook_Data->lpHookingEx);
        ret = FALSE;
    }

    if (ProcessBufferFree(hProcess, lpWinApi_Global_Hook_DataEx))
    {
        Success("VirtualFreeEx Call Success!");
    }
    else
    {
        Fail("Pointer %p Free Failed!\n", lpWinApi_Global_Hook_DataEx);
        ret = FALSE;
    }

    if (lpWinApi_Global_Hook_Data->Parameter)
    {
        if (ProcessBufferFree(hProcess, lpWinApi_Global_Hook_Data->lpParameterEx))
        {
            Success("VirtualFreeEx Call Success!");
        }
        else
        {
            Fail("Pointer %p Free Failed!\n", lpWinApi_Global_Hook_Data->lpParameterEx);
            ret = FALSE;
        }
    }

    return ret;
}

LPVOID ProcessBufferAlloc(HANDLE hProcess, SIZE_T dwSize)
{
    return VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}

WINBOOL ProcessBufferFree(HANDLE hProcess, LPVOID lpAddress)
{
    WINBOOL ret = VirtualFreeEx(hProcess, lpAddress, 0, MEM_RELEASE);
    DWORD Status;
    if (!ret)
    {
        Status = RtlGetLastNtStatus();
        ret = (Status == 0xC000001B) ? TRUE : FALSE;
    }
    return ret;
}

WINBOOL WriteHookData(PWINAPI_GLOBAL_HOOK_DATAA lpWinApi_Global_Hook_Data, HANDLE hProcess, LPVOID lpWinApi_Global_Hook_DataEx)
{
    if (WriteProcessMemory(hProcess, lpWinApi_Global_Hook_Data->lpHookingEx, lpWinApi_Global_Hook_Data->lpHooking, lpWinApi_Global_Hook_Data->dwSizeHooking, NULL) == FALSE)
    {
        Fail("WriteProcessMemory Call Failed!");
        ProcessMemoryFree(lpWinApi_Global_Hook_Data, hProcess, lpWinApi_Global_Hook_DataEx);
        return FALSE;
    }
    else if (WriteProcessMemory(hProcess, lpWinApi_Global_Hook_DataEx, lpWinApi_Global_Hook_Data, sizeof(*lpWinApi_Global_Hook_Data), NULL) == FALSE)
    {
        Fail("WriteProcessMemory Call Failed!");
        ProcessMemoryFree(lpWinApi_Global_Hook_Data, hProcess, lpWinApi_Global_Hook_DataEx);
        return FALSE;
    }
    else if (WriteProcessMemory(hProcess, lpWinApi_Global_Hook_Data->lpNewFunctionEx, lpWinApi_Global_Hook_Data->lpNewFunction, lpWinApi_Global_Hook_Data->dwSizeNewFunction, NULL) == FALSE)
    {
        Fail("WriteProcessMemory Call Failed!");
        ProcessMemoryFree(lpWinApi_Global_Hook_Data, hProcess, lpWinApi_Global_Hook_DataEx);
        return FALSE;
    }
    else if (WriteProcessMemory(hProcess, lpWinApi_Global_Hook_Data->lpNewNtCreateUserProcessEx, lpWinApi_Global_Hook_Data->lpNewNtCreateUserProcess, lpWinApi_Global_Hook_Data->dwSizeNewNtCreateUserProcess, NULL) == FALSE)
    {
        Fail("WriteProcessMemory Call Failed!");
        ProcessMemoryFree(lpWinApi_Global_Hook_Data, hProcess, lpWinApi_Global_Hook_DataEx);
        return FALSE;
    }

    if (lpWinApi_Global_Hook_Data->Parameter)
    {
        if (WriteProcessMemory(hProcess, lpWinApi_Global_Hook_Data->lpParameterEx, lpWinApi_Global_Hook_Data->lpParameter, lpWinApi_Global_Hook_Data->dwSizeParameter, NULL) == FALSE)
        {
            Fail("WriteProcessMemory Call Failed!");
            ProcessMemoryFree(lpWinApi_Global_Hook_Data, hProcess, lpWinApi_Global_Hook_DataEx);
            return FALSE;
        }
    }

    return TRUE;
}

#ifdef _WIN64
DWORD __stdcall GetImageOfSizeA(char *username)
{
    __int64 base = LoadLibraryA(username);
    struct _IMAGE_NT_HEADERS64 *v1;
    DWORD *v2;

    v1 = 0;
    if ((unsigned __int64)(base - 1) <= 0xFFFFFFFFFFFFFFFD && *(WORD *)base == 23117 && *(DWORD *)(base + 60) >= 0 && *(DWORD *)(base + 60) < 0x10000000u)
    {
        v2 = (DWORD *)(base + *(signed int *)(base + 60));
        if (*v2 != 17744)
            v2 = 0;
        v1 = v2;
    }

    if (!v1)
    {
        SetLastError(0xC1u);
    }
    return v1->OptionalHeader.SizeOfImage;
}
#else
DWORD __stdcall GetImageOfSizeA(char *username)
{
    DWORD *base = LoadLibraryA(username);
    struct _IMAGE_NT_HEADERS *v1;
    unsigned int v2;

    v1 = 0;
    if (base)
    {
        if (base != (DWORD *)-1 && *(WORD *)base == 23117)
        {
            v2 = base[15];
            if ((v2 & 0x80000000) == 0 && v2 < 0x10000000)
            {
                v1 = *(DWORD *)((char *)base + v2) == 17744 ? (unsigned int)base + v2 : 0;
            }
        }
    }

    if (!v1)
    {
        SetLastError(0xC1u);
    }
    return v1->OptionalHeader.SizeOfImage;
}
#endif