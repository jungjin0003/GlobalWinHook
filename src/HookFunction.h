#pragma once
#ifndef __HOOKFUNCTION_H__
#define __HOOKFUNCTION_H__

#include "Common.h"

#define HookingSize (Address)AtherFunc - (Address)Hooking
#define NewNtCreateUserProcessSize (Address)Hooking - (Address)NewNtCreateUserProcess

NTSTATUS NTAPI NewNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, void *CreateInfo, void *AttributeList);
int Hooking(PWINAPI_GLOBAL_HOOK_DATAA Data);
int AtherFunc();

#endif