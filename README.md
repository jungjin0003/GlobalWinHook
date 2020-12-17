# GlobalWinHook
This library can do Global Windows API Hook. And use Code Injection instead of DLL injection.

# Example Code
```
/* wchar_t(Wide Char) is not supported yet */
#include <stdio.h>
#include <windows.h>
#include "Global_WinHook.h"

typedef int(__stdcall *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

typedef struct _Data
{
    char text[10];
    MESSAGEBOXA NewMessageBoxA;
} Data;

int __stdcall NewMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    Data *data;
    #ifdef _WIN64
    data = 0xCCCCCCCCCCCCCCCC;
    #else
    data = 0xCCCCCCCC;
    #endif
    return ((MESSAGEBOXA)data->NewMessageBoxA)(hWnd, data->text, data->text, uType);
}

int main()
{
    Data data;
    WINAPI_BASIC_GLOBAL_HOOK_DATAA WBGHD;
    WBGHD.CopyOrigin_Parameter_Offset = offsetof(Data, NewMessageBoxA);
    strcpy(WBGHD.DllName, "user32.dll");
    WBGHD.dwSizeNewFunction = (Address)main - (Address)NewMessageBoxA;
    WBGHD.dwSizeParameter = sizeof(Data);
    WBGHD.lpNewFunction = NewMessageBoxA;
    WBGHD.lpOrigin = GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA");
    WBGHD.lpParameter = &data;
    WBGHD.Parameter = TRUE;
    strcpy(data.text, "Hooked!");
    HookA(&WBGHD);
    system("pause");
}
```
