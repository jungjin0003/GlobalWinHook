#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include "Common.h"

void Info(char *Message, ...)
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 2);
    printf("[*] ");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
    int __retval;
    __builtin_va_list __local_argv;
    __builtin_va_start(__local_argv, Message);
    __retval = __mingw_vfprintf(stdout, Message, __local_argv);
    __builtin_va_end(__local_argv);
    putchar('\n');
}

void Success(char *Message, ...)
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 1);
    printf("[*] ");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
    int __retval;
    __builtin_va_list __local_argv;
    __builtin_va_start(__local_argv, Message);
    __retval = __mingw_vfprintf(stdout, Message, __local_argv);
    __builtin_va_end(__local_argv);
    putchar('\n');
}

void Fail(char *Message, ...)
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);
    printf("[-] ");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
    int __retval;
    __builtin_va_list __local_argv;
    __builtin_va_start(__local_argv, Message);
    __retval = __mingw_vfprintf(stdout, Message, __local_argv);
    __builtin_va_end(__local_argv);
    putchar('\n');
}