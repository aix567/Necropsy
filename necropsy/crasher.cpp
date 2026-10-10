#include <windows.h>
#include <dbghelp.h>
#include <cstdio>
#pragma comment(lib, "dbghelp.lib")

LONG WINAPI handler(EXCEPTION_POINTERS* info) {
    HANDLE f = CreateFileA("C:\\dumps\\crasher.dmp",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION mei;
        mei.ThreadId = GetCurrentThreadId();
        mei.ExceptionPointers = info;
        mei.ClientPointers = FALSE;
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
            f, MiniDumpWithFullMemory, &mei, NULL, NULL);
        CloseHandle(f);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

int main() {
    SetUnhandledExceptionFilter(handler);
    volatile int* p = (int*)0x41414141;
    *p = 12345;
    return 0;
}
