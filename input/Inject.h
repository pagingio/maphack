#ifndef __INJECT_H_
#define __INJECT_H_

#include <windows.h>

DWORD GetImageBase();
DWORD GetImageBase2();

DWORD WINAPI InjectCode( HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartProc );
DWORD WINAPI HookEndScene(LPVOID lpThreadParameter);

#endif