// Copyright 2013 jiankun.ma. All Rights Reserved.
// Author: jiankun.ma. tao-mjk-tx@hotmail.com

#include "stdafx.h"
#include <Windows.h>

#ifndef _PELOAD_H_
#define _PELOAD_H_

typedef HMODULE HPEMODULE;

HPEMODULE WINAPI PeLoad(char* fileName);
HPEMODULE WINAPI MemoryLoad(LPVOID buffer, DWORD bufferLength);
BOOLEAN WINAPI ReplaceGlobalReloc(HPEMODULE module, ULONG_PTR va, ULONG_PTR newVa);

PVOID WINAPI PeGetProcAddress(HPEMODULE module, DWORD hash);
void WINAPI ClearModuleHeader(HPEMODULE module);

#endif