#include <Windows.h>
#include <ImageHlp.h>

#ifndef _CRT_H_
#define _CRT_H_

void* m_malloc(size_t length);
void  m_free(void* buffer, size_t length);

void  m_memset(void* dest, int value, size_t length);
void  m_memcpy(void* dest, void* source, size_t length);

int m_wcscmp(wchar_t* source, wchar_t* dest);

void  DebugString(char* fmt,...);
ULONG SafeWrite(PULONG address, ULONG newValue);

DWORD GetProcessID(LPCTSTR pName);

#endif