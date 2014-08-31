// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "stdio.h"
#include "Inject.h"
#include "crt.h"

#define MAX_PROCESS 2048
DWORD   g_War3Process[MAX_PROCESS];
ULONG   g_Index;

DWORD WINAPI CheckWar3Process(LPVOID lpParam)
{
  ULONG   i;
  DWORD   processId;
  DWORD   threadId;
  HANDLE  processHandle;
  HANDLE  threadHandle;
  DWORD   addressInjected;

  while (TRUE)
  {
    Sleep(1000);

    DebugString("---- check war3 ---");
    processId = GetProcessID(TEXT("war3.exe"));
    if (processId == 0)
      continue;

    for (i = 0; i < MAX_PROCESS; i++)
    {
      if (processId == g_War3Process[i])
        break;
    }

    if (i == MAX_PROCESS)
    {
      g_War3Process[g_Index] = processId;
      g_Index++;

      // inject dll to war3

      // wait for loading game.dll.
      Sleep(2000);

      DebugString("---- inject to war3:%d", processId);
      processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
      addressInjected = InjectCode(processHandle, HookEndScene);

      threadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)addressInjected, NULL, 0, &threadId);
      if (threadHandle == NULL)
      {
        DebugString("\n ----- error code:%d ---------", GetLastError());
      }
      else
      {
        ResumeThread(threadHandle);
        CloseHandle(threadHandle);
      }
      CloseHandle(processHandle);
    }
  }
  return 0;
}

void MainInit()
{
  DWORD   dwThreadId;
  HANDLE  hThread = CreateThread( 
    NULL,
    0,
    CheckWar3Process,
    NULL,
    0,
    &dwThreadId);
  CloseHandle(hThread);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
    // printf("------ in input main ----");
    ::OutputDebugStringA(" ---- in input main ----");
    MainInit();
    break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
