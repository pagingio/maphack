#include "stdafx.h"
#include "search.h"
//
//MemorySearch::MemorySearch()
//{
//  m_SearchPointer = 0;
//}
//
//MemorySearch::~MemorySearch()
//{
//}
//
//void MemorySearch::AddSearch(BYTE* signature, ULONG length, DWORD type, pMemorySearchCallback callback)
//{
//  MEMORY_SEARCH_ITEM    item;
//  item.signature = signature;
//  item.length = length;
//  item.type = type;
//  item.callback = callback;
//  m_MemorySignatures.push_back(item);
//}
//
//void MemorySearch::ProcessSearch()
//{
//  PBYTE     page;
//  PBYTE     p;
//  BOOL      found;
//  ULONG     length;
//  DWORD     tickStart;
//  DWORD     tickCurrent;
//  NTSTATUS  status;
//  MEMORY_BASIC_INFORMATION              info;
//  vector<MEMORY_SEARCH_ITEM>::iterator  it;
//
//  if (IsInWatchMode())
//  {
//    return;
//  }
//
//  // g_Log->Log("process search:0x%.8x", m_SearchPointer);
//
//  page = m_SearchPointer;
//  found = FALSE;
//  tickStart = GetTickCount();
//  while (TRUE)
//  {
//    tickCurrent = GetTickCount();
//    if (tickCurrent - tickStart > 5)
//    {
//      //
//      // it takes more than 30 milliseconds, just break.
//      //
//      // g_Log->Log("===== more than 30 milliseconds");
//      break;
//    }
//    ::memset(&info, 0, sizeof(MEMORY_BASIC_INFORMATION));
//    status = MyNtQueryVirtualMemory(
//      GetCurrentProcess(),
//      page,
//      MemoryBasicInformation,
//      &info,
//      sizeof(MEMORY_BASIC_INFORMATION),
//      &length
//      );
//    if (status == STATUS_SUCCESS)
//    {
//      //g_Log->Log("page:0x%.8x Base:0x%.8x alloc Base:0x%.8x size:0x%.8x",
//      //  page,
//      //  info.BaseAddress, info.AllocationBase, info.RegionSize);
//
//      if ((info.Protect != PAGE_EXECUTE && info.Protect != PAGE_EXECUTE_READ &&
//        info.Protect != PAGE_EXECUTE_READWRITE)
//        || info.State != MEM_COMMIT)
//      {
//        // g_Log->Log("pass non execute memory.");
//        page = (PBYTE)(info.BaseAddress) + info.RegionSize;
//        continue;
//      }
//
//      length = info.RegionSize - (ULONG_PTR)page + (ULONG_PTR)info.BaseAddress;
//      length = min(length, SEARCH_PAGE_SIZE);
//    }
//    else
//    {
//      if ((ULONG)page >= 0x7fff0000)
//      {
//        page = NULL;
//        break;
//      }
//      g_Log->Log("failed query virtual memory, page:0x%.8x.", page);
//      if (IsBadReadPtr(page, sizeof(ULONG)))
//      {
//        page += PAGE_SIZE;
//        continue;
//      }
//      length = PAGE_SIZE;
//    }
//
//    //
//    // skip memory of game.dll
//    //
//    if (IsAddressInGame((ULONG_PTR)page))
//    {
//      page = (PBYTE)GetGameAddress(0) + CODE_SECTION_END;
//      continue;
//    }
//
//    for (it = m_MemorySignatures.begin(); it != m_MemorySignatures.end(); it++)
//    {
//      __try
//      {
//        p = NULL;
//        p = QuickSearch(it->signature, it->length, page, length);
//      }
//      __except(EXCEPTION_EXECUTE_HANDLER)
//      {
//      }
//
//      if (p != NULL)
//      {
//        it->callback(p, *it);
//        found = TRUE;
//      }
//    }
//    page += length;
//    if (length == SEARCH_PAGE_SIZE)
//      break;
//  }
//  m_SearchPointer = page;
//  if ((ULONG)m_SearchPointer >= 0x7fff0000)
//  {
//    m_SearchPointer = NULL;
//  }
//}