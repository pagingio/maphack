#include <Windows.h>
#include "crt.h"

#ifndef _SEARCH_H_
#define _SEARCH_H_

typedef enum _MEMORY_MEMORY_SEARCH_TYPE 
{
  MemorySearchTypeFogOfWar,
  MemorySearchTypeReloadGame,
}MEMORY_MEMORY_SEARCH_TYPE;

struct _MEMORY_SEARCH_ITEM;
typedef struct _MEMORY_SEARCH_ITEM MEMORY_SEARCH_ITEM;

typedef void (WINAPI *pMemorySearchCallback)(BYTE* address, MEMORY_SEARCH_ITEM item);

typedef struct _MEMORY_SEARCH_ITEM
{
  BYTE*                   signature;
  ULONG                   length;
  DWORD                   type;
  pMemorySearchCallback   callback;
}MEMORY_SEARCH_ITEM, *PMEMORY_SEARCH_ITEM;


#define   SEARCH_PAGE_SIZE    0x8000

class MemorySearch
{
public:
  MemorySearch();
  ~MemorySearch();

  void AddSearch(BYTE* signature, ULONG length, DWORD type, pMemorySearchCallback callback);
  void ProcessSearch();

private:
  // vector<MEMORY_SEARCH_ITEM>    m_MemorySignatures;
  PBYTE                         m_SearchPointer;
};

extern  MemorySearch*    g_MemorySearch;

#endif