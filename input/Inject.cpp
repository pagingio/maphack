#include "stdafx.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "crt.h"

#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue)) 
#define MakeDelta(cast, x, y) (cast) ( (DWORD_PTR)(x) - (DWORD_PTR)(y)) 

DWORD dwNewBase = 0;

DWORD GetImageBase2()
{
	DWORD dwRet = 0;
  /*	__asm
	{
			call getbase
		getbase:
			pop eax
			and eax, 0ffff0000h
		find:
			cmp word ptr [ eax ], 0x5a4d
			je end
			sub eax, 00010000h
			jmp find
		end:
			mov [dwRet], eax
	} */
	return dwRet;
}

DWORD GetImageBase()
{
	DWORD dwRet = 0;	
	DWORD* Addr = (DWORD *)&GetImageBase;

	__asm
	{
			mov EAX, Addr
			and eax, 0FFFF0000h
		find:
			cmp word ptr [eax], 0x5A4D
			je end
			sub eax, 00010000h
			JMP find
		end:
			mov [dwRet], eax
	}

	return dwRet;
}

void PerformRebase( LPVOID lpAddress, DWORD dwNewBase )
{
	PIMAGE_DOS_HEADER pDH = (PIMAGE_DOS_HEADER)lpAddress;

	if ( pDH->e_magic != IMAGE_DOS_SIGNATURE )
	{
		return;
	}

	PIMAGE_NT_HEADERS pPE = (PIMAGE_NT_HEADERS) ((char *)pDH + pDH->e_lfanew);

	if ( pPE->Signature != IMAGE_NT_SIGNATURE )
	{
		return;
	}

	DWORD dwDelta = dwNewBase - pPE->OptionalHeader.ImageBase;

	DWORD dwVa = pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD dwCb = pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	PIMAGE_BASE_RELOCATION pBR = MakePtr( PIMAGE_BASE_RELOCATION, lpAddress, dwVa );

	UINT c = 0;

	while ( c < dwCb )
	{
		c += pBR->SizeOfBlock;

		int RelocCount = (pBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		LPVOID lpvBase = MakePtr(LPVOID, lpAddress, pBR->VirtualAddress);

		WORD *areloc = MakePtr(LPWORD, pBR, sizeof(IMAGE_BASE_RELOCATION));

		for ( int i = 0; i < RelocCount; i++ )
		{
			int type = areloc[i] >> 12;

			if ( !type )
			{
				continue;
			}

			if ( type != 3 )
			{
				return;
			}

			int ofs = areloc[i] & 0x0fff;

			DWORD *pReloc = MakePtr( DWORD *, lpvBase, ofs );

			if ( *pReloc - pPE->OptionalHeader.ImageBase > pPE->OptionalHeader.SizeOfImage )
			{
				return;
			}

			*pReloc += dwDelta;
		}

		pBR = MakePtr( PIMAGE_BASE_RELOCATION, pBR, pBR->SizeOfBlock );
	}

	pPE->OptionalHeader.ImageBase = dwNewBase;

	return;
}

typedef struct 
{
	WORD	Offset:12;
	WORD	Type:4;
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;

void ProcessRelocs( PIMAGE_BASE_RELOCATION Relocs, DWORD ImageBase, DWORD Delta, DWORD RelocSize )
{
	PIMAGE_BASE_RELOCATION Reloc = Relocs;

	while ( (DWORD)Reloc - (DWORD)Relocs < RelocSize ) 
	{
		if ( !Reloc->SizeOfBlock )
		{
			break;
		}

		PIMAGE_FIXUP_ENTRY Fixup = (PIMAGE_FIXUP_ENTRY)((ULONG)Reloc + sizeof(IMAGE_BASE_RELOCATION));

		for ( ULONG r = 0; r < (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) >> 1; r++ ) 
		{
			DWORD dwPointerRva = Reloc->VirtualAddress + Fixup->Offset;

			if ( Fixup->Offset != 0  )
			{
				*(PULONG)((ULONG)ImageBase + dwPointerRva) += Delta;
			}

			Fixup++;
		}

		Reloc = (PIMAGE_BASE_RELOCATION)( (ULONG)Reloc + Reloc->SizeOfBlock );
	}
	return;
}

DWORD WINAPI InjectCode( HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartProc )
{
	HMODULE   hModule = (HMODULE)GetImageBase();

	PIMAGE_DOS_HEADER pDH = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pPE = (PIMAGE_NT_HEADERS) ((LPSTR)pDH + pDH->e_lfanew);

	DWORD dwSize = pPE->OptionalHeader.SizeOfImage;

	LPVOID lpNewAddr = VirtualAlloc( NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	if ( lpNewAddr == NULL )
	{
    DebugString("new address:0x%.8x", lpNewAddr);
		return -1;
	}
	m_memcpy( lpNewAddr, hModule, dwSize );

	LPVOID  lpNewModule = NULL;

	DWORD   dwAddr = -1;
	HMODULE hNewModule = NULL;

  lpNewModule = VirtualAllocEx( hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	if ( lpNewModule != NULL )
	{
    DebugString("new module:0x%.8x", lpNewModule);
		hNewModule = (HMODULE)lpNewModule;	

		ULONG RelRVA   = pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		ULONG RelSize  = pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		ProcessRelocs( (PIMAGE_BASE_RELOCATION)( (DWORD)hModule + RelRVA ), (DWORD)lpNewAddr, (DWORD)hNewModule - (DWORD)hModule, RelSize );		

    DebugString(" ---- ProcessRelocs --- ");
		dwNewBase = (DWORD)hNewModule;

		if ( WriteProcessMemory( hProcess,   hNewModule, lpNewAddr, dwSize, NULL ) )
		{
			dwAddr = (DWORD)lpStartProc - (DWORD)hModule + (DWORD)hNewModule;
		}
    DebugString(" ---- WriteProcessMemory --- ");

    DWORD dwOldProtect = 0;
    VirtualProtectEx( hProcess, hNewModule, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect );
    DebugString(" ---- VirtualProtectEx:%0.8x--- ", dwAddr);
	}
  else
  {
    DWORD   errorCode;
    errorCode = GetLastError();
    DebugString(" ---- virtual alloc failed, error code:%d --- ", errorCode);
  }

	VirtualFree( lpNewAddr, dwSize, MEM_DECOMMIT );
	return dwAddr;
}
