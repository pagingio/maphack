// Copyright 2013 Netease Inc. All Rights Reserved.
// Author: gzmajiankun@corp.netease.com (Ma jiankun)

#include "stdafx.h"
#include <ImageHlp.h>
#include "peloader.h"
#include "crt.h"

PIMAGE_NT_HEADERS GetImageNtHeader(LPVOID imageBase)
{
  PIMAGE_DOS_HEADER header = (PIMAGE_DOS_HEADER)imageBase;
  if ( header->e_magic != IMAGE_DOS_SIGNATURE )
  {
    return NULL;
  }

  PIMAGE_NT_HEADERS headerNt = (PIMAGE_NT_HEADERS) ((char *)header + header->e_lfanew);
  if ( headerNt->Signature != IMAGE_NT_SIGNATURE )
  {
    return NULL;
  }
  return headerNt;
}

DWORD WINAPI GetAlignSize(DWORD length, DWORD sizeAlign)
{
  return (length+sizeAlign-1)/sizeAlign*sizeAlign;
}

DWORD WINAPI GetTotalImageSize(PVOID buffer, DWORD fileSize)
{
  PIMAGE_DOS_HEADER headerDos = (PIMAGE_DOS_HEADER)buffer;
  PIMAGE_NT_HEADERS headerNt = (PIMAGE_NT_HEADERS)((ULONG)buffer + headerDos->e_lfanew);

  DWORD totalSize = GetAlignSize(
    headerNt->OptionalHeader.SizeOfHeaders,
    headerNt->OptionalHeader.SectionAlignment);
  PIMAGE_SECTION_HEADER headerSection = (PIMAGE_SECTION_HEADER)((ULONG)headerNt + sizeof(IMAGE_NT_HEADERS));

  DWORD count = headerNt->FileHeader.NumberOfSections;
  for(DWORD index = 0; index < count; index++)
  {
    if((headerSection[index].PointerToRawData + headerSection[index].SizeOfRawData) > fileSize)
    {
      return 0;
    }
    else if(headerSection[index].VirtualAddress != NULL)
    {
      if(headerSection[index].Misc.VirtualSize != 0)
        totalSize += GetAlignSize(
        headerSection[index].Misc.VirtualSize,
        headerNt->OptionalHeader.SectionAlignment);
      else
        totalSize += GetAlignSize(
        headerSection[index].SizeOfRawData,
        headerNt->OptionalHeader.SectionAlignment);
    }
    else 
    {
      if(headerSection[index].SizeOfRawData > headerSection[index].Misc.VirtualSize)
        totalSize += GetAlignSize(
        headerSection[index].SizeOfRawData,
        headerNt->OptionalHeader.SectionAlignment);
      else
        totalSize += GetAlignSize(
        headerSection[index].Misc.VirtualSize,
        headerNt->OptionalHeader.SectionAlignment);
    }
  }
  return totalSize;
}

HPEMODULE WINAPI AlignFileToMem(PVOID buffer, ULONG* length)
{
  DWORD                   sizeTotal;
  DWORD                   index;
  DWORD                   skip;
  DWORD                   sizeCopy;
  HPEMODULE               module = NULL;
  PIMAGE_NT_HEADERS       headerNt = NULL;
  PIMAGE_SECTION_HEADER   headerSection = NULL;
  PVOID                   source;
  PVOID                   target;
  BOOLEAN                 success = FALSE;

  __try
  {
    sizeTotal = GetTotalImageSize(buffer, *length);
    module = (HPEMODULE)VirtualAlloc(NULL, sizeTotal, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (module == NULL)
    {
      __leave;
    }
    m_memset(module, 0, sizeTotal);

    headerNt = (PIMAGE_NT_HEADERS)((ULONG)buffer + ((PIMAGE_DOS_HEADER)buffer)->e_lfanew);
    headerSection = IMAGE_FIRST_SECTION(headerNt);

    //
    // copy header
    //
    sizeCopy = headerNt->OptionalHeader.SizeOfHeaders;
    for (index = 0; index < headerNt->FileHeader.NumberOfSections; index++)
    {
      if (headerSection[index].PointerToRawData != 0 &&
        headerSection[index].PointerToRawData < sizeCopy)
      {
        sizeCopy = headerSection[index].PointerToRawData;
      }
    }

    memcpy(module, buffer, sizeCopy);

    //
    // copy sections
    //
    skip = GetAlignSize(
      headerNt->OptionalHeader.SizeOfHeaders,
      headerNt->OptionalHeader.SectionAlignment
      );
    target = (PVOID)((ULONG)module + skip); 

    for (index = 0; index < headerNt->FileHeader.NumberOfSections; index++)
    {
      if (headerSection[index].VirtualAddress != 0)
      {
        target = (PVOID)((ULONG)module + headerSection[index].VirtualAddress);
      }

      if (headerSection[index].SizeOfRawData > 0)
      {
        source = (PVOID)((ULONG)buffer + headerSection[index].PointerToRawData);
        sizeCopy = headerSection[index].SizeOfRawData;
        memcpy(target, source, sizeCopy);

        if (headerSection[index].SizeOfRawData > headerSection[index].Misc.VirtualSize)
        {
          skip = GetAlignSize(
            headerSection[index].SizeOfRawData,
            headerNt->OptionalHeader.SectionAlignment
            );
        }
        else
        {
          skip = GetAlignSize(
            headerSection[index].Misc.VirtualSize,
            headerNt->OptionalHeader.SectionAlignment
            );
        }
      }
      else
      {
        skip = GetAlignSize(
          headerSection[index].Misc.VirtualSize,
          headerNt->OptionalHeader.SectionAlignment
          );
      }
      target = (PVOID)((ULONG_PTR)target + skip);
    }
    success = TRUE;
  }
  __finally
  {
  }

  if (!success && module != NULL)
  {
    VirtualFree(module, sizeTotal, MEM_DECOMMIT);
    module = NULL;
  }
  return module;
}

BOOLEAN WINAPI ProcessIat(HPEMODULE module)
{
  PIMAGE_NT_HEADERS		      imageHeader;
  PIMAGE_DATA_DIRECTORY 	  importTable;
  PIMAGE_IMPORT_DESCRIPTOR	importDescriptor;
  PIMAGE_IMPORT_BY_NAME     importByName;
  DWORD                     j;
  DWORD                     address;
  DWORD                     ordinal;
  HMODULE                   moduleImport;
  char*                     moduleName;
  char*                     functionName;
  PIMAGE_THUNK_DATA32       thunkFirst;
  PIMAGE_THUNK_DATA32       thunkOriginal;
  DWORD					            moduleBase;

  moduleBase = (DWORD)module;
  imageHeader = GetImageNtHeader(module);
  if (imageHeader == NULL)
  {
    return FALSE;
  }

  importTable = &(imageHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
  if (importTable->VirtualAddress == 0)
  {
    return TRUE;
  }

  importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importTable->VirtualAddress + moduleBase);
  for (j = 0; importDescriptor[j].Characteristics != 0; j++)
  {
    if (importDescriptor[j].Name == 0 ||
      importDescriptor[j].FirstThunk == 0 ||
      importDescriptor[j].OriginalFirstThunk == 0)
      continue;

    moduleName = (char*)(importDescriptor[j].Name + moduleBase);
    moduleImport = LoadLibraryA(moduleName);

    thunkFirst = (PIMAGE_THUNK_DATA32)((DWORD)importDescriptor[j].FirstThunk + moduleBase);
    thunkOriginal = (PIMAGE_THUNK_DATA32)((DWORD)importDescriptor[j].OriginalFirstThunk + moduleBase);

    while (thunkOriginal->u1.Ordinal != 0)
    {
      if (!(thunkOriginal->u1.Ordinal & IMAGE_ORDINAL_FLAG))
      {
        //
        // import by name
        //
        importByName = (PIMAGE_IMPORT_BY_NAME)(moduleBase + (ULONG)thunkOriginal->u1.AddressOfData);
        functionName = (char*)(&importByName->Name);
        address = (DWORD)GetProcAddress(moduleImport, functionName);
      }
      else
      {
        //
        // import by ordinal
        //
        ordinal = thunkOriginal->u1.Ordinal & (~IMAGE_ORDINAL_FLAG);
        address = (DWORD)GetProcAddress(moduleImport, (LPCSTR)ordinal);
      }

      *(DWORD*)thunkFirst = address;
      thunkFirst++;
      thunkOriginal++;
    }    
  }
  return TRUE;
}

//
// Mark a HIGHADJ entry as needing an increment if reprocessing.
//
#define LDRP_RELOCATION_INCREMENT   0x1

//
// Mark a HIGHADJ entry as not suitable for reprocessing.
//
#define LDRP_RELOCATION_FINAL       0x2

PIMAGE_BASE_RELOCATION
WINAPI
LdrProcessRelocationBlockLongLong(
  IN ULONG_PTR VA,
  IN ULONG SizeOfBlock,
  IN PUSHORT NextOffset,
  IN LONGLONG Diff
  )
{
  PUCHAR FixupVA;
  USHORT Offset;
  LONG Temp;
  ULONGLONG Value64;

  while (SizeOfBlock--)
  {
    Offset = *NextOffset & (USHORT)0xfff;
    FixupVA = (PUCHAR)(VA + Offset);

    //
    // Apply the fixups.
    //
    switch ((*NextOffset) >> 12)
    {
    case IMAGE_REL_BASED_HIGHLOW:
      //
      // HighLow - (32-bits) relocate the high and low half
      //      of an address.
      //
      *(LONG UNALIGNED *)FixupVA += (ULONG) Diff;
      break;

    case IMAGE_REL_BASED_HIGH:
      //
      // High - (16-bits) relocate the high half of an address.
      //
      Temp = *(PUSHORT)FixupVA << 16;
      Temp += (ULONG) Diff;
      *(PUSHORT)FixupVA = (USHORT)(Temp >> 16);
      break;

    case IMAGE_REL_BASED_HIGHADJ:
      //
      // Adjust high - (16-bits) relocate the high half of an
      //      address and adjust for sign extension of low half.
      //

      //
      // If the address has already been relocated then don't
      // process it again now or information will be lost.
      //
      if (Offset & LDRP_RELOCATION_FINAL)
      {
        ++NextOffset;
        --SizeOfBlock;
        break;
      }

      Temp = *(PUSHORT)FixupVA << 16;
      ++NextOffset;
      --SizeOfBlock;
      Temp += (LONG)(*(PSHORT)NextOffset);
      Temp += (ULONG) Diff;
      Temp += 0x8000;
      *(PUSHORT)FixupVA = (USHORT)(Temp >> 16);
      break;

    case IMAGE_REL_BASED_LOW:
      //
      // Low - (16-bit) relocate the low half of an address.
      //
      Temp = *(PSHORT)FixupVA;
      Temp += (ULONG) Diff;
      *(PUSHORT)FixupVA = (USHORT)Temp;
      break;

    case IMAGE_REL_BASED_IA64_IMM64:

      //
      // Align it to bundle address before fixing up the
      // 64-bit immediate value of the movl instruction.
      //

      FixupVA = (PUCHAR)((ULONG_PTR)FixupVA & ~(15));
      Value64 = (ULONGLONG)0;

      //
      // Extract the lower 32 bits of IMM64 from bundle
      //

      EXT_IMM64(Value64,
        (PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X,
        EMARCH_ENC_I17_IMM7B_SIZE_X,
        EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
        EMARCH_ENC_I17_IMM7B_VAL_POS_X);
      EXT_IMM64(Value64,
        (PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X,
        EMARCH_ENC_I17_IMM9D_SIZE_X,
        EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
        EMARCH_ENC_I17_IMM9D_VAL_POS_X);
      EXT_IMM64(Value64,
        (PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X,
        EMARCH_ENC_I17_IMM5C_SIZE_X,
        EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
        EMARCH_ENC_I17_IMM5C_VAL_POS_X);
      EXT_IMM64(Value64,
        (PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X,
        EMARCH_ENC_I17_IC_SIZE_X,
        EMARCH_ENC_I17_IC_INST_WORD_POS_X,
        EMARCH_ENC_I17_IC_VAL_POS_X);
      EXT_IMM64(Value64,
        (PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X,
        EMARCH_ENC_I17_IMM41a_SIZE_X,
        EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
        EMARCH_ENC_I17_IMM41a_VAL_POS_X);

      EXT_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
        EMARCH_ENC_I17_IMM41b_SIZE_X,
        EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
        EMARCH_ENC_I17_IMM41b_VAL_POS_X);
      EXT_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
        EMARCH_ENC_I17_IMM41c_SIZE_X,
        EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
        EMARCH_ENC_I17_IMM41c_VAL_POS_X);
      EXT_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
        EMARCH_ENC_I17_SIGN_SIZE_X,
        EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
        EMARCH_ENC_I17_SIGN_VAL_POS_X);
      //
      // Update 64-bit address
      //

      Value64+=Diff;

      //
      // Insert IMM64 into bundle
      //

      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X),
        EMARCH_ENC_I17_IMM7B_SIZE_X,
        EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
        EMARCH_ENC_I17_IMM7B_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X),
        EMARCH_ENC_I17_IMM9D_SIZE_X,
        EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
        EMARCH_ENC_I17_IMM9D_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X),
        EMARCH_ENC_I17_IMM5C_SIZE_X,
        EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
        EMARCH_ENC_I17_IMM5C_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X),
        EMARCH_ENC_I17_IC_SIZE_X,
        EMARCH_ENC_I17_IC_INST_WORD_POS_X,
        EMARCH_ENC_I17_IC_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X),
        EMARCH_ENC_I17_IMM41a_SIZE_X,
        EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
        EMARCH_ENC_I17_IMM41a_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
        EMARCH_ENC_I17_IMM41b_SIZE_X,
        EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
        EMARCH_ENC_I17_IMM41b_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
        EMARCH_ENC_I17_IMM41c_SIZE_X,
        EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
        EMARCH_ENC_I17_IMM41c_VAL_POS_X);
      INS_IMM64(Value64,
        ((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
        EMARCH_ENC_I17_SIGN_SIZE_X,
        EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
        EMARCH_ENC_I17_SIGN_VAL_POS_X);
      break;

    case IMAGE_REL_BASED_DIR64:
      *(ULONGLONG UNALIGNED *)FixupVA += Diff;
      break;

    case IMAGE_REL_BASED_MIPS_JMPADDR:
      //
      // JumpAddress - (32-bits) relocate a MIPS jump address.
      //
      Temp = (*(PULONG)FixupVA & 0x3ffffff) << 2;
      Temp += (ULONG) Diff;
      *(PULONG)FixupVA = (*(PULONG)FixupVA & ~0x3ffffff) |
        ((Temp >> 2) & 0x3ffffff);
      break;

    case IMAGE_REL_BASED_ABSOLUTE:
      //
      // Absolute - no fixup required.
      //
      break;

    default:
      //
      // Illegal - illegal relocation type.
      //

      return (PIMAGE_BASE_RELOCATION)NULL;
    }
    ++NextOffset;
  }
  return (PIMAGE_BASE_RELOCATION)NextOffset;
}


BOOLEAN WINAPI ProcessReloc(HPEMODULE module)
{
  PIMAGE_NT_HEADERS		      imageHeader;
  PIMAGE_DATA_DIRECTORY     imageData;
  PIMAGE_BASE_RELOCATION    relocDescriptor;
  DWORD                     totalSize;
  ULONG                     sizeOfBlock;
  PVOID                     p;
  PUSHORT                   nextOffset;
  LONGLONG                  diff;
  ULONGLONG                 oldBase;
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)module;
  PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG)pDosHeader + pDosHeader->e_lfanew);

  imageHeader = GetImageNtHeader(module);
  switch (imageHeader->OptionalHeader.Magic)
  {
  case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
    oldBase = ((PIMAGE_NT_HEADERS32)imageHeader)->OptionalHeader.ImageBase;
    break;
  case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
    oldBase = ((PIMAGE_NT_HEADERS64)imageHeader)->OptionalHeader.ImageBase;
    break;
  default:
    return FALSE;
    break;
  }

  diff = (ULONG_PTR)module - oldBase;

  imageData = &(imageHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
  relocDescriptor = (PIMAGE_BASE_RELOCATION)(imageData->VirtualAddress + (ULONG_PTR)module);
  if (relocDescriptor == NULL)
  {
    return FALSE;
  }

  totalSize = imageData->Size;

  while (totalSize > 0)
  {
    sizeOfBlock = relocDescriptor->SizeOfBlock;
    totalSize -= sizeOfBlock;
    sizeOfBlock -= sizeof(IMAGE_BASE_RELOCATION);
    sizeOfBlock /= sizeof(USHORT);
    nextOffset = (PUSHORT)((PCHAR)relocDescriptor + sizeof(IMAGE_BASE_RELOCATION));

    p = (PVOID)((ULONG_PTR)module + relocDescriptor->VirtualAddress);

    relocDescriptor = LdrProcessRelocationBlockLongLong(
      (ULONG_PTR)p,
      sizeOfBlock,
      nextOffset,
      diff);
    if (relocDescriptor == NULL)
    {
      return FALSE;
      break;
    }
  }

  return TRUE;
}

BOOLEAN WINAPI ReplaceGlobalReloc(HPEMODULE module, ULONG_PTR va, ULONG_PTR newVa)
{
  PIMAGE_NT_HEADERS		      imageHeader;
  PIMAGE_DATA_DIRECTORY     imageData;
  PIMAGE_BASE_RELOCATION    relocDescriptor;
  DWORD                     totalSize;
  ULONG                     sizeOfBlock;
  PVOID                     p;
  PUSHORT                   nextOffset;
  LONGLONG                  diff;
  ULONGLONG                 oldBase;
  PULONG                    fixupVA;
  USHORT                    offset;

  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)module;
  PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG)pDosHeader + pDosHeader->e_lfanew);

  imageHeader = GetImageNtHeader(module);
  switch (imageHeader->OptionalHeader.Magic)
  {
  case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
    oldBase = ((PIMAGE_NT_HEADERS32)imageHeader)->OptionalHeader.ImageBase;
    break;
  case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
    oldBase = ((PIMAGE_NT_HEADERS64)imageHeader)->OptionalHeader.ImageBase;
    break;
  default:
    return FALSE;
    break;
  }

  diff = (ULONG_PTR)module - oldBase;

  imageData = &(imageHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
  relocDescriptor = (PIMAGE_BASE_RELOCATION)(imageData->VirtualAddress + (ULONG_PTR)module);
  if (relocDescriptor == NULL)
  {
    return FALSE;
  }

  totalSize = imageData->Size;

  while (totalSize > 0)
  {
    sizeOfBlock = relocDescriptor->SizeOfBlock;
    totalSize -= sizeOfBlock;
    sizeOfBlock -= sizeof(IMAGE_BASE_RELOCATION);
    sizeOfBlock /= sizeof(USHORT);
    nextOffset = (PUSHORT)((PCHAR)relocDescriptor + sizeof(IMAGE_BASE_RELOCATION));

    p = (PVOID)((ULONG_PTR)module + relocDescriptor->VirtualAddress);

    while (sizeOfBlock--)
    {
      offset = *nextOffset & (USHORT)0xfff;
      fixupVA = (PULONG)((PCHAR)p + offset);
      if (*fixupVA == va)
      {
        SafeWrite(fixupVA, newVa);
      }
      ++nextOffset;
    }

    relocDescriptor = (PIMAGE_BASE_RELOCATION)nextOffset;
  }
  return TRUE;
}

HPEMODULE WINAPI MemoryLoad(LPVOID buffer, DWORD bufferLength)
{
  HPEMODULE moduleBuffer = NULL;
  BOOLEAN   success = FALSE;

  __try
  {
    moduleBuffer = AlignFileToMem(buffer, &bufferLength);
    if (moduleBuffer == NULL)
    {
      __leave;
    }

    if (!ProcessIat(moduleBuffer))
    {
      __leave;
    }

    if (!ProcessReloc(moduleBuffer))
    {
      __leave;
    }
    success = TRUE;
  }
  __finally
  {
  }

  if (!success && moduleBuffer != NULL)
  {
    VirtualFree(moduleBuffer, bufferLength, MEM_DECOMMIT);
    moduleBuffer = NULL;
  }

  return moduleBuffer;
}

HPEMODULE WINAPI PeLoad(char* fileName)
{
  HANDLE    file = INVALID_HANDLE_VALUE;
  DWORD     fileSize;
  DWORD     readSize;
  DWORD     bufferLength;
  PVOID     buffer = NULL;
  HPEMODULE moduleBuffer = NULL;
  BOOLEAN   success = FALSE;

  __try
  {
    file = CreateFileA(
      fileName,
      GENERIC_READ,
      FILE_SHARE_READ,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL
      );
    if (file == INVALID_HANDLE_VALUE)
    {
      __leave;
    }

    fileSize = GetFileSize(file, NULL);
    if (fileSize == INVALID_FILE_SIZE)
    {
      __leave;
    }

    buffer = m_malloc(fileSize);
    if (buffer == NULL)
    {
      __leave;
    }

    if (!ReadFile(file, buffer, fileSize, &readSize, NULL))
    {
      __leave;
    }

    bufferLength = readSize;
    moduleBuffer = AlignFileToMem(buffer, &bufferLength);
    if (moduleBuffer == NULL)
    {
      __leave;
    }

    if (!ProcessIat(moduleBuffer))
    {
      __leave;
    }

    if (!ProcessReloc(moduleBuffer))
    {
      __leave;
    }
    success = TRUE;
  }
  __finally
  {
  }

  if (file != INVALID_HANDLE_VALUE)
  {
    CloseHandle(file);
  }

  if (buffer != NULL)
  {
    m_free(buffer, fileSize);
  }

  if (!success && moduleBuffer != NULL)
  {
    VirtualFree(moduleBuffer, bufferLength, MEM_DECOMMIT);
    moduleBuffer = NULL;
  }

  return moduleBuffer;
}

void WINAPI ClearModuleHeader(HPEMODULE module)
{
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)module;
  PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG)pDosHeader + pDosHeader->e_lfanew);

  ::m_memset(pDosHeader, 0, sizeof(IMAGE_DOS_HEADER));
  ::m_memset(pNtHeaders, 0, sizeof(IMAGE_NT_HEADERS));
}