#include "stdafx.h"
#include <Windows.h>
#include "crt.h"

DWORD GetHeroAddrPFunc();
void  MainDraw(DWORD HeroAddr);

// λ�ýṹ��x,y����˵��unknown��3F800000��������1.0
struct Pos
{
  DWORD x,y,unknow;
};


DWORD g_StormBase;
DWORD g_GameBase;

// storm.dll�ĵ�ַ
DWORD GetStromAddr()
{
  if (g_StormBase == NULL)
  {
    g_StormBase = (DWORD)GetModuleHandleA("Storm.dll");
  }
  return g_StormBase;
}

// game.dll�ĵ�ַ
DWORD GetGameAddr()
{
  if (g_GameBase == NULL)
  {
    g_GameBase = (DWORD)GetModuleHandleA("Game.dll");
  }
  return g_GameBase;
}

//��ȡӢ�۱�ͷ
DWORD  GetHeroAddrPFunc()
{
  DWORD HeroAddrPoint=0;
  DWORD Addr=0x55514+GetStromAddr();

  if (*(DWORD*)Addr == 0)
  {
    DWORD Addr = GetStromAddr() + 0x23E0c;
    Addr = *(DWORD*)Addr;
    Addr = Addr + 0x69 * 4;
  }
  // Addr = (DWORD)g_Pools + 0x69 * 4;
  m_memcpy(&HeroAddrPoint, (void*)(Addr), 4);
  HeroAddrPoint = *(DWORD*)Addr;

  if(*(DWORD*)(HeroAddrPoint+0x88)!=0x18)
    return 0;

  HeroAddrPoint=HeroAddrPoint+0x98;
  // �ر�ע�⣬���ﷵ��ֵ����Ϊ0��
  return HeroAddrPoint;
}

// ֻҪ��ĳЩ�ط�HOOK��������������Ϳ���С��ͼ�ϻ���Ӣ�۵�λ
void AllDraw()
{
  DWORD   HeroPoint,HeroNext;

  HeroPoint = GetHeroAddrPFunc();
  if (HeroPoint == 0)
  {
    return;
  }
  // ȡ����һ����λ�ĵ�ַ
  HeroNext = *(DWORD*)HeroPoint;
  while (HeroNext != 0)
  {
    BYTE  Dead = 0;
    Dead = *(BYTE*)(HeroNext+0x20);
    if(Dead==0x46)
    {
      // û���ͻ�
      MainDraw(HeroNext);
    }

    // ��������
    HeroPoint += 0x18;
    //ȡ����һ����λ��ַ��ֱ��Ϊ0��ʾû����
    HeroNext = *(DWORD*)HeroPoint;
  }
}

// ���ͼ����תС��ͼ�����call �������в����ġ�����naked�Ͳ�д��
void  _declspec(naked) ConvertPos()
{
  _asm
  {
    push ebp
    mov ebp,esp
    pushad
    pushfd
    mov   edx,[ebp+0xc]
    mov   ecx,[ebp+0x10]
    push  DWORD PTR SS:[ebp+8]
    push  eax
    PUSH  ESI
    MOV   ESI,DWORD PTR SS:[ESP+0x8]
    FLD   DWORD PTR DS:[ESI+0xC]
    MOV   EAX,ECX
    FMUL  DWORD PTR DS:[EDX+4]
    FLD   DWORD PTR DS:[EDX]
    FMUL  DWORD PTR DS:[ESI]
    FADDP ST(1),ST
    FLD   DWORD PTR DS:[ESI+0x18]
    FMUL  DWORD PTR DS:[EDX+0x8]
    FADDP ST(1),ST
    FSTP  DWORD PTR DS:[EAX]
    FLD   DWORD PTR DS:[ESI+0x4]
    FMUL  DWORD PTR DS:[EDX]
    FLD   DWORD PTR DS:[ESI+0x10]
    FMUL  DWORD PTR DS:[EDX+4]
    FADDP ST(1),ST
    FLD   DWORD PTR DS:[ESI+0x1C]
    FMUL  DWORD PTR DS:[EDX+8]
    FADDP ST(1),ST
    FSTP  DWORD PTR DS:[EAX+4]
    FLD   DWORD PTR DS:[ESI+8]
    FMUL  DWORD PTR DS:[EDX]
    FLD   DWORD PTR DS:[ESI+0x14]
    FMUL  DWORD PTR DS:[EDX+4]
    FADDP ST(1),ST
    FLD   DWORD PTR DS:[ESI+0x20]
    POP   ESI
    FMUL  DWORD PTR DS:[EDX+8]
    FADDP ST(1),ST
    FSTP  DWORD PTR DS:[EAX+8]
    pop   eax
    add   esp,4
    popfd
    popad
    mov   esp,ebp
    pop   ebp
    retn
  }
}

DWORD  GetHeroLC(DWORD HeroAddr)
{
  return *(DWORD*)(HeroAddr + 0x58);
}

// ��ȡ�����ַ�������Ҫ�Ľṹ
void  GetHeroLocData(DWORD HeroAddr, Pos* p)
{
  p->x = *(DWORD*)(HeroAddr + 0x284);
  p->y = *(DWORD*)(HeroAddr + 0x288);
  // ����1.0
  p->unknow = 0x3f800000;
}

void  MainDraw(DWORD HeroAddr)
{
  Pos   pReal;
  Pos   pChange;
  DWORD lc;
  DWORD Gaddr;
  DWORD StartAddr;
  DWORD TempCount;
  DWORD Judge;
  DWORD CopyAddr;
  DWORD Offset;

  lc = GetHeroLC(HeroAddr);
  // ��ȡ���ͼ����
  GetHeroLocData(HeroAddr,&pReal);
  Gaddr = GetGameAddr();

  // �Ѵ��ͼת��С��ͼ
  DWORD   MiniVal = *(DWORD*)(Gaddr+0xACD06C);
  LPVOID  p1 = &pChange;
  LPVOID  p2 = &pReal;
  DWORD   p3 = MiniVal+0x750;

  _asm
  {
    pushad
    push  p1
    push  p2
    push  p3
    call  ConvertPos
    add   esp,0xc
    popad
  }

  /*����ǵ��ˣ������GetHeroLC�����ڼ������¥�㡣��һ����ǡ�
  ���е�Ӣ�۵�λ����һ�����飬1��ʾҪ��ͼ��0��ʾ��Ҫ��ͼ��*/

  //��������,LC=¥�㡣

  //ConvertPos(MiniVal+0x750,&pReal,&pChange);
  StartAddr = *(DWORD*)(MiniVal + 0x2e4);

  //StartAddr�����������ĵ�ַ
  TempCount = *(DWORD*)(StartAddr + lc*4);
  if (TempCount != 0)
  {
    // �������������ʾҪ���ˣ�������û��Ҫ���һ��
    return;
  }

  Judge = *(DWORD*)(MiniVal + 0x2f0);
  Judge = *(DWORD*)(lc*4 + Judge);
  if (Judge == 0)
  {
    //���ﻹ�и��жϣ����ǵ��Ǹ�����ˡ�
    return;
  }

  //�����������ֵ���Ϊ1����ʾҪ������
  *(DWORD*)(StartAddr + lc*4) = TempCount + 1;

  //������ṹ�ŵ�һ��λ�ã���ħ�޻�������
  lc = lc<<4;
  CopyAddr = *(DWORD*)(lc + MiniVal + 0x2fc);
  Offset = TempCount*3;
  CopyAddr += Offset*4;
  ((Pos*)CopyAddr)->x = pChange.x;
  ((Pos*)CopyAddr)->y = pChange.y;
  ((Pos*)CopyAddr)->unknow = pChange.unknow;
}

DWORD   g_OldEndScene;

void __declspec(naked) HookedEndScene()
{
  __asm
  {
    pushad
    pushfd

    call AllDraw

    popfd
    popad
    jmp   g_OldEndScene
  }
}

DWORD WINAPI HookEndScene(LPVOID lpThreadParameter)
{
  DWORD     address;
  DWORD     object;
  DWORD     direct3D8;

  ::OutputDebugStringA(" ---- hook end scene ----");

  address = GetGameAddr() + 0xAC519C;
  DebugString("---- address:0x%.8x", address);

  object = *(DWORD*)address;

  direct3D8 = *(DWORD*)(object + 0x584);
  direct3D8 = *(DWORD*)direct3D8;

  g_OldEndScene = *(DWORD*)(direct3D8 + 0x8c);
  DebugString("---- old end scene:0x%.8x", g_OldEndScene);

  SafeWrite((PULONG)(direct3D8 + 0x8c), (ULONG)HookedEndScene);
  DebugString(" --- write end scenen.");
  return 0;
}