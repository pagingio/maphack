#include "stdafx.h"
#include <Windows.h>
#include "crt.h"

DWORD GetHeroAddrPFunc();
void  MainDraw(DWORD HeroAddr);

// 位置结构。x,y不多说，unknown是3F800000。浮点数1.0
struct Pos
{
  DWORD x,y,unknow;
};


DWORD g_StormBase;
DWORD g_GameBase;

// storm.dll的地址
DWORD GetStromAddr()
{
  if (g_StormBase == NULL)
  {
    g_StormBase = (DWORD)GetModuleHandleA("Storm.dll");
  }
  return g_StormBase;
}

// game.dll的地址
DWORD GetGameAddr()
{
  if (g_GameBase == NULL)
  {
    g_GameBase = (DWORD)GetModuleHandleA("Game.dll");
  }
  return g_GameBase;
}

//获取英雄表头
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
  // 特别注意，这里返回值可能为0；
  return HeroAddrPoint;
}

// 只要在某些地方HOOK，调用这个函数就可以小地图上画出英雄单位
void AllDraw()
{
  DWORD   HeroPoint,HeroNext;

  HeroPoint = GetHeroAddrPFunc();
  if (HeroPoint == 0)
  {
    return;
  }
  // 取出第一个单位的地址
  HeroNext = *(DWORD*)HeroPoint;
  while (HeroNext != 0)
  {
    BYTE  Dead = 0;
    Dead = *(BYTE*)(HeroNext+0x20);
    if(Dead==0x46)
    {
      // 没死就画
      MainDraw(HeroNext);
    }

    // 链表自增
    HeroPoint += 0x18;
    //取出下一个单位地址。直到为0表示没有了
    HeroNext = *(DWORD*)HeroPoint;
  }
}

// 大地图坐标转小地图坐标的call 本来是有参数的。这里naked就不写了
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

// 获取坐标地址。填充需要的结构
void  GetHeroLocData(DWORD HeroAddr, Pos* p)
{
  p->x = *(DWORD*)(HeroAddr + 0x284);
  p->y = *(DWORD*)(HeroAddr + 0x288);
  // 浮点1.0
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
  // 获取大地图坐标
  GetHeroLocData(HeroAddr,&pReal);
  Gaddr = GetGameAddr();

  // 把大地图转到小地图
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

  /*这里记得了，上面的GetHeroLC是用于计算玩家楼层。有一个标记。
  所有的英雄单位还有一个数组，1表示要画图，0表示不要画图。*/

  //想起来了,LC=楼层。

  //ConvertPos(MiniVal+0x750,&pReal,&pChange);
  StartAddr = *(DWORD*)(MiniVal + 0x2e4);

  //StartAddr就是这个数组的地址
  TempCount = *(DWORD*)(StartAddr + lc*4);
  if (TempCount != 0)
  {
    // 如果数组里面显示要画了，那我们没必要多此一举
    return;
  }

  Judge = *(DWORD*)(MiniVal + 0x2f0);
  Judge = *(DWORD*)(lc*4 + Judge);
  if (Judge == 0)
  {
    //这里还有个判断，不记得是干嘛的了。
    return;
  }

  //把数组里面的值标记为1，表示要画出来
  *(DWORD*)(StartAddr + lc*4) = TempCount + 1;

  //把这个结构放到一个位置，让魔兽画出来。
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