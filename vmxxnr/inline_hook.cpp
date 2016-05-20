// Copyright University of North Carolina, 2016
// Author: Kevin Snow, kzsnow@cs.unc.edu
// Author: Jan Werner, jjwerner@cs.unc.edu
#include <ntddk.h>
#include "inline_hook.h"
#include "vmxxnr.h"
#include "intrin.h"

//
// Note: the inline hooking defined here works correctly only on x86.


#define INST_NOP     0x90
#define INST_BREAKPT 0xcc
#define INST_JMPLONG 0xe9
#define INST_JMPBACK 0xf9eb
#define INST_MOV_EDI 0xff8b

#pragma pack(1)
typedef struct _DESC {
  UINT16 offset00;
  UINT16 segsel;
  CHAR unused:5;
  CHAR zeros:3;
  CHAR type:5;
  CHAR DPL:2;
  CHAR P:1;
  UINT16 offset16;
} DESC, *PDESC;
#pragma pack()

#pragma pack(1)
typedef struct _IDTR {
  UINT16 bytes;
  UINT32 addr;
} IDTR;
#pragma pack()

//
// Verify that function can be redirected: is the address valid, is there
// enough space to place long jump to function hook.
//
bool IsValidFunctionForHooking(PVOID Function) {
  if (!MmIsAddressValid(Function)) {
    DbgPrint("kspi: inline hooking invalid function address (0x%08X)\r\n",
      Function);
    return FALSE;
  }
  if (*((PUSHORT)Function) != INST_MOV_EDI) {
    DbgPrint("kspi: tried to hook function without 'mov edi,edi' (0x%02X)\r\n",
      *(PUSHORT)Function);
    return FALSE;
  }
  if ((*((PULONG)((UINT32)Function-5)) != 0xCCCCCCCC) &&
    (*((PULONG)((UINT32)Function-5)) != 0x90909090)) {
    DbgPrint("kspi: inline hooking a function without padding (0x%08X)\r\n",
      *(PULONG)((UINT32)Function-5));
    return FALSE;
  }
  return TRUE;
}

//
// Function to insert a function redirection to NotifyRoutine
//
int SetFunctionNotifyRoutine(PVOID Function, PVOID NotifyRoutine) {
  if (!IsValidFunctionForHooking(Function)) {
    return 0;
  }
  if (!MmIsAddressValid(NotifyRoutine)) {
    DbgPrint("kspi: inline hooking with invalid notify routine (0x%08X)\r\n",
      NotifyRoutine);
    return 0;
  }
  __writecr0(__readcr0() & 0xFFFEFFFF);
    // Write JMP in NOP/BP padded area before function entry
  InterlockedExchange8((PCHAR)(((UINT32)Function)-5),
    (UCHAR)INST_JMPLONG); // JMP
  InterlockedExchange((PLONG)(((UINT32)Function-4)),
    (LONG)(((UINT32)NotifyRoutine) - ((UINT32)Function))); // ADDR
  // Write short JMP backwards to padded area, overwriting
  // mov edi, edi at function entry
  InterlockedExchange16((PSHORT)Function, (USHORT)INST_JMPBACK);
  __writecr0(__readcr0() | 0x00010000);
  return 1;
}

//
// Function to remove redirection from Function and restore function padding.
//
int RemoveFunctionNotifyRoutine(PVOID Function) {
  if (!MmIsAddressValid(Function)) {
    DbgPrint("kspi: inline hooking invalid function address (0x%08X)\r\n",
      Function);
    return 0;
  }
  __writecr0(__readcr0() & 0xFFFEFFFF);
  // Write back 'mov edi, edi' at function entry
  InterlockedExchange16((PSHORT)Function, (USHORT)INST_MOV_EDI);
  RtlFillMemory((PSHORT)((UINT32)Function-5), 5, INST_BREAKPT);
  __writecr0(__readcr0() | 0x00010000);
  return 1;
}

//
// Function to retrieve Page Fault Handler function pointer from IDT
//
PVOID GetMmAccessFaultAddress() {
  // First get the page fault interrupt service routine (pf_isr) from the IDT
  IDTR idt;
  _disable();
  __sidt(&idt);
  _enable();
  PDESC pf_entry = (PDESC)(idt.addr + 14 * 0x8);
  PUCHAR pf_isr = (PUCHAR)((pf_entry->offset16 << 16) + pf_entry->offset00);
  // Now scan the page fault ISR code for the first call instruction,
  // which should point us to the relative offset of MmAccessFault().
  PUCHAR code = pf_isr;
  do {
    // Is this a call rel32 instruction?
    if (*code != 0xe8)
      continue;
    // If so, compute the absolute target address
    UINT32 MmAccessFault = *((PINT32)(code+1)) + (INT32)(code+5);
    // Double-check that it points to a hookable function
    if (!IsValidFunctionForHooking((PVOID)MmAccessFault))
      continue;
    return (PVOID)MmAccessFault;
  } while (++code - pf_isr < 1000);
  return NULL;
}