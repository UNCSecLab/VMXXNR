// Copyright University of North Carolina, 2016
// Author: Kevin Snow, kzsnow@cs.unc.edu
// Author: Jan Werner, jjwerner@cs.unc.edu
#ifndef VMXXNR_INLINE_HOOK_H
#define VMXXNR_INLINE_HOOK_H

// For now this library only supports hooking functions that follow a certain
// format, e.g.:
//   ret                 <-- previous function end
//   90 nop (or CC)
//   90 nop (or CC)      <-- 0x90 or 0xCC padding
//   90 nop (or CC)          between functions
//   90 nop (or CC)
//   90 nop (or CC)
//   8B FF mov edi, edi  <-- function start
//   55    push ebp
//   8B EC mov ebp, esp
//   ...
int SetFunctionNotifyRoutine(PVOID Function, PVOID NotifyRoutine);
int RemoveFunctionNotifyRoutine(PVOID Function);
PVOID GetMmAccessFaultAddress();

#endif  // VMXXNR_INLINE_HOOK_H