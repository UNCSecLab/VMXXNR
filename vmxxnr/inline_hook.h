// Copyright University of North Carolina, 2016
// Author: Kevin Snow, kzsnow@cs.unc.edu
// Author: Jan Werner, jjwerner@cs.unc.edu
//
//    This file is part of VMXXNR.
//
//    VMXXNR is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Lesser General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    VMXXNR is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Lesser General Public License for more details.
//
//    You should have received a copy of the GNU Lesser General Public License
//    along with VMXXNR.  If not, see <http://www.gnu.org/licenses/>.

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