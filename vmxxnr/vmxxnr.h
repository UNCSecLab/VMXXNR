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

#ifndef VMXXNR_H
#define VMXXNR_H

#include <ntddk.h>

//
// Architecture-specific defines and structures
//
#define PPI_SHIFT 30
#define PTI_SHIFT 12
#define PAGE_SIZE 0x1000
#define MI_FAULT_STATUS_INDICATES_EXECUTION(_FaultStatus) (_FaultStatus & 0x8)
#define MI_FAULT_STATUS_INDICATES_WRITE(_FaultStatus) (_FaultStatus & 0x1)

#ifdef _X86_

#define MM_LOWEST_SYSTEM_ADDRESS (PVOID)0xC0C00000
#define PTE_BASE 0xc0000000
#define PDE_BASE 0xc0600000
#define PTE_TOP  0xC07FFFFF
#define PDE_TOP  0xC0603FFF

#define PAGETABLE_MAP       (0xc0000000)
#define PAGEDIRECTORY_MAP   (0xc0000000 + (PAGETABLE_MAP / (1024)))
#define MiGetPdeAddress(x) \
    ((PMMPTE)(((((ULONG)(x)) >> 22) << 2) + PAGEDIRECTORY_MAP))
#define MiGetPteAddress(x) \
    ((PMMPTE)(((((ULONG)(x)) >> 12) << 2) + PAGETABLE_MAP))
#define MiGetPteOffset(x) \
    ((((ULONG)(x)) << 10) >> 22)

#define MiGetPdeAddressPae(VirtualAddress) \
  ( (PMMPTE_PAE)(((((ULONG)VirtualAddress)>>PDI_SHIFT)<<3)+PDE_BASE))
#define MiGetPteAddressPae(VirtualAddress) \
  ( (PMMPTE_PAE)(((((ULONG)VirtualAddress)>>PTI_SHIFT)<<3)+PTE_BASE))

typedef struct _HARDWARE_PTE_PAE {
    ULONGLONG Valid : 1;
    ULONGLONG Write : 1;
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Accessed : 1;
    ULONGLONG Dirty : 1;
    ULONGLONG LargePage : 1;
    ULONGLONG Global : 1;
    ULONGLONG CopyOnWrite : 1;
    ULONGLONG Prototype : 1;
    ULONGLONG reserved0 : 1;
    ULONGLONG PageFrameNumber : 26;
    ULONGLONG reserved1 : 25;
    ULONGLONG NoExecute : 1;
} HARDWARE_PTE_PAE, *PHARDWARE_PTE_PAE;

typedef struct _HARDWARE_PTE {
    ULONG Valid : 1;
    ULONG Write : 1;
    ULONG Owner : 1;
    ULONG WriteThrough : 1;
    ULONG CacheDisable : 1;
    ULONG Accessed : 1;
    ULONG Dirty : 1;
    ULONG LargePage : 1;
    ULONG Global : 1;
    ULONG CopyOnWrite : 1; // software field
    ULONG Prototype : 1;   // software field
    ULONG reserved : 1;  // software field
    ULONG PageFrameNumber : 20;
} HARDWARE_PTE, *PHARDWARE_PTE;

typedef HARDWARE_PTE MMPTE;
typedef PHARDWARE_PTE PMMPTE;
typedef HARDWARE_PTE_PAE MMPTE_PAE;
typedef PHARDWARE_PTE_PAE PMMPTE_PAE;

#elif _WIN64

// The amd64 data structures are provided here in preparation
// for supporting 64-bit, but not yet tested.

#define MM_LOWEST_SYSTEM_ADDRESS (PVOID)0xFFFF080000000000
#define _HARDWARE_PTE_WORKING_SET_BITS  11
#define PTE_SHIFT 3
#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((ULONG_PTR)1) << VIRTUAL_ADDRESS_BITS) - 1)
#define MiGetPdeAddress(va)  \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) \
      >> PDI_SHIFT) << PTE_SHIFT) + PDE_BASE))
#define MiGetPteAddress(va) \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) \
      >> PTI_SHIFT) << PTE_SHIFT) + PTE_BASE))

typedef struct _HARDWARE_PTE {
    ULONG64 Valid : 1;
    ULONG64 Write : 1;
    ULONG64 Owner : 1;
    ULONG64 WriteThrough : 1;
    ULONG64 CacheDisable : 1;
    ULONG64 Accessed : 1;
    ULONG64 Dirty : 1;
    ULONG64 LargePage : 1;
    ULONG64 Global : 1;
    ULONG64 CopyOnWrite : 1;
    ULONG64 Prototype : 1;
    ULONG64 reserved0 : 1;
    ULONG64 PageFrameNumber : 28;
    ULONG64 reserved1 : 24 - (_HARDWARE_PTE_WORKING_SET_BITS+1);
    ULONG64 SoftwareWsIndex : _HARDWARE_PTE_WORKING_SET_BITS;
    ULONG64 NoExecute : 1;
} MMPTE, *PMMPTE;

#endif  // _WIN64


typedef struct {
  UINT32 system_wide;      // If set, ignore blacklist and protect system-wide
  bool   using_pae;        // Indicates if PAE is in use
} *PDRIVER_OPTIONS, DRIVER_OPTIONS;


typedef NTSTATUS(*MMACCESSFAULT)(ULONG_PTR, PVOID, KPROCESSOR_MODE, PVOID);


#endif  // VMXXNR_H