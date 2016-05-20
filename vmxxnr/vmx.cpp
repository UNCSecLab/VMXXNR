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

//
// This driver implements a thin hypervisor.
// This hypervisor used EPT page execute and read permissions to implement
// an execute-but-don't-read strategy for protecting against memory
// disclosure attacks such as JIT-ROP.
//

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "intrin.h"
#include "vmx.h"
#include "vmxxnr.h"

VMXXNR xnr;  // dom0 guest state



//
// A few defines and macros that are private to the VMX module.
//
#define VM_VPID 1
#define PAGE_SIZE_1G (1*1024*1024*1024)
#define PAGE_SIZE_2M (2*1024*1024)
#define IsBitSet(BITS,INDEX) ((BITS) & (((UINT64)1)<<(INDEX)))
#define SetBit(BITS,INDEX)   ((BITS) |  (1<<(INDEX)))
#define ClearBit(BITS,INDEX) ((BITS) & ~(1<<(INDEX)))
#define High32Bits(BITS) (((BITS) >> 32) & 0xFFFFFFFF)
#define Low32Bits(BITS) ((BITS) & 0xFFFFFFFF)
#define VmxOn(pa)      __vmx_on((pa))
#define VmxOff()       __vmx_off()
#define VmClear(pa)    __vmx_vmclear((pa))
#define VmWrite(f, v) __vmx_vmwrite((f), (v))
#define VmRead(f, v)   __vmx_vmread((f), (v))
#define VmLaunch()     __vmx_vmlaunch()
#define VmResume()     __vmx_vmresume()
#define VmPtrLd(pa)    __vmx_vmptrld((pa))
#define ReadEflags()   __readeflags()
#define ReadCR0()      __readcr0()
#define WriteCR0(Data) __writecr0(Data)
#define ReadCR3()      __readcr3()
#define WriteCR3(Data) __writecr3(Data)
#define ReadCR4()      __readcr4()
#define WriteCR4(Data) __writecr4(Data)
#define ReadCR8()      __readcr8()
#define WriteCR8(Data) __writecr8(Data)
#define ReadMSR(Msr)   __readmsr(Msr)
#define WriteMSR(Msr, Value)     __writemsr(Msr, Value)
#define ReadMSR32(Msr)           ((UINT32) __readmsr(Msr))
#define WriteMSR(Msr, Data)      __writemsr(Msr, Data)
#define InvalidatePage(Page)     __invlpg(Page)
#define WritebackInvalidate()    __wbinvd()
#define SegmentEntry(GdtBase, Selector) \
  (((PKGDTENTRY)(GdtBase))[(((Selector)&0xFFFF)>>3)])
#define SegmentLimit(Selector) __segmentlimit((Selector)&0xFFFF)

// Uncomment this macro to get debug output for each VMWrite.
// #define VmWrite(f, v)  \
//  DbgPrint("[0x%08X] %s\r\n", v, #f); __vmx_vmwrite((f), (v))

// ============================================================================
// ==================== Generic Helper Functions ==============================
// ============================================================================

//
// Function to test whether PAE is enabled
//
bool IsPaeUsed() {
  return ((ReadCR4() & 0x20) != 0);
}

#ifndef _WIN64

//
// Activates virtual machine extensions (VMX) operation in the processor.
//
unsigned char __vmx_on(ULONG VmsSupportPhysicalAddress) {
  EFLAGS eflags;
  __asm {
    PUSH  DWORD PTR 0
    PUSH  DWORD PTR VmsSupportPhysicalAddress
    _emit 0xF3  // VMXON [ESP]
    _emit 0x0F
    _emit 0xC7
    _emit 0x34
    _emit 0x24
    PUSHFD
    POP   eflags
    ADD   ESP, 8
  }
  if (eflags.CF) return 2;
  if (eflags.ZF) return 1;
  return 0;
}

//
// Initializes the specified virtual machine control structure (VMCS)
// and sets its launch state to Clear.
//
unsigned char __vmx_vmclear(ULONG VmsSupportPhysicalAddress) {
  EFLAGS eflags;
  __asm {
    PUSH  DWORD PTR 0
    PUSH  DWORD PTR VmsSupportPhysicalAddress
    _emit 0x66  // VMCLEAR [ESP]
    _emit 0x0F
    _emit 0xc7
    _emit 0x34
    _emit 0x24
    ADD   ESP, 8
    PUSHFD
    POP   eflags
  }
  if (eflags.CF) return 2;
  if (eflags.ZF) return 1;
  return 0;
}

//
// Loads the pointer to the current virtual-machine control structure (VMCS)
// from the specified address.
//
int __vmx_vmptrld(ULONG VmcsPhysicalAddress) {
  EFLAGS eflags;
  __asm {
    PUSH  DWORD PTR 0
    PUSH  DWORD PTR VmcsPhysicalAddress
    _emit 0x0F  // VMPTRLD [ESP]
    _emit 0xC7
    _emit 0x34
    _emit 0x24
    ADD   ESP, 8
    PUSHFD
    POP   eflags
  }
  if (eflags.CF) return 2;
  if (eflags.ZF) return 1;
  return 0;
}

//
// Writes the specified value to the specified field in the current
// virtual machine control structure (VMCS).
//
unsigned char __vmx_vmwrite(size_t Field, size_t FieldValue) {
  EFLAGS eflags;
  __asm {
    PUSHAD
    MOV EAX, Field
    MOV EBX, FieldValue
    _emit 0x0F  // VMWRITE EAX, EBX
    _emit 0x79
    _emit 0xC3
    POPAD
    PUSHFD
    POP   eflags
  }
  if (eflags.CF) {
    DbgPrint("vmxxnr: VMWRITE fail CF\r\n");
    return 2;
  }
  if (eflags.ZF) {
    DbgPrint("vmxxnr: VMWRITE fail ZF\r\n");
    return 1;
  }
  return 0;
}

//
// Reads a specified field from the current virtual machine control structure
// (VMCS) and places it in the specified location.
//
unsigned char __vmx_vmread(size_t Field, size_t *FieldValue) {
  EFLAGS eflags;
  UINT32 result;
  __asm {
    PUSHAD
    MOV EAX, Field
    _emit 0x0F  // VMREAD  EBX, EAX
    _emit 0x78
    _emit 0xC3
    MOV result, EBX
    POPAD
    PUSHFD
    POP   eflags
  }
  *FieldValue = result;
  if (eflags.CF) return 2;
  if (eflags.ZF) return 1;
  return 0;
}

//
// Places the calling application in VMX non-root operation state (VM enter)
// by using the current virtual-machine control structure (VMCS).
//
unsigned char __vmx_vmlaunch(void) {
  EFLAGS eflags;
  __asm {
    _emit 0x0F  // VMLAUNCH
    _emit 0x01
    _emit 0xC2
    PUSHFD
    POP   eflags
  }
  if (eflags.CF) return 2;
  if (eflags.ZF) return 1;
  return 0;
}

//
// Places the calling application in VMX non-root operation state (VM enter)
// by using the current virtual-machine control structure (VMCS).
//
unsigned char __vmx_vmresume(void) {
  EFLAGS eflags;
  __asm {
    _emit 0x0F  // VMRESUME
    _emit 0x01
    _emit 0xC3
    PUSHFD
    POP   eflags
  }
  if (eflags.CF) return 2;
  if (eflags.ZF) return 1;
  return 0;
}

//
// Allows guest software to make a call for service into the underlying
// VM monitor with the given function ID and argument.
//
void __vmx_vmcall(unsigned int id, unsigned int argc, ...) {
  if (argc > 5) {
    DbgPrint("vmxxnr: vmcall is restricted to 5 arguments or less.\r\n");
    return;
  }
  unsigned int args[5] = {0};
  va_list vl;
  va_start(vl, argc);
  for (size_t i = 0; i < argc; i++)
    args[i] = va_arg(vl, unsigned int);
  __asm {
    PUSHAD
    MOV   EAX, id
    MOV   EBX, args[0*TYPE int]
    MOV   ECX, args[1*TYPE int]
    MOV   EDX, args[2*TYPE int]
    MOV   EDI, args[3*TYPE int]
    MOV   ESI, args[4*TYPE int]
    _emit 0x0F    // VMCALL
    _emit 0x01
    _emit 0xC1
    POPAD
  }
  va_end(vl);
}

//
// Invalidates (flushes) the processor's internal and external ecaches
//
void __invd() {
  __asm {
    _emit 0x0F  // INVD
    _emit 0x08
  }
}

//
// Invalidates mappings in the translation lookaside buffers (TLBs) and
// paging-structure caches that were derived from extended page tables (EPT).
//
void __invept() {
  __asm {
    PUSH EAX
    MOV EAX, 2
    // Set 128 bits of zeros
    PUSH  DWORD PTR 0
    PUSH  DWORD PTR 0
    PUSH  DWORD PTR 0
    PUSH  DWORD PTR 0
    _emit 0x66      // INVEPT EAX, [ESP]
    _emit 0x0F
    _emit 0x38
    _emit 0x80
    _emit 0x04
    _emit 0x24
    ADD ESP, 16
    POP EAX
  }
}

//
// Invalidates mappings in the translation lookaside buffers (TLBs) and
// paging-structure caches based on virtual-processor identifier (VPID).
//
static void __invvpid(UINT32 invtype, INV_VPID_DESC desc) {
  __asm {
    PUSH EAX
    MOV EAX, invtype
    PUSH  desc.Dwords.dword1
    PUSH  desc.Dwords.dword2
    PUSH  desc.Dwords.dword3
    PUSH  desc.Dwords.dword4
    _emit 0x66      // INVVPID EAX, [ESP]
    _emit 0x0F
    _emit 0x38
    _emit 0x81
    _emit 0x04
    _emit 0x24
    ADD ESP, 16
    POP EAX
  }
}

//
// Reads the current valud of the Task state Register (TR).
//
USHORT __sseg_tr() {
  USHORT selector;
  _asm str selector;
  return selector;
}

//
// Reads the current value of the Global Descriptor Table (GDT)
//
extern "C" {
  __MACHINEX86_X64(void _sgdt(void *))
}

//
// Jump out of guest mode. The current guest begins execution
// as the host after this function call. Use this function to
// handle cases where a VMExit is unsupported by the hypervisor
// and it is more desirable to jump out of guest mode than to
// BSOD the system.
//
__declspec(naked) void VmxStopInternal(UINT32 *regs,
    UINT32 GuestEip, UINT32 GuestEsp) {
  DbgPrint("vmxxnr: VmxStop\r\n");
  __asm MOV EAX, regs[EAX]
  __asm MOV EBX, regs[EBX]
  __asm MOV ECX, regs[ECX]
  __asm MOV EDX, regs[EDX]
  __asm MOV ESI, regs[ESI]
  __asm MOV EDI, regs[EDI]
  __asm MOV EBP, regs[EBP]
  __asm MOV ESP, GuestEsp
  __asm STI
  //__asm JMP GuestEip
  UNREFERENCED_PARAMETER(GuestEip);
}

#endif

//
// Invalidates mappings in the translation lookaside buffers (TLBs) and
// paging-structure caches for all virtual-processor identifiers (VPIDs).
//
void InvVpidAllContext() {
    INV_VPID_DESC desc = {0};
    __invvpid(2, desc);
}

//
// Invalidates mappings in the translation lookaside buffers (TLBs) and
// paging-structure caches for the specified virtual-processor identifier
// (VPID) and linear address.
//
void InvVpidIndividualAddress(UINT16 vpid, UINT32 address) {
    INV_VPID_DESC desc = {0};
    int ProcessorSupportsType0InvVpid = 0;
    // Ensure the process supports this type
    if (ProcessorSupportsType0InvVpid == 1) {
        desc.Bits.LinearAddress = address;
        desc.Bits.Vpid = vpid;
        __invvpid(0, desc);
    }
    else {
        __invvpid(2, desc);
    }
}

//
// Convert the given physical address to it's virtual address counterpart.
//
PVOID phys_to_virt(PVOID addr) {
  PHYSICAL_ADDRESS phys = {0};
  phys.LowPart = (UINT32)addr;
  return MmGetVirtualForPhysical(phys);
}

//
// Retrieve the specified segment selector's base address.
//
ULONG SegmentBase(ULONG gdt_base , USHORT seg_selector) {
  ULONG base = 0;
  KGDTENTRY segDescriptor = {0};
  RtlCopyBytes( &segDescriptor, (ULONG *)
    (gdt_base + ((seg_selector&0xFFFF) >> 3) * 8), 8 );
  base = segDescriptor.BaseHi;
  base <<= 8;
  base |= segDescriptor.BaseMid;
  base <<= 16;
  base |= segDescriptor.BaseLo;
  return base;
}

//
// Retrieve the specified segment selector's access bits, per the layout
// required by Intel VMX.
//
ULONG SegmentAccess(ULONG gdt_base , ULONG seg_selector) {
  ULONG access = 0;
  RtlCopyBytes( &access, (PUCHAR)((ULONG *)
    (gdt_base + ((seg_selector&0xFFFF) >> 3) * 8)) + 5, 4 );
  access &= 0xF0FF;
  return access;
}

//
// Dump the given register state to the kernel log.
//
void DumpRegs(PREGISTER_STATE regs) {
  DbgPrint("Edi 0x%08X\r\n", regs->regs[REG_EDI]);
  DbgPrint("Esi 0x%08X\r\n", regs->regs[REG_ESI]);
  DbgPrint("Ebp 0x%08X\r\n", regs->regs[REG_EBP]);
  DbgPrint("Esp 0x%08X\r\n", regs->regs[REG_ESP]);
  DbgPrint("Ebx 0x%08X\r\n", regs->regs[REG_EBX]);
  DbgPrint("Edx 0x%08X\r\n", regs->regs[REG_EDX]);
  DbgPrint("Ecx 0x%08X\r\n", regs->regs[REG_ECX]);
  DbgPrint("Eax 0x%08X\r\n", regs->regs[REG_EAX]);
  DbgPrint("EFlags 0x%08X\r\n", regs->eflags);
}

// ============================================================================
// ==================== Extended Page Table Functions =========================
// ============================================================================

//
// Allocate a new page mapping level -- a PAGE_SIZE contiguous memory region
// for an array of 512 page mapping entries.
//
EPT_ENTRY* NewPml() {
  PHYSICAL_ADDRESS Highest = {0};
  Highest.LowPart = ~0ul;
  EPT_ENTRY* pml = NULL;
  if ((pml = (EPT_ENTRY*)
        MmAllocateContiguousMemory(PAGE_SIZE, Highest)) == 0) {
    DbgPrint("vmxxnr: pml allocation failed\r\n");
    return NULL;
  }
  RtlZeroMemory(pml, PAGE_SIZE);
  return pml;
}

//
// Retrieve the EPT entry for the given guest physical address. The last level
// entry will be return when the target level is set to one, while directory
// entries can be retrieved when the target level is set higher.
//
EPT_ENTRY* EptGetEntry(EPT_ENTRY *pml4, unsigned long guest_addr,
    int target_level) {
  EPT_ENTRY *pml = pml4;
  unsigned offset;
  int level;
  for (level = 4; level > 1; level--) {
    offset = ((unsigned long long)guest_addr>>(((level-1)*9)+12))&511;
    if (!(pml[offset].PhysAddr)) {
      DbgPrint("vmxxnr: failed to lookup ept entry @ 0x%08X\r\n", guest_addr);
      return NULL;
    }
    if ((level == target_level) || (level < 4 && pml[offset].LargePage))
      return &pml[offset];
    pml = (EPT_ENTRY*)phys_to_virt((PVOID)(pml[offset].PhysAddr << 12));
  }
  offset = ((unsigned long long)guest_addr>>(((level-1)*9)+12))&511;
  return &pml[offset];
}

//
// Allocate and initialize EPT entries for the given guest physical address.
//
bool VmxInitializeEptEntry(int pte_level, unsigned long guest_addr,
    EPT_ENTRY entry) {
  // Allocate the top level if not already allocated
  if (!xnr.pml4) {
    if ((xnr.pml4 = NewPml()) == NULL)
      return false;
    xnr.eptp = {0};
    xnr.eptp.Bits.PhysAddr =
      MmGetPhysicalAddress(xnr.pml4).LowPart >> 12;
    xnr.eptp.Bits.PageWalkLength = 3;
    xnr.eptp.Bits.MemoryType = 6;  //memory caching options
  }
  // Next, handle all the directory entries leading up to the page entry
  EPT_ENTRY *pml = xnr.pml4;
  unsigned offset;
  int level;
  for (level = 4; level > pte_level; level--) {
    offset = ((unsigned long long)guest_addr>>((level-1)*9+12))&511;
    if (!(pml[offset].PhysAddr)) {
      // Entry does not exist, create it
      EPT_ENTRY *newEntry;
      if ((newEntry = NewPml()) == NULL)
        return false;
      pml[offset].Read = 1;
      pml[offset].Write = 1;
      pml[offset].Execute = 1;
      pml[offset].PhysAddr = MmGetPhysicalAddress(newEntry).LowPart >> 12;
    } else {
      // Entry exists, remove large page attribute if set
      pml[offset].LargePage = 0;
    }
    // Set the active page mapping to the next level for use
    // in the next iteration of the loop
    pml = (EPT_ENTRY*)phys_to_virt((PVOID)(pml[offset].PhysAddr << 12));
  }
  // Now handle the page entry itself
  offset = ((unsigned long long)guest_addr>>((level-1)*9+12))&511;
  entry.MemoryType = 6;
  pml[offset] = entry;
  return true;
}

//
// Allocate and initialize EPT entries for the given guest physical range. Use
// either 4KB, 2MB, or 1GB pages depending on the map flags.
//
bool VmxInitializeEpt(unsigned long start, unsigned long len,
    int map_1g, int map_2m) {
  __int64 phys = (__int64)start;
  __int64 max = (__int64)len+(__int64)start;
  EPT_ENTRY entry;
  entry.Read = 1;
  entry.Write = 1;
  entry.Execute = 1;
  if (map_1g) {
    entry.LargePage = 1;
    while (phys + PAGE_SIZE_1G - 1 <= max) {
      entry.PhysAddr = phys >> 12;
      if (!VmxInitializeEptEntry(3, (unsigned long)phys, entry))
        return false;
      phys += PAGE_SIZE_1G;
    }
  }
  if (map_2m) {
    entry.LargePage = 1;
    while (phys + PAGE_SIZE_2M - 1 <= max) {
      entry.PhysAddr = phys >> 12;
      if (!VmxInitializeEptEntry(2, (unsigned long)phys, entry))
        return false;
      phys += PAGE_SIZE_2M;
    }
  }
  entry.LargePage = 0;
  while (phys + PAGE_SIZE - 1 <= max) {
    entry.PhysAddr = phys >> 12;
    if (!VmxInitializeEptEntry(1, (unsigned long)phys, entry))
      return false;
    phys += PAGE_SIZE;
  }
  return true;
}


//
// Handles hypercalls coming from the userspace
//
void NearHandleHypercall(PREGISTER_STATE guest, UINT32 GuestEip) {
	UNREFERENCED_PARAMETER(GuestEip);
	switch (guest->regs[REG_EAX]) {
    case HYPER_VMX_STOP:
      break;
    case HYPER_SINGLE_PARAM:
		DbgPrint("vmxxnr: single parameter hypercall: 0x%x\r\n",
              guest->regs[REG_EBX]);
      break;
    case HYPER_TWO_PARAMS:
		DbgPrint("vmxxnr: two parameter hypercall: 0x%x, 0x%x\r\n",
              guest->regs[REG_EBX], guest->regs[REG_ECX]);
        break;
    default:
		DbgPrint("vmxxnr: ignoring unsupported hypercall: 0x%x.\r\n");
      break;
  }
}

void NearLogEptFault(UINT32 GuestPa, UINT32 GuestEip) {
	UNREFERENCED_PARAMETER(GuestPa);
	UNREFERENCED_PARAMETER(GuestEip);
}

//
// Handles EPT faults for no-execute-after read by temporarily allowing the
// read for one instruction via the trap flag.
//
void NearHandleEptFault(PREGISTER_STATE guest, UINT32 GuestEip) {
  UNREFERENCED_PARAMETER(guest);
  UNREFERENCED_PARAMETER(GuestEip);
  UINT32 cr3;
  VmRead(GUEST_CR3, &cr3);
  unsigned int ExitQualification, GuestPa;
  VmRead(EXIT_QUALIFICATION, &ExitQualification);
  VmRead(GUEST_PHYSICAL_ADDRESS, &GuestPa);
  NearLogEptFault(GuestPa, GuestEip);
  if (ExitQualification & EPT_MASK_DATA_EXEC) {
    DbgPrint("vmxxnr: EPT execute fault. This is a bug.\r\n");
    __halt();
  } else if (ExitQualification & EPT_MASK_DATA_READ ||
    ExitQualification & EPT_MASK_DATA_WRITE) {
    // An attempt was made to read or write from an execute-only page.
    // Save pointer and value of faulting page's EPT current (protected) entry.
    // Swap in the original unprotected page EPT entry.
    // Set a trap to allow the faulting instruction to execute before fixing up.
     __invept();
  } else {
    DbgPrint("VMExit (Unhandled EPT Violation)\r\n");
  }
}

//
// Handles re-protecting a physical page for no-execute-after-read.
//
void NearHandleTrap(PREGISTER_STATE guest, UINT32 GuestEip) {
  UNREFERENCED_PARAMETER(guest);
  UNREFERENCED_PARAMETER(GuestEip);
}

// ============================================================================
// ==================== Hypervisor (VMExit Handler) ===========================
// ============================================================================

//
// Write the PDPTRs at the given CR3 address to the current VMCS.
//
void SetPdptrs(PVOID cr3) {
  PDPTRS *pdptrs = (PDPTRS*)phys_to_virt(cr3);
  VmWrite(GUEST_PDPTR0, Low32Bits(pdptrs->pdpte0));
  VmWrite(GUEST_PDPTR0_HIGH, High32Bits(pdptrs->pdpte0));
  VmWrite(GUEST_PDPTR1, Low32Bits(pdptrs->pdpte1));
  VmWrite(GUEST_PDPTR1_HIGH, High32Bits(pdptrs->pdpte1));
  VmWrite(GUEST_PDPTR2, Low32Bits(pdptrs->pdpte2));
  VmWrite(GUEST_PDPTR2_HIGH, High32Bits(pdptrs->pdpte2));
  VmWrite(GUEST_PDPTR3, Low32Bits(pdptrs->pdpte3));
  VmWrite(GUEST_PDPTR3_HIGH, High32Bits(pdptrs->pdpte3));
}

//
// Take the appropriate action for each corresponding VMExit.
//
void __cdecl VmxExit(PREGISTER_STATE guest) {
  UINT32 GuestEip;
  size_t reason, instr_len;
  VmRead(GUEST_RIP, &GuestEip);
  VmRead(VM_EXIT_INSTRUCTION_LEN, &instr_len);
  VmRead(VM_EXIT_REASON, &reason);
  // DbgPrint("VMExit Reason [0x%08X]\r\n", reason);
  // DbgPrint("Guest EIP 0x%08X, ESP 0x%08X\r\n", GuestEip, GuestEsp);
  // DumpRegs(guest);

  switch (reason) {
    case EXIT_REASON_VMCALL:
      GuestEip += instr_len;
      NearHandleHypercall(guest, GuestEip);
      break;
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
      // Hypervisor must handle all VMX instructions
      DbgPrint("VMExit (Ignoring Nested VMX operation)\r\n");
      GuestEip += instr_len;
      break;
    case EXIT_REASON_INVD:
      // Hypervisor must handle all INVD instructions
      DbgPrint("VMExit (INVD)\r\n");
      GuestEip += instr_len;
      __invd();
      break;
    case EXIT_REASON_CPUID:
      // Hypervisor must handle all CPUID instructions
      GuestEip += instr_len;
      {
        int cpuInfo[4];
        __cpuid(cpuInfo, guest->regs[REG_EAX]);
        guest->regs[REG_EAX] = cpuInfo[0];
        guest->regs[REG_EBX] = cpuInfo[1];
        guest->regs[REG_ECX] = cpuInfo[2];
        guest->regs[REG_EDX] = cpuInfo[3];
      }
      break;
    case EXIT_REASON_CR_ACCESS:
      // Hypervisor must handle all CR3 read and write instructions
      // if CR3 exit option is set.
      GuestEip += instr_len;
      {
        unsigned int ExitQualification;
        VmRead(EXIT_QUALIFICATION, &ExitQualification);
        if ((ExitQualification & 0x30) >> 4) {
          VmRead(GUEST_CR3, &(guest->regs[(ExitQualification & 0xF00 ) >> 8]));
        } else {
          VmWrite(GUEST_CR3, guest->regs[(ExitQualification & 0xF00 ) >> 8]);
          // Update the PDPTRs for PAE
          SetPdptrs((PVOID)guest->regs[(ExitQualification & 0xF00 ) >> 8]);
          InvVpidAllContext();
        }
      }
      break;
    case EXIT_REASON_MSR_READ:
      // Hypervisor must handle all MSR read and write instructions
      {
        __int64 msr = ReadMSR(guest->regs[REG_ECX]);
        guest->regs[REG_EAX] = Low32Bits(msr);
        guest->regs[REG_EDX] = High32Bits(msr);
      }
      GuestEip += instr_len;
      break;
    case EXIT_REASON_MSR_WRITE:
      WriteMSR(guest->regs[REG_ECX],
        (((__int64)guest->regs[REG_EDX])<<32) + guest->regs[REG_EAX]);
      GuestEip += instr_len;
      break;
    case EXIT_REASON_EXCEPTION_NMI:
	    // We want hypervisor to trap non-maskable user interrupts e.g. traps
      NearHandleTrap(guest, GuestEip);
      break;
    case EXIT_REASON_EPT_VIOLATION:
	    // The hypervisor has to handle EPT page faults. Those faults should NOT
	    // occur unless you modify EPT table for example to track reads on
      // executable pages.
      NearHandleEptFault(guest, GuestEip);
      break;
    case EXIT_REASON_EPT_MISCONFIG:
      DbgPrint("VMExit (EPT Misconfiguration)\r\n");
      // 25.2.3.1 EPT Misconfigurations
      //   AN EPT misconfiguration occurs if any of the following is identified
      //   while translating a guest-physical address:
      //     -The value is either 010b (write-only) or 110b (write/execute).
      //     -The value is 100b (execute-only) and IA32_VMX_EPT_VPID_CAP is not
      //      supported.
      __halt();
      break;
    case EXIT_REASON_TRIPLE_FAULT:
      DbgPrint("VMExit (Triple Fault)\r\n");
      __halt();
      break;
    default:
      DbgPrint("VMExit (Unhandled VMExit Reason 0x%08X)\r\n", reason);
      break;
  }
  VmWrite(GUEST_RIP, GuestEip);
}

//
// The hypervisor entry point. This function is called on every VMExit.
// It saves register state, handles the exit reason, restores register
// state, then finally resumes the guest. Performance is critical here.
//
#pragma optimize("", off)
__declspec(naked) void __hyper_entry() {
  __asm CLI
  __asm MOV xnr.guest_state.regs[REG_EAX*TYPE UINT32] , EAX
  __asm MOV xnr.guest_state.regs[REG_EBX*TYPE UINT32] , EBX
  __asm MOV xnr.guest_state.regs[REG_ECX*TYPE UINT32] , ECX
  __asm MOV xnr.guest_state.regs[REG_EDX*TYPE UINT32] , EDX
  __asm MOV xnr.guest_state.regs[REG_EDI*TYPE UINT32] , EDI
  __asm MOV xnr.guest_state.regs[REG_ESI*TYPE UINT32] , ESI
  __asm MOV xnr.guest_state.regs[REG_EBP*TYPE UINT32] , EBP
  VmxExit(&xnr.guest_state);
  __asm MOV EAX, xnr.guest_state.regs[REG_EAX*TYPE UINT32]
  __asm MOV EBX, xnr.guest_state.regs[REG_EBX*TYPE UINT32]
  __asm MOV ECX, xnr.guest_state.regs[REG_ECX*TYPE UINT32]
  __asm MOV EDX, xnr.guest_state.regs[REG_EDX*TYPE UINT32]
  __asm MOV EDI, xnr.guest_state.regs[REG_EDI*TYPE UINT32]
  __asm MOV ESI, xnr.guest_state.regs[REG_ESI*TYPE UINT32]
  __asm MOV EBP, xnr.guest_state.regs[REG_EBP*TYPE UINT32]
  __asm STI
  __asm {
    _emit 0x0F  // VMRESUME
    _emit 0x01
    _emit 0xC3
  }
}
#pragma optimize("", on)

// ============================================================================
// ==================== DOM0 Setup // Host Mirroring ==========================
// ============================================================================

bool VmxMirrorHost() {
  CONTEXT state;
  state.ContextFlags = CONTEXT_FULL;
  RtlCaptureContext(&state);
  state.SegEs &= 0xFFFF;
  state.SegCs &= 0xFFFF;
  state.SegSs &= 0xFFFF;
  state.SegDs &= 0xFFFF;
  state.SegFs &= 0xFFFF;
  state.SegGs &= 0xFFFF;
  IDTR idt, gdt;
  __sidt(&idt);
  _sgdt(&gdt);
  //
  // ----------------- Guest -------------------
  //
  // Guest Control registers CR0, CR3, and CR4
  VmWrite(GUEST_CR0,
      ClearBit(SetBit(SetBit(SetBit(ReadCR0(), 0), 5), 31),30));  // PE+NE+PG-CD
  VmWrite(GUEST_CR3, ReadCR3());
  VmWrite(GUEST_CR4, SetBit(ReadCR4(), 13));  // VMXE
  //
  //
  // Guest RSP, RIP, and RFLAGS
  VmWrite(GUEST_RSP, xnr.GuestStack);
  VmWrite(GUEST_RIP, xnr.GuestReturn);
  DbgPrint("setting eflags to 0x%x\r\n", ReadEflags());
  VmWrite(GUEST_RFLAGS, ReadEflags() | 0x100000);

  //
  // Guest Segment registers CS, SS, DS, ES, FS, GS, LDTR, and TR
  // selector, base, limit, access
  VmWrite(GUEST_ES_SELECTOR, state.SegEs);
  VmWrite(GUEST_CS_SELECTOR, state.SegCs);
  VmWrite(GUEST_SS_SELECTOR, state.SegSs);
  VmWrite(GUEST_DS_SELECTOR, state.SegDs);
  VmWrite(GUEST_FS_SELECTOR, state.SegFs);
  VmWrite(GUEST_GS_SELECTOR, state.SegGs);
  VmWrite(GUEST_TR_SELECTOR, ClearBit(__sseg_tr(), 2));  // Clear TI Flag
  VmWrite(GUEST_ES_BASE, SegmentBase(gdt.base, (USHORT)state.SegEs));
  VmWrite(GUEST_CS_BASE, SegmentBase(gdt.base, (USHORT)state.SegCs));
  VmWrite(GUEST_SS_BASE, SegmentBase(gdt.base, (USHORT)state.SegSs));
  VmWrite(GUEST_DS_BASE, SegmentBase(gdt.base, (USHORT)state.SegDs));
  VmWrite(GUEST_FS_BASE, SegmentBase(gdt.base, (USHORT)state.SegFs));
  VmWrite(GUEST_TR_BASE, SegmentBase(gdt.base, (USHORT)__sseg_tr()));
  VmWrite(GUEST_ES_LIMIT, SegmentLimit(state.SegEs));
  VmWrite(GUEST_CS_LIMIT, SegmentLimit(state.SegCs));
  VmWrite(GUEST_SS_LIMIT, SegmentLimit(state.SegSs));
  VmWrite(GUEST_DS_LIMIT, SegmentLimit(state.SegDs));
  VmWrite(GUEST_FS_LIMIT, SegmentLimit(state.SegFs));
  VmWrite(GUEST_GS_LIMIT, 0xFFFFFFFF);
  VmWrite(GUEST_TR_LIMIT, SegmentLimit(__sseg_tr()));
  VmWrite(GUEST_ES_AR_BYTES, SegmentAccess(gdt.base, state.SegEs));
  VmWrite(GUEST_CS_AR_BYTES, SegmentAccess(gdt.base, state.SegCs));
  VmWrite(GUEST_SS_AR_BYTES, SegmentAccess(gdt.base, state.SegSs));
  VmWrite(GUEST_DS_AR_BYTES, SegmentAccess(gdt.base, state.SegDs));
  VmWrite(GUEST_FS_AR_BYTES, SegmentAccess(gdt.base, state.SegFs));
  // Make GS segment unuseable with bit 16
  VmWrite(GUEST_GS_AR_BYTES, SetBit(SegmentAccess(gdt.base, state.SegGs), 16));
  VmWrite(GUEST_TR_AR_BYTES, SegmentAccess(gdt.base, __sseg_tr()));
  VmWrite(GUEST_LDTR_AR_BYTES, SetBit(0, 16));  // Make LDT Unusable
  //
  // Guest GDTR and IDTR base and limit
  VmWrite(GUEST_GDTR_BASE, gdt.base);
  VmWrite(GUEST_IDTR_BASE, idt.base);
  VmWrite(GUEST_GDTR_LIMIT, gdt.limit);
  VmWrite(GUEST_IDTR_LIMIT, idt.limit);
  //
  // Guest Model-specific registers (MSRs)
  VmWrite(GUEST_SYSENTER_CS, ReadMSR32(IA32_MSR_SYSENTER_CS));
  VmWrite(GUEST_SYSENTER_ESP, ReadMSR32(IA32_MSR_SYSENTER_ESP));
  VmWrite(GUEST_SYSENTER_EIP, ReadMSR32(IA32_MSR_SYSENTER_EIP));
  VmWrite(GUEST_IA32_DEBUGCTL, Low32Bits(ReadMSR(IA32_MSR_DEBUG_CTRL)));
  VmWrite(GUEST_IA32_DEBUGCTL_HIGH, High32Bits(ReadMSR(IA32_MSR_DEBUG_CTRL)));
  //  IA32_PERF_GLOBAL_CTRL, IA32_PAT, IA32_EFER
  VmWrite(GUEST_IA32_PAT_HIGH, 0x06060606);
  VmWrite(GUEST_IA32_PAT, 0x06060606);

  //
  // Guest register SMBASE
  //
  //
  // Guest Non-Register State
  VmWrite(VMCS_LINK_POINTER, ULONG_MAX);  // Not using VMCS shadowing
  VmWrite(VMCS_LINK_POINTER_HIGH, ULONG_MAX);
  if (IsPaeUsed()) { // PAE is in use
    DbgPrint("vmxxnr: using PAE.\r\n");
    SetPdptrs((PVOID)ReadCR3());
  } else {
    DbgPrint("vmxxnr: WARNING PAE is not enabled.\r\n");
  }
  //
  // ----------------- Host -------------------
  //
  // Host Control registers CR0, CR3, and CR4
  VmWrite(HOST_CR0,
    ClearBit(SetBit(ReadCR0(), 5),30));  // Set NE Bit clear CD bit
  VmWrite(HOST_CR3, ReadCR3());
  VmWrite(HOST_CR4, ReadCR4());
  //
  // Host RSP and RIP
  VmWrite(HOST_RSP, ((ULONG)xnr.stack + 0x1FFF));
  VmWrite(HOST_RIP, (ULONG)__hyper_entry);
  //
  // Host selectors for CS, SS, DS, ES, FS, GS, and TR
  VmWrite(HOST_ES_SELECTOR, state.SegEs&0xFFFC);
  VmWrite(HOST_CS_SELECTOR, state.SegCs&0xFFFF);
  VmWrite(HOST_SS_SELECTOR, state.SegSs&0xFFFF);
  VmWrite(HOST_DS_SELECTOR, state.SegDs&0xFFFC);
  VmWrite(HOST_FS_SELECTOR, state.SegFs&0xFFFF);
  VmWrite(HOST_GS_SELECTOR, state.SegGs&0xFFFF);
  VmWrite(HOST_TR_SELECTOR, __sseg_tr()&0xFFFF);
  //
  // Host base for FS, GS, TR, GDTR, and IDTR
  VmWrite(HOST_FS_BASE, SegmentBase(gdt.base, (USHORT)state.SegFs));
  VmWrite(HOST_GS_BASE, SegmentBase(gdt.base, (USHORT)state.SegGs));
  VmWrite(HOST_TR_BASE, SegmentBase(gdt.base, (USHORT)__sseg_tr()));
  VmWrite(HOST_GDTR_BASE, gdt.base);
  VmWrite(HOST_IDTR_BASE, idt.base);
  //
  // Host Model-specific registers (MSRs)
  VmWrite(HOST_IA32_SYSENTER_CS, ReadMSR32(IA32_MSR_SYSENTER_CS));
  VmWrite(HOST_IA32_SYSENTER_ESP, ReadMSR32(IA32_MSR_SYSENTER_ESP));
  VmWrite(HOST_IA32_SYSENTER_EIP, ReadMSR32(IA32_MSR_SYSENTER_EIP));
  //  IA32_PERF_GLOBAL_CTRL, IA32_PAT, IA32_EFER

  VmWrite(HOST_IA32_PAT_HIGH,  0x06060606);
  VmWrite(HOST_IA32_PAT,  0x06060606);

  //
  // ----------------- Control -------------------
  //
  //
  // Extended Page Tables (EPT)
  VmWrite(EPT_POINTER, xnr.eptp.Val & 0xFFFFFFFF);
  VmWrite(EPT_POINTER_HIGH, 0);
  VmWrite(SECONDARY_VM_EXEC_CONTROL, 0ul | (1 << 5) | (1 << 1) );
  VmWrite(VIRTUAL_PROCESSOR_ID, VM_VPID);
  InvVpidAllContext();
  //
  // VM-Execution Control Fields
  VmWrite(PIN_BASED_VM_EXEC_CONTROL,
      ReadMSR32(IA32_MSR_VMX_PIN_BASED_VM_EXEC_CONTROL));
  VmWrite(CPU_BASED_VM_EXEC_CONTROL,  // Enable EPT, disable exit on cr3 access
       ClearBit(ClearBit(ReadMSR32(IA32_MSR_VMX_CPU_BASED_VM_EXEC_CONTROL) |
        (1 << 31),16),15));
  VmWrite(EXCEPTION_BITMAP, 0x2);  // only catch int1 exceptions (bit 1)
  VmWrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
  VmWrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);
  VmWrite(VM_EXIT_CONTROLS, ReadMSR32(IA32_MSR_VMX_VMEXIT_CTRLS));
  // Disable IA-32e Guest Mode
  VmWrite(VM_ENTRY_CONTROLS,
      ClearBit(ReadMSR32(IA32_MSR_VMX_VMENTRY_CTRLS), 9));
  RtlZeroMemory(((PUCHAR)xnr.vmcs)+4, 4);  // clear error code, if any
  return TRUE;
}

// ============================================================================
// ================= VMX Check, Allocation, Initialization ====================
// ============================================================================

//
// Checks that all necessary requirements are met by the CPU to use this
// implementation of VMX support, e.g. VMX is supported and enabled, EPT with
// execute-only bit, and VPID support.
//
bool VmxCheck() {
  int cpuInfo[4];
  __cpuid(cpuInfo, 1);
  if (!IsBitSet(cpuInfo[2], 5)) {
    DbgPrint("vmxxnr: vmx not supported\r\n");
  } else if (!IsBitSet(ReadMSR(IA32_MSR_FEATURE_CONTROL_CODE), 0)) {
    DbgPrint("vmxxnr: vmx supported, but disabled in bios\r\n");
  } else if (!IsBitSet(ReadMSR(IA32_MSR_FEATURE_CONTROL_CODE), 2)) {
    DbgPrint("vmxxnr: vmx supported, but disabled in bios\r\n");
  } else if (!IsBitSet(ReadMSR(IA32_MSR_VMX_CPU_BASED_VM_EXEC_CONTROL), 63)) {
    DbgPrint("vmxxnr: secondary not supported\r\n");
  } else if (!IsBitSet(ReadMSR(IA32_MSR_VMX_PROCBASED_CTLS2), 33)) {
    DbgPrint("vmxxnr: ept not supported\r\n");
  } else if (!IsBitSet(ReadMSR(IA32_MSR_VMX_PROCBASED_CTLS2), 35)) {
    DbgPrint("vmxxnr: vpid not supported\r\n");
  } else if (!IsBitSet(ReadMSR(IA32_MSR_VMX_EPT_VPID_CAP), 0)) {
    DbgPrint("vmxxnr: ept execute-only bit not supported\r\n");
  } else if (((ReadMSR(IA32_MSR_VMX_BASIC_MSR_CODE) >> 50) & 0xF) != 6) {
    DbgPrint("vmxxnr: vmxon memory type not supported (not write-back)\r\n");
  } else {
    return TRUE;
  }
  return FALSE;
}

//
// Frees the memory allocated by VmxAllocate.
//
void VmxFree() {
  if (xnr.vmxon) MmFreeNonCachedMemory(xnr.vmxon, PAGE_SIZE);
  if (xnr.vmcs) MmFreeNonCachedMemory(xnr.vmcs, PAGE_SIZE);
  if (xnr.ioa) MmFreeNonCachedMemory(xnr.ioa, PAGE_SIZE);
  if (xnr.iob) MmFreeNonCachedMemory(xnr.iob, PAGE_SIZE);
  if (xnr.msr) MmFreeNonCachedMemory(xnr.msr, PAGE_SIZE);
  if (xnr.vapic) MmFreeNonCachedMemory(xnr.vapic, PAGE_SIZE);
  if (xnr.stack) ExFreePoolWithTag(xnr.stack, 'kSkF');
}

//
// Allocations and initializes varialbes required for the VMCS and VMX
// operation.
//
bool VmxAllocate() {
  RtlZeroMemory(&xnr, sizeof(xnr));
  if ((xnr.vmxon = (PUCHAR)MmAllocateNonCachedMemory(PAGE_SIZE)) == 0) {
    DbgPrint("vmxxnr: vmxon allocation failed\r\n");
  } else if ((xnr.vmcs = (PUCHAR)MmAllocateNonCachedMemory(PAGE_SIZE)) == 0) {
    DbgPrint("vmxxnr: vmcs allocation failed\r\n");
  } else if ((xnr.ioa = (PUCHAR)MmAllocateNonCachedMemory(PAGE_SIZE)) == 0) {
    DbgPrint("vmxxnr: ioa allocation failed\r\n");
  } else if ((xnr.iob = (PUCHAR)MmAllocateNonCachedMemory(PAGE_SIZE)) == 0) {
    DbgPrint("vmxxnr: iob allocation failed\r\n");
  } else if ((xnr.msr = (PUCHAR)MmAllocateNonCachedMemory(PAGE_SIZE)) == 0) {
    DbgPrint("vmxxnr: msr allocation failed\r\n");
  } else if ((xnr.vapic = (PUCHAR)MmAllocateNonCachedMemory(PAGE_SIZE)) == 0) {
    DbgPrint("vmxxnr: vapic allocation failed\r\n");
  } else if ((xnr.stack = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool,
      0x2000,'kSkF')) == 0) {
    DbgPrint("vmxxnr: stack allocation failed\r\n");
  } else if (!VmxInitializeEpt(0, 0xFFFFFFFF, 0, 0)) {
    DbgPrint("vmxxnr: ept table allocation failed\r\n");
  }
  else {
    xnr.vmxon_physical = MmGetPhysicalAddress(xnr.vmxon).LowPart;
    xnr.vmcs_physical = MmGetPhysicalAddress(xnr.vmcs).LowPart;
    xnr.ioa_physical = MmGetPhysicalAddress(xnr.ioa).LowPart;
    xnr.iob_physical = MmGetPhysicalAddress(xnr.iob).LowPart;
    xnr.msr_physical = MmGetPhysicalAddress(xnr.msr).LowPart;
    xnr.vapic_physical = MmGetPhysicalAddress(xnr.vapic).LowPart;
    RtlZeroMemory(xnr.vmxon, PAGE_SIZE);
    RtlZeroMemory(xnr.vmcs, PAGE_SIZE);
    RtlZeroMemory(xnr.ioa, PAGE_SIZE);
    RtlZeroMemory(xnr.iob, PAGE_SIZE);
    RtlZeroMemory(xnr.msr, PAGE_SIZE);
    RtlZeroMemory(xnr.vapic, PAGE_SIZE);
    RtlZeroMemory(xnr.stack, 0x2000);
    // Store VMCS Rev ID at start of the VMCS and VMXON variables.
    *((PUINT32)xnr.vmxon) = ReadMSR32(IA32_MSR_VMX_BASIC_MSR_CODE);
    *((PUINT32)xnr.vmcs) = ReadMSR32(IA32_MSR_VMX_BASIC_MSR_CODE);
    return TRUE;
  }
  VmxFree();
  return FALSE;
}

//
// Performs the VMX guest start sequence to start VMX root mode operation.
// If successfull, this function does not execute past the VMLaunch(). Instead
// execution splits off in two directions given by the host and guest EIP in
// the VMCS structure.
//
// Must be naked so the stack is not off when entering guest mode.
//
#pragma optimize("", off)
__declspec( naked ) void VmxStart2() {
  //xnr.GuestReturn = (UINT32)_ReturnAddress();
  __asm POP xnr.GuestReturn
  WriteCR4(SetBit(ReadCR4(), 13));  // VMXE=1
  WriteCR0(SetBit(ReadCR0(), 5));   // NE=1
  // Activate VMX operation in the processor.
  if (VmxOn(xnr.vmxon_physical)) {
    DbgPrint("vmxxnr: vmxon failed\r\n");
  // Initialize the VMCS and set launch state to 'Clear'.
  } else if (VmClear(xnr.vmcs_physical)) {
    DbgPrint("vmxxnr: vmclear failed\r\n");
  // Load pointer to the current VMCS.
  } else if (VmPtrLd(xnr.vmcs_physical)) {
    DbgPrint("vmxxnr: vmptrld failed\r\n");
  // Write VMCS values mirroring the host.
  } else if (!VmxMirrorHost()) {
    DbgPrint("vmxxnr: failed to mirror host\r\n");
  // Enter the VM
  } else {
    DbgPrint("vmlaunch...\r\n");
    VmLaunch();
    // We only reach this point if the launch failed
    UINT32 err = 0;
    VmRead(VM_INSTRUCTION_ERROR, &err);
    DbgPrint("vmxxnr: vmlaunch failed. Error 0x%08X\r\n", err);
  }
  VmxOff();
  WriteCR4(ClearBit(ReadCR4(), 13));  // VMXE=0
}
#pragma optimize("", on)

//
// Starts the hypervisor and makes the host run as DOM0.
//
#pragma optimize("", off)
bool VmxStart() {
  if (!VmxCheck()) return FALSE;
  if (!VmxAllocate()) return FALSE;
  __asm {
    CLI
    MOV   xnr.GuestStack, ESP
    PUSHAD
    POP   xnr.guest_state.regs[REG_EDI*TYPE UINT32]
    POP   xnr.guest_state.regs[REG_ESI*TYPE UINT32]
    POP   xnr.guest_state.regs[REG_EBP*TYPE UINT32]
    POP   xnr.guest_state.regs[REG_ESP*TYPE UINT32]
    POP   xnr.guest_state.regs[REG_EBX*TYPE UINT32]
    POP   xnr.guest_state.regs[REG_EDX*TYPE UINT32]
    POP   xnr.guest_state.regs[REG_ECX*TYPE UINT32]
    POP   xnr.guest_state.regs[REG_EAX*TYPE UINT32]
    PUSHFD
    POP   xnr.GuestEflags
  }
  VmxStart2();
  __asm {
    PUSH  xnr.GuestEflags
    POPFD
    PUSH  xnr.guest_state.regs[REG_EAX*TYPE UINT32]
    PUSH  xnr.guest_state.regs[REG_ECX*TYPE UINT32]
    PUSH  xnr.guest_state.regs[REG_EDX*TYPE UINT32]
    PUSH  xnr.guest_state.regs[REG_EBX*TYPE UINT32]
    PUSH  xnr.guest_state.regs[REG_ESP*TYPE UINT32]
    PUSH  xnr.guest_state.regs[REG_EBP*TYPE UINT32]
    PUSH  xnr.guest_state.regs[REG_ESI*TYPE UINT32]
    PUSH  xnr.guest_state.regs[REG_EDI*TYPE UINT32]
    POPAD
    STI
    MOV   ESP, xnr.GuestStack
  }
  return TRUE;
}
#pragma optimize("", on)

//
// Stops the hypervisor and changes the host from DOM0 back to being a
// regular host.
//
void VmxStop() {
  HyperVmxStop();
  VmxFree();
}