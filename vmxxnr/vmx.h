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


//  VMX/EPT support
#ifndef VMXXNR_VMX_H
#define VMXXNR_VMX_H

#include <ntddk.h>

#define IA32_MSR_FEATURE_CONTROL_CODE   0x03A
#define IA32_MSR_SYSENTER_CS            0x174
#define IA32_MSR_SYSENTER_ESP           0x175
#define IA32_MSR_SYSENTER_EIP           0x176
#define IA32_MSR_DEBUG_CTRL             0x1D9
#define IA32_MSR_PAT                    0x277
#define IA32_MSR_VMX_BASIC_MSR_CODE     0x480
#define IA32_MSR_VMX_PIN_BASED_VM_EXEC_CONTROL  0x481
#define IA32_MSR_VMX_CPU_BASED_VM_EXEC_CONTROL  0x482
#define IA32_MSR_VMX_VMEXIT_CTRLS       0x483
#define IA32_MSR_VMX_VMENTRY_CTRLS      0x484
#define IA32_MSR_VMX_MISC_MSR           0x485
#define IA32_MSR_VMX_CR0_FIXED0         0x486
#define IA32_MSR_VMX_CR0_FIXED1         0x487
#define IA32_MSR_VMX_PROCBASED_CTLS2    0x48B
#define IA32_MSR_VMX_EPT_VPID_CAP       0x48C

enum vmcs_field {
  VIRTUAL_PROCESSOR_ID            = 0x00000000,
  POSTED_INTR_NV                  = 0x00000002,
  GUEST_ES_SELECTOR               = 0x00000800,
  GUEST_CS_SELECTOR               = 0x00000802,
  GUEST_SS_SELECTOR               = 0x00000804,
  GUEST_DS_SELECTOR               = 0x00000806,
  GUEST_FS_SELECTOR               = 0x00000808,
  GUEST_GS_SELECTOR               = 0x0000080a,
  GUEST_LDTR_SELECTOR             = 0x0000080c,
  GUEST_TR_SELECTOR               = 0x0000080e,
  GUEST_INTR_STATUS               = 0x00000810,
  HOST_ES_SELECTOR                = 0x00000c00,
  HOST_CS_SELECTOR                = 0x00000c02,
  HOST_SS_SELECTOR                = 0x00000c04,
  HOST_DS_SELECTOR                = 0x00000c06,
  HOST_FS_SELECTOR                = 0x00000c08,
  HOST_GS_SELECTOR                = 0x00000c0a,
  HOST_TR_SELECTOR                = 0x00000c0c,
  IO_BITMAP_A                     = 0x00002000,
  IO_BITMAP_A_HIGH                = 0x00002001,
  IO_BITMAP_B                     = 0x00002002,
  IO_BITMAP_B_HIGH                = 0x00002003,
  MSR_BITMAP                      = 0x00002004,
  MSR_BITMAP_HIGH                 = 0x00002005,
  VM_EXIT_MSR_STORE_ADDR          = 0x00002006,
  VM_EXIT_MSR_STORE_ADDR_HIGH     = 0x00002007,
  VM_EXIT_MSR_LOAD_ADDR           = 0x00002008,
  VM_EXIT_MSR_LOAD_ADDR_HIGH      = 0x00002009,
  VM_ENTRY_MSR_LOAD_ADDR          = 0x0000200a,
  VM_ENTRY_MSR_LOAD_ADDR_HIGH     = 0x0000200b,
  TSC_OFFSET                      = 0x00002010,
  TSC_OFFSET_HIGH                 = 0x00002011,
  VIRTUAL_APIC_PAGE_ADDR          = 0x00002012,
  VIRTUAL_APIC_PAGE_ADDR_HIGH     = 0x00002013,
  APIC_ACCESS_ADDR                = 0x00002014,
  APIC_ACCESS_ADDR_HIGH           = 0x00002015,
  POSTED_INTR_DESC_ADDR           = 0x00002016,
  POSTED_INTR_DESC_ADDR_HIGH      = 0x00002017,
  EPT_POINTER                     = 0x0000201a,
  EPT_POINTER_HIGH                = 0x0000201b,
  EOI_EXIT_BITMAP0                = 0x0000201c,
  EOI_EXIT_BITMAP0_HIGH           = 0x0000201d,
  EOI_EXIT_BITMAP1                = 0x0000201e,
  EOI_EXIT_BITMAP1_HIGH           = 0x0000201f,
  EOI_EXIT_BITMAP2                = 0x00002020,
  EOI_EXIT_BITMAP2_HIGH           = 0x00002021,
  EOI_EXIT_BITMAP3                = 0x00002022,
  EOI_EXIT_BITMAP3_HIGH           = 0x00002023,
  VMREAD_BITMAP                   = 0x00002026,
  VMWRITE_BITMAP                  = 0x00002028,
  XSS_EXIT_BITMAP                 = 0x0000202C,
  XSS_EXIT_BITMAP_HIGH            = 0x0000202D,
  GUEST_PHYSICAL_ADDRESS          = 0x00002400,
  GUEST_PHYSICAL_ADDRESS_HIGH     = 0x00002401,
  VMCS_LINK_POINTER               = 0x00002800,
  VMCS_LINK_POINTER_HIGH          = 0x00002801,
  GUEST_IA32_DEBUGCTL             = 0x00002802,
  GUEST_IA32_DEBUGCTL_HIGH        = 0x00002803,
  GUEST_IA32_PAT                  = 0x00002804,
  GUEST_IA32_PAT_HIGH             = 0x00002805,
  GUEST_IA32_EFER                 = 0x00002806,
  GUEST_IA32_EFER_HIGH            = 0x00002807,
  GUEST_IA32_PERF_GLOBAL_CTRL     = 0x00002808,
  GUEST_IA32_PERF_GLOBAL_CTRL_HIGH= 0x00002809,
  GUEST_PDPTR0                    = 0x0000280a,
  GUEST_PDPTR0_HIGH               = 0x0000280b,
  GUEST_PDPTR1                    = 0x0000280c,
  GUEST_PDPTR1_HIGH               = 0x0000280d,
  GUEST_PDPTR2                    = 0x0000280e,
  GUEST_PDPTR2_HIGH               = 0x0000280f,
  GUEST_PDPTR3                    = 0x00002810,
  GUEST_PDPTR3_HIGH               = 0x00002811,
  GUEST_BNDCFGS                   = 0x00002812,
  GUEST_BNDCFGS_HIGH              = 0x00002813,
  HOST_IA32_PAT                   = 0x00002c00,
  HOST_IA32_PAT_HIGH              = 0x00002c01,
  HOST_IA32_EFER                  = 0x00002c02,
  HOST_IA32_EFER_HIGH             = 0x00002c03,
  HOST_IA32_PERF_GLOBAL_CTRL      = 0x00002c04,
  HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002c05,
  PIN_BASED_VM_EXEC_CONTROL       = 0x00004000,
  CPU_BASED_VM_EXEC_CONTROL       = 0x00004002,
  EXCEPTION_BITMAP                = 0x00004004,
  PAGE_FAULT_ERROR_CODE_MASK      = 0x00004006,
  PAGE_FAULT_ERROR_CODE_MATCH     = 0x00004008,
  CR3_TARGET_COUNT                = 0x0000400a,
  VM_EXIT_CONTROLS                = 0x0000400c,
  VM_EXIT_MSR_STORE_COUNT         = 0x0000400e,
  VM_EXIT_MSR_LOAD_COUNT          = 0x00004010,
  VM_ENTRY_CONTROLS               = 0x00004012,
  VM_ENTRY_MSR_LOAD_COUNT         = 0x00004014,
  VM_ENTRY_INTR_INFO_FIELD        = 0x00004016,
  VM_ENTRY_EXCEPTION_ERROR_CODE   = 0x00004018,
  VM_ENTRY_INSTRUCTION_LEN        = 0x0000401a,
  TPR_THRESHOLD                   = 0x0000401c,
  SECONDARY_VM_EXEC_CONTROL       = 0x0000401e,
  PLE_GAP                         = 0x00004020,
  PLE_WINDOW                      = 0x00004022,
  VM_INSTRUCTION_ERROR            = 0x00004400,
  VM_EXIT_REASON                  = 0x00004402,
  VM_EXIT_INTR_INFO               = 0x00004404,
  VM_EXIT_INTR_ERROR_CODE         = 0x00004406,
  IDT_VECTORING_INFO_FIELD        = 0x00004408,
  IDT_VECTORING_ERROR_CODE        = 0x0000440a,
  VM_EXIT_INSTRUCTION_LEN         = 0x0000440c,
  VMX_INSTRUCTION_INFO            = 0x0000440e,
  GUEST_ES_LIMIT                  = 0x00004800,
  GUEST_CS_LIMIT                  = 0x00004802,
  GUEST_SS_LIMIT                  = 0x00004804,
  GUEST_DS_LIMIT                  = 0x00004806,
  GUEST_FS_LIMIT                  = 0x00004808,
  GUEST_GS_LIMIT                  = 0x0000480a,
  GUEST_LDTR_LIMIT                = 0x0000480c,
  GUEST_TR_LIMIT                  = 0x0000480e,
  GUEST_GDTR_LIMIT                = 0x00004810,
  GUEST_IDTR_LIMIT                = 0x00004812,
  GUEST_ES_AR_BYTES               = 0x00004814,
  GUEST_CS_AR_BYTES               = 0x00004816,
  GUEST_SS_AR_BYTES               = 0x00004818,
  GUEST_DS_AR_BYTES               = 0x0000481a,
  GUEST_FS_AR_BYTES               = 0x0000481c,
  GUEST_GS_AR_BYTES               = 0x0000481e,
  GUEST_LDTR_AR_BYTES             = 0x00004820,
  GUEST_TR_AR_BYTES               = 0x00004822,
  GUEST_INTERRUPTIBILITY_INFO     = 0x00004824,
  GUEST_ACTIVITY_STATE            = 0X00004826,
  GUEST_SYSENTER_CS               = 0x0000482A,
  VMX_PREEMPTION_TIMER_VALUE      = 0x0000482E,
  HOST_IA32_SYSENTER_CS           = 0x00004c00,
  CR0_GUEST_HOST_MASK             = 0x00006000,
  CR4_GUEST_HOST_MASK             = 0x00006002,
  CR0_READ_SHADOW                 = 0x00006004,
  CR4_READ_SHADOW                 = 0x00006006,
  CR3_TARGET_VALUE0               = 0x00006008,
  CR3_TARGET_VALUE1               = 0x0000600a,
  CR3_TARGET_VALUE2               = 0x0000600c,
  CR3_TARGET_VALUE3               = 0x0000600e,
  EXIT_QUALIFICATION              = 0x00006400,
  GUEST_LINEAR_ADDRESS            = 0x0000640a,
  GUEST_CR0                       = 0x00006800,
  GUEST_CR3                       = 0x00006802,
  GUEST_CR4                       = 0x00006804,
  GUEST_ES_BASE                   = 0x00006806,
  GUEST_CS_BASE                   = 0x00006808,
  GUEST_SS_BASE                   = 0x0000680a,
  GUEST_DS_BASE                   = 0x0000680c,
  GUEST_FS_BASE                   = 0x0000680e,
  GUEST_GS_BASE                   = 0x00006810,
  GUEST_LDTR_BASE                 = 0x00006812,
  GUEST_TR_BASE                   = 0x00006814,
  GUEST_GDTR_BASE                 = 0x00006816,
  GUEST_IDTR_BASE                 = 0x00006818,
  GUEST_DR7                       = 0x0000681a,
  GUEST_RSP                       = 0x0000681c,
  GUEST_RIP                       = 0x0000681e,
  GUEST_RFLAGS                    = 0x00006820,
  GUEST_PENDING_DBG_EXCEPTIONS    = 0x00006822,
  GUEST_SYSENTER_ESP              = 0x00006824,
  GUEST_SYSENTER_EIP              = 0x00006826,
  HOST_CR0                        = 0x00006c00,
  HOST_CR3                        = 0x00006c02,
  HOST_CR4                        = 0x00006c04,
  HOST_FS_BASE                    = 0x00006c06,
  HOST_GS_BASE                    = 0x00006c08,
  HOST_TR_BASE                    = 0x00006c0a,
  HOST_GDTR_BASE                  = 0x00006c0c,
  HOST_IDTR_BASE                  = 0x00006c0e,
  HOST_IA32_SYSENTER_ESP          = 0x00006c10,
  HOST_IA32_SYSENTER_EIP          = 0x00006c12,
  HOST_RSP                        = 0x00006c14,
  HOST_RIP                        = 0x00006c16,
};

typedef enum {
  EXIT_REASON_EXCEPTION_NMI = 0,
  EXIT_REASON_EXTERNAL_INTERRUPT  = 1,
  EXIT_REASON_TRIPLE_FAULT  = 2,
  EXIT_REASON_INIT    = 3,
  EXIT_REASON_SIPI    = 4,
  EXIT_REASON_IO_SMI    = 5,
  EXIT_REASON_OTHER_SMI   = 6,
  EXIT_REASON_PENDING_VIRT_INTR   = 7,
  EXIT_REASON_PENDING_VIRT_NMI  = 8,
  EXIT_REASON_TASK_SWITCH   = 9,
  EXIT_REASON_CPUID   = 10,
  EXIT_REASON_HLT     = 12,
  EXIT_REASON_INVD    = 13,
  EXIT_REASON_INVLPG    = 14,
  EXIT_REASON_RDPMC   = 15,
  EXIT_REASON_RDTSC   = 16,
  EXIT_REASON_RSM     = 17,
  EXIT_REASON_VMCALL    = 18,
  EXIT_REASON_VMCLEAR   = 19,
  EXIT_REASON_VMLAUNCH    = 20,
  EXIT_REASON_VMPTRLD   = 21,
  EXIT_REASON_VMPTRST   = 22,
  EXIT_REASON_VMREAD    = 23,
  EXIT_REASON_VMRESUME    = 24,
  EXIT_REASON_VMWRITE   = 25,
  EXIT_REASON_VMXOFF    = 26,
  EXIT_REASON_VMXON   = 27,
  EXIT_REASON_CR_ACCESS   = 28,
  EXIT_REASON_DR_ACCESS   = 29,
  EXIT_REASON_IO_INSTRUCTION  = 30,
  EXIT_REASON_MSR_READ    = 31,
  EXIT_REASON_MSR_WRITE   = 32,
  EXIT_REASON_INVALID_GUEST_STATE = 33,
  EXIT_REASON_MSR_LOADING   = 34,
  EXIT_REASON_MWAIT_INSTRUCTION = 36,
  EXIT_REASON_MONITOR_INSTRUCTION = 39,
  EXIT_REASON_PAUSE_INSTRUCTION = 40,
  EXIT_REASON_MACHINE_CHECK = 41,
  EXIT_REASON_TPR_BELOW_THRESHOLD = 43,
  EXIT_REASON_APIC_ACCESS   = 44,
  EXIT_REASON_EPT_VIOLATION = 48,
  EXIT_REASON_EPT_MISCONFIG = 49,
  EXIT_REASON_WBINVD    = 54,
  MAX_VM_EXIT_NUMBER    = 55
} vm_exit_reason;

//
// Extended Page Tables (EPT)
//
// EPT uses a 4-level page hierarchy similar to that used in long mode:
//
//   PML4 - Covers a 256TB region or 512 PML4 512GB entries
//   PML3 - Covers a 512GB region or 512 PML3 1GB entries (PDPE's)
//   PML2 - Covers a 1GB region or 512 PML2 2MB entries   (PDE's)
//   PML1 - Covers a 2MB region or 512 PML1 4KB entries   (PTE's)
//
// Defines for parsing the EPT violation exit qualification
// Bitmask for data read violation
#define EPT_MASK_DATA_READ 0x1
// Bitmask for data write violation
#define EPT_MASK_DATA_WRITE (1 << 1)
// Bitmask for data execute violation
#define EPT_MASK_DATA_EXEC (1 << 2)
// Bitmask for if the guest linear address is valid
#define EPT_MASK_GUEST_LINEAR_VALID (1 << 7)

#pragma pack(push, ept, 1)

// Extended Page Table Pointer (EPTP) written to the VMCS (VMCS_EPT_POINTER)
// PhysAddr points to an array of PML4E
typedef union {
  __int64 Val;
  struct {
    __int64 MemoryType :3; // EPT Paging structure memory type (0 for UC)
    __int64 PageWalkLength :3; // Page-walk length - 1
    __int64 reserved1 :6; // Reserved
    __int64 PhysAddr :24; // Physical address of the EPT PML4 table
    __int64 reserved2 :28;
  } Bits;
} EPT_PTR;  // Pointer to Level 4

// One structure to represent page directories and page entries for EPT
typedef struct {
  __int64 Read :1;         // Read access
  __int64 Write :1;        // Write access
  __int64 Execute :1;      // Execute access
  __int64 MemoryType :3;   // Must be 0 for directory entries
  __int64 IgnorePat :1;    // Must be 0 for directory entries
  __int64 LargePage :1;    // Must be 0 for levels 4 and 1
  __int64 Accessed :1;     // Init as 0, set by MMU
  __int64 Dirty :1;        // Init as 0, set by MMU
  __int64 reserved1 :2;    // Must be 0
  __int64 PhysAddr :24;    // Mask appropriately for different levels
  __int64 reserved2 :28;   // Must be 0
} EPT_ENTRY, * PEPT_ENTRY;  // EPT Entry

typedef union {
  struct {
    UINT32 dword1;
    UINT32 dword2;
    UINT32 dword3;
    UINT32 dword4;
  } Dwords;
  struct {
    __int64 Vpid :16;          // VPID to effect
    __int64 reserved :48;      // Reserved
    __int64 LinearAddress :64; // Linear address
  } Bits;
} INV_VPID_DESC;

// PDPTEs (used when PAE is enabled)
typedef struct {
  __int64 pdpte0;
  __int64 pdpte1;
  __int64 pdpte2;
  __int64 pdpte3;
} PDPTRS;

#pragma pack(pop, ept)

#ifdef _X86_

#define REG_EAX 0
#define REG_ECX 1
#define REG_EDX 2
#define REG_EBX 3
#define REG_ESP 4
#define REG_EBP 5
#define REG_ESI 6
#define REG_EDI 7

#pragma pack(1)
typedef struct {
  UINT32 regs[8];  // Registers indexed by above REG_XXX defines
  UINT32 eflags;
} *PREGISTER_STATE, REGISTER_STATE;
#pragma pack()

typedef struct _EFLAGS {
  unsigned Reserved1  :10;
  unsigned ID     :1;   // Identification flag
  unsigned VIP    :1;   // Virtual interrupt pending
  unsigned VIF    :1;   // Virtual interrupt flag
  unsigned AC     :1;   // Alignment check
  unsigned VM     :1;   // Virtual 8086 mode
  unsigned RF     :1;   // Resume flag
  unsigned Reserved2  :1;
  unsigned NT     :1;   // Nested task flag
  unsigned IOPL   :2;   // I/O privilege level
  unsigned OF     :1;
  unsigned DF     :1;
  unsigned IF     :1;   // Interrupt flag
  unsigned TF     :1;   // Task flag
  unsigned SF     :1;   // Sign flag
  unsigned ZF     :1;   // Zero flag
  unsigned Reserved3  :1;
  unsigned AF     :1;   // Borrow flag
  unsigned Reserved4  :1;
  unsigned PF     :1;   // Parity flag
  unsigned Reserved5  :1;
  unsigned CF     :1;   // Carry flag [Bit 0]
} EFLAGS;

#pragma pack(1)
typedef struct _KGDTENTRY {
    unsigned    LimitLo :16;
    unsigned    BaseLo  :16;
    unsigned    BaseMid :8;
    unsigned    Type    :4;
    unsigned    System  :1;
    unsigned    DPL     :2;
    unsigned    Present :1;
    unsigned    LimitHi :4;
    unsigned    AVL     :1;
    unsigned    L       :1;
    unsigned    DB      :1;
    unsigned    Gran    :1;
    unsigned    BaseHi  :8;
} KGDTENTRY, *PKGDTENTRY;
#pragma pack()

#pragma pack(1)
typedef struct _IDTR {
  UINT16 limit;
  UINT32 base;
} IDTR;
#pragma pack()

#endif // _X86_

typedef struct {
  PVOID vmcs;
} *PVCPU, VCPU;

typedef struct {
  UINT32 cpu_cnt;
  VCPU cpus[32];
  PUCHAR vmxon;
  ULONG vmxon_physical;
  // Per-guest vmx variables
  // The Virtual Machine Control Structure (VMCS)
  PUCHAR vmcs;
  ULONG vmcs_physical;
  // IO Bitmaps A and B (currently unused)
  PUCHAR ioa;
  ULONG ioa_physical;
  PUCHAR iob;
  ULONG iob_physical;
  // Guest Model-Specific Registers (MSR) (currently unused)
  PUCHAR msr;
  ULONG msr_physical;
  // Guest Virtual APIC (VAPIC)
  PUCHAR vapic;
  ULONG vapic_physical;
  // Guest Memory Management via Extended Page Tables (EPT)
  EPT_PTR    eptp;    // Points to the Level 4 table, written to VMCS
  EPT_ENTRY *pml4;    // Level 4 array of 512GB entries on a page (top-level)
  // The stack for use by the Hypervisor VMExit routine
  PUCHAR stack;
  // Guest and host register state
  REGISTER_STATE host_state;
  REGISTER_STATE guest_state;
  UINT32 GuestStack;
  UINT32 GuestReturn;
  UINT32 GuestEflags;
} *PVMXXNR, VMXXNR;

// The public interface
//
// Hypercalls
typedef enum {
  HYPER_SINGLE_PARAM = 0,
  HYPER_TWO_PARAMS,
  HYPER_VMX_STOP,
} hypercall;
//
#define HyperSingleParamCall(Single) \
  __vmx_vmcall(HYPER_SINGLE_PARAM, 1, (Single))
#define HyperTwoParamCall(First, Second) \
	__vmx_vmcall(HYPER_TWO_PARAMS, 2, (First), (Second))
#define HyperVmxStop()     __vmx_vmcall(HYPER_VMX_STOP, 0)
//
// Performs a hypercall with the specified ID and argument
void __vmx_vmcall(unsigned int id, unsigned int argc, ...);
//
// VmxStart starts the hypervisor and places the host
// operating system in guest mode, e.g. it implements
// a type 1 hypervisor with VMX.
bool VmxStart();
//
// VmxStop unloads the hypervisor and returns dom0 to the host OS.
void VmxStop();
//
// Checks if PAE is in use.
bool IsPaeUsed();

#endif  // #define VMXXNR_VMX_H