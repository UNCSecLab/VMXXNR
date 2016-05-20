// Copyright University of North Carolina, 2016
// Author: Kevin Snow, kzsnow@cs.unc.edu
// Author: Jan Werner, jjwerner@cs.unc.edu
// This driver implements a thin hypervisor.
// The hypervisor uses EPT page execute and read permissions to implement
// an execute-but-don't-read strategy for protecting against memory
// disclosure attacks such as JIT-ROP.
//
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "vmx.h"
#include "vmxxnr.h"
#include "inline_hook.h"
#include "intrin.h"

DRIVER_OPTIONS options_;                  // Options derived from registry
PVOID MmAccessFaultHooked = NULL;         // Address of hooked MmAccessFault
MMACCESSFAULT MmAccessFault = NULL;       // Address of original MmAccessFault

//
// Routine executed when a process is created and terminated.
//
void OnProcessExNotification(
  _Inout_   PEPROCESS Process,
  _In_      HANDLE ProcessId,
  _In_opt_  PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	UNREFERENCED_PARAMETER(Process);
	if (!CreateInfo) {
		// Process termination
		HyperSingleParamCall(ProcessId);
	}
	else {
		// Process creation
		HyperTwoParamCall(ProcessId, CreateInfo);
	}
}

//
// The new page fault handler, marks pages accessible or inaccessible
//
NTSTATUS OnMmAccessFault(
    IN ULONG_PTR FaultStatus,
    IN PVOID VirtualAddress,
    IN KPROCESSOR_MODE PreviousMode,
    IN PVOID TrapInformation
)
{
  // Call original fault handler first
  NTSTATUS result = MmAccessFault(FaultStatus, VirtualAddress,
    PreviousMode, TrapInformation);
  // Mark pages accessible or inaccessible after Windows handled the fault.
  // Invoke hypervisor to acceess EPT table.
  return result;
}

//
// Routine to set up driver options e.g. from system registry.
// Note IsPaeUsed() function is defined in the hypervisor code.
//
void OptionsParse(
  IN PUNICODE_STRING Path
)
{
  UNREFERENCED_PARAMETER(Path);
    options_.using_pae = IsPaeUsed();
    if (options_.using_pae)
		DbgPrint("vmxxnr: PAE is enabled.\r\n");
    else
		DbgPrint("vnxxnr: no PAE detected.\r\n");

}

//
// Driver unload routine
//
extern "C"
void DriverUnload(
  IN PDRIVER_OBJECT DriverObject
)
{
  UNREFERENCED_PARAMETER(DriverObject);
  PsSetCreateProcessNotifyRoutineEx(OnProcessExNotification, TRUE);
  RemoveFunctionNotifyRoutine((PVOID)MmAccessFaultHooked);
  VmxStop();
  DbgPrint("vmxxnr: unloaded, hypervisor stopped\r\n");
}

//
// Driver initialization routine
//
extern "C"
NTSTATUS DriverEntry(
  IN struct _DRIVER_OBJECT  *DriverObject,
  IN PUNICODE_STRING         RegistryPath
)
{
  UNREFERENCED_PARAMETER(RegistryPath);
  DriverObject->DriverUnload = DriverUnload;
  OptionsParse(RegistryPath);
  if (!VmxStart()) {
    DbgPrint("vnxxnr: failed to start hypervisor\r\n");
    return STATUS_INVALID_PARAMETER;
  }
  DbgPrint("vmxxnr: hypervisor started\r\n");
  PsSetCreateProcessNotifyRoutineEx(OnProcessExNotification, FALSE);
  MmAccessFaultHooked = GetMmAccessFaultAddress();
  MmAccessFault = (MMACCESSFAULT)((UINT32)MmAccessFaultHooked + 2);
  SetFunctionNotifyRoutine((PVOID)MmAccessFaultHooked,
    (PVOID)OnMmAccessFault);
  DbgPrint("vmxxnr: loaded %wZ\r\n", RegistryPath);
  return STATUS_SUCCESS;
}
