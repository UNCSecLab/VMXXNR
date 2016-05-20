# VMXXNR
=== About VMXXNR ===
This repository contains the source code of the thin hypervisor that was used
to implement No-Execute After Read memory permission primitive.
For more details about this research please see the paper titled:
"No-Execute-After-Read: Preventing Code Disclosure in Commodity Software"
published in AsiaCCS 2016.
The paper is available at: cs.unc.edu/~jjwerner/near-asiaccs.pdf.

The purpose of this release is to assist other researchers in future reasearch
involving techniques requring the use of Intel's hardware virtualization
primivites. While other hypervisors are available, they are either closed source
and not directly useful or open source but often more complicated than necessary.
In this release we strive to provide researchers with a minimal, well documented,
example of a thin hypervisor.

The complete implementation of NEAR uses EPT page execute and read permissions
to implement an execute-but-don't-read strategy for protecting against memory
disclosure attacks such as JIT-ROP.

It achieves this as follows:
 - Hooks the OS page fault handler
 - Hooks process creation and tracks the given list of executables
 - Places the host in 'dom0' guest mode using VMX
 - Watches for page not-present faults on tracked executable pages
   - This indicates a new page has been loaded that we should read-protect
 - Hypercall from dom0 page fault handler to hypervisor to protect the page
 - Hypervisor marks the corresponding EPT entry as non-readable
 - Windows code sometimes legitimately reads code pages
   - e.g. constant function local variables, jump tables, code fixups, etc.
 - When a legitimate read occurs, make the EPT entry readable again
 - Set the trap flag in the hypervisor
 - The read will succeed, then an NMI exception VMExit occurs
 - Mark the EPT entry as non-readable again
 - Clear the trap flag and continue execution


=== Acknowledgements ===
This work is supported in part by the National Science Foundation under award
1421703.

=== Requirements ===
- Single core VT-X, VT-D capable Intel CPU (enabled in BIOS if running on bare
  metal, or set in the Virtual Machine Processor settings)
- Windows 7 32-bit
- Visual Studio 2013
- Windows Driver Kit (e.g. WDK 8.1 Update)
- VMXXNR was tested in a virtualized environment e.g. VMWare Fusion, and on
  bare metal machine Dell OptiPlex 990


=== One-time Setup ===

- Enable drivers signed with a test cert:
  $ enabletestsigning.bat

- Enable kernel debug logging:
  $ dbgview.bat

- Setup Dbgview.exe
  - Launch it.
  - Select everything under the 'Capture' menu.


=== Build ===

- Open 'Visual Studio 2013 x86 Native Tools Command Prompt' as Administrator.
- Navigate to the vmxxnr directory
- Type 'make'


=== Test ===

- Open Dbgview.exe as Administrator
- Run load.bat
- You should see a debug message indicating that vmxxnr loaded.
- When the hypervisor is active everytime a process is created and terminated,
  the hypervisor will print debug message to the debug log.


=== Debugger Configuration ===

This section describes how to setup kernel debugging with two VMWare Fusion
instances of Windows 7 on OSX.

  - First, create a linked clone of your main Windows 7 development VM. This
    clone will serve as the debugger. It should already have your dev
    environment and the WDK and WinDbg on it.
  - In the dev/target VM enable debug mode:
      $ bcdedit /debug on
      $ bcdedit /dbgsettings serial debugport:1 baudrate:115200
  - Shutdown debugger and target/dev VMs
  - In the Fusion Virtual Machine Library right click the debugger VM and show
    in Finder. Then right click the VM file and Show Contents.
  - Edit the .VMX file:
    Replace existing serial0 entries with the following:
      serial0.present = "TRUE"
      serial0.fileType = "pipe"
      serial0.fileName = "/private/tmp/com1"
      serial0.tryNoRxLoss = "FALSE"
      serial0.pipe.endPoint = "server"
  - Do the same for the target/dev VMX file, but make the endpoint a "client".
  - Boot the debugger VM, start WinDbg as an Admin
    WinDbg -> Set "File->Symbol Path"
      srv*c:\symbols* http://msdl.microsoft.com/download/symbols
    Connect with "File->Kernel Debug"
      Connect over com1 (do not use the pipe option)
  - Start the target/dev machine, then switch back over to the debugger and
    start using from there.

Other tips for WinDbg
  Enable DbgPrint output:
    "Debug->Break", then type "ed nt!Kd_DEFAULT_Mask 0x8"
  Set breakpoint on driver function:
    "Debug->Break", then type "bu vmxxnr!DriverEntry"
  Use VMWare to save a snapshot before each test, then simply revert after
  each crash instead of rebooting and reconnecting the debugger.