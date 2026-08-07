using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static Indirect_Syscalls.Native;

namespace Indirect_Syscalls
{
    public static unsafe partial class Syscalls
    {
        private const string snn = "7AC4BDB1358D260EC70B46EAEA6B3331";
        public static NTSTATUS NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionZize, UInt32 AllocationType, UInt32 Protect)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtAllocateVirtualMemory;
            syscall[4] = GetSysCallId("NtAllocateVirtualMemory");


            fixed (byte* ptr = syscall)
            {
                IntPtr memoryAddress = (IntPtr)ptr;

                if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                {
                    throw new Win32Exception();
                }

                ZwAllocateVirtualMemory assembledFunction = (ZwAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(ZwAllocateVirtualMemory));

                return (NTSTATUS)assembledFunction(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionZize, AllocationType, Protect);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate
        NTSTATUS ZwAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionZize, UInt32 AllocationType, UInt32 Protect);

    }
}
