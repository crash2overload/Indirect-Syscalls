using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static Indirect_Syscalls.Native;

namespace Indirect_Syscalls
{
    public static unsafe partial class Syscalls
    {
        // E8FB4E2DE6F0AC146C2B72D0D4C7B496
        public static NTSTATUS NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, ref uint OldProtect)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtProtectVirtualMemory;
            syscall[4] = GetSysCallId("NtProtectVirtualMemory");


            fixed (byte* ptr = syscall)
            {
                IntPtr memoryAddress = (IntPtr)ptr;

                if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                {
                    throw new Win32Exception();
                }

                ZwProtectVirtualMemory assembledFunction = (ZwProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(ZwProtectVirtualMemory));

                return (NTSTATUS)assembledFunction(ProcessHandle, ref BaseAddress, ref RegionSize, NewProtect, ref OldProtect);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate
        NTSTATUS ZwProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, ref uint OldProtect);

    }
}
