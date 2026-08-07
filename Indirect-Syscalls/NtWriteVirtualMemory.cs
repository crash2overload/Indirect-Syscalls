using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static Indirect_Syscalls.Native;

namespace Indirect_Syscalls
{
    // 906135A44ABBE75FFFC90F0EA5B594DF
    public static unsafe partial class Syscalls
    {
        public static NTSTATUS NtWriteVirtualMemory(IntPtr hProcess, IntPtr baseAddress, IntPtr buffer, UInt32 Length, ref UInt32 bytesWritten)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtWriteVirtualMemory;
            syscall[4] = GetSysCallId("NtWriteVirtualMemory");

            fixed (byte* ptr = syscall)
            {
                IntPtr memoryAddress = (IntPtr)ptr;

                if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                {
                    throw new Win32Exception();
                }

                ZwWriteVirtualMemory assembledFunction = (ZwWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(ZwWriteVirtualMemory));

                return (NTSTATUS)assembledFunction(hProcess, baseAddress, buffer, (uint)Length, ref bytesWritten);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate
        NTSTATUS ZwWriteVirtualMemory(IntPtr hProcess, IntPtr baseAddress, IntPtr buffer, UInt32 Length, ref UInt32 bytesWritten);
    }
}
