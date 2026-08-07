using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static Indirect_Syscalls.Native;

namespace Indirect_Syscalls
{
    public static unsafe partial class Syscalls
    {
        // 4B3C2DD4E83CA77AAE1991FB78BD4FF5
        public static NTSTATUS NtSetContextThread(IntPtr ThreadHandle, ref CONTEXT64 ctx)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtSetContextThread;
            syscall[4] = GetSysCallId("NtSetContextThread");

            fixed (byte* ptr = syscall)
            {
                IntPtr memoryAddress = (IntPtr)ptr;

                if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                {
                    throw new Win32Exception();
                }

                ZwSetContextThread assembledFunction = (ZwSetContextThread)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(ZwSetContextThread));

                return (NTSTATUS)assembledFunction(ThreadHandle, ref ctx);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate
        NTSTATUS ZwSetContextThread(IntPtr ThreadHandle, ref CONTEXT64 ctx);


    }
}
