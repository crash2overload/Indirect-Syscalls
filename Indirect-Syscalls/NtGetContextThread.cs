using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static Indirect_Syscalls.Native;

namespace Indirect_Syscalls
{
    //E2B89AB9B0F31BAD80E48BFF5868AB77
    public static unsafe partial class Syscalls
    {
        public static NTSTATUS NtGetContextThread(IntPtr ThreadHandle, ref CONTEXT64 ctx)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtGetContextThread;
            syscall[4] = GetSysCallId("NtGetContextThread");

            fixed (byte* ptr = syscall)
            {
                IntPtr memoryAddress = (IntPtr)ptr;

                if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                {
                    throw new Win32Exception();
                }

                ZwGetContextThread assembledFunction = (ZwGetContextThread)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(ZwGetContextThread));

                return (NTSTATUS)assembledFunction(ThreadHandle, ref ctx);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate
        NTSTATUS ZwGetContextThread(IntPtr ThreadHandle, ref CONTEXT64 ctx);

    }
}
