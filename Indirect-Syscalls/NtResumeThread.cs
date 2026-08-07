using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static Indirect_Syscalls.Native;

namespace Indirect_Syscalls
{
    public static unsafe partial class Syscalls
    {
        // 7D15F95818EA65DD21122E9ADB50CE54
        public static NTSTATUS NtResumeThread(IntPtr ThreadHandle, ref uint PrevCount)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtResumeThread;
            syscall[4] = GetSysCallId("NtResumeThread");

            fixed (byte* ptr = syscall)
            {
                IntPtr memoryAddress = (IntPtr)ptr;

                if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                {
                    throw new Win32Exception();
                }

                ZwResumeThread assembledFunction = (ZwResumeThread)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(ZwResumeThread));

                return (NTSTATUS)assembledFunction(ThreadHandle, ref PrevCount);
            }

        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate
        NTSTATUS ZwResumeThread(IntPtr ThreadHandle, ref uint PrevCount);

    }
}
