using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static Indirect_Syscalls.Native;

namespace Indirect_Syscalls
{
    public static unsafe partial class Syscalls
    {
        // 81877BF6439BB77722C7FEC47D92FBC6
        public static NTSTATUS NtSuspendThread(IntPtr ThreadHandle, ref uint PrevCount)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtSuspendThread;
            syscall[4] = GetSysCallId("NtSuspendThread");


            fixed (byte* ptr = syscall)
            {
                IntPtr memoryAddress = (IntPtr)ptr;

                if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                {
                    throw new Win32Exception();
                }

                ZwSuspendThread assembledFunction = (ZwSuspendThread)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(ZwSuspendThread));

                return (NTSTATUS)assembledFunction(ThreadHandle, ref PrevCount);
            }

        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate
        NTSTATUS ZwSuspendThread(IntPtr ThreadHandle, ref uint PrevCount);

    }
}
