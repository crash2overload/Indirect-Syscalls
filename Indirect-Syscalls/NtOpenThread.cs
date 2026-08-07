using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static Indirect_Syscalls.Native;

namespace Indirect_Syscalls
{
    public static partial class Syscalls
    {
        // AA8A9349A78CD76569F60E89F830D855
        public static NTSTATUS NtOpenThread(ref IntPtr ThreadHandle, ThreadAccess AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtOpenThread;
            syscall[4] = GetSysCallId("NtOpenThread");

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    ZwOpenThread assembledFunction = (ZwOpenThread)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(ZwOpenThread));

                    return (NTSTATUS)assembledFunction(ref ThreadHandle, AccessMask, ref ObjectAttributes, ref ClientId);
                }
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate
        NTSTATUS ZwOpenThread(ref IntPtr ThreadHandle, ThreadAccess AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

    }
}
