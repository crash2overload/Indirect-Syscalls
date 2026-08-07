using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static Indirect_Syscalls.Native;

namespace Indirect_Syscalls
{
    public static unsafe partial class Syscalls
    {
        //082B8B2698FAB72A86144B161CEF5B4F
        public static NTSTATUS NtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtOpenProcess;
            syscall[4] = GetSysCallId("NtOpenProcess");

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    ZwOpenProcess assembledFunction = (ZwOpenProcess)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(ZwOpenProcess));

                    return (NTSTATUS)assembledFunction(ref ProcessHandle, AccessMask, ref ObjectAttributes, ref ClientId);
                }
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate
        NTSTATUS ZwOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

    }
}
