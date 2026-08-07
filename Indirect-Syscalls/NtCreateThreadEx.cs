using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static Indirect_Syscalls.Native;

namespace Indirect_Syscalls
{
    public static unsafe partial class Syscalls
    {
        private const string hNtCreateThreadEx = "3FE46DC108A425F193C20633E22D62EC";

        public static NTSTATUS NtCreateThreadEx(ref IntPtr threadHandle, ThreadAccess desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, ulong CreateFlags, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
        {
            // dynamically resolve the syscall
            byte[] syscall = bNtCreateThreadEx;
            syscall[4] = GetSysCallId("NtCreateThreadEx");

            fixed (byte* ptr = syscall)
            {
                IntPtr memoryAddress = (IntPtr)ptr;

                if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                {
                    throw new Win32Exception();
                }

                ZwCreateThreadEx assembledFunction = (ZwCreateThreadEx)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(ZwCreateThreadEx));

                return (NTSTATUS)assembledFunction(ref threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, CreateFlags, stackZeroBits, sizeOfStack, maximumStackSize, attributeList);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate
        NTSTATUS ZwCreateThreadEx(ref IntPtr threadHandle, ThreadAccess desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, ulong CreateFlags, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList);

    }
}
