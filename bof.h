/*
 * bof.h - PyNet BOF SDK
 *
 * Write BOFs like regular C code. Include this header and use:
 *   - _printf(fmt, ...) / _perror(fmt, ...) for teamserver output
 *   - Windows APIs directly: VirtualAlloc(), OpenProcess(), etc.
 *   - API(dll, func)(args) for APIs not covered by convenience macros
 *   - _args_* functions for argument parsing
 * 
 * Changelog:
 * 
 * 
 *
 */

#ifndef PYNET_BOF_H
#define PYNET_BOF_H

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===========================================================================
 * OUTPUT
 *
 * Write output like a normal C program. The SDK handles transport to the
 * teamserver transparently.
 *
 *   _printf(fmt, ...) - standard output (like printf to stdout)
 *   _perror(fmt, ...) - error output (like fprintf to stderr)
 * ===========================================================================*/

DECLSPEC_IMPORT void __cdecl BeaconPrintf(int type, const char* fmt, ...);
DECLSPEC_IMPORT void __cdecl BeaconOutput(int type, const char* data, int len);

#define CALLBACK_OUTPUT      0x00
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

#define _printf(fmt, ...) BeaconPrintf(CALLBACK_OUTPUT, fmt, ##__VA_ARGS__)
#define _perror(fmt, ...) BeaconPrintf(CALLBACK_ERROR, fmt, ##__VA_ARGS__)

/* ===========================================================================
 * ARGUMENT PARSING
 *
 * Arguments are packed by the teamserver as:
 *   int:   4 bytes little-endian
 *   short: 2 bytes little-endian
 *   str:   4-byte length + data + null
 *
 * Usage:
 *   _args args;
 *   _args_parse(&args, raw, raw_len);
 *   int pid = _args_int(&args);
 *   char* name = _args_str(&args, &len);
 * ===========================================================================*/

typedef struct {
    char* original;
    char* current;
    int used;
    int size;
} _args;

DECLSPEC_IMPORT void   BeaconDataParse(_args* a, char* buf, int len);
DECLSPEC_IMPORT int    BeaconDataInt(_args* a);
DECLSPEC_IMPORT short  BeaconDataShort(_args* a);
DECLSPEC_IMPORT char*  BeaconDataExtract(_args* a, int* out_len);
DECLSPEC_IMPORT int    BeaconDataLength(_args* a);

#define _args_parse(a, buf, len)  BeaconDataParse(a, buf, len)
#define _args_int(a)              BeaconDataInt(a)
#define _args_short(a)            BeaconDataShort(a)
#define _args_str(a, out_len)     BeaconDataExtract(a, out_len)
#define _args_left(a)             BeaconDataLength(a)

/* Additional data parser function */
DECLSPEC_IMPORT char* BeaconDataPtr(_args* a, int size);
#define _args_ptr(a, size)        BeaconDataPtr(a, size)

/* ===========================================================================
 * FORMAT API
 *
 * Build complex output incrementally before sending.
 * ===========================================================================*/

typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} formatp;

DECLSPEC_IMPORT void  BeaconFormatAlloc(formatp* format, int maxsz);
DECLSPEC_IMPORT void  BeaconFormatReset(formatp* format);
DECLSPEC_IMPORT void  BeaconFormatFree(formatp* format);
DECLSPEC_IMPORT void  BeaconFormatAppend(formatp* format, const char* text, int len);
DECLSPEC_IMPORT void  BeaconFormatPrintf(formatp* format, const char* fmt, ...);
DECLSPEC_IMPORT void  BeaconFormatInt(formatp* format, int value);
DECLSPEC_IMPORT char* BeaconFormatToString(formatp* format, int* size);

/* ===========================================================================
 * TOKEN API
 *
 * Token impersonation and privilege checking.
 * ===========================================================================*/

DECLSPEC_IMPORT BOOL BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void BeaconRevertToken(void);
DECLSPEC_IMPORT BOOL BeaconIsAdmin(void);

/* ===========================================================================
 * SPAWN & INJECT API
 *
 * Process creation and payload injection.
 * ===========================================================================*/

/* SpawnTo configuration */
DECLSPEC_IMPORT void BeaconGetSpawnTo(BOOL x86, char* buffer, int length);

/* Process spawn info structure */
typedef struct {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
} PROCESS_BASIC_INFO;

DECLSPEC_IMPORT BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFOA* si, PROCESS_BASIC_INFO* pbi);
DECLSPEC_IMPORT void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int payloadLen, int offset, char* arg, int argLen);
DECLSPEC_IMPORT void BeaconInjectTemporaryProcess(PROCESS_BASIC_INFO* pbi, char* payload, int payloadLen, int offset, char* arg, int argLen);
DECLSPEC_IMPORT void BeaconCleanupProcess(PROCESS_BASIC_INFO* pbi);

/* ===========================================================================
 * DATA STORE API
 *
 * Persistent storage across BOF executions.
 * ===========================================================================*/

#define DATA_STORE_TYPE_EMPTY    0
#define DATA_STORE_TYPE_GENERAL  1

typedef struct {
    char* Buffer;
    int   Length;
    int   Type;
} DATA_STORE_OBJECT;

DECLSPEC_IMPORT DATA_STORE_OBJECT* BeaconDataStoreGetItem(int index);
DECLSPEC_IMPORT void BeaconDataStoreProtectItem(int index);
DECLSPEC_IMPORT void BeaconDataStoreUnprotectItem(int index);
DECLSPEC_IMPORT int  BeaconDataStoreMaxEntries(void);

/* ===========================================================================
 * KEY-VALUE STORE API
 *
 * Store and retrieve values by key name.
 * ===========================================================================*/

DECLSPEC_IMPORT BOOL  BeaconAddValue(const char* key, void* ptr);
DECLSPEC_IMPORT void* BeaconGetValue(const char* key);
DECLSPEC_IMPORT BOOL  BeaconRemoveValue(const char* key);

/* ===========================================================================
 * UTILITY API
 * ===========================================================================*/

/* String conversion */
DECLSPEC_IMPORT BOOL toWideChar(const char* src, wchar_t* dst, int max);

/* Beacon metadata */
typedef struct {
    int   version;
    int   pid;
    int   ppid;
    BOOL  is64;
    BOOL  isAdmin;
    char* processName;
    char* userName;
} BEACON_INFO;

DECLSPEC_IMPORT void BeaconInformation(BEACON_INFO* info);

/* Custom user data */
DECLSPEC_IMPORT char* BeaconGetCustomUserData(void);

/* File download */
DECLSPEC_IMPORT void BeaconDownload(const char* fileName, const char* data, int dataLen);

/* ===========================================================================
 * SYSCALL API
 *
 * Direct syscall support (if enabled in agent).
 * ===========================================================================*/

typedef struct {
    void*  fnAddr;      /* Function address */
    DWORD  sysnum;      /* Syscall number */
} SYSCALL_API_ENTRY;

typedef struct {
    SYSCALL_API_ENTRY ntAllocateVirtualMemory;
    SYSCALL_API_ENTRY ntProtectVirtualMemory;
    SYSCALL_API_ENTRY ntFreeVirtualMemory;
    SYSCALL_API_ENTRY ntGetContextThread;
    SYSCALL_API_ENTRY ntSetContextThread;
    SYSCALL_API_ENTRY ntResumeThread;
    SYSCALL_API_ENTRY ntOpenProcess;
    SYSCALL_API_ENTRY ntOpenThread;
    SYSCALL_API_ENTRY ntCloseHandle;
    SYSCALL_API_ENTRY ntUnmapViewOfFile;
    SYSCALL_API_ENTRY ntVirtualQuery;
    SYSCALL_API_ENTRY ntDuplicateHandle;
    SYSCALL_API_ENTRY ntReadProcessMemory;
    SYSCALL_API_ENTRY ntWriteProcessMemory;
} SYSCALL_API_INFO;

DECLSPEC_IMPORT SYSCALL_API_INFO* BeaconGetSyscallInformation(void);

/* Beacon-wrapped syscall functions (use agent's syscall mechanism) */
DECLSPEC_IMPORT LPVOID    BeaconVirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD protect);
DECLSPEC_IMPORT LPVOID    BeaconVirtualAllocEx(HANDLE hProc, LPVOID addr, SIZE_T size, DWORD type, DWORD protect);
DECLSPEC_IMPORT BOOL      BeaconVirtualProtect(LPVOID addr, SIZE_T size, DWORD newProtect, PDWORD oldProtect);
DECLSPEC_IMPORT BOOL      BeaconVirtualProtectEx(HANDLE hProc, LPVOID addr, SIZE_T size, DWORD newProtect, PDWORD oldProtect);
DECLSPEC_IMPORT BOOL      BeaconVirtualFree(LPVOID addr, SIZE_T size, DWORD freeType);
DECLSPEC_IMPORT BOOL      BeaconGetThreadContext(HANDLE hThread, LPCONTEXT ctx);
DECLSPEC_IMPORT BOOL      BeaconSetThreadContext(HANDLE hThread, LPCONTEXT ctx);
DECLSPEC_IMPORT DWORD     BeaconResumeThread(HANDLE hThread);
DECLSPEC_IMPORT HANDLE    BeaconOpenProcess(DWORD desiredAccess, BOOL inheritHandle, DWORD pid);
DECLSPEC_IMPORT HANDLE    BeaconOpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD tid);
DECLSPEC_IMPORT BOOL      BeaconCloseHandle(HANDLE h);
DECLSPEC_IMPORT BOOL      BeaconUnmapViewOfFile(LPCVOID baseAddr);
DECLSPEC_IMPORT SIZE_T    BeaconVirtualQuery(LPCVOID addr, PMEMORY_BASIC_INFORMATION mbi, SIZE_T len);
DECLSPEC_IMPORT BOOL      BeaconDuplicateHandle(HANDLE hSrcProc, HANDLE hSrc, HANDLE hDstProc, LPHANDLE hDst, DWORD access, BOOL inherit, DWORD options);
DECLSPEC_IMPORT BOOL      BeaconReadProcessMemory(HANDLE hProc, LPCVOID baseAddr, LPVOID buffer, SIZE_T size, SIZE_T* bytesRead);
DECLSPEC_IMPORT BOOL      BeaconWriteProcessMemory(HANDLE hProc, LPVOID baseAddr, LPCVOID buffer, SIZE_T size, SIZE_T* bytesWritten);

/* ===========================================================================
 * BEACON GATE API
 *
 * Control BeaconGate functionality.
 * ===========================================================================*/

DECLSPEC_IMPORT void BeaconDisableBeaconGate(void);
DECLSPEC_IMPORT void BeaconEnableBeaconGate(void);
DECLSPEC_IMPORT void BeaconDisableBeaconGateMasking(void);
DECLSPEC_IMPORT void BeaconEnableBeaconGateMasking(void);

/* ===========================================================================
 * DYNAMIC FUNCTION RESOLUTION
 *
 * Usage: API(DLL, func)(args...)
 *
 *   API(KERNEL32, GetCurrentProcessId)()
 *   API(KERNEL32, CloseHandle)(h)
 *   API(ADVAPI32, OpenProcessToken)(proc, TOKEN_QUERY, &tok)
 *   API(NTDLL, NtQuerySystemInformation)(class, buf, len, &ret)
 * ===========================================================================*/

#define API(dll, func) dll##$##func

/* ===========================================================================
 * KERNEL32
 * ===========================================================================*/

/* Error handling */
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT void   WINAPI KERNEL32$SetLastError(DWORD);

/* Process/Thread identity */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentThread(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentThreadId(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetProcessId(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetThreadId(HANDLE);

/* Handles */
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DuplicateHandle(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);

/* Memory */
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT SIZE_T WINAPI KERNEL32$VirtualQuery(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

/* Modules */
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryW(LPCWSTR);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetModuleFileNameA(HMODULE, LPSTR, DWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetModuleFileNameW(HMODULE, LPWSTR, DWORD);

/* Process */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$TerminateProcess(HANDLE, UINT);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetExitCodeProcess(HANDLE, LPDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

/* Thread */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenThread(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$TerminateThread(HANDLE, DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$SuspendThread(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$ResumeThread(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetExitCodeThread(HANDLE, LPDWORD);

/* Synchronization */
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForMultipleObjects(DWORD, const HANDLE*, BOOL, DWORD);
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$SwitchToThread(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateEventW(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$SetEvent(HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ResetEvent(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateMutexA(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateMutexW(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReleaseMutex(HANDLE);

/* Files */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetFileSizeEx(HANDLE, PLARGE_INTEGER);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$SetFilePointer(HANDLE, LONG, PLONG, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DeleteFileA(LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DeleteFileW(LPCWSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CopyFileA(LPCSTR, LPCSTR, BOOL);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CopyFileW(LPCWSTR, LPCWSTR, BOOL);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$MoveFileA(LPCSTR, LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$MoveFileW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetFileAttributesA(LPCSTR);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FindClose(HANDLE);

/* Directories */
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$CreateDirectoryA(LPCSTR, LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$CreateDirectoryW(LPCWSTR, LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$RemoveDirectoryA(LPCSTR);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$RemoveDirectoryW(LPCWSTR);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetCurrentDirectoryA(DWORD, LPSTR);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetCurrentDirectoryW(DWORD, LPWSTR);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$SetCurrentDirectoryA(LPCSTR);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$SetCurrentDirectoryW(LPCWSTR);

/* Environment */
DECLSPEC_IMPORT LPWCH WINAPI KERNEL32$GetEnvironmentStringsW(void);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$FreeEnvironmentStringsW(LPWCH);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetEnvironmentVariableW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$SetEnvironmentVariableA(LPCSTR, LPCSTR);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$SetEnvironmentVariableW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ExpandEnvironmentStringsA(LPCSTR, LPSTR, DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR, LPWSTR, DWORD);

/* System info */
DECLSPEC_IMPORT VOID  WINAPI KERNEL32$GetSystemInfo(LPSYSTEM_INFO);
DECLSPEC_IMPORT VOID  WINAPI KERNEL32$GetNativeSystemInfo(LPSYSTEM_INFO);
DECLSPEC_IMPORT VOID  WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME);
DECLSPEC_IMPORT VOID  WINAPI KERNEL32$GetLocalTime(LPSYSTEMTIME);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT ULONGLONG WINAPI KERNEL32$GetTickCount64(void);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$QueryPerformanceCounter(LARGE_INTEGER*);
DECLSPEC_IMPORT UINT  WINAPI KERNEL32$GetSystemDirectoryA(LPSTR, UINT);
DECLSPEC_IMPORT UINT  WINAPI KERNEL32$GetSystemDirectoryW(LPWSTR, UINT);
DECLSPEC_IMPORT UINT  WINAPI KERNEL32$GetWindowsDirectoryA(LPSTR, UINT);
DECLSPEC_IMPORT UINT  WINAPI KERNEL32$GetWindowsDirectoryW(LPWSTR, UINT);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTempPathA(DWORD, LPSTR);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTempPathW(DWORD, LPWSTR);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$GetComputerNameA(LPSTR, LPDWORD);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$GetComputerNameW(LPWSTR, LPDWORD);

/* String (avoid CRT) */
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrlenA(LPCSTR);
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT LPSTR  WINAPI KERNEL32$lstrcpyA(LPSTR, LPCSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcpyW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT LPSTR  WINAPI KERNEL32$lstrcpynA(LPSTR, LPCSTR, int);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcpynW(LPWSTR, LPCWSTR, int);
DECLSPEC_IMPORT LPSTR  WINAPI KERNEL32$lstrcatA(LPSTR, LPCSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcatW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrcmpA(LPCSTR, LPCSTR);
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrcmpW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrcmpiA(LPCSTR, LPCSTR);
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrcmpiW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

/* Pipes */
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CreatePipe(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$PeekNamedPipe(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);

/* ===========================================================================
 * ADVAPI32
 * ===========================================================================*/

/* Token */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenThreadToken(HANDLE, DWORD, BOOL, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DuplicateToken(HANDLE, SECURITY_IMPERSONATION_LEVEL, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$SetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ImpersonateSelf(SECURITY_IMPERSONATION_LEVEL);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$RevertToSelf(void);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$SetThreadToken(PHANDLE, HANDLE);

/* SID/Account */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountNameA(LPCSTR, LPCSTR, PSID, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountNameW(LPCWSTR, LPCWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID, LPWSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$IsValidSid(PSID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$EqualSid(PSID, PSID);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetLengthSid(PSID);

/* Privilege */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeNameA(LPCSTR, PLUID, LPSTR, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeNameW(LPCWSTR, PLUID, LPWSTR, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$PrivilegeCheck(HANDLE, PPRIVILEGE_SET, LPBOOL);

/* User */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetUserNameA(LPSTR, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetUserNameW(LPWSTR, LPDWORD);

/* Registry */
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCreateKeyExW(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegSetValueExW(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegDeleteKeyA(HKEY, LPCSTR);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegDeleteKeyW(HKEY, LPCWSTR);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegDeleteValueA(HKEY, LPCSTR);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegDeleteValueW(HKEY, LPCWSTR);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumKeyExA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumKeyExW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumValueA(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegEnumValueW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);

/* Service */
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE, LPCWSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$QueryServiceStatus(SC_HANDLE, LPSERVICE_STATUS);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$StartServiceA(SC_HANDLE, DWORD, LPCSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$StartServiceW(SC_HANDLE, DWORD, LPCWSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ControlService(SC_HANDLE, DWORD, LPSERVICE_STATUS);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$QueryServiceConfigA(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD);
/* Crypto */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptAcquireContextA(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptAcquireContextW(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenRandom(HCRYPTPROV, DWORD, BYTE*);

/* ===========================================================================
 * SECUR32
 * ===========================================================================*/

DECLSPEC_IMPORT BOOLEAN WINAPI SECUR32$GetUserNameExA(DWORD, LPSTR, PULONG);
DECLSPEC_IMPORT BOOLEAN WINAPI SECUR32$GetUserNameExW(DWORD, LPWSTR, PULONG);
DECLSPEC_IMPORT BOOLEAN WINAPI SECUR32$GetComputerObjectNameA(DWORD, LPSTR, PULONG);
DECLSPEC_IMPORT BOOLEAN WINAPI SECUR32$GetComputerObjectNameW(DWORD, LPWSTR, PULONG);

/* ===========================================================================
 * NTDLL
 * ===========================================================================*/

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose(HANDLE);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryInformationThread(HANDLE, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryObject(HANDLE, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtFreeVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenProcess(PHANDLE, ACCESS_MASK, PVOID, PVOID);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtOpenThread(PHANDLE, ACCESS_MASK, PVOID, PVOID);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtGetContextThread(HANDLE, PCONTEXT);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtSetContextThread(HANDLE, PCONTEXT);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtResumeThread(HANDLE, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtSuspendThread(HANDLE, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtDelayExecution(BOOLEAN, PLARGE_INTEGER);

/* RTL */
DECLSPEC_IMPORT PVOID   NTAPI NTDLL$RtlAllocateHeap(PVOID, ULONG, SIZE_T);
DECLSPEC_IMPORT BOOLEAN NTAPI NTDLL$RtlFreeHeap(PVOID, ULONG, PVOID);
DECLSPEC_IMPORT ULONG   NTAPI NTDLL$RtlNtStatusToDosError(NTSTATUS);

/* ===========================================================================
 * IPHLPAPI
 * ===========================================================================*/

DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetAdaptersInfo(PVOID, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetAdaptersAddresses(ULONG, ULONG, PVOID, PVOID, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetIpAddrTable(PVOID, PULONG, BOOL);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetTcpTable(PVOID, PDWORD, BOOL);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetExtendedTcpTable(PVOID, PDWORD, BOOL, ULONG, DWORD, ULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetUdpTable(PVOID, PDWORD, BOOL);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetExtendedUdpTable(PVOID, PDWORD, BOOL, ULONG, DWORD, ULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetIfTable(PVOID, PULONG, BOOL);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetIpNetTable(PVOID, PULONG, BOOL);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetNetworkParams(PVOID, PULONG);

/* ===========================================================================
 * WS2_32
 * ===========================================================================*/

DECLSPEC_IMPORT int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAGetLastError(void);
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT int WSAAPI WS2_32$bind(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$listen(SOCKET, int);
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$accept(SOCKET, struct sockaddr*, int*);
DECLSPEC_IMPORT int WSAAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$send(SOCKET, const char*, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$recv(SOCKET, char*, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$sendto(SOCKET, const char*, int, int, const struct sockaddr*, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$recvfrom(SOCKET, char*, int, int, struct sockaddr*, int*);
DECLSPEC_IMPORT int WSAAPI WS2_32$select(int, fd_set*, fd_set*, fd_set*, const struct timeval*);
DECLSPEC_IMPORT int WSAAPI WS2_32$ioctlsocket(SOCKET, long, u_long*);
DECLSPEC_IMPORT int WSAAPI WS2_32$setsockopt(SOCKET, int, int, const char*, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$getsockopt(SOCKET, int, int, char*, int*);
DECLSPEC_IMPORT int WSAAPI WS2_32$shutdown(SOCKET, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$getsockname(SOCKET, struct sockaddr*, int*);
DECLSPEC_IMPORT int WSAAPI WS2_32$getpeername(SOCKET, struct sockaddr*, int*);
DECLSPEC_IMPORT struct hostent* WSAAPI WS2_32$gethostbyname(const char*);
DECLSPEC_IMPORT int WSAAPI WS2_32$gethostname(char*, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$getaddrinfo(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
DECLSPEC_IMPORT void WSAAPI WS2_32$freeaddrinfo(PADDRINFOA);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$inet_addr(const char*);
DECLSPEC_IMPORT char* WSAAPI WS2_32$inet_ntoa(struct in_addr);
DECLSPEC_IMPORT unsigned short WSAAPI WS2_32$htons(unsigned short);
DECLSPEC_IMPORT unsigned short WSAAPI WS2_32$ntohs(unsigned short);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$htonl(unsigned long);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$ntohl(unsigned long);

/* ===========================================================================
 * USER32
 * ===========================================================================*/

DECLSPEC_IMPORT HWND WINAPI USER32$GetDesktopWindow(void);
DECLSPEC_IMPORT HWND WINAPI USER32$GetForegroundWindow(void);
DECLSPEC_IMPORT HWND WINAPI USER32$FindWindowA(LPCSTR, LPCSTR);
DECLSPEC_IMPORT HWND WINAPI USER32$FindWindowW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT int WINAPI USER32$GetWindowTextA(HWND, LPSTR, int);
DECLSPEC_IMPORT int WINAPI USER32$GetWindowTextW(HWND, LPWSTR, int);
DECLSPEC_IMPORT DWORD WINAPI USER32$GetWindowThreadProcessId(HWND, LPDWORD);
DECLSPEC_IMPORT BOOL WINAPI USER32$IsWindow(HWND);
DECLSPEC_IMPORT BOOL WINAPI USER32$IsWindowVisible(HWND);
DECLSPEC_IMPORT BOOL WINAPI USER32$EnumWindows(WNDENUMPROC, LPARAM);
DECLSPEC_IMPORT int WINAPI USER32$MessageBoxA(HWND, LPCSTR, LPCSTR, UINT);
DECLSPEC_IMPORT int WINAPI USER32$MessageBoxW(HWND, LPCWSTR, LPCWSTR, UINT);
DECLSPEC_IMPORT int CDECL USER32$wsprintfA(LPSTR, LPCSTR, ...);
DECLSPEC_IMPORT int CDECL USER32$wsprintfW(LPWSTR, LPCWSTR, ...);

/* ===========================================================================
 * SHELL32
 * ===========================================================================*/

DECLSPEC_IMPORT HINSTANCE WINAPI SHELL32$ShellExecuteA(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
DECLSPEC_IMPORT HINSTANCE WINAPI SHELL32$ShellExecuteW(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
DECLSPEC_IMPORT BOOL WINAPI SHELL32$SHGetSpecialFolderPathA(HWND, LPSTR, int, BOOL);
DECLSPEC_IMPORT BOOL WINAPI SHELL32$SHGetSpecialFolderPathW(HWND, LPWSTR, int, BOOL);

/* ===========================================================================
 * OLE32
 * ===========================================================================*/

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitialize(LPVOID);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT void WINAPI OLE32$CoTaskMemFree(LPVOID);

/* ===========================================================================
 * MSVCRT (use sparingly)
 * ===========================================================================*/

DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$calloc(size_t, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$realloc(void*, size_t);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memmove(void*, const void*, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strncpy(char*, const char*, size_t);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcat(char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$strncmp(const char*, const char*, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strchr(const char*, int);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strrchr(const char*, int);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strstr(const char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$vsprintf(char*, const char*, va_list);
DECLSPEC_IMPORT int __cdecl MSVCRT$vsnprintf(char*, size_t, const char*, va_list);
DECLSPEC_IMPORT int __cdecl MSVCRT$sscanf(const char*, const char*, ...);
DECLSPEC_IMPORT long __cdecl MSVCRT$strtol(const char*, char**, int);
DECLSPEC_IMPORT unsigned long __cdecl MSVCRT$strtoul(const char*, char**, int);
DECLSPEC_IMPORT int __cdecl MSVCRT$atoi(const char*);

/* ===========================================================================
 * CONVENIENCE MACROS
 *
 * Write code like normal C - macros expand to DFR symbols.
 * Example: VirtualAlloc(...) -> KERNEL32$VirtualAlloc(...)
 * ===========================================================================*/

/* kernel32 */
#define GetLastError(...) KERNEL32$GetLastError(__VA_ARGS__)
#define SetLastError(...) KERNEL32$SetLastError(__VA_ARGS__)
#define GetCurrentProcess(...) KERNEL32$GetCurrentProcess(__VA_ARGS__)
#define GetCurrentThread(...) KERNEL32$GetCurrentThread(__VA_ARGS__)
#define GetCurrentProcessId(...) KERNEL32$GetCurrentProcessId(__VA_ARGS__)
#define GetCurrentThreadId(...) KERNEL32$GetCurrentThreadId(__VA_ARGS__)
#define GetProcessId(...) KERNEL32$GetProcessId(__VA_ARGS__)
#define GetThreadId(...) KERNEL32$GetThreadId(__VA_ARGS__)
#define CloseHandle(...) KERNEL32$CloseHandle(__VA_ARGS__)
#define DuplicateHandle(...) KERNEL32$DuplicateHandle(__VA_ARGS__)
#define VirtualAlloc(...) KERNEL32$VirtualAlloc(__VA_ARGS__)
#define VirtualFree(...) KERNEL32$VirtualFree(__VA_ARGS__)
#define VirtualProtect(...) KERNEL32$VirtualProtect(__VA_ARGS__)
#define VirtualQuery(...) KERNEL32$VirtualQuery(__VA_ARGS__)
#define GetProcessHeap(...) KERNEL32$GetProcessHeap(__VA_ARGS__)
#define HeapAlloc(...) KERNEL32$HeapAlloc(__VA_ARGS__)
#define HeapReAlloc(...) KERNEL32$HeapReAlloc(__VA_ARGS__)
#define HeapFree(...) KERNEL32$HeapFree(__VA_ARGS__)
#define GetModuleHandleA(...) KERNEL32$GetModuleHandleA(__VA_ARGS__)
#define GetModuleHandleW(...) KERNEL32$GetModuleHandleW(__VA_ARGS__)
#define LoadLibraryA(...) KERNEL32$LoadLibraryA(__VA_ARGS__)
#define LoadLibraryW(...) KERNEL32$LoadLibraryW(__VA_ARGS__)
#define FreeLibrary(...) KERNEL32$FreeLibrary(__VA_ARGS__)
#define GetProcAddress(...) KERNEL32$GetProcAddress(__VA_ARGS__)
#define GetModuleFileNameA(...) KERNEL32$GetModuleFileNameA(__VA_ARGS__)
#define GetModuleFileNameW(...) KERNEL32$GetModuleFileNameW(__VA_ARGS__)
#define OpenProcess(...) KERNEL32$OpenProcess(__VA_ARGS__)
#define TerminateProcess(...) KERNEL32$TerminateProcess(__VA_ARGS__)
#define GetExitCodeProcess(...) KERNEL32$GetExitCodeProcess(__VA_ARGS__)
#define CreateProcessA(...) KERNEL32$CreateProcessA(__VA_ARGS__)
#define CreateProcessW(...) KERNEL32$CreateProcessW(__VA_ARGS__)
#define OpenThread(...) KERNEL32$OpenThread(__VA_ARGS__)
#define CreateThread(...) KERNEL32$CreateThread(__VA_ARGS__)
#define TerminateThread(...) KERNEL32$TerminateThread(__VA_ARGS__)
#define SuspendThread(...) KERNEL32$SuspendThread(__VA_ARGS__)
#define ResumeThread(...) KERNEL32$ResumeThread(__VA_ARGS__)
#define GetExitCodeThread(...) KERNEL32$GetExitCodeThread(__VA_ARGS__)
#define WaitForSingleObject(...) KERNEL32$WaitForSingleObject(__VA_ARGS__)
#define WaitForMultipleObjects(...) KERNEL32$WaitForMultipleObjects(__VA_ARGS__)
#define Sleep(...) KERNEL32$Sleep(__VA_ARGS__)
#define SwitchToThread(...) KERNEL32$SwitchToThread(__VA_ARGS__)
#define CreateEventA(...) KERNEL32$CreateEventA(__VA_ARGS__)
#define CreateEventW(...) KERNEL32$CreateEventW(__VA_ARGS__)
#define SetEvent(...) KERNEL32$SetEvent(__VA_ARGS__)
#define ResetEvent(...) KERNEL32$ResetEvent(__VA_ARGS__)
#define CreateMutexA(...) KERNEL32$CreateMutexA(__VA_ARGS__)
#define CreateMutexW(...) KERNEL32$CreateMutexW(__VA_ARGS__)
#define ReleaseMutex(...) KERNEL32$ReleaseMutex(__VA_ARGS__)
#define CreateFileA(...) KERNEL32$CreateFileA(__VA_ARGS__)
#define CreateFileW(...) KERNEL32$CreateFileW(__VA_ARGS__)
#define ReadFile(...) KERNEL32$ReadFile(__VA_ARGS__)
#define WriteFile(...) KERNEL32$WriteFile(__VA_ARGS__)
#define GetFileSize(...) KERNEL32$GetFileSize(__VA_ARGS__)
#define GetFileSizeEx(...) KERNEL32$GetFileSizeEx(__VA_ARGS__)
#define SetFilePointer(...) KERNEL32$SetFilePointer(__VA_ARGS__)
#define DeleteFileA(...) KERNEL32$DeleteFileA(__VA_ARGS__)
#define DeleteFileW(...) KERNEL32$DeleteFileW(__VA_ARGS__)
#define CopyFileA(...) KERNEL32$CopyFileA(__VA_ARGS__)
#define CopyFileW(...) KERNEL32$CopyFileW(__VA_ARGS__)
#define MoveFileA(...) KERNEL32$MoveFileA(__VA_ARGS__)
#define MoveFileW(...) KERNEL32$MoveFileW(__VA_ARGS__)
#define GetFileAttributesA(...) KERNEL32$GetFileAttributesA(__VA_ARGS__)
#define GetFileAttributesW(...) KERNEL32$GetFileAttributesW(__VA_ARGS__)
#define FindFirstFileA(...) KERNEL32$FindFirstFileA(__VA_ARGS__)
#define FindFirstFileW(...) KERNEL32$FindFirstFileW(__VA_ARGS__)
#define FindNextFileA(...) KERNEL32$FindNextFileA(__VA_ARGS__)
#define FindNextFileW(...) KERNEL32$FindNextFileW(__VA_ARGS__)
#define FindClose(...) KERNEL32$FindClose(__VA_ARGS__)
#define CreateDirectoryA(...) KERNEL32$CreateDirectoryA(__VA_ARGS__)
#define CreateDirectoryW(...) KERNEL32$CreateDirectoryW(__VA_ARGS__)
#define RemoveDirectoryA(...) KERNEL32$RemoveDirectoryA(__VA_ARGS__)
#define RemoveDirectoryW(...) KERNEL32$RemoveDirectoryW(__VA_ARGS__)
#define GetCurrentDirectoryA(...) KERNEL32$GetCurrentDirectoryA(__VA_ARGS__)
#define GetCurrentDirectoryW(...) KERNEL32$GetCurrentDirectoryW(__VA_ARGS__)
#define SetCurrentDirectoryA(...) KERNEL32$SetCurrentDirectoryA(__VA_ARGS__)
#define SetCurrentDirectoryW(...) KERNEL32$SetCurrentDirectoryW(__VA_ARGS__)
#define GetEnvironmentStringsW(...) KERNEL32$GetEnvironmentStringsW(__VA_ARGS__)
#define FreeEnvironmentStringsW(...) KERNEL32$FreeEnvironmentStringsW(__VA_ARGS__)
#define GetEnvironmentVariableA(...) KERNEL32$GetEnvironmentVariableA(__VA_ARGS__)
#define GetEnvironmentVariableW(...) KERNEL32$GetEnvironmentVariableW(__VA_ARGS__)
#define SetEnvironmentVariableA(...) KERNEL32$SetEnvironmentVariableA(__VA_ARGS__)
#define SetEnvironmentVariableW(...) KERNEL32$SetEnvironmentVariableW(__VA_ARGS__)
#define ExpandEnvironmentStringsA(...) KERNEL32$ExpandEnvironmentStringsA(__VA_ARGS__)
#define ExpandEnvironmentStringsW(...) KERNEL32$ExpandEnvironmentStringsW(__VA_ARGS__)
#define GetSystemInfo(...) KERNEL32$GetSystemInfo(__VA_ARGS__)
#define GetNativeSystemInfo(...) KERNEL32$GetNativeSystemInfo(__VA_ARGS__)
#define GetSystemTime(...) KERNEL32$GetSystemTime(__VA_ARGS__)
#define GetLocalTime(...) KERNEL32$GetLocalTime(__VA_ARGS__)
#define GetTickCount(...) KERNEL32$GetTickCount(__VA_ARGS__)
#define GetTickCount64(...) KERNEL32$GetTickCount64(__VA_ARGS__)
#define QueryPerformanceCounter(...) KERNEL32$QueryPerformanceCounter(__VA_ARGS__)
#define GetSystemDirectoryA(...) KERNEL32$GetSystemDirectoryA(__VA_ARGS__)
#define GetSystemDirectoryW(...) KERNEL32$GetSystemDirectoryW(__VA_ARGS__)
#define GetWindowsDirectoryA(...) KERNEL32$GetWindowsDirectoryA(__VA_ARGS__)
#define GetWindowsDirectoryW(...) KERNEL32$GetWindowsDirectoryW(__VA_ARGS__)
#define GetTempPathA(...) KERNEL32$GetTempPathA(__VA_ARGS__)
#define GetTempPathW(...) KERNEL32$GetTempPathW(__VA_ARGS__)
#define GetComputerNameA(...) KERNEL32$GetComputerNameA(__VA_ARGS__)
#define GetComputerNameW(...) KERNEL32$GetComputerNameW(__VA_ARGS__)
#define lstrlenA(...) KERNEL32$lstrlenA(__VA_ARGS__)
#define lstrlenW(...) KERNEL32$lstrlenW(__VA_ARGS__)
#define lstrcpyA(...) KERNEL32$lstrcpyA(__VA_ARGS__)
#define lstrcpyW(...) KERNEL32$lstrcpyW(__VA_ARGS__)
#define lstrcpynA(...) KERNEL32$lstrcpynA(__VA_ARGS__)
#define lstrcpynW(...) KERNEL32$lstrcpynW(__VA_ARGS__)
#define lstrcatA(...) KERNEL32$lstrcatA(__VA_ARGS__)
#define lstrcatW(...) KERNEL32$lstrcatW(__VA_ARGS__)
#define lstrcmpA(...) KERNEL32$lstrcmpA(__VA_ARGS__)
#define lstrcmpW(...) KERNEL32$lstrcmpW(__VA_ARGS__)
#define lstrcmpiA(...) KERNEL32$lstrcmpiA(__VA_ARGS__)
#define lstrcmpiW(...) KERNEL32$lstrcmpiW(__VA_ARGS__)
#define MultiByteToWideChar(...) KERNEL32$MultiByteToWideChar(__VA_ARGS__)
#define WideCharToMultiByte(...) KERNEL32$WideCharToMultiByte(__VA_ARGS__)
#define CreatePipe(...) KERNEL32$CreatePipe(__VA_ARGS__)
#define PeekNamedPipe(...) KERNEL32$PeekNamedPipe(__VA_ARGS__)

/* advapi32 */
#define OpenProcessToken(...) ADVAPI32$OpenProcessToken(__VA_ARGS__)
#define OpenThreadToken(...) ADVAPI32$OpenThreadToken(__VA_ARGS__)
#define DuplicateToken(...) ADVAPI32$DuplicateToken(__VA_ARGS__)
#define DuplicateTokenEx(...) ADVAPI32$DuplicateTokenEx(__VA_ARGS__)
#define GetTokenInformation(...) ADVAPI32$GetTokenInformation(__VA_ARGS__)
#define SetTokenInformation(...) ADVAPI32$SetTokenInformation(__VA_ARGS__)
#define AdjustTokenPrivileges(...) ADVAPI32$AdjustTokenPrivileges(__VA_ARGS__)
#define ImpersonateLoggedOnUser(...) ADVAPI32$ImpersonateLoggedOnUser(__VA_ARGS__)
#define ImpersonateSelf(...) ADVAPI32$ImpersonateSelf(__VA_ARGS__)
#define RevertToSelf(...) ADVAPI32$RevertToSelf(__VA_ARGS__)
#define SetThreadToken(...) ADVAPI32$SetThreadToken(__VA_ARGS__)
#define LookupAccountSidA(...) ADVAPI32$LookupAccountSidA(__VA_ARGS__)
#define LookupAccountSidW(...) ADVAPI32$LookupAccountSidW(__VA_ARGS__)
#define LookupAccountNameA(...) ADVAPI32$LookupAccountNameA(__VA_ARGS__)
#define LookupAccountNameW(...) ADVAPI32$LookupAccountNameW(__VA_ARGS__)
#define ConvertSidToStringSidA(...) ADVAPI32$ConvertSidToStringSidA(__VA_ARGS__)
#define ConvertSidToStringSidW(...) ADVAPI32$ConvertSidToStringSidW(__VA_ARGS__)
#define IsValidSid(...) ADVAPI32$IsValidSid(__VA_ARGS__)
#define EqualSid(...) ADVAPI32$EqualSid(__VA_ARGS__)
#define GetLengthSid(...) ADVAPI32$GetLengthSid(__VA_ARGS__)
#define LookupPrivilegeNameA(...) ADVAPI32$LookupPrivilegeNameA(__VA_ARGS__)
#define LookupPrivilegeNameW(...) ADVAPI32$LookupPrivilegeNameW(__VA_ARGS__)
#define LookupPrivilegeValueA(...) ADVAPI32$LookupPrivilegeValueA(__VA_ARGS__)
#define LookupPrivilegeValueW(...) ADVAPI32$LookupPrivilegeValueW(__VA_ARGS__)
#define PrivilegeCheck(...) ADVAPI32$PrivilegeCheck(__VA_ARGS__)
#define GetUserNameA(...) ADVAPI32$GetUserNameA(__VA_ARGS__)
#define GetUserNameW(...) ADVAPI32$GetUserNameW(__VA_ARGS__)
#define RegOpenKeyExA(...) ADVAPI32$RegOpenKeyExA(__VA_ARGS__)
#define RegOpenKeyExW(...) ADVAPI32$RegOpenKeyExW(__VA_ARGS__)
#define RegCreateKeyExA(...) ADVAPI32$RegCreateKeyExA(__VA_ARGS__)
#define RegCreateKeyExW(...) ADVAPI32$RegCreateKeyExW(__VA_ARGS__)
#define RegCloseKey(...) ADVAPI32$RegCloseKey(__VA_ARGS__)
#define RegQueryValueExA(...) ADVAPI32$RegQueryValueExA(__VA_ARGS__)
#define RegQueryValueExW(...) ADVAPI32$RegQueryValueExW(__VA_ARGS__)
#define RegSetValueExA(...) ADVAPI32$RegSetValueExA(__VA_ARGS__)
#define RegSetValueExW(...) ADVAPI32$RegSetValueExW(__VA_ARGS__)
#define RegDeleteKeyA(...) ADVAPI32$RegDeleteKeyA(__VA_ARGS__)
#define RegDeleteKeyW(...) ADVAPI32$RegDeleteKeyW(__VA_ARGS__)
#define RegDeleteValueA(...) ADVAPI32$RegDeleteValueA(__VA_ARGS__)
#define RegDeleteValueW(...) ADVAPI32$RegDeleteValueW(__VA_ARGS__)
#define RegEnumKeyExA(...) ADVAPI32$RegEnumKeyExA(__VA_ARGS__)
#define RegEnumKeyExW(...) ADVAPI32$RegEnumKeyExW(__VA_ARGS__)
#define RegEnumValueA(...) ADVAPI32$RegEnumValueA(__VA_ARGS__)
#define RegEnumValueW(...) ADVAPI32$RegEnumValueW(__VA_ARGS__)
#define QueryServiceConfigA(...) ADVAPI32$QueryServiceConfigA(__VA_ARGS__)
#define OpenSCManagerA(...) ADVAPI32$OpenSCManagerA(__VA_ARGS__)
#define OpenSCManagerW(...) ADVAPI32$OpenSCManagerW(__VA_ARGS__)
#define OpenServiceA(...) ADVAPI32$OpenServiceA(__VA_ARGS__)
#define OpenServiceW(...) ADVAPI32$OpenServiceW(__VA_ARGS__)
#define CloseServiceHandle(...) ADVAPI32$CloseServiceHandle(__VA_ARGS__)
#define QueryServiceStatus(...) ADVAPI32$QueryServiceStatus(__VA_ARGS__)
#define StartServiceA(...) ADVAPI32$StartServiceA(__VA_ARGS__)
#define StartServiceW(...) ADVAPI32$StartServiceW(__VA_ARGS__)
#define ControlService(...) ADVAPI32$ControlService(__VA_ARGS__)
#define CryptAcquireContextA(...) ADVAPI32$CryptAcquireContextA(__VA_ARGS__)
#define CryptAcquireContextW(...) ADVAPI32$CryptAcquireContextW(__VA_ARGS__)
#define CryptReleaseContext(...) ADVAPI32$CryptReleaseContext(__VA_ARGS__)
#define CryptGenRandom(...) ADVAPI32$CryptGenRandom(__VA_ARGS__)

/* secur32 */
#define GetUserNameExA(...) SECUR32$GetUserNameExA(__VA_ARGS__)
#define GetUserNameExW(...) SECUR32$GetUserNameExW(__VA_ARGS__)
#define GetComputerObjectNameA(...) SECUR32$GetComputerObjectNameA(__VA_ARGS__)
#define GetComputerObjectNameW(...) SECUR32$GetComputerObjectNameW(__VA_ARGS__)

/* ntdll */
#define NtClose(...) NTDLL$NtClose(__VA_ARGS__)
#define NtQueryInformationProcess(...) NTDLL$NtQueryInformationProcess(__VA_ARGS__)
#define NtQueryInformationThread(...) NTDLL$NtQueryInformationThread(__VA_ARGS__)
#define NtQuerySystemInformation(...) NTDLL$NtQuerySystemInformation(__VA_ARGS__)
#define NtQueryObject(...) NTDLL$NtQueryObject(__VA_ARGS__)
#define NtAllocateVirtualMemory(...) NTDLL$NtAllocateVirtualMemory(__VA_ARGS__)
#define NtFreeVirtualMemory(...) NTDLL$NtFreeVirtualMemory(__VA_ARGS__)
#define NtProtectVirtualMemory(...) NTDLL$NtProtectVirtualMemory(__VA_ARGS__)
#define NtReadVirtualMemory(...) NTDLL$NtReadVirtualMemory(__VA_ARGS__)
#define NtWriteVirtualMemory(...) NTDLL$NtWriteVirtualMemory(__VA_ARGS__)
#define NtOpenProcess(...) NTDLL$NtOpenProcess(__VA_ARGS__)
#define NtOpenThread(...) NTDLL$NtOpenThread(__VA_ARGS__)
#define NtGetContextThread(...) NTDLL$NtGetContextThread(__VA_ARGS__)
#define NtSetContextThread(...) NTDLL$NtSetContextThread(__VA_ARGS__)
#define NtResumeThread(...) NTDLL$NtResumeThread(__VA_ARGS__)
#define NtSuspendThread(...) NTDLL$NtSuspendThread(__VA_ARGS__)
#define NtDelayExecution(...) NTDLL$NtDelayExecution(__VA_ARGS__)
#define RtlAllocateHeap(...) NTDLL$RtlAllocateHeap(__VA_ARGS__)
#define RtlFreeHeap(...) NTDLL$RtlFreeHeap(__VA_ARGS__)
#define RtlNtStatusToDosError(...) NTDLL$RtlNtStatusToDosError(__VA_ARGS__)

/* iphlpapi */
#define GetAdaptersInfo(...) IPHLPAPI$GetAdaptersInfo(__VA_ARGS__)
#define GetAdaptersAddresses(...) IPHLPAPI$GetAdaptersAddresses(__VA_ARGS__)
#define GetIpAddrTable(...) IPHLPAPI$GetIpAddrTable(__VA_ARGS__)
#define GetTcpTable(...) IPHLPAPI$GetTcpTable(__VA_ARGS__)
#define GetExtendedTcpTable(...) IPHLPAPI$GetExtendedTcpTable(__VA_ARGS__)
#define GetUdpTable(...) IPHLPAPI$GetUdpTable(__VA_ARGS__)
#define GetExtendedUdpTable(...) IPHLPAPI$GetExtendedUdpTable(__VA_ARGS__)
#define GetIfTable(...) IPHLPAPI$GetIfTable(__VA_ARGS__)
#define GetIpNetTable(...) IPHLPAPI$GetIpNetTable(__VA_ARGS__)
#define GetNetworkParams(...) IPHLPAPI$GetNetworkParams(__VA_ARGS__)

/* ws2_32 */
#define WSAStartup(...) WS2_32$WSAStartup(__VA_ARGS__)
#define WSACleanup(...) WS2_32$WSACleanup(__VA_ARGS__)
#define WSAGetLastError(...) WS2_32$WSAGetLastError(__VA_ARGS__)
/* socket/closesocket/bind/listen/accept/connect/send/recv use generic names - use API() macro */
#define sendto(...) WS2_32$sendto(__VA_ARGS__)
#define recvfrom(...) WS2_32$recvfrom(__VA_ARGS__)
/* select conflicts with POSIX - use API() macro */
#define ioctlsocket(...) WS2_32$ioctlsocket(__VA_ARGS__)
#define setsockopt(...) WS2_32$setsockopt(__VA_ARGS__)
#define getsockopt(...) WS2_32$getsockopt(__VA_ARGS__)
/* shutdown is generic - use API() macro */
#define gethostbyname(...) WS2_32$gethostbyname(__VA_ARGS__)
#define gethostname(...) WS2_32$gethostname(__VA_ARGS__)
#define getsockname(...) WS2_32$getsockname(__VA_ARGS__)
#define getpeername(...) WS2_32$getpeername(__VA_ARGS__)
#define getaddrinfo(...) WS2_32$getaddrinfo(__VA_ARGS__)
#define freeaddrinfo(...) WS2_32$freeaddrinfo(__VA_ARGS__)
#define inet_addr(...) WS2_32$inet_addr(__VA_ARGS__)
#define inet_ntoa(...) WS2_32$inet_ntoa(__VA_ARGS__)
#define htons(...) WS2_32$htons(__VA_ARGS__)
#define ntohs(...) WS2_32$ntohs(__VA_ARGS__)
#define htonl(...) WS2_32$htonl(__VA_ARGS__)
#define ntohl(...) WS2_32$ntohl(__VA_ARGS__)

/* user32 */
#define GetDesktopWindow(...) USER32$GetDesktopWindow(__VA_ARGS__)
#define GetForegroundWindow(...) USER32$GetForegroundWindow(__VA_ARGS__)
#define FindWindowA(...) USER32$FindWindowA(__VA_ARGS__)
#define FindWindowW(...) USER32$FindWindowW(__VA_ARGS__)
#define GetWindowTextA(...) USER32$GetWindowTextA(__VA_ARGS__)
#define GetWindowTextW(...) USER32$GetWindowTextW(__VA_ARGS__)
#define GetWindowThreadProcessId(...) USER32$GetWindowThreadProcessId(__VA_ARGS__)
#define IsWindow(...) USER32$IsWindow(__VA_ARGS__)
#define IsWindowVisible(...) USER32$IsWindowVisible(__VA_ARGS__)
#define EnumWindows(...) USER32$EnumWindows(__VA_ARGS__)
#define MessageBoxA(...) USER32$MessageBoxA(__VA_ARGS__)
#define MessageBoxW(...) USER32$MessageBoxW(__VA_ARGS__)
#define wsprintfA(...) USER32$wsprintfA(__VA_ARGS__)
#define wsprintfW(...) USER32$wsprintfW(__VA_ARGS__)

/* shell32 */
#define ShellExecuteA(...) SHELL32$ShellExecuteA(__VA_ARGS__)
#define ShellExecuteW(...) SHELL32$ShellExecuteW(__VA_ARGS__)
#define SHGetSpecialFolderPathA(...) SHELL32$SHGetSpecialFolderPathA(__VA_ARGS__)
#define SHGetSpecialFolderPathW(...) SHELL32$SHGetSpecialFolderPathW(__VA_ARGS__)

/* ole32 */
#define CoInitialize(...) OLE32$CoInitialize(__VA_ARGS__)
#define CoInitializeEx(...) OLE32$CoInitializeEx(__VA_ARGS__)
#define CoUninitialize(...) OLE32$CoUninitialize(__VA_ARGS__)
#define CoCreateInstance(...) OLE32$CoCreateInstance(__VA_ARGS__)
#define CoTaskMemFree(...) OLE32$CoTaskMemFree(__VA_ARGS__)

/* msvcrt - prefixed with underscore to avoid conflicts with compiler builtins */
#define _malloc(...) MSVCRT$malloc(__VA_ARGS__)
#define _calloc(...) MSVCRT$calloc(__VA_ARGS__)
#define _realloc(...) MSVCRT$realloc(__VA_ARGS__)
#define _free(...) MSVCRT$free(__VA_ARGS__)
#define _memcpy(...) MSVCRT$memcpy(__VA_ARGS__)
#define _memset(...) MSVCRT$memset(__VA_ARGS__)
#define _memmove(...) MSVCRT$memmove(__VA_ARGS__)
#define _memcmp(...) MSVCRT$memcmp(__VA_ARGS__)
#define _strlen(...) MSVCRT$strlen(__VA_ARGS__)
#define _wcslen(...) MSVCRT$wcslen(__VA_ARGS__)
#define _strcpy(...) MSVCRT$strcpy(__VA_ARGS__)
#define _strncpy(...) MSVCRT$strncpy(__VA_ARGS__)
#define _strcat(...) MSVCRT$strcat(__VA_ARGS__)
#define _strcmp(...) MSVCRT$strcmp(__VA_ARGS__)
#define _strncmp(...) MSVCRT$strncmp(__VA_ARGS__)
#define _stricmp(...) MSVCRT$_stricmp(__VA_ARGS__)
#define _strchr(...) MSVCRT$strchr(__VA_ARGS__)
#define _strrchr(...) MSVCRT$strrchr(__VA_ARGS__)
#define _strstr(...) MSVCRT$strstr(__VA_ARGS__)
#define _sprintf(...) MSVCRT$sprintf(__VA_ARGS__)
#define _snprintf(...) MSVCRT$snprintf(__VA_ARGS__)
#define _vsprintf(...) MSVCRT$vsprintf(__VA_ARGS__)
#define _vsnprintf(...) MSVCRT$vsnprintf(__VA_ARGS__)
#define _sscanf(...) MSVCRT$sscanf(__VA_ARGS__)
#define _strtol(...) MSVCRT$strtol(__VA_ARGS__)
#define _strtoul(...) MSVCRT$strtoul(__VA_ARGS__)
#define _atoi(...) MSVCRT$atoi(__VA_ARGS__)

/* ===========================================================================
 * COBALT STRIKE COMPATIBILITY
 *
 * CS BOFs work natively. The real functions are BeaconPrintf, BeaconData*, etc.
 * DFR symbols (KERNEL32$, ADVAPI32$, etc.) work as-is.
 * ===========================================================================*/

/* datap is the CS name for the argument parser struct */
#define datap _args

#ifdef __cplusplus
}
#endif

#endif /* PYNET_BOF_H */
