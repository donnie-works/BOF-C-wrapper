#ifndef MANUAL_GETPROC_H
#define MANUAL_GETPROC_H

/*
 * manual_getproc.h - Manual GetProcAddress replacement
 *
 * Resolves function addresses using PEB walking + PE export parsing.
 * No API calls - completely manual resolution.
 *
 * Usage:
 *   #include "bof.h"
 *   #include "manual_getproc.h"
 *
 *   PVOID addr = manual_get_proc("kernel32.dll", "VirtualAlloc");
 */

#include "bof_ntapi.h"

// Case-insensitive compare: wide string (from PEB) vs narrow string
static int _wcscmp_narrow(const wchar_t* wide, const char* narrow) {
    while (*wide && *narrow) {
        wchar_t w = *wide;
        char    n = *narrow;
        if (w >= 'A' && w <= 'Z') w += 32;
        if (n >= 'A' && n <= 'Z') n += 32;
        if (w != (wchar_t)n) return 1;
        wide++;
        narrow++;
    }
    return (*wide == 0 && *narrow == 0) ? 0 : 1;
}

// Case-insensitive narrow string compare
static int _stricmp_manual(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 1;
        a++;
        b++;
    }
    return (*a == 0 && *b == 0) ? 0 : 1;
}

// Typedef for LoadLibraryA (used for forwarder resolution)
typedef HMODULE (WINAPI *fnLoadLibraryA)(LPCSTR);

// Forward declaration
static PVOID manual_get_proc(const char* dll_name, const char* func_name);

/*
 * _get_proc_no_fwd - Internal helper that doesn't follow forwarders
 * Used to safely resolve LoadLibraryA without recursion issues
 */
static PVOID _get_proc_no_fwd(const char* dll_name, const char* func_name) {

    #ifdef _WIN64
        PEB* peb = (PEB*)__readgsqword(0x60);
    #else
        PEB* peb = (PEB*)__readfsdword(0x30);
    #endif

    PVOID dll_base = NULL;
    LIST_ENTRY* listHead = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* current  =  peb->Ldr->InMemoryOrderModuleList.Flink;

    while (current != listHead) {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(
            current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer != NULL) {
            if (_wcscmp_narrow(entry->BaseDllName.Buffer, dll_name) == 0) {
                dll_base = entry->DllBase;
                break;
            }
        }
        current = current->Flink;
    }

    if (dll_base == NULL) return NULL;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dll_base;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)((BYTE*)dll_base + dos->e_lfanew);

    if (nt->OptionalHeader.DataDirectory[0].VirtualAddress == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(
        (BYTE*)dll_base + nt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)dll_base + exp->AddressOfNames);
    DWORD* funcs = (DWORD*)((BYTE*)dll_base + exp->AddressOfFunctions);
    WORD*  ords  = (WORD*) ((BYTE*)dll_base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)dll_base + names[i]);
        if (_stricmp_manual(name, func_name) == 0) {
            WORD  ord  = ords[i];
            DWORD rva  = funcs[ord];
            return (PVOID)((BYTE*)dll_base + rva);
        }
    }
    return NULL;
}

/*
 * manual_get_proc - Resolve function address without API calls
 *
 * @dll_name:  DLL name (e.g., "kernel32.dll") - case insensitive
 * @func_name: Export name (e.g., "VirtualAlloc") - case insensitive
 *
 * Returns: Function address, or NULL if not found
 */
static PVOID manual_get_proc(const char* dll_name, const char* func_name) {

    // =========================================================================
    // PHASE 1: PEB Walk - Find DLL base address
    // =========================================================================

    #ifdef _WIN64
        PEB* peb = (PEB*)__readgsqword(0x60);
    #else
        PEB* peb = (PEB*)__readfsdword(0x30);
    #endif

    PVOID dll_base = NULL;
    LIST_ENTRY* listHead = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* current  =  peb->Ldr->InMemoryOrderModuleList.Flink;

    while (current != listHead) {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(
            current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (entry->BaseDllName.Buffer != NULL) {
            if (_wcscmp_narrow(entry->BaseDllName.Buffer, dll_name) == 0) {
                dll_base = entry->DllBase;
                break;
            }
        }
        current = current->Flink;
    }

    if (dll_base == NULL) {
        return NULL;
    }

    // =========================================================================
    // PHASE 2: Export Walk - Find function address in PE export table
    // =========================================================================

    // Navigate PE headers: DOS -> NT -> Export Directory
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dll_base;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)((BYTE*)dll_base + dos->e_lfanew);

    // Check if export directory exists
    if (nt->OptionalHeader.DataDirectory[0].VirtualAddress == 0) {
        return NULL;
    }

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(
        (BYTE*)dll_base + nt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD exp_start = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    DWORD exp_end = exp_start + nt->OptionalHeader.DataDirectory[0].Size;

    // Get the three export arrays
    DWORD* names = (DWORD*)((BYTE*)dll_base + exp->AddressOfNames);
    DWORD* funcs = (DWORD*)((BYTE*)dll_base + exp->AddressOfFunctions);
    WORD*  ords  = (WORD*) ((BYTE*)dll_base + exp->AddressOfNameOrdinals);

    // Walk names looking for func_name
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)dll_base + names[i]);

        if (_stricmp_manual(name, func_name) == 0) {
            WORD  ord  = ords[i];
            DWORD rva  = funcs[ord];

            // Check for forwarded export
            if (rva >= exp_start && rva < exp_end) {
                char* forwarder = (char*)((BYTE*)dll_base + rva);
                char* dot = _strchr(forwarder, '.');
                if (dot) {
                    char fwd_dll[64];
                    int fwd_dll_len = dot - forwarder;
                    _memcpy(fwd_dll, forwarder, fwd_dll_len);
                    _strcpy(fwd_dll + fwd_dll_len, ".dll");

                    // Resolve LoadLibraryA using internal helper (no forwarder handling)
                    fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)_get_proc_no_fwd(
                        "kernel32.dll", "LoadLibraryA");
                    if (pLoadLibraryA) {
                        pLoadLibraryA(fwd_dll);
                    }

                    return manual_get_proc(fwd_dll, dot + 1);
                }
                return NULL;
            }
            PVOID addr = (PVOID)((BYTE*)dll_base + rva);
            return addr;
        }
    }

    return NULL;
}

#endif /* MANUAL_GETPROC_H */
