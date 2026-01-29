#ifndef PYNET_BOF_NTAPI_H
#define PYNET_BOF_NTAPI_H

/*
 * bof_ntapi.h - NT native API structs for PyNet BOFs
 *
 * Use instead of <winternl.h> to avoid DFR conflicts.
 * Include AFTER bof.h
 */

typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STR;

typedef struct _SYSTEM_PROC_INFO {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STR ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
} SYSTEM_PROC_INFO;

#endif /* PYNET_BOF_NTAPI_H */
