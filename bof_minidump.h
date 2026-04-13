/*
 * bof_minidump.h - Minidump format structures for MiniDumpWriteDump BOF
 *
 * Windows Minidump file format structures for creating process memory dumps.
 * Based on Microsoft's minidump format specification.
 */

#ifndef BOF_MINIDUMP_H
#define BOF_MINIDUMP_H

#include <windows.h>

/* ===========================================================================
 * MINIDUMP CONSTANTS
 * ===========================================================================*/

#define MINIDUMP_SIGNATURE 0x504D444D  /* 'MDMP' */
#define MINIDUMP_VERSION   (42899)

/* Stream types */
#define UnusedStream                0
#define ReservedStream0             1
#define ReservedStream1             2
#define ThreadListStream            3
#define ModuleListStream            4
#define MemoryListStream            5
#define ExceptionStream             6
#define SystemInfoStream            7
#define ThreadExListStream          8
#define Memory64ListStream          9
#define CommentStreamA              10
#define CommentStreamW              11
#define HandleDataStream            12
#define FunctionTableStream         13
#define UnloadedModuleListStream    14
#define MiscInfoStream              15
#define MemoryInfoListStream        16
#define ThreadInfoListStream        17
#define HandleOperationListStream   18

/* Processor architecture */
#define PROCESSOR_ARCHITECTURE_INTEL   0
#define PROCESSOR_ARCHITECTURE_AMD64   9
#define PROCESSOR_ARCHITECTURE_ARM64   12

/* ===========================================================================
 * MINIDUMP STRUCTURES
 * ===========================================================================*/

#pragma pack(push, 4)

typedef struct _MINIDUMP_LOCATION_DESCRIPTOR {
    ULONG32 DataSize;
    ULONG32 Rva;
} MINIDUMP_LOCATION_DESCRIPTOR;

typedef struct _MINIDUMP_LOCATION_DESCRIPTOR64 {
    ULONG64 DataSize;
    ULONG64 Rva;
} MINIDUMP_LOCATION_DESCRIPTOR64;

typedef struct _MINIDUMP_MEMORY_DESCRIPTOR {
    ULONG64 StartOfMemoryRange;
    MINIDUMP_LOCATION_DESCRIPTOR Memory;
} MINIDUMP_MEMORY_DESCRIPTOR;

typedef struct _MINIDUMP_MEMORY_DESCRIPTOR64 {
    ULONG64 StartOfMemoryRange;
    ULONG64 DataSize;
} MINIDUMP_MEMORY_DESCRIPTOR64;

typedef struct _MINIDUMP_HEADER {
    ULONG32 Signature;
    ULONG32 Version;
    ULONG32 NumberOfStreams;
    ULONG32 StreamDirectoryRva;
    ULONG32 CheckSum;
    union {
        ULONG32 Reserved;
        ULONG32 TimeDateStamp;
    };
    ULONG64 Flags;
} MINIDUMP_HEADER;

typedef struct _MINIDUMP_DIRECTORY {
    ULONG32 StreamType;
    MINIDUMP_LOCATION_DESCRIPTOR Location;
} MINIDUMP_DIRECTORY;

typedef struct _MINIDUMP_STRING {
    ULONG32 Length;
    WCHAR   Buffer[1];  /* Variable length */
} MINIDUMP_STRING;

typedef struct _MINIDUMP_SYSTEM_INFO {
    USHORT  ProcessorArchitecture;
    USHORT  ProcessorLevel;
    USHORT  ProcessorRevision;
    union {
        USHORT Reserved0;
        struct {
            UCHAR NumberOfProcessors;
            UCHAR ProductType;
        };
    };
    ULONG32 MajorVersion;
    ULONG32 MinorVersion;
    ULONG32 BuildNumber;
    ULONG32 PlatformId;
    ULONG32 CSDVersionRva;
    union {
        ULONG32 Reserved1;
        struct {
            USHORT SuiteMask;
            USHORT Reserved2;
        };
    };
    union {
        struct {
            ULONG32 VendorId[3];
            ULONG32 VersionInformation;
            ULONG32 FeatureInformation;
            ULONG32 AMDExtendedCpuFeatures;
        } X86CpuInfo;
        struct {
            ULONG64 ProcessorFeatures[2];
        } OtherCpuInfo;
    } Cpu;
} MINIDUMP_SYSTEM_INFO;

typedef struct _MINIDUMP_THREAD {
    ULONG32 ThreadId;
    ULONG32 SuspendCount;
    ULONG32 PriorityClass;
    ULONG32 Priority;
    ULONG64 Teb;
    MINIDUMP_MEMORY_DESCRIPTOR Stack;
    MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
} MINIDUMP_THREAD;

typedef struct _MINIDUMP_THREAD_LIST {
    ULONG32 NumberOfThreads;
    MINIDUMP_THREAD Threads[1];  /* Variable length */
} MINIDUMP_THREAD_LIST;

/* VS_FIXEDFILEINFO is already defined in winver.h via windows.h */

typedef struct _MINIDUMP_MODULE {
    ULONG64 BaseOfImage;
    ULONG32 SizeOfImage;
    ULONG32 CheckSum;
    ULONG32 TimeDateStamp;
    ULONG32 ModuleNameRva;
    VS_FIXEDFILEINFO VersionInfo;
    MINIDUMP_LOCATION_DESCRIPTOR CvRecord;
    MINIDUMP_LOCATION_DESCRIPTOR MiscRecord;
    ULONG64 Reserved0;
    ULONG64 Reserved1;
} MINIDUMP_MODULE;

typedef struct _MINIDUMP_MODULE_LIST {
    ULONG32 NumberOfModules;
    MINIDUMP_MODULE Modules[1];  /* Variable length */
} MINIDUMP_MODULE_LIST;

typedef struct _MINIDUMP_MEMORY_LIST {
    ULONG32 NumberOfMemoryRanges;
    MINIDUMP_MEMORY_DESCRIPTOR MemoryRanges[1];  /* Variable length */
} MINIDUMP_MEMORY_LIST;

typedef struct _MINIDUMP_MEMORY64_LIST {
    ULONG64 NumberOfMemoryRanges;
    ULONG64 BaseRva;
    MINIDUMP_MEMORY_DESCRIPTOR64 MemoryRanges[1];  /* Variable length */
} MINIDUMP_MEMORY64_LIST;

#pragma pack(pop)

/* ===========================================================================
 * PSAPI STRUCTURES
 * ===========================================================================*/

typedef struct _MODULEINFO {
    LPVOID lpBaseOfDll;
    DWORD SizeOfImage;
    LPVOID EntryPoint;
} MODULEINFO, *LPMODULEINFO;

/* ===========================================================================
 * DUMP CONTEXT STRUCTURES (for building minidump)
 * ===========================================================================*/

typedef struct _DUMP_MODULE_ENTRY {
    ULONG64 BaseAddress;
    ULONG32 Size;
    ULONG32 TimeDateStamp;
    ULONG32 CheckSum;
    WCHAR   Name[MAX_PATH];
} DUMP_MODULE_ENTRY;

typedef struct _DUMP_MEMORY_ENTRY {
    ULONG64 BaseAddress;
    ULONG64 Size;
} DUMP_MEMORY_ENTRY;

typedef struct _DUMP_CONTEXT {
    HANDLE  hProcess;
    DWORD   ProcessId;
    HANDLE  hFile;

    /* Modules */
    DUMP_MODULE_ENTRY* Modules;
    ULONG32 ModuleCount;
    ULONG32 ModuleCapacity;

    /* Memory regions */
    DUMP_MEMORY_ENTRY* MemoryRanges;
    ULONG64 MemoryRangeCount;
    ULONG64 MemoryRangeCapacity;

    /* File position tracking */
    ULONG32 CurrentRva;

} DUMP_CONTEXT;

/* ===========================================================================
 * HELPER MACROS
 * ===========================================================================*/

#define ALIGN_UP(value, alignment) (((value) + (alignment) - 1) & ~((alignment) - 1))
#define RVA_ALIGN 4

#endif /* BOF_MINIDUMP_H */
