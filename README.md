# BOF-C-wrapper

C header SDK for writing Beacon Object Files (BOFs) in a manner closer to standard C code. Compatible with Cobalt Strike and other C2s using the Cobalt Strike BOF format.

## Files

- **bof.h** - Main SDK header. Includes output macros, argument parsing, Dynamic Function Resolution (DFR)
declarations, and convenience macros for Windows APIs.
- **bof_net.h** - Network structure definitions (`MIB_TCPTABLE_OWNER_PID`, `IP_ADAPTER_INFO`, etc.). Use instead of
`<iphlpapi.h>` to avoid DFR conflicts. Include after `bof.h`.

## Usage 

```c
#include "bof.h"
#include "bof_net.h"  // only if you need network structs

void go(char* args, int len)
{
    _printf("Hello from BOF\n");

    // Argument parsing
    _args parser;
    _args_parse(&parser, args, len);
    int pid = _args_int(&parser);

    // Windows APIs work directly via convenience macros
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    CloseHandle(h);

    // Or use the API() macro for any DFR symbol
    API(KERNEL32, GetCurrentProcessId)();
}
```

## Comparison bof.h format vs beacon.h format

### bof.h format:
```c
#include "bof.h"
#include "bof_ntapi.h"

  void go(char *args, int len) {
      NTSTATUS status;
      ULONG bufferSize = 0x200000;  // 2MB
      ULONG returnLength = 0;
      PVOID buffer = NULL;
      HANDLE heap = GetProcessHeap();

      
      buffer = HeapAlloc(heap, 0, bufferSize);
      if (!buffer) {
          _printf("Failed to allocate memory\n");
          return;
      }
      
      status = NtQuerySystemInformation(5, buffer, bufferSize, &returnLength);
      if (status !=  0) {
         _perror("Failed: 0x%08X\n", status);
         
         HeapFree(heap, 0, buffer);
         return;
      }

      SYSTEM_PROC_INFO *proc = (SYSTEM_PROC_INFO *)buffer;
      _printf("%-7s %-7s %s\n", "PID", "PPID", "Name");
      _printf("------- ------- ----\n");

      while (1) {
          ULONG pid = (ULONG)(ULONG_PTR)proc->UniqueProcessId;
          ULONG ppid = (ULONG)(ULONG_PTR)proc->InheritedFromUniqueProcessId;

          if (proc->ImageName.Length > 0 && proc->ImageName.Buffer) {
              WCHAR *name = proc->ImageName.Buffer;
              int nameLen = proc->ImageName.Length / 2;
              char ascii[128];
              int i;
              for (i = 0; i < nameLen && i < 127; i++) {
                  ascii[i] = (char)name[i];
              }
              ascii[i] = 0;
              _printf("%-7d %-7d %s\n", pid, ppid, ascii);
          } else {
              _printf("%-7d %-7d [System]\n", pid, ppid);
          }

          if (proc->NextEntryOffset == 0)
              break;
          proc = (SYSTEM_PROC_INFO *)((BYTE *)proc + proc->NextEntryOffset);
      }

      HeapFree(heap, 0, buffer);
  }
```

### Standard beacon.h format:
```c
  #include <windows.h>
  #include "beacon.h"

  
  typedef LONG NTSTATUS;
  #define NTAPI __stdcall

  DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(
      ULONG SystemInformationClass,
      PVOID SystemInformation,
      ULONG SystemInformationLength,
      PULONG ReturnLength
  );
  DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
  DECLSPEC_IMPORT PVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
  DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);

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

  void go(char *args, int len) {
      NTSTATUS status;
      ULONG bufferSize = 0x200000;
      ULONG returnLength = 0;
      PVOID buffer = NULL;
      HANDLE heap = KERNEL32$GetProcessHeap();

      buffer = KERNEL32$HeapAlloc(heap, 0, bufferSize);
      if (!buffer) {
          BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory\n");
          return;
      }

      status = NTDLL$NtQuerySystemInformation(5, buffer, bufferSize, &returnLength);
      if (status != 0) {
          BeaconPrintf(CALLBACK_ERROR, "Failed: 0x%08X\n", status);
          KERNEL32$HeapFree(heap, 0, buffer);
          return;
      }

      SYSTEM_PROC_INFO *proc = (SYSTEM_PROC_INFO *)buffer;

      BeaconPrintf(CALLBACK_OUTPUT, "%-7s %-7s %s\n", "PID", "PPID", "Name");
      BeaconPrintf(CALLBACK_OUTPUT, "------- ------- ----\n");

      while (1) {
          ULONG pid = (ULONG)(ULONG_PTR)proc->UniqueProcessId;
          ULONG ppid = (ULONG)(ULONG_PTR)proc->InheritedFromUniqueProcessId;

          if (proc->ImageName.Length > 0 && proc->ImageName.Buffer) {
              WCHAR *name = proc->ImageName.Buffer;
              int nameLen = proc->ImageName.Length / 2;
              char ascii[128];
              int i;
              for (i = 0; i < nameLen && i < 127; i++) {
                  ascii[i] = (char)name[i];
              }
              ascii[i] = 0;
              BeaconPrintf(CALLBACK_OUTPUT, "%-7d %-7d %s\n", pid, ppid, ascii);
          } else {
              BeaconPrintf(CALLBACK_OUTPUT, "%-7d %-7d [System]\n", pid, ppid);
          }

          if (proc->NextEntryOffset == 0)
              break;
          proc = (SYSTEM_PROC_INFO *)((BYTE *)proc + proc->NextEntryOffset);
      }

      KERNEL32$HeapFree(heap, 0, buffer);
  }
```

## API Coverage

| DLL | Examples |
|---|---|
| KERNEL32 | Memory, process, thread, file, sync, module, string |
| ADVAPI32 | Token, SID, privilege, registry, service, crypto |
| NTDLL | Nt* syscall wrappers, RTL heap |
| IPHLPAPI | TCP/UDP tables, adapter info, network params |
| WS2_32 | Sockets, address conversion (`inet_ntoa`, `ntohs`, etc.) |
| USER32 | Window enumeration, message box |
| SHELL32 | Shell execute, special folders |
| OLE32 | COM initialization |
| MSVCRT | String, memory, formatting (prefixed with `_`) |

---

## Convenience Macros

| Macro | Maps To | Description |
|---|---|---|
| `_printf(fmt, ...)` | `BeaconPrintf(CALLBACK_OUTPUT, ...)` | Standard output to teamserver |
| `_perror(fmt, ...)` | `BeaconPrintf(CALLBACK_ERROR, ...)` | Error output to teamserver |
| `_args_parse(a, buf, len)` | `BeaconDataParse()` | Initialize argument parser |
| `_args_int(a)` | `BeaconDataInt()` | Extract int from args |
| `_args_short(a)` | `BeaconDataShort()` | Extract short from args |
| `_args_str(a, out_len)` | `BeaconDataExtract()` | Extract string from args |
| `_args_left(a)` | `BeaconDataLength()` | Remaining bytes in args |
| `_args_ptr(a, size)` | `BeaconDataPtr()` | Extract raw pointer from args |

## Beacon APIs

These are used directly by name — no wrapper macros.

- **Format**: `BeaconFormatAlloc()`, `BeaconFormatReset()`, `BeaconFormatFree()`, `BeaconFormatAppend()`,
`BeaconFormatPrintf()`, `BeaconFormatInt()`, `BeaconFormatToString()`
- **Token**: `BeaconUseToken()`, `BeaconRevertToken()`, `BeaconIsAdmin()`
- **Spawn/Inject**: `BeaconGetSpawnTo()`, `BeaconSpawnTemporaryProcess()`, `BeaconInjectProcess()`,
`BeaconInjectTemporaryProcess()`, `BeaconCleanupProcess()`
- **Data Store**: `BeaconDataStoreGetItem()`, `BeaconDataStoreProtectItem()`, `BeaconDataStoreUnprotectItem()`,
`BeaconDataStoreMaxEntries()`
- **Key-Value**: `BeaconAddValue()`, `BeaconGetValue()`, `BeaconRemoveValue()`
- **Syscalls**: `BeaconVirtualAlloc()`, `BeaconVirtualAllocEx()`, `BeaconVirtualProtect()`,
`BeaconVirtualProtectEx()`, `BeaconVirtualFree()`, `BeaconOpenProcess()`, `BeaconCloseHandle()`, etc.
- **Beacon Gate**: `BeaconEnableBeaconGate()`, `BeaconDisableBeaconGate()`, `BeaconEnableBeaconGateMasking()`,
`BeaconDisableBeaconGateMasking()`
- **Utility**: `toWideChar()`, `BeaconInformation()`, `BeaconGetCustomUserData()`, `BeaconDownload()`

## Notes

- MSVCRT functions are prefixed with `_` to avoid compiler builtin conflicts (e.g., `_strlen()`, `_sprintf()`)
- All other header files should be included after `bof.h`
- `bof_net.h` must be included for network structs
- `bof_ntapi.h` must be included for native api structs
- Cobalt Strike BOFs work natively — `datap` is aliased to `_args`
