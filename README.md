# BOF-C-wrapper

Writing BOFs traditionally requires verbose `DECLSPEC_IMPORT` declarations, explicit `DLL$Function` syntax, and manual struct definitions — all of which make BOF code harder to write and maintain.

This SDK seeks to eliminate that friction. Through convenience macros and pre-declared DFR symbols, you can write BOFs using familiar Windows API names and standard C patterns.

## Features

- **Standard C style** — Use `OpenProcess()`, `VirtualAlloc()`, `HeapFree()` directly instead of `KERNEL32$OpenProcess`
- **No boilerplate** — 300+ DFR declarations and convenience macros included
- **Backwards compatible** — Works with existing `datap` and `beacon.h` patterns
- **Standalone testing** — Compile and test BOFs as regular executables via compatibility layer

## Files

- **bof.h** — Main SDK header with output macros, argument parsing, DFR declarations, and convenience macros
- **bof_net.h** — Network structures (`MIB_TCPTABLE_OWNER_PID`, `IP_ADAPTER_INFO`, etc.) for use instead of `<iphlpapi.h>`
- **bof_ntapi.h** — NT native API structures (`SYSTEM_PROC_INFO`, `PS_ATTRIBUTE_LIST`, etc.)
- **bof_wmi.h** — WMI/DCOM interface definitions for remote operations
- **bof_compat.h** — Compatibility layer for compiling BOFs as standalone executables outside a C2

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
| OLEAUT32 | BSTR, VARIANT, SafeArray functions |
| MSVCRT | String, memory, formatting (prefixed with `_`) |

---

## Convenience Macros

Output and argument parsing use short, familiar names:

```c
_printf("PID: %d\n", pid);       // BeaconPrintf(CALLBACK_OUTPUT, ...)
_perror("Failed: 0x%08X", err);  // BeaconPrintf(CALLBACK_ERROR, ...)

_args parser;
_args_parse(&parser, args, len); // BeaconDataParse()
int pid = _args_int(&parser);    // BeaconDataInt()
char* str = _args_str(&parser, &out_len); // BeaconDataExtract()
```

## Beacon APIs

Standard Beacon APIs are available directly — Format, Token, Spawn/Inject, Data Store, Key-Value, Syscalls, BeaconGate, and Utility functions.

## Notes

- Include `bof.h` first, then any additional headers as needed
- MSVCRT functions are prefixed with `_` to avoid compiler builtin conflicts (`_strlen()`, `_sprintf()`)
- Cobalt Strike BOFs work natively — `datap` is aliased to `_args`

## Disclaimer

This project is a work in progress. Please be aware that:

- Struct definitions may be incomplete or missing fields for certain use cases
- DFR declarations and convenience macros may not cover all function signatures or calling conventions
- Not all Windows API surface area is covered — you may need to add your own `DECLSPEC_IMPORT` declarations
- Compatibility has not been verified across all C2 frameworks that support the BOF format

If you find issues or have improvements, contributions are welcome.

## License

This project is licensed under the [MIT License](LICENSE).
