import winim
import winim/lean

type
  NtAllocateVirtualMemoryFunc = proc(
    ProcessHandle: HANDLE,
    BaseAddress: ptr PVOID,
    ZeroBits: ULONG_PTR,
    RegionSize: ptr SIZE_T,
    AllocationType: ULONG,
    Protect: ULONG
  ): NTSTATUS {.stdcall.}

  NtWriteVirtualMemoryFunc = proc(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    Buffer: PVOID,
    NumberOfBytesToWrite: SIZE_T,
    NumberOfBytesWritten: ptr SIZE_T
  ): NTSTATUS {.stdcall.}

  NtProtectVirtualMemoryFunc = proc(
    ProcessHandle: HANDLE,
    BaseAddress: ptr PVOID,
    NumberOfBytesToProtect: ptr SIZE_T,
    NewAccessProtection: ULONG,
    OldAccessProtection: ptr ULONG
  ): NTSTATUS {.stdcall.}

proc VirtualAllocEx*(
  hProcess: HANDLE,
  lpAddress: LPVOID,
  dwSize: SIZE_T,
  flAllocationType: DWORD,
  flProtect: DWORD
): LPVOID =
  let ntdll = GetModuleHandleA("ntdll")
  if ntdll == 0:
    return nil
  
  let pNtAllocateVirtualMemory = cast[NtAllocateVirtualMemoryFunc](
    GetProcAddress(ntdll, "NtAllocateVirtualMemory")
  )
  
  if pNtAllocateVirtualMemory == nil:
    return nil
  
  var requestedAddress: PVOID = lpAddress
  var requestedSize: SIZE_T = dwSize
  
  if pNtAllocateVirtualMemory(
    hProcess,
    addr requestedAddress,
    0,
    addr requestedSize,
    flAllocationType.ULONG,
    flProtect.ULONG
  ) != 0:
    return nil
  
  return requestedAddress

proc WriteProcessMemory*(
  hProcess: HANDLE,
  lpBaseAddress: LPVOID,
  lpBuffer: LPVOID,
  nSize: SIZE_T,
  lpNumberOfBytesWritten: ptr SIZE_T
): BOOL =
  let ntdll = GetModuleHandleA("ntdll")
  if ntdll == 0:
    return FALSE
  
  let pNtWriteVirtualMemory = cast[NtWriteVirtualMemoryFunc](
    GetProcAddress(ntdll, "NtWriteVirtualMemory")
  )
  
  if pNtWriteVirtualMemory == nil:
    return FALSE
  
  if pNtWriteVirtualMemory(
    hProcess,
    lpBaseAddress,
    lpBuffer,
    nSize,
    lpNumberOfBytesWritten
  ) != 0:
    return FALSE
  
  return TRUE

proc VirtualProtectEx*(
  hProcess: HANDLE,
  lpAddress: LPVOID,
  dwSize: SIZE_T,
  flNewProtect: DWORD,
  lpflOldProtect: PDWORD
): BOOL =
  let ntdll = GetModuleHandleA("ntdll")
  if ntdll == 0:
    return FALSE
  
  let pNtProtectVirtualMemory = cast[NtProtectVirtualMemoryFunc](
    GetProcAddress(ntdll, "NtProtectVirtualMemory")
  )
  
  if pNtProtectVirtualMemory == nil:
    return FALSE
  
  var requestedAddress: PVOID = lpAddress
  var requestedSize: SIZE_T = dwSize
  
  if pNtProtectVirtualMemory(
    hProcess,
    addr requestedAddress,
    addr requestedSize,
    flNewProtect.ULONG,
    cast[ptr ULONG](lpflOldProtect)
  ) != 0:
    return FALSE
  
  return TRUE 