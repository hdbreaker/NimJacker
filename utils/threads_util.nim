import winim
import winim/lean
import tables
import strformat

# Import thread constants
import thread_constants

type
  SYSTEM_THREAD_INFORMATION {.pure.} = object
    KernelTime: LARGE_INTEGER
    UserTime: LARGE_INTEGER
    CreateTime: LARGE_INTEGER
    WaitTime: ULONG
    StartAddress: PVOID
    ClientId: CLIENT_ID
    Priority: KPRIORITY
    BasePriority: LONG
    ContextSwitches: ULONG
    ThreadState: ULONG
    WaitReason: ULONG

  SYSTEM_PROCESS_INFORMATION {.pure.} = object
    NextEntryOffset: ULONG
    NumberOfThreads: ULONG
    WorkingSetPrivateSize: LARGE_INTEGER
    HardFaultCount: ULONG
    NumberOfThreadsHighWatermark: ULONG
    CycleTime: ULONGLONG
    CreateTime: LARGE_INTEGER
    UserTime: LARGE_INTEGER
    KernelTime: LARGE_INTEGER
    ImageName: UNICODE_STRING
    BasePriority: KPRIORITY
    UniqueProcessId: HANDLE
    InheritedFromUniqueProcessId: HANDLE
    HandleCount: ULONG
    SessionId: ULONG
    UniqueProcessKey: ULONG_PTR
    PeakVirtualSize: SIZE_T
    VirtualSize: SIZE_T
    PageFaultCount: ULONG
    PeakWorkingSetSize: SIZE_T
    WorkingSetSize: SIZE_T
    QuotaPeakPagedPoolUsage: SIZE_T
    QuotaPagedPoolUsage: SIZE_T
    QuotaPeakNonPagedPoolUsage: SIZE_T
    QuotaNonPagedPoolUsage: SIZE_T
    PagefileUsage: SIZE_T
    PeakPagefileUsage: SIZE_T
    PrivatePageCount: SIZE_T
    ReadOperationCount: LARGE_INTEGER
    WriteOperationCount: LARGE_INTEGER
    OtherOperationCount: LARGE_INTEGER
    ReadTransferCount: LARGE_INTEGER
    WriteTransferCount: LARGE_INTEGER
    OtherTransferCount: LARGE_INTEGER
    Threads: array[1, SYSTEM_THREAD_INFORMATION]

type
  NtQuerySystemInformationType = proc(
    SystemInformationClass: SYSTEM_INFORMATION_CLASS,
    SystemInformation: PVOID,
    SystemInformationLength: ULONG,
    ReturnLength: PULONG
  ): NTSTATUS {.stdcall.}

# Thread information definitions
type
  ThreadInfoExt* = object
    sysStartAddr*: ULONGLONG
    state*: DWORD
    waitReason*: DWORD
    waitTime*: DWORD

  ThreadInfo* = object
    tid*: DWORD
    startAddr*: ULONGLONG
    isExtended*: bool
    ext*: ThreadInfoExt

# Function to read a thread's context
proc readContext*(tid: DWORD, ctx: var CONTEXT): bool =
  let thAccess: DWORD = THREAD_GET_CONTEXT
  let hThread = OpenThread(thAccess, WINBOOL(FALSE), tid)
  if hThread == 0:
    return false

  ctx.ContextFlags = CONTEXT_INTEGER or CONTEXT_CONTROL
  let success = GetThreadContext(hThread, addr ctx)
  CloseHandle(hThread)
  
  return success != 0

# Function to read the return pointer from the stack
proc readReturnPtr*[T](hProcess: HANDLE, rsp: ULONGLONG): T =
  var retAddr: T = 0
  var readSize: SIZE_T = 0
  
  if ReadProcessMemory(
    hProcess, 
    cast[LPVOID](rsp), 
    addr retAddr, 
    sizeof(T), 
    addr readSize
  ) != 0 and readSize == sizeof(T):
    return retAddr
  
  return 0

# Get detailed information about threads
proc queryThreadDetails*(tid: DWORD, info: var ThreadInfo): bool =
  let ntdll = GetModuleHandleA("ntdll.dll")
  if ntdll == 0:
    return false
  
  type 
    NtQueryInformationThreadType = proc(
      ThreadHandle: HANDLE,
      ThreadInformationClass: THREADINFOCLASS,
      ThreadInformation: PVOID,
      ThreadInformationLength: ULONG,
      ReturnLength: PULONG
    ): NTSTATUS {.stdcall.}
  
  let pNtQueryInformationThread = cast[NtQueryInformationThreadType](
    GetProcAddress(ntdll, "NtQueryInformationThread")
  )
  
  if pNtQueryInformationThread == nil:
    return false
  
  let thAccess: DWORD = THREAD_QUERY_INFORMATION
  let hThread = OpenThread(thAccess, WINBOOL(FALSE), tid)
  if hThread == 0:
    return false
  
  var isOk = false
  var returnedLen: ULONG = 0
  var startAddr: PVOID = nil
  var status: NTSTATUS = 0
  
  const ThreadQuerySetWin32StartAddress = THREADINFOCLASS(9)
  
  status = pNtQueryInformationThread(
    hThread,
    ThreadQuerySetWin32StartAddress,
    cast[PVOID](addr startAddr),
    ULONG(sizeof(PVOID)),
    addr returnedLen
  )
  
  if status == 0 and returnedLen == sizeof(startAddr):
    info.startAddr = cast[ULONGLONG](startAddr)
    isOk = true
  
  CloseHandle(hThread)
  return isOk

# Process information for all threads
proc queryThreadsDetails*(threadsInfo: var Table[DWORD, ThreadInfo]): bool =
  for tid, info in threadsInfo.mpairs:
    if not queryThreadDetails(tid, info):
      return false
  
  return true

# Get information about threads in a process
proc fetchThreadsInfo*(pid: DWORD, threadsInfo: var Table[DWORD, ThreadInfo]): bool =
  const SystemProcessInformation = SYSTEM_INFORMATION_CLASS(5)
  
  let ntdll = GetModuleHandleA("ntdll.dll")
  if ntdll == 0:
    return false
  
  let pNtQuerySystemInformation = cast[NtQuerySystemInformationType](
    GetProcAddress(ntdll, "NtQuerySystemInformation")
  )
  
  if pNtQuerySystemInformation == nil:
    return false
  
  # Dynamic buffer for system information
  var bufSize: ULONG = 1024 * 1024  # Start with 1MB
  var buffer: pointer = nil
  var status: NTSTATUS = STATUS_INFO_LENGTH_MISMATCH
  
  while status == STATUS_INFO_LENGTH_MISMATCH:
    if buffer != nil:
      dealloc(buffer)
    
    buffer = alloc(bufSize)
    if buffer == nil:
      return false
    
    var returnLength: ULONG = 0
    status = pNtQuerySystemInformation(
      SystemProcessInformation,
      buffer,
      bufSize,
      addr returnLength
    )
    
    if status == STATUS_INFO_LENGTH_MISMATCH:
      bufSize = returnLength + 4096  # Add some extra space
  
  if status != STATUS_SUCCESS:
    if buffer != nil:
      dealloc(buffer)
    return false
  
  # Traverse the process information
  var procInfo = cast[ptr SYSTEM_PROCESS_INFORMATION](buffer)
  var found = false
  
  while true:
    if procInfo.UniqueProcessId == cast[HANDLE](pid):
      found = true
      break
    
    if procInfo.NextEntryOffset == 0:
      break
    
    procInfo = cast[ptr SYSTEM_PROCESS_INFORMATION](
      cast[int](procInfo) + procInfo.NextEntryOffset.int
    )
  
  if not found:
    dealloc(buffer)
    return false
  
  # Get information about threads in the found process
  let threadCount = procInfo.NumberOfThreads
  let threadsPtr = addr procInfo.Threads[0]
  
  for i in 0..<threadCount:
    let threadInfo = cast[ptr SYSTEM_THREAD_INFORMATION](
      cast[int](threadsPtr) + i * sizeof(SYSTEM_THREAD_INFORMATION)
    )
    
    let tid = cast[DWORD](threadInfo.ClientId.UniqueThread)
    
    if not threadsInfo.hasKey(tid):
      threadsInfo[tid] = ThreadInfo(tid: tid)
    
    var threadInfoRef = addr threadsInfo[tid]
    threadInfoRef.isExtended = true
    threadInfoRef.ext.sysStartAddr = cast[ULONGLONG](threadInfo.StartAddress)
    threadInfoRef.ext.state = threadInfo.ThreadState
    threadInfoRef.ext.waitReason = threadInfo.WaitReason
    threadInfoRef.ext.waitTime = threadInfo.WaitTime
  
  dealloc(buffer)
  return true

# Function to print detailed information about a thread's context
proc printThreadInfo*(pid: DWORD, tid: DWORD, ctx: CONTEXT) =
  echo "\n====== DETAILED INFORMATION OF TARGET THREAD ======="
  echo &"PID: {pid}, TID: {tid}"
  echo "--- CPU Context Registers ---"
  echo &"RIP: 0x{ctx.Rip:X}"
  echo &"RSP: 0x{ctx.Rsp:X}"
  echo &"RBP: 0x{ctx.Rbp:X}"
  echo &"RAX: 0x{ctx.Rax:X}, RBX: 0x{ctx.Rbx:X}, RCX: 0x{ctx.Rcx:X}, RDX: 0x{ctx.Rdx:X}"
  echo &"R8 : 0x{ctx.R8:X},  R9 : 0x{ctx.R9:X},  R10: 0x{ctx.R10:X}, R11: 0x{ctx.R11:X}"
  echo &"R12: 0x{ctx.R12:X}, R13: 0x{ctx.R13:X}, R14: 0x{ctx.R14:X}, R15: 0x{ctx.R15:X}"
  echo &"EFLAGS: 0x{ctx.EFlags:X}"
  echo "--- Segments ---"
  echo &"CS: 0x{ctx.SegCs:X}, SS: 0x{ctx.SegSs:X}, DS: 0x{ctx.SegDs:X}"
  echo &"ES: 0x{ctx.SegEs:X}, FS: 0x{ctx.SegFs:X}, GS: 0x{ctx.SegGs:X}"
  echo "==============================================" 