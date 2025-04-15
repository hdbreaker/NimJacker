import winim
import winim/lean
import strformat

# Import the custom module for ntdll functions
import ntdll_api

# Function to display memory around a pointer
proc dumpMemoryAroundPtr*(hProcess: HANDLE, address: ULONGLONG, numQWords: int = 8) =
  echo &"\n===== MEMORY AROUND 0x{address:X} ====="
  
  # Adjust address to align to 8 bytes
  let alignedAddress = cast[ULONGLONG](cast[uint64](address) and (not uint64(7)))
  var buffer: array[16, uint64]
  var bytesRead: SIZE_T = 0

  # Read before the pointer
  let beforeStart = cast[ULONGLONG](cast[uint64](alignedAddress) - uint64(numQWords * 8))
  if ReadProcessMemory(
    hProcess,
    cast[LPVOID](beforeStart),
    addr buffer[0],
    SIZE_T(numQWords * 8),
    addr bytesRead
  ) != 0:
    echo "--- Bytes BEFORE the pointer ---"
    for i in 0..<numQWords:
      let currentAddress = cast[ULONGLONG](cast[uint64](beforeStart) + uint64(i * 8))
      echo &"0x{currentAddress:X}: 0x{buffer[i]:X}"
  
  # Read after the pointer
  if ReadProcessMemory(
    hProcess,
    cast[LPVOID](alignedAddress),
    addr buffer[0],
    SIZE_T(numQWords * 8),
    addr bytesRead
  ) != 0:
    echo "--- Bytes AT and AFTER the pointer ---"
    for i in 0..<numQWords:
      let currentAddress = cast[ULONGLONG](cast[uint64](alignedAddress) + uint64(i * 8))
      echo &"0x{currentAddress:X}: 0x{buffer[i]:X}"
      
      # Mark the specific pointer
      if currentAddress == address:
        echo &"^^^ THIS IS THE RETURN POINTER ^^^"
  
  echo "=============================================="

# Function to change memory protection in a process
proc protectMemory*(pid: DWORD, memPtr: LPVOID, memSize: SIZE_T, protect: DWORD): bool =
  let hProcess = OpenProcess(PROCESS_VM_OPERATION, WINBOOL(FALSE), pid)
  if hProcess == 0:
    return false

  var oldProtect: DWORD = 0
  let isOk = ntdll_api.VirtualProtectEx(hProcess, memPtr, memSize, protect, addr oldProtect)
  CloseHandle(hProcess)
  return isOk != 0

# Function to allocate memory in a remote process
proc allocMemoryInProcess*(processID: DWORD, size: SIZE_T, initialProtect: DWORD = PAGE_READWRITE): LPVOID =
  var hProcess = OpenProcess(PROCESS_VM_OPERATION, WINBOOL(FALSE), processID)
  if hProcess == 0:
    return nil
  
  let memPtr = ntdll_api.VirtualAllocEx(
    hProcess, 
    nil, 
    size, 
    MEM_COMMIT or MEM_RESERVE, 
    initialProtect
  )
  CloseHandle(hProcess)
  return memPtr

# Function to write data to a remote process memory
proc writeMemoryIntoProcess*(processID: DWORD, destPtr: LPVOID, srcPtr: pointer, size: SIZE_T): bool =
  if destPtr == nil:
    return false
  
  var hProcess = OpenProcess(PROCESS_VM_OPERATION or PROCESS_VM_WRITE, WINBOOL(FALSE), processID)
  if hProcess == 0:
    return false
  
  var written: SIZE_T = 0
  let isOk = ntdll_api.WriteProcessMemory(
    hProcess, 
    destPtr, 
    srcPtr, 
    size, 
    addr written
  )
  
  CloseHandle(hProcess)
  return isOk != 0 and written == size

# Function to validate that a return pointer points to a valid DLL
proc checkRetTarget*(ret: LPVOID): bool =
  # Validate that the return pointer points to a valid DLL like ntdll or kernel32
  let module = GetModuleHandleA("ntdll.dll")
  let k32 = GetModuleHandleA("kernel32.dll")
  let kbase = GetModuleHandleA("kernelbase.dll")
  
  var modBase: ULONGLONG = cast[ULONGLONG](module)
  var k32Base: ULONGLONG = cast[ULONGLONG](k32)
  var kbaseBase: ULONGLONG = cast[ULONGLONG](kbase)
  var retAddr: ULONGLONG = cast[ULONGLONG](ret)
  
  # Check if the pointer is within the range of any of the DLLs
  # Note: This is an approximation, in reality you should get the exact size
  const MAX_MODULE_SIZE = 0x200000  # 2MB as an approximate size
  
  if ret == nil:
    return false
    
  echo &"Checking return target: 0x{cast[uint64](ret):X}"
  
  if retAddr >= modBase and retAddr <= modBase + MAX_MODULE_SIZE:
    echo "Pointer in ntdll.dll"
    return true
  elif retAddr >= k32Base and retAddr <= k32Base + MAX_MODULE_SIZE:
    echo "Pointer in kernel32.dll"
    return true
  elif retAddr >= kbaseBase and retAddr <= kbaseBase + MAX_MODULE_SIZE:
    echo "Pointer in kernelbase.dll"
    return true
  
  echo "Pointer is not in any recognized module"
  return false 