import winim
import winim/lean

# Global variable to control debug mode
var inDebugMode* = false

# Function for debugging - pauses execution using ReadConsole instead of scanf
proc debugPause*(message: string) =
  # Only wait for input if in debug mode
  if inDebugMode:
    echo "\n[DEBUG BREAK] " & message
    echo "Press Enter to continue..."
    
    var buffer: array[2, char]
    var charRead: DWORD = 0
    var hStdin = GetStdHandle(STD_INPUT_HANDLE)
    
    if hStdin != INVALID_HANDLE_VALUE:
      discard ReadConsoleA(hStdin, addr buffer[0], 1, addr charRead, nil) 