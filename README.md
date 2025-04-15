![NimJacker - Waiting Thread Hijacking in Nim](docs/banner.png)

# Waiting Thread Hijacking (WTH) - Nim Implementation

This project is a Nim implementation of the "Waiting Thread Hijacking" (WTH) technique, a stealthier variant of the "Thread Execution Hijacking" injection technique. This implementation is heavily based on the [original C code](https://github.com/hasherezade/waiting_thread_hijacking) developed by [@hasherezade](https://twitter.com/hasherezade).

## About the Technique

This technique was documented by hasherezade in the Check Point Research investigation:
[Waiting Thread Hijacking: A Stealthier Version of Thread Execution Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)

WTH is an injection technique that allows executing code in a remote process by intercepting threads in waiting state (specifically those with `WrQueue` state). Unlike the classic Thread Hijacking technique, WTH avoids using APIs that typically trigger alerts in EDR systems, such as `SuspendThread`/`ResumeThread` and `SetThreadContext`.

## Project Structure

```
NimJacker/
├── utils/
│   ├── debug.nim             # Debugging functions and execution pauses
│   ├── memory_utils.nim      # Memory operations (dump, protection, allocation, writing)
│   ├── ntdll_api.nim         # Definitions for ntdll.dll APIs
│   ├── thread_constants.nim  # Constants related to thread states
│   └── threads_util.nim      # Utilities for thread and context manipulation
├── shellcode/
│   └── stub_and_shellcode.nim # Shellcode definition and construction
├── runpe/
│   └── wht_injection.nim     # Main injection functions
├── payloads/
│   ├── calc.bin              # Binary payload (launches calculator)
│   ├── gen_calc.py           # Script to generate payloads
│   └── msgbox.bin            # Binary payload (displays a message)
└── nimjacker.nim               # Main program entry point
```

### Description of Main Components:

- **utils/debug.nim**: Provides debugging functions, including controlled pauses during execution.
- **utils/memory_utils.nim**: Contains functions to manipulate memory in remote processes.
- **utils/ntdll_api.nim**: Defines ntdll.dll APIs necessary for virtual memory operations.
- **utils/thread_constants.nim**: Defines constants related to thread states and wait reasons.
- **utils/threads_util.nim**: Implements utilities to get thread and context information.
- **shellcode/stub_and_shellcode.nim**: Handles shellcode definition and construction.
- **runpe/wht_injection.nim**: Contains the main functions for WTH injection.
- **payloads/**: Contains example binary payloads and scripts to generate them.
- **nimjacker.nim**: Main file that implements the command-line interface.

## Usage

```
nimjacker <PID> [--debug]
```

### Options:
- `<PID>`: The target process ID for injection.
- `--debug`: Enables debug mode with pauses at key points, useful for following execution with x64dbg.

### Example usage with debug mode:

```
nimjacker 1234 --debug
```

## Important Note

**Warning**: This code implementation may fail occasionally due to timing issues, target process state, or system configuration. The WTH technique relies on specific thread states which are not always guaranteed to be available or stable in all target processes.

**Note**: This code is designed to work exclusively on x64 architecture systems. It will not function correctly on 32-bit systems.

## Building

To build the code:

```
nim c -f --os:windows --cpu:amd64 -d:binary nimjacker.nim
```

## Analysis with x64dbg

[x64dbg](https://x64dbg.com) is recommended for analyzing the behavior of this technique. When running the program with the `--debug` option, pauses will occur at key points during execution, allowing you to follow the process step by step and better understand how the technique works.

## Example in Action

<video src="docs/poc.mp4" width="640" height="360" controls></video>

## Developer

Developed by Alejandro Parodi ([@SecSignal](https://twitter.com/SecSignal))

## Credits

- Original concept and C code: [@hasherezade](https://twitter.com/hasherezade)
- Research: [Check Point Research](https://research.checkpoint.com)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.