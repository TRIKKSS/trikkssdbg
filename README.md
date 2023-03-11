# TRIKKSDBG

a simple linux 64 bits debugger.

I wrote it to improve my C devellopement skills and also to learn the usage of ptrace.

## Installation

install capstone (used to decode opcodes)

[Download – Capstone – The Ultimate Disassembler](https://www.capstone-engine.org/download.html)

and compile the project.

```
git clone https://github.com/TRIKKSS/trikkssdbg
cd trikkssdbg
make
```

## Usage

```./trikkssdbg binary_to_debug```

## Help

```
bp address [description] : place a breakpoint at address.
                           whitout arguments the bp command
                           will print all defined breakpoints
del breakoint_id         : delete a breakpoint.
reg [register name]      : print registers value.
read address size        : read size bytes at address
disas address size       : disassemble memory at address
map                      : print /proc/pid/maps of child
continue                 : continue the binary execution
exit                     : exit the debugger and kill child process.
help                     : print this help
```




