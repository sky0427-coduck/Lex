# Lex v0.1 PE Inspector

Requires Zig 0.17.0. A small Zig-first PE file inspector for ARM64 Linux (including Raspberry Pi 5). It validates the DOS header, `e_lfanew`, PE signature, COFF header, and PE32/PE32+ optional header before reporting the COFF machine architecture. It does not load or execute Windows binaries.

## Build and run

With Zig installed:

```sh
zig build-exe src/main.zig -O ReleaseSafe -femit-bin=lex-pe-inspector
./lex-pe-inspector path/to/program.exe
```

Run parser tests:

```sh
zig test src/pe.zig
```

The parser uses bounded reads and subtraction-based range checks so malformed offsets and lengths cannot wrap around.
