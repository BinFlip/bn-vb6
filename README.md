# bn-vb6

Binary Ninja plugin for VB6 P-Code executable analysis. Automatically detects
VB6 binaries (EXE, DLL, OCX) and enriches them with structure annotations,
named symbols, function discovery, and a custom P-Code architecture with
LLIL lifting.

## Features

- **Auto-detection** of VB6 binaries on load (PE + VbHeader signature)
- **15 struct types + 4 enum types** applied as overlays at VB6 structure VAs
- **Function discovery** via `code_entries()`: P-Code methods, native methods,
  method link thunks, and event handlers
- **Custom VB6-PCode architecture** with tokenized disassembly and LLIL lifting
- **Instruction text enrichment**: `%x` resolves to `library!function`,
  `%s` to string literals, `%v` to control names, `%a` to named variables
- **Import resolution**: Declare imports and COM typelib GUID references
- **False-positive cleanup**: removes BN's auto-created x86 functions from
  VB6 data regions while preserving imports and the entry point

## Requirements

- [Binary Ninja](https://binary.ninja/) (tested with dev branch API)
- Rust nightly toolchain (edition 2024)
- The [`visualbasic`](https://crates.io/crates/visualbasic) crate (pulled automatically via Cargo)

## Building

```sh
cargo build --release
```

The output is `target/release/libbn_vb6.dylib` (macOS) or
`target/release/libbn_vb6.so` (Linux).

### macOS code signing

If Binary Ninja refuses to load the unsigned dylib:

```sh
codesign --force --sign - target/release/libbn_vb6.dylib
```

## Installation

Copy the built library to your Binary Ninja plugins directory:

```sh
# macOS
cp target/release/libbn_vb6.dylib ~/Library/Application\ Support/Binary\ Ninja/plugins/

# Linux
cp target/release/libbn_vb6.so ~/.binaryninja/plugins/

# Windows
copy target\release\bn_vb6.dll "%APPDATA%\Binary Ninja\plugins\"
```

Restart Binary Ninja. The plugin loads automatically and logs
`VB6 plugin loaded successfully` to the console.

## Usage

Open any VB6 P-Code executable in Binary Ninja. The plugin triggers
automatically after initial analysis completes. You can also run it
manually via **VB6 > Analyze VB6 Structures** in the command palette.

After analysis:

- The **Symbols** panel shows VB6 objects, methods, controls, and imports
- **Linear view** displays annotated VB6 structures with typed overlays
- **LLIL/HLIL views** show lifted P-Code with resolved operand names
- The **function list** contains only legitimate code entries (P-Code stubs,
  native methods, thunks, event handlers, imports)

## License

Apache-2.0
