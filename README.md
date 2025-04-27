# Multi Decompile/Disassemble Plugin for IDA Pro

## Overview

The **Multi Decompile/Disassemble Plugin** is a custom plugin for IDA Pro that allows users to decompile or disassemble multiple selected functions at once and display the results in a single, user-friendly window. The plugin provides syntax highlighting for both C (decompiled code) and assembly (disassembled code), supports multiple architectures, and includes features like text copying and window management.

### Features
- **Decompile Multiple Functions**: Decompile selected functions into a single window with C syntax highlighting.
- **Disassemble Multiple Functions**: Disassemble selected functions into a single window with assembly syntax highlighting.
- **Syntax Highlighting**:
  - C code: keywords, types, comments, and strings.
  - Assembly: instructions, registers, comments, and addresses for x86/x64, MIPS, ARM, ARM64, and PowerPC architectures.
- **Copy to Clipboard**: A button to copy the entire content of the output window to the clipboard.
- **Context Menu**: Right-click to copy selected text or select all text.
- **Window Management**: Automatically reopens the output window if closed.

## Installation

1. **Prerequisites**:
   - IDA Pro with Python support.
   - PyQt5 (usually bundled with IDA Pro).
   - Hex-Rays Decompiler (required for decompilation functionality).

2. **Steps**:
   - Copy the plugin file (`ida_multi_decompile.py`) to the IDA Pro plugins directory:
     - On Windows: `C:\Program Files\IDA Pro\plugins\` or you custom ida installation.
     - On Linux/macOS: `/path/to/ida/plugins/`
   - Restart IDA Pro.
   - The plugin will automatically load and initialize. You should see the message "Multi Decompile/Disassemble plugin by CynicRus initialized" in the IDA Output window.

## Usage

1. **Open the Functions Window**:
   - In IDA Pro, go to `View` -> `Open subviews` -> `Functions` to open the Functions window.

2. **Select Functions**:
   - Hold `Ctrl` or `Shift` (or `Cmd` on macOS) and click to select multiple functions in the Functions window. 

3. **Decompile or Disassemble**:
   - Right-click on the selected functions.
   - In the context menu, navigate to `Decompile/` and choose:
     - `Decompile selected`: Decompiles the selected functions into a "Decompiled Functions" window.
     - `Disassemble selected`: Disassembles the selected functions into a "Disassembled Functions" window.

4. **Interact with the Output Window**:
   - The output window displays the decompiled or disassembled code with syntax highlighting.
   - Use the right-click context menu to copy selected text or select all text.
   - Click the "Copy to Clipboard" button at the bottom to copy the entire content to the clipboard.
   - Close the window by clicking the "X" button; it will reopen automatically on the next decompile/disassemble action.

## Syntax Highlighting

### Decompiled Code (C)
- **Keywords** (e.g., `if`, `while`, `return`): Blue, bold.
- **Types** (e.g., `int`, `void`, `uint32_t`): Dark cyan.
- **Comments** (e.g., `// ...`): Gray, italic.
- **Strings** (e.g., `"..."`): Dark green.

### Disassembled Code (Assembly)
- **Instructions**:
  - Supported architectures: x86/x64, MIPS, ARM, ARM64, PowerPC.
  - Examples: `MOV`, `ADD`, `LDR`, `LWZ`, `SLL` (case-insensitive).
  - Color: Purple, bold.
- **Registers**:
  - Examples: `R0`, `SP`, `$t0`, `x1`, `r31` (case-insensitive).
  - Color: Dark red.
- **Comments** (e.g., `; ...`): Gray, italic.
- **Addresses** (e.g., `0x12345678`): Dark blue.

## Limitations
- Requires the Hex-Rays Decompiler for decompilation to work. If the decompiler is unavailable, the plugin will log a message in the Output window.
- Ctrl+C for copying text may conflict with IDA Pro's shortcuts. Use the "Copy to Clipboard" button or the context menu as a workaround.
- Syntax highlighting supports common instructions and registers for the listed architectures but may not cover all possible instructions.

## Troubleshooting
- **Plugin does not load**:
  - Ensure the plugin file is in the correct directory and named `ida_multi_decompile.py`.
  - Check the IDA Output window for error messages during initialization.
- **Decompilation fails**:
  - Verify that the Hex-Rays Decompiler is installed and licensed.
  - Check the Output window for specific error messages.
- **Syntax highlighting issues**:
  - If an instruction or register is not highlighted, it may not be in the predefined lists. Contact the developer to add support for additional instructions/registers.

## License
This plugin is provided as-is, with no warranty. Feel free to modify and distribute under the terms of the MIT License.
