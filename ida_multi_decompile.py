'''Copyright (c) Aleksandr Vorobev aka CynicRus, 2025'''
import idaapi
import idautils
import idc
import ida_kernwin
import ida_hexrays
import ida_funcs
from PyQt5 import QtWidgets, QtGui, QtCore

# Уникальные идентификаторы действий
ACTION_DECOMPILE_ID = 'multi_decompile:decompile_selected'
ACTION_DISASSEMBLE_ID = 'multi_decompile:disassemble_selected'

# Подсветка синтаксиса для C-кода
class CSyntaxHighlighter(QtGui.QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []

        keyword_format = QtGui.QTextCharFormat()
        keyword_format.setForeground(QtGui.QColor("blue"))
        keyword_format.setFontWeight(QtGui.QFont.Bold)

        type_format = QtGui.QTextCharFormat()
        type_format.setForeground(QtGui.QColor("darkCyan"))

        comment_format = QtGui.QTextCharFormat()
        comment_format.setForeground(QtGui.QColor("gray"))
        comment_format.setFontItalic(True)

        string_format = QtGui.QTextCharFormat()
        string_format.setForeground(QtGui.QColor("darkGreen"))

        keywords = ["if", "else", "while", "for", "return", "break", "continue", 
                    "switch", "case", "default", "goto", "do", "struct", "union", 
                    "enum", "typedef", "const", "volatile", "static", "extern", "inline"]
        for word in keywords:
            pattern = QtCore.QRegularExpression(f"\\b{word}\\b")
            self.highlighting_rules.append((pattern, keyword_format))

        types = ["void", "int", "char", "float", "double", "long", "short", 
                 "unsigned", "signed", "bool", "size_t", "uint8_t", "uint16_t", 
                 "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t"]
        for word in types:
            pattern = QtCore.QRegularExpression(f"\\b{word}\\b")
            self.highlighting_rules.append((pattern, type_format))

        comment_pattern = QtCore.QRegularExpression("//[^\n]*")
        self.highlighting_rules.append((comment_pattern, comment_format))

        string_pattern = QtCore.QRegularExpression("\".*\"")
        self.highlighting_rules.append((string_pattern, string_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            iterator = pattern.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)

# Подсветка синтаксиса для дизассемблированного кода
class AsmSyntaxHighlighter(QtGui.QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []

        # Форматы для разных элементов
        instruction_format = QtGui.QTextCharFormat()
        instruction_format.setForeground(QtGui.QColor("purple"))
        instruction_format.setFontWeight(QtGui.QFont.Bold)

        register_format = QtGui.QTextCharFormat()
        register_format.setForeground(QtGui.QColor("darkRed"))

        comment_format = QtGui.QTextCharFormat()
        comment_format.setForeground(QtGui.QColor("gray"))
        comment_format.setFontItalic(True)

        address_format = QtGui.QTextCharFormat()
        address_format.setForeground(QtGui.QColor("darkBlue"))

        # Инструкции для x86/x64
        x86_instructions = ["mov", "lea", "add", "sub", "cmp", "jmp", "jne", "je", 
                           "call", "ret", "push", "pop", "test", "and", "or", "xor"]

        # Инструкции для MIPS
        mips_instructions = ["add", "addu", "sub", "subu", "mul", "div", "and", "or", 
                            "xor", "nor", "sll", "srl", "sra", "lw", "sw", "lb", "sb", 
                            "beq", "bne", "j", "jal", "jr", "mfhi", "mflo", "mtlo", "mthi"]

        # Инструкции для ARM
        arm_instructions = ["mov", "add", "sub", "mul", "ldr", "str", "ldrb", "strb", 
                           "cmp", "b", "beq", "bne", "bl", "bx", "and", "orr", "eor", 
                           "lsl", "lsr", "asr", "push", "pop"]

        # Инструкции для ARM64
        arm64_instructions = ["mov", "add", "sub", "mul", "ldr", "str", "ldp", "stp", 
                             "cmp", "b", "b.eq", "b.ne", "bl", "ret", "and", "orr", "eor", 
                             "lsl", "lsr", "asr", "cbz", "cbnz"]

        # Инструкции для PowerPC
        ppc_instructions = ["add", "subf", "mullw", "divw", "and", "or", "xor", 
                           "slw", "srw", "sraw", "lwz", "stw", "lbz", "stb", 
                           "cmpw", "cmpwi", "b", "beq", "bne", "bl", "blr", "mtctr", "bctr"]

        # Объединяем все инструкции
        all_instructions = (x86_instructions + mips_instructions + arm_instructions + 
                           arm64_instructions + ppc_instructions)
        for word in all_instructions:
            pattern = QtCore.QRegularExpression(f"\\b{word}\\b", QtCore.QRegularExpression.CaseInsensitiveOption)
            self.highlighting_rules.append((pattern, instruction_format))

        # Регистры для x86/x64
        x86_registers = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", 
                        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", 
                        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

        # Регистры для MIPS
        mips_registers = ["$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3", 
                         "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", 
                         "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", 
                         "$t8", "$t9", "$sp", "$ra"]

        # Регистры для ARM
        arm_registers = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", 
                        "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"]

        # Регистры для ARM64
        arm64_registers = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", 
                          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", 
                          "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", 
                          "x24", "x25", "x26", "x27", "x28", "sp", "lr", "pc"]

        # Регистры для PowerPC
        ppc_registers = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", 
                        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", 
                        "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", 
                        "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31", 
                        "sp", "lr", "ctr"]

        # Объединяем все регистры
        all_registers = (x86_registers + mips_registers + arm_registers + 
                        arm64_registers + ppc_registers)
        for word in all_registers:
            pattern = QtCore.QRegularExpression(f"\\b{word}\\b", QtCore.QRegularExpression.CaseInsensitiveOption)
            self.highlighting_rules.append((pattern, register_format))

        # Комментарии
        comment_pattern = QtCore.QRegularExpression(";.*")
        self.highlighting_rules.append((comment_pattern, comment_format))

        # Адреса (например, 0x12345678)
        address_pattern = QtCore.QRegularExpression("0x[0-9a-fA-F]+")
        self.highlighting_rules.append((address_pattern, address_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            iterator = pattern.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)

class OutputWindow(QtWidgets.QWidget):
    def __init__(self, title, mode="c", parent=None, plugin=None):
        super(OutputWindow, self).__init__(parent)
        self.setWindowTitle(title)
        self.mode = mode
        self.plugin = plugin
        self.is_decompile_window = (title == "Decompiled Functions")
        self.setup_ui()

    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout()
        self.text_area = QtWidgets.QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setFont(QtGui.QFont("Courier New", 10))

        if self.mode == "c":
            self.highlighter = CSyntaxHighlighter(self.text_area.document())
        else:
            self.highlighter = AsmSyntaxHighlighter(self.text_area.document())

        self.text_area.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.text_area.customContextMenuRequested.connect(self.show_context_menu)

        self.text_area.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.text_area.setFocus()

        layout.addWidget(self.text_area)

        self.copy_button = QtWidgets.QPushButton("Copy to Clipboard")
        self.copy_button.clicked.connect(self.copy_to_clipboard)
        layout.addWidget(self.copy_button)

        self.setLayout(layout)
        self.resize(800, 600)

    def show_context_menu(self, pos):
        menu = QtWidgets.QMenu()
        copy_action = menu.addAction("Copy")
        select_all_action = menu.addAction("Select All")

        action = menu.exec_(self.text_area.mapToGlobal(pos))
        if action == copy_action:
            self.text_area.copy()
        elif action == select_all_action:
            self.text_area.selectAll()

    def copy_to_clipboard(self):
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText(self.text_area.toPlainText())
        idaapi.msg("Text copied to clipboard\n")

    def append_text(self, text):
        self.text_area.append(text)

    def clear(self):
        self.text_area.clear()

    def closeEvent(self, event):
        if self.plugin:
            if self.is_decompile_window:
                self.plugin.decompile_window = None
            else:
                self.plugin.disassemble_window = None
        super().closeEvent(event)

class DecompileHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.decompile_selected(ctx)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DisassembleHandler(idaapi.action_handler_t):
    def __init__(self, plugin):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.disassemble_selected(ctx)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class MultiDecompileDisassemblePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "Decompile or disassemble multiple selected functions"
    help = "Select functions in Functions window, right-click and choose Decompile/Disassemble selected"
    wanted_name = "Multi Decompile/Disassemble by CynicRus"
    wanted_hotkey = ""

    def __init__(self):
        self.decompile_window = None
        self.disassemble_window = None
        self.popup_hook = None

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            idaapi.msg("Hex-Rays decompiler is not available\n")
        else:
            idaapi.msg("Hex-Rays decompiler initialized successfully\n")

        idaapi.msg("Multi Decompile/Disassemble plugin by CynicRus initialized\n")

        action_desc_decompile = idaapi.action_desc_t(
            ACTION_DECOMPILE_ID,
            'Decompile selected',
            DecompileHandler(self),
            None,
            'Decompile selected functions into one window',
            0
        )

        action_desc_disassemble = idaapi.action_desc_t(
            ACTION_DISASSEMBLE_ID,
            'Disassemble selected',
            DisassembleHandler(self),
            None,
            'Disassemble selected functions into one window',
            0
        )

        try:
            if not idaapi.register_action(action_desc_decompile):
                idaapi.msg(f"Error: Failed to register action {ACTION_DECOMPILE_ID}\n")
                return idaapi.PLUGIN_SKIP

            if not idaapi.register_action(action_desc_disassemble):
                idaapi.msg(f"Error: Failed to register action {ACTION_DISASSEMBLE_ID}\n")
                return idaapi.PLUGIN_SKIP
        except Exception as e:
            idaapi.msg(f"Exception during action registration: {str(e)}\n")
            return idaapi.PLUGIN_SKIP

        class PopupHook(idaapi.UI_Hooks):
            def __init__(self, plugin):
                idaapi.UI_Hooks.__init__(self)
                self.plugin = plugin

            def finish_populating_widget_popup(self, widget, popup):
                if idaapi.get_widget_type(widget) == idaapi.BWN_FUNCS:
                    idaapi.attach_action_to_popup(widget, popup, ACTION_DECOMPILE_ID, 'Decompile/')
                    idaapi.attach_action_to_popup(widget, popup, ACTION_DISASSEMBLE_ID, 'Decompile/')

        self.popup_hook = PopupHook(self)
        self.popup_hook.hook()

        return idaapi.PLUGIN_KEEP

    def term(self):
        if self.popup_hook:
            self.popup_hook.unhook()
            idaapi.msg("UI hook removed\n")
        if self.decompile_window:
            self.decompile_window.close()
        if self.disassemble_window:
            self.disassemble_window.close()
        idaapi.msg("Multi Decompile/Disassemble plugin terminated\n")

    def get_selected_functions(self, ctx):
        chooser_caption = "Functions"
        if not hasattr(ctx, 'chooser_selection') or not ctx.chooser_selection:
            idaapi.msg("No selection in Functions window\n")
            return []

        functions = []
        for idx in ctx.chooser_selection:
            row_data = ida_kernwin.get_chooser_data(chooser_caption, idx)
            if not row_data or len(row_data) < 3:
                idaapi.msg(f"Row {idx}: Insufficient data returned by get_chooser_data: {row_data}\n")
                continue

            #idaapi.msg(f"Row {idx} data: {row_data}\n")
            address_str = row_data[2].strip()
            if not address_str:
                idaapi.msg(f"Row {idx}: Empty address string\n")
                continue

            if address_str.startswith("0x"):
                address_str = address_str[2:]

            try:
                func_ea = int(address_str, 16)
                if func_ea == idaapi.BADADDR:
                    idaapi.msg(f"Row {idx}: Invalid address (BADADDR)\n")
                    continue

                func = ida_funcs.get_func(func_ea)
                if not func:
                    idaapi.msg(f"Row {idx}: No function found at address {hex(func_ea)}\n")
                    continue

                func_name = idc.get_func_name(func_ea)
                functions.append(func.start_ea)

            except ValueError as e:
                idaapi.msg(f"Row {idx}: Failed to parse address '{address_str}' - {str(e)}\n")
                continue

        return functions

    def decompile_selected(self, ctx):
        functions = self.get_selected_functions(ctx)
        if not functions:
            idaapi.msg("No valid functions selected\n")
            return

        if not self.decompile_window or not self.decompile_window.isVisible():
            self.decompile_window = OutputWindow("Decompiled Functions", mode="c", plugin=self)
            self.decompile_window.show()
        else:
            self.decompile_window.clear()

        seen_funcs = set()
        for ea in functions:
            func = ida_funcs.get_func(ea)
            if func and func.start_ea not in seen_funcs:
                func_name = idc.get_func_name(func.start_ea)
                self.decompile_window.append_text(f"// Function: {func_name} @ {hex(func.start_ea)}\n")
                try:
                    cfunc = ida_hexrays.decompile(func.start_ea, None)
                    if cfunc:
                        self.decompile_window.append_text(f"{str(cfunc)}\n")
                    else:
                        self.decompile_window.append_text("// Failed to decompile\n")
                    seen_funcs.add(func.start_ea)
                except Exception as e:
                    self.decompile_window.append_text(f"// Decompilation error: {str(e)}\n")
                self.decompile_window.append_text("\n" + "="*80 + "\n")

    def disassemble_selected(self, ctx):
        functions = self.get_selected_functions(ctx)
        if not functions:
            idaapi.msg("No valid functions selected\n")
            return

        if not self.disassemble_window or not self.disassemble_window.isVisible():
            self.disassemble_window = OutputWindow("Disassembled Functions", mode="asm", plugin=self)
            self.disassemble_window.show()
        else:
            self.disassemble_window.clear()

        seen_funcs = set()
        for ea in functions:
            func = ida_funcs.get_func(ea)
            if func and func.start_ea not in seen_funcs:
                func_name = idc.get_func_name(func.start_ea)
                self.disassemble_window.append_text(f"; Function: {func_name} @ {hex(func.start_ea)}\n")
                current_ea = func.start_ea
                while current_ea < func.end_ea:
                    disasm_line = idc.generate_disasm_line(current_ea, 0)
                    if disasm_line:
                        self.disassemble_window.append_text(disasm_line + "\n")
                    current_ea = idc.next_head(current_ea, func.end_ea)
                seen_funcs.add(func.start_ea)
                self.disassemble_window.append_text("\n" + "="*80 + "\n")

    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return MultiDecompileDisassemblePlugin()
