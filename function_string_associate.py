import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_auto
import ida_kernwin
import time
from PyQt5 import QtWidgets

MAX_LINE_STR_COUNT = 10
MAX_LABEL_STR = 60
MAX_COMMENT = 764
MIN_STR_SIZE = 4

# if True, replace existing function comments;
# if False, append new strings to the existing comment.
g_replace_comments = False

def filter_whitespace(s):
    return "".join(ch if " " <= ch <= "~" else " " for ch in s).strip()

def process_function(ea, comment_counter):
    f = ida_funcs.get_func(ea)
    if not f or f.size() < 8:
        return

    str_list = []
    for item_ea in idautils.FuncItems(ea):
        for xref in idautils.XrefsFrom(item_ea, idaapi.XREF_DATA):
            max_len = ida_bytes.get_max_strlit_length(xref.to, 0)  # 0 = ASCII
            if max_len > MIN_STR_SIZE:
                raw_bytes = ida_bytes.get_strlit_contents(xref.to, max_len, 0)
                if raw_bytes:
                    try:
                        s = raw_bytes.decode("ascii", errors="replace")
                    except Exception:
                        s = str(raw_bytes)
                    s = filter_whitespace(s)
                    if len(s) >= MIN_STR_SIZE:
                        found = False
                        for entry in str_list:
                            if entry[0] == s:
                                entry[1] += 1
                                found = True
                                break
                        if not found:
                            if len(str_list) < MAX_LINE_STR_COUNT:
                                str_list.append([s, 1])
                            if len(str_list) >= MAX_LINE_STR_COUNT:
                                break
        if len(str_list) >= MAX_LINE_STR_COUNT:
            break

    if str_list:
        str_list.sort(key=lambda x: x[1])
        new_text = "STR: "
        for i, (val, refs) in enumerate(str_list):
            free_size = MAX_COMMENT - len(new_text) - 1
            needed = len(val) + 2  # for quotes
            if free_size < needed:
                break
            new_text += f"\"{val}\""
            if i + 1 < len(str_list):
                free_size = MAX_COMMENT - len(new_text) - 1
                if free_size > 2:
                    new_text += ", "
                else:
                    break

        if not g_replace_comments:
            # Append mode: retrieve any existing comment and add new text.
            current = idc.get_func_cmt(ea, repeatable=True)
            if current is None:
                current = idc.get_func_cmt(ea, repeatable=False) or ""
            if current:
                combined = current + "\n" + new_text
            else:
                combined = new_text
            idc.set_func_cmt(ea, combined, repeatable=True)
        else:
            # Replace mode: overwrite with new text.
            idc.set_func_cmt(ea, new_text, repeatable=True)
        comment_counter[0] += 1

# -----------------------------------------------------------------------
# PyQt dialog for "Replace or Append"
# -----------------------------------------------------------------------
class ReplaceOrAppendDialog(QtWidgets.QDialog):
    """
    A simple modal dialog with a checkbox to choose between REPLACE and APPEND.
    """
    def __init__(self, func_count, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Function String Associate")
        self.setModal(True)

        layout = QtWidgets.QVBoxLayout()

        label = QtWidgets.QLabel(
            f"This will extract strings from all {func_count} functions.\n\n"
            "If you choose REPLACE, any existing function comment will be overwritten.\n"
            "If unchecked, the plugin will APPEND to the existing comment.\n"
        )
        layout.addWidget(label)

        self.checkbox = QtWidgets.QCheckBox("Replace existing comments?")
        layout.addWidget(self.checkbox)

        # OK / Cancel
        button_box = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

    def should_replace(self):
        return self.checkbox.isChecked()


def show_qt_dialog(func_count):
    """
    Shows the PyQt dialog. Returns:
      True  => user chose "OK" with checkbox checked (REPLACE)
      False => user chose "OK" with checkbox unchecked (APPEND)
      None  => user canceled
    """
    dlg = ReplaceOrAppendDialog(func_count)
    result = dlg.exec_()
    if result == QtWidgets.QDialog.Accepted:
        return dlg.should_replace()
    else:
        return None

class MyPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Function String Associate plugin"
    help = "Extracts strings from each function and adds them as function comments"
    wanted_name = "Function String Associate"
    wanted_hotkey = ""

    def init(self):
        # If init fails (return idaapi.PLUGIN_SKIP), it won't appear in the menu.
        # Return PLUGIN_OK or PLUGIN_UNL to ensure it shows up under Edit->Plugins.
        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg("[FuncStrPlugin] Plugin invoked!\n")

        if not ida_auto.auto_is_ok():
            ida_kernwin.warning("Auto analysis must finish before running this plugin!")
            idaapi.msg("*** Aborted ***\n")
            return

        funcs = list(idautils.Functions())
        
        choice = show_qt_dialog(len(funcs))
        if choice is None:
            idaapi.msg(" - Canceled -\n")
            return
        
        global g_replace_comments
        g_replace_comments = choice

        mode = "REPLACE" if g_replace_comments else "APPEND"
        idaapi.msg(f"User chose to {mode} existing comments.\n")

        start_time = time.time()
        comment_count = [0]

        ida_kernwin.show_wait_box("Processing functions...")

        for idx, func_ea in enumerate(funcs):
            process_function(func_ea, comment_count)
            if idx % 100 == 0:
                ida_kernwin.replace_wait_box(f"Processing function {idx+1}/{len(funcs)}")
                if ida_kernwin.user_cancelled():
                    idaapi.msg("* Aborted *\n")
                    break

        ida_kernwin.hide_wait_box()

        elapsed = time.time() - start_time
        idaapi.msg(f"Done: Generated {comment_count[0]} string comments in {elapsed:.3f} seconds.\n")
        idaapi.msg("--------------------------------------------------\n")
        idaapi.refresh_idaview_anyway()

    def term(self):
        # Called when the plugin is about to be unloaded (if flags=PLUGIN_UNL).
        idaapi.msg("[FuncStrPlugin] term() called.\n")

def PLUGIN_ENTRY():
    return MyPlugin()
