# vault/explorer.py
# Provides a VaultExplorer widget that looks and behaves like a file explorer for vault files.
import customtkinter as ctk
import tkinter as tk
from vault.file_manager import list_vault_files

class VaultExplorer(ctk.CTkFrame):
    def __init__(self, master, on_select=None, **kwargs):
        super().__init__(master, fg_color='#e3f0fc', corner_radius=15, **kwargs)
        self.on_select = on_select
        self.list_label = ctk.CTkLabel(self, text='Vault Explorer', font=('JetBrains Mono', 13, 'bold'), text_color='#155fa0')
        self.list_label.pack(anchor='w', padx=8, pady=(4, 0))
        self.file_listbox = tk.Listbox(self, height=8, width=70, bg='#ffffff', fg='#155fa0', selectbackground='#b3d8f8', activestyle='none', borderwidth=0, highlightthickness=1, font=('JetBrains Mono', 12))
        self.file_listbox.pack(padx=8, pady=(0, 8), fill='x', expand=True)
        self.file_listbox.bind('<<ListboxSelect>>', self._on_select)
        self.refresh()

    def refresh(self):
        files = list_vault_files()
        self.file_listbox.delete(0, 'end')
        for f in files:
            self.file_listbox.insert('end', f)
        if files:
            self.file_listbox.selection_set(0)

    def get_selected_file(self):
        selection = self.file_listbox.curselection()
        if selection:
            return self.file_listbox.get(selection[0])
        return None

    def _on_select(self, event):
        if self.on_select:
            self.on_select(self.get_selected_file())
