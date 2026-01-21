# vault/ui.py
# Contains a VaultFileList class for displaying and selecting files in the vault.
import customtkinter as ctk
from vault.file_manager import list_vault_files

class VaultFileList(ctk.CTkFrame):
    def __init__(self, master, on_select=None, **kwargs):
        super().__init__(master, fg_color='#e3f0fc', corner_radius=15, **kwargs)
        self.on_select = on_select
        self.list_label = ctk.CTkLabel(self, text='Files in Vault:', font=('JetBrains Mono', 13, 'bold'), text_color='#155fa0')
        self.list_label.pack(anchor='w', padx=8, pady=(4, 0))
        self.listbox = ctk.CTkComboBox(self, values=[], font=('JetBrains Mono', 12), width=540, height=32, corner_radius=8, state='readonly')
        self.listbox.pack(padx=8, pady=(0, 8), fill='x', expand=True)
        self.listbox.bind('<<ComboboxSelected>>', self._on_select)
        self.refresh()

    def refresh(self):
        files = list_vault_files()
        self.listbox.configure(values=files)
        if files:
            self.listbox.set(files[0])
        else:
            self.listbox.set('')

    def get_selected_file(self):
        return self.listbox.get()

    def _on_select(self, event):
        if self.on_select:
            self.on_select(self.get_selected_file())
