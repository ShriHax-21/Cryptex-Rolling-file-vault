# app.py
# Tkinter GUI for Cryptex Rolling File Vault


import customtkinter as ctk
import tkinter.filedialog as filedialog
from tkinter import messagebox
import tkinter.simpledialog as simpledialog
import subprocess
import sys
import shlex
import os
from vault.explorer import VaultExplorer
from core.key_manager import KeyManager
try:
    from core.db import DB
except Exception:
    DB = None

class VaultApp:
    def _pkcs7_pad(self, data, block_size):
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    def _pkcs7_unpad(self, data):
        pad_len = data[-1]
        if pad_len < 1 or pad_len > len(data):
            raise ValueError('Invalid padding')
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError('Invalid padding')
        return data[:-pad_len]

    def __init__(self, root):
        self.root = root
        self.root.title('Cryptex – Rolling File Vault')
        try:
            self.root.withdraw()
        except Exception:
            pass
        # set the app window to fixed desktop size (840x690), center it and prevent resizing
        try:
            # default size: wider/taller workspace
            w, h = 1280, 840
            # compute center position
            self.root.update_idletasks()
            sw = self.root.winfo_screenwidth()
            sh = self.root.winfo_screenheight()
            x = max(0, (sw - w) // 2)
            y = max(0, (sh - h) // 2)
            self.root.geometry(f"{w}x{h}+{x}+{y}")
            # store default size and allow dynamic resizing up to screen size
            self.default_w, self.default_h = w, h
            self.root.minsize(w, h)
            # allow growing up to screen resolution
            self.root.maxsize(sw, sh)
            # lock the window to the default size by default
            self.root.resizable(False, False)
            # ensure max size equals default so window stays fixed
            self.root.maxsize(w, h)
            # additional centering fallback for some window managers
            try:
                # Tk 8.6+ supports placing the window centered via tk::PlaceWindow
                self.root.update_idletasks()
                self.root.eval('tk::PlaceWindow . center')
            except Exception:
                pass
        except Exception:
            pass
        self.master_secret = None
        self.key_manager = None
        self.crypto_engine = None
        # whether the window is currently dynamic/resizable (default: disabled/locked)
        self.dynamic_size = False
        self.password_frame = None
        self.metadata_path = os.path.join('storage', 'metadata.json')
        # DB helper (SQLite single-file vault.db by default)
        self.db = None
        if DB is not None:
            try:
                self.db = DB()
                self.db.init_db()
            except Exception:
                self.db = None

        # Enforce DB-only mode
        if self.db is None:
            messagebox.showerror('Database Required', 'This build requires database-backed storage. Ensure a SQLite DB is available (default vault.db) or set SQLITE_DB_PATH env var.')
            try:
                self.root.destroy()
            except Exception:
                pass
            return

        # Password prompt / creation frame
        pw_set = KeyManager.password_is_set(self.metadata_path, db=self.db)
        self.password_frame = ctk.CTkFrame(self.root, fg_color='#e3f0fc', corner_radius=18)
        self.password_frame.pack(fill='both', expand=True, padx=18, pady=18)
        if pw_set:
            title_text = 'Enter Vault Password'
        else:
            title_text = 'Create Master Password (first run)'
        ctk.CTkLabel(self.password_frame, text=title_text, font=('JetBrains Mono', 18, 'bold'), text_color='#155fa0').pack(pady=(30, 10))
        self.password_entry = ctk.CTkEntry(self.password_frame, show='*', font=('JetBrains Mono', 15), width=260, corner_radius=10)
        self.password_entry.pack(pady=(0, 8))
        self.confirm_entry = None
        if not pw_set:
            self.confirm_entry = ctk.CTkEntry(self.password_frame, show='*', font=('JetBrains Mono', 13), width=260, corner_radius=10)
            self.confirm_entry.pack(pady=(0, 8))
        # autofocus the password entry and bind Enter to unlock/set
        try:
            self.password_entry.focus_set()
            self.password_entry.bind('<Return>', lambda e: self.unlock_vault())
            if self.confirm_entry:
                self.confirm_entry.bind('<Return>', lambda e: self.unlock_vault())
        except Exception:
            pass
        btn_text = 'Unlock' if pw_set else 'Set Password'
        ctk.CTkButton(self.password_frame, text=btn_text, font=('JetBrains Mono', 14, 'bold'), fg_color='#1976d2', command=self.unlock_vault, width=140, height=38, corner_radius=12).pack(pady=(6, 12))
        self.unlock_status = ctk.CTkLabel(self.password_frame, text='', font=('JetBrains Mono', 12), text_color='#d32f2f')
        self.unlock_status.pack()

    def unlock_vault(self):
        password = self.password_entry.get()
        if not password:
            self.unlock_status.configure(text='Password required!')
            return
        # Setup vault session manager
        from core.vault_session import VaultSession
        metadata_path = os.path.join('storage', 'metadata.json')
        # If no password exists yet, create it (first run)
        if not KeyManager.password_is_set(metadata_path, db=self.db):
            # require confirmation
            if not self.confirm_entry:
                self.unlock_status.configure(text='Confirmation required.')
                return
            confirm = self.confirm_entry.get()
            if password != confirm:
                self.unlock_status.configure(text='Passwords do not match!')
                return
            try:
                km = KeyManager(password, metadata_path, db=self.db)
                km.set_password(password)
            except Exception as e:
                self.unlock_status.configure(text=f'Failed to set password: {e}')
                return
        # proceed to create session and unlock using provided password
        self.master_secret = password
        try:
            self.vault_session = VaultSession(self.master_secret, metadata_path)
            self.vault_session.unlock()
        except Exception as e:
            self.unlock_status.configure(text=str(e))
            return
        # expose crypto engine for backwards compatibility with existing methods
        self.key_manager = self.vault_session.key_manager
        self.crypto_engine = self.vault_session.crypto_engine
        # Destroy password frame and show main UI
        self.password_frame.destroy()

        # Main frame for all widgets
        frame = ctk.CTkFrame(self.root, fg_color='#e3f0fc', corner_radius=18)
        frame.pack(fill='both', expand=True, padx=18, pady=18)

        # Title
        title = ctk.CTkLabel(frame, text='Cryptex: Rolling File Vault', font=('JetBrains Mono', 20, 'bold'), text_color='#155fa0')
        title.pack(pady=(18, 10), fill='x')

        # Action buttons: Reset and Change Password
        btn_row = ctk.CTkFrame(frame, fg_color='#eaf6ff', corner_radius=8)
        btn_row.pack(pady=(0, 8))
        reset_btn = ctk.CTkButton(btn_row, text='Reset Vault', font=('JetBrains Mono', 12, 'bold'), fg_color='#d32f2f', command=self.reset_vault, width=120, height=30, corner_radius=10)
        reset_btn.pack(side='left', padx=(0, 8))
        change_btn = ctk.CTkButton(btn_row, text='Change Password', font=('JetBrains Mono', 12, 'bold'), fg_color='#1976d2', command=self.change_password_prompt, width=160, height=30, corner_radius=10)
        change_btn.pack(side='left')

        # (size is locked by default; toggle removed)

        # Vault file explorer (from vault/explorer.py)
        # pass on_select callback so clicking a file updates the browse path
        self.vault_explorer = VaultExplorer(frame, on_select=self._on_vault_select)
        self.vault_explorer.pack(pady=(0, 10), fill='x', padx=10)


        # File selection row
        file_row = ctk.CTkFrame(frame, fg_color='#b3d8f8', corner_radius=15)
        file_row.pack(pady=(8, 10), fill='x', padx=10)
        select_btn = ctk.CTkButton(file_row, text='Browse Files', font=('JetBrains Mono', 13, 'bold'), fg_color='#1976d2', command=self.select_file, width=140, height=36, corner_radius=12)
        select_btn.pack(side='left', padx=(0, 16))
        self.file_entry = ctk.CTkEntry(file_row, font=('JetBrains Mono', 13), height=36, corner_radius=12, state='readonly')
        self.file_entry.pack(side='left', fill='x', expand=True)


        # Crypto options box
        options_box = ctk.CTkFrame(frame, fg_color='#b3d8f8', corner_radius=15)
        options_box.pack(pady=(10, 0), fill='x', padx=10)
        ctk.CTkLabel(options_box, text='Algorithm:', font=('JetBrains Mono', 12, 'bold'), text_color='#155fa0').pack(side='left', padx=(10, 2))
        self.alg_var = ctk.StringVar(value='AES')
        alg_menu = ctk.CTkComboBox(options_box, variable=self.alg_var, values=['AES', 'DES', '3DES'], font=('JetBrains Mono', 12), width=90, height=32, corner_radius=8, state='readonly')
        alg_menu.pack(side='left', padx=(0, 12))
        ctk.CTkLabel(options_box, text='Mode:', font=('JetBrains Mono', 12, 'bold'), text_color='#155fa0').pack(side='left', padx=(10, 2))
        self.mode_var = ctk.StringVar(value='GCM')
        mode_menu = ctk.CTkComboBox(options_box, variable=self.mode_var, values=['CBC', 'GCM', 'ECB'], font=('JetBrains Mono', 12), width=90, height=32, corner_radius=8, state='readonly')
        mode_menu.pack(side='left', padx=(0, 12))

        # Compatibility indicator
        self.compat_label = ctk.CTkLabel(options_box, text='', font=('JetBrains Mono', 11, 'bold'))
        self.compat_label.pack(side='left', padx=(8, 4))
        # update on selection change
        def _on_alg_mode_change(*_):
            self._update_compatibility()
        try:
            self.alg_var.trace_add('write', _on_alg_mode_change)
            self.mode_var.trace_add('write', _on_alg_mode_change)
            self._update_compatibility()
        except Exception:
            try:
                self.alg_var.trace('w', _on_alg_mode_change)
                self.mode_var.trace('w', _on_alg_mode_change)
                self._update_compatibility()
            except Exception:
                pass

        # Action buttons in a box
        action_box = ctk.CTkFrame(frame, fg_color='#b3d8f8', corner_radius=15)
        action_box.pack(pady=(10, 16), fill='x', padx=10)
        self.encrypt_btn = ctk.CTkButton(action_box, text='Encrypt', font=('JetBrains Mono', 15, 'bold'), fg_color='#1976d2', command=self.encrypt_file, width=160, height=48, corner_radius=16)
        self.encrypt_btn.pack(side='left', padx=(30, 20), pady=12)
        decrypt_btn = ctk.CTkButton(action_box, text='Decrypt', font=('JetBrains Mono', 15, 'bold'), fg_color='#155fa0', command=self.decrypt_file, width=160, height=48, corner_radius=16)
        decrypt_btn.pack(side='left', padx=(20, 12), pady=12)
        view_btn = ctk.CTkButton(action_box, text='View', font=('JetBrains Mono', 15, 'bold'), fg_color='#2e7d32', command=self.view_file, width=120, height=48, corner_radius=16)
        view_btn.pack(side='left', padx=(8, 30), pady=12)
        delete_btn = ctk.CTkButton(action_box, text='Delete', font=('JetBrains Mono', 15, 'bold'), fg_color='#d32f2f', command=self.delete_file, width=120, height=48, corner_radius=16)
        delete_btn.pack(side='left', padx=(8, 30), pady=12)

        # Output box for status messages
        output_frame = ctk.CTkFrame(self.root, fg_color='#b3d8f8', corner_radius=15)
        output_frame.pack(side='bottom', fill='x', padx=18, pady=(8, 20))
        output_label = ctk.CTkLabel(output_frame, text='Output', font=('JetBrains Mono', 14, 'bold'), text_color='#155fa0', anchor='w')
        output_label.pack(anchor='w', padx=10, pady=(8, 0))
        self.output_box = ctk.CTkTextbox(output_frame, font=('JetBrains Mono', 13), height=140, fg_color='#b3d8f8', text_color="#000000", corner_radius=10, state='disabled')
        self.output_box.pack(padx=10, pady=(6, 12), fill='x')

        # Save buttons for later reference
        self.select_btn = select_btn
        self.decrypt_btn = decrypt_btn
        self.view_btn = view_btn

        # Vault state indicator
        self.state_label = ctk.CTkLabel(frame, text='Unlocked', font=('JetBrains Mono', 11, 'bold'), text_color='#2e7d32')
        self.state_label.pack(anchor='ne', padx=10, pady=(0, 0))

        # schedule show+center after building the main UI so WM decorations settle
        try:
            def _show_and_center():
                try:
                    self.center_on_start()
                except Exception:
                    pass
                try:
                    self.root.deiconify()
                except Exception:
                    pass
            self.root.after(50, _show_and_center)
        except Exception:
            pass

    def select_file(self):
        import subprocess
        import sys
        import os
        file_path = None
        # Try to use system's default file explorer
        if sys.platform.startswith('linux'):
            # Try to use kdialog, zenity, or xdg-open
            try:
                # Try kdialog (KDE)
                file_path = subprocess.check_output(['kdialog', '--getopenfilename'], universal_newlines=True).strip()
            except Exception:
                try:
                    # Try zenity (GNOME)
                    file_path = subprocess.check_output(['zenity', '--file-selection'], universal_newlines=True).strip()
                except Exception:
                    # Fallback to Tkinter dialog
                    from tkinter import filedialog
                    file_path = filedialog.askopenfilename()
        elif sys.platform == 'darwin':
            # macOS
            try:
                file_path = subprocess.check_output(['osascript', '-e', 'POSIX path of (choose file)'], universal_newlines=True).strip()
            except Exception:
                from tkinter import filedialog
                file_path = filedialog.askopenfilename()
        elif sys.platform == 'win32':
            # Windows
            from tkinter import filedialog
            file_path = filedialog.askopenfilename()
        else:
            from tkinter import filedialog
            file_path = filedialog.askopenfilename()

        if file_path and os.path.isfile(file_path):
            self.file_path = file_path
            self.file_entry.configure(state='normal')
            self.file_entry.delete(0, ctk.END)
            self.file_entry.insert(0, file_path)
            self.file_entry.configure(state='readonly')
            self._set_output(f'Selected: {file_path}')
        else:
            self._set_output('No file selected.')

    def center_window(self, width=None, height=None):
        try:
            w = width or getattr(self, 'default_w', 1280)
            h = height or getattr(self, 'default_h', 840)
            self.root.update_idletasks()
            sw = self.root.winfo_screenwidth()
            sh = self.root.winfo_screenheight()
            x = max(0, (sw - w) // 2)
            y = max(0, (sh - h) // 2)
            self.root.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

    def toggle_dynamic_size(self):
        """Toggle whether the main window is resizable by the user."""
        try:
            if not getattr(self, 'dynamic_size', False):
                # enable dynamic resizing
                self.dynamic_size = True
                self.root.resizable(True, True)
                self.root.maxsize(self.root.winfo_screenwidth(), self.root.winfo_screenheight())
                # update button label
                try:
                    self.toggle_size_btn.configure(text='Lock Size')
                except Exception:
                    pass
            else:
                # lock back to default fixed size
                self.dynamic_size = False
                self.root.resizable(False, False)
                try:
                    self.root.minsize(self.default_w, self.default_h)
                    self.root.maxsize(self.default_w, self.default_h)
                except Exception:
                    pass
                # re-center and enforce default geometry
                self.center_window(self.default_w, self.default_h)
                try:
                    self.toggle_size_btn.configure(text='Enable Dynamic Size')
                except Exception:
                    pass
            self._set_output(f"Window dynamic sizing: {'enabled' if self.dynamic_size else 'disabled'}")
        except Exception as e:
            self._set_output(f'Error toggling dynamic size: {e}')

    def _on_vault_select(self, filename):
        """Handle selection from the VaultExplorer listbox.
        Sets the browse path to the selected vault file.
        """
        if not filename:
            return
        # DB-only: explorer lists filenames and they are DB keys
        if not hasattr(self, 'db') or self.db is None:
            self._set_output('Error: Database not available.')
            return
        self.file_path = filename
        try:
            self.file_entry.configure(state='normal')
            self.file_entry.delete(0, ctk.END)
            self.file_entry.insert(0, filename)
            self.file_entry.configure(state='readonly')
        except Exception:
            pass
        self._set_output(f'Selected from vault (DB): {filename}')

    def view_file(self):
        """Decrypt the selected file into memory and show a secure preview window.
        Supports DB-backed files when `USE_DB=1` and `self.db` initialized.
        """
        if not hasattr(self, 'file_path') or not self.file_path:
            self._set_output('Error: No file selected.')
            return
        try:
            data, status = self.vault_session.decrypt_in_memory(self.file_path)
            preview = ctk.CTkToplevel(self.root)
            preview.title('Preview')
            # position the preview to the right/top of the main window so dialogs
            # opened from it don't block the main UI
            try:
                pw, ph = 700, 500
                self.root.update_idletasks()
                preview.update_idletasks()
                rw = self.root.winfo_width() or getattr(self, 'default_w', 1280)
                rh = self.root.winfo_height() or getattr(self, 'default_h', 840)
                rx = self.root.winfo_x()
                ry = self.root.winfo_y()
                # place preview on the right half of the main window
                px = rx + max(20, int(rw * 0.45))
                py = ry + 30
                sw = self.root.winfo_screenwidth()
                sh = self.root.winfo_screenheight()
                # clamp to screen
                px = min(max(0, px), sw - pw)
                py = min(max(0, py), sh - ph)
                preview.geometry(f"{pw}x{ph}+{px}+{py}")
            except Exception:
                try:
                    preview.geometry('700x500')
                except Exception:
                    pass
            try:
                preview.transient(self.root)
                preview.lift()
                preview.focus_force()
            except Exception:
                pass
            status_label = ctk.CTkLabel(preview, text=f'Integrity: {status}', font=('JetBrains Mono', 12, 'bold'))
            status_label.pack(anchor='w', padx=10, pady=(8, 4))
            # Decide preview strategy: text vs binary
            try:
                filename = os.path.basename(self.file_path) if isinstance(self.file_path, str) else ''
                ext = os.path.splitext(filename)[1].lower()
            except Exception:
                ext = ''

            binary_exts = ('.pdf', '.docx', '.doc', '.xlsx', '.xls', '.png', '.jpg', '.jpeg', '.gif', '.bmp')
            is_text = False
            if ext and ext not in binary_exts:
                try:
                    data.decode('utf-8')
                    is_text = True
                except Exception:
                    is_text = False

            if is_text:
                text = data.decode('utf-8')
                box = ctk.CTkTextbox(preview, width=660, height=380, font=('JetBrains Mono', 12))
                box.insert('0.0', text)
                box.pack(padx=10, pady=(0, 8), fill='both', expand=True)
            else:
                # For binary files (PDF/office/images/etc) avoid rendering large hex or raw bytes.
                label = ctk.CTkLabel(preview, text=f'Binary file preview not available for "{filename}". Use Export or Open.', wraplength=640)
                label.pack(padx=10, pady=(10, 8))
                box = None
            btn_frame = ctk.CTkFrame(preview)
            btn_frame.pack(pady=(0, 10))
            def export():
                from tkinter import filedialog
                # parent the dialog to the preview so it appears over it
                dst = filedialog.asksaveasfilename(parent=preview, initialdir=os.path.expanduser('~/Downloads'))
                if not dst:
                    return
                # prevent accidental saving to hidden files: warn if filename starts with a dot
                bn = os.path.basename(dst)
                if bn.startswith('.'):
                    if not messagebox.askyesno('Hidden File', f"You're saving a hidden file '{bn}'. Continue?"):
                        return
                try:
                    with open(dst, 'wb') as f:
                        f.write(data)
                    self._set_output(f'Exported decrypted file to {dst}')
                except Exception as e:
                    self._set_output(f'Error: Export failed: {e}')

            def open_with_default():
                # write to a temp file with original extension and open with system default viewer
                import tempfile, subprocess
                try:
                    suffix = ext or ''
                    tf = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
                    tf.write(data)
                    tf.close()
                    # Use xdg-open on Linux
                    if os.name == 'posix':
                        subprocess.Popen(['xdg-open', tf.name])
                    else:
                        try:
                            os.startfile(tf.name)
                        except Exception:
                            subprocess.Popen(['open', tf.name])
                    self._set_output(f'Opened temporary decrypted file: {tf.name}')
                except Exception as e:
                    self._set_output(f'Error: Open failed: {e}')

            def close_preview():
                try:
                    box.delete('0.0', 'end')
                except Exception:
                    pass
                preview.destroy()

            export_btn = ctk.CTkButton(btn_frame, text='Export', command=export, fg_color='#1976d2')
            export_btn.pack(side='left', padx=(6, 6))
            open_btn = ctk.CTkButton(btn_frame, text='Open', command=open_with_default, fg_color='#009688')
            open_btn.pack(side='left', padx=(6, 6))
            close_btn = ctk.CTkButton(btn_frame, text='Close', command=close_preview, fg_color='#bdbdbd')
            close_btn.pack(side='left', padx=(6, 6))
        except Exception as e:
            self._set_output(f'Error: View failed: {e}')

    def _update_compatibility(self):
        """Update compatibility label and toggle Encrypt button based on selection."""
        mapping = {
            'AES': ['GCM', 'CBC', 'ECB'],
            'DES': ['CBC', 'ECB'],
            '3DES': ['CBC', 'ECB']
        }
        alg = self.alg_var.get() if hasattr(self, 'alg_var') else None
        mode = self.mode_var.get() if hasattr(self, 'mode_var') else None
        compat = False
        if alg in mapping and mode in mapping[alg]:
            compat = True
        if compat:
            try:
                self.compat_label.configure(text='Compatible', text_color='#2e7d32')
            except Exception:
                pass
            try:
                self.encrypt_btn.configure(state='normal')
            except Exception:
                pass
        else:
            try:
                self.compat_label.configure(text='Incompatible', text_color='#d32f2f')
            except Exception:
                pass
            try:
                self.encrypt_btn.configure(state='disabled')
            except Exception:
                pass

    def encrypt_file(self):
        # check selected algorithm/mode compatibility
        mapping = {
            'AES': ['GCM', 'CBC', 'ECB'],
            'DES': ['CBC', 'ECB'],
            '3DES': ['CBC', 'ECB']
        }
        alg = self.alg_var.get()
        mode = self.mode_var.get()
        if alg not in mapping or mode not in mapping[alg]:
            self._set_output(f'Error: Selected mode {mode} is not compatible with {alg}.')
            return
        if not hasattr(self, 'file_path') or not self.file_path:
            self._set_output('Error: No file selected.')
            return
        if not hasattr(self, 'db') or self.db is None:
            self._set_output('Error: Database not configured. Cannot store encrypted file.')
            return
        try:
            from Crypto.Cipher import AES, DES, DES3
            from Crypto.Random import get_random_bytes
            import os, json
            alg = self.alg_var.get()
            mode = self.mode_var.get()
            with open(self.file_path, 'rb') as f:
                data = f.read()

            if alg == 'AES':
                key = self.crypto_engine.key[:32]
                cipher_mode = getattr(AES, f"MODE_{mode}")
                cipher = AES.new(key, cipher_mode)
                if mode in ['CBC', 'ECB']:
                    data = self._pkcs7_pad(data, AES.block_size)
            elif alg == 'DES':
                key = self.crypto_engine.key[:8]
                cipher_mode = getattr(DES, f"MODE_{mode}")
                cipher = DES.new(key, cipher_mode)
                if mode in ['CBC', 'ECB']:
                    data = self._pkcs7_pad(data, DES.block_size)
            elif alg == '3DES':
                key = self.crypto_engine.key[:24]
                cipher_mode = getattr(DES3, f"MODE_{mode}")
                cipher = DES3.new(key, cipher_mode)
                if mode in ['CBC', 'ECB']:
                    data = self._pkcs7_pad(data, DES3.block_size)
            else:
                self._set_output('Unsupported algorithm.')
                return

            if mode == 'GCM':
                ciphertext, tag = cipher.encrypt_and_digest(data)
            else:
                ciphertext = cipher.encrypt(data)
                tag = b''

            header = json.dumps({
                'nonce': getattr(cipher, 'nonce', b'').hex() if hasattr(cipher, 'nonce') else '',
                'iv': getattr(cipher, 'iv', b'').hex() if hasattr(cipher, 'iv') else '',
                'tag': tag.hex() if tag else ''
            }).encode() + b'\n'

            filename = os.path.basename(self.file_path)
            enc_name = filename + f'.{alg.lower()}_{mode.lower()}.enc'

            # DB-only: store encrypted blob in database
            content = header + ciphertext
            self.db.store_file_blob(enc_name, content, nonce=(getattr(cipher, 'nonce', b'').hex() if hasattr(cipher, 'nonce') else None), iv=(getattr(cipher, 'iv', b'').hex() if hasattr(cipher, 'iv') else None), tag=(tag.hex() if tag else None), alg=alg, mode=mode)
            self._set_output(f'Success: File encrypted and stored in DB as {enc_name}')

            try:
                if hasattr(self, 'vault_explorer') and self.vault_explorer:
                    self.vault_explorer.refresh()
            except Exception:
                pass
        except Exception as e:
            self._set_output(f'Error: Encryption failed: {e}')

    def decrypt_file(self):
        if not hasattr(self, 'file_path') or not self.file_path:
            self._set_output('Error: No file selected.')
            return
        if not hasattr(self, 'db') or self.db is None:
            self._set_output('Error: Database not configured. Cannot retrieve encrypted file.')
            return
        try:
            from Crypto.Cipher import AES, DES, DES3
            import os, json
            alg = self.alg_var.get()
            mode = self.mode_var.get()

            # fetch content from DB
            name = self.file_path if os.path.basename(self.file_path) == self.file_path else os.path.basename(self.file_path)
            row = self.db.get_file_by_name(name)
            if not row or row.get('content') is None:
                self._set_output('Error: File not found in DB')
                return
            content = row.get('content')
            if isinstance(content, memoryview):
                content = bytes(content)
            parts = content.split(b'\n', 1)
            header = parts[0] if parts else b'{}'
            enc_dict = json.loads(header.decode())
            ciphertext = parts[1] if len(parts) > 1 else b''

            if alg == 'AES':
                key = self.crypto_engine.key[:32]
                cipher_mode = getattr(AES, f"MODE_{mode}")
                if mode == 'GCM':
                    cipher = AES.new(key, cipher_mode, nonce=bytes.fromhex(enc_dict.get('nonce', '')))
                    dec_bytes = cipher.decrypt_and_verify(ciphertext, bytes.fromhex(enc_dict.get('tag', '')))
                elif mode == 'CBC':
                    cipher = AES.new(key, cipher_mode, iv=bytes.fromhex(enc_dict.get('iv', '')))
                    dec_bytes = self._pkcs7_unpad(cipher.decrypt(ciphertext))
                else:  # ECB
                    cipher = AES.new(key, cipher_mode)
                    dec_bytes = self._pkcs7_unpad(cipher.decrypt(ciphertext))
            elif alg == 'DES':
                key = self.crypto_engine.key[:8]
                cipher_mode = getattr(DES, f"MODE_{mode}")
                if mode == 'GCM':
                    self._set_output('DES does not support GCM mode.')
                    return
                elif mode == 'CBC':
                    cipher = DES.new(key, cipher_mode, iv=bytes.fromhex(enc_dict.get('iv', '')))
                    dec_bytes = self._pkcs7_unpad(cipher.decrypt(ciphertext))
                else:  # ECB
                    cipher = DES.new(key, cipher_mode)
                    dec_bytes = self._pkcs7_unpad(cipher.decrypt(ciphertext))
            elif alg == '3DES':
                key = self.crypto_engine.key[:24]
                cipher_mode = getattr(DES3, f"MODE_{mode}")
                if mode == 'GCM':
                    self._set_output('3DES does not support GCM mode.')
                    return
                elif mode == 'CBC':
                    cipher = DES3.new(key, cipher_mode, iv=bytes.fromhex(enc_dict.get('iv', '')))
                    dec_bytes = self._pkcs7_unpad(cipher.decrypt(ciphertext))
                else:  # ECB
                    cipher = DES3.new(key, cipher_mode)
                    dec_bytes = self._pkcs7_unpad(cipher.decrypt(ciphertext))
            else:
                self._set_output('Unsupported algorithm.')
                return

            filename = os.path.basename(self.file_path)
            if filename.endswith('.enc'):
                filename = filename[:-4]
            # Prompt user for save location instead of writing to storage/
            from tkinter import filedialog
            dst = filedialog.asksaveasfilename(initialdir=os.path.expanduser('~/Downloads'), initialfile=(filename + '.decrypted'))
            if not dst:
                self._set_output('Decryption cancelled (no destination chosen).')
                return
            bn = os.path.basename(dst)
            if bn.startswith('.'):
                if not messagebox.askyesno('Hidden File', f"You're saving a hidden file '{bn}'. Continue?"):
                    self._set_output('Decryption cancelled (hidden filename)')
                    return
            try:
                with open(dst, 'wb') as f:
                    f.write(dec_bytes)
                self._set_output(f'Success: File decrypted and saved to {dst}')
            except Exception as e:
                self._set_output(f'Error: Decryption failed when saving: {e}')
        except Exception as e:
            self._set_output(f'Error: Decryption failed: {e}')
          

    def delete_file(self):
        """Delete the selected vault file from the DB after confirmation."""
        if not hasattr(self, 'file_path') or not self.file_path:
            self._set_output('Error: No file selected to delete.')
            return
        if not hasattr(self, 'db') or self.db is None:
            self._set_output('Error: Database not configured. Cannot delete file.')
            return
        name = self.file_path if os.path.basename(self.file_path) == self.file_path else os.path.basename(self.file_path)
        ok = messagebox.askyesno('Delete File', f'Permanently delete "{name}" from the vault?')
        if not ok:
            self._set_output('Delete cancelled.')
            return
        try:
            self.db.delete_file_by_name(name)
            try:
                if hasattr(self, 'vault_explorer') and self.vault_explorer:
                    self.vault_explorer.refresh()
            except Exception:
                pass
            # clear selection
            try:
                self.file_entry.configure(state='normal')
                self.file_entry.delete(0, ctk.END)
                self.file_entry.configure(state='readonly')
            except Exception:
                pass
            self.file_path = None
            self._set_output(f'Success: Deleted {name} from vault')
        except Exception as e:
            self._set_output(f'Error: Delete failed: {e}')

    def _set_output(self, message):
        self.output_box.configure(state='normal')
        self.output_box.delete(1.0, 'end')
        self.output_box.insert('end', message)
        self.output_box.configure(state='disabled')

    def reset_vault(self):
        # confirm destructive action
        if not hasattr(self, 'vault_session') or not self.vault_session:
            messagebox.showinfo('Reset Vault', 'Vault session not initialized.')
            return
        ok = messagebox.askyesno('Reset Vault', 'This will permanently delete all vault data (encrypted files, metadata). Continue?')
        if not ok:
            return
        try:
            self.vault_session.reset()
        except Exception as e:
            messagebox.showerror('Reset Failed', str(e))
            return
        messagebox.showinfo('Reset Complete', 'Vault has been reset. The application will close.')
        try:
            self.root.destroy()
        except Exception:
            pass

    def change_password_prompt(self):
        if not hasattr(self, 'vault_session') or not self.vault_session:
            messagebox.showinfo('Change Password', 'Vault session not initialized.')
            return
        # Ask for new password and confirmation
        new_pw = simpledialog.askstring('Change Password', 'Enter new password:', show='*')
        if not new_pw:
            return
        confirm = simpledialog.askstring('Change Password', 'Confirm new password:', show='*')
        if new_pw != confirm:
            messagebox.showerror('Change Password', 'Passwords do not match.')
            return
        ok = messagebox.askyesno('Change Password', 'Changing the password will migrate and re-encrypt vault data. This can be destructive if backups fail. Continue?')
        if not ok:
            return
        # Run migration script using current Python executable
        try:
            script_path = os.path.join(os.getcwd(), 'scripts', 'change_password.py')
            cmd = [sys.executable, script_path, '--new-password', new_pw]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                messagebox.showerror('Change Password Failed', f'Error: {proc.stderr or proc.stdout}')
                return
            messagebox.showinfo('Change Password', 'Password changed successfully. The application will now close.')
            try:
                self.root.destroy()
            except Exception:
                pass
        except Exception as e:
            messagebox.showerror('Change Password Failed', str(e))

if __name__ == '__main__':
    root = ctk.Tk()
    app = VaultApp(root)
    root.mainloop()
