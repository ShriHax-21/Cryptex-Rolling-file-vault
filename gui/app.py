# app.py
# Tkinter GUI for Nettoss Rolling File Vault


import customtkinter as ctk
import tkinter.filedialog as filedialog
import os
from vault.explorer import VaultExplorer
from core.key_manager import KeyManager

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
        self.root.title('Nettoss – Rolling File Vault')
        # set the app window to fixed desktop size (840x690), center it and prevent resizing
        try:
            w, h = 840, 690
            # compute center position
            self.root.update_idletasks()
            sw = self.root.winfo_screenwidth()
            sh = self.root.winfo_screenheight()
            x = max(0, (sw - w) // 2)
            y = max(0, (sh - h) // 2)
            self.root.geometry(f"{w}x{h}+{x}+{y}")
            self.root.minsize(w, h)
            self.root.maxsize(w, h)
            self.root.resizable(False, False)
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
        self.password_frame = None
        # metadata path
        self.metadata_path = os.path.join('storage', 'metadata.json')

        # Password prompt / creation frame
        pw_set = KeyManager.password_is_set(self.metadata_path)
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
        if not KeyManager.password_is_set(metadata_path):
            # require confirmation
            if not self.confirm_entry:
                self.unlock_status.configure(text='Confirmation required.')
                return
            confirm = self.confirm_entry.get()
            if password != confirm:
                self.unlock_status.configure(text='Passwords do not match!')
                return
            try:
                km = KeyManager(password, metadata_path)
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
        title = ctk.CTkLabel(frame, text='NetToss: secure vault', font=('JetBrains Mono', 20, 'bold'), text_color='#155fa0')
        title.pack(pady=(18, 10), fill='x')

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

        # Action buttons in a box
        action_box = ctk.CTkFrame(frame, fg_color='#b3d8f8', corner_radius=15)
        action_box.pack(pady=(10, 16), fill='x', padx=10)
        encrypt_btn = ctk.CTkButton(action_box, text='Encrypt', font=('JetBrains Mono', 15, 'bold'), fg_color='#1976d2', command=self.encrypt_file, width=160, height=48, corner_radius=16)
        encrypt_btn.pack(side='left', padx=(30, 20), pady=12)
        decrypt_btn = ctk.CTkButton(action_box, text='Decrypt', font=('JetBrains Mono', 15, 'bold'), fg_color='#155fa0', command=self.decrypt_file, width=160, height=48, corner_radius=16)
        decrypt_btn.pack(side='left', padx=(20, 12), pady=12)
        view_btn = ctk.CTkButton(action_box, text='View', font=('JetBrains Mono', 15, 'bold'), fg_color='#2e7d32', command=self.view_file, width=120, height=48, corner_radius=16)
        view_btn.pack(side='left', padx=(8, 30), pady=12)

        # Output box for status messages
        output_frame = ctk.CTkFrame(self.root, fg_color='#b3d8f8', corner_radius=15)
        output_frame.pack(side='bottom', fill='x', padx=18, pady=(8, 20))
        output_label = ctk.CTkLabel(output_frame, text='Output', font=('JetBrains Mono', 14, 'bold'), text_color='#155fa0', anchor='w')
        output_label.pack(anchor='w', padx=10, pady=(8, 0))
        self.output_box = ctk.CTkTextbox(output_frame, font=('JetBrains Mono', 13), height=140, fg_color='#b3d8f8', text_color="#000000", corner_radius=10, state='disabled')
        self.output_box.pack(padx=10, pady=(6, 12), fill='x')

        # Save buttons for later reference
        self.select_btn = select_btn
        self.encrypt_btn = encrypt_btn
        self.decrypt_btn = decrypt_btn
        self.view_btn = view_btn

        # Vault state indicator
        self.state_label = ctk.CTkLabel(frame, text='Unlocked', font=('JetBrains Mono', 11, 'bold'), text_color='#2e7d32')
        self.state_label.pack(anchor='ne', padx=10, pady=(0, 0))

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

    def _on_vault_select(self, filename):
        """Handle selection from the VaultExplorer listbox.
        Sets the browse path to the selected vault file.
        """
        if not filename:
            return
        vault_path = os.path.join('storage', 'encrypted', filename)
        if os.path.exists(vault_path):
            self.file_path = vault_path
            try:
                self.file_entry.configure(state='normal')
                self.file_entry.delete(0, ctk.END)
                self.file_entry.insert(0, vault_path)
                self.file_entry.configure(state='readonly')
            except Exception:
                pass
            self._set_output(f'Selected from vault: {vault_path}')

    def view_file(self):
        """Decrypt the selected file into memory and show a secure preview window."""
        if not hasattr(self, 'file_path') or not self.file_path:
            self._set_output('Error: No file selected.')
            return
        try:
            # use vault_session for in-memory decryption and integrity status
            data, status = self.vault_session.decrypt_in_memory(self.file_path)
            # open a Toplevel preview
            preview = ctk.CTkToplevel(self.root)
            preview.title('Preview')
            preview.geometry('700x500')
            # show integrity/auth feedback
            status_label = ctk.CTkLabel(preview, text=f'Integrity: {status}', font=('JetBrains Mono', 12, 'bold'))
            status_label.pack(anchor='w', padx=10, pady=(8, 4))
            # attempt to decode as UTF-8 text
            try:
                text = data.decode('utf-8')
                box = ctk.CTkTextbox(preview, width=660, height=380, font=('JetBrains Mono', 12))
                box.insert('0.0', text)
            except Exception:
                # binary: show hex
                hextext = data.hex()
                box = ctk.CTkTextbox(preview, width=660, height=380, font=('JetBrains Mono', 11))
                box.insert('0.0', hextext)
            box.pack(padx=10, pady=(0, 8), fill='both', expand=True)
            # export and close buttons
            btn_frame = ctk.CTkFrame(preview)
            btn_frame.pack(pady=(0, 10))
            def export():
                from tkinter import filedialog
                dst = filedialog.asksaveasfilename()
                if dst:
                    with open(dst, 'wb') as f:
                        f.write(data)
                    self._set_output(f'Exported decrypted file to {dst}')
            def close_preview():
                # wipe sensitive data references
                try:
                    box.delete('0.0', 'end')
                except Exception:
                    pass
                preview.destroy()
            export_btn = ctk.CTkButton(btn_frame, text='Export', command=export, fg_color='#1976d2')
            export_btn.pack(side='left', padx=(6, 6))
            close_btn = ctk.CTkButton(btn_frame, text='Close', command=close_preview, fg_color='#bdbdbd')
            close_btn.pack(side='left', padx=(6, 6))
            # when preview closed, ensure memory cleared by losing references
        except Exception as e:
            self._set_output(f'Error: View failed: {e}')

    def encrypt_file(self):
        if not hasattr(self, 'file_path') or not self.file_path:
            self._set_output('Error: No file selected.')
            return
        try:
            from Crypto.Cipher import AES, DES, DES3
            from Crypto.Random import get_random_bytes
            import os, json
            alg = self.alg_var.get()
            mode = self.mode_var.get()
            with open(self.file_path, 'rb') as f:
                data = f.read()
            # Key selection and mode mapping, with PKCS7 padding for block ciphers
            if alg == 'AES':
                key = self.crypto_engine.key[:32]
                cipher_mode = getattr(AES, f"MODE_{mode}")
                if mode in ['CBC', 'ECB']:
                    cipher = AES.new(key, cipher_mode)
                    data = self._pkcs7_pad(data, AES.block_size)
                else:
                    cipher = AES.new(key, cipher_mode)
            elif alg == 'DES':
                key = self.crypto_engine.key[:8]
                cipher_mode = getattr(DES, f"MODE_{mode}")
                if mode in ['CBC', 'ECB']:
                    cipher = DES.new(key, cipher_mode)
                    data = self._pkcs7_pad(data, DES.block_size)
                else:
                    cipher = DES.new(key, cipher_mode)
            elif alg == '3DES':
                key = self.crypto_engine.key[:24]
                cipher_mode = getattr(DES3, f"MODE_{mode}")
                if mode in ['CBC', 'ECB']:
                    cipher = DES3.new(key, cipher_mode)
                    data = self._pkcs7_pad(data, DES3.block_size)
                else:
                    cipher = DES3.new(key, cipher_mode)
            else:
                self._set_output('Unsupported algorithm.')
                return
            if mode in ['CBC', 'GCM']:
                ciphertext, tag = cipher.encrypt_and_digest(data) if mode == 'GCM' else (cipher.encrypt(data), b'')
                header = json.dumps({
                    'nonce': cipher.nonce.hex() if hasattr(cipher, 'nonce') else '',
                    'iv': cipher.iv.hex() if hasattr(cipher, 'iv') else '',
                    'tag': tag.hex() if tag else ''
                }).encode() + b'\n'
            else:  # ECB
                ciphertext = cipher.encrypt(data)
                header = json.dumps({}).encode() + b'\n'
            filename = os.path.basename(self.file_path)
            # ensure encrypted output directory exists
            enc_dir = os.path.join('storage', 'encrypted')
            os.makedirs(enc_dir, exist_ok=True)
            out_path = os.path.join(enc_dir, filename + f'.{alg.lower()}_{mode.lower()}.enc')
            with open(out_path, 'wb') as f:
                f.write(header)
                f.write(ciphertext)
            self._set_output(f'Success: File encrypted and saved to {out_path}')
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
        try:
            from Crypto.Cipher import AES, DES, DES3
            import os, json
            alg = self.alg_var.get()
            mode = self.mode_var.get()
            with open(self.file_path, 'rb') as f:
                header = f.readline()
                enc_dict = json.loads(header.decode())
                ciphertext = f.read()
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
            # ensure decrypted output directory exists
            dec_dir = os.path.join('storage', 'decrypted')
            os.makedirs(dec_dir, exist_ok=True)
            out_path = os.path.join(dec_dir, filename + f'.decrypted')
            with open(out_path, 'wb') as f:
                f.write(dec_bytes)
            self._set_output(f'Success: File decrypted and saved to {out_path}')
        except Exception as e:
            self._set_output(f'Error: Decryption failed: {e}')
          

    def _set_output(self, message):
        self.output_box.configure(state='normal')
        self.output_box.delete(1.0, 'end')
        self.output_box.insert('end', message)
        self.output_box.configure(state='disabled')

if __name__ == '__main__':
    root = ctk.Tk()
    app = VaultApp(root)
    root.mainloop()
