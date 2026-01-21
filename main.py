
# --- VENV AUTO-ACTIVATION BLOCK (Linux/macOS) ---
import os, sys
VENV_PYTHON = os.path.join(os.path.dirname(__file__), "venv", "bin", "python")
if sys.executable != VENV_PYTHON and os.path.exists(VENV_PYTHON):
    os.execv(VENV_PYTHON, [VENV_PYTHON] + sys.argv)

# Entry point for Nettoss – Rolling File Vault
from gui.app import VaultApp
import tkinter as tk

if __name__ == '__main__':
	root = tk.Tk()
	app = VaultApp(root)
	root.mainloop()
