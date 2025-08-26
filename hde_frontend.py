"""
hde_frontend.py
GUI for the HDE simulator. Imports cryptographic functions from hde_backend.
"""
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hde_backend as hde

class HDEGui(tk.Tk):
    """
    HDE Simulator GUI using Tkinter.
    Provides a user-friendly interface for file encryption and decryption
    using both AES-256-GCM and RSA-2048 (hybrid) algorithms.
    """
    def __init__(self):
        super().__init__()
        self.title("HDE Simulator - AES & RSA (hybrid)")
        self.geometry("800x600")
        self.resizable(False, False)
        
        # Apply a modern style
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("Helvetica", 10))
        self.style.configure("TButton", font=("Helvetica", 10, "bold"), padding=5)
        self.style.configure("TEntry", font=("Helvetica", 10), padding=5)
        self.style.configure("TCombobox", font=("Helvetica", 10))
        self.style.configure("TCheckbutton", background="#f0f0f0")
        self.style.configure("Heading.TLabel", font=("Helvetica", 16, "bold"), foreground="#333333")
        self.style.configure("Status.TLabel", font=("Helvetica", 10, "italic"), foreground="#555555")

        # Store keys
        self.aes_key = None
        self.rsa_private = None
        self.rsa_public = None

        # Widgets
        self._build_widgets()

    def _build_widgets(self):
        """Creates and packs all the GUI widgets."""
        pad = 20

        # Main frame
        main_frame = ttk.Frame(self, padding=pad)
        main_frame.pack(fill="both", expand=True)

        lbl_title = ttk.Label(main_frame, text="Hardware Data Encryption (HDE)", style="Heading.TLabel")
        lbl_title.pack(pady=(0, 10))
        lbl_subtitle = ttk.Label(main_frame, text="AES-256-GCM & RSA-2048 (hybrid)", font=("Helvetica", 12))
        lbl_subtitle.pack(pady=(0, 20))

        # Algorithm selector frame
        algo_frame = ttk.Frame(main_frame)
        algo_frame.pack(fill="x", pady=(10, 10))
        ttk.Label(algo_frame, text="Select Algorithm:").grid(row=0, column=0, sticky="w", padx=5)
        self.algo_var = tk.StringVar(value="AES")
        algo_dropdown = ttk.Combobox(algo_frame, textvariable=self.algo_var, values=["AES", "RSA"], state="readonly", width=10)
        algo_dropdown.grid(row=0, column=1, sticky="ew", padx=5)
        algo_frame.grid_columnconfigure(1, weight=1)

        # Key frame
        self.frame_key = ttk.Frame(main_frame)
        self.frame_key.pack(fill="x", pady=10)
        self._update_key_widgets("AES")

        # File selection frame
        file_frame = ttk.Frame(main_frame, padding=(0, 10))
        file_frame.pack(fill="x", pady=10)
        file_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(file_frame, text="Input File:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.input_entry = ttk.Entry(file_frame)
        self.input_entry.grid(row=0, column=1, sticky="ew", padx=5)
        btn_browse_in = ttk.Button(file_frame, text="Browse...", command=self.on_browse_input)
        btn_browse_in.grid(row=0, column=2, padx=5)

        ttk.Label(file_frame, text="Output File:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.output_entry = ttk.Entry(file_frame)
        self.output_entry.grid(row=1, column=1, sticky="ew", padx=5)
        btn_browse_out = ttk.Button(file_frame, text="Browse...", command=self.on_browse_output)
        btn_browse_out.grid(row=1, column=2, padx=5)

        # Operation buttons frame
        ops_frame = ttk.Frame(main_frame, padding=(0, 10))
        ops_frame.pack(pady=10)
        btn_encrypt = ttk.Button(ops_frame, text="Encrypt", command=self.on_encrypt)
        btn_encrypt.grid(row=0, column=0, padx=10)
        btn_decrypt = ttk.Button(ops_frame, text="Decrypt", command=self.on_decrypt)
        btn_decrypt.grid(row=0, column=1, padx=10)
        btn_clear = ttk.Button(ops_frame, text="Clear", command=self.on_clear)
        btn_clear.grid(row=0, column=2, padx=10)

        # Status frame
        status_frame = ttk.Frame(main_frame, padding=(0, 10))
        status_frame.pack(fill="both", expand=True, pady=(10, 0))
        ttk.Label(status_frame, text="Status:").pack(anchor="w", padx=5)
        self.status_text = tk.Text(status_frame, height=8, state="disabled", font=("Courier New", 10), wrap="word")
        self.status_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Bind algorithm change event
        self.algo_var.trace_add("write", self.on_algo_change)

    # ---------- Key UI ----------
    def _update_key_widgets(self, algo):
        """Dynamically updates the key-related widgets based on the selected algorithm."""
        for w in self.frame_key.winfo_children():
            w.destroy()

        if algo == "AES":
            self.frame_key.grid_columnconfigure(1, weight=1)
            ttk.Label(self.frame_key, text="AES Key (hex):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
            self.key_entry = ttk.Entry(self.frame_key)
            self.key_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
            btn_gen = ttk.Button(self.frame_key, text="Generate Key", command=self.on_generate_aes_key)
            btn_gen.grid(row=0, column=2, padx=5, pady=5)

            btn_save = ttk.Button(self.frame_key, text="Save Key...", command=self.on_save_aes_key)
            btn_save.grid(row=1, column=0, padx=5, pady=5, sticky="e")
            btn_load = ttk.Button(self.frame_key, text="Load Key...", command=self.on_load_aes_key)
            btn_load.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        else:  # RSA
            self.frame_key.grid_columnconfigure(1, weight=1)
            btn_gen = ttk.Button(self.frame_key, text="Generate RSA Keys", command=self.on_generate_rsa_keys)
            btn_gen.grid(row=0, column=0, columnspan=3, padx=5, pady=5)
            
            status_frame = ttk.Frame(self.frame_key)
            status_frame.grid(row=1, column=0, columnspan=3, pady=5)
            self.rsa_status = ttk.Label(status_frame, text="No keys loaded", foreground="red")
            self.rsa_status.pack(pady=5)

            btn_save_pub = ttk.Button(self.frame_key, text="Save Public Key...", command=self.on_save_rsa_pub)
            btn_save_pub.grid(row=2, column=0, padx=5, pady=5)
            btn_save_priv = ttk.Button(self.frame_key, text="Save Private Key...", command=self.on_save_rsa_priv)
            btn_save_priv.grid(row=2, column=1, padx=5, pady=5)
            btn_load_priv = ttk.Button(self.frame_key, text="Load Private Key...", command=self.on_load_rsa_priv)
            btn_load_priv.grid(row=2, column=2, padx=5, pady=5)

    def on_algo_change(self, *args):
        """Callback for algorithm change event."""
        self._update_key_widgets(self.algo_var.get())

    # ---------- Key Ops (calls backend functions) ----------
    def on_generate_aes_key(self):
        """Generates and displays a new AES key."""
        self.aes_key = hde.aes_generate_key()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, hde.aes_key_to_hex(self.aes_key))
        self._log("Generated AES-256 key.")

    def on_save_aes_key(self):
        """Saves the current AES key to a file."""
        hexval = self.key_entry.get().strip()
        if not hexval:
            messagebox.showwarning("No Key", "Key field is empty.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files","*.key"),("All files","*.*")])
        if path:
            with open(path, "w") as f:
                f.write(hexval)
            self._log(f"Saved AES key to: {path}")

    def on_load_aes_key(self):
        """Loads an AES key from a file."""
        path = filedialog.askopenfilename(filetypes=[("Key files","*.key;*.txt"),("All files","*.*")])
        if not path:
            return
        with open(path, "r") as f:
            hexval = f.read().strip()
        try:
            key = hde.aes_hex_to_key(hexval)
        except Exception as e:
            messagebox.showerror("Invalid Key File", f"Failed to load key: {e}")
            return
        self.aes_key = key
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, hexval)
        self._log(f"Loaded AES key from: {path}")

    def on_generate_rsa_keys(self):
        """Generates a new RSA public/private keypair."""
        priv, pub = hde.rsa_generate_keypair()
        self.rsa_private, self.rsa_public = priv, pub
        self.rsa_status.config(text="RSA keys generated", foreground="green")
        self._log("Generated RSA 2048-bit keypair.")

    def on_save_rsa_pub(self):
        """Saves the public RSA key to a file."""
        if not self.rsa_public:
            messagebox.showwarning("No Key", "No RSA public key in memory.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pub.pem", filetypes=[("PEM","*.pem"),("All files","*.*")])
        if path:
            with open(path, "wb") as f:
                f.write(self.rsa_public)
            self._log(f"Saved RSA public key: {path}")

    def on_save_rsa_priv(self):
        """Saves the private RSA key to a file."""
        if not self.rsa_private:
            messagebox.showwarning("No Key", "No RSA private key in memory.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".priv.pem", filetypes=[("PEM","*.pem"),("All files","*.*")])
        if path:
            with open(path, "wb") as f:
                f.write(self.rsa_private)
            self._log(f"Saved RSA private key: {path}")

    def on_load_rsa_priv(self):
        """Loads a private RSA key from a file."""
        path = filedialog.askopenfilename(filetypes=[("PEM","*.pem;*.key"),("All files","*.*")])
        if not path:
            return
        with open(path, "rb") as f:
            data = f.read()
        try:
            _ = hde.RSA.import_key(data)  # validate
        except Exception as e:
            messagebox.showerror("Invalid Key File", f"Failed to load key: {e}")
            return
        self.rsa_private = data
        self.rsa_public = hde.RSA.import_key(data).publickey().export_key()
        self.rsa_status.config(text=f"Loaded RSA private: {os.path.basename(path)}", foreground="green")
        self._log(f"Loaded RSA private key from: {path}")

    # ---------- File Ops (calls backend functions) ----------
    def on_browse_input(self):
        """Opens a file dialog to select the input file."""
        p = filedialog.askopenfilename()
        if p:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, p)

    def on_browse_output(self):
        """Opens a file dialog to select the output file."""
        p = filedialog.asksaveasfilename()
        if p:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, p)

    def on_encrypt(self):
        """Initiates file encryption based on the selected algorithm."""
        try:
            algo = self.algo_var.get()
            in_path = self.input_entry.get().strip()
            out_path = self.output_entry.get().strip()
            if not in_path:
                messagebox.showwarning("Missing input", "Select an input file.")
                return
            if not out_path:
                out_path = in_path + (".enc" if algo == "AES" else ".rsa.enc")
                self.output_entry.delete(0, tk.END)
                self.output_entry.insert(0, out_path)

            if algo == "AES":
                hexk = self.key_entry.get().strip()
                if not hexk:
                    raise ValueError("AES key missing.")
                key = hde.aes_hex_to_key(hexk)
                hde.aes_encrypt_file(in_path, out_path, key)
                self._log(f"AES encrypted '{in_path}' -> '{out_path}'")
            else:
                if not self.rsa_public:
                    raise ValueError("RSA public key missing. Generate keys first.")
                hde.rsa_encrypt_file(in_path, out_path, self.rsa_public)
                self._log(f"RSA (hybrid) encrypted '{in_path}' -> '{out_path}'")
            messagebox.showinfo("Done", "Encryption completed.")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            self._log(f"Encryption error: {e}")

    def on_decrypt(self):
        """Initiates file decryption based on the selected algorithm."""
        try:
            algo = self.algo_var.get()
            in_path = self.input_entry.get().strip()
            out_path = self.output_entry.get().strip()
            if not in_path:
                messagebox.showwarning("Missing input", "Select the encrypted input file.")
                return
            if not out_path:
                base = in_path
                if base.endswith(".enc"):
                    base = base[:-4]
                elif base.endswith(".rsa.enc"):
                    base = base[:-8]
                out_path = base + ".dec"
                self.output_entry.delete(0, tk.END)
                self.output_entry.insert(0, out_path)

            if algo == "AES":
                hexk = self.key_entry.get().strip()
                if not hexk:
                    raise ValueError("AES key missing.")
                key = hde.aes_hex_to_key(hexk)
                hde.aes_decrypt_file(in_path, out_path, key) 
                self._log(f"AES decrypted '{in_path}' -> '{out_path}'")
            else:
                if not self.rsa_private:
                    raise ValueError("RSA private key missing. Load it first.")
                hde.rsa_decrypt_file(in_path, out_path, self.rsa_private)
                self._log(f"RSA (hybrid) decrypted '{in_path}' -> '{out_path}'")
            messagebox.showinfo("Done", "Decryption completed.")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            self._log(f"Decryption error: {e}")

    def on_clear(self):
        """Clears all input and output file paths and key fields."""
        self.input_entry.delete(0, tk.END)
        self.output_entry.delete(0, tk.END)
        if self.algo_var.get() == "AES":
            self.key_entry.delete(0, tk.END)
        self._log("Cleared fields.")

    # ---------- Utility ----------
    def _log(self, text: str):
        """Appends a message to the status text box."""
        self.status_text.configure(state="normal")
        self.status_text.insert(tk.END, text + "\n")
        self.status_text.see(tk.END)
        self.status_text.configure(state="disabled")

if __name__ == "__main__":
    app = HDEGui()
    app.mainloop()
