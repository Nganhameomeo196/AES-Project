"""Tkinter educational AES demo. Importing this module does not start a GUI."""
import os
from .aes_encrypt import aes_encrypt
from .aes_decrypt import aes_decrypt
from .modes import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt, ctr_crypt, gcm_encrypt, gcm_decrypt
from .trace import encrypt_trace, decrypt_trace


def main():
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox
    except ImportError as exc:
        raise SystemExit("Tkinter is not installed. Install python3-tk or use python -m src.cli") from exc
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise SystemExit("No graphical display available; use python -m src.cli") from exc
    root.title("AES Educational Laboratory")
    root.geometry("900x750")
    frame = ttk.Frame(root, padding=14)
    frame.pack(fill="both", expand=True)
    mode = tk.StringVar(value="Block")
    action = tk.StringVar(value="Encrypt")
    data_format = tk.StringVar(value="Hex")
    ttk.Label(frame, text="AES educational laboratory", font=("Arial", 17, "bold")).pack(anchor="w")
    ttk.Label(frame, text="Mode").pack(anchor="w")
    ttk.Combobox(frame, textvariable=mode, values=["Block", "ECB", "CBC", "CTR", "GCM"], state="readonly").pack(fill="x")
    ttk.Label(frame, text="Action").pack(anchor="w")
    ttk.Combobox(frame, textvariable=action, values=["Encrypt", "Decrypt"], state="readonly").pack(fill="x")
    ttk.Label(frame, text="Data (hex; select UTF-8 for ordinary text)").pack(anchor="w")
    ttk.Combobox(frame, textvariable=data_format, values=["Hex", "UTF-8"], state="readonly").pack(fill="x")
    data_entry = tk.Text(frame, height=3)
    data_entry.pack(fill="x")
    data_entry.insert("1.0", "00112233445566778899aabbccddeeff")
    ttk.Label(frame, text="AES key (hex: 32/48/64 digits)").pack(anchor="w")
    key_entry = ttk.Entry(frame)
    key_entry.pack(fill="x")
    key_entry.insert(0, bytes(range(16)).hex())
    ttk.Label(frame, text="IV / initial counter / nonce (hex). GCM encrypt generates fresh nonce automatically.").pack(anchor="w")
    iv_entry = ttk.Entry(frame)
    iv_entry.pack(fill="x")
    ttk.Label(frame, text="GCM AAD (hex)").pack(anchor="w")
    aad_entry = ttk.Entry(frame)
    aad_entry.pack(fill="x")
    ttk.Label(frame, text="GCM tag (hex, 16 bytes)").pack(anchor="w")
    tag_entry = ttk.Entry(frame)
    tag_entry.pack(fill="x")
    ttk.Label(frame, text="Result / round trace").pack(anchor="w")
    output = tk.Text(frame, height=14, wrap="none")
    output.pack(fill="both", expand=True)

    def show(text):
        output.delete("1.0", "end")
        output.insert("1.0", text)

    def execute(trace=False):
        try:
            key = bytes.fromhex(key_entry.get().strip())
            if len(key) not in (16, 24, 32):
                raise ValueError("Key must be 16/24/32 bytes")
            raw_data = data_entry.get("1.0", "end-1c")
            data = bytes.fromhex(raw_data.strip()) if data_format.get() == "Hex" else raw_data.encode("utf-8")
            name = mode.get()
            encrypt = action.get() == "Encrypt"
            if trace:
                if name != "Block":
                    raise ValueError("Round trace is available in Block mode")
                events = encrypt_trace(data, key) if encrypt else decrypt_trace(data, key)
                show("\n".join(f"Round {e['round']:2} | {e['step']:<15} | {e['state']}" for e in events))
                return
            if name == "Block":
                result = aes_encrypt(data, key) if encrypt else aes_decrypt(data, key)
            elif name == "ECB":
                result = ecb_encrypt(data, key) if encrypt else ecb_decrypt(data, key)
            elif name == "CBC":
                if encrypt and len(iv_entry.get().strip()) != 32:
                    iv_entry.delete(0, "end")
                    iv_entry.insert(0, os.urandom(16).hex())
                iv = bytes.fromhex(iv_entry.get().strip())
                result = cbc_encrypt(data, key, iv) if encrypt else cbc_decrypt(data, key, iv)
            elif name == "CTR":
                if encrypt and len(iv_entry.get().strip()) != 32:
                    iv_entry.delete(0, "end")
                    iv_entry.insert(0, os.urandom(16).hex())
                result = ctr_crypt(data, key, bytes.fromhex(iv_entry.get().strip()))
            else:
                aad = bytes.fromhex(aad_entry.get().strip())
                if encrypt:
                    nonce = os.urandom(12)
                    iv_entry.delete(0, "end")
                    iv_entry.insert(0, nonce.hex())
                    result, tag = gcm_encrypt(data, key, nonce, aad)
                    tag_entry.delete(0, "end")
                    tag_entry.insert(0, tag.hex())
                else:
                    result = gcm_decrypt(data, key, bytes.fromhex(iv_entry.get().strip()), bytes.fromhex(tag_entry.get().strip()), aad)
            show(result.hex() if encrypt or data_format.get() == "Hex" else result.decode("utf-8", errors="replace"))
        except (ValueError, TypeError) as exc:
            messagebox.showerror("Invalid input", str(exc))

    buttons = ttk.Frame(frame)
    buttons.pack(fill="x", pady=8)
    ttk.Button(buttons, text="Run", command=execute).pack(side="left", padx=5)
    ttk.Button(buttons, text="Trace AES rounds", command=lambda: execute(trace=True)).pack(side="left", padx=5)
    ttk.Label(frame, text="Teaching implementation only. Do not use to secure real data.").pack(anchor="w")
    root.mainloop()


if __name__ == "__main__":
    main()
