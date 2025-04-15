import hashlib
from getpass import getpass
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def gui():

    #Pobranie PIN-u od użytkownika
    #  pin = getpass("Podaj PIN:").encode()

    #Hashowanie PIN-u
    root = tk.Tk()
    root.geometry('500x500')
    root.title('RSA keys generator')

    private_key_path = tk.StringVar()
    public_key_path = tk.StringVar()

    def select_private_key_path():
        path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Files", "*.pem")])
        private_key_path.set(path)

    def select_public_key_path():
        path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Files", "*.pem")])
        public_key_path.set(path)

    def generate_keys():
        pin = pin_entry.get().encode()

        if not pin:
            messagebox.showerror("Error", "PIN cannot be empty")
            return
        if not private_key_path.get() or not public_key_path.get():
            messagebox.showerror("Error", "Path cannot be empty")
            return


        key = hashlib.sha256(pin).digest()

        # Generowanie kluczy
        try:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

            public_key = private_key.public_key()

            # Zapis klucza prywatnego
            with open("private_key.pem", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(key) #Algorytym szyfrowania AES.256
                ))

            # Zapis klucza publicznego
            with open("public_key.pem", "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            messagebox.showinfo("Success", "RSA key generation successful")
            return
        except Exception as e:
            messagebox.showerror("Error", f"An error occured: {str(e)}")


    tk.Label(root, text="PIN: ").pack()
    pin_entry = tk.Entry(root, show="*")
    pin_entry.pack(pady=5)

    tk.Label(root, text="Private key path: ").pack()
    tk.Entry(root, textvariable=private_key_path).pack()
    tk.Button(root, text="Pick path", command=select_private_key_path).pack(pady=5)
    tk.Label(root, text="Public key path: ").pack()
    tk.Entry(root, textvariable=public_key_path).pack()
    tk.Button(root, text="Pick path", command=select_public_key_path).pack(pady=5)

    tk.Button(root, text="Generate keys", command=generate_keys).pack(pady=20)

    root.mainloop()

gui()