import hashlib
import tkinter as tk
import platform
from tkinter import filedialog, messagebox, ttk
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from pypdf import PdfReader, PdfWriter
import win32api, win32file


# Funkcja do tworzenia hasha zawartości PDF
def create_pdf_content_hash(pdf_path):
    reader = PdfReader(pdf_path)
    digest = hashes.Hash(hashes.SHA256())
    for page in reader.pages:
        # Get the raw bytes of the page object
        page_bytes = page.get_contents().get_data()
        digest.update(page_bytes)
    return digest.finalize()

# Funkcja do wyświetlenia głównego menu
def main_menu():
    root = tk.Tk()
    root.title("PDF App")
    root.geometry("300x200")

    tk.Label(root, text="What do you want to do", font=("Arial", 14)).pack(pady=20)

    tk.Button(root, text="Sign PDF", command=lambda: [root.destroy(), gui_sign()]).pack(pady=10)
    tk.Button(root, text="Verify PDF", command=lambda: [root.destroy(), verify_gui()]).pack(pady=10)
    tk.Button(root, text="Exit", command=root.quit).pack(pady=10)
    root.mainloop()

# Funkcja do znajdowania plików .pem w bieżącym folderze
def find_pem_files_in_current_folder():
    """Find all .pem files in the same folder as this script."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    pem_files = []
    for file in os.listdir(current_dir):
        if file.lower().endswith(".pem"):
            pem_files.append(os.path.join(current_dir, file))
    return pem_files

# Funkcja do znajdowania dysków wymiennych w systemie Windows
def get_removable_drives():
    drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
    removable_drives = []
    for drive in drives:
        drive_type = win32file.GetDriveType(drive)
        if drive_type == win32file.DRIVE_REMOVABLE:
            removable_drives.append(drive)
    return removable_drives

# Funkcja do znajdowania plików .pem na zewnętrznych dyskach
def find_pem_files_on_external_drives():
    found = []
    system = platform.system()
    try:
        drives = get_removable_drives()
        for drive in drives:
            if drive == "C:\\": # Pomijamy dysk C, bo przeglądamy tylko zewnętrzne dyski
                continue
            try:
                for root, _, files in os.walk(drive):
                    for file in files:
                        if file.lower().endswith(".pem"):
                            found.append(os.path.join(root, file))
            except Exception:
                messagebox.showerror(f"Nie można przeszukać dysku {drive}. Możliwe, że jest to dysk sieciowy lub nie jest dostępny.")
    except ImportError:
        messagebox.showerror("Błąd", "Biblioteka win32api nie jest zainstalowana. Zainstaluj ją za pomocą 'pip install pywin32'.")
        return []
    return found


# Funkcja do podpisywania PDF
def sign_pdf(pdf_path, private_key_path, output_path, key):
    # Wczytanie dokumentu PDF
    with open(pdf_path, "rb") as f:
        pdf_data = f.read()

    pdf_hash = create_pdf_content_hash(pdf_path)
    # Wczytanie klucza prywatnego
    with open(private_key_path, "rb") as f:

        try:
            private_key = serialization.load_pem_private_key(f.read(), password=key)
        except ValueError:
            messagebox.showerror("Błąd", "Niepoprawny PIN!")
            return False

    signature = private_key.sign(
        pdf_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Otwieramy PDF i dodajemy podpis
    reader = PdfReader(pdf_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    # Dodanie podpisu do metadanych PDF
    writer.add_metadata({"/Signature": signature.hex()})

    with open(output_path, "wb") as f:
        writer.write(f)

    messagebox.showinfo(f"Dokument '{pdf_path}' został podpisany i zapisany jako '{output_path}'.")

    return True

# Funkcja do weryfikacji podpisu PDF
def verify_pdf(signed_pdf_path, public_key_path):
    reader = PdfReader(signed_pdf_path)

    # Pobieranie podpisu z pliku PDF
    signature_hex = reader.metadata.get("/Signature")
    if not signature_hex:
        raise ValueError("Dokument PDF nie zawiera podpisu.")
    signature = bytes.fromhex(signature_hex)

    # Hash the page content of the signed PDF (ignore metadata)
    pdf_hash = create_pdf_content_hash(signed_pdf_path)

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    try:
        public_key.verify(
            signature,
            pdf_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        raise e

# GUI do weryfikacji podpisu PDF
def verify_gui():
    root = tk.Tk()
    root.title("PDF Verifier")
    root.geometry("500x250")

    signed_pdf_path = tk.StringVar()
    public_key_path = tk.StringVar()

    def exit_to_menu():
        root.destroy()
        main_menu()
    def select_pdf():
        signed_pdf_path.set(filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")]))

    def select_public_key():
        public_key_path.set(filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")]))

    def verify():
        try:
            verify_pdf(signed_pdf_path.get(), public_key_path.get())
            messagebox.showinfo("Sukces", "Podpis poprawny! Dokument nie został zmodyfikowany.")
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie udało się zweryfikować: {e}")

    tk.Label(root, text="Podpisany PDF:").pack()
    tk.Entry(root, textvariable=signed_pdf_path).pack()
    tk.Button(root, text="Wybierz PDF", command=select_pdf).pack()

    tk.Label(root, text="Klucz publiczny (.pem):").pack()
    tk.Entry(root, textvariable=public_key_path).pack()
    tk.Button(root, text="Wybierz Public Key", command=select_public_key).pack()

    tk.Button(root, text="Zweryfikuj", command=verify).pack(pady=20)
    tk.Button(root, text="Wyjdź", command=exit_to_menu).pack()

    root.mainloop()

# GUI do podpisywania PDF
def gui_sign():
    root = tk.Tk()
    root.title("PDF Signer")
    root.geometry("500x300")
    def exit_to_menu():
        root.destroy()
        main_menu()
    def select_pdf():
        pdf_path.set(filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")]))

    def select_key():
        key_path.set(filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")]))

    def select_output():
        output_path.set(filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")]))

    def sign():
        if not pdf_path.get():
            messagebox.showerror("Błąd", "Nie wybrano pliku PDF!")
            return
        if not output_path.get():
            messagebox.showerror("Błąd", "Nie wybrano ścieżki do zapisu!")
            return
        if not pin_entry.get():
            messagebox.showerror("Błąd", "PIN nie może być pusty!")
            return
        pin = hashlib.sha256(pin_entry.get().encode()).digest()
        try:
            if sign_pdf(pdf_path.get(), key_path.get(), output_path.get(), pin):
                messagebox.showinfo("Sukces", "Plik PDF został poprawnie podpisany.")
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie udało się podpisać: {e}")

    # Funkcja do odświeżania listy plików .pem z dysków zewnętrznych
    def refresh_pem_files():
        pem_files = find_pem_files_on_external_drives()
        if not pem_files:
            pem_files = ["(brak znalezionych .pem)"]
            messagebox.showwarning("Uwaga", "Nie znaleziono żadnych plików .pem na dyskach zewnętrznych.")
        key_dropdown['values'] = pem_files
        key_dropdown_var.set(pem_files[0])


    pdf_path = tk.StringVar()
    key_path = tk.StringVar()
    public_key_path = tk.StringVar()
    output_path = tk.StringVar()

    tk.Label(root, text="PDF File:").pack()
    tk.Entry(root, textvariable=pdf_path).pack()
    tk.Button(root, text="Select PDF", command=select_pdf).pack()

    #znajdowanie plików .pem na dysku zewnętrznym

    tk.Label(root, text="Private Key (.pem):").pack()

    def update_selected_key(event):
        key_path.set(key_dropdown_var.get())

    pem_files = find_pem_files_on_external_drives()
    if not pem_files:
        pem_files = ["(brak znalezionych .pem)"]

    pem_frame = tk.Frame(root)
    pem_frame.pack(pady=5)

    key_dropdown_var = tk.StringVar()
    key_dropdown = ttk.Combobox(pem_frame, textvariable=key_dropdown_var, values=pem_files, width=50)
    key_dropdown.bind("<<ComboboxSelected>>", update_selected_key)
    key_dropdown.pack(side="left", padx=5)

    tk.Button(pem_frame, text="Refresh", command=refresh_pem_files).pack(side="left", padx=5)


    # Initialize dropdown with empty or default value
    # refresh_pem_files()


    tk.Label(root, text="Output Path:").pack()
    tk.Entry(root, textvariable=output_path).pack()
    tk.Button(root, text="Select Output Path", command=select_output).pack()

    tk.Label(root, text="PIN:").pack()
    pin_entry = tk.Entry(root, show="*")
    pin_entry.pack()

    button_frame = tk.Frame(root)
    button_frame.pack(pady=20)

    tk.Button(button_frame, text="Sign PDF", command=sign).pack(side="left", padx=10)
    tk.Button(button_frame, text="Wyjdź", command=exit_to_menu).pack(side="left", padx=10)
    root.mainloop()


if __name__ == "__main__":
    main_menu()
