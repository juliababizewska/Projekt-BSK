import hashlib
import tkinter as tk
import platform
from tkinter import filedialog, messagebox, ttk
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from pypdf import PdfReader, PdfWriter
import tempfile

def create_pdf_content_hash(pdf_path):
    reader = PdfReader(pdf_path)
    digest = hashes.Hash(hashes.SHA256())
    for page in reader.pages:
        # Get the raw bytes of the page object
        page_bytes = page.get_contents().get_data()
        digest.update(page_bytes)
    return digest.finalize()


def main_menu():
    root = tk.Tk()
    root.title("PDF App")
    root.geometry("300x200")

    tk.Label(root, text="What do you want to do", font=("Arial", 14)).pack(pady=20)

    tk.Button(root, text="Sign PDF", command=lambda: [root.destroy(), gui_sign()]).pack(pady=10)
    tk.Button(root, text="Verify PDF", command=lambda: [root.destroy(), verify_gui()]).pack(pady=10)

    root.mainloop()

def find_pem_files_in_current_folder():
    """Find all .pem files in the same folder as this script."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    pem_files = []
    for file in os.listdir(current_dir):
        if file.lower().endswith(".pem"):
            pem_files.append(os.path.join(current_dir, file))
    return pem_files

def find_pem_files_on_external_drives():
    found = []
    system = platform.system()

    if system == "Windows":
        try:
            import win32api
            drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
        except ImportError:
            messagebox.showerror("Błąd", "Biblioteka win32api nie jest zainstalowana. Zainstaluj ją za pomocą 'pip install pywin32'.")
            return []
    else:
        mount_points = ["/media", "/mnt"]
        for mount_point in mount_points:
            if os.path.exists(mount_point):
                for root, _, files in os.walk(mount_point):
                    for file in files:
                        if file.lower().endswith(".pem"):
                            found.append(os.path.join(root, file))
    return found

def create_hash(pdf_path):
    # Wczytanie dokumentu PDF
    with open(pdf_path, "rb") as f:
        pdf_data = f.read()

    # Hashowanie dokumentu
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pdf_data)
    pdf_hash = digest.finalize()

    return pdf_hash

def sign_pdf(pdf_path, private_key_path, output_path, key):
    # Wczytanie dokumentu PDF
    with open(pdf_path, "rb") as f:
        pdf_data = f.read()

    # Hashowanie dokumentu
    # digest = hashes.Hash(hashes.SHA256())
    # digest.update(pdf_data)
    # pdf_hash = digest.finalize()
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

    print(f"Dokument '{pdf_path}' został podpisany i zapisany jako '{output_path}'.")
    print("HASH (sign):", pdf_hash.hex())
    print("SIGNATURE (sign):", signature.hex())
    return True


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
    print("HASH (verify):", pdf_hash.hex())
    print("SIGNATURE (verify):", signature.hex())
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
        print("Podpis jest poprawny! Dokument nie został zmieniony.")
    except Exception as e:
        print("Podpis niepoprawny! Dokument mógł zostać zmodyfikowany.")
        raise e


# Test: podpisujemy dokument

    # Test: podpisujemy dokument


    # pin = getpass("Podaj PIN").encode()
    #
    # key = hashlib.sha256(pin).digest()
    #
    # sign_pdf("Test PDF.pdf", "private_key.pem", "signed_document.pdf", key)
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
        pin = hashlib.sha256(pin_entry.get().encode()).digest()

        # Nowe okno z wynikiem podpisywania

        try:
            if sign_pdf(pdf_path.get(), key_path.get(), output_path.get(), pin):
                # msg = f"Dokument '{pdf_path.get()}' został podpisany."
                # result_window = tk.Toplevel(root)
                # result_window.title("Wynik podpisu")
                # result_window.geometry("500x100")
                #
                messagebox.showinfo("Succes", "The PDF file has been signed succesfully")

                # tk.Button(result_window, text="Zamknij", command=result_window.destroy).pack(pady=5)
                # tk.Label(result_window, text=msg, fg="green").pack(pady=20)
        except Exception as e:
            msg = f"Błąd: {e}"

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

    key_dropdown_var = tk.StringVar()
    key_dropdown = ttk.Combobox(root, textvariable=key_dropdown_var, values=pem_files, width=50)
    key_dropdown.bind("<<ComboboxSelected>>", update_selected_key)
    key_dropdown.pack(pady=5)


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
