import hashlib
import tkinter as tk
import platform
from tkinter import filedialog, messagebox, ttk
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from pypdf import PdfReader, PdfWriter

def main_menu():
    root = tk.Tk()
    root.title("PDF App")
    root.geometry("300x200")

    tk.Label(root, text="What do you want to do", font=("Arial", 14)).pack(pady=20)

    tk.Button(root, text="Sign PDF", command=lambda: [root.destroy(), gui_sign()]).pack(pady=10)
    tk.Button(root, text="Verify PDF", command=lambda: [root.destroy(), verify_gui()]).pack(pady=10)

    root.mainloop()

def find_pem_files_on_external_drives():
    found = []
    system = platform.system()

    if system == "Windows":
        # Sprawdź litery od D: do Z: (bo A: i C: to zazwyczaj dyski wewnętrzne)
        for drive in map(chr, range(68, 91)):  # D-Z
            path = f"{drive}:/"
            if os.path.exists(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        if file.endswith(".pem"):
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
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pdf_data)
    pdf_hash = digest.finalize()

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
    return True


def verify_pdf(signed_pdf_path, public_key_path):

    reader = PdfReader(signed_pdf_path)
    writer = PdfWriter()

    # Pobieranie podpisu z pliku PDF
    signature_hex = reader.metadata.get("/Signature")
    signature = bytes.fromhex(signature_hex)

    # TODO Usuwanie podpisu z metadanych


    signed_pdf_hash = create_hash(signed_pdf_path)

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            signature,  # Podpis pobrany z dokumentu PDF
            signed_pdf_hash,  # Hash obliczony z dokumentu przez użytkownika B
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Podpis jest poprawny! Dokument nie został zmieniony.")
    except:
        print("Podpis niepoprawny! Dokument mógł zostać zmodyfikowany.")



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
