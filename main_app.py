import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from pypdf import PdfReader, PdfWriter

from getpass import getpass


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

    # Wczytanie klucza prywatnego
    with open(private_key_path, "rb") as f:

        try:
            private_key = serialization.load_pem_private_key(f.read(), password=key)
        except:
            print("Podano nieprawidłowy PIN")
            return

    pdf_hash = create_hash(pdf_path)

    # Podpisanie dokumentu (RSA-4096)
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

pin = getpass("Podaj PIN").encode()

key = hashlib.sha256(pin).digest()

sign_pdf("Test PDF.pdf", "private_key.pem", "signed_document.pdf", key)
#verify_pdf("signed_document.pdf", "public_key.pem")