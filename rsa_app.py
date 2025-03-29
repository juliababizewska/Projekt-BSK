import hashlib
from getpass import getpass

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


#Pobranie PIN-u od użytkownika
pin = getpass("Podaj PIN:").encode()

#Hashowanie PIN-u
key = hashlib.sha256(pin).digest()

# Generowanie kluczy
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

print("Klucze zostały wygenerowanie i zapisane.")