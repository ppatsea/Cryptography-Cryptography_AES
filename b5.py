"""
     ΜΕΡΟΣ Β - 5.0 : Διάδοση σφαλμάτων(Error propagation) 
 """
import os
import matplotlib.pyplot as plt
import numpy as np

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from PIL import Image


# Δημιουργία κλειδιού από κωδικό πρόσβασης
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
    )

    key = kdf.derive(password)
    return key



# Aποκρυπτογράφηση AES
def aes_decrypt(output_file, decrypted_file, password, mode):
    with open(output_file, "rb") as f_in, open(decrypted_file, "wb") as f_out:
        header = f_in.read(54)          # Ανάγνωση ΒΜΡ επικεφαλίδας
        salt = f_in.read(16)
        f_out.write(header) 
        iv = None
        if mode not in [modes.ECB]:
            iv = f_in.read(16)
        ciphertext = f_in.read()

        key = generate_key(password, salt)

        cipher = Cipher(algorithms.AES(key), mode(iv) if iv else mode(), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = PKCS7(128).unpadder()
        try:
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        except ValueError as e:
            print(f"Invalid padding bytes: {e}")
            return

        f_out.write(plaintext)
    return decrypted_file



# Προβολή εικόνας από αρχείο
def show_image(ax, title, file_name):
    try:
        image = Image.open(file_name)
        ax.imshow(image)
        ax.set_title(title)
        ax.axis('off')
        
    except Exception as e:
        print(f"Σφάλμα προβολής εικόνας {file_name}: {e} !!")
        ax.set_title(f"Σφάλμα προβολής εικόνας: {title} !!")
        ax.axis('off')



if __name__ == "__main__":
    output_ecb_file = "security-ecb.bmp"
    output_cbc_file = "security-cbc.bmp"
    output_ofb_file = "security-ofb.bmp"
    output_cfb_file = "security-cfb.bmp"
    output_ctr_file = "security-ctr.bmp"

    decrypted_ecb_file = "decrypted-ecb.bmp"
    decrypted_cbc_file = "decrypted-cbc.bmp"
    decrypted_ofb_file = "decrypted-ofb.bmp"
    decrypted_cfb_file = "decrypted-cfb.bmp"
    decrypted_ctr_file = "decrypted-ctr.bmp"

    password = input("Εισαγωγή Κωδικού: ").encode()

    # Κλήση Αποκρυπτογράφησης
    aes_decrypt(output_ecb_file, decrypted_ecb_file, password, modes.ECB)
    aes_decrypt(output_cbc_file, decrypted_cbc_file, password, modes.CBC)
    aes_decrypt(output_ofb_file, decrypted_ofb_file, password, modes.OFB)
    aes_decrypt(output_cfb_file, decrypted_cfb_file, password, modes.CFB)
    aes_decrypt(output_ctr_file, decrypted_ctr_file, password, modes.CTR)

    plt.figure(figsize=(15, 3))

    plt.subplot(1, 5, 1)
    show_image(plt.gca(), "Αποκρυπτογράφηση με ECB", decrypted_ecb_file)

    plt.subplot(1, 5, 2)
    show_image(plt.gca(), "Αποκρυπτογράφηση με CBC", decrypted_cbc_file)

    plt.subplot(1, 5, 3)
    show_image(plt.gca(), "Αποκρυπτογράφηση με OFB", decrypted_ofb_file)

    plt.subplot(1, 5, 4)
    show_image(plt.gca(), "Αποκρυπτογράφηση με CFB", decrypted_cfb_file)

    plt.subplot(1, 5, 5)
    show_image(plt.gca(), "Αποκρυπτογράφηση με CTR", decrypted_ctr_file)

    plt.tight_layout()
    plt.show()