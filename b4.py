"""
    ΜΕΡΟΣ Β - 4.0 : Διάδοση μοτίβων (Propagation of patterns)
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
def generate_key(password):
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
    )
    
    key = kdf.derive(password)
    return key, salt



# κρυπτογράφηση αρχείων AES
def aes_encrypt(input_file, output_file, password, mode):
    key, salt = generate_key(password)
    iv = os.urandom(16) if mode not in [modes.ECB] else None

    with open(input_file, "rb") as f:
        header = f.read(54)         # Ανάγνωση της επικεφαλίδας BMP
        plaintext = f.read()        # Ανάγνωση των υπόλοιπων δεδομένων της εικόνας

    padder = PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    if iv:
        cipher = Cipher(algorithms.AES(key), mode(iv), backend=default_backend())

    else:
        cipher = Cipher(algorithms.AES(key), mode(), backend=default_backend())


    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    with open(output_file, "wb") as f:
        f.write(header)             # Εγγραφή BMP επκεφαλίδας
        f.write(salt)
        if iv:
            f.write(iv)
        f.write(ciphertext)

    return salt, iv



# Επαναφορά ΒΜΡ επικεφαλίδας
def restore_bmp_header(original_file, encrypted_file, restored_file):
    with open(original_file, 'rb') as f_orig, open(encrypted_file, 'rb') as f_enc, open(restored_file, 'wb') as f_rest:
        header = f_orig.read(54)            # Ανάγνωση της επικεφαλίδας BMP από το αρχικό αρχείο
        f_rest.write(header)                # Εγγραφή ΒΜΡ επικεφαλίδας στο νέο αρχείο (restored)
        f_rest.write(f_enc.read()[54:])     # Εγγραφή υπόλοιπου κρυπτογραφημένου περιεχομένου



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
    input_file = "security.bmp"
    # input_file = "security_1.bmp"
    # input_file = "security_2.bmp"

    output_ecb_file = "security-ecb.bmp"
    output_cbc_file = "security-cbc.bmp"
    output_ofb_file = "security-ofb.bmp"
    output_cfb_file = "security-cfb.bmp"
    output_ctr_file = "security-ctr.bmp"

    restored_ecb_file = "restored-ecb.bmp"
    restored_cbc_file = "restored-cbc.bmp"
    restored_ofb_file = "restored-ofb.bmp"
    restored_cfb_file = "restored-cfb.bmp"
    restored_ctr_file = "restored-ctr.bmp"

    password = input("Εισαγωγή κωδικού: ").encode()


    # Encrypt με ECB
    aes_encrypt(input_file, output_ecb_file, password, modes.ECB)
    restore_bmp_header(input_file, output_ecb_file, restored_ecb_file)

    # Encrypt με CBC
    aes_encrypt(input_file, output_cbc_file, password, modes.CBC)
    restore_bmp_header(input_file, output_cbc_file, restored_cbc_file)

    # Encrypt με OFB
    aes_encrypt(input_file, output_ofb_file, password, modes.OFB)
    restore_bmp_header(input_file, output_ofb_file, restored_ofb_file)

    # Encrypt με CFB
    aes_encrypt(input_file, output_cfb_file, password, modes.CFB)
    restore_bmp_header(input_file, output_cfb_file, restored_cfb_file)

    # Encrypt με CTR
    aes_encrypt(input_file, output_ctr_file, password, modes.CTR)
    restore_bmp_header(input_file, output_ctr_file, restored_ctr_file)


    # 1o Figure
    plt.figure(figsize=(20, 10))

    plt.subplot(2, 3, 1)
    plt.title("Αρχική Εικόνα")
    show_image(plt.gca(), "Αρχική Εικόνα", input_file)

    plt.subplot(2, 3, 2)
    plt.title("Κρυπτογραφημένη με ECB")
    show_image(plt.gca(), "Κρυπτογραφημένη με ECB", output_ecb_file)

    plt.subplot(2, 3, 3)
    plt.title("Restored με ECB")
    show_image(plt.gca(), "Restored με ECB", restored_ecb_file)

    plt.subplot(2, 3, 4)
    plt.title("Κρυπτογραφημένη με CBC")
    show_image(plt.gca(), "Κρυπτογραφημένη με CBC", output_cbc_file)

    plt.subplot(2, 3, 5)
    plt.title("Restored με CBC")
    show_image(plt.gca(), "Restored με CBC", restored_cbc_file)

    plt.tight_layout()
    plt.show()


    # 2o Figure
    plt.figure(figsize=(20, 10))

    plt.subplot(2, 3, 1)
    plt.title("Κρυπτογραφημένη με OFB")
    show_image(plt.gca(), "Κρυπτογραφημένη με OFB", output_ofb_file)

    plt.subplot(2, 3, 2)
    plt.title("Restored με OFB")
    show_image(plt.gca(), "Restored με OFB", restored_ofb_file)

    plt.subplot(2, 3, 3)
    plt.title("Κρυπτογραφημένη με CFB")
    show_image(plt.gca(), "Κρυπτογραφημένη με CFB", output_cfb_file)

    plt.subplot(2, 3, 4)
    plt.title("Restored με CFB")
    show_image(plt.gca(), "Restored με CFB", restored_cfb_file)

    plt.subplot(2, 3, 5)
    plt.title("Κρυπτογραφημένη με CTR")
    show_image(plt.gca(), "Κρυπτογραφημένη με CTR", output_ctr_file)

    plt.subplot(2, 3, 6)
    plt.title("Restored με CTR")
    show_image(plt.gca(), "Restored με CTR", restored_ctr_file)

    plt.tight_layout()
    plt.show()