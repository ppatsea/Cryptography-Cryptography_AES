"""
    ΜEΡΟΣ Α : Κρυπτογράφηση χρησιμοποιώντας τον AES αλγόριθμο

    ΜΕΡΟΣ Β - 1.0 : Αποκρυπτογράφηση ενός αρχείου με χρήση AES

    ΜΕΡΟΣ Β - 2.0 : Κρυπτογράφηση & αποκρυπτογράφηση ενός αρχείου χρησιμοποιώντας ένα δεδομένο αλγόριθμο	
"""
import os
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


# Δημιουργία κλειδιού
def generate_key(password_bytes, salt, key_length=16, iterations=1000):
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA1(),
        length = key_length,
        salt = salt,
        iterations = iterations,
        backend = default_backend()
    )
    key = kdf.derive(password_bytes)
    return key, salt



# Δημιουργία αρχείου κλειδιού
def generate_key_file(password, filename, key_length=16):
    salt = os.urandom(16)
    key, salt = generate_key(password.encode(), salt, key_length=key_length)
    key_b64 = base64.b64encode(key).decode('utf-8')
    salt_b64 = base64.b64encode(salt).decode('utf-8')

    with open(filename, 'wb') as f:
        f.write(key_b64.encode())
        f.write(b'\n')
        f.write(salt_b64.encode())



# Κρυπτογράφηση αρχείου με padding PKCS7
def encrypt_file_padding(key_file, input_file, output_file, algorithm, key_length, use_padding):
    if not os.path.exists(input_file):
        print("Σφάλμα: Το αρχείο προς κρυπτογράφηση δεν υπάρχει !!")
        return


    with open(key_file, 'rb') as f:
        key_b64 = f.readline().decode('utf-8')
        salt_b64 = f.readline().decode('utf-8')

    key = base64.b64decode(key_b64)
    salt = base64.b64decode(salt_b64)


    with open(input_file, 'rb') as fin, open(output_file, 'wb') as fout:
        iv = os.urandom(algorithm.block_size // 8)
        cipher = Cipher(algorithm(key[:key_length]), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()

        if use_padding:
            padder = padding.PKCS7(algorithm.block_size).padder()

        fout.write(iv)


        while True:
            chunk = fin.read(1024)
            if not chunk:
                break

            if use_padding:
                padded_chunk = padder.update(chunk) + padder.finalize()
            else:
                padded_chunk = chunk


            # Προσθέστε έλεγχο για το μήκος του chunk
            if len(padded_chunk) % (algorithm.block_size // 8) != 0:
                # Αν το μήκος δεν είναι πολλαπλάσιο του μεγέθους block, προσθέστε padding
                padded_chunk += b'\x00' * ((algorithm.block_size // 8) - len(padded_chunk) % (algorithm.block_size // 8))

            ciphertext = encryptor.update(padded_chunk) + encryptor.finalize()
            fout.write(ciphertext)



# Αποκρυπτογράφηση αρχείου με padding PKCS7
def decrypt_file_padding(key_file, input_file, output_file, algorithm, key_length):
    if not os.path.exists(input_file):
        print("Σφάλμα: Το αρχείο προς αποκρυπτογράφηση δεν υπάρχει !!")
        return

    with open(key_file, 'rb') as f:
        key_b64 = f.readline().decode('utf-8')
        salt_b64 = f.readline().decode('utf-8')
    key = base64.b64decode(key_b64)
    salt = base64.b64decode(salt_b64)

    with open(input_file, 'rb') as fin, open(output_file, 'wb') as fout:
        iv = fin.read(algorithm.block_size // 8)
        cipher = Cipher(algorithm(key[:key_length]), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = b""
        while True:
            ciphertext = fin.read(1024)

            if not ciphertext:
                break

            decrypted_chunk = decryptor.update(ciphertext)
            decrypted_data += decrypted_chunk

        try:
            unpadder = padding.PKCS7(algorithm.block_size).unpadder()
            decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()
        except ValueError:
            # Padding error, remove it and continue
            pass

        fout.write(decrypted_data)



if __name__ == "__main__":
    key_file = input("Εισαγωγή ονόματος βασικού αρχείου: ")         # key
    input_file = input("Εισαγωγή ονόματος αρχείου εισόδου: ")       # input
    output_file = input("Εισαγωγή ονόματος αρχείου εξόδου: ")       # output
    
    choice = input("Θέλετε να κρυπτογραφήσετε ή να αποκρυπτογραφήσετε το αρχείο; (encrypt ή decrypt): ").lower()
    padding_choice = input("Χρήση PKCS7 padding; (Yes ή No): ").lower()
    algorithm_choice = input("Επιλέξτε αλγόριθμο υλοποίησης (AES ή 3DES): ").lower()

    use_padding = padding_choice == "yes"

    if algorithm_choice == "aes":
        algorithm = algorithms.AES
        key_length = 32

    elif algorithm_choice == "3des":
        algorithm = algorithms.TripleDES
        key_length = 24

    else:
        print("Σφάλμα: Άγνωστος αλγόριθμος !!")
        exit(1)


    if choice == "encrypt":
        encrypt_file_padding(key_file, input_file, output_file, algorithm, key_length, use_padding)
        print("Η κρυπτογράφηση ολοκληρώθηκε !!")

    elif choice == "decrypt":
        decrypt_file_padding(key_file, input_file, output_file, algorithm, key_length)
        print("Η αποκρυπτογράφηση ολοκληρώθηκε !!")

    else:
        print("Σφάλμα: Άγνωστη επιλογή !!")