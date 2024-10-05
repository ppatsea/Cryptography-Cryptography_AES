"""
    ΜΕΡΟΣ Β - 3.0 : Λειτουργίες	κρυπτογράφησης	
"""
import os
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


# Δημιουργία κλειδιού από κωδικό πρόσβασης
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

            # Έλεγχος για το μήκος του chunk
            if len(padded_chunk) % (algorithm.block_size // 8) != 0:
                # Αν το μήκος δεν είναι πολλαπλάσιο του μεγέθους block, προσθήκη padding
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
            # Σφάλμα padding, αφαίρεση για συνέχεια
            pass

        fout.write(decrypted_data)



def create_final_file(final_file, algorithm_choice, mode_choice, iv):
    with open(final_file, 'w') as f:
        f.write(f"{algorithm_choice}\n")
        f.write(f"{mode_choice}\n")
        f.write(f"{iv.hex()}\n")  



if __name__ == "__main__":
    
    key_file = input("Εισαγωγή ονόματος βασικού αρχείου: ")         # key
    input_file = input("Εισαγωγή ονόματος αρχείου εισόδου: ")       # input
    output_file = input("Εισαγωγή ονόματος αρχείου εξόδου: ")       # output
    

    # Επιλογή αλγορίθμου
    algorithm_choice = input("Επιλογή 'AES' ή '3DES': ").strip().upper()
    if algorithm_choice not in ["AES", "3DES"]:
        print("Μη έγκυρος αλγόριθμος !!")
        exit(1)
    

    # Ορισμός αλγορίθμου κρυπτογράφησης
    if algorithm_choice == "AES":
        algorithm = algorithms.AES
        key_length = 32         # Μήκος κλειδιού : 256 bits
        iv_length = 16          # Μήκος IV για AES: 16 bytes


    elif algorithm_choice == "3DES":
        algorithm = algorithms.TripleDES
        key_length = 24         # Μήκος κλειδιού : 192 bits
        iv_length = 8           # Μήκος IV για 3DES: 8 bytes
 

    # Επιλογή λειτουργίας κρυπτογράφησης
    mode_choice = input("Επιλογή λειτουργίας κρυπτογράφησης : CBC, OFB, CFB ή CTR ;; ").strip().upper()
    if mode_choice not in ["CBC", "OFB", "CFB", "CTR"]:
        print("Μη έγκυρη λειτουργία !!")
        exit(1)
   

    # Δημιουργία τυχαίου IV
    iv = os.urandom(iv_length)
   
    # Δημιουργία κλειδιού και αρχείου κλειδιού
    password = input("Εισαγωγή κωδικού πρόσβασης για τη δημιουργία κλειδιών: ").strip()
    generate_key_file(password, key_file, key_length)
   

    # Δημιουργία αρχείου που περιέχει τις ζητούμενες πληροφορίες
    create_final_file('information', algorithm_choice, mode_choice, iv)
   
 
    # Κρυπτογράφηση αρχείου με ή χωρίς Padding
    choice = input("Θέλετε να κρυπτογραφήσετε με padding? (Yes ή No): ").strip().lower()
    use_padding = True if choice == 'yes' else False

    encrypt_file_padding(key_file, input_file, output_file, algorithm, key_length, use_padding)
 

    # Αποκρυπτογράφηση του κρυπτογραφημένου αρχείου
    decrypt_file_padding(key_file, input_file, output_file, algorithm, key_length)