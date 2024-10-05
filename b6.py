"""
    ΜΕΡΟΣ Β - 6.0 :  Triple DES
"""
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# Δημιουργία κλειδιού από κωδικό πρόσβασης
def generate_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 24,  # 3 * 8 bytes for 3DES keys
        salt = salt,
        iterations = 100000,
        backend = default_backend())
    key = kdf.derive(password)
    return key, salt



# Αποθήκευση κλειδιού σε αρχείο
def save_key_to_file(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)



# Φόρτωση κλειδιού από αρχείο
def load_key_from_file(filename):
    with open(filename, 'rb') as file:
        key = file.read()
    return key



# Κρυπτογράφηση με Triple DES
def triple_des_encrypt(message, key1, key2, key3):
    # Πρώτη κρυπτογράφηση με το πρώτο κλειδί (K1)
    cipher1 = DES.new(key1, DES.MODE_ECB)
    padded_message = pad(message, DES.block_size)
    intermediate = cipher1.encrypt(padded_message)

    # Αποκρυπτογράφηση με το δεύτερο κλειδί (K2)
    cipher2 = DES.new(key2, DES.MODE_ECB)
    intermediate = cipher2.decrypt(intermediate)

    # Κρυπτογράφηση με το τρίτο κλειδί (K3)
    cipher3 = DES.new(key3, DES.MODE_ECB)
    ciphertext = cipher3.encrypt(intermediate)

    return ciphertext



# Αποκρυπτογράφηση με Triple DES
def triple_des_decrypt(ciphertext, key1, key2, key3):
    # Πρώτη αποκρυπτογράφηση με το τρίτο κλειδί (K3)
    cipher3 = DES.new(key3, DES.MODE_ECB)
    intermediate = cipher3.decrypt(ciphertext)

    # Κρυπτογράφηση με το δεύτερο κλειδί (K2)
    cipher2 = DES.new(key2, DES.MODE_ECB)
    intermediate = cipher2.encrypt(intermediate)

    # Αποκρυπτογράφηση με το πρώτο κλειδί (K1)
    cipher1 = DES.new(key1, DES.MODE_ECB)
    decrypted_message = cipher1.decrypt(intermediate)
    unpadded_message = unpad(decrypted_message, DES.block_size)

    return unpadded_message



if __name__ == "__main__":
    password = b"my_secret_password"
    key, salt = generate_key(password)

    # Χωρισμός του κλειδιού σε τρία κλειδιά των 8-byte
    key1 = key[:8]
    key2 = key[8:16]
    key3 = key[16:24]


    # Αποθήκευση των κλειδιών σε αρχεία
    save_key_to_file(key1, 'key1.txt')
    save_key_to_file(key2, 'key2.txt')
    save_key_to_file(key3, 'key3.txt')


    # Φόρτωση των κλειδιών από αρχεία
    loaded_key1 = load_key_from_file('key1.txt')
    loaded_key2 = load_key_from_file('key2.txt')
    loaded_key3 = load_key_from_file('key3.txt')


    message = b"Hello, this is a secret message !!"

    ciphertext = triple_des_encrypt(message, loaded_key1, loaded_key2, loaded_key3)
    print("Κρυπτογραφημένο Μήνυμα: ", ciphertext)

    decrypted_message = triple_des_decrypt(ciphertext, loaded_key1, loaded_key2, loaded_key3)
    print("Αποκρυπτογραφημένο Μήνυμα: ", decrypted_message.decode())