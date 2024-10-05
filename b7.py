"""
    ΜΕΡΟΣ Β - 7.0 : Απόδοση κρυπτογράφησης(Cipher performance) 	
"""
import time
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import Blowfish, ARC4
from Crypto.Cipher import DES, DES3


# Δημιουργία τυχαίου κλειδιού 
def generate_key(algorithm):
    key_size = algorithm.key_size // 8
    return os.urandom(key_size)



# Εκτέλεση μέτρησης επιδόσεων
def benchmark(algorithm, block_size, iterations):
    backend = default_backend()
    key = b"0123456789ABCDEF"  
    text = b"A" * block_size  # Μέγεθος Μπλοκ

    # Δημιουργία του αλγορίθμου κρυπτογράφησης
    cipher_algorithm = algorithm(key)
    cipher = Cipher(cipher_algorithm, modes.ECB(), backend=backend)

    # Μέτρηση του χρόνου για iterations
    start_time = time.time()
    for _ in range(iterations):
        encryptor = cipher.encryptor()
        encryptor.update(text)
    end_time = time.time()

    return end_time - start_time



# Εκτύπωση Αποτελεσμάτων
def print_results(algorithm, block_size, time_taken):
    print("Αλγόριθμος: ", algorithm.name)
    print("Μέγεθος Block: ", block_size, "bytes")
    print("Απαιτούμενος Χρόνος: ", round(time_taken, 3), "sec\n")
    print("\n")


algorithms = [
    algorithms.Blowfish,
    algorithms.AES,
    algorithms.TripleDES,
    # algorithms.RC2,
    # algorithms.RC4,
    # algorithms.ARC4,
]

# block_sizes = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192]
# iterations = 10000000

block_sizes = [16, 32]
iterations = 1000000



for algorithm in algorithms:
    print("Συγκριτική αξιολόγηση (Benchmarking)", algorithm.name + ":")
    
    for block_size in block_sizes:
        time_taken = benchmark(algorithm, block_size, iterations)
        print_results(algorithm, block_size, time_taken)