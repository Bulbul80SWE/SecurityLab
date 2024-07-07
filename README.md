# SecurityLab

Lab Report: Implementing Symmetric and Asymmetric Cryptography in Python

Introduction
In this lab, we implemented and studied the operations of symmetric (AES) and asymmetric (RSA) cryptographic techniques, including encryption, decryption, and digital signatures, using the PyCryptodome library in Python. We also implemented SHA-256 hashing and measured the execution times of these cryptographic operations.

Objectives
- Implement AES encryption and decryption with two key lengths (128 and 256 bits) and two modes (ECB and CFB).
- Implement RSA encryption and decryption.
- Implement RSA signature creation and verification.
- Implement SHA-256 hashing.
- Measure and analyze the execution times of these cryptographic operations.

Implementation Details

AES Encryption and Decryption
AES (Advanced Encryption Standard) is a symmetric key encryption algorithm. We used 128-bit and 256-bit key lengths and implemented ECB (Electronic Codebook) mode for encryption and decryption.

Key Generation
from Crypto.Random import get_random_bytes

def create_aes_key(bits):
    aes_key = get_random_bytes(bits // 8)
    with open(f'aes_key_{bits}.bin', 'wb') as key_file:
        key_file.write(aes_key)
    return aes_key

AES Encryption and Decryption Functions
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(data, key, mode):
    aes_cipher = AES.new(key, mode)
    encrypted_data = aes_cipher.encrypt(pad(data, AES.block_size))
    return encrypted_data

def aes_decrypt(encrypted_data, key, mode):
    aes_cipher = AES.new(key, mode)
    decrypted_data = unpad(aes_cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

RSA Encryption, Decryption, and Signature
RSA (Rivest-Shamir-Adleman) is an asymmetric cryptographic algorithm. We generated RSA keys of size 2048 bits for encryption/decryption and digital signatures.


Key Generation
from Crypto.PublicKey import RSA

def create_rsa_keys(bits):
    rsa_key = RSA.generate(bits)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()
    with open(f'rsa_private_key_{bits}.pem', 'wb') as prv_file:
        prv_file.write(private_key)
    with open(f'rsa_public_key_{bits}.pem', 'wb') as pub_file:
        pub_file.write(public_key)
    return private_key, public_key

RSA Encryption and Decryption Functions
from Crypto.Cipher import PKCS1_OAEP

def rsa_encrypt(data, pub_key):
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(pub_key))
    encrypted_data = rsa_cipher.encrypt(data)
    return encrypted_data

def rsa_decrypt(encrypted_data, priv_key):
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(priv_key))
    decrypted_data = rsa_cipher.decrypt(encrypted_data)
    return decrypted_data

RSA Signature Creation and Verification
We implemented functions to create and verify RSA signatures.

RSA Signature Functions
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def rsa_sign(data, priv_key):
    rsa_key = RSA.import_key(priv_key)
    hash_data = SHA256.new(data)
    signature = pkcs1_15.new(rsa_key).sign(hash_data)
    return signature

def rsa_verify(data, signature, pub_key):
    rsa_key = RSA.import_key(pub_key)
    hash_data = SHA256.new(data)
    try:
        pkcs1_15.new(rsa_key).verify(hash_data, signature)
        return True
    except (ValueError, TypeError):
        return False


SHA-256 Hashing
SHA-256 is a cryptographic hash function that produces a 256-bit hash value.

SHA-256 Hashing Function
def sha256_hash(data):
    hash_obj = SHA256.new()
    hash_obj.update(data)
    return hash_obj.hexdigest()

Measuring Execution Time
We measured the execution time of the cryptographic operations using the `time` module.

Measuring Execution Time
import time

def measure_exec_time(func, *args):
    start = time.time()
    result = func(*args)
    end = time.time()
    exec_time = end - start
    return exec_time, result

Results and Analysis

AES Execution Time Measurement
We measured the execution time of AES encryption for different key sizes.

AES Execution Time Measurement Code
import matplotlib.pyplot as plt

data = b"Sample encryption data" * 10
aes_key_sizes = [16, 24, 32]
exec_times = []

for key_size in aes_key_sizes:
    aes_key = create_aes_key(key_size * 8)
    exec_time, _ = measure_exec_time(aes_encrypt, data, aes_key, AES.MODE_ECB)
    exec_times.append(exec_time)

plt.plot([size * 8 for size in aes_key_sizes], exec_times)
plt.xlabel('Key Size (bits)')
plt.ylabel('Execution Time (seconds)')
plt.title('AES Encryption Execution Time vs Key Size')
plt.show()

RSA Execution Time Measurement
We measured the execution time of RSA encryption, decryption, and signature operations for different key sizes.
 
Figure 1: AES Encryption Time vs Key Size

 

Figure 2: User Interface for Cryptographic Operations

 
Figure 3: User Interface for Cryptographic Operations

RSA Execution Time Measurement Code
rsa_key_sizes = [512, 1024, 2048, 3072, 4096]
rsa_enc_times = []
rsa_dec_times = []
rsa_sign_times = []
rsa_verify_times = []

for key_size in rsa_key_sizes:
    private_key, public_key = create_rsa_keys(key_size)
    Encryption
    exec_time, _ = measure_exec_time(rsa_encrypt, data, public_key)
    rsa_enc_times.append(exec_time)
    Decryption
    encrypted_data, _ = rsa_encrypt(data, public_key)
    exec_time, _ = measure_exec_time(rsa_decrypt, encrypted_data, private_key)
    rsa_dec_times.append(exec_time)
    Signing
    exec_time, _ = measure_exec_time(rsa_sign, data, private_key)
    rsa_sign_times.append(exec_time)
    Verification
    signature, _ = rsa_sign(data, private_key)
    exec_time, _ = measure_exec_time(rsa_verify, data, signature, public_key)
    rsa_verify_times.append(exec_time)

plt.plot(rsa_key_sizes, rsa_enc_times, label='Encryption')
plt.plot(rsa_key_sizes, rsa_dec_times, label='Decryption')
plt.plot(rsa_key_sizes, rsa_sign_times, label='Signing')
plt.plot(rsa_key_sizes, rsa_verify_times, label='Verification')
plt.xlabel('Key Size (bits)')
plt.ylabel('Execution Time (seconds)')
plt.title('RSA Operations Execution Time vs Key Size')
plt.legend()
plt.show()

Observations
AES Encryption: The execution time for AES encryption increases with the key size. This is expected as larger keys require more computational effort.
RSA Operations: The execution times for RSA encryption, decryption, signing, and verification increase significantly with key size. This reflects the higher computational complexity associated with larger RSA keys.

Conclusion
In this lab, we successfully implemented and analyzed the performance of symmetric (AES) and asymmetric (RSA) cryptographic operations. We observed that both AES and RSA have increased execution times with larger key sizes, highlighting the trade-off between security and performance. This exercise provided practical insights into the workings of modern cryptographic algorithms and their performance characteristics.

References
AES Encryption: https://book.jorianwoltjer.com/cryptography/aes
RSA Encryption: https://medium.com/coinmonks/rsa-encryption-and-decryption-with-pythons-pycryptodome-library-94f28a6a1816
Python Cyber Security Exercises: https://www.w3resource.com/python-exercises/cybersecurity/ 

