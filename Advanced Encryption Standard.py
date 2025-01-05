from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def generate_key():
    return get_random_bytes(32)

def encrypt_message(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # Initialization Vector
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_message(key, encrypted_message):
    data = base64.b64decode(encrypted_message)
    iv = data[:16]  # Extract IV from the start
    ciphertext = data[16:]  # Extract ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

def main():
    print("=== AES Encryption and Decryption ===")
    
    key = generate_key()
    print(f"Generated Key (Base64): {base64.b64encode(key).decode()}")
    
    plaintext = input("Enter a message to encrypt: ")
    encrypted_message = encrypt_message(key, plaintext)
    print(f"Encrypted Message: {encrypted_message}")
    
    decrypted_message = decrypt_message(key, encrypted_message)
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()
