from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import os
import base64
import secrets
import string
import struct

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt(text, passwords):
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    keys = [derive_key(p, salt) for p in passwords]
    
    data = text.encode()
    for key in keys:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        data = encryptor.update(padded_data) + encryptor.finalize()
    
    random_prefix = os.urandom(secrets.randbelow(1000) + 1000)
    random_suffix = os.urandom(secrets.randbelow(1000) + 1000)
    prefix_length = len(random_prefix)
    suffix_length = len(random_suffix)
    
    length_info = struct.pack('II', prefix_length, suffix_length)
    combined_data = random_prefix + data + random_suffix
    encrypted_content = base64.b64encode(salt + iv + length_info + combined_data).decode('utf-8')
    
    return encrypted_content

def decrypt(encrypted_text, passwords):
    encrypted_data = base64.b64decode(encrypted_text)
    
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    length_info = encrypted_data[32:40]
    prefix_length, suffix_length = struct.unpack('II', length_info)
    combined_data = encrypted_data[40:]
    
    data = combined_data[prefix_length:-suffix_length]
    
    keys = [derive_key(p, salt) for p in passwords]
    
    for key in reversed(keys):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return data.decode('utf-8')

def read_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()

def write_file(file_path, content):
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(content)

def save_passwords(file_path, passwords):
    password_file_path = file_path.replace(".txt", "-passwords.txt")
    with open(password_file_path, 'w', encoding='utf-8') as file:
        for i, password in enumerate(passwords, 1):
            file.write(f"Password {i}: {password}\n")
    print(f"Passwords saved to: {password_file_path}")

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

if __name__ == "__main__":
    choice = input("Do you want to (d) decrypt or (e) encrypt? : ").strip().lower()
    file_path = input("Enter the path of the .txt file: ").strip()
    
    if choice == 'e':
        generate_pw = input("Do you want to generate passwords for you? (y/n): ").strip().lower()
        if generate_pw == 'y':
            passwords = [generate_password() for _ in range(3)]
            print("Generated passwords are:")
            for i, pw in enumerate(passwords, 1):
                print(f"Password {i}: {pw}")
        else:
            passwords = [input(f"Enter password {i+1}: ").strip() for i in range(3)]
        
        text = read_file(file_path)
        encrypted_text = encrypt(text, passwords)
        output_path = file_path + ".encrypted"
        write_file(output_path, encrypted_text)
        save_passwords(file_path, passwords)
        print(f"File encrypted and saved as: {output_path}")
    
    elif choice == 'd':
        passwords = [input(f"Enter password {i+1}: ").strip() for i in range(3)]
        encrypted_text = read_file(file_path)
        try:
            decrypted_text = decrypt(encrypted_text, passwords)
            output_path = file_path.replace(".encrypted", ".decrypted")
            write_file(output_path, decrypted_text)
            print(f"File decrypted and saved as: {output_path}")
        except (ValueError, base64.binascii.Error):
            print("Wrong passwords.")
    else:
        print("Invalid choice. Please enter 'd' to decrypt or 'e' to encrypt.")
