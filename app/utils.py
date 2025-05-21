import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_salt():
    """Generate a random salt for encryption"""
    return os.urandom(16)

def generate_iv():
    """Generate a random initialization vector"""
    return os.urandom(12)

def derive_key(password, salt):
    """Derive encryption key from password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_file(file_data, password):
    """Encrypt file data with password"""
    salt = generate_salt()
    iv = generate_iv()
    key = derive_key(password, salt)
    
    # Create encryptor
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()
    
    # Encrypt data
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    
    # Return encrypted data with the tag and parameters needed for decryption
    return {
        'ciphertext': ciphertext + encryptor.tag,
        'salt': salt,
        'iv': iv
    }

def decrypt_file(encrypted_data, password, salt, iv):
    """Decrypt file data with password, salt, and iv"""
    key = derive_key(password, salt)
    
    #plit ciphertext and tag
    ciphertext = encrypted_data[:-16]  # GCM tag is 16 bytes
    tag = encrypted_data[-16:]
    
    #create decryptor
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag)
    ).decryptor()
    
    #decrypt data
    return decryptor.update(ciphertext) + decryptor.finalize()

def hash_password(password, salt=None):
    """Create password hash for stored passwords"""
    if salt is None:
        salt = os.urandom(16)
    
    # Create password hash
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        100000,
    )
    
    # rturn hash and salt
    return base64.b64encode(key).decode(), salt

def verify_password(password, stored_hash, salt):
    """Verify a password against stored hash and salt"""
    password_hash, _ = hash_password(password, salt)
    return password_hash == stored_hash