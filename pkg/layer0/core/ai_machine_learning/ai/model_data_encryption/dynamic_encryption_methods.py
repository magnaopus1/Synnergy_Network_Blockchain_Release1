import numpy as np
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

class DynamicEncryptionMethods:
    def __init__(self):
        # Initialize encryption parameters
        self.symmetric_key = None
        self.public_key = None
        self.private_key = None
        
    def generate_symmetric_key(self, key_length=32):
        """
        Generate a symmetric encryption key.
        
        Args:
        - key_length: Length of the key in bytes (default is 32 bytes)
        
        Returns:
        - symmetric_key: Symmetric encryption key
        """
        symmetric_key = get_random_bytes(key_length)
        self.symmetric_key = symmetric_key
        return symmetric_key
    
    def generate_asymmetric_keys(self, key_length=2048):
        """
        Generate asymmetric encryption keys (public and private keys).
        
        Args:
        - key_length: Length of the key in bits (default is 2048 bits)
        
        Returns:
        - public_key: Public key
        - private_key: Private key
        """
        key = RSA.generate(key_length)
        self.public_key = key.publickey()
        self.private_key = key
        return self.public_key, self.private_key
    
    def encrypt_data_symmetric(self, data):
        """
        Encrypt data using symmetric encryption.
        
        Args:
        - data: Data to encrypt
        
        Returns:
        - encrypted_data: Encrypted data
        """
        if self.symmetric_key is None:
            raise ValueError("Symmetric key is not generated.")
        
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = cipher.iv
        return ct_bytes, iv
    
    def decrypt_data_symmetric(self, encrypted_data, iv):
        """
        Decrypt data using symmetric encryption.
        
        Args:
        - encrypted_data: Encrypted data
        - iv: Initialization vector
        
        Returns:
        - decrypted_data: Decrypted data
        """
        if self.symmetric_key is None:
            raise ValueError("Symmetric key is not generated.")
        
        cipher = AES.new(self.symmetric_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted_data
    
    def encrypt_data_asymmetric(self, data, public_key):
        """
        Encrypt data using asymmetric encryption.
        
        Args:
        - data: Data to encrypt
        - public_key: Public key
        
        Returns:
        - encrypted_data: Encrypted data
        """
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_data = cipher_rsa.encrypt(data)
        return encrypted_data
    
    def decrypt_data_asymmetric(self, encrypted_data, private_key):
        """
        Decrypt data using asymmetric encryption.
        
        Args:
        - encrypted_data: Encrypted data
        - private_key: Private key
        
        Returns:
        - decrypted_data: Decrypted data
        """
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_data = cipher_rsa.decrypt(encrypted_data)
        return decrypted_data

# Helper function for padding
def pad(data, block_size):
    padding_length = block_size - len(data) % block_size
    return data + bytes([padding_length] * padding_length)

# Helper function for unpadding
def unpad(data, block_size):
    padding_length = data[-1]
    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid padding length")
    return data[:-padding_length]

# Example usage:
if __name__ == "__main__":
    # Initialize DynamicEncryptionMethods
    encryption_methods = DynamicEncryptionMethods()
    
    # Generate symmetric key
    symmetric_key = encryption_methods.generate_symmetric_key()
    print("Symmetric Key:", symmetric_key.hex())
    
    # Generate asymmetric keys
    public_key, private_key = encryption_methods.generate_asymmetric_keys()
    print("Public Key:", public_key.export_key().decode())
    print("Private Key:", private_key.export_key().decode())
    
    # Encrypt data symmetrically
    data = b"Sensitive data"
    encrypted_data, iv = encryption_methods.encrypt_data_symmetric(data)
    print("Encrypted Data:", encrypted_data.hex())
    
    # Decrypt data symmetrically
    decrypted_data = encryption_methods.decrypt_data_symmetric(encrypted_data, iv)
    print("Decrypted Data:", decrypted_data.decode())
    
    # Encrypt data asymmetrically
    encrypted_data_asymmetric = encryption_methods.encrypt_data_asymmetric(data, public_key)
    print("Encrypted Data (Asymmetric):", encrypted_data_asymmetric.hex())
    
    # Decrypt data asymmetrically
    decrypted_data_asymmetric = encryption_methods.decrypt_data_asymmetric(encrypted_data_asymmetric, private_key)
    print("Decrypted Data (Asymmetric):", decrypted_data_asymmetric.decode())
