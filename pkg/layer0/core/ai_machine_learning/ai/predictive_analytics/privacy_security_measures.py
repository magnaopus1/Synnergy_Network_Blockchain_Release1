import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class PrivacySecurityMeasures:
    def __init__(self):
        self.secret_key = get_random_bytes(32)  # Generate a random secret key
    
    def encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt data using AES encryption.
        """
        cipher = AES.new(self.secret_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, cipher.nonce, tag
    
    def decrypt_data(self, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
        """
        Decrypt ciphertext using AES decryption.
        """
        cipher = AES.new(self.secret_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    
    def hash_data(self, data: str) -> str:
        """
        Hash data using SHA-256 hashing algorithm.
        """
        hashed_data = hashlib.sha256(data.encode()).hexdigest()
        return hashed_data

# Example usage:
if __name__ == "__main__":
    # Initialize PrivacySecurityMeasures
    privacy_security = PrivacySecurityMeasures()
    
    # Example of encrypting data
    data_to_encrypt = b"Sensitive information"
    encrypted_data, nonce, tag = privacy_security.encrypt_data(data_to_encrypt)
    print("Encrypted data:", encrypted_data)
    print("Nonce:", nonce)
    print("Tag:", tag)
    
    # Example of decrypting data
    decrypted_data = privacy_security.decrypt_data(encrypted_data, nonce, tag)
    print("Decrypted data:", decrypted_data)
    
    # Example of hashing data
    data_to_hash = "Data to be hashed"
    hashed_data = privacy_security.hash_data(data_to_hash)
    print("Hashed data:", hashed_data)
