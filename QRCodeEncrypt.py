import qrcode
import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import os

class SecureQRCodeGenerator:
    def __init__(self):
        """
        Initializes the SecureQRCodeGenerator with a randomly generated secret key.
        """
        self.secret_key = self.generate_secret_key()
        print(f"Generated Secret Key: {self.secret_key}")  # Display the key (remove in production)

    def generate_secret_key(self) -> str:
        """
        Generates a secure random 256-bit secret key.
        :return: A 64-character hexadecimal string.
        """
        return secrets.token_hex(32)  # Generates a 256-bit key

    def generate_signature(self, data: str) -> str:
        """
        Generates an HMAC-SHA256 signature for the given data.
        :param data: The data to be signed.
        :return: Hexadecimal representation of the signature.
        """
        return hmac.new(self.secret_key.encode(), data.encode(), hashlib.sha256).hexdigest()

    def encrypt_data(self, data: str) -> str:
        """
        Encrypts the data using AES encryption.
        :param data: The data to be encrypted.
        :return: Base64 encoded encrypted data.
        """
        # Ensure key is 32 bytes for AES-256
        key = self.secret_key.encode().ljust(32, b'\0')[:32]
        
        # Generate a random IV (Initialization Vector)
        iv = os.urandom(16)
        
        # Pad the data to be a multiple of the block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        
        # Create AES cipher with CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt the data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + Encrypted data, both encoded in base64
        iv_encoded = base64.b64encode(iv).decode('utf-8')
        encrypted_data_encoded = base64.b64encode(encrypted_data).decode('utf-8')
        
        return f"{iv_encoded}:{encrypted_data_encoded}"

    def create_secure_qr(self, data: str):
        """
        Generates a QR code containing the encrypted data and its HMAC-SHA256 signature.
        Allows the user to specify a filename.
        :param data: The data to be encoded.
        """
        # Encrypt the data
        encrypted_data = self.encrypt_data(data)
        
        # Generate an HMAC-SHA256 signature for the encrypted data
        signature = self.generate_signature(encrypted_data)
        
        # Combine the encrypted data and its signature
        secured_data = f"{encrypted_data}:{signature}"

        # Ask the user to provide a filename
        filename = input("Enter the filename for the QR code (without extension): ") + ".png"

        # Generate the QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(secured_data)
        qr.make(fit=True)

        img = qr.make_image()
        img.save(filename)

        print(f"Secure QR code saved as {filename}")

# Example Usage:
if __name__ == "__main__":
    qr_generator = SecureQRCodeGenerator()

    # Ask user for the data to encode
    user_data = input("Enter the data to encode in the QR code (URL, text, or file path): ")
    
    # Generate and save a secure QR code
    qr_generator.create_secure_qr(user_data)
