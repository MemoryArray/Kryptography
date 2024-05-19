from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import os

class SHA224:
    """
    Encrypt/Decrypt support for files using SHA224 algorithm.
    """
    @staticmethod
    def encrypt(file_path: str, password: str, output_directory: str) -> bool:
        """
        Encrypts a file using SHA224 algorithm.

        Args:
            file_path (str): path of the file to be encrypted.
            password (str): password to be used for encryption.
            output_directory (str): directory where encrypted file will be saved.

        Returns:
            bool: True if file is encrypted successfully, False otherwise.
        """
        with open(file_path, 'rb') as file:
            plaintext = file.read()

        try:
            salt = os.urandom(16)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA224(),
                length=28,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )

            key = kdf.derive(password.encode())

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            path = output_directory + '.enc'
            with open(path, 'wb') as file:
                file.write(salt)
                file.write(iv)
                file.write(ciphertext)

            print("File encrypted successfully.")
            return path
        except Exception as e:
            print(f"Error while encrypting file: {e}")
            return False

    @staticmethod
    def decrypt(file_path: str, password: str, output_directory: str) -> bool:
        """ 
        Decrypts a file using SHA224 algorithm.

        Args:   
            file_path (str): path of the file to be decrypted.
            password (str): password to be used for decryption.
            output_directory (str): directory where decrypted file will be saved.

        Returns:
            bool: True if file is decrypted successfully, False otherwise.
        """
        with open(file_path, 'rb') as file:
            salt = file.read(16)
            iv = file.read(16)
            ciphertext = file.read()

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA224(),
                salt=salt,
                length=28,
                iterations=100000,
                backend=default_backend()
            )

            key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

            output_file_path = os.path.join(output_directory, os.path.basename(file_path).replace('.enc', ''))
            with open(output_file_path, 'wb') as file:
                file.write(plaintext)

            print("File decrypted successfully.")
            return output_file_path
        
        except Exception as e:
            if str(e) == "Invalid padding bytes.":
                raise ValueError("Incorrect password for file " + os.path.basename(file_path) + ".")
            elif "Invalid key size" in str(e):
                raise ValueError("Incorrect algorithm or corruption for file " + os.path.basename(file_path) + ".")
            print(f"Error while decrypting file: {e}")
            return False
        
class SHA256:
    """
    Encrypt/Decrypt support for files using SHA256 algorithm.
    """
    @staticmethod
    def encrypt(file_path: str, password: str, output_directory: str) -> bool:
        """
        Encrypts a file using SHA256 algorithm.

        Args:
            file_path (str): path of the file to be encrypted.
            password (str): password to be used for encryption.
            output_directory (str): directory where encrypted file will be saved.

        Returns:
            bool: True if file is encrypted successfully, False otherwise.
        """        
        with open(file_path, 'rb') as file:
            plaintext = file.read()

        try:
            salt = os.urandom(16)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )

            key = kdf.derive(password.encode())

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            path = output_directory + '.enc'
            with open(path, 'wb') as file:
                file.write(salt)
                file.write(iv)
                file.write(ciphertext)

            print("File encrypted successfully.")
            return path
        except Exception as e:
            print(f"Error while encrypting file: {e}")
            return False

    @staticmethod
    def decrypt(file_path: str, password: str, output_directory: str) -> bool:
        """
        Decrypts a file using SHA256 algorithm.

        Args:
            file_path (str): path of the file to be decrypted.
            password (str): password to be used for decryption.
            output_directory (str): directory where decrypted file will be saved.

        Returns:
            bool: True if file is decrypted successfully, False otherwise.
        """        
        with open(file_path, 'rb') as file:
            salt = file.read(16)
            iv = file.read(16)
            ciphertext = file.read()

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                salt=salt,
                length=32,
                iterations=100000,
                backend=default_backend()
            )

            key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

            output_file_path = os.path.join(output_directory, os.path.basename(file_path).replace('.enc', ''))
            with open(output_file_path, 'wb') as file:
                file.write(plaintext)

            print("File decrypted successfully.")
            return output_file_path
        
        except Exception as e:
            if str(e) == "Invalid padding bytes.":
                raise ValueError("Incorrect password for file " + os.path.basename(file_path) + ".")
            elif "Invalid key size" in str(e):
                raise ValueError("Incorrect algorithm or corruption for file " + os.path.basename(file_path) + ".")
            print(f"Error while decrypting file: {e}")
            return False
        
class SHA384:
    """
    Encrypt/Decrypt support for files using SHA384 algorithm.
    """
    @staticmethod
    def encrypt(file_path: str, password: str, output_directory: str) -> bool:
        """
        Encrypts a file using SHA384 algorithm.

        Args:
            file_path (str): path of the file to be encrypted.
            password (str): password to be used for encryption.
            output_directory (str): directory where encrypted file will be saved.

        Returns:
            bool: True if file is encrypted successfully, False otherwise.
        """
        with open(file_path, 'rb') as file:
            plaintext = file.read()

        try:
            salt = os.urandom(16)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA384(),
                length=48,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )

            key = kdf.derive(password.encode())

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            path = output_directory + '.enc'
            with open(path, 'wb') as file:
                file.write(salt)
                file.write(iv)
                file.write(ciphertext)

            print("File encrypted successfully.")
            return path
        except Exception as e:
            print(f"Error while encrypting file: {e}")
            return False

    @staticmethod
    def decrypt(file_path: str, password: str, output_directory: str) -> bool:
        """
        Decrypts a file using SHA384 algorithm.

        Args:
            file_path (str): path of the file to be decrypted.
            password (str): password to be used for decryption.
            output_directory (str): directory where decrypted file will be saved.

        Returns:
            bool: True if file is decrypted successfully, False otherwise.
        """
        with open(file_path, 'rb') as file:
            salt = file.read(16)
            iv = file.read(16)
            ciphertext = file.read()

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA384(),
                salt=salt,
                length=48,
                iterations=100000,
                backend=default_backend()
            )

            key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

            output_file_path = os.path.join(output_directory, os.path.basename(file_path).replace('.enc', ''))
            with open(output_file_path, 'wb') as file:
                file.write(plaintext)

            print("File decrypted successfully.")
            return output_file_path
        
        except Exception as e:
            if str(e) == "Invalid padding bytes.":
                raise ValueError("Incorrect password for file " + os.path.basename(file_path) + ".")
            elif "Invalid key size" in str(e):
                raise ValueError("Incorrect algorithm or corruption for file " + os.path.basename(file_path) + ".")
            print(f"Error while decrypting file: {e}")
            return False
        
class SHA512:
    """
    Encrypt/Decrypt support for files using SHA512 algorithm.
    """
    @staticmethod
    def encrypt(file_path: str, password: str, output_directory: str) -> bool:
        """
        Encrypts a file using SHA512 algorithm and AES encryption.

        Args:
            file_path (str): path of the file to be encrypted.
            password (str): password to be used for encryption.
            output_directory (str): directory where encrypted file will be saved.

        Returns:
            bool: True if file is encrypted successfully, False otherwise.
        """
        with open(file_path, 'rb') as input_file:
            plaintext = input_file.read()

        try:
            salt = os.urandom(16)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )

            key = kdf.derive(password.encode())

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            path = os.path.join(output_directory, os.path.basename(file_path) + '.enc')
            with open(path, 'wb') as output_file:
                output_file.write(salt)
                output_file.write(iv)
                output_file.write(ciphertext)

            print("File encrypted successfully.")
            return path
        except Exception as e:
            print(f"Error while encrypting file: {e}")
            return False

    @staticmethod
    def decrypt(file_path: str, password: str, output_directory: str) -> bool:
        """
        Decrypts a file using SHA512 algorithm and AES decryption.

        Args:
            file_path (str): path of the file to be decrypted.
            password (str): password to be used for decryption.
            output_directory (str): directory where decrypted file will be saved.

        Returns:
            bool: True if file is decrypted successfully, False otherwise.
        """
        with open(file_path, 'rb') as input_file:
            salt = input_file.read(16)
            iv = input_file.read(16)
            ciphertext = input_file.read()

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                salt=salt,
                length=32,
                iterations=100000,
                backend=default_backend()
            )

            key = kdf.derive(password.encode())

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

            output_file_path = os.path.join(output_directory, os.path.basename(file_path).replace('.enc', ''))
            with open(output_file_path, 'wb') as output_file:
                output_file.write(plaintext)

            print("File decrypted successfully.")
            return output_file_path
        
        except Exception as e:
            if str(e) == "Invalid padding bytes.":
                raise ValueError("Incorrect password for file " + os.path.basename(file_path) + ".")
            elif "Invalid key size" in str(e):
                raise ValueError("Incorrect algorithm or corruption for file " + os.path.basename(file_path) + ".")
            print(f"Error while decrypting file: {e}")
            return False
        
def encrypt(file_path: str, password: str, output_directory: str, method: str) -> bool:
    """
    Encrypts a file using AES algorithm.

    Args:
        file_path (str): path of the file to be encrypted.
        password (str): password to be used for encryption.
        output_directory (str): directory where encrypted file will be saved.
        method (str): encryption method to be used.

    Returns:
        bool: True if file is encrypted successfully, False otherwise.
    """
    assert method in ['SHA224', 'SHA256', 'SHA384', 'SHA512'], "Invalid encryption method."
    password = str(password)
    if method == 'SHA224':
        return SHA224.encrypt(file_path, password, output_directory)
    elif method == 'SHA256':
        return SHA256.encrypt(file_path, password, output_directory)
    elif method == 'SHA384':
        return SHA384.encrypt(file_path, password, output_directory)
    elif method == 'SHA512':
        return SHA512.encrypt(file_path, password, output_directory)

def decrypt(file_path: str, password: str, output_directory: str, method: str) -> bool:
    """
    Decrypts a file using AES algorithm.

    Args:
        file_path (str): path of the file to be decrypted.
        password (str): password to be used for decryption.
        output_directory (str): directory where decrypted file will be saved.
        method (str): decryption method to be used.

    Returns:
        bool: True if file is decrypted successfully, False otherwise.
    """
    assert method in ['SHA224', 'SHA256', 'SHA384', 'SHA512'], "Invalid decryption method."
    password = str(password)
    if method == 'SHA224':
        return SHA224.decrypt(file_path, password, output_directory)
    elif method == 'SHA256':
        return SHA256.decrypt(file_path, password, output_directory)
    elif method == 'SHA384':
        return SHA384.decrypt(file_path, password, output_directory)
    elif method == 'SHA512':
        return SHA512.decrypt(file_path, password, output_directory)
    
def KeyMix(password: str | bytes = None, keyfile: str = None) -> bytes:
    """
    Generates a key using the password and/or a keyfile.

    Args:
        password (str | bytes): password to be used for key generation.
        keyfile (str): path of the keyfile to be used for key generation.

    Returns:
        bytes: generated key.
    """
    if keyfile:
        with open(keyfile, 'rb') as file:
            key = file.read()
        if password:
            if isinstance(password, str):
                password = password.encode()
            return hashlib.sha256(key + password).digest()
        else:
            return key
    else:
        if password:
            if isinstance(password, str):
                password = password.encode()
            return hashlib.sha256(password).digest()
        else:
            raise ValueError("Password or keyfile must be provided.")

def random_key() -> bytes:
    """
    Generates a random key.

    Returns:
        bytes: generated key.
    """
    return os.urandom(32)