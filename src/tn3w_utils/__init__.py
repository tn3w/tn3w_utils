from typing import Optional, Union, Tuple
from threading import Lock
import json
import re
import pkg_resources
import os
import hashlib
import secrets
from urllib.parse import urlparse, urlunparse, parse_qs
from base64 import b64encode, b64decode
from time import time
from werkzeug import Request

#####################
#### Basic Tools ####
#####################

def generate_random_string(length: int, with_numbers: bool = True, with_letters: bool = True, with_punctuation: bool = True) -> str:
    """
    Generates a random string

    :param length: The length of the string
    :param with_numbers: Whether numbers should be included
    :param with_letters: Whether letters should be included
    :param with_punctuation: Whether special characters should be included
    """

    characters = ""

    if with_numbers: characters += "0123456789"
    if with_punctuation: characters += r"!\"#$%&'()*+,-.:;<=>?@[\]^_`{|}~"
    if with_letters: characters += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string

def shorten_text(text: str, length: int) -> str:
    """
    Function to shorten the text and append "...".

    :param text: The text to be shortened
    :param length: The length of the text
    """

    if len(text) > length:
        text = text[:length] + "..."
    return text

def list_remove_duplicates(origin_list: list) -> list:
    """
    Removes duplicate elements from a list while preserving the original order.

    :param origin_list: The original list containing elements with potential duplicates.
    """

    return list(dict.fromkeys(origin_list).keys())

def reverse_list(origin_list: list) -> list:
    """
    Reverses the order of elements in a list.

    :param origin_list: The original list to be reversed.
    """

    return origin_list[::-1]

####################
#### File Tools ####
####################

file_locks = {}

class JSON:
    "Class for loading / saving JavaScript Object Notation (= JSON)"

    @staticmethod
    def load(file_name: str, default: Optional[Union[dict, list]] = None) -> Union[dict, list]:
        """
        Function to load a JSON file securely.

        :param file_name: The JSON file you want to load
        :param default: Returned if no data was found
        """

        if not os.path.isfile(file_name):
            if default is None:
                return {}
            return default
        
        if file_name not in file_locks:
            file_locks[file_name] = Lock()

        with file_locks[file_name]:
            with open(file_name, "r", encoding = "utf-8") as file:
                data = json.load(file)
            return data
    
    @staticmethod
    def dump(data: Union[dict, list], file_name: str) -> bool:
        """
        Function to save a JSON file securely.
        
        :param data: The data to be stored should be either dict or list
        :param file_name: The file to save to

        :return: Bool that says if the dump process was successful
        """

        file_directory = os.path.dirname(file_name)
        if not os.path.isdir(file_directory):
            return False
        
        if file_name not in file_locks:
            file_locks[file_name] = Lock()

        with file_locks[file_name]:
            with open(file_name, "w", encoding = "utf-8") as file:
                json.dump(data, file)
        
        return True

def read(
        file_name: str,
        is_bytes: bool = False,
        default: any = None
        ) -> Optional[any]:
    """
    Reads the content of a file and returns it as either a string or bytes, depending on the 'is_bytes' parameter.
    
    :param file_name: The name of the file to be read.
    :param is_bytes: If True, the content will be returned as bytes; if False, the content will be returned as a string.
    :param default: The value to return if the file does not exist or cannot be read. Defaults to None.
    """

    if not os.path.isfile(file_name):
        return default
    
    if file_name not in file_locks:
        file_locks[file_name] = Lock()

    with file_locks[file_name]:
        with open(file_name, "r" + ("b" if is_bytes else ""),
            encoding = "utf-8") as readable_file:
            file_content = readable_file.read()
    return file_content

def write(
        data: any,
        file_name: str,
        is_bytes: bool = False
        ) -> bool:
    """
    Writes data to a file, either as bytes or as a string, depending on the 'is_bytes' parameter.

    :param data: The data to be written to the file.
    :param file_name: The name of the file to write to.
    :param is_bytes: If True, the data will be written as bytes; if False, the data will be written as a string.
    """

    file_directory = os.path.dirname(file_name)
    if not os.path.isdir(file_directory):
        return False
    
    if file_name not in file_locks:
        file_locks[file_name] = Lock()

    with file_locks[file_name]:
        with open(file_name, "w" + ("b" if is_bytes else ""),
            encoding = "utf-8") as writeable_file:
            writeable_file.write(data)
    return True

#############################
#### Cryptographic Tools ####
#############################

class FastHashing:
    "Implementation for fast hashing"

    def __init__(self, salt: Optional[str] = None, without_salt: bool = False):
        """
        :param salt: The salt, makes the hashing process more secure (Optional)
        :param without_salt: If True, no salt is added to the hash
        """

        self.salt = salt
        self.without_salt = without_salt

    def hash(self, plain_text: str, hash_length: int = 8) -> str:
        """
        Function to hash a plaintext

        :param plain_text: The text to be hashed
        :param hash_length: The length of the returned hashed value
        """

        if not self.without_salt:
            salt = self.salt
            if salt is None:
                salt = secrets.token_hex(hash_length)
            plain_text = salt + plain_text

        hash_object = hashlib.sha256(plain_text.encode())
        hex_dig = hash_object.hexdigest()

        if not self.without_salt:
            hex_dig += "//" + salt
        return hex_dig

    def compare(self, plain_text: str, hashed_value: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plain_text: The text that was hashed
        :param hashed_value: The hashed value
        """

        salt = None
        if not self.without_salt:
            salt = self.salt
            if "//" in hashed_value:
                hashed_value, salt = hashed_value.split("//")

        hash_length = len(hashed_value)

        comparison_hash = FastHashing(salt=salt, without_salt = self.without_salt)\
            .hash(plain_text, hash_length = hash_length).split("//")[0]

        return comparison_hash == hashed_value

class Hashing:
    "Implementation of secure hashing with SHA256 and 200000 iterations"

    def __init__(self, salt: Optional[str] = None, without_salt: bool = False):
        """
        :param salt: The salt, makes the hashing process more secure (Optional)
        :param without_salt: If True, no salt is added to the hash
        """

        self.salt = salt
        self.without_salt = without_salt

    def hash(self, plain_text: str, hash_length: int = 32) -> str:
        """
        Function to hash a plaintext

        :param plain_text: The text to be hashed
        :param hash_length: The length of the returned hashed value
        """

        plain_text = str(plain_text).encode('utf-8')

        if not self.without_salt:
            salt = self.salt
            if salt is None:
                salt = secrets.token_bytes(32)
            else:
                if not isinstance(salt, bytes):
                    try:
                        salt = bytes.fromhex(salt)
                    except:
                        salt = salt.encode('utf-8')
        else:
            salt = None

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=hash_length,
            salt=salt,
            iterations=200000,
            backend=default_backend()
        )

        hashed_data = kdf.derive(plain_text)

        if not self.without_salt:
            hashed_value = b64encode(hashed_data).decode('utf-8') + "//" + salt.hex()
        else:
            hashed_value = b64encode(hashed_data).decode('utf-8')

        return hashed_value

    def compare(self, plain_text: str, hashed_value: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plain_text: The text that was hashed
        :param hashed_value: The hashed value
        """

        if not self.without_salt:
            salt = self.salt
            if "//" in hashed_value:
                hashed_value, salt = hashed_value.split("//")

            if salt is None:
                raise ValueError("Salt cannot be None if there is no salt in hash")

            salt = bytes.fromhex(salt)
        else:
            salt = None

        hash_length = len(b64decode(hashed_value))

        comparison_hash = Hashing(salt=salt, without_salt = self.without_salt)\
            .hash(plain_text, hash_length = hash_length).split("//")[0]

        return comparison_hash == hashed_value

class SymmetricEncryption:
    "Implementation of symmetric encryption with AES"

    def __init__(self, password: Optional[str] = None, salt_length: int = 32):
        """
        :param password: A secure encryption password, should be at least 32 characters long
        :param salt_length: The length of the salt, should be at least 16
        """

        self.password = password.encode()
        self.salt_length = salt_length

    def encrypt(self, plain_text: str) -> str:
        """
        Encrypts a text

        :param plaintext: The text to be encrypted
        """

        salt = secrets.token_bytes(self.salt_length)

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, padding as sym_padding
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        iv = secrets.token_bytes(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_text.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return b64encode(salt + iv + ciphertext).decode()

    def decrypt(self, cipher_text: str) -> str:
        """
        Decrypts a text

        :param ciphertext: The encrypted text
        """

        cipher_text = b64decode(cipher_text.encode())

        salt, iv, cipher_text = cipher_text[:self.salt_length], cipher_text[
            self.salt_length:self.salt_length + 16], cipher_text[self.salt_length + 16:]
        
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, padding as sym_padding
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

        return plaintext.decode()

class AsymmetricEncryption:
    "Implementation of secure asymmetric encryption with RSA"

    def __init__(self, public_key: Optional[str] = None, private_key: Optional[str] = None):
        """
        :param public_key: The public key to encrypt a message / to verify a signature
        :param private_key: The private key to decrypt a message / to create a signature
        """

        self.public_key, self.private_key = public_key, private_key

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization

        if not public_key is None:
            self.publ_key = serialization.load_der_public_key(
                b64decode(public_key.encode("utf-8")), backend=default_backend()
            )
        else:
            self.publ_key = None

        if not private_key is None:
            self.priv_key = serialization.load_der_private_key(
                b64decode(private_key.encode("utf-8")), password=None, backend=default_backend()
            )
            
            if self.publ_key is None:
                self.publ_key = self.priv_key.public_key()
                self.public_key = b64encode(self.publ_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode("utf-8")
        else:
            self.priv_key = None

    def generate_keys(self, key_size: int = 2048) -> "AsymmetricEncryption":
        """
        Generates private and public key

        :param key_size: The key size of the private key
        """

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        self.priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.private_key = b64encode(self.priv_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )).decode("utf-8")

        self.publ_key = self.priv_key.public_key()
        self.public_key = b64encode(self.publ_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode("utf-8")

        return self

    def encrypt(self, plain_text: str) -> Tuple[str, str]:
        """
        Encrypt the provided plain_text using asymmetric and symmetric encryption

        :param plain_text: The text to be encrypted
        """

        if self.publ_key is None:
            raise ValueError("The public key cannot be None in encode, this error occurs because no public key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        symmetric_key = secrets.token_bytes(64)

        cipher_text = SymmetricEncryption(symmetric_key).encrypt(plain_text)

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding as asy_padding

        encrypted_symmetric_key = self.publ_key.encrypt(
            symmetric_key,
            asy_padding.OAEP(
                mgf = asy_padding.MGF1(
                    algorithm = hashes.SHA256()
                ),
                algorithm = hashes.SHA256(),
                label = None
            )
        )

        encrypted_key = b64encode(encrypted_symmetric_key).decode('utf-8')
        return f"{encrypted_key}//{cipher_text}", b64encode(symmetric_key).decode('utf-8')

    def decrypt(self, cipher_text: str) -> str:
        """
        Decrypt the provided cipher_text using asymmetric and symmetric decryption

        :param cipher_text: The encrypted message with the encrypted symmetric key
        """

        if self.priv_key is None:
            raise ValueError("The private key cannot be None in decode, this error occurs because no private key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        encrypted_key, cipher_text = cipher_text.split("//")[0], cipher_text.split("//")[1]
        encrypted_symmetric_key = b64decode(encrypted_key.encode('utf-8'))

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding as asy_padding

        symmetric_key = self.priv_key.decrypt(
            encrypted_symmetric_key, 
            asy_padding.OAEP(
                mgf = asy_padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm = hashes.SHA256(),
                label = None
            )
        )

        plain_text = SymmetricEncryption(symmetric_key).decrypt(cipher_text)

        return plain_text

    def sign(self, plain_text: Union[str, bytes]) -> str:
        """
        Sign the provided plain_text using the private key

        :param plain_text: The text to be signed
        """

        if self.priv_key is None:
            raise ValueError("The private key cannot be None in sign, this error occurs because no private key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        if isinstance(plain_text, str):
            plain_text = plain_text.encode()
        
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding as asy_padding

        signature = self.priv_key.sign(
            plain_text,
            asy_padding.PSS(
                mgf = asy_padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length = asy_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return b64encode(signature).decode('utf-8')

    def verify_sign(self, signature: str, plain_text: Union[str, bytes]) -> bool:
        """
        Verify the signature of the provided plain_text using the public key

        :param sign_text: The signature of the plain_text with base64 encoding
        :param plain_text: The text whose signature needs to be verified
        """

        if self.publ_key is None:
            raise ValueError("The public key cannot be None in verify_sign, this error occurs because no public key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        if isinstance(plain_text, str):
            plain_text = plain_text.encode()

        signature = b64decode(signature)

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding as asy_padding

        try:
            self.publ_key.verify(
                signature,
                plain_text,
                asy_padding.PSS(
                    mgf = asy_padding.MGF1(
                        hashes.SHA256()
                    ),
                    salt_length = asy_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

def derive_password(
        password: str, salt: Optional[bytes] = None
        ) -> Tuple[str, bytes]:
    """
    Derives a secure password hash using PBKDF2-HMAC algorithm.

    :param password: The input password to be hashed.
    :param salt: (Optional) A random byte string used as a salt. If not provided, a 32-byte random salt will be generated.
    """

    if salt is None:
        salt = secrets.token_bytes(32)

    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=48
    )

    key = kdf.derive(password.encode())
    hashed_password = b64encode(key).decode('utf-8')

    return hashed_password, salt

##########################
#### User-Agent Tools ####
##########################

USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.3", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.3", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.1"]

def random_ua() -> str:
    "Generates a random user agent"

    return secrets.choice(USER_AGENTS)

##########################
#### IP-Address Tools ####
##########################

def shorten_ipv6(ip_address: str) -> str:
    """
    Minimizes each ipv6 Ip address to be able to compare it with others
    
    :param ip_address: An ipv4 or ipv6 Ip address
    """
    import ipaddress

    try:
        return str(ipaddress.IPv6Address(ip_address).compressed)
    except:
        return ip_address

def ipv4_to_ipv6(ipv4_address: str) -> Optional[str]:
    """
    Converts an ipv4 address to an ipv6 address

    :param ipv4_address: An Ip version 4 address
    """
    import ipaddress

    try:
        ipv4 = ipaddress.IPv4Address(ipv4_address)
    except ipaddress.AddressValueError:
        return None

    ipv6_minimized = ipaddress.IPv6Address("::ffff:" + str(ipv4)).compressed

    return str(ipv6_minimized)

def is_valid_ip(ip_address: Optional[str] = None) -> bool:
    """
    Checks whether the current Ip is valid
    
    :param ip_address: Ipv4 or Ipv6 address (Optional)
    """

    if not isinstance(ip_address, str)\
        or ip_address is None\
        or ip_address in ["127.0.0.1", "192.168.0.1", "10.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1"]:
        return False

    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|:|::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,2}:([0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,3}:([0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,4}:([0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}:([0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}|:((:[0-9a-fA-F]{1,4}){1,7}|:)|([0-9a-fA-F]{1,4}:)(:[0-9a-fA-F]{1,4}){1,7}|([0-9a-fA-F]{1,4}:){2}(:[0-9a-fA-F]{1,4}){1,6}|([0-9a-fA-F]{1,4}:){3}(:[0-9a-fA-F]{1,4}){1,5}|([0-9a-fA-F]{1,4}:){4}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){5}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){6}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){7}(:[0-9a-fA-F]{1,4}):)$'

    ipv4_regex = re.compile(ipv4_pattern)
    ipv6_regex = re.compile(ipv6_pattern)

    if ipv4_regex.match(ip_address):
        octets = ip_address.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    elif ipv6_regex.match(ip_address):
        return True

    return False

def get_client_ip(request: Request) -> Optional[str]:
    """
    Get the client IP in v4 or v6 based on an Flask Request
    
    :param request: An Request object
    """

    client_ip = request.remote_addr
    if is_valid_ip(client_ip):
        client_ip = shorten_ipv6(client_ip)
        return client_ip

    other_client_ips = [
        request.environ.get('HTTP_X_REAL_IP', None),
        request.environ.get('REMOTE_ADDR', None),
        request.environ.get('HTTP_X_FORWARDED_FOR', None),
    ]

    for client_ip in other_client_ips:
        if is_valid_ip(client_ip):
            client_ip = shorten_ipv6(client_ip)
            return client_ip
    
    try:
        client_ip = request.headers.getlist("X-Forwarded-For")[0].rpartition(' ')[-1]
    except:
        pass
    else:
        if is_valid_ip(client_ip):
            client_ip = shorten_ipv6(client_ip)
            return client_ip
    
    headers_to_check = [
        'X-Forwarded-For',
        'X-Real-Ip',
        'CF-Connecting-IP',
        'True-Client-Ip',
    ]

    for header in headers_to_check:
        if header in request.headers:
            client_ip = request.headers[header]
            client_ip = client_ip.split(',')[0].strip()
            if is_valid_ip(client_ip):
                client_ip = shorten_ipv6(client_ip)
                return client_ip
    
    return None

IP_API_CACHE_PATH = pkg_resources.resource_filename('tn3w_utils', 'ipapi-cache.json')

def get_ip_info(
        ip_address: str,
        cache_path: Optional[str] = None,
        save_securely: bool = False
        ) -> Optional[dict]:
    """
    Function to query IP information with cache con ip-api.com

    :param ip_address: The client IP
    :param cache_path: Path to the file where results are to be cached
    :param save_securely: Whether Ip addresses are hashed and data encrypted to protect private information
    """

    if not isinstance(cache_path, str):
        cache_path = IP_API_CACHE_PATH

    ip_api_cache = JSON.load(cache_path)

    found_ip_data = None
    ip_api_cache_copy = ip_api_cache.copy()
    for client_ip, ip_data in ip_api_cache.items():
        if int(time()) - int(ip_data["time"]) > 518400:
            del ip_api_cache_copy[client_ip]
        else:
            if found_ip_data is not None: continue
            if isinstance(ip_data["data"], dict):
                if client_ip == ip_address:
                    found_ip_data = ip_data["data"]
            elif isinstance(ip_data["data"], str):
                comparison = FastHashing().compare(ip_address, client_ip)
                if comparison:
                    try:
                        decrypted_data = SymmetricEncryption(ip_address).decrypt(ip_data["data"])
                        found_ip_data = json.load(decrypted_data)
                    except:
                        pass

    if len(ip_api_cache) != len(ip_api_cache_copy):
        ip_api_cache = ip_api_cache_copy
        JSON.dump(cache_path, ip_api_cache)
    
    import requests
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_address}?fields=66846719",
            headers = {"User-Agent": random_ua()},
            timeout = 3
        )
        response.raise_for_status()
    except:
        return None

    if response.ok:
        data = response.json()
        if data["status"] == "success":
            del data["status"], data["query"]

            new_data = {"time": int(time())}
            if save_securely:
                response_string = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
                
                crypted_response = SymmetricEncryption(ip_address).encrypt(response_string)
                new_data["data"] = crypted_response

                hashed_ip = FastHashing().hash(ip_address)
                ip_api_cache[hashed_ip] = new_data
            else:
                new_data["data"] = data
                ip_api_cache[ip_address] = new_data
            JSON.dump(ip_api_cache, cache_path)

            del data["time"]

            return data
        
    return None

###################
#### Web Tools ####
###################

def remove_args_from_url(url: str) -> str:
    """
    Removes query parameters from the given URL and returns the modified URL.

    :param url: The input URL
    """

    parsed_url = urlparse(url)

    scheme, netloc, path, params, query, fragment = parsed_url

    query_args = parse_qs(query)
    query_args.clear()

    url_without_args = urlunparse((scheme, netloc, path, params, '', fragment))

    return url_without_args

LANGUAGES_FILE_PATH = pkg_resources.resource_filename('flask_AuthGenius', 'languages.json')
TRANSLATIONS_FILE_PATH = pkg_resources.resource_filename('flask_AuthGenius', 'translations.json')

LANGUAGES = JSON.load(LANGUAGES_FILE_PATH)
LANGUAGE_CODES = [language["code"] for language in LANGUAGES]

class WebPage:
    "Class with useful tools for WebPages"
    
    @staticmethod
    def client_language(request: Request, default: Optional[str] = None) -> Tuple[str, bool]:
        """
        Which language the client prefers

        :param request: An Request object

        :return language: The client languge
        :return is_default: Is Default Value
        """

        language_from_args = request.args.get("language")
        language_from_cookies = request.cookies.get("language")

        chosen_language = (
            language_from_args
            if language_from_args in LANGUAGE_CODES
            else (
                language_from_cookies
                if language_from_cookies in LANGUAGE_CODES
                else None
            )
        )

        if chosen_language is None:
            preferred_language = request.accept_languages.best_match(LANGUAGE_CODES)

            if preferred_language != None:
                return preferred_language, False
        else:
            return chosen_language, False
        
        if default is None: default = "en"

        return default, True
    
    @staticmethod
    def _minimize_tag_content(html: str, tag: str) -> str:
        """
        Minimizes the content of a given tag
        
        :param html: The HTML page where the tag should be minimized
        :param tag: The HTML tag e.g. "script" or "style"
        """

        tag_pattern = rf'<{tag}\b[^>]*>(.*?)<\/{tag}>'
        
        def minimize_tag_content(match: re.Match):
            content = match.group(1)
            content = re.sub(r'\s+', ' ', content)
            return f'<{tag}>{content}</{tag}>'

        return re.sub(tag_pattern, minimize_tag_content, html, flags=re.DOTALL | re.IGNORECASE)

    @staticmethod
    def minimize(html: str) -> str:
        """
        Minimizes an HTML page

        :param html: The content of the page as html
        """

        html = re.sub(r'<!--(.*?)-->', '', html, flags=re.DOTALL)
        html = re.sub(r'\s+', ' ', html)

        html = WebPage._minimize_tag_content(html, 'script')
        html = WebPage._minimize_tag_content(html, 'style')
        return html
    
    @staticmethod
    def _translate_text(text_to_translate: str, from_lang: str, to_lang: str) -> str:
        """
        Function to translate a text based on a translation file

        :param text_to_translate: The text to translate
        :param from_lang: The language of the text to be translated
        :param to_lang: Into which language the text should be translated
        """

        if from_lang == to_lang:
            return text_to_translate
        
        translations = JSON.load(TRANSLATIONS_FILE_PATH, [])
        
        for translation in translations:
            if translation["text_to_translate"] == text_to_translate\
                and translation["from_lang"] == from_lang\
                    and translation["to_lang"] == to_lang:
                return translation["translated_output"]
        
        from googletrans import Translator
        translator = Translator()

        try:
            translated_output = translator.translate(text_to_translate, src=from_lang, dest=to_lang).text
            translated_output = translated_output.encode('latin-1').decode('unicode_escape')
        except:
            return text_to_translate
        
        translation = {
            "text_to_translate": text_to_translate, 
            "from_lang": from_lang,
            "to_lang": to_lang, 
            "translated_output": translated_output
        }
        translations.append(translation)
        
        JSON.dump(translations, TRANSLATIONS_FILE_PATH)

        if to_lang in ["de", "en", "es", "fr", "pt", "it"]:
            translated_output = translated_output[0].upper() + translated_output[1:]
        
        return translated_output
    
    @staticmethod
    def translate(html: str, from_lang: str, to_lang: str) -> str:
        """
        Function to translate a page into the correct language

        :param html: The content of the page as html
        :param from_lang: The language of the text to be translated
        :param to_lang: Into which language the text should be translated
        """

        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(html, 'html.parser')

        def translate_htmlified_text(html_tag):
            try:
                new_soup = BeautifulSoup(str(html_tag), 'html.parser')
                outer_tag = new_soup.find(lambda tag: tag.find_all(recursive=False))

                text = ''.join(str(tag) for tag in outer_tag.contents)
            except:
                text = html_tag.text
                        
            if "<" in text:
                pattern = r'(<.*?>)(.*?)(<\/.*?>)'
        
                def replace(match):
                    tag_open, content, tag_close = match.groups()
                    processed_content = WebPage._translate_text(content, from_lang, to_lang)
                    return f'{tag_open}{processed_content}{tag_close}'
                
                modified_text = re.sub(pattern, replace, text)
            else:
                modified_text = WebPage._translate_text(text, from_lang, to_lang)
            return modified_text
        
        tags = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'p', 'button'])
        for tag in tags:
            if 'ntr' not in tag.attrs:
                translated_html = translate_htmlified_text(tag)
                tag.clear()
                tag.append(BeautifulSoup(translated_html, 'html.parser'))
        
        inputs = soup.find_all('input')
        for input_tag in inputs:
            if input_tag.has_attr('placeholder') and 'ntr' not in input_tag.attrs:
                input_tag['placeholder'] = WebPage._translate_text(input_tag['placeholder'], from_lang, to_lang)
        
        head_tag = soup.find('head')
        if head_tag:
            title_element = head_tag.find('title')
            if title_element:
                title_element.string = WebPage._translate_text(title_element.text, from_lang, to_lang)
        
        translated_html = soup.prettify()
        return translated_html
    
    @staticmethod
    def render_template(file_path: Optional[str] = None, html: Optional[str] = None, **args) -> str:
        """
        Function to render a HTML template (= insert arguments / translation / minimization)

        :param file_path: From which file HTML code should be loaded (Optional)
        :param html: The content of the page as html (Optional)
        :param args: Arguments to be inserted into the WebPage with Jinja2
        """

        if file_path is None and html is None:
            raise ValueError("Arguments 'file_path' and 'html' are None")
        
        if not file_path is None:
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"File `{file_path}` does not exist")
        
        from jinja2 import Environment, select_autoescape, Undefined

        class SilentUndefined(Undefined):
            "Class to not get an error when specifying a non-existent argument"

            def _fail_with_undefined_error(self, *args, **kwargs):
                return None

        env = Environment(
            autoescape=select_autoescape(['html', 'xml']),
            undefined=SilentUndefined
        )

        if html is None:
            with open(file_path, "r", encoding = "utf-8") as file:
                html = file.read()
                
        template = env.from_string(html)

        html = template.render(**args)

        return html

def render_template(
        file_name: str,
        request: Request,
        template_dir: Optional[str] = None,
        template_language: Optional[str] = None,
        **args
        ) -> str:
    """
    Renders a template file into HTML content, optionally translating it to the specified language.

    :param file_name: The name of the template file to render.
    :param request: The request object providing information about the client's language preference.
    :param template_dir: The directory path where template files are located. If not provided, defaults to the 'templates' directory in the current working directory.
    :param template_language: The language code specifying the language of the template content. If not provided, defaults to 'en' (English).
    :param **args: Additional keyword arguments to pass to the template rendering function.

    :return: The rendered HTML content of the template.
    """

    if template_dir is None:
        template_dir = os.path.join(os.getcwd(), "templates")

    if template_language is None: template_language = "en"
    
    file_path = os.path.join(template_dir, file_name)

    client_language = WebPage.client_language(request)
    args["language"] = client_language

    html = WebPage.render_template(file_path = file_path, html = None, **args)
    html = WebPage.translate(html, template_language, client_language)
    html = WebPage.minimize(html)

    return html