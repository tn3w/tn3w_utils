"""
Module with useful tools from TN3W under Apache-2.0 licenses
*~* https://github.com/tn3w/tn3w_utils *~*
"""

from typing import Optional, Union, Tuple, Callable, Any
from threading import Lock
import json
import re
import os
import hashlib
import platform
import shutil
import random
import atexit
import subprocess
import mimetypes
import secrets
from io import BytesIO
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlunparse, parse_qs
from base64 import b64encode, b64decode
from time import time
import pkg_resources
from werkzeug import Request

#####################
#### Basic Tools ####
#####################

def random_string(
        length: int, with_numbers: bool = True, with_letters: bool = True,
        with_punctuation: bool = True
        ) -> str:
    """
    Generates a random string

    :param length: The length of the string
    :param with_numbers: Whether numbers should be included
    :param with_letters: Whether letters should be included
    :param with_punctuation: Whether special characters should be included
    """

    characters = ""

    if with_numbers:
        characters += "0123456789"
    if with_punctuation:
        characters += r"!\"#$%&'()*+,-.:;<=>?@[\]^_`{|}~"
    if with_letters:
        characters += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    generated_random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return generated_random_string

FONTS = [
    pkg_resources.resource_filename('tn3w_utils', 'Comic_Sans_MS.ttf'),
    pkg_resources.resource_filename('tn3w_utils', 'Droid_Sans_Mono.ttf'),
    pkg_resources.resource_filename('tn3w_utils', 'Helvetica.ttf')
]

def random_font() -> str:
    "Generates a random font file"

    return secrets.choice(FONTS)

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

def get_system_architecture() -> Tuple[str, str]:
    "Function to get the correct system information"

    system = platform.system()
    if system == "Darwin":
        system = "macOS"

    machine_mappings = {
        "AMD64": "x86_64",
        "i386": "i686"
    }

    machine = platform.machine()

    machine = machine_mappings.get(machine, "x86_64")

    return system, machine

def get_console_columns() -> int:
    "Returns the console size"

    if os.name == 'nt':
        columns, _ = shutil.get_terminal_size()
        return columns
    else:
        _, columns = os.popen('stty size', 'r').read().split()
        return int(columns)

def find_missing_numbers_in_range(range_start: int, range_end: int, data: list):
    """
    Finds missing numbers within a given range excluding the ones provided in the data.

    :param range_start: The start value of the range.
    :param range_end: The end value of the range.
    :param data: A list containing tuples of numbers and their associated data.
    """

    numbers = list(range(range_start + 1, range_end + 1))

    for item in data:
        if item[0] in numbers:
            numbers.remove(item[0])

    return numbers

def get_password_strength(password: str) -> int:
    """
    Function to get a password strength from 0 (bad) to 100% (good)

    :param password: The password to check
    """

    strength = min((len(password) * 62.5) / 16, 70)

    if re.search(r'[A-Z]', password):
        strength += 5
    if re.search(r'[a-z]', password):
        strength += 5
    if re.search(r'[!@#$%^&*()_+{}\[\]:;<>,.?~\\]', password):
        strength += 20

    strength = min(strength, 100)

    return round(strength)

def is_password_pwned(password: str, session: Optional[Any] = None) -> bool:
    """
    Ask pwnedpasswords.com if password is available in data leak

    :param password: Password to check against
    :param session: a requests.Session Object (Optional)
    """

    import requests

    if session is None:
        requests.Session()

    password_sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    hash_prefix = password_sha1_hash[:5]

    url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"

    while True:
        try:
            response = requests.get(
                url,
                headers = {'User-Agent': random.choice(USER_AGENTS)},
                timeout = 5
            )
            response.raise_for_status()

            if response.status_code == 200:
                hashes = [line.split(':') for line in response.text.splitlines()]
                for password_hash, _ in hashes:
                    if password_hash == password_sha1_hash[5:]:
                        return False         
        except (requests.exceptions.ProxyError, requests.exceptions.ReadTimeout):
            session = requests.Session()
        else:
            break

    return True

class EmptyWith:
    "A class that provides a no-operation (dummy) implementation of an with Statement."

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

def download_file(url: str, dict_path: Optional[str] = None,
                  operation_name: Optional[str] = None,
                  file_name: Optional[str] = None,
                  session: Optional[Any] = None,
                  return_as_bytes: bool = False, 
                  quite: bool = False
                  ) -> Optional[Union[str, bytes]]:
    """
    Function to download a file

    :param url: The url of the file
    :param dict_path: Specifies the directory where the file should be saved
    :param operation_name: Sets the name of the operation in the console (Optional)
    :param file_name: Sets the file name (Optional)
    :param session: a requests.Session (Optional)
    :param return_as_bytes: If True, the function returns a bytes instead of a file path
    :param quite: If True nothing is written to the console
    """

    import requests

    if session is None:
        session = requests.Session()

    if not return_as_bytes:
        if file_name is None:
            parsed_url = urlparse(url)
            file_name = os.path.basename(parsed_url.path)

        save_path = os.path.join(dict_path, file_name)

        if os.path.isfile(save_path):
            return save_path

    if not quite:
        from rich.progress import Progress

        progress = Progress()
    else:
        progress = EmptyWith()

    with progress:
        downloaded_bytes = 0

        if not return_as_bytes:
            file = open(save_path, 'wb')
        else:
            file_bytes = b''

        try:
            response = session.get(
                url, stream=True, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=5
            )
            response.raise_for_status()
        except Exception as e:
            print(f"[Error] Error downloading the file: '{e}'")
            return None

        if response.status_code == 200:
            total_length = response.headers.get('content-length')
            total_length = 500000 if total_length is None else int(total_length)

            if not total_length is None and not quite:
                if operation_name:
                    task = progress.add_task(
                        f"[green]Downloading {operation_name}...",
                        total=total_length
                    )
                else:
                    task = progress.add_task("[green]Downloading...", total=total_length)

            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    if not return_as_bytes:
                        file.write(chunk)
                    else:
                        file_bytes += chunk

                    if downloaded_bytes > total_length:
                        downloaded_bytes = total_length
                    elif not downloaded_bytes == total_length:
                        downloaded_bytes += len(chunk)

                    if not quite:
                        progress.update(task, completed=downloaded_bytes)
            if not quite:
                progress.update(task, completed=total_length)
        else:
            return None

    if return_as_bytes:
        return file_bytes

    file.close()
    return save_path

class AtExit:
    """
    Manages functions to be executed at program exit.

    This class provides methods to register functions to be called at program exit
    and to remove registered functions.
    """

    def __init__(self) -> "AtExit":
        "Initializes the AtExit object."

        self.all_atexit_handlers = []
        self.atexit_handlers = []

    def register(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> str:
        """
        Register a function to be called at program exit with optional arguments.
        
        :param func: The function to be called at exit.
        :param *args: Optional positional arguments to be passed to the function.
        :param **kwargs: Optional keyword arguments to be passed to the function.

        :return: Unique identifier for the registered function.
        """

        atexit_id = random_string(12)

        while atexit_id in self.all_atexit_handlers:
            atexit_id = random_string(12)

        self.all_atexit_handlers.append(atexit_id)
        self.atexit_handlers.append(atexit_id)

        def atexit_func(func, *args, **kwargs):
            """
            Wrapper function to call the registered function with arguments at program exit.
            
            :param func: The function to be called at exit.
            :param *args: Optional positional arguments to be passed to the function.
            :param **kwargs: Optional keyword arguments to be passed to the function.
            """
            if atexit_id in self.atexit_handlers:
                func(*args, **kwargs)

        atexit.register(atexit_func, func, *args, **kwargs)

        return atexit_id

    def remove_atexit(self, atexit_id: str):
        """
        Remove a registered function from the atexit handlers.

        :param atexit_id: The unique identifier of the function to be removed.
        """

        if atexit_id in self.atexit_handlers:
            self.atexit_handlers.remove(atexit_id)

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

class Block:
    "Functions for saving data in blocks instead of alone"

    def __init__(self, block_size: int, file_name: str) -> "Block":
        """
        :param block_size: How big each block is
        :param file_name: The name of the file to write the block to.
        """

        if block_size < 0:
            block_size = 4000

        self.block_size = block_size
        self.file_name = file_name

        self.executor = ThreadPoolExecutor(max_workers=5)

        self.blocks = {}

    def _get_id(self, index: int) -> int:
        """
        Returns the nearest block index based on the given index and block size.

        :param index: The index value.
        """

        remains = index % self.block_size

        if remains == 0:
            return index

        return index + (self.block_size - remains)

    def _write_data(self, block_data: tuple) -> None:
        """
        Writes data to a file while ensuring thread safety using locks.

        :param block_data: A tuple containing data to be written to the file.
        """

        if self.file_name not in file_locks:
            file_locks[self.file_name] = Lock()

        with file_locks[self.file_name]:
            if os.path.isfile(self.file_name):
                with open(self.file_name, "r", encoding="utf-8") as file:
                    data = json.load(file)
            else:
                data = []

            for _, new_data in block_data:
                if new_data is not None:
                    data.append(new_data)

            with open(self.file_name, "w", encoding="utf-8") as file:
                json.dump(data, file)

    def add_data(self, index: int, new_data: Optional[dict] = None) -> Tuple[bool, Optional[int]]:
        """
        Adds new data to the specified index in the data structure, and writes the block to file
        if all expected data within the block range is present.

        :param index: The index where the new data should be added.
        :param new_data: The data to be added, if any.
        """

        block_id = self._get_id(index)

        block = self.blocks.get(block_id, [])
        block.append((index, new_data))
        self.blocks[block_id] = block

        missing = find_missing_numbers_in_range(block_id - self.block_size, block_id, block)
        if 1 in missing:
            missing.remove(1)

        if len(missing) == 0:
            self.executor.submit(self._write_data, block)

            del self.blocks[block_id]

            return True, block_id
        return False, block_id

def read(
        file_name: str,
        is_bytes: bool = False,
        default: any = None
        ) -> Optional[any]:
    """
    Reads the content of a file and returns it as either a string or bytes,
    depending on the 'is_bytes' parameter.
    
    :param file_name: The name of the file to be read.
    :param is_bytes: If True, the content will be returned as bytes; if False,
                     the content will be returned as a string.
    :param default: The value to return if the file does not exist or
                    cannot be read. Defaults to None.
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
    :param is_bytes: If True, the data will be written as bytes;
                     if False, the data will be written as a string.
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

class SecureDelete:
    "Class for secure deletion of files or folders"

    @staticmethod
    def list_files_and_directories(directory_path: str) -> Tuple[list, list]:
        """
        Function to get all files and directorys in a directory

        :param directory_path: The path to the directory
        """

        all_files = []
        all_directories = []

        def list_files_recursive(root, depth):
            for item in os.listdir(root):
                item_path = os.path.join(root, item)
                if os.path.isfile(item_path):
                    all_files.append((item_path, depth))
                elif os.path.isdir(item_path):
                    all_directories.append((item_path, depth))
                    list_files_recursive(item_path, depth + 1)

        list_files_recursive(directory_path, 0)

        all_files.sort(key=lambda x: x[1], reverse=True)
        all_directories.sort(key=lambda x: x[1], reverse=True)

        all_files = [path for path, _ in all_files]
        all_directories = [path for path, _ in all_directories]

        return all_files, all_directories

    @staticmethod
    def file(file_path: str, quite: bool = False) -> None:
        """
        Function to securely delete a file by replacing it first with random characters and
        then according to Gutmann patterns and DoD 5220.22-M patterns

        :param file_path: The path to the file
        :param quite: If True nothing is written to the console
        """
        if not os.path.isfile(file_path):
            return

        file_size = os.path.getsize(file_path)
        file_size_times_two = file_size * 2

        gutmann_patterns = [bytes([i % 256] * (file_size_times_two)) for i in range(35)]
        dod_patterns = [
            bytes([0x00] * file_size_times_two),
            bytes([0xFF] * file_size_times_two),
            bytes([0x00] * file_size_times_two)
        ]

        for _ in range(10):
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)

                with open(file_path, 'wb') as file:
                    file.write(os.urandom(file_size_times_two))

                if os.path.isfile(file_path):
                    os.remove(file_path)

                with open(file_path, 'ab') as file:
                    file.seek(0, os.SEEK_END)

                    # Gutmann Pattern
                    for pattern in gutmann_patterns:
                        file.write(pattern)

                    # DoD 5220.22-M Pattern
                    for pattern in dod_patterns:
                        file.write(pattern)
            except Exception as e:
                if not quite:
                    print(f"[Error] Error deleting the file '{file_path}': {e}")

            try:
                os.remove(file_path)
            except Exception as e:
                print(f"[Error] Error deleting the file '{file_path}': {e}")

    @staticmethod
    def directory(directory_path: str, quite: bool = False) -> None:
        """
        Securely deletes entire folders with files and subfolders

        :param directory_path: The path to the directory
        :param quite: If True nothing is written to the console
        """

        files, directories = SecureDelete.list_files_and_directories(directory_path)

        with ThreadPoolExecutor() as executor:
            file_futures = {executor.submit(SecureDelete.file, file, quite): file for file in files}

            concurrent.futures.wait(file_futures)

            for directory in directories:
                try:
                    shutil.rmtree(directory)
                except Exception as e:
                    if not quite:
                        print(f"[Error] Error deleting directory '{directory}': {e}")

            try:
                shutil.rmtree(directory_path)
            except Exception as e:
                if not quite:
                    print(f"[Error] Error deleting directory '{directory_path}': {e}")

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
                    except Exception:
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
            raise ValueError("""The public key cannot be None in encode, this error occurs because
                             no public key was specified when initializing the AsymmetricCrypto function and
                             none was generated with generate_keys.""")

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
            raise ValueError("""The private key cannot be None in decode, this error occurs because
                             no private key was specified when initializing the AsymmetricCrypto function and
                             none was generated with generate_keys.""")

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
            raise ValueError("""The private key cannot be None in sign, this error occurs because
                             no private key was specified when initializing the AsymmetricCrypto function and
                             none was generated with generate_keys.""")

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
            raise ValueError("""The public key cannot be None in verify_sign, this error occurs
                             because no public key was specified when initializing the AsymmetricCrypto function and
                             none was generated with generate_keys.""")

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

class NoEncryption:
    "A class that provides a no-operation (dummy) implementation for encryption and decryption."

    def __init__(self):
        pass

    def encrypt(self = None, plain_text: str = "Dummy") -> str:
        "Dummy encryption method that returns the input plain text unchanged"

        return plain_text

    def decrypt(self = None, cipher_text: str = "Dummy") -> str:
        "Dummy decryption method that returns the input cipher text unchanged"

        return cipher_text

def derive_password(
        password: str, salt: Optional[bytes] = None
        ) -> Tuple[str, bytes]:
    """
    Derives a secure password hash using PBKDF2-HMAC algorithm.

    :param password: The input password to be hashed.
    :param salt: (Optional) A random byte string used as a salt. If not provided,
                 a 32-byte random salt will be generated.
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

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.1"
    ]

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

UNWANTED_IPS = ["127.0.0.1", "192.168.0.1", "10.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1"]#
IPV4_PATTERN = r'^(\d{1,3}\.){3}\d{1,3}$'
IPV6_PATTERN = (
    r'^('
    r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|:'
    r'|::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}'
    r'|[0-9a-fA-F]{1,4}::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}'
    r'|([0-9a-fA-F]{1,4}:){1,2}:([0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}'
    r'|([0-9a-fA-F]{1,4}:){1,3}:([0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}'
    r'|([0-9a-fA-F]{1,4}:){1,4}:([0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}'
    r'|([0-9a-fA-F]{1,4}:){1,5}:([0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4}'
    r'|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
    r'|([0-9a-fA-F]{1,4}:){1,7}|:((:[0-9a-fA-F]{1,4}){1,7}|:)'
    r'|([0-9a-fA-F]{1,4}:)(:[0-9a-fA-F]{1,4}){1,7}'
    r'|([0-9a-fA-F]{1,4}:){2}(:[0-9a-fA-F]{1,4}){1,6}'
    r'|([0-9a-fA-F]{1,4}:){3}(:[0-9a-fA-F]{1,4}){1,5}'
    r'|([0-9a-fA-F]{1,4}:){4}(:[0-9a-fA-F]{1,4}){1,4}'
    r'|([0-9a-fA-F]{1,4}:){5}(:[0-9a-fA-F]{1,4}){1,3}'
    r'|([0-9a-fA-F]{1,4}:){6}(:[0-9a-fA-F]{1,4}){1,2}'
    r'|([0-9a-fA-F]{1,4}:){7}(:[0-9a-fA-F]{1,4}):)$'
)

def is_valid_ip(ip_address: Optional[str] = None) -> bool:
    """
    Checks whether the current Ip is valid
    
    :param ip_address: Ipv4 or Ipv6 address (Optional)
    """

    if not isinstance(ip_address, str)\
        or ip_address is None\
        or ip_address in UNWANTED_IPS:
        return False

    ipv4_regex = re.compile(IPV4_PATTERN)
    ipv6_regex = re.compile(IPV6_PATTERN)

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
    :param save_securely: Whether Ip addresses are hashed and data
                          encrypted to protect private information
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
            if found_ip_data is not None:
                continue

            if isinstance(ip_data["data"], dict):
                if client_ip == ip_address:
                    found_ip_data = ip_data["data"]

            elif isinstance(ip_data["data"], str):
                comparison = FastHashing().compare(ip_address, client_ip)
                if comparison:
                    try:
                        decrypted_data = SymmetricEncryption(ip_address).decrypt(ip_data["data"])
                        if decrypted_data is not None:
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

LANGUAGES_FILE_PATH = pkg_resources.resource_filename('tn3w_utils', 'languages.json')
TRANSLATIONS_FILE_PATH = pkg_resources.resource_filename('tn3w_utils', 'translations.json')

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

            if preferred_language is not None:
                return preferred_language, False
        else:
            return chosen_language, False

        if default is None:
            default = "en"

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
            translated_output = translator.translate(
                text_to_translate, src=from_lang, dest=to_lang
                ).text

            if translated_output is not None:
                translated_output = translated_output\
                    .encode('latin-1')\
                    .decode('unicode_escape')
            else:
                return text_to_translate
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
                input_tag['placeholder'] = WebPage._translate_text(
                    input_tag['placeholder'], from_lang, to_lang
                    )

        head_tag = soup.find('head')
        if head_tag:
            title_element = head_tag.find('title')
            if title_element:
                title_element.string = WebPage._translate_text(
                    title_element.text, from_lang, to_lang
                    )

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
    :param template_dir: The directory path where template files are located. 
                         If not provided, defaults to the 'templates' directory in the 
                         current working directory.
    :param template_language: The language code specifying the language of the template content. 
                              If not provided, defaults to 'en' (English).
    :param **args: Additional keyword arguments to pass to the template rendering function.

    :return: The rendered HTML content of the template.
    """

    if template_dir is None:
        template_dir = os.path.join(os.getcwd(), "templates")

    if template_language is None:
        template_language = "en"

    file_path = os.path.join(template_dir, file_name)

    client_language = WebPage.client_language(request)
    args["language"] = client_language

    html = WebPage.render_template(file_path = file_path, html = None, **args)
    html = WebPage.translate(html, template_language, client_language)
    html = WebPage.minimize(html)

    return html

#####################
#### Image Tools ####
#####################

def show_image_in_console(image_bytes: bytes) -> None:
    """
    Turns a given image into Ascii Art and prints it in the console

    :param image_bytes: The bytes of the image to be displayed in the console
    """

    from PIL import Image

    img = Image.open(BytesIO(image_bytes))

    ascii_chars = '@%#*+=-:. '
    width, height = img.size
    aspect_ratio = height / width
    new_width = get_console_columns()
    new_height = int(aspect_ratio * new_width * 0.55)
    img = img.resize((new_width, new_height))
    img = img.convert('L')

    pixels = img.getdata()
    ascii_str = ''.join([ascii_chars[min(pixel // 25, len(ascii_chars) - 1)] for pixel in pixels])
    ascii_str_len = len(ascii_str)
    ascii_img = ''
    for i in range(0, ascii_str_len, new_width):
        ascii_img += ascii_str[i:i + new_width] + '\n'

    print(ascii_img)

def random_website_logo(name: str) -> str:
    """
    Generates a website logo matching the name

    :param name: Name whose first two letters appear on the logo
    """

    size = 200
    background_color = tuple(random.randint(0, 255) for _ in range(3))

    from PIL import Image, ImageDraw, ImageFont

    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse([(0, 0), (size, size)], fill=background_color)

    brightness = 0.299 * background_color[0] + 0.587\
        * background_color[1] + 0.114 * background_color[2]
    text_color = (255, 255, 255) if brightness < 128 else (0, 0, 0)

    font = ImageFont.truetype(random_font(), 80)

    initials = name[:2].upper()

    text_bbox = draw.textbbox((0, 0), initials, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]
    text_position = ((size - text_width) // 2, (size - text_height) // 2)

    draw.text(text_position, initials, font=font, fill=text_color)

    image_buffer = BytesIO()
    image.save(image_buffer, format="PNG")

    image_base64 = b64encode(image_buffer.getvalue()).decode("utf-8")
    return "data:image/png;base64," + image_base64

def convert_image_to_base64(file_path: str) -> Optional[str]:
    """
    Converts an image file into Base64 Web Format

    :param file_path: The path to the image file
    """

    if not os.path.isfile(file_path):
        return

    try:
        with open(file_path, 'rb', encoding = "utf-8") as image_file:
            encoded_image = b64encode(image_file.read()).decode('utf-8')

            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = 'application/octet-stream'

            data_url = f'data:{mime_type};base64,{encoded_image}'

            return data_url
    except:
        return

def is_valid_image(image_data: bytes) -> bool:
    """
    Checks the validity of the given image data.

    :param image_data: Bytes representing the image.
    """

    try:
        import imghdr
        import magic

        image_format = imghdr.what(None, h=image_data)
        if not image_format:
            return False

        mime = magic.Magic()
        image_type = mime.from_buffer(image_data)

        allowed_types = ["image/jpeg", "image/png", "image/webp"]

        if image_type not in allowed_types:
            return False

        return True
    except:
        return False

def resize_image(image_data: bytes, target_size: tuple = (100, 100)) -> Optional[bytes]:
    """
    Resizes the given image data to the specified target size.

    :param image_data: Bytes representing the image.
    :param target_size: Tuple representing the target size (width, height).
    """

    try:
        from PIL import Image, ImageOps

        image = Image.open(BytesIO(image_data))
        resized_image = ImageOps.fit(image, target_size, method=0, bleed=0.0, centering=(0.5, 0.5))

        bytes_io = BytesIO()
        resized_image.save(bytes_io, format='WEBP', quality=85)

        return bytes_io.getvalue()
    except:
        return None

########################
#### Software Tools ####
########################

def macos_get_installer_and_volume_path() -> Tuple[Optional[str], Optional[str]]:
    "Function to automatically detect the macOS installer and the volume path"

    installer_path = None

    mounted_volumes = [volume for volume in os.listdir("/Volumes") if not volume.startswith(".")]
    if mounted_volumes:
        volume_name = mounted_volumes[0]
        volume_path = os.path.join("/Volumes", volume_name)

        for root, _, files in os.walk(volume_path):
            for file in files:
                if file.endswith(".app"):
                    installer_path = os.path.join(root, file)
                    break
        else:
            return None, None
    else:
        return None, None

    return installer_path, volume_path

DISTRO_TO_PACKAGE_MANAGER = {
    "ubuntu":
        {
            "installation_command": "apt-get install",
            "update_command": "apt-get update; apt-get upgrade"
        },
    "debian": 
        {
            "installation_command": "apt-get install",
            "update_command": "apt-get update; apt-get upgrade"
        },
    "fedora":
        {
            "installation_command": "dnf install",
            "update_command": "dnf upgrade"
        },
    "centos":
        {
            "installation_command": "yum install",
            "update_command": "yum update"
        },
    "arch":
        {
            "installation_command": "pacman -S",
            "update_command": "pacman -Syu"
        },
    "opensuse":
        {
            "installation_command": "zypper install",
            "update_command": "zypper update"
        },
    "linuxmint":
        {
            "installation_command": "apt-get install",
            "update_command": "apt-get update; apt-get upgrade"
        },
    "gentoo":
        {
            "installation_command": "emerge",
            "update_command": "emerge --sync"
        },
    "rhel":
        {
            "installation_command": "yum install",
            "update_command": "yum update"
        },
    "kali":
        {
            "installation_command": "apt-get install",
            "update_command": "apt-get update; apt-get upgrade"
        },
    "tails":
        {
            "installation_command": "apt-get install",
            "update_command": "apt-get update; apt-get upgrade"
        },
    "zorin":
        {
            "installation_command": "apt-get install",
            "update_command": "apt-get update; apt-get upgrade"
        },
    "mx":
        {
            "installation_command": "apt-get install",
            "update_command": "apt-get update; apt-get upgrade"
        },
    "solus":
        {
            "installation_command": "eopkg install",
            "update_command": "eopkg up"
        },
    "antergos":
        {
            "installation_command": "pacman -S",
            "update_command": "pacman -Syu"
        },
    "lubuntu":
        {
            "installation_command": "apt-get install",
            "update_command": "apt-get update; apt-get upgrade"
        },
    "xubuntu":
        {
            "installation_command": "apt-get install",
            "update_command": "apt-get update; apt-get upgrade"
        },
}

PACKAGE_MANAGERS = [
    {
        "version_command": "apt-get --version",
        "installation_command": "apt-get install",
        "update_command": "apt-get update; apt-get upgrade"
    },
    {
        "version_command": "dnf --version",
        "installation_command": "dnf install",
        "update_command": "dnf upgrade"
    },
    {
        "version_command": "yum --version",
        "installation_command": "yum install",
        "update_command": "yum update"
    },
    {
        "version_command": "pacman --version",
        "installation_command": "pacman -S",
        "update_command": "pacman -Syu"
    },
    {
        "version_command": "zypper --version",
        "installation_command": "zypper install",
        "update_command": "zypper update"
    },
    {
        "version_command": "emerge --version",
        "installation_command": "emerge",
        "update_command": "emerge --sync"
    },
    {
        "version_command": "eopkg --version",
        "installation_command": "eopkg install",
        "update_command": "eopkg up"
    }
]

class Linux:
    "Collection of functions that have something to do with Linux"

    @staticmethod
    def get_package_manager() -> Tuple[Optional[str], Optional[str]]:
        "Returns the Packet Manager install command and the update command"

        import distro

        distro_id = distro.id()

        package_manager = DISTRO_TO_PACKAGE_MANAGER.get(
            distro_id, {"installation_command": None, "update_command": None}
        )

        installation_command, update_command = \
            package_manager["installation_command"], package_manager["update_command"]

        if None in [installation_command, update_command]:
            for package_manager in PACKAGE_MANAGERS:
                try:
                    subprocess.check_call(package_manager["version_command"], shell=True)
                except:
                    pass
                else:
                    installation_command, update_command = \
                        package_manager["installation_command"], package_manager["update_command"]

        return installation_command, update_command

    @staticmethod
    def install_package(package_name: str, quite: bool = False) -> None:
        """
        Attempts to install a Linux package
        
        :param package_name: Name of the Linux packet
        :param quite: If True nothing is written to the console
        """

        if not quite:
            from rich.console import Console
            console = Console()

            with console.status("[green]Trying to get package manager..."):
                installation_command, update_command = Linux.get_package_manager()
            console.print(f"[green]~ Package Manager is `{installation_command.split(' ')[0]}`")

        if not None in [installation_command, update_command]:
            try:
                update_process = subprocess.Popen("sudo " + update_command, shell=True)
                update_process.wait()
            except Exception as e:
                if not quite:
                    print(f"""[Error] Error using update Command while
                          installing linux package '{package_name}': '{e}'""")

            with subprocess.Popen(
                f"sudo {installation_command} {package_name} -y",
                shell=True
                ) as install_process:
                install_process.wait()
        else:
            print("""[Error] No packet manager found for the current
                  Linux system, you seem to use a distribution we don't know?""")

        return None

class GnuPG:
    "All functions that have something to do with GnuPG"

    @property
    def path(self) -> str:
        "Function to query the GnuPG path"

        system = get_system_architecture()

        gnupg_path = {
            "Windows": r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
            "macOS": "/usr/local/bin/gpg"
        }.get(system, "/usr/bin/gpg")

        if os.path.isfile(gnupg_path):
            return gnupg_path

        command = {"Windows": "where gpg"}.get(system, "which gpg")

        try:
            result = subprocess.check_output(command, shell=True, text=True)
            gnupg_path = result.strip()
        except Exception as e:
            print(f"[Error] Error when requesting pgp: '{e}'\n")

        return gnupg_path

    @staticmethod
    def get_download_link(session: Optional[Any] = None) -> Optional[str]:
        """
        Request https://gnupg.org/download/ or https://gpgtools.org/
        to get the latest download link
        """

        import requests

        if session is None:
            requests.Session()

        system = get_system_architecture()

        url = {"Windows": "https://gnupg.org/download/"}.get(system, "https://gpgtools.org/")

        while True:
            try:
                response = session.get(
                    url,
                    headers={'User-Agent': random.choice(USER_AGENTS)},
                    timeout = 5
                )
                response.raise_for_status()
            except (requests.exceptions.ProxyError, requests.exceptions.ReadTimeout):
                session = requests.Session()
            else:
                break

        from bs4 import BeautifulSoup

        soup = BeautifulSoup(response.text, 'html.parser')
        anchors = soup.find_all('a')

        download_url = None
        for anchor in anchors:
            href = anchor.get('href')

            if href:
                if "/ftp/gcrypt/binary/gnupg-w32-" in href\
                        and ".exe" in href\
                            and not ".sig" in href\
                                and system == "Windows":
                    download_url = "https://gnupg.org" + href
                    break
                elif "https://releases.gpgtools.com/GPG_Suite-" in href\
                    and ".dmg" in href\
                        and not ".sig" in href\
                            and system == "macOS":
                    download_url = href
                    break

        return download_url

class Captcha:
    "Class to generate and verify a captcha"

    def __init__(self, captcha_secret: str, data: dict):
        """
        :param captcha_secret: A secret token that only the server knows to verify the captcha
        """

        self.captcha_secret = captcha_secret
        self.data = data

    def generate(self) -> Tuple[str, str]:
        "Generate a captcha for the client"

        image_captcha_code = random_string(secrets.choice([8,9,10,11,12]), with_punctuation=False)

        minimized_data = json.dumps(self.data, indent = None, separators = (',', ':'))
        captcha_prove = image_captcha_code + "//" + minimized_data

        crypted_captcha_prove = SymmetricEncryption(self.captcha_secret).encrypt(captcha_prove)

        from captcha.image import ImageCaptcha

        image_captcha = ImageCaptcha(width=320, height=120, fonts=FONTS)

        captcha_image = image_captcha.generate(image_captcha_code)
        captcha_image_data = b64encode(captcha_image.getvalue()).decode('utf-8')
        captcha_image_data = "data:image/png;base64," + captcha_image_data

        return captcha_image_data, crypted_captcha_prove

    def verify(self, client_input: str, crypted_captcha_prove: str) -> bool:
        """
        Verify a captcha

        :param client_input: The input from the client
        :param crypted_captcha_prove: The encrypted captcha prove generated by the generate function
        """

        try:
            captcha_prove = SymmetricEncryption(self.captcha_secret).decrypt(crypted_captcha_prove)

            captcha_code, data = captcha_prove.split("//")
            data = json.loads(data)
        except:
            return False

        return bool(not (data != self.data or captcha_code.lower() != client_input.lower()))
