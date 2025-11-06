import os, base64, hashlib
from typing import Tuple
from hashlib import sha256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERS = 100000  


def derive_key(password: str, salt: bytes = None) -> Tuple[bytes, str]:
    if salt is None:
        salt = os.urandom(32)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)
        
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERS)
    # print(key)
    return key, salt.hex()

def master_key_hash(key: bytes) -> str:
    return sha256(key).hexdigest()


def encrypt(plaintext: str, key: bytes):
    aesgcm = AESGCM(key)  

    iv = os.urandom(12)  

    ct = aesgcm.encrypt(iv, plaintext.encode(), None)  

    return iv.hex(), base64.b64encode(ct).decode()  

def decrypt(iv_hex: str, ct_b64: str, key: bytes) -> str:
    aesgcm = AESGCM(key)  

    iv     = bytes.fromhex(iv_hex) 

    ct     = base64.b64decode(ct_b64)   

    return aesgcm.decrypt(iv, ct, None).decode()

