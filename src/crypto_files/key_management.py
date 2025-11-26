from __future__ import annotations
import os
from getpass import getpass
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

DEFAULT_KEY_DIR = Path.home() / "keys"
DEFAULT_KEY_NAME = "id_rsa"


def _key_paths(key_dir: Path = DEFAULT_KEY_DIR, key_name: str = DEFAULT_KEY_NAME):
    print(f"Generating key paths in directory: {key_dir} with base name: {key_name}")
    priv = key_dir / f"{key_name}_priv.pem"
    pub = key_dir / f"{key_name}_pub.pem"
    return priv, pub


def init_keys(key_dir: Path = DEFAULT_KEY_DIR, key_name: str = DEFAULT_KEY_NAME, passphrase: Optional[bytes] = None) -> tuple[Path, Path]:
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = _key_paths(key_dir, key_name)

    if passphrase is None:
        env = os.getenv("CRYPTOFILES_PASSPHRASE")
        if env:
            passphrase = env.encode()
        else:
            passphrase = getpass("Defina a senha da chave privada: ").encode()
            confirm = getpass("Confirme a senha: ").encode()
            if passphrase != confirm:
                raise ValueError("As senhas não conferem.")

    # Gerar RSA 4096
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    public_key = private_key.public_key()

    # Serializar privada com proteção
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Gravar em disco
    priv_path.write_bytes(pem_priv)
    os.chmod(priv_path, 0o600)
    pub_path.write_bytes(pem_pub)

    return priv_path, pub_path


def load_public_key(key_dir: Path = DEFAULT_KEY_DIR, key_name: str = DEFAULT_KEY_NAME):
    _, pub_path = _key_paths(key_dir, key_name)
    pem = pub_path.read_bytes()
    return serialization.load_pem_public_key(pem, backend=default_backend())


def load_private_key(key_dir: Path = DEFAULT_KEY_DIR, key_name: str = DEFAULT_KEY_NAME, passphrase: Optional[bytes] = None):
    priv_path, _ = _key_paths(key_dir, key_name)

    if passphrase is None:
        env = os.getenv("CRYPTOFILES_PASSPHRASE")
        if env:
            passphrase = env.encode()
        else:
            from getpass import getpass
            passphrase = getpass("Senha da chave privada: ").encode()

    pem = priv_path.read_bytes()
    return serialization.load_pem_private_key(pem, password=passphrase, backend=default_backend())