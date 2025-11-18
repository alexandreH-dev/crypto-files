from __future__ import annotations
import json
import os
import tempfile
from pathlib import Path
from typing import BinaryIO, Dict, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

from .utils import B64, B64D, utc_now_iso, ensure_parent_dir, sha256_hex

MAGIC = b"CFENC1"  # Crypto Files ENC v1
HDR_LEN = len(MAGIC)

DEFAULT_CHUNK = 64 * 1024  # 64 KiB


def _pubkey_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_hex(der)


def encrypt_file(in_path: Path, out_path: Optional[Path], public_key, chunk_size: int = DEFAULT_CHUNK) -> Dict:
    in_path = Path(in_path)
    if out_path is None:
        out_path = in_path.with_suffix(in_path.suffix + ".cfen")
    out_path = Path(out_path)

    ensure_parent_dir(out_path)

    # 1) Chave AES e nonce
    key = os.urandom(32)   # AES-256
    nonce = os.urandom(12) # GCM 96-bit

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # 2) Criptografar streaming para temp file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = Path(tmp.name)
        with open(in_path, 'rb') as fin:
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                if ct:
                    tmp.write(ct)
        encryptor.finalize()

    tag = encryptor.tag

    # 3) Encapsular a chave AES com RSA-OAEP
    enc_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    metadata = {
        "alg": "AES-256-GCM",
        "nonce": B64(nonce).decode(),
        "tag": B64(tag).decode(),
        "chunk_size": chunk_size,
        "created_at": utc_now_iso(),
        "orig_name": in_path.name,
        "rsa_fingerprint": _pubkey_fingerprint(public_key),
        "enc_key": B64(enc_key).decode(),
        "input_size": in_path.stat().st_size,
    }

    meta_bytes = json.dumps(metadata, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    meta_len = len(meta_bytes).to_bytes(4, 'big')

    # 4) Escrever arquivo final: header + metadados + ciphertext
    with open(out_path, 'wb') as fout:
        fout.write(MAGIC)
        fout.write(meta_len)
        fout.write(meta_bytes)
        with open(tmp_path, 'rb') as ct_in:
            while True:
                chunk = ct_in.read(chunk_size)
                if not chunk:
                    break
                fout.write(chunk)

    os.remove(tmp_path)
    return metadata


def _read_header_and_metadata(f: BinaryIO) -> Dict:
    magic = f.read(HDR_LEN)
    if magic != MAGIC:
        raise ValueError("Formato inválido ou arquivo corrompido (magic mismatch).")
    meta_len_bytes = f.read(4)
    if len(meta_len_bytes) != 4:
        raise ValueError("Cabeçalho inválido (tamanho de metadados).")
    meta_len = int.from_bytes(meta_len_bytes, 'big')
    meta = f.read(meta_len)
    try:
        metadata = json.loads(meta.decode('utf-8'))
    except Exception as e:
        raise ValueError(f"Metadados inválidos: {e}")
    return metadata


def decrypt_file(in_path: Path, out_path: Optional[Path], private_key, chunk_size_fallback: int = DEFAULT_CHUNK) -> Dict:
    in_path = Path(in_path)
    if out_path is None:
        # Remover apenas a última extensão .cfen, se existir
        out_path = in_path.with_suffix("") if in_path.suffix == ".cfen" else in_path.with_suffix(in_path.suffix + ".dec")
    out_path = Path(out_path)
    ensure_parent_dir(out_path)

    with open(in_path, 'rb') as fin:
        metadata = _read_header_and_metadata(fin)
        nonce = B64D(metadata["nonce"])  # 12 bytes
        tag = B64D(metadata["tag"])      # 16 bytes
        enc_key = B64D(metadata["enc_key"])  # RSA-encrypted AES key
        chunk_size = int(metadata.get("chunk_size", chunk_size_fallback))

        # Recuperar chave AES
        key = private_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        with open(out_path, 'wb') as fout:
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                pt = decryptor.update(chunk)
                if pt:
                    fout.write(pt)
            # finalize() valida a tag – InvalidTag => arquivo adulterado/senha errada
            try:
                final = decryptor.finalize()
                if final:
                    fout.write(final)
            except Exception as e:
                # Se falhar, apaga arquivo de saída para não deixar lixo parcial
                try:
                    os.remove(out_path)
                except Exception:
                    pass
                raise

    return metadata


def inspect_metadata(in_path: Path) -> Dict:
    with open(in_path, 'rb') as f:
        metadata = _read_header_and_metadata(f)
    return metadata