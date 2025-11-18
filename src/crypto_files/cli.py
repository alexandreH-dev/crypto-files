
from __future__ import annotations
import argparse
import os
import sys
import tempfile
from pathlib import Path

from .key_management import (
    DEFAULT_KEY_DIR,
    DEFAULT_KEY_NAME,
    init_keys,
    load_private_key,
    load_public_key,
)
from .crypto_core import encrypt_file, decrypt_file, inspect_metadata


def human_size(n: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != 'B' else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def cmd_init_keys(args):
    priv, pub = init_keys(Path(args.key_dir), args.key_name)
    print(f"✔ Chaves geradas:
  Privada: {priv}
  Pública: {pub}")


def cmd_encrypt(args):
    pub = load_public_key(Path(args.key_dir), args.key_name)
    in_path = Path(args.input)
    out_path = Path(args.out) if args.out else None
    meta = encrypt_file(in_path, out_path, pub)
    out_final = Path(args.out) if args.out else in_path.with_suffix(in_path.suffix + ".cfen")

    print("✔ Arquivo criptografado com sucesso!")
    print(f"  Entrada:  {in_path}")
    print(f"  Saída:    {out_final}")
    print(f"  Tamanho:  {human_size(meta['input_size'])}")
    print(f"  Algoritmo:{meta['alg']} | Nonce: {meta['nonce']} | Tag: {meta['tag']}")
    print(f"  Fingerprint RSA: {meta['rsa_fingerprint']}")


def cmd_decrypt(args):
    priv = load_private_key(Path(args.key_dir), args.key_name)
    in_path = Path(args.input)
    if args.out:
        out_path = Path(args.out)
    else:
        out_path = in_path.with_suffix("") if in_path.suffix == ".cfen" else in_path.with_suffix(in_path.suffix + ".dec")

    try:
        meta = decrypt_file(in_path, out_path, priv)
        print("✔ Arquivo descriptografado com sucesso!")
        print(f"  Entrada:  {in_path}")
        print(f"  Saída:    {out_path}")
        print(f"  Algoritmo:{meta['alg']} | Data: {meta['created_at']}")
    except Exception as e:
        print("✖ Falha na descriptografia.")
        print(f"  Motivo: {e}")
        sys.exit(2)


def cmd_inspect(args):
    meta = inspect_metadata(Path(args.input))
    print("🔎 Metadados:")
    for k, v in meta.items():
        print(f"  {k}: {v}")


def cmd_self_test(_args):
    with tempfile.TemporaryDirectory() as tmpd:
        tmpd = Path(tmpd)
        data = os.urandom(256 * 1024)  # 256 KiB
        p = tmpd / "sample.bin"
        p.write_bytes(data)

        # Gere chaves em tmp para não tocar nas do usuário
        from .key_management import init_keys, load_private_key, load_public_key
        kd = tmpd / "keys"
        kd.mkdir(parents=True, exist_ok=True)
        os.environ['CRYPTOFILES_PASSPHRASE'] = 'testepass'
        init_keys(kd, 'temp')
        pub = load_public_key(kd, 'temp')
        enc_path = tmpd / "sample.bin.cfen"
        encrypt_file(p, enc_path, pub)

        priv = load_private_key(kd, 'temp')
        dec_path = tmpd / "sample.bin.dec"
        decrypt_file(enc_path, dec_path, priv)

        assert p.read_bytes() == dec_path.read_bytes()
        print("✔ Self-test OK: criptografia e integridade validadas.")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="crypto-files",
        description="Criptografe e descriptografe arquivos com AES-256-GCM e RSA-OAEP",
    )
    sub = parser.add_subparsers(dest='command', required=True)

    p1 = sub.add_parser('init-keys', help='Gerar par de chaves RSA (privada protegida por senha)')
    p1.add_argument('--key-dir', default=str(DEFAULT_KEY_DIR), help='Diretório das chaves (padrão: ~/.crypto_files/keys)')
    p1.add_argument('--key-name', default=DEFAULT_KEY_NAME, help='Nome base dos arquivos de chave (padrão: id_rsa)')
    p1.set_defaults(func=cmd_init_keys)

    p2 = sub.add_parser('encrypt', help='Criptografar arquivo')
    p2.add_argument('input', help='Arquivo de entrada')
    p2.add_argument('--out', help='Arquivo de saída (.cfen)', default=None)
    p2.add_argument('--key-dir', default=str(DEFAULT_KEY_DIR))
    p2.add_argument('--key-name', default=DEFAULT_KEY_NAME)
    p2.set_defaults(func=cmd_encrypt)

    p3 = sub.add_parser('decrypt', help='Descriptografar arquivo .cfen')
    p3.add_argument('input', help='Arquivo .cfen')
    p3.add_argument('--out', help='Arquivo de saída (opcional)', default=None)
    p3.add_argument('--key-dir', default=str(DEFAULT_KEY_DIR))
    p3.add_argument('--key-name', default=DEFAULT_KEY_NAME)
    p3.set_defaults(func=cmd_decrypt)

    p4 = sub.add_parser('inspect', help='Mostrar metadados de arquivo .cfen')
    p4.add_argument('input', help='Arquivo .cfen')
    p4.set_defaults(func=cmd_inspect)

    p5 = sub.add_parser('self-test', help='Executa um autoteste de criptografia/descriptografia')
    p5.set_defaults(func=cmd_self_test)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == '__main__':
    main()
