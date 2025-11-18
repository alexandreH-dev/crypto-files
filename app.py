import streamlit as st
import tempfile
import os
from pathlib import Path

from src.crypto_files.key_management import (
    DEFAULT_KEY_DIR,
    DEFAULT_KEY_NAME,
    init_keys,
    load_private_key,
    load_public_key,
)
from src.crypto_files.crypto_core import encrypt_file, decrypt_file, inspect_metadata


# -------------------------------------------------------------------
# Configuração inicial
# -------------------------------------------------------------------
st.set_page_config(page_title="Crypto Files", page_icon="🔐", layout="centered")
st.title("🔐 Crypto Files – Interface Gráfica (AES-256-GCM + RSA-OAEP)")

key_dir = Path(DEFAULT_KEY_DIR)
key_dir.mkdir(parents=True, exist_ok=True)


# ================================================================
# 1) GERAR CHAVES
# ================================================================
st.header("🔑 Gerar Par de Chaves RSA")

with st.expander("Gerar novas chaves RSA"):
    key_name = st.text_input("Nome base das chaves (ex: id_rsa)", value=DEFAULT_KEY_NAME)
    password = st.text_input("Senha da chave privada", type="password")

    if st.button("Gerar chaves RSA"):
        if not password:
            st.error("Informe uma senha para proteger a chave privada.")
        else:
            os.environ["CRYPTOFILES_PASSPHRASE"] = password
            priv, pub = init_keys(key_dir, key_name)
            st.success(f"Chaves geradas!\nPrivada: {priv}\nPública: {pub}")


# ================================================================
# 2) Carregar chave privada
# ================================================================
st.header("🔐 Carregar Chave Privada")

password_load = st.text_input("Senha da chave privada carregada", type="password")

private_key = None
if password_load:
    try:
        private_key = load_private_key(key_dir, DEFAULT_KEY_NAME, password_load.encode())
        st.success("Chave privada carregada!")
    except Exception as e:
        st.error(f"Falha ao carregar chave privada: {e}")


# ================================================================
# 3) CRIPTOGRAFAR ARQUIVO
# ================================================================
st.header("🔒 Criptografar Arquivo")

file_encrypt = st.file_uploader("Selecione o arquivo para criptografar", type=None)

if st.button("Criptografar arquivo"):
    if not file_encrypt:
        st.error("Selecione um arquivo antes.")
    else:
        # Salvar arquivo temporário
        temp_in = tempfile.NamedTemporaryFile(delete=False)
        temp_in.write(file_encrypt.read())
        temp_in.close()

        # Carregar chave pública
        try:
            pub_key = load_public_key(key_dir, DEFAULT_KEY_NAME)
        except Exception as e:
            st.error(f"Falha ao carregar chave pública: {e}")
            st.stop()

        temp_out = temp_in.name + ".cfen"

        meta = encrypt_file(Path(temp_in.name), Path(temp_out), pub_key)
        st.success("Arquivo criptografado com sucesso!")

        with open(temp_out, "rb") as f:
            st.download_button(
                "⬇ Baixar arquivo .cfen",
                f.read(),
                file_name=file_encrypt.name + ".cfen",
            )


# ================================================================
# 4) DESCRIPTOGRAFAR ARQUIVO
# ================================================================
st.header("🔓 Descriptografar Arquivo (.cfen)")

file_decrypt = st.file_uploader("Selecione o arquivo .cfen para descriptografar", type=["cfen"])

if st.button("Descriptografar arquivo"):
    if not file_decrypt:
        st.error("Envie um arquivo .cfen.")
    elif private_key is None:
        st.error("Carregue a chave privada antes.")
    else:
        # Salvar arquivo temporário
        temp_in = tempfile.NamedTemporaryFile(delete=False)
        temp_in.write(file_decrypt.read())
        temp_in.close()

        out_path = temp_in.name + "_dec"

        try:
            meta = decrypt_file(Path(temp_in.name), Path(out_path), private_key)
            st.success("Arquivo descriptografado!")

            with open(out_path, "rb") as f:
                st.download_button(
                    "⬇ Baixar arquivo descriptografado",
                    f.read(),
                    file_name=file_decrypt.name.replace(".cfen", ""),
                )

        except Exception as e:
            st.error(f"Falha na descriptografia: {e}")


# ================================================================
# 5) INSPECIONAR METADADOS
# ================================================================
st.header("🧐 Inspecionar Metadados (.cfen)")

file_inspect = st.file_uploader("Selecione um .cfen para visualizar metadados", type=["cfen"])

if st.button("Inspecionar metadados"):
    if not file_inspect:
        st.error("Selecione um arquivo .cfen.")
    else:
        temp_in = tempfile.NamedTemporaryFile(delete=False)
        temp_in.write(file_inspect.read())
        temp_in.close()

        try:
            meta = inspect_metadata(Path(temp_in.name))
            st.json(meta)
        except Exception as e:
            st.error(f"Erro ao ler metadados: {e}")
