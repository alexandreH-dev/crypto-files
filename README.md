# 🔐 Crypto Files (Python)

**Criptografe e descriptografe arquivos** com segurança usando **AES-256-GCM** (simétrico) e **RSA-OAEP com SHA-256** (assimétrico), via **linha de comando**.

> Projeto acadêmico para a disciplina *Segurança no Ciberespaço* – implementa **envelope encryption**: cada arquivo é protegido com uma chave AES aleatória, que é, por sua vez, protegida com a **chave pública RSA** do usuário.

## ✨ Recursos
- **AES-256-GCM** com **nonce aleatório** e **autenticidade integrada** (tag GCM).
- **RSA-4096 OAEP** (SHA-256) para proteger a chave AES de cada arquivo.
- **Formato de arquivo próprio** com cabeçalho e metadados (JSON) contendo algoritmo, nonce, fingerprint da chave RSA, etc.
- **Streaming** de criptografia/decodificação (suporta arquivos grandes sem carregar tudo na memória).
- **Chave privada protegida por senha** (PKCS#8 + `BestAvailableEncryption`).
- **CLI** ergonomica: `init-keys`, `encrypt`, `decrypt`, `inspect`, `self-test`.

## 🧱 Arquitetura
- `crypto_files/crypto_core.py`: criptografia simétrica + formato do arquivo.
- `crypto_files/key_management.py`: geração, carga e proteção de chaves RSA.
- `crypto_files/cli.py`: interface de linha de comando.
- `crypto_files/utils.py`: utilidades (hashes, base64, datas, I/O segura).

## 🔧 Instalação
Requer **Python 3.9+**.

```bash
# 1) (opcional) criar venv
python -m venv .venv && source .venv/bin/activate  # (Windows: .venv\Scripts\activate)

# 2) instalar dependências
pip install -r requirements.txt

# 3) rodar via CMD
python -m crypto_files.cli --help
# ou, se instalar via pyproject (opcional)
pip install -e .
crypto-files --help

# 4) rodar via interface
streamlit run app.py
```

## 🔑 Geração de chaves
Gere um **par RSA** protegido por senha (será salvo em `~/.crypto_files/keys/`):

```bash
python -m crypto_files.cli init-keys
```

Saídas padrão:
- `~/.crypto_files/keys/id_rsa_priv.pem` (privada **criptografada**)
- `~/.crypto_files/keys/id_rsa_pub.pem` (pública)

> **Dica:** a senha **não** fica registrada no histórico do shell. Você também pode fornecê-la via variável de ambiente `CRYPTOFILES_PASSPHRASE` (apenas quando necessário; avalie os riscos em seu ambiente).

## 🔒 Criptografar um arquivo
```bash
python -m crypto_files.cli encrypt caminho/arquivo.pdf
# Saída: caminho/arquivo.pdf.cfen (mesma pasta por padrão)
```
Opções úteis:
- `--out`: define caminho de saída manualmente.
- `--key-dir`/`--key-name`: usar outro local/identificador de chave.

## 🔓 Descriptografar
```bash
python -m crypto_files.cli decrypt caminho/arquivo.pdf.cfen
# Saída: caminho/arquivo.pdf (restaurado)
```
Se a senha da chave privada não estiver exportada, será solicitada no terminal.

## 🧐 Inspecionar metadados
```bash
python -m crypto_files.cli inspect caminho/arquivo.pdf.cfen
```
Exibe algoritmo, nonce, fingerprint da chave pública usada, data de criação, nome original, etc.

## 🧪 Auto-teste rápido
```bash
python -m crypto_files.cli self-test
```
Cria um arquivo temporário, criptografa, descriptografa e valida integridade.

## 🧰 Formato do arquivo `.cfen`
```
[6 bytes]  Magic: CFENC1
[4 bytes]  Tamanho do JSON de metadados (big-endian)
[...   ]   Metadados JSON (UTF-8)
[...   ]   Ciphertext (bytes)
```

Campos principais dos **metadados**:
- `alg`: `AES-256-GCM`
- `nonce`: base64 URL-safe (12 bytes)
- `tag`: base64 URL-safe (16 bytes)
- `chunk_size`: tamanho do bloco usado no streaming
- `created_at`: ISO 8601 (UTC)
- `orig_name`: nome original do arquivo
- `rsa_fingerprint`: SHA-256 da chave pública (DER), em hex
- `enc_key`: chave AES criptografada com RSA-OAEP (base64 URL-safe)

## 🛡️ Boas práticas implementadas
- **AES-GCM** (AEAD): confidencialidade + integridade.
- **Nonce único** por arquivo (12 bytes aleatórios).
- **RSA-OAEP (SHA-256)** para encapsular a chave simétrica.
- **Chave privada** em `PKCS#8` com `BestAvailableEncryption` (derivação + AES-256-CBC).
- **Streaming**: evita picos de memória para arquivos grandes.
- **Erros explícitos** e mensagens claras quando a integridade falha (tag GCM inválida).

> Consulte `SECURITY.md` para ameaças cobertas, limites e recomendações de produção (HSM, rotação de chaves, backups, varredura de malware, etc.).

## 📄 Licença
[MIT](LICENSE)