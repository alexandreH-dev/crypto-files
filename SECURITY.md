# Segurança – Notas e Recomendações

## Ameaças abordadas
- Exposição acidental de arquivos: conteúdo protegido por AES-256-GCM.
- Alteração maliciosa/troca de bits: detectada pelo **GCM tag** na descriptografia.
- Interceptação da chave simétrica: chave AES é protegida por **RSA-OAEP (SHA-256)**.

## Limitações e considerações
- **Gestão de senhas**: a proteção do PEM usa uma senha. Use um gerenciador de senhas; considere **HSM**/TPM quando possível.
- **Backups**: faça backup seguro da **chave privada** – sem ela, você **não recupera** os arquivos.
- **Rotação de chaves**: não implementa recriptação em lote. Estratégia sugerida: manter fingerprints por arquivo; para rotação, descriptografar e recriptografar com a nova chave pública.
- **Integridade do executável ambiente**: este projeto não aborda *supply chain* do Python/host.
- **Malware**: não impede que você criptografe malware; combine com antivírus e varreduras.
- **Nonce reuse**: evitado por gerar nonce aleatório por arquivo. Nunca reutilize nonce com a **mesma** chave AES.

## Dicas operacionais
- Restrinja permissões da pasta `~/.crypto_files/keys/` (ex.: 700 no Linux/macOS).
- Nunca envie sua **chave privada** por e-mail/IM. Compartilhe **apenas** a chave pública.
- Valide checksums/assine o zip do projeto se distribuir para terceiros.