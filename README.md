# PKI with Azure Storage Blobs & Azure Key Vault

## Approach

**Encryption**

1. Create a random 32-byte key (random key) that will be used to encrypt the data.

2. Encrypt the random key using the `public key`.

3. Encrypt the data (blobs in Azure Storage) using AES & random key.

4. Serialize the key, encrypted data and file name into JSON.

**Decryption**

1. Deserialize the JSON payload.

2. Decrypt the random key using the `private key`.

3. Decrypt the data using the random key.

4. Save the decrypted data with the file name (part of JSON payload).

## Create certificates

Create public and private keys based on RSA 2048

```
openssl req -x509  -days 365 -newkey rsa:2048 -keyout private.pem -out public.pem -nodes
```

Create PFXs

```
openssl pkcs12 -in public.pem -inkey private.pem -export -out public_key.pfx -nokeys

openssl pkcs12 -in private.pem -inkey private.pem -export -out private_key.pfx -nocerts
```

## Azure Setup

Configure Azure Key Vault

1. Import `private_key.pfx` to Keys in Azure Key Vault
2. Import `public_key.pfx` to Secrets in Azure Key Vault

Configure Azure Storage

1. Create container `raw`
2. Create container `encrypted`
3. Create container `decrypted`

Flow:

1. Unencrypted files will be uploaded to `raw`.

2. Files in `raw` are processed by an Azure Function to encrypt and upload to `encrypted` container.  The encrypted data is stored in JSON format.  The content includes a base64 encoded `random key` & `encrypted data` and original file name

3. Files in `encrypted` are processed by an Azure Function to decrypt.s