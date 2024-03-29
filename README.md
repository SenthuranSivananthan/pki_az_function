# PKI with Azure Storage Blobs & Azure Key Vault

> This is a prototype to help understand how PKI based encryption.  **The source code is not to be used in production and shared under MIT license.**

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

Create public and private keys based on RSA 2048.

```
openssl req -x509  -days 365 -newkey rsa:2048 -keyout private.pem -out public.pem -nodes
```

Create PFXs

```
openssl pkcs12 -in public.pem -inkey private.pem -export -out public_key.pfx -nokeys

openssl pkcs12 -in private.pem -inkey private.pem -export -out private_key.pfx -nocerts
```

## Azure Setup

**Configure Azure Key Vault**

1. Import `private_key.pfx` to Keys in Azure Key Vault
2. Import `public_key.pfx` to Secrets in Azure Key Vault

**Configure Azure Storage**

1. Create container `raw`
2. Create container `encrypted`
3. Create container `decrypted`

**Flow**

1. Unencrypted files will be uploaded to `raw`.

2. Files in `raw` are processed by an Azure Function to encrypt and upload to `encrypted` container.  The encrypted data is stored in JSON format.  The content includes a base64 encoded `random key` & `encrypted data` and original file name

3. Files in `encrypted` are processed by an Azure Function to decrypt.

## Example Outputs

**Raw file**

File name:  test.txt

```text
hello world
hello senthuran
hello senthuran sivananthan
```

**Encrypted file**

File name:  test.txt.json

```json
{
  "Key": "UB0SGli00b+0++33cGhWZ4uJMJi2z6bhF1pj2/X0bpsDQxn22mvYagSJfeC8xmOoakcbQ2FXT6jt4MtdLlHJVyBQCg2ERjPFjIJrRNUqowOTLU3Gd9D90Ecgqw7i7auW6xDBhi5R9sUjzGHZKNX9jWuzgDr/Ks0/GQJLSdqpFKbFor6mwONSbFtOXDRkNgOIJnvOou+M0DF72W60v+g3h7tkWg4+Ot0UbIzP/NXEUyX04ABofSXjtJB1E2q2WBQ8Sr/VhH0chGJ3Prj6Y4YlVUTH6kUwQt6B38wWFL0sKcYk80e51VkwtZmJh2T0X20ehKWwy554enhZqYwd7KUjkg==",
  "Data": "sPaiCq1Wtcb687jDNkh9BlQCz2nk+gosFju8UR62Kb00iMyyZb0rlXvZVSu/UyUV",
  "FileName": "test.txt"
}
```

## Reference

* [Encryption and decryption via the envelope technique](https://docs.microsoft.com/en-us/azure/storage/common/storage-client-side-encryption?tabs=dotnet)
