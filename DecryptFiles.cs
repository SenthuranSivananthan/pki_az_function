using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Company.Function
{
    public static class DecryptFiles
    {
        // credit: https://www.c-sharpcorner.com/article/encryption-and-decryption-using-a-symmetric-key-in-c-sharp/
        public static string DecryptString(byte[] key, byte[] cipherText)  
        {  
            byte[] iv = new byte[16];  
            byte[] buffer = cipherText;
  
            using (Aes aes = Aes.Create())  
            {  
                aes.Key = key;
                aes.IV = iv;  
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);  
  
                using (MemoryStream memoryStream = new MemoryStream(buffer))  
                {  
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))  
                    {  
                        using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))  
                        {  
                            return streamReader.ReadToEnd();  
                        }  
                    }  
                }  
            }  
        }
        
        [FunctionName("DecryptFiles")]
        public static async Task Run(
            [BlobTrigger("encrypted/{name}.json", Connection = "sesivanpki_STORAGE")]TextReader inputBlob,
            [Blob("decrypted/{name}", FileAccess.Write, Connection = "sesivanpki_STORAGE")]Stream outputBlob,
            string name, ILogger log)
        {
            log.LogInformation($"C# Blob trigger function Processed blob\n Name:{name}.json");

            var envelope = JsonConvert.DeserializeObject<EncryptionEnvelope>(inputBlob.ReadToEnd());

            // Decrypt the random key
            var credentials = new AzureCliCredential();
            var keyClient = new KeyClient(new Uri("https://sesivanpki.vault.azure.net"), credentials);
            var privateKey = await keyClient.GetKeyAsync("pkiprivate");

            var cryptoClient = new CryptographyClient(privateKey.Value.Id, credentials);
            var decryptedRandomKey = cryptoClient.Decrypt(EncryptionAlgorithm.RsaOaep, Convert.FromBase64String(envelope.Key));

            // Use random key to decrypt data
            var decryptedData = DecryptString(decryptedRandomKey.Plaintext, Convert.FromBase64String(envelope.Data));
            var decryptedBase64Data = Convert.FromBase64String(decryptedData);
            var decryptedOriginalData = Encoding.UTF8.GetString(decryptedBase64Data, 0, decryptedBase64Data.Length);

            var decryptedOriginalDataBytes = Encoding.UTF8.GetBytes(decryptedOriginalData);
            outputBlob.Write(decryptedOriginalDataBytes, 0, decryptedOriginalDataBytes.Length);

            log.LogInformation($"Decryption complete for {name}.json");
        }
    }
}
