using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Company.Function
{
    public static class EncryptFiles
    {
        [FunctionName("EncryptFiles")]
        public static async Task Run(
            [BlobTrigger("raw/{name}", Connection = "sesivanpki_STORAGE")]Stream inputBlob,
            [Blob("encrypted/{name}.json", FileAccess.Write, Connection = "sesivanpki_STORAGE")]Stream outputBlob,
            string name, ILogger log)
        {
            log.LogInformation($"C# Blob trigger function Processed blob\n Name:{name} \n Size: {inputBlob.Length} Bytes");

            var envelope = new EncryptionEnvelope();
            envelope.FileName = name;

            var credentials = new AzureCliCredential();

            // generate random key
            var randomKey = RandomKey(32);

            // encrypt random key with public key (asymmetric key)
            var secretClient = new SecretClient(new Uri("https://sesivanpki.vault.azure.net"), credentials);
            var secret = await secretClient.GetSecretAsync("pkipublic");
            var x509 = new X509Certificate2(Convert.FromBase64String(secret.Value.Value));
            var randomKeyEncrypted = x509.GetRSAPublicKey().Encrypt(randomKey, RSAEncryptionPadding.OaepSHA1);

            // save random key as base64 encoded string
            envelope.Key = Convert.ToBase64String(randomKeyEncrypted);

            // encode data to base64
            var data = new byte[inputBlob.Length];
            inputBlob.Read(data, 0, (int)inputBlob.Length);
            var dataAsBase64 = Convert.ToBase64String(data);

            // encrypt data using random key (symmetric key)
            envelope.Data = EncryptString(randomKey, dataAsBase64);

            // save to output
            var serializedOutput = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(envelope));
            outputBlob.Write(serializedOutput, 0, serializedOutput.Length);

            log.LogInformation($"Encryption complete for {name}");
        }

        public static byte[] RandomKey(int length)
        {
            var rng = RandomNumberGenerator.Create();
            byte[] key = new byte[length];
            rng.GetBytes(key);

            return key;
        }

        // credit: https://www.c-sharpcorner.com/article/encryption-and-decryption-using-a-symmetric-key-in-c-sharp/
        public static string EncryptString(byte[] key, string plainText)  
        {  
            byte[] iv = new byte[16];  
            byte[] array;  

            using (Aes aes = Aes.Create())  
            {  
                aes.Key = key;
                aes.IV = iv;  

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);  

                using (MemoryStream memoryStream = new MemoryStream())  
                {  
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))  
                    {  
                        using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))  
                        {  
                            streamWriter.Write(plainText);  
                        }  

                        array = memoryStream.ToArray();  
                    }  
                }  
            }  

            return Convert.ToBase64String(array);  
        }
    }
}
