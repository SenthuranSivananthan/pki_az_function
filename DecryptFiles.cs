using System;
using System.IO;
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
            var decryptedData = Crypto.Decrypt(decryptedRandomKey.Plaintext, Convert.FromBase64String(envelope.Data));
            outputBlob.Write(decryptedData, 0, decryptedData.Length);

            log.LogInformation($"Decryption complete for {name}.json");
        }
    }
}
