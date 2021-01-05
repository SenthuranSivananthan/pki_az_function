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
            var randomKey = Crypto.RandomKey(32);

            // encrypt random key with public key (asymmetric key)
            var secretClient = new SecretClient(new Uri("https://sesivanpki.vault.azure.net"), credentials);
            var secret = await secretClient.GetSecretAsync("pkipublic");
            var x509 = new X509Certificate2(Convert.FromBase64String(secret.Value.Value));
            var randomKeyEncrypted = x509.GetRSAPublicKey().Encrypt(randomKey, RSAEncryptionPadding.OaepSHA1);

            // save random key as base64 encoded string
            envelope.Key = Convert.ToBase64String(randomKeyEncrypted);

            // encrypt data using random key (symmetric key)
            envelope.Data = Convert.ToBase64String(Crypto.Encrypt(randomKey, inputBlob));

            // save to output
            var serializedOutput = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(envelope));
            outputBlob.Write(serializedOutput, 0, serializedOutput.Length);

            log.LogInformation($"Encryption complete for {name}");
        }
    }
}
