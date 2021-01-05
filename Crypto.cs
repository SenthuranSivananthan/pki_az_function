using System;
using System.IO;
using System.Security.Cryptography;

namespace Company.Function
{
    public static class Crypto
    {
        
        public static byte[] RandomKey(int length)
        {
            var rng = RandomNumberGenerator.Create();
            byte[] key = new byte[length];
            rng.GetBytes(key);

            return key;
        }
        
        // credit: https://www.c-sharpcorner.com/article/encryption-and-decryption-using-a-symmetric-key-in-c-sharp/
        public static string Encrypt(byte[] key, string plainText)  
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

        // credit: https://www.c-sharpcorner.com/article/encryption-and-decryption-using-a-symmetric-key-in-c-sharp/
        public static string Decrypt(byte[] key, byte[] cipherText)  
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
    }
}