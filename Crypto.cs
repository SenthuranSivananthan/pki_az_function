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

        public static byte[] Encrypt(byte[] key, Stream data)  
        {  
            byte[] iv = new byte[16];  

            using (Aes aes = Aes.Create())  
            {  
                aes.Key = key;
                aes.IV = iv; 
                aes.Padding = PaddingMode.Zeros; 

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);  

                using (MemoryStream memoryStream = new MemoryStream())  
                {  
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))  
                    {  
                        data.CopyTo(cryptoStream);

                        memoryStream.Flush();
                        memoryStream.Position = 0;                        
                        return memoryStream.ToArray();  
                    }  
                }  
            }
        }

        public static byte[] Decrypt(byte[] key, byte[] cipherText)  
        {  
            byte[] iv = new byte[16];  
            byte[] buffer = cipherText;
  
            using (Aes aes = Aes.Create())  
            {  
                aes.Key = key;
                aes.IV = iv;  
                aes.Padding = PaddingMode.Zeros;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);  
  
                using (MemoryStream memoryStream = new MemoryStream(buffer))  
                {  
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))  
                    {  
                        var decrypted = new MemoryStream();
                        cryptoStream.CopyTo(decrypted);

                        return decrypted.ToArray();
                    }
                }  
            }  
        }
    }
}