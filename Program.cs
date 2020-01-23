using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AESEncrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            string inFile = @"C:\Users\jeremy.m.johnson120\Documents\Visual Studio 2017\Projects\repos\TestConsoleApps\AESEncrypt\ERMSMassLoad.zip";
            string encFile = @"C:\Users\jeremy.m.johnson120\Documents\Visual Studio 2017\Projects\repos\TestConsoleApps\AESEncrypt\ERMSMassLoad.zip.aes";
            string pass = string.Empty;

            AES_Encrypt(inFile, pass);
            AES_Decrypt(encFile, pass);
        }

        public static byte[] GenerateRandomSalt()
        {
            byte[] data = new byte[32];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                for (int i = 0; i < 10; i++)
                {
                    rng.GetBytes(data);
                }
            }
            return data;
        }

        private static void AES_Encrypt(string inputFile, string password)
        {
            var salt = GenerateRandomSalt();
            var AES = NewAESAlgorithm(Encoding.UTF8.GetBytes(password), salt);

            using (var fsCrypt = new FileStream(inputFile + ".aes", FileMode.Create))
            {
                fsCrypt.Write(salt, 0, salt.Length);
                using (var cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    using (var fsIn = new FileStream(inputFile, FileMode.Open))
                    {
                        byte[] buffer = new byte[1048576];
                        int read;
                        try
                        {
                            while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                cs.Write(buffer, 0, read);
                            }
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine("Error: " + ex.Message);
                        }
                    }
                }
            }
        }

        private static void AES_Decrypt(string inputFile, string password)
        {
            var fsCrypt = new FileStream(inputFile, FileMode.Open);
            byte[] salt = new byte[32];
            fsCrypt.Read(salt, 0, salt.Length);
            var AES = NewAESAlgorithm(Encoding.UTF8.GetBytes(password), salt);

            using (var cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read))
            {
                using (var fsOut = new FileStream(inputFile + ".decrypted", FileMode.Create))
                {
                    int read;
                    byte[] buffer = new byte[1048576];

                    try
                    {
                        while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            fsOut.Write(buffer, 0, read);
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine("Error: " + ex.Message);
                    }
                }
            }

            fsCrypt.Close();
        }

        private static SymmetricAlgorithm NewAESAlgorithm(byte[] passBytes, byte[] salt, int iterations = 50000)
        {
            var AES = new RijndaelManaged() { KeySize = 256, BlockSize = 128, Padding = PaddingMode.PKCS7, Mode = CipherMode.CFB };
            var key = new Rfc2898DeriveBytes(passBytes, salt, iterations);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            return AES;
        }
    }
}
