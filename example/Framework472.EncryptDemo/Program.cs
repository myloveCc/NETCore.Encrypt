using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NETCore.Encrypt;
using System.IO;
using System.Security.Cryptography;

namespace Framework472.EncryptDemo
{
    class Program
    {
        static void Main(string[] args)
        {

            Console.WriteLine();
            Console.WriteLine("** Test issues #25 on .net framework 4.7.2  https://github.com/myloveCc/NETCore.Encrypt/issues/25 **");

            Console.WriteLine();
            var privateKeyPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "privateKey.txt");

            if (!File.Exists(privateKeyPath))
            {
                Console.WriteLine();
                Console.WriteLine("Not found file privateKey.txt");
                Console.WriteLine();
                Console.WriteLine("Run project NETCore.Encrypt.Demo first");
                Console.ReadKey();
                return;
            }

            var privateKey = string.Empty;

            using (StreamReader sr = new StreamReader(privateKeyPath))
            {
                privateKey = sr.ReadToEnd();
            }

            Console.WriteLine();
            Console.WriteLine($"private key：{privateKey}");

            if (string.IsNullOrEmpty(privateKey))
            {
                Console.WriteLine();
                Console.WriteLine("Private key is null or empty");
                Console.WriteLine();
                Console.WriteLine("Run project NETCore.Encrypt.Demo first");
                Console.ReadKey();
                return;
            }

            var encryptedFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "encrypt.txt");

            if (!File.Exists(encryptedFilePath))
            {
                Console.WriteLine("Not found file encrypt.txt");
                Console.WriteLine();
                Console.WriteLine("Run project NETCore.Encrypt.Demo first");
                Console.ReadKey();
                return;
            }

            var encryptStr = string.Empty;

            using (StreamReader sr = new StreamReader(encryptedFilePath))
            {
                encryptStr = sr.ReadToEnd();
            }

            Console.WriteLine();
            Console.WriteLine($"Encrypt str：{encryptStr}");


            if (string.IsNullOrEmpty(encryptStr))
            {
                Console.WriteLine();
                Console.WriteLine("Encrypt str is null or empty");

                Console.WriteLine();
                Console.WriteLine("Run project NETCore.Encrypt.Demo first");

                Console.ReadKey();
                return;
            }

            Console.WriteLine();
            Console.WriteLine($"--------------Start descrypt-------------------");

            var decryptedStr = EncryptProvider.RSADecrypt(privateKey, encryptStr, RSAEncryptionPadding.Pkcs1);
            Console.WriteLine();
            Console.WriteLine($"Decrypted str:{decryptedStr}");

            Console.ReadKey();
        }
    }
}
