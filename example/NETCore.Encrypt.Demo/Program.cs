using System;
using NETCore.Encrypt.Internal;
using System.Diagnostics;
using System.Security.Cryptography;

namespace NETCore.Encrypt.Demo
{
    class Program
    {
        static void Main(string[] args)
        {

            var aesKey = EncryptProvider.CreateAesKey();
            var key = aesKey.Key;
            var iv = aesKey.IV;

            /*
            var _max = 10000;

            var s1 = Stopwatch.StartNew();

            for (int i = 0; i < _max; i++)
            {
                aesKey = EncryptProvider.CreateAesKey();
            }
            s1.Stop();

            var s2 = Stopwatch.StartNew();
            for (int i = 0; i < _max; i++)
            {
                aesKey = EncryptProvider.CreateAesKey(false);
            }
            s2.Stop();

            Console.WriteLine(((double)(s1.Elapsed.TotalMilliseconds * 1000000) / _max).ToString("0.00 ns"));
            Console.WriteLine(((double)(s2.Elapsed.TotalMilliseconds * 1000000) / _max).ToString("0.00 ns"));
            Console.Read();
            */

            var plaintext = "Hello world";
            var encrypted = EncryptProvider.AESEncrypt(plaintext, key, iv);
            var decrypted = EncryptProvider.AESDecrypt(encrypted, key, iv);

            Console.WriteLine("Plaintext to encrypt: " + plaintext);
            Console.WriteLine();

            Console.WriteLine("** AES SecureRandom **");
            Console.WriteLine("Encrypted: " + encrypted);
            Console.WriteLine("Decrypted: " + decrypted);
            Console.WriteLine("Key: {0} IV: {1}", key, iv);


            Console.WriteLine();
            Console.WriteLine("** AES Non-SecureRandom **");

            aesKey = EncryptProvider.CreateAesKey(false);
            key = aesKey.Key;
            iv = aesKey.IV;

            encrypted = EncryptProvider.AESEncrypt(plaintext, key, iv);
            decrypted = EncryptProvider.AESDecrypt(encrypted, key, iv);
            Console.WriteLine("Encrypted: " + encrypted);
            Console.WriteLine("Decrypted: " + decrypted);
            Console.WriteLine("Key: {0} IV: {1}", key, iv);

            Console.WriteLine();
            Console.WriteLine("** RSA **");
            var rsaKey = EncryptProvider.CreateRsaKey();

            var publicKey = rsaKey.PublicKey;
            var privateKey = rsaKey.PrivateKey;
            //var exponent = rsaKey.Exponent;
            //var modulus = rsaKey.Modulus;

            encrypted = EncryptProvider.RSAEncrypt(publicKey, plaintext);

            encrypted = EncryptProvider.RSAEncrypt(publicKey, plaintext, RSAEncryptionPadding.Pkcs1);
            decrypted = EncryptProvider.RSADecrypt(privateKey, encrypted, RSAEncryptionPadding.Pkcs1);


            Console.WriteLine("Encrypted: " + encrypted);
            Console.WriteLine("Decrypted: " + decrypted);
            //Console.WriteLine("publicKey: {0} privateKey: {1}", publicKey, privateKey);

            Console.WriteLine();
            Console.WriteLine("** SHA **");
            Console.WriteLine("SHA1: " + EncryptProvider.Sha1(plaintext));
            Console.WriteLine("SHA256: " + EncryptProvider.Sha256(plaintext));
            Console.WriteLine("SHA384: " + EncryptProvider.Sha384(plaintext));
            Console.WriteLine("SHA512: " + EncryptProvider.Sha512(plaintext));

            Console.ReadKey();
        }
    }
}