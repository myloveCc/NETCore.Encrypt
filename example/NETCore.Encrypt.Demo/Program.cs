using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

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

            var plaintext = "Hello world 123456789/*-+!@#$%^&*()-=_+";
            var encrypted = EncryptProvider.AESEncrypt(plaintext, key, iv);
            var decrypted = EncryptProvider.AESDecrypt(encrypted, key, iv);

            Console.WriteLine("Plaintext to encrypt: " + plaintext);
            Console.WriteLine();

            Console.WriteLine("** AES SecureRandom **");
            Console.WriteLine("Encrypted " + " (Length: " + encrypted.Length + ") " + encrypted);
            Console.WriteLine("Decrypted " + " (Length: " + decrypted.Length + ") " + decrypted);
            Console.WriteLine("Key: {0} IV: {1}", key, iv);

            Console.WriteLine();
            Console.WriteLine("** AES SecureRandom with Byte input/output **");
            byte[] bencrypted = EncryptProvider.AESEncrypt(Encoding.UTF8.GetBytes(plaintext), key, iv);
            byte[] bdecrypted = EncryptProvider.AESDecrypt(bencrypted, key, iv);

            Console.WriteLine("Encrypted " + " (Length: " + bencrypted.Length + ") " + Encoding.UTF8.GetString(bencrypted));
            Console.WriteLine("Decrypted " + " (Length: " + bdecrypted.Length + ") " + Encoding.UTF8.GetString(bdecrypted));
            Console.WriteLine("Key: {0} IV: {1}", key, iv);

            Console.WriteLine();

            Console.WriteLine("** AES Non-SecureRandom **");

            aesKey = EncryptProvider.CreateAesKey();
            key = aesKey.Key;
            iv = aesKey.IV;

            encrypted = EncryptProvider.AESEncrypt(plaintext, key, iv);
            decrypted = EncryptProvider.AESDecrypt(encrypted, key, iv);
            Console.WriteLine("Encrypted " + " (Length: " + encrypted.Length + ") " + encrypted);
            Console.WriteLine("Decrypted " + " (Length: " + decrypted.Length + ") " + decrypted);
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


            Console.WriteLine();
            Console.WriteLine("** Test issues #25  https://github.com/myloveCc/NETCore.Encrypt/issues/25 **");

            rsaKey = EncryptProvider.CreateRsaKey();

            publicKey = rsaKey.PublicKey;
            privateKey = rsaKey.PrivateKey;

            var testStr = "test issues #25 ";

            Console.WriteLine($"Test str:{testStr}");

            var saveDir = AppDomain.CurrentDomain.BaseDirectory;

            //save public key
            var publicKeySavePath = Path.Combine(saveDir, "privateKey.txt");
            if (File.Exists(publicKeySavePath))
            {
                File.Delete(publicKeySavePath);
            }
            using (FileStream fs = new FileStream(publicKeySavePath, FileMode.CreateNew))
            {
                fs.Write(Encoding.UTF8.GetBytes(privateKey));
            }

            //save encrypt text
            var encryptStr = EncryptProvider.RSAEncrypt(publicKey, testStr, RSAEncryptionPadding.Pkcs1);
            Console.WriteLine($"encryped str:{encryptStr}");
            var encryptSavePath = Path.Combine(saveDir, "encrypt.txt");

            if (File.Exists(encryptSavePath))
            {
                File.Delete(encryptSavePath);
            }

            using (FileStream fs = new FileStream(encryptSavePath, FileMode.CreateNew))
            {
                fs.Write(Encoding.UTF8.GetBytes(encryptStr));
            }

            Console.ReadKey();


        }
    }
}