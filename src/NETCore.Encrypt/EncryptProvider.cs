using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using NETCore.Encrypt.Shared;
using NETCore.Encrypt.Extensions;
using NETCore.Encrypt.Internal;
using NETCore.Encrypt.Extensions.Internal;
using System.Security.Cryptography.X509Certificates;

namespace NETCore.Encrypt
{
    public class EncryptProvider
    {
        #region Common

        /// <summary>
        /// The single Random Generator
        /// </summary>
        private static Random random;

        /// <summary>
        /// Generate a random key
        /// </summary>
        /// <param name="n">key length，IV is 16，Key is 32</param>
        /// <returns>return random value</returns>
        private static string GetRandomStr(int length)
        {
            char[] arrChar = new char[]{
           'a','b','d','c','e','f','g','h','i','j','k','l','m','n','p','r','q','s','t','u','v','w','z','y','x',
           '0','1','2','3','4','5','6','7','8','9',
           'A','B','C','D','E','F','G','H','I','J','K','L','M','N','Q','P','R','T','S','V','U','W','X','Y','Z'
          };

            StringBuilder num = new StringBuilder();

            //New stronger Random Generator
            if (random == null)
            {
                random = new Random();
            }

            for (int i = 0; i < length; i++)
            {
                num.Append(arrChar[random.Next(0, arrChar.Length)].ToString());
            }

            return num.ToString();
        }


        #endregion

        #region AES

        /*
        AES: 16-bit key=128 bits, 24-bit key=192 bits, 32-bit key=256 bits, IV is 16 bits
        */

        /// <summary>
        /// Create ase key
        /// </summary>
        /// <returns></returns>
        public static AESKey CreateAesKey()
        {
            return new AESKey()
            {
                Key = GetRandomStr(32),
                IV = GetRandomStr(16)
            };
        }

        /// <summary>
        /// AES encrypt
        /// </summary>
        /// <param name="data">Raw data</param>
        /// <param name="key">Key, requires 32 bits</param>
        /// <param name="vector">IV,requires 16 bits</param>
        /// <returns>Encrypted string</returns>
        public static string AESEncrypt(string data, string key, string vector)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));

            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 32, nameof(key));

            Check.Argument.IsNotEmpty(vector, nameof(vector));
            Check.Argument.IsEqualLength(vector.Length, 16, nameof(vector));

            byte[] plainBytes = Encoding.UTF8.GetBytes(data);

            var encryptBytes = AESEncrypt(plainBytes, key, vector);
            if (encryptBytes == null)
            {
                return null;
            }
            return Convert.ToBase64String(encryptBytes);
        }

        /// <summary>
        /// AES encrypt
        /// </summary>
        /// <param name="data">Raw data</param>
        /// <param name="key">Key, requires 32 bits</param>
        /// <param name="vector">IV,requires 16 bits</param>
        /// <returns>Encrypted byte array</returns>
        public static byte[] AESEncrypt(byte[] data, string key, string vector)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));

            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 32, nameof(key));

            Check.Argument.IsNotEmpty(vector, nameof(vector));
            Check.Argument.IsEqualLength(vector.Length, 16, nameof(vector));

            byte[] plainBytes = data;
            byte[] bKey = new byte[32];
            Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);
            byte[] bVector = new byte[16];
            Array.Copy(Encoding.UTF8.GetBytes(vector.PadRight(bVector.Length)), bVector, bVector.Length);

            byte[] encryptData = null; // encrypted data
            using (Aes Aes = Aes.Create())
            {
                try
                {
                    using (MemoryStream memory = new MemoryStream())
                    {
                        using (CryptoStream Encryptor = new CryptoStream(memory,
                         Aes.CreateEncryptor(bKey, bVector),
                         CryptoStreamMode.Write))
                        {
                            Encryptor.Write(plainBytes, 0, plainBytes.Length);
                            Encryptor.FlushFinalBlock();

                            encryptData = memory.ToArray();
                        }
                    }
                }
                catch
                {
                    encryptData = null;
                }
                return encryptData;
            }
        }

        /// <summary>
        ///  AES decrypt
        /// </summary>
        /// <param name="data">Encrypted data</param>
        /// <param name="key">Key, requires 32 bits</param>
        /// <param name="vector">IV,requires 16 bits</param>
        /// <returns>Decrypted string</returns>
        public static string AESDecrypt(string data, string key, string vector)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));

            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 32, nameof(key));

            Check.Argument.IsNotEmpty(vector, nameof(vector));
            Check.Argument.IsEqualLength(vector.Length, 16, nameof(vector));

            byte[] encryptedBytes = Convert.FromBase64String(data);

            byte[] decryptBytes = AESDecrypt(encryptedBytes, key, vector);

            if (decryptBytes == null)
            {
                return null;
            }
            return Encoding.UTF8.GetString(decryptBytes);
        }

        /// <summary>
        ///  AES decrypt
        /// </summary>
        /// <param name="data">Encrypted data</param>
        /// <param name="key">Key, requires 32 bits</param>
        /// <param name="vector">IV,requires 16 bits</param>
        /// <returns>Decrypted byte array</returns>

        public static byte[] AESDecrypt(byte[] data, string key, string vector)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));

            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 32, nameof(key));

            Check.Argument.IsNotEmpty(vector, nameof(vector));
            Check.Argument.IsEqualLength(vector.Length, 16, nameof(vector));

            byte[] encryptedBytes = data;
            byte[] bKey = new byte[32];
            Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);
            byte[] bVector = new byte[16];
            Array.Copy(Encoding.UTF8.GetBytes(vector.PadRight(bVector.Length)), bVector, bVector.Length);

            byte[] decryptedData = null; // decrypted data

            using (Aes Aes = Aes.Create())
            {
                try
                {
                    using (MemoryStream memory = new MemoryStream(encryptedBytes))
                    {
                        using (CryptoStream decryptor = new CryptoStream(memory, Aes.CreateDecryptor(bKey, bVector), CryptoStreamMode.Read))
                        {
                            using (MemoryStream tempMemory = new MemoryStream())
                            {
                                byte[] Buffer = new byte[1024];
                                Int32 readBytes = 0;
                                while ((readBytes = decryptor.Read(Buffer, 0, Buffer.Length)) > 0)
                                {
                                    tempMemory.Write(Buffer, 0, readBytes);
                                }

                                decryptedData = tempMemory.ToArray();
                            }
                        }
                    }
                }
                catch
                {
                    decryptedData = null;
                }

                return decryptedData;
            }
        }

        /// <summary>
        /// AES encrypt ( no IV)
        /// </summary>
        /// <param name="data">Raw data</param>
        /// <param name="key">Key, requires 32 bits</param>
        /// <returns>Encrypted string</returns>
        public static string AESEncrypt(string data, string key)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 32, nameof(key));

            using (MemoryStream memory = new MemoryStream())
            {
                using (Aes aes = Aes.Create())
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(data);
                    byte[] bKey = new byte[32];
                    Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);

                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = 256;
                    aes.Key = bKey;

                    using (CryptoStream cryptoStream = new CryptoStream(memory, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        try
                        {
                            cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                            cryptoStream.FlushFinalBlock();
                            return Convert.ToBase64String(memory.ToArray());
                        }
                        catch (Exception ex)
                        {
                            return null;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// AES decrypt( no IV)
        /// </summary>
        /// <param name="data">Encrypted data</param>
        /// <param name="key">Key, requires 32 bits</param>
        /// <returns>Decrypted string</returns>
        public static string AESDecrypt(string data, string key)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 32, nameof(key));

            byte[] encryptedBytes = Convert.FromBase64String(data);
            byte[] bKey = new byte[32];
            Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);

            try
            {
                byte[] decryptedData = null; // decrypted data

                using (MemoryStream memory = new MemoryStream(encryptedBytes))
                {
                    using (Aes aes = Aes.Create())
                    {
                        aes.Mode = CipherMode.ECB;
                        aes.Padding = PaddingMode.PKCS7;
                        aes.KeySize = 256;
                        aes.Key = bKey;

                        using (CryptoStream decryptor = new CryptoStream(memory, aes.CreateDecryptor(), CryptoStreamMode.Read))
                        {
                            using (MemoryStream tempMemory = new MemoryStream())
                            {
                                byte[] buffer = new byte[1024];
                                Int32 readBytes = 0;
                                while ((readBytes = decryptor.Read(buffer, 0, buffer.Length)) > 0)
                                {
                                    tempMemory.Write(buffer, 0, readBytes);
                                }

                                decryptedData = tempMemory.ToArray();
                                return Encoding.UTF8.GetString(decryptedData);
                            }
                        }
                    }
                }
            }
            catch
            {
                return null;
            }
        }


        #endregion

        #region DES

        /// <summary>
        /// Create des key
        /// </summary>
        /// <returns></returns>
        public static string CreateDesKey()
        {
            return GetRandomStr(24);
        }

        /// <summary>
        /// Create des iv
        /// </summary>
        /// <returns></returns>
        public static string CreateDesIv()
        {
            return GetRandomStr(8);
        }

        /// <summary>
        /// DES encrypt
        /// </summary>
        /// <param name="data">Raw data</param>
        /// <param name="key">Key, requires 24 bits</param>
        /// <returns>Encrypted string</returns>
        public static string DESEncrypt(string data, string key)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 24, nameof(key));

            byte[] plainBytes = Encoding.UTF8.GetBytes(data);
            var encryptBytes = DESEncrypt(plainBytes, key, CipherMode.ECB);

            if (encryptBytes == null)
            {
                return null;
            }
            return Convert.ToBase64String(encryptBytes);
        }

        /// <summary>
        /// DES encrypt
        /// </summary>
        /// <param name="data">Raw data byte array</param>
        /// <param name="key">Key, requires 24 bits</param>
        /// <returns>Encrypted byte array</returns>
        public static byte[] DESEncrypt(byte[] data, string key)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 24, nameof(key));

            return DESEncrypt(data, key, CipherMode.ECB);
        }


        /// <summary>
        /// DES encrypt
        /// </summary>
        /// <param name="data">Raw data byte array</param>
        /// <param name="key">Key, requires 24 bits</param>
        /// <param name="vector">IV,requires 8 bits</param>
        /// <returns>Encrypted byte array</returns>
        public static byte[] DESEncrypt(byte[] data, string key, string vector)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 24, nameof(key));
            Check.Argument.IsNotEmpty(vector, nameof(vector));
            Check.Argument.IsEqualLength(vector.Length, 8, nameof(vector));

            return DESEncrypt(data, key, CipherMode.CBC, vector);
        }

        /// <summary>
        /// DES encrypt
        /// </summary>
        /// <param name="data">Raw data</param>
        /// <param name="key">Key, requires 24 bits</param>
        /// <param name="cipherMode"><see cref="CipherMode"/></param>
        /// <param name="paddingMode"><see cref="PaddingMode"/> default is PKCS7</param>
        /// <param name="vector">IV,requires 8 bits</param>
        /// <returns>Encrypted byte array</returns>
        private static byte[] DESEncrypt(byte[] data, string key, CipherMode cipherMode, string vector = "", PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 24, nameof(key));

            using (MemoryStream Memory = new MemoryStream())
            {
                using (TripleDES des = TripleDES.Create())
                {
                    byte[] plainBytes = data;
                    byte[] bKey = new byte[24];
                    Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);

                    des.Mode = cipherMode;
                    des.Padding = paddingMode;
                    des.Key = bKey;

                    if (cipherMode == CipherMode.CBC)
                    {
                        byte[] bVector = new byte[8];
                        Array.Copy(Encoding.UTF8.GetBytes(vector.PadRight(bVector.Length)), bVector, bVector.Length);
                        des.IV = bVector;
                    }

                    using (CryptoStream cryptoStream = new CryptoStream(Memory, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        try
                        {
                            cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                            cryptoStream.FlushFinalBlock();
                            return Memory.ToArray();
                        }
                        catch (Exception ex)
                        {
                            return null;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// DES decrypt
        /// </summary>
        /// <param name="data">Encrypted data</param>
        /// <param name="key">Key, requires 24 bits</param>
        /// <returns>Decrypted string</returns>
        public static string DESDecrypt(string data, string key)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 24, nameof(key));

            byte[] encryptedBytes = Convert.FromBase64String(data);
            byte[] bytes = DESDecrypt(encryptedBytes, key, CipherMode.ECB);

            if (bytes == null)
            {
                return null;
            }
            return Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// DES decrypt
        /// </summary>
        /// <param name="data">Encrypted data byte array</param>
        /// <param name="key">Key, requires 24 bits</param>
        /// <returns>Decrypted string</returns>
        public static byte[] DESDecrypt(byte[] data, string key)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 24, nameof(key));

            return DESDecrypt(data, key, CipherMode.ECB);
        }

        /// <summary>
        /// DES encrypt
        /// </summary>
        /// <param name="data">Raw data byte array</param>
        /// <param name="key">Key, requires 24 bits</param>
        /// <param name="vector">IV,requires 8 bits</param>
        /// <returns>Encrypted byte array</returns>
        public static byte[] DESDecrypt(byte[] data, string key, string vector)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 24, nameof(key));
            Check.Argument.IsNotEmpty(vector, nameof(vector));
            Check.Argument.IsEqualLength(vector.Length, 8, nameof(vector));

            return DESDecrypt(data, key, CipherMode.CBC, vector);
        }

        /// <summary>
        /// DES decrypt
        /// </summary>
        /// <param name="data">Encrypted data</param>
        /// <param name="key">Key, requires 24 bits</param>
        /// <param name="cipherMode"><see cref="CipherMode"/></param>
        /// <param name="paddingMode"><see cref="PaddingMode"/> default is PKCS7</param>
        /// <returns>Decrypted byte array</returns>
        private static byte[] DESDecrypt(byte[] data, string key, CipherMode cipherMode, string vector = "", PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsEqualLength(key.Length, 24, nameof(key));

            byte[] encryptedBytes = data;
            byte[] bKey = new byte[24];
            Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);

            using (MemoryStream Memory = new MemoryStream(encryptedBytes))
            {
                using (TripleDES des = TripleDES.Create())
                {
                    des.Mode = cipherMode;
                    des.Padding = paddingMode;
                    des.Key = bKey;

                    if (cipherMode == CipherMode.CBC)
                    {
                        byte[] bVector = new byte[8];
                        Array.Copy(Encoding.UTF8.GetBytes(vector.PadRight(bVector.Length)), bVector, bVector.Length);
                        des.IV = bVector;
                    }

                    using (CryptoStream cryptoStream = new CryptoStream(Memory, des.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        try
                        {
                            byte[] tmp = new byte[encryptedBytes.Length];
                            int len = cryptoStream.Read(tmp, 0, encryptedBytes.Length);
                            byte[] ret = new byte[len];
                            Array.Copy(tmp, 0, ret, 0, len);
                            return ret;
                        }
                        catch
                        {
                            return null;
                        }
                    }
                }
            }
        }

        #endregion

        #region RSA

        /// <summary>
        /// RSA Converter to pem
        /// </summary>
        /// <param name="isPKCS8">true:PKCS8 false:PKCS1</param>
        /// <param name="keySize">Rsa key size ,default is 2048, min value is 2048</param>
        /// <returns></returns>
        public static (string publicPem, string privatePem) RSAToPem(bool isPKCS8, int keySize = 2048)
        {
            if (keySize < 2048)
            {
                throw new ArgumentException($" Key size min value is 2048!");
            }

            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = keySize;

                var publicPem = RsaProvider.ToPem(rsa, false, isPKCS8);
                var privatePem = RsaProvider.ToPem(rsa, true, isPKCS8);

                return (publicPem, privatePem);
            }
        }

        /// <summary>
        /// RSA From pem
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        public static RSA RSAFromPem(string pem)
        {
            Check.Argument.IsNotEmpty(pem, nameof(pem));
            return RsaProvider.FromPem(pem);
        }

        /// <summary>
        /// Export Rsa PKCS1 key
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static (string publicPkcs1, string privatePkcs1) RsaToPkcs1(int keySize = 2048)
        {
            if (keySize < 2048)
            {
                throw new ArgumentException($" Key size min value is 2048!");
            }

            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = keySize;
                var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

                return (publicKey, privateKey);
            }
        }

        /// <summary>
        /// Export Rsa PKCS8 key
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static (string publicPkcs8, string privatePkcs8) RsaToPkcs8(int keySize = 2048)
        {
            if (keySize < 2048)
            {
                throw new ArgumentException($" Key size min value is 2048!");
            }

            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = keySize;

                var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                var privateKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());

                return (publicKey, privateKey);
            }
        }

        /// <summary>
        /// RSA From pkcs public key
        /// </summary>
        /// <param name="pkcsKey"></param>
        /// <returns></returns>
        public static RSA RSAFromPublicPkcs(string pkcsKey)
        {
            return RSAFromPkcs(pkcsKey, false);
        }

        /// <summary>
        ///  RSA From pkcs #1 private key
        /// </summary>
        /// <param name="pkcsKey"></param>
        /// <returns></returns>
        public static RSA RSAFromPrivatePkcs1(string pkcsKey)
        {
            return RSAFromPkcs(pkcsKey, true);
        }

        /// <summary>
        ///  RSA From pkcs #8 private key
        /// </summary>
        /// <param name="pkcsKey"></param>
        /// <returns></returns>
        public static RSA RSAFromPrivatePkcs8(string pkcsKey)
        {
            return RSAFromPkcs(pkcsKey, true, true);
        }

        /// <summary>
        /// RSA From pkcs#1 or pkcs#8
        /// </summary>
        /// <param name="pkcsKey">Pkcs #1 or Pkcs #8</param>
        /// <param name="isPrivateKey">true:privateKey,false:publicKey</param>
        /// <param name="isPKCS8">true:PKCS8 false:PKCS1</param>
        /// <returns></returns>
        public static RSA RSAFromPkcs(string pkcsKey, bool isPrivateKey, bool isPKCS8 = false)
        {
            Check.Argument.IsNotEmpty(pkcsKey, nameof(pkcsKey));

            RSA rsa = RSA.Create();

            var keySource = Convert.FromBase64String(pkcsKey);

            if (!isPrivateKey)
            {
                try
                {
                    rsa.ImportRSAPublicKey(keySource, out _);
                }
                catch
                {
                    rsa.ImportSubjectPublicKeyInfo(keySource, out _);
                }
            }
            else
            {
                if (isPKCS8)
                {
                    rsa.ImportPkcs8PrivateKey(keySource, out _);
                }
                else
                {
                    rsa.ImportRSAPrivateKey(keySource, out _);
                }
            }

            return rsa;

        }

        /// <summary>
        /// RSA Sign
        /// </summary>
        /// <param name="conent">raw cotent </param>
        /// <param name="privateKey">private key</param>
        /// <returns></returns>
        public static string RSASign(string conent, string privateKey)
        {
            return RSASign(conent, privateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, Encoding.UTF8);
        }

        /// <summary>
        /// RSA Sign
        /// </summary>
        /// <param name="content">raw content </param>
        /// <param name="privateKey">private key</param>
        /// <param name="hashAlgorithmName">hashAlgorithm name</param>
        /// <param name="rSASignaturePadding">ras siginature padding</param>
        /// <param name="encoding">text encoding</param>
        /// <returns></returns>
        public static string RSASign(string content, string privateKey, HashAlgorithmName hashAlgorithmName, RSASignaturePadding rSASignaturePadding, Encoding encoding)
        {
            Check.Argument.IsNotEmpty(content, nameof(content));
            Check.Argument.IsNotEmpty(privateKey, nameof(privateKey));
            Check.Argument.IsNotNull(rSASignaturePadding, nameof(rSASignaturePadding));

            byte[] dataBytes = encoding.GetBytes(content);

            using (RSA rsa = RSA.Create())
            {
                rsa.FromJsonString(privateKey);
                var signBytes = rsa.SignData(dataBytes, hashAlgorithmName, rSASignaturePadding);

                return Convert.ToBase64String(signBytes);
            }
        }

        /// <summary>
        /// RSA Verify
        /// </summary>
        /// <param name="content">raw content</param>
        /// <param name="signStr">sign str</param>
        /// <param name="publickKey">public key</param>
        /// <returns></returns>
        public static bool RSAVerify(string content, string signStr, string publickKey)
        {
            return RSAVerify(content, signStr, publickKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, Encoding.UTF8);
        }

        /// <summary>
        /// RSA Verify
        /// </summary>
        /// <param name="content">raw content</param>
        /// <param name="signStr">sign str</param>
        /// <param name="publickKey">public key</param>
        /// <param name="hashAlgorithmName">hashAlgorithm name</param>
        /// <param name="rSASignaturePadding">ras siginature padding</param>
        /// <param name="encoding">text encoding</param>
        /// <returns></returns>
        public static bool RSAVerify(string content, string signStr, string publickKey, HashAlgorithmName hashAlgorithmName, RSASignaturePadding rSASignaturePadding, Encoding encoding)
        {
            Check.Argument.IsNotEmpty(content, nameof(content));
            Check.Argument.IsNotEmpty(signStr, nameof(signStr));

            byte[] dataBytes = encoding.GetBytes(content);
            byte[] signBytes = Convert.FromBase64String(signStr);

            using (RSA rsa = RSA.Create())
            {
                rsa.FromJsonString(publickKey);
                return rsa.VerifyData(dataBytes, signBytes, hashAlgorithmName, rSASignaturePadding);
            }
        }

        /// <summary>
        /// RSA encrypt
        /// </summary>
        /// <param name="publicKey">public key</param>
        /// <param name="srcString">src string</param>
        /// <returns>encrypted string</returns>
        public static string RSAEncrypt(string publicKey, string srcString)
        {
            string encryptStr = RSAEncrypt(publicKey, srcString, RSAEncryptionPadding.OaepSHA512);
            return encryptStr;
        }

        /// <summary>
        /// RSA encrypt with pem key
        /// </summary>
        /// <param name="publicKey">pem public key</param>
        /// <param name="srcString">src string</param>
        /// <returns></returns>
        public static string RSAEncryptWithPem(string publicKey, string srcString)
        {
            string encryptStr = RSAEncrypt(publicKey, srcString, RSAEncryptionPadding.Pkcs1, true);
            return encryptStr;
        }

        /// <summary>
        /// RSA encrypt
        /// </summary>
        /// <param name="publicKey">public key</param>
        /// <param name="srcString">src string</param>
        /// <param name="padding">rsa encryptPadding <see cref="RSAEncryptionPadding"/> RSAEncryptionPadding.Pkcs1 for linux/mac openssl </param>
        /// <param name="isPemKey">set key is pem format,default is false</param>
        /// <returns>encrypted string</returns>
        public static string RSAEncrypt(string publicKey, string srcString, RSAEncryptionPadding padding, bool isPemKey = false)
        {
            Check.Argument.IsNotEmpty(publicKey, nameof(publicKey));
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            Check.Argument.IsNotNull(padding, nameof(padding));

            RSA rsa;
            if (isPemKey)
            {
                rsa = RsaProvider.FromPem(publicKey);
            }
            else
            {
                rsa = RSA.Create();
                rsa.FromJsonString(publicKey);
            }

            using (rsa)
            {
                var maxLength = GetMaxRsaEncryptLength(rsa, padding);
                var rawBytes = Encoding.UTF8.GetBytes(srcString);

                if (rawBytes.Length > maxLength)
                {
                    throw new OutofMaxlengthException($"'{srcString}' is out of max encrypt length {maxLength}", maxLength, rsa.KeySize, padding);
                }

                byte[] encryptBytes = rsa.Encrypt(rawBytes, padding);
                return encryptBytes.ToHexString();
            }
        }

        /// <summary>
        /// RSA encrypt
        /// </summary>
        /// <param name="publicKey">public key</param>
        /// <param name="data">data byte[]</param>
        /// <returns>encrypted byte[]</returns>
        public static byte[] RSAEncrypt(string publicKey, byte[] data)
        {
            byte[] encryptBytes = RSAEncrypt(publicKey, data, RSAEncryptionPadding.OaepSHA512);
            return encryptBytes;
        }

        /// <summary>
        /// RSA encrypt with pem key
        /// </summary>
        /// <param name="publicKey">pem public key</param>
        /// <param name="data">data byte[]</param>
        /// <returns></returns>
        public static byte[] RSAEncryptWithPem(string publicKey, byte[] data)
        {
            byte[] encryptBytes = RSAEncrypt(publicKey, data, RSAEncryptionPadding.Pkcs1, true);
            return encryptBytes;
        }

        /// <summary>
        /// RSA encrypt
        /// </summary>
        /// <param name="publicKey">public key</param>
        /// <param name="data">data byte[]</param>
        /// <param name="padding">rsa encryptPadding <see cref="RSAEncryptionPadding"/> RSAEncryptionPadding.Pkcs1 for linux/mac openssl </param>
        /// <param name="isPemKey">set key is pem format,default is false</param>
        /// <returns>encrypted byte[]</returns>
        public static byte[] RSAEncrypt(string publicKey, byte[] data, RSAEncryptionPadding padding, bool isPemKey = false)
        {
            Check.Argument.IsNotEmpty(publicKey, nameof(publicKey));
            Check.Argument.IsNotNull(data, nameof(data));
            Check.Argument.IsNotNull(padding, nameof(padding));

            RSA rsa;
            if (isPemKey)
            {
                rsa = RsaProvider.FromPem(publicKey);
            }
            else
            {
                rsa = RSA.Create();
                rsa.FromJsonString(publicKey);
            }

            using (rsa)
            {
                var maxLength = GetMaxRsaEncryptLength(rsa, padding);
                var rawBytes = data;

                if (rawBytes.Length > maxLength)
                {
                    throw new OutofMaxlengthException($"data is out of max encrypt length {maxLength}", maxLength, rsa.KeySize, padding);
                }

                byte[] encryptBytes = rsa.Encrypt(rawBytes, padding);
                return encryptBytes;
            }
        }

        /// <summary>
        /// RSA decrypt
        /// </summary>
        /// <param name="privateKey">private key</param>
        /// <param name="srcString">encrypted string</param>
        /// <returns>Decrypted string</returns>
        public static string RSADecrypt(string privateKey, string srcString)
        {
            string decryptStr = RSADecrypt(privateKey, srcString, RSAEncryptionPadding.OaepSHA512);
            return decryptStr;
        }

        /// <summary>
        /// RSA decrypt with pem key
        /// </summary>
        /// <param name="privateKey">pem private key</param>
        /// <param name="scrString">src string</param>
        /// <returns></returns>
        public static string RSADecryptWithPem(string privateKey, string srcString)
        {
            string decryptStr = RSADecrypt(privateKey, srcString, RSAEncryptionPadding.Pkcs1, true);
            return decryptStr;
        }

        /// <summary>
        /// RSA encrypt
        /// </summary>
        /// <param name="publicKey">public key</param>
        /// <param name="srcString">src string</param>
        /// <param name="padding">rsa encryptPadding <see cref="RSAEncryptionPadding"/> RSAEncryptionPadding.Pkcs1 for linux/mac openssl </param>
        /// <param name="isPemKey">set key is pem format,default is false</param>
        /// <returns>encrypted string</returns>
        public static string RSADecrypt(string privateKey, string srcString, RSAEncryptionPadding padding, bool isPemKey = false)
        {
            Check.Argument.IsNotEmpty(privateKey, nameof(privateKey));
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            Check.Argument.IsNotNull(padding, nameof(padding));

            RSA rsa;
            if (isPemKey)
            {
                rsa = RsaProvider.FromPem(privateKey);
            }
            else
            {
                rsa = RSA.Create();
                rsa.FromJsonString(privateKey);
            }

            using (rsa)
            {
                byte[] srcBytes = srcString.ToBytes();
                byte[] decryptBytes = rsa.Decrypt(srcBytes, padding);
                return Encoding.UTF8.GetString(decryptBytes);
            }
        }

        /// <summary>
        /// RSA decrypt
        /// </summary>
        /// <param name="privateKey">private key</param>
        /// <param name="data">encrypted byte[]</param>
        /// <returns>Decrypted string</returns>
        public static byte[] RSADecrypt(string privateKey, byte[] data)
        {
            byte[] decryptBytes = RSADecrypt(privateKey, data, RSAEncryptionPadding.OaepSHA512);
            return decryptBytes;
        }

        /// <summary>
        /// RSA decrypt with pem key
        /// </summary>
        /// <param name="privateKey">pem private key</param>
        /// <param name="data">encrypted byte[]</param>
        /// <returns></returns>
        public static byte[] RSADecryptWithPem(string privateKey, byte[] data)
        {
            byte[] decryptBytes = RSADecrypt(privateKey, data, RSAEncryptionPadding.Pkcs1, true);
            return decryptBytes;
        }

        /// <summary>
        /// RSA encrypt
        /// </summary>
        /// <param name="publicKey">public key</param>
        /// <param name="data">src string</param>
        /// <param name="padding">rsa encryptPadding <see cref="RSAEncryptionPadding"/> RSAEncryptionPadding.Pkcs1 for linux/mac openssl </param>
        /// <param name="isPemKey">set key is pem format,default is false</param>
        /// <returns>encrypted string</returns>
        public static byte[] RSADecrypt(string privateKey, byte[] data, RSAEncryptionPadding padding, bool isPemKey = false)
        {
            Check.Argument.IsNotEmpty(privateKey, nameof(privateKey));
            Check.Argument.IsNotNull(data, nameof(data));
            Check.Argument.IsNotNull(padding, nameof(padding));

            RSA rsa;
            if (isPemKey)
            {
                rsa = RsaProvider.FromPem(privateKey);
            }
            else
            {
                rsa = RSA.Create();
                rsa.FromJsonString(privateKey);
            }

            using (rsa)
            {
                byte[] srcBytes = data;
                byte[] decryptBytes = rsa.Decrypt(srcBytes, padding);
                return decryptBytes;
            }
        }

        /// <summary>
        /// RSA from json string
        /// </summary>
        /// <param name="rsaKey">rsa json string</param>
        /// <returns></returns>
        [Obsolete("This method is obsoleted,please use RSAFromJson method!")]
        public static RSA RSAFromString(string rsaKey)
        {
            Check.Argument.IsNotEmpty(rsaKey, nameof(rsaKey));
            RSA rsa = RSA.Create();

            rsa.FromJsonString(rsaKey);
            return rsa;
        }

        /// <summary>
        /// RSA from json string
        /// </summary>
        /// <param name="rsaKey">rsa json key</param>
        /// <returns></returns>
        public static RSA RSAFromJson(string rsaKey)
        {
            Check.Argument.IsNotEmpty(rsaKey, nameof(rsaKey));
            RSA rsa = RSA.Create();

            rsa.FromJsonString(rsaKey);
            return rsa;
        }

        /// <summary>
        /// Create an RSA key
        /// </summary>
        /// <param name="keySizeInBits">the default size is 2048</param>
        /// <returns></returns>
        public static RSAKey CreateRsaKey(RsaSize rsaSize = RsaSize.R2048)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = (int)rsaSize;

                string publicKey = rsa.ToJsonString(false);
                string privateKey = rsa.ToJsonString(true);

                return new RSAKey()
                {
                    PublicKey = publicKey,
                    PrivateKey = privateKey,
                    Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                    Modulus = rsa.ExportParameters(false).Modulus.ToHexString()
                };
            }
        }

        /// <summary>
        /// Create an RSA key
        /// </summary>
        /// <param name="rsa">rsa</param>
        /// <param name="includePrivate"></param>
        /// <returns></returns>
        public static RSAKey CreateRsaKey(RSA rsa, bool includePrivate = true)
        {
            Check.Argument.IsNotNull(rsa, nameof(rsa));

            string publicKey = rsa.ToJsonString(false);

            var rsaKey = new RSAKey()
            {
                PublicKey = publicKey,

                Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                Modulus = rsa.ExportParameters(false).Modulus.ToHexString()
            };

            if (includePrivate)
            {
                string privateKey = rsa.ToJsonString(true);
                rsaKey.PrivateKey = privateKey;
            }
            return rsaKey;
        }

        /// <summary>
        /// Get rsa encrypt max length
        /// </summary>
        /// <param name="rsa">Rsa instance </param>
        /// <param name="padding"><see cref="RSAEncryptionPadding"/></param>
        /// <returns></returns>
        private static int GetMaxRsaEncryptLength(RSA rsa, RSAEncryptionPadding padding)
        {
            var offset = 0;
            if (padding.Mode == RSAEncryptionPaddingMode.Pkcs1)
            {
                offset = 11;
            }
            else
            {
                if (padding.Equals(RSAEncryptionPadding.OaepSHA1))
                {
                    offset = 42;
                }

                if (padding.Equals(RSAEncryptionPadding.OaepSHA256))
                {
                    offset = 66;
                }

                if (padding.Equals(RSAEncryptionPadding.OaepSHA384))
                {
                    offset = 98;
                }

                if (padding.Equals(RSAEncryptionPadding.OaepSHA512))
                {
                    offset = 130;
                }
            }
            var keySize = rsa.KeySize;
            var maxLength = keySize / 8 - offset;
            return maxLength;
        }

        #endregion

        #region MD5
        /// <summary>
        /// MD5 hash
        /// </summary>
        /// <param name="srcString">The string to be encrypted.</param>
        /// <param name="length">The length of hash result , default value is <see cref="MD5Length.L32"/>.</param>
        /// <returns></returns>
        public static string Md5(string srcString, MD5Length length = MD5Length.L32)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));

            string str_md5_out = string.Empty;
            using (MD5 md5 = MD5.Create())
            {
                byte[] bytes_md5_in = Encoding.UTF8.GetBytes(srcString);
                byte[] bytes_md5_out = md5.ComputeHash(bytes_md5_in);

                str_md5_out = length == MD5Length.L32
                    ? BitConverter.ToString(bytes_md5_out)
                    : BitConverter.ToString(bytes_md5_out, 4, 8);

                str_md5_out = str_md5_out.Replace("-", "");
                return str_md5_out;
            }
        }
        #endregion

        #region HMACMD5
        /// <summary>
        /// HMACMD5 hash
        /// </summary>
        /// <param name="srcString">The string to be encrypted</param>
        /// <param name="key">encrypte key</param>
        /// <returns></returns>
        public static string HMACMD5(string srcString, string key)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            Check.Argument.IsNotEmpty(key, nameof(key));

            byte[] secrectKey = Encoding.UTF8.GetBytes(key);
            using (HMACMD5 md5 = new HMACMD5(secrectKey))
            {
                byte[] bytes_md5_in = Encoding.UTF8.GetBytes(srcString);
                byte[] bytes_md5_out = md5.ComputeHash(bytes_md5_in);
                string str_md5_out = BitConverter.ToString(bytes_md5_out);
                str_md5_out = str_md5_out.Replace("-", "");
                return str_md5_out;
            }
        }

        #endregion

        #region SHA1
        /// <summary>
        /// SHA1 Encryption
        /// </summary>
        /// <param name="str">The string to be encrypted</param>
        /// <returns></returns>
        public static string Sha1(string str)
        {
            Check.Argument.IsNotEmpty(str, nameof(str));

            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] bytes_sha1_in = Encoding.UTF8.GetBytes(str);
                byte[] bytes_sha1_out = sha1.ComputeHash(bytes_sha1_in);
                string str_sha1_out = BitConverter.ToString(bytes_sha1_out);
                str_sha1_out = str_sha1_out.Replace("-", "");
                return str_sha1_out;
            }
        }
        #endregion

        #region SHA256

        /// <summary>
        /// SHA256 encrypt
        /// </summary>
        /// <param name="srcString">The string to be encrypted</param>
        /// <returns></returns>
        public static string Sha256(string srcString)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes_sha256_in = Encoding.UTF8.GetBytes(srcString);
                byte[] bytes_sha256_out = sha256.ComputeHash(bytes_sha256_in);
                string str_sha256_out = BitConverter.ToString(bytes_sha256_out);
                str_sha256_out = str_sha256_out.Replace("-", "");
                return str_sha256_out;
            }
        }

        #endregion

        #region SHA384

        /// <summary>
        /// SHA384 encrypt
        /// </summary>
        /// <param name="srcString">The string to be encrypted</param>
        /// <returns></returns>
        public static string Sha384(string srcString)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));

            using (SHA384 sha384 = SHA384.Create())
            {
                byte[] bytes_sha384_in = Encoding.UTF8.GetBytes(srcString);
                byte[] bytes_sha384_out = sha384.ComputeHash(bytes_sha384_in);
                string str_sha384_out = BitConverter.ToString(bytes_sha384_out);
                str_sha384_out = str_sha384_out.Replace("-", "");
                return str_sha384_out;
            }

        }
        #endregion

        #region SHA512
        /// <summary>
        /// SHA512 encrypt
        /// </summary>
        /// <param name="srcString">The string to be encrypted</param>
        /// <returns></returns>
        public static string Sha512(string srcString)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));

            using (SHA512 sha512 = SHA512.Create())
            {
                byte[] bytes_sha512_in = Encoding.UTF8.GetBytes(srcString);
                byte[] bytes_sha512_out = sha512.ComputeHash(bytes_sha512_in);
                string str_sha512_out = BitConverter.ToString(bytes_sha512_out);
                str_sha512_out = str_sha512_out.Replace("-", "");
                return str_sha512_out;
            }
        }

        #endregion

        #region HMACSHA1

        /// <summary>
        /// HMAC_SHA1
        /// </summary>
        /// <param name="srcString">The string to be encrypted</param>
        /// <param name="key">encrypte key</param>
        /// <returns></returns>
        public static string HMACSHA1(string srcString, string key)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            Check.Argument.IsNotEmpty(key, nameof(key));

            byte[] secrectKey = Encoding.UTF8.GetBytes(key);
            using (HMACSHA1 hmac = new HMACSHA1(secrectKey))
            {
                hmac.Initialize();

                byte[] bytes_hmac_in = Encoding.UTF8.GetBytes(srcString);
                byte[] bytes_hamc_out = hmac.ComputeHash(bytes_hmac_in);

                string str_hamc_out = BitConverter.ToString(bytes_hamc_out);
                str_hamc_out = str_hamc_out.Replace("-", "");

                return str_hamc_out;
            }
        }

        #endregion

        #region HMACSHA256

        /// <summary>
        /// HMAC_SHA256
        /// </summary>
        /// <param name="srcString">The string to be encrypted</param>
        /// <param name="key">encrypte key</param>
        /// <returns></returns>
        public static string HMACSHA256(string srcString, string key)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            Check.Argument.IsNotEmpty(key, nameof(key));

            byte[] secrectKey = Encoding.UTF8.GetBytes(key);
            using (HMACSHA256 hmac = new HMACSHA256(secrectKey))
            {
                hmac.Initialize();

                byte[] bytes_hmac_in = Encoding.UTF8.GetBytes(srcString);
                byte[] bytes_hamc_out = hmac.ComputeHash(bytes_hmac_in);

                string str_hamc_out = BitConverter.ToString(bytes_hamc_out);
                str_hamc_out = str_hamc_out.Replace("-", "");

                return str_hamc_out;
            }
        }

        #endregion

        #region HMACSHA384

        /// <summary>
        /// HMAC_SHA384
        /// </summary>
        /// <param name="srcString">The string to be encrypted</param>
        /// <param name="key">encrypte key</param>
        /// <returns></returns>
        public static string HMACSHA384(string srcString, string key)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            Check.Argument.IsNotEmpty(key, nameof(key));

            byte[] secrectKey = Encoding.UTF8.GetBytes(key);
            using (HMACSHA384 hmac = new HMACSHA384(secrectKey))
            {
                hmac.Initialize();

                byte[] bytes_hmac_in = Encoding.UTF8.GetBytes(srcString);
                byte[] bytes_hamc_out = hmac.ComputeHash(bytes_hmac_in);


                string str_hamc_out = BitConverter.ToString(bytes_hamc_out);
                str_hamc_out = str_hamc_out.Replace("-", "");

                return str_hamc_out;
            }
        }

        #endregion

        #region HMACSHA512

        /// <summary>
        /// HMAC_SHA512
        /// </summary>
        /// <param name="srcString">The string to be encrypted</param>
        /// <param name="key">encrypte key</param>
        /// <returns></returns>
        public static string HMACSHA512(string srcString, string key)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            Check.Argument.IsNotEmpty(key, nameof(key));

            byte[] secrectKey = Encoding.UTF8.GetBytes(key);
            using (HMACSHA512 hmac = new HMACSHA512(secrectKey))
            {
                hmac.Initialize();

                byte[] bytes_hmac_in = Encoding.UTF8.GetBytes(srcString);
                byte[] bytes_hamc_out = hmac.ComputeHash(bytes_hmac_in);

                string str_hamc_out = BitConverter.ToString(bytes_hamc_out);
                str_hamc_out = str_hamc_out.Replace("-", "");

                return str_hamc_out;
            }
        }

        #endregion

        #region Machine Key

        /// <summary>
        /// Create decryptionKey
        /// </summary>
        /// <param name="length">decryption key length range is 16 -48</param>
        /// <returns>DecryptionKey</returns>
        public static string CreateDecryptionKey(int length)
        {
            Check.Argument.IsNotOutOfRange(length, 16, 48, nameof(length));
            return CreateMachineKey(length);
        }

        /// <summary>
        /// Create validationKey
        /// </summary>
        /// <param name="length"></param>
        /// <returns>ValidationKey</returns>
        public static string CreateValidationKey(int length)
        {
            Check.Argument.IsNotOutOfRange(length, 48, 128, nameof(length));
            return CreateMachineKey(length);
        }

        /// <summary>
        /// <para>Use cryptographic service providers to implement encryption to generate random numbers</para>
        /// <para>
        /// Description:
        /// validationKey The value can be 48 to 128 characters long.It is strongly recommended to use the longest key available
        /// decryptionKey The value can be 16 to 48 characters long.It is recommended to use 48 characters long
        /// </para>
        /// <para>
        /// How to use:
        /// string decryptionKey = EncryptManager.CreateMachineKey(48);
        /// string validationKey = EncryptManager.CreateMachineKey(128);
        /// </para>
        /// </summary>
        /// <param name="length">Length</param>
        /// <returns></returns>
        private static string CreateMachineKey(int length)
        {

            byte[] random = new byte[length / 2];

            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(random);

            StringBuilder machineKey = new StringBuilder(length);
            for (int i = 0; i < random.Length; i++)
            {
                machineKey.Append(string.Format("{0:X2}", random[i]));
            }
            return machineKey.ToString();
        }

        #endregion

        #region Base64

        #region Base64加密解密
        /// <summary>
        /// Base64 encrypt
        /// </summary>
        /// <param name="input">input value</param>
        /// <returns></returns>
        public static string Base64Encrypt(string input)
        {
            return Base64Encrypt(input, Encoding.UTF8);
        }

        /// <summary>
        /// Base64 encrypt
        /// </summary>
        /// <param name="input">input value</param>
        /// <param name="encoding">text encoding</param>
        /// <returns></returns>
        public static string Base64Encrypt(string input, Encoding encoding)
        {
            Check.Argument.IsNotEmpty(input, nameof(input));
            return Convert.ToBase64String(encoding.GetBytes(input));
        }

        /// <summary>
        /// Base64 decrypt
        /// </summary>
        /// <param name="input">input value</param>
        /// <returns></returns>
        public static string Base64Decrypt(string input)
        {
            return Base64Decrypt(input, Encoding.UTF8);
        }

        /// <summary>
        /// Base64 decrypt
        /// </summary>
        /// <param name="input">input value</param>
        /// <param name="encoding">text encoding</param>
        /// <returns></returns>
        public static string Base64Decrypt(string input, Encoding encoding)
        {
            Check.Argument.IsNotEmpty(input, nameof(input));
            return encoding.GetString(Convert.FromBase64String(input));
        }
        #endregion

        #endregion
    }
}
