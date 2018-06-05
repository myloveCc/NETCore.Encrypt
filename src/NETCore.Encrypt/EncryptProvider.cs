using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using NETCore.Encrypt.Shared;
using NETCore.Encrypt.Extensions;
using NETCore.Encrypt.Internal;
using NETCore.Encrypt.Extensions.Internal;

namespace NETCore.Encrypt
{
    public class EncryptProvider
    {
        #region Common

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

            Random rnd = new Random(DateTime.Now.Millisecond);
            for (int i = 0;i < length;i++)
            {
                num.Append(arrChar[rnd.Next(0, arrChar.Length)].ToString());
            }

            return num.ToString();
        }


        #endregion

        #region AES

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
            Check.Argument.IsNotOutOfRange(key.Length, 32, 32, nameof(key));

            Check.Argument.IsNotEmpty(vector, nameof(vector));
            Check.Argument.IsNotOutOfRange(vector.Length, 16, 16, nameof(vector));

            Byte[] plainBytes = Encoding.UTF8.GetBytes(data);

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
            Check.Argument.IsNotOutOfRange(key.Length, 32, 32, nameof(key));

            Check.Argument.IsNotEmpty(vector, nameof(vector));
            Check.Argument.IsNotOutOfRange(vector.Length, 16, 16, nameof(vector));

            Byte[] plainBytes = data;
            Byte[] bKey = new Byte[32];
            Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);
            Byte[] bVector = new Byte[16];
            Array.Copy(Encoding.UTF8.GetBytes(vector.PadRight(bVector.Length)), bVector, bVector.Length);

            Byte[] encryptData = null; // encrypted data
            using (Aes Aes = Aes.Create())
            {
                try
                {
                    using (MemoryStream Memory = new MemoryStream())
                    {
                        using (CryptoStream Encryptor = new CryptoStream(Memory,
                         Aes.CreateEncryptor(bKey, bVector),
                         CryptoStreamMode.Write))
                        {
                            Encryptor.Write(plainBytes, 0, plainBytes.Length);
                            Encryptor.FlushFinalBlock();

                            encryptData = Memory.ToArray();
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
            Check.Argument.IsNotOutOfRange(key.Length, 32, 32, nameof(key));

            Check.Argument.IsNotEmpty(vector, nameof(vector));
            Check.Argument.IsNotOutOfRange(vector.Length, 16, 16, nameof(vector));

            Byte[] encryptedBytes = Convert.FromBase64String(data);

            Byte[] decryptBytes = AESDecrypt(encryptedBytes, key, vector);

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
            Check.Argument.IsNotOutOfRange(key.Length, 32, 32, nameof(key));

            Check.Argument.IsNotEmpty(vector, nameof(vector));
            Check.Argument.IsNotOutOfRange(vector.Length, 16, 16, nameof(vector));

            Byte[] encryptedBytes = data;
            Byte[] bKey = new Byte[32];
            Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);
            Byte[] bVector = new Byte[16];
            Array.Copy(Encoding.UTF8.GetBytes(vector.PadRight(bVector.Length)), bVector, bVector.Length);

            Byte[] decryptedData = null; // decrypted data

            using (Aes Aes = Aes.Create())
            {
                try
                {
                    using (MemoryStream Memory = new MemoryStream(encryptedBytes))
                    {
                        using (CryptoStream Decryptor = new CryptoStream(Memory, Aes.CreateDecryptor(bKey, bVector), CryptoStreamMode.Read))
                        {
                            using (MemoryStream tempMemory = new MemoryStream())
                            {
                                Byte[] Buffer = new Byte[1024];
                                Int32 readBytes = 0;
                                while ((readBytes = Decryptor.Read(Buffer, 0, Buffer.Length)) > 0)
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
            Check.Argument.IsNotOutOfRange(key.Length, 32, 32, nameof(key));

            using (MemoryStream Memory = new MemoryStream())
            {
                using (Aes aes = Aes.Create())
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(data);
                    Byte[] bKey = new Byte[32];
                    Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);

                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = 128;
                    //aes.Key = _key;  
                    aes.Key = bKey;
                    //aes.IV = _iV; 
                    using (CryptoStream cryptoStream = new CryptoStream(Memory, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        try
                        {
                            cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                            cryptoStream.FlushFinalBlock();
                            return Convert.ToBase64String(Memory.ToArray());
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
            Check.Argument.IsNotOutOfRange(key.Length, 32, 32, nameof(key));

            Byte[] encryptedBytes = Convert.FromBase64String(data);
            Byte[] bKey = new Byte[32];
            Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);

            using (MemoryStream Memory = new MemoryStream(encryptedBytes))
            {
                //mStream.Write( encryptedBytes, 0, encryptedBytes.Length );  
                //mStream.Seek( 0, SeekOrigin.Begin );  
                using (Aes aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = 128;
                    aes.Key = bKey;
                    //aes.IV = _iV;  
                    using (CryptoStream cryptoStream = new CryptoStream(Memory, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        try
                        {
                            byte[] tmp = new byte[encryptedBytes.Length];
                            int len = cryptoStream.Read(tmp, 0, encryptedBytes.Length);
                            byte[] ret = new byte[len];
                            Array.Copy(tmp, 0, ret, 0, len);
                            return Encoding.UTF8.GetString(ret);
                        }
                        catch (Exception ex)
                        {
                            return null;
                        }
                    }
                }
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
        /// DES encrypt
        /// </summary>  
        /// <param name="data">Raw data</param>  
        /// <param name="key">Key, requires 24 bits</param>  
        /// <returns>Encrypted string</returns>  
        public static string DESEncrypt(string data, string key)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsNotOutOfRange(key.Length, 24, 24, nameof(key));

            byte[] plainBytes = Encoding.UTF8.GetBytes(data);
            var encryptBytes = DESEncrypt(plainBytes, key);

            if (encryptBytes == null)
            {
                return null;
            }
            return Convert.ToBase64String(encryptBytes);
        }

        /// <summary>  
        /// DES encrypt
        /// </summary>  
        /// <param name="data">Raw data</param>  
        /// <param name="key">Key, requires 24 bits</param>  
        /// <returns>Encrypted byte array</returns>  
        public static byte[] DESEncrypt(byte[] data, string key)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsNotOutOfRange(key.Length, 24, 24, nameof(key));

            using (MemoryStream Memory = new MemoryStream())
            {
                using (TripleDES des = TripleDES.Create())
                {
                    Byte[] plainBytes = data;
                    Byte[] bKey = new Byte[24];
                    Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);

                    des.Mode = CipherMode.ECB;
                    des.Padding = PaddingMode.PKCS7;
                    des.Key = bKey;
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
            Check.Argument.IsNotOutOfRange(key.Length, 24, 24, nameof(key));

            Byte[] encryptedBytes = Convert.FromBase64String(data);
            Byte[] bytes = DESDecrypt(encryptedBytes, key);

            if (bytes == null)
            {
                return null;
            }
            return Encoding.UTF8.GetString(bytes);
        }

        /// <summary>  
        /// DES decrypt
        /// </summary>  
        /// <param name="data">Encrypted data</param>  
        /// <param name="key">Key, requires 24 bits</param>  
        /// <returns>Decrypted byte array</returns>  
        public static byte[] DESDecrypt(byte[] data, string key)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsNotOutOfRange(key.Length, 24, 24, nameof(key));

            Byte[] encryptedBytes = data;
            Byte[] bKey = new Byte[24];
            Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);

            using (MemoryStream Memory = new MemoryStream(encryptedBytes))
            {
                using (TripleDES des = TripleDES.Create())
                {
                    des.Mode = CipherMode.ECB;
                    des.Padding = PaddingMode.PKCS7;
                    des.Key = bKey;
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
        /// RSA encrypt 
        /// </summary>
        /// <param name="publicKey">public key</param>
        /// <param name="srcString">src string</param>
        /// <param name="padding">rsa encryptPadding <see cref="RSAEncryptionPadding"/> RSAEncryptionPadding.Pkcs1 for linux/mac openssl </param>
        /// <returns>encrypted string</returns>
        public static string RSAEncrypt(string publicKey, string srcString, RSAEncryptionPadding padding)
        {
            Check.Argument.IsNotEmpty(publicKey, nameof(publicKey));
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            Check.Argument.IsNotNull(padding, nameof(padding));

            using (RSA rsa = RSA.Create())
            {
                rsa.FromJsonString(publicKey);
                var maxLength = GetMaxRsaEncryptLength(rsa, padding);
                var rawBytes = Encoding.UTF8.GetBytes(srcString);

                if (rawBytes.Length > maxLength)
                {
                    throw new OutofMaxlengthException(maxLength, $"'{srcString}' is out of max length");
                }

                byte[] encryptBytes = rsa.Encrypt(rawBytes, padding);
                return encryptBytes.ToHexString();
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
        /// RSA encrypt 
        /// </summary>
        /// <param name="publicKey">public key</param>
        /// <param name="srcString">src string</param>
        /// <param name="padding">rsa encryptPadding <see cref="RSAEncryptionPadding"/> RSAEncryptionPadding.Pkcs1 for linux/mac openssl </param>
        /// <returns>encrypted string</returns>
        public static string RSADecrypt(string privateKey, string srcString, RSAEncryptionPadding padding)
        {
            Check.Argument.IsNotEmpty(privateKey, nameof(privateKey));
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            Check.Argument.IsNotNull(padding, nameof(padding));

            using (RSA rsa = RSA.Create())
            {
                rsa.FromJsonString(privateKey);
                byte[] srcBytes = srcString.ToBytes();
                byte[] decryptBytes = rsa.Decrypt(srcBytes, padding);
                return Encoding.UTF8.GetString(decryptBytes);
            }
        }

        /// <summary>
        /// RSA from json string
        /// </summary>
        /// <param name="rsaKey">rsa json string</param>
        /// <returns></returns>
        public static RSA RSAFromString(string rsaKey)
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
                rsa.KeySize = (int) rsaSize;

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
        /// SHA1加密
        /// </summary>
        /// <param name="str">The string to be encrypted</param>
        /// <returns></returns>
        public static string Sha1(string str)
        {
            Check.Argument.IsNotEmpty(str, "SHA1待加密字符");

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
        /// 使用加密服务提供程序实现加密生成随机数
        /// 
        /// 说明：
        /// validationKey 的值可以是48到128个字符长，强烈建议使用可用的最长密钥
        /// decryptionKey 的值可以是16到48字符长，建议使用48字符长
        /// 
        /// 使用方式：
        /// string decryptionKey = EncryptManager.CreateMachineKey(48);
        /// string validationKey = EncryptManager.CreateMachineKey(128);
        /// </summary>
        /// <param name="length">长度</param>
        /// <returns></returns>
        private static string CreateMachineKey(int length)
        {

            byte[] random = new byte[length / 2];

            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(random);

            StringBuilder machineKey = new StringBuilder(length);
            for (int i = 0;i < random.Length;i++)
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
