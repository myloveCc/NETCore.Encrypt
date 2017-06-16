using System;
using System.Collections.Generic;
using System.Text;
using NETCore.Encrypt;
using Newtonsoft.Json;
using NETCore.Encrypt.Shared;

namespace NETCore.Encrypt.Extensions
{
    public static class EncryptExtensions
    {
        /// <summary>
        /// String MD5 extension
        /// </summary>
        /// <param name="srcString"></param>
        /// <returns></returns>
        public static string MD5(this string srcString)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            return EncryptProvider.Md5(srcString);
        }

        /// <summary>
        /// Data MD5 extension
        /// </summary>
        /// <typeparam name="T"><see cref="T"/></typeparam>
        /// <param name="srcObj"></param>
        /// <returns></returns>
        public static string MD5<T>(this T srcObj) where T : class
        {
            Check.Argument.IsNotNull(srcObj, nameof(srcObj));
            return EncryptProvider.Md5(JsonConvert.SerializeObject(srcObj));
        }

        /// <summary>
        /// String SHA1 extensions
        /// </summary>
        /// <param name="srcString"></param>
        /// <returns></returns>
        public static string SHA1(this string srcString)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            return EncryptProvider.Sha1(srcString);
        }


        /// <summary>
        /// DATA SHA1 extensions
        /// </summary>
        /// <typeparam name="T"><see cref="T"/></typeparam>
        /// <param name="srcObj"></param>
        /// <returns></returns>
        public static string SHA1<T>(this T srcObj) where T : class
        {
            Check.Argument.IsNotNull(srcObj, nameof(srcObj));
            return EncryptProvider.Sha1(JsonConvert.SerializeObject(srcObj));
        }

        /// <summary>
        /// String SHA256 extensions
        /// </summary>
        /// <param name="srcString"></param>
        /// <returns></returns>
        public static string SHA256(this string srcString)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            return EncryptProvider.Sha256(srcString);
        }

        /// <summary>
        /// Data SHA256 extensions
        /// </summary>
        /// <typeparam name="T"><see cref="T"/></typeparam>
        /// <param name="srcObj"></param>
        /// <returns></returns>
        public static string SHA256<T>(this T srcObj) where T : class
        {
            Check.Argument.IsNotNull(srcObj, nameof(srcObj));
            return EncryptProvider.Sha256(JsonConvert.SerializeObject(srcObj));
        }

        /// <summary>
        /// String SHA384 extensions
        /// </summary>
        /// <param name="srcString"></param>
        /// <returns></returns>
        public static string SHA384(this string srcString)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            return EncryptProvider.Sha384(srcString);
        }

        /// <summary>
        /// Data SHA384 extensions
        /// </summary>
        /// <typeparam name="T"><see cref="T"/></typeparam>
        /// <param name="srcObj"></param>
        /// <returns></returns>
        public static string SHA384<T>(this T srcObj) where T : class
        {
            Check.Argument.IsNotNull(srcObj, nameof(srcObj));
            return EncryptProvider.Sha384(JsonConvert.SerializeObject(srcObj));
        }

        /// <summary>
        /// String SHA512 extensions
        /// </summary>
        /// <param name="srcString"></param>
        /// <returns></returns>
        public static string SHA512(this string srcString)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            return EncryptProvider.Sha512(srcString);
        }

        /// <summary>
        /// Data SHA512 extensions
        /// </summary>
        /// <typeparam name="T"><see cref="T"/></typeparam>
        /// <param name="srcObj"></param>
        /// <returns></returns>
        public static string SHA512<T>(this T srcObj) where T : class
        {
            Check.Argument.IsNotNull(srcObj, nameof(srcObj));
            return EncryptProvider.Sha512(JsonConvert.SerializeObject(srcObj));
        }


        /// <summary>
        /// String HMACSHA1 extensions
        /// </summary>
        /// <param name="srcString"></param>
        /// <returns></returns>
        public static string HMACSHA1(this string srcString, string key)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            return EncryptProvider.HMACSHA1(srcString, key);
        }

        /// <summary>
        /// Data HMACSHA1 extensions
        /// </summary>
        /// <typeparam name="T"><see cref="T"/></typeparam>
        /// <param name="srcObj"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string HMACSHA1<T>(this T srcObj, string key) where T : class
        {
            Check.Argument.IsNotNull(srcObj, nameof(srcObj));
            return EncryptProvider.HMACSHA1(JsonConvert.SerializeObject(srcObj), key);
        }


        /// <summary>
        /// String HMACSHA1 extensions
        /// </summary>
        /// <param name="srcString"></param>
        /// <returns></returns>
        public static string HMACSHA256(this string srcString, string key)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            return EncryptProvider.HMACSHA256(srcString, key);
        }

        /// <summary>
        /// Data HMACSHA256 extensions
        /// </summary>
        /// <typeparam name="T"><see cref="T"/></typeparam>
        /// <param name="srcObj"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string HMACSHA256<T>(this T srcObj, string key) where T : class
        {
            Check.Argument.IsNotNull(srcObj, nameof(srcObj));
            return EncryptProvider.HMACSHA256(JsonConvert.SerializeObject(srcObj), key);
        }

        /// <summary>
        /// String HMACSHA384 extensions
        /// </summary>
        /// <param name="srcString"></param>
        /// <returns></returns>
        public static string HMACSHA384(this string srcString, string key)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            return EncryptProvider.HMACSHA384(srcString, key);
        }

        /// <summary>
        /// Data HMACSHA384 extensions
        /// </summary>
        /// <typeparam name="T"><see cref="T"/></typeparam>
        /// <param name="srcObj"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string HMACSHA384<T>(this T srcObj, string key) where T : class
        {
            Check.Argument.IsNotNull(srcObj, nameof(srcObj));
            return EncryptProvider.HMACSHA384(JsonConvert.SerializeObject(srcObj), key);
        }

        /// <summary>
        /// String HMACSHA512 extensions
        /// </summary>
        /// <param name="srcString"></param>
        /// <returns></returns>
        public static string HMACSHA512(this string srcString, string key)
        {
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            return EncryptProvider.HMACSHA512(srcString, key);
        }

        /// <summary>
        /// Data HMACSHA512 extensions
        /// </summary>
        /// <typeparam name="T"><see cref="T"/></typeparam>
        /// <param name="srcObj"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string HMACSHA512<T>(this T srcObj, string key) where T : class
        {
            Check.Argument.IsNotNull(srcObj, nameof(srcObj));
            return EncryptProvider.HMACSHA512(JsonConvert.SerializeObject(srcObj), key);
        }
    }
}
