using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using NETCore.Encrypt.Extensions;

namespace NETCore.Encrypt.Tests
{
    public class EncryptExtensions_Tests
    {
        [Fact(DisplayName = "Md5 string extension test")]
        public void MD5_String_Extension_Test()
        {

            var value = "3e25960a79dbc69b674cd4ec67a72c62";

            //Act
            var hashed = "Hello world".MD5().ToLower();

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal(value, hashed);
        }

        [Fact(DisplayName = "Sha1 string extension test")]
        public void SHA1_String_Extension_Test()
        {

            var value = "7b502c3a1f48c8609ae212cdfb639dee39673f5e";

            //Act
            var hashed = "Hello world".SHA1().ToLower();

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal(value, hashed);
        }

        [Fact(DisplayName = "SHA256 string extension test")]
        public void SHA256_String_Extension_Test()
        {

            var value = "64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c";

            //Act
            var hashed = "Hello world".SHA256().ToLower();

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal(value, hashed);
        }

        [Fact(DisplayName = "SHA384 string extension test")]
        public void SHA384_String_Extension_Test()
        {

            var value = "9203b0c4439fd1e6ae5878866337b7c532acd6d9260150c80318e8ab8c27ce330189f8df94fb890df1d298ff360627e1";

            //Act
            var hashed = "Hello world".SHA384().ToLower();

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal(value, hashed);
        }


        [Fact(DisplayName = "SHA512 string extension test")]
        public void SHA512_String_Extension_Test()
        {

            var value = "b7f783baed8297f0db917462184ff4f08e69c2d5e5f79a942600f9725f58ce1f29c18139bf80b06c0fff2bdd34738452ecf40c488c22a7e3d80cdf6f9c1c0d47";

            //Act
            var hashed = "Hello world".SHA512().ToLower();

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal(value, hashed);
        }

        [Fact(DisplayName = "HMACMD5 string extension test")]
        public void HMACMD5_String_Extension_Test()
        {

            var key = "NETCore.Encrypt";
            var value = "02cb05793ec76c55cd4e66cd5ebc53ae";

            //Act
            var hashed = "Hello world".HMACMD5(key).ToLower();

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal(value, hashed);
        }


        [Fact(DisplayName = "HMACSHA1 string extension test")]
        public void HMACSHA1_String_Extension_Test()
        {

            var key = "NETCore.Encrypt";
            var value = "28f82cb000fcf0ee024750a292619db671d7e198";

            //Act
            var hashed = "Hello world".HMACSHA1(key).ToLower();

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal(value, hashed);
        }

        [Fact(DisplayName = "HMACSHA256 string extension test")]
        public void HMACSHA256_String_Extension_Test()
        {

            var key = "NETCore.Encrypt";
            var value = "2e94df0bdbd2dc278e23b7f643ac20e7a227f0ae44238f1c199876cf7489386d";

            //Act
            var hashed = "Hello world".HMACSHA256(key).ToLower();

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal(value, hashed);
        }

        [Fact(DisplayName = "HMACSHA384 string extension test")]
        public void HMACSHA384_String_Extension_Test()
        {

            var key = "NETCore.Encrypt";
            var value = "7e02fd799d8dbec62ae630fb445bd3a9a073f694c3a46b32cdc8828a0f6a6c1eb23b00d558317625fd1d457ae647eb9a";

            //Act
            var hashed = "Hello world".HMACSHA384(key).ToLower();

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal(value, hashed);
        }

        [Fact(DisplayName = "HMACSHA512 string extension test")]
        public void HMACSHA512_String_Extension_Test()
        {

            var key = "NETCore.Encrypt";
            var value = "fe8b73fc8fd64a0efe657faf2769d6e601867eaa5736c0b8386f73dd9e81ebc533490feab363bcb072ab4f4ce358c65b2212776606f33f92e583a7f0edfa929f";

            //Act
            var hashed = "Hello world".HMACSHA512(key).ToLower();

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal(value, hashed);
        }

    }
}
