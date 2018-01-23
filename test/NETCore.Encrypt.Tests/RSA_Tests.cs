using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using NETCore.Encrypt;
using System.Security.Cryptography;

namespace NETCore.Encrypt.Tests
{
    public class RSA_Tests
    {

        [Theory]
        [InlineData(RsaSize.R2048)]
        [InlineData(RsaSize.R3072)]
        [InlineData(RsaSize.R4096)]
        public void Create_RSAKey_Test(RsaSize size)
        {
            //Act
            var rsaKey = EncryptProvider.CreateRsaKey(size);

            //Assert
            Assert.NotNull(rsaKey);
            Assert.NotEmpty(rsaKey.PublicKey);
            Assert.NotEmpty(rsaKey.PrivateKey);
            Assert.NotEmpty(rsaKey.Exponent);
            Assert.NotEmpty(rsaKey.Modulus);
        }

        [Theory]
        [InlineData(RsaSize.R2048)]
        [InlineData(RsaSize.R3072)]
        [InlineData(RsaSize.R4096)]
        public void Rsa_Encrypt_Success_Test(RsaSize size)
        {
            var rsaKey = EncryptProvider.CreateRsaKey(size);
            var srcString = "rsa encrypt";

            //Act
            var encrypted = EncryptProvider.RSAEncrypt(rsaKey.PublicKey, srcString);

            //Assert
            Assert.NotEmpty(encrypted);
        }

        [Theory(DisplayName = "Rsa encrypt with custom RSAEncryptionPadding")]
        [InlineData(RsaSize.R2048)]
        [InlineData(RsaSize.R3072)]
        [InlineData(RsaSize.R4096)]
        public void Rsa_Encrypt_WithPadding_Test(RsaSize size)
        {
            var rsaKey = EncryptProvider.CreateRsaKey(size);
            var srcString = "rsa encrypt";

            //Act
            var encrypted = EncryptProvider.RSAEncrypt(rsaKey.PublicKey, srcString, RSAEncryptionPadding.Pkcs1);

            //Assert
            Assert.NotEmpty(encrypted);
        }


        [Fact(DisplayName = "Rsa encrypt fail with emtpy key")]
        public void Rsa_Encrypt_EmptyKey_Test()
        {
            var key = string.Empty;
            var srcString = "rsa encrypt";

            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.RSAEncrypt(key, srcString));
        }

        [Fact(DisplayName = "Rsa encrypt fail with emtpy data")]
        public void Rsa_Encrypt_EmptyData_Test()
        {
            var rsaKey = EncryptProvider.CreateRsaKey();
            var srcString = string.Empty;

            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.RSAEncrypt(rsaKey.PublicKey, srcString));
        }

        [Theory]
        [InlineData(RsaSize.R2048)]
        [InlineData(RsaSize.R3072)]
        [InlineData(RsaSize.R4096)]
        public void Rsa_Decrypt_Success_Test(RsaSize size)
        {
            var rsaKey = EncryptProvider.CreateRsaKey(size);
            var srcString = "rsa decrypt";

            //Act
            var encrypted = EncryptProvider.RSAEncrypt(rsaKey.PublicKey, srcString);
            var decrypted = EncryptProvider.RSADecrypt(rsaKey.PrivateKey, encrypted);

            //Assert
            Assert.NotEmpty(encrypted);
            Assert.NotEmpty(decrypted);
            Assert.Equal(srcString, decrypted);
        }


        [Theory(DisplayName = "Rsa decrypt with custom RSAEncryptionPadding")]
        [InlineData(RsaSize.R2048)]
        [InlineData(RsaSize.R3072)]
        [InlineData(RsaSize.R4096)]
        public void Rsa_Decrypt_WithPadding_Test(RsaSize size)
        {
            var rsaKey = EncryptProvider.CreateRsaKey(size);
            var srcString = "rsa decrypt";

            //Act
            var padding = RSAEncryptionPadding.Pkcs1;
            var encrypted = EncryptProvider.RSAEncrypt(rsaKey.PublicKey, srcString, padding);
            var decrypted = EncryptProvider.RSADecrypt(rsaKey.PrivateKey, encrypted, padding);

            //Assert
            Assert.NotEmpty(encrypted);
            Assert.NotEmpty(decrypted);
            Assert.Equal(srcString, decrypted);
        }


        [Fact(DisplayName = "Rsa decrypt fail with emtpy key")]
        public void Rsa_Decrypt_EmptyKey_Test()
        {
            var key = string.Empty;
            var srcString = "rsa decrypt";

            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.RSAEncrypt(key, srcString));
        }

        [Fact(DisplayName = "Rsa decrypt fail with emtpy data")]
        public void Rsa_Decrypt_EmptyData_Test()
        {
            var rsaKey = EncryptProvider.CreateRsaKey();
            var srcString = string.Empty;

            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.RSAEncrypt(rsaKey.PublicKey, srcString));
        }

        [Fact(DisplayName = "Rsa from json string test")]
        public void Rsa_From_JsonString_Test()
        {
            var rsaKey = EncryptProvider.CreateRsaKey();

            var publicKey = rsaKey.PublicKey;
            var privateKey = rsaKey.PrivateKey;

            var rsa = EncryptProvider.RSAFromString(publicKey);

            Assert.NotNull(rsa);

        }
    }
}
