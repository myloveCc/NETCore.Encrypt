using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using NETCore.Encrypt;

namespace NETCore.Encrypt.Tests
{
    public class RSA_Tests
    {

        [Fact(DisplayName = "Create rsa key test")]
        public void Create_RSAKey_Test()
        {
            //Act
            var rsaKey = EncryptProvider.CreateRsaKey();

            //Assert
            Assert.NotNull(rsaKey);
            Assert.NotEmpty(rsaKey.PublicKey);
            Assert.NotEmpty(rsaKey.PrivateKey);
            Assert.NotEmpty(rsaKey.Exponent);
            Assert.NotEmpty(rsaKey.Modulus);
        }

        [Fact(DisplayName = "Rsa encrypt success")]
        public void Rsa_Encrypt_Success_Test()
        {
            var rsaKey = EncryptProvider.CreateRsaKey();
            var srcString = "rsa encrypt";

            //Act
            var encrypted = EncryptProvider.RSAEncrypt(rsaKey.PublicKey, srcString);

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

        [Fact(DisplayName = "Rsa decrypt success")]
        public void Rsa_Decrypt_Success_Test()
        {
            var rsaKey = EncryptProvider.CreateRsaKey();
            var srcString = "rsa decrypt";

            //Act
            var encrypted = EncryptProvider.RSAEncrypt(rsaKey.PublicKey, srcString);
            var decrypted = EncryptProvider.RSADecrypt(rsaKey.PrivateKey, encrypted);

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

        [Fact(DisplayName = "Rsa instance test")]
        public void Rsa_Instance_Test()
        {
            var rsaKey = EncryptProvider.CreateRsaKey();

            var publicKey = rsaKey.PublicKey;
            var privateKey = rsaKey.PrivateKey;

            var rsa = EncryptProvider.RSAInstance(publicKey);

            Assert.NotNull(rsa);
            Assert.Equal(2048, rsa.KeySize);

        }
    }
}
