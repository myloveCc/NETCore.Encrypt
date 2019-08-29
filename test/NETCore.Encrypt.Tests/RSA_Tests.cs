using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using NETCore.Encrypt;
using System.Security.Cryptography;
using NETCore.Encrypt.Extensions;

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

        [Theory(DisplayName = "Rsa encrypt string length limit test")]
        [InlineData(RsaSize.R2048)]
        [InlineData(RsaSize.R3072)]
        [InlineData(RsaSize.R4096)]
        public void Rsa_Encrypt_LengthLimit_Test(RsaSize size)
        {
            var rsaKey = EncryptProvider.CreateRsaKey(size);

            var publicKey = rsaKey.PublicKey;
            var privateKey = rsaKey.PrivateKey;

            //Act
            var rawStr = "eyJNb2R1bHVzIjoidHVSL1V1dFVSV0RSVElDYTFFRDcraUF2MUVnQUl0dC9oNkhHc0x6SG80QXAyVVdqWGtvRkp4T1NuRmdhY3d4cWM0WUg5UDdRaVIxQ1lCK3lvMnJUbkhZbVIrYWs2V3RJRU1YNWtmTTJrWHBNUVY2aFBrd0FxRTFpU1pWRUM2eXlmeTNGZUJTVmNnVlUwMFpJMGozbzhqT3ZMOXhneGhmT1J1eTcwM1RUbXdFPSIsIkV4cG9uZW50IjoiQVFBQiIsIlAiOiI3MVNIYVRnK2JvOXhzRnEzSXlrcHRFUXVHUXZTNDNEUDFoM04xcVlBN1E1VHpoS0IydEc1RWxvamtYTkF4d0VVVStxSnZMWDBxTHdzd09zRkhaL3lydz09IiwiUSI6Inc2R2ltem84a0lUL0xuS2U0Sk5QTUt2YTlVVzBSZUZlVzA5U1ZtVnFVWS9VeHl2eU9kemowd3JzTTZib1ZCU1JnZi9SbUZwRUZ1bUZTVW9yVWkxNVR3PT0iLCJEUCI6Im9yNXpPaXloMzZLeFozKzRhek54aFlDYmJES3JIRGc1VEZ1Ri9rRngvY0V4WWI4YUNFZDJ0ekVPWUxqandxOU1PR2dUYzN5enV3NEN6TWpEK01vc1J3PT0iLCJEUSI6InMvNGhhQVM2K0pVRlhDemxkT2JVTTRuTEdXUWFxempoNGMwbmlvb2d1ZzVGelVMbnlNa3RiRjFlV1YrMTNyWlY4bS8yM2VBZlNaMXRuckw1RE5EK0RRPT0iLCJJbnZlcnNlUSI6IlBPSkRGUk03MmVxd0R3TytldDFpTzIwTWlQcFVEUS93N1hEMHBMLzJWYTE4OEgrRGlaK0NuZDJRdnFYZyt4NFdNZSsrVlVNYXo2bWM3V1g4WnBaWW9RPT0iLCJEIjoiWE1QUEZPYktDcHFON21pNG4zb0tsSmFveTlwdFAwRG9FWXBydGc4NmoyS2RWMWZzQWhJM1JOZTNvRmRMcXhrY0VWWmxTTTNLUmhHeUxnRkY0WDk0cnVIYjBQeC9LZVQxMW1BeDNvQ2NCRVlWelhabXlIUHQzWCs2dlBMZzdmYUhtRmlxK3N0Y2NMTlBNSEdna2lkWTF6NGtiTXZwZnBlOWxhN0VMWUdKM21VPSJ9";

            //RSAEncryptionPaddingMode is Pkcs1
            var padding = RSAEncryptionPadding.Pkcs1;
            var maxLength = ((int)size - 384) / 8 + 37;
            var rawData = rawStr.Substring(0, maxLength);

            var encryptedStr = EncryptProvider.RSAEncrypt(publicKey, rawData, padding);
            var decryptedStr = EncryptProvider.RSADecrypt(privateKey, encryptedStr, padding);

            //RSAEncryptionPaddingMode is Oaep
            padding = RSAEncryptionPadding.OaepSHA1;

            var sha1 = "oaep".SHA1();
            var length = sha1.Length;
            maxLength = (int)size / 8 - 42;   //214 //40 
            rawData = rawStr.Substring(0, maxLength);

            encryptedStr = EncryptProvider.RSAEncrypt(publicKey, rawData, padding);
            decryptedStr = EncryptProvider.RSADecrypt(privateKey, encryptedStr, padding);
            Assert.Equal(decryptedStr, rawData);


            padding = RSAEncryptionPadding.OaepSHA256;

            maxLength = (int)size / 8 - 66;   //190   //64
            rawData = rawStr.Substring(0, maxLength);

            encryptedStr = EncryptProvider.RSAEncrypt(publicKey, rawData, padding);
            decryptedStr = EncryptProvider.RSADecrypt(privateKey, encryptedStr, padding);

            Assert.Equal(decryptedStr, rawData);

            padding = RSAEncryptionPadding.OaepSHA384;
            maxLength = (int)size / 8 - 98;  //158  //96
            rawData = rawStr.Substring(0, maxLength);

            encryptedStr = EncryptProvider.RSAEncrypt(publicKey, rawData, padding);
            decryptedStr = EncryptProvider.RSADecrypt(privateKey, encryptedStr, padding);

            Assert.Equal(decryptedStr, rawData);

            padding = RSAEncryptionPadding.OaepSHA512;
            maxLength = (int)size / 8 - 130; //126  // 128
            rawData = rawStr.Substring(0, maxLength);

            encryptedStr = EncryptProvider.RSAEncrypt(publicKey, rawData, padding);
            decryptedStr = EncryptProvider.RSADecrypt(privateKey, encryptedStr, padding);

            Assert.Equal(decryptedStr, rawData);
        }

        [Fact(DisplayName = "Rsa encrypt out of max length exception test")]
        public void Rsa_Encrypt_OutofMaxLength_Exception_Test()
        {
            //Act
            var rawStr = "eyJNb2R1bHVzIjoidHVSL1V1dFVSV0RSVElDYTFFRDcraUF2MUVnQUl0dC9oNkhHc0x6SG80QXAyVVdqWGtvRkp4T1NuRmdhY3d4cWM0WUg5UDdRaVIxQ1lCK3lvMnJUbkhZbVIrYWs2V3RJRU1YNWtmTTJrWHBNUVY2aFBrd0FxRTFpU1pWRUM2eXlmeTNGZUJTVmNnVlUwMFpJMGozbzhqT3ZMOXhneGhmT1J1eTcwM1RUbXdFPSIsIkV4cG9uZW50IjoiQVFBQiIsIlAiOiI3MVNIYVRnK2JvOXhzRnEzSXlrcHRFUXVHUXZTNDNEUDFoM04xcVlBN1E1VHpoS0IydEc1RWxvamtYTkF4d0VVVStxSnZMWDBxTHdzd09zRkhaL3lydz09IiwiUSI6Inc2R2ltem84a0lUL0xuS2U0Sk5QTUt2YTlVVzBSZUZlVzA5U1ZtVnFVWS9VeHl2eU9kemowd3JzTTZib1ZCU1JnZi9SbUZwRUZ1bUZTVW9yVWkxNVR3PT0iLCJEUCI6Im9yNXpPaXloMzZLeFozKzRhek54aFlDYmJES3JIRGc1VEZ1Ri9rRngvY0V4WWI4YUNFZDJ0ekVPWUxqandxOU1PR2dUYzN5enV3NEN6TWpEK01vc1J3PT0iLCJEUSI6InMvNGhhQVM2K0pVRlhDemxkT2JVTTRuTEdXUWFxempoNGMwbmlvb2d1ZzVGelVMbnlNa3RiRjFlV1YrMTNyWlY4bS8yM2VBZlNaMXRuckw1RE5EK0RRPT0iLCJJbnZlcnNlUSI6IlBPSkRGUk03MmVxd0R3TytldDFpTzIwTWlQcFVEUS93N1hEMHBMLzJWYTE4OEgrRGlaK0NuZDJRdnFYZyt4NFdNZSsrVlVNYXo2bWM3V1g4WnBaWW9RPT0iLCJEIjoiWE1QUEZPYktDcHFON21pNG4zb0tsSmFveTlwdFAwRG9FWXBydGc4NmoyS2RWMWZzQWhJM1JOZTNvRmRMcXhrY0VWWmxTTTNLUmhHeUxnRkY0WDk0cnVIYjBQeC9LZVQxMW1BeDNvQ2NCRVlWelhabXlIUHQzWCs2dlBMZzdmYUhtRmlxK3N0Y2NMTlBNSEdna2lkWTF6NGtiTXZwZnBlOWxhN0VMWUdKM21VPSJ9";

            var rsaKey = EncryptProvider.CreateRsaKey();
            var publicKey = rsaKey.PublicKey;

            //Assert
            Assert.Throws<OutofMaxlengthException>(() =>
            {
                EncryptProvider.RSAEncrypt(publicKey, rawStr);
            });
        }

        [Fact(DisplayName = "Rsa sign and verify test")]
        public void Rsa_SignAndVerify_Test()
        {
            //Act
            var rawStr = "123456";

            var rsaKey = EncryptProvider.CreateRsaKey();
            var privateKey = rsaKey.PrivateKey;
            var publicKey = rsaKey.PublicKey;

            var signStr = EncryptProvider.RSASign(rawStr, privateKey);

            var result = EncryptProvider.RSAVerify(rawStr, signStr, publicKey);

            //Assert
            Assert.NotEmpty(signStr);
            Assert.True(result);
        }
    }
}
