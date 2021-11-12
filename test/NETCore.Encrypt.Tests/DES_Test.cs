using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using NETCore.Encrypt;

namespace NETCore.Encrypt.Tests
{
    public class DES_Test
    {
        private readonly string _Key;
        private readonly string _IV;

        public DES_Test()
        {
            _Key = EncryptProvider.CreateDesKey();
            _IV = EncryptProvider.CreateDesIv();
        }

        [Fact(DisplayName = "DES ke test")]
        public void Cretea_DESKey_Test()
        {

            var DESKey = EncryptProvider.CreateDesKey();

            //Assert
            Assert.NotNull(DESKey);
            Assert.Equal(24, DESKey.Length);
        }


        [Fact(DisplayName = "DES encrypt with empty data test")]
        public void DES_Encryt_EmptyData_Fail_Test()
        {
            var srcString = string.Empty;
            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.DESDecrypt(srcString, _Key));
        }


        [Fact(DisplayName = "DES encrypt with error key test")]
        public void DES_Encrypt_ErrorKey_Fail_Test()
        {
            var key = "1hyhuo";
            var srcString = "test DES encrypt";

            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.DESEncrypt(srcString, key));
        }

        [Fact(DisplayName = "DES decrypt success test")]
        public void DES_Decryt_Success_Test()
        {
            var srcString = "test DES encrypt";

            //Ack
            var encrypted = EncryptProvider.DESEncrypt(srcString, _Key);
            var decrypted = EncryptProvider.DESDecrypt(encrypted, _Key);

            //Assert
            Assert.NotEmpty(encrypted);
            Assert.NotEmpty(decrypted);
            Assert.Equal(srcString, decrypted);
        }


        [Fact(DisplayName = "DES CBC mode decrypt success test")]
        public void DES_CBCMode_Success_Test()
        {
            var srcString = "test DES encrypt";

            //Ack
            var srsDatas = Encoding.UTF8.GetBytes(srcString);
            var encrypted = EncryptProvider.DESEncrypt(srsDatas, _Key, _IV);
            var decrypted = EncryptProvider.DESDecrypt(encrypted, _Key, _IV);
            var decryptedStr = Encoding.UTF8.GetString(decrypted);
            //Assert
            Assert.NotEmpty(encrypted);
            Assert.NotEmpty(decrypted);
            Assert.Equal(srcString, decryptedStr);
        }

        [Fact(DisplayName = "DES decrypt with empty data test")]
        public void DES_Decrypt_EmptyData_Fail_Test()
        {
            var srcString = string.Empty;

            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.DESDecrypt(srcString, _Key));
        }

        [Fact(DisplayName = "DES decrypt with error key test")]
        public void DES_Decrypt_ErrorKey_Fail_Test()
        {
            var key = "dfafa";  //must be 24 bit
            var srcString = "test DES encrypt";

            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.DESDecrypt(srcString, key));
        }
    }
}
