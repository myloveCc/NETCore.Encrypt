using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using NETCore.Encrypt;

namespace NETCore.Encrypt.Tests
{
    public class MD5_Tests
    {
        [Fact(DisplayName = "MD5 success test")]
        public void MD5_Success_Test()
        {
            var srcString = "Md5 test";

            var hashed = EncryptProvider.Md5(srcString);

            Assert.NotEmpty(hashed);
            Assert.Equal("d69fa0d969c6ecadb32f549229b21e13", hashed.ToLower());
        }


        [Fact(DisplayName = "MD5 error test")]
        public void MD5_Error_Test()
        {
            Assert.Throws<ArgumentException>(() => EncryptProvider.Md5(string.Empty));
        }
        
        [Fact(DisplayName = "MD5 with length success test")]
        public void MD5_With_Length_Success_Test()
        {
            var srcString = "Md5 test";

            var hashed = EncryptProvider.Md5(srcString, MD5Length.L16);

            Assert.NotEmpty(hashed);
            Assert.Equal("69c6ecadb32f5492", hashed.ToLower());
        }
    }
}
