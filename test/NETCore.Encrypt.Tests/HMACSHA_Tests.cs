using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace NETCore.Encrypt.Tests
{
    public class HMACHMACSHA_Tests
    {
        private const string key = "hjajsfp[1nj;ko";


        [Fact(DisplayName = "HMACSHA1 success test")]
        public void HMACSHA1_Success_Test()
        {
            var srcString = "hmacsha encrypt";

            //Ack
            var hashed = EncryptProvider.HMACSHA1(srcString, key);

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal("9aa40a36ee02095934254f8a848a44d77b929eee", hashed.ToLower());
        }

        [Fact(DisplayName = "HMACSHA1 empty data test")]
        public void HMACSHA1_EmptyData_Test()
        {
            var srcString = string.Empty;

            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.HMACSHA1(srcString, key));
        }

        [Fact(DisplayName = "HMACSHA1 empty key test")]
        public void HMACSHA1_EmptyKey_Test()
        {
            var srcString = "hmacsha encrypt";
            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.HMACSHA1(srcString, string.Empty));
        }

        [Fact(DisplayName = "HMACSHA256 success test")]
        public void HMACSHA256_Success_Test()
        {
            var srcString = "hmacsha encrypt";

            //Ack
            var hashed = EncryptProvider.HMACSHA256(srcString, key);

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal("96d1fd99232ecf6d5e30bbce472f42d752ce3486c1f0fb5007189dda298e1811", hashed.ToLower());
        }

        [Fact(DisplayName = "HMACSHA256 empty data test")]
        public void HMACSHA256_EmptyData_Test()
        {
            var srcString = string.Empty;

            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.HMACSHA256(srcString, key));
        }

        [Fact(DisplayName = "HMACSHA256 empty key test")]
        public void HMACSHA256_EmptyKey_Test()
        {
            var srcString = "hmacsha encrypt";
            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.HMACSHA256(srcString, string.Empty));
        }

        [Fact(DisplayName = "HMACSHA384 success test")]
        public void HMACSHA384_Success_Test()
        {
            var srcString = "hmacsha encrypt";

            //Ack
            var hashed = EncryptProvider.HMACSHA384(srcString, key);

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal("211205887bcea4938e4cadd51b2006c03d40f2b85b26393ff1112b5a4dd192db3a023eb4a7e22bd9de351da7464250ae", hashed.ToLower());
        }

        [Fact(DisplayName = "HMACSHA384 emtpy data test")]
        public void HMACSHA384_EmptyData_Test()
        {
            var srcString = string.Empty;

            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.HMACSHA384(srcString, key));
        }

        [Fact(DisplayName = "HMACSHA384 emtpy key test")]
        public void HMACSHA384_EmptyKey_Test()
        {
            var srcString = "hmacsha encrypt";

            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.HMACSHA384(srcString, string.Empty));
        }


        [Fact(DisplayName = "HMACSHA512 success test")]
        public void HMACSHA512_Success_Test()
        {
            var srcString = "hmacsha encrypt";

            //Ack
            var hashed = EncryptProvider.HMACSHA512(srcString, key);

            //Assert
            Assert.NotEmpty(hashed);
            Assert.Equal("f69b5385072514906a431a9a60b09e3e304be0149cf01c7a881040bc85a88f3321dfba7e02f517b7219a1f25cc77b4fe672774d35f50b3d118172f35418fd2cf", hashed.ToLower());
        }

        [Fact(DisplayName = "HMACSHA512 empty data test")]
        public void HMACSHA512_EmptyData_Test()
        {
            var srcString = string.Empty;

            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.HMACSHA512(srcString, key));
        }

        [Fact(DisplayName = "HMACSHA512 empty key test")]
        public void HMACSHA512_EmptyKey_Test()
        {
            var srcString = "HMACSHA encrypt";

            //Assert
            Assert.Throws<ArgumentException>(() => EncryptProvider.HMACSHA512(srcString, string.Empty));
        }
    }
}
