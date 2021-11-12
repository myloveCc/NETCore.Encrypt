# NETCore.Encrypt [中文文档](http://www.cnblogs.com/piscesLoveCc/p/7423205.html)
[![NuGet](https://img.shields.io/nuget/v/NETCore.Encrypt.svg)](https://nuget.org/packages/NETCore.Encrypt)
[![NET 6.0](https://img.shields.io/badge/.NET-6.0-brightgreen)](https://www.microsoft.com/net/core)
[![NetStandard 2.1](https://img.shields.io/badge/NetStandard-2.1-orange.svg)](https://www.microsoft.com/net/core)
[![license](https://img.shields.io/github/license/myloveCc/NETCore.Encrypt.svg)](https://github.com/myloveCc/NETCore.Encrypt/blob/master/License)
[![GitHub-Actions-Img]][GitHub-Actions-Url]

[GitHub-Actions-Img]:https://github.com/myloveCc/NETCore.Encrypt/workflows/test/badge.svg
[GitHub-Actions-Url]:https://github.com/myloveCc/NETCore.Encrypt/actions

NETCore encrypt and decrpty tool，Include AES，RSA，MD5，SAH1，SAH256，SHA384，SHA512 and more

To install NETCore.Encrypt, run the following command in the [Package Manager Console](https://docs.microsoft.com/zh-cn/nuget/tools/package-manager-console)



## Package Manager
```
Install-Package NETCore.Encrypt -Version 2.1.0
```
## .NET CLI
```
dotnet add package NETCore.Encrypt --version 2.1.0
```

## PackageReference
```
<PackageReference Include="NETCore.Encrypt" Version="2.1.0" />
```


***

# Easy to use with `EncryptProvider`

## AES

#### Create AES Key

  ```csharp
  var aesKey = EncryptProvider.CreateAesKey();
  
  var key = aesKey.Key;
  var iv = aesKey.IV;
  ```

#### AES encrypt
  - AES encrypt without iv (ECB mode)

    ```csharp
    var srcString = "aes encrypt";
    var encrypted = EncryptProvider.AESEncrypt(srcString, key);

    ```
  - AES encrypt with iv (CBC mode)

    ```csharp
    var srcString = "aes encrypt";
    var encrypted = EncryptProvider.AESEncrypt(srcString, key, iv);

    ```
  - AES encrypt bytes with iv (CBC mode)

    ```csharp
    var srcBytes = new byte[]{xxx};
    var encryptedBytes = EncryptProvider.AESEncrypt(srcBytes, key, iv);

    ```
#### ASE decrypt

  - AES decrypt without iv (ECB mode)
    
    ```csharp
    var encryptedStr = "xxxx";
    var decrypted = EncryptProvider.AESDecrypt(encryptedStr, key);
    ```
  
  - AES decrypt with iv (CBC mode)
   
    ```csharp
    var encryptedStr = "xxxx";
    var decrypted = EncryptProvider.AESDecrypt(encryptedStr, key, iv);
    ```

  - AES decrypt bytes with iv (CBC mode)
   
    ```csharp
    var encryptedBytes =  new byte[]{xxx};
    var decryptedBytes = EncryptProvider.AESDecrypt(encryptedBytes, key, iv);
    ```

## DES

- #### Create DES Key

  ```csharp
  
  //des key length is 24 bit
  var desKey = EncryptProvider.CreateDesKey();
  
  ```
- #### Create DES Iv 【NEW】

  ```csharp
  
  //des iv length is 8 bit
  var desIv = EncryptProvider.CreateDesIv();
  
  ```

- #### DES encrypt (ECB mode)

    ```csharp
    var srcString = "des encrypt";
    var encrypted = EncryptProvider.DESEncrypt(srcString, key);
    ```
- #### DES encrypt bytes (ECB mode)
   
    ```csharp
    var srcBytes =  new byte[]{xxx};
    var decryptedBytes = EncryptProvider.DESEncrypt(srcBytes, key);
    ```
- #### DES decrypt (ECB mode)

    ```csharp
    var encryptedStr = "xxxx";
    var decrypted = EncryptProvider.DESDecrypt(encryptedStr, key);
    ```

- #### DES decrypt bytes  (ECB mode)

    ```csharp
    var encryptedBytes =  new byte[]{xxx};
    var decryptedBytes = EncryptProvider.DESDecrypt(encryptedBytes, key);
    ```

- #### DES encrypt bytes with iv (CBC mode)【NEW】

    ```csharp
    var srcBytes =  new byte[]{xxx};
    var encrypted = EncryptProvider.DESEncrypt(srcBytes, key, iv);
    ```

- #### DES decrypt bytes with iv (CBC mode)【NEW】

    ```csharp
    var encryptedBytes =  new byte[]{xxx};
    var encrypted = EncryptProvider.DESDecrypt(encryptedBytes, key, iv);
    ```

## RSA

  - #### Enum RsaSize

    ```csharp
    public enum RsaSize
    {
        R2048=2048,
        R3072=3072,
        R4096=4096
    }
    ```
  
  - #### Create RSA Key with RsaSize

    ```csharp
    var rsaKey = EncryptProvider.CreateRsaKey();    //default is 2048

	// var rsaKey = EncryptProvider.CreateRsaKey(RsaSize.R3072);

    var publicKey = rsaKey.PublicKey;
    var privateKey = rsaKey.PrivateKey;
    var exponent = rsaKey.Exponent;
    var modulus = rsaKey.Modulus;
    ```
	  
  - #### Rsa Sign and Verify method

    ```csharp
	string rawStr = "xxx";
    string signStr = EncryptProvider.RSASign(rawStr, privateKey);
    bool   result = EncryptProvider.RSAVerify(rawStr, signStr, publicKey);
    ```

  - #### RSA encrypt
  
    ```csharp
    var publicKey = rsaKey.PublicKey;
    var srcString = "rsa encrypt";

    
    var encrypted = EncryptProvider.RSAEncrypt(publicKey, srcString);

    // On mac/linux at version 2.0.5
    var encrypted = EncryptProvider.RSAEncrypt(publicKey, srcString, RSAEncryptionPadding.Pkcs1);

    ```
  
  - #### RSA decrypt

    ```csharp
    var privateKey = rsaKey.PrivateKey;
    var encryptedStr = "xxxx";

    var decrypted = EncryptProvider.RSADecrypt(privateKey, encryptedStr);

    // On mac/linux at version 2.0.5
    var decrypted = EncryptProvider.RSADecrypt(privateKey, encryptedStr, RSAEncryptionPadding.Pkcs1);
    ```

  - #### RSA from string 

    ```csharp
    var privateKey = rsaKey.PrivateKey;
    RSA rsa = EncryptProvider.RSAFromString(privateKey);
    ```

   - #### RSA with PEM

     ```csharp

	 //Rsa to pem format key

	 //PKCS1 pem
	 var pkcs1KeyTuple = EncryptProvider.RSAToPem(false);
	 var publicPem = pkcs1KeyTuple.publicPem;
	 var privatePem = pkcs1KeyTuple.privatePem;

	 //PKCS8 pem
	 var pkcs8KeyTuple = EncryptProvider.RSAToPem(true);
	 publicPem = pkcs8KeyTuple.publicPem;
	 privatePem = pkcs8KeyTuple.privatePem;

	 //Rsa from pem key

	 var rsa = EncryptProvider.RSAFromPem(pemPublicKey);
	 rsa = EncryptProvider.RSAFromPem(pemPrivateKey);

	 //Rsa encrypt and decrypt with pem key

	 var rawStr = "xxx";
	 var enctypedStr = EncryptProvider.RSAEncryptWithPem(pemPublicKey, rawStr);
	 var decryptedStr = EncryptProvider.RSADecryptWithPem(pemPrivateKey, enctypedStr);

	 ```
   - #### RSA with PKCS #1 / PKCS #8 

     ```csharp

	 //Rsa to pkcs1 format key

	 //PKCS1
	 var pkcs1KeyTuple = EncryptProvider.RsaToPkcs1();
	 var publicPkcs1 = pkcs1KeyTuple.publicPkcs1;
	 var privatePkcs1 = pkcs1KeyTuple.privatePkcs1;

	 //Rsa to pkcs8 format key
	 
	 //PKCS8
	 var pkcs8KeyTuple = EncryptProvider.RsaToPkcs8();
	 var publicPkcs8 = pkcs1KeyTuple.publicPkcs8;
	 var privatePkcs8 = pkcs1KeyTuple.privatePkcs8;

	 //Rsa from pkcs public key

	 var rsa = EncryptProvider.RSAFromPublicPkcs(pkcsPublicKey);  // Pkcs #1 | Pkcs #8
	 rsa = EncryptProvider.RSAFromPrivatePkcs1(privatePkcs1);
	 rsa = EncryptProvider.RSAFromPrivatePkcs8(privatePkcs8);
	 
	 //Rsa encrypt and decrypt with pkcs key
		


	 ```
  ## MD5
  
  ```csharp
  
  var srcString = "Md5 hash";
  var hashed = EncryptProvider.Md5(srcString);
  
  ```
  
  ```csharp
  
  var srcString = "Md5 hash";
  var hashed = EncryptProvider.Md5(srcString, MD5Length.L16);
  
  ```
  
  ## SHA
  
  - #### SHA1
    ```csharp
    var srcString = "sha hash";    
    var hashed = EncryptProvider.Sha1(srcString); 
    ```
  - #### SHA256
    ```csharp  
    var srcString = "sha hash";    
    var hashed = EncryptProvider.Sha256(srcString); 
    ```  
  - #### SHA384
    ```csharp  
    var srcString = "sha hash";    
    var hashed = EncryptProvider.Sha384(srcString); 
    ```
  - #### SHA512
    ```csharp
    var srcString = "sha hash";    
    var hashed = EncryptProvider.Sha512(srcString);
    ```
  
  ## HMAC
  
  - #### HMAC-MD5
    ```csharp
    var key="xxx";
    var srcString = "hmac md5 hash";     
    var hashed = EncryptProvider.HMACMD5(srcString,key);
    ```
  - #### HMAC-SHA1
    ```csharp
    var key="xxx";
    var srcString = "hmac sha hash";    
    var hashed = EncryptProvider.HMACSHA1(srcString,key);
    ```
  - #### HMAC-SHA256
    ```csharp
    var key="xxx";
    var srcString = "hmac sha hash";    
    var hashed = EncryptProvider.HMACSHA256(srcString,key);
    ```
  - #### HMAC-SHA384
    ```csharp
    var key="xxx";
    var srcString = "hmac sha hash";    
    var hashed = EncryptProvider.HMACSHA384(srcString,key);
    ```
  - #### HMAC-SHA512
    ```csharp
    var key="xxx";
    var srcString = "hmac sha hash";    
    var hashed = EncryptProvider.HMACSHA512(srcString，key);
    ```

  ## Base64 
  
  - #### Base64Encrypt
    ```csharp
    var srcString = "base64 string";    
    var hashed = EncryptProvider.Base64Encrypt(srcString);   //default encoding is UTF-8
    ```
	```csharp
    var srcString = "base64 string";    
    var hashed = EncryptProvider.Base64Encrypt(srcString,Encoding.ASCII);  
    ```
  - #### Base64Decrypt
    ```csharp  
    var encryptedStr = "xxxxx";    
    var strValue = EncryptProvider.Base64Decrypt(encryptedStr);   //default encoding is UTF-8
    ```  
	```csharp  
    var encryptedStr = "xxxxx";    
    var strValue = EncryptProvider.Base64Decrypt(encryptedStr,Encoding.ASCII); 
    ```  
***
# Easy to use hash with `EncryptExtensions`

## MD5 Extensions

   - ### String to MD5

   ```csharp
   var hashed="some string".MD5();
   ```
## SHA Extensions

   - ### String to SHA1

   ```csharp
   var hashed="some string".SHA1();
   ```
   
 ### `Tips：SHA256,SHA384,SHA512 the same usage like SHA1 `
 
 ## HMACSHA Extensions

   - ### String to HMACSHA1

   ```csharp
   var key="xxx";
   var hashed="some string".HMACSHA1(key);
   ```
   
 ### `Tips：HMACSHA256,HMACSHA384,HMACSHA512 the same usage like HMACSHA1 `


# LICENSE

[MIT License](https://github.com/myloveCc/NETCore.Encrypt/blob/master/License)

