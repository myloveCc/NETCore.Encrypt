# NETCore.Encrypt
NETCore encrypt and decrpty tool，Include AES，RSA，MD5，SAH1，SAH256，SHA384，SHA512 and more

To install NETCore.Encrypt, run the following command in the [Package Manager Console](https://docs.microsoft.com/zh-cn/nuget/tools/package-manager-console)
```
Install-Package NETCore.Encrypt -Version 2.0.1
```

***

# Easy to use with `EncryptProvider`

## AES

#### Create AES Key

  ```csharp
  var aseKey = EncryptProvider.CreateAesKey();
  
  var key = aesKey.Key;
  var iv = aesKey.IV;
  ```

#### AES encrypt
  - AES encrypt without iv

    ```csharp
    var srcString = "aes encrypt";
    var encrypted = EncryptProvider.AESEncrypt(srcString, key);

    ```
  - AES encrypt with iv

    ```csharp
    var srcString = "aes encrypt";
    var encrypted = EncryptProvider.AESEncrypt(srcString, key, iv);

    ```
#### ASE decrypt

  - AES decrypt without iv
    
    ```csharp
    var encryptedStr = "xxxx";
    var decrypted = EncryptProvider.AESDecrypt(encryptedStr, key);
    ```
  
  - AES decrypt with iv
   
    ```csharp
    var encryptedStr = "xxxx";
    var decrypted = EncryptProvider.AESDecrypt(encryptedStr, key, iv);
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
  
  - #### Create RSA Key with RsaSize(update at version 2.0.1)

    ```csharp
    var rsaKey = EncryptProvider.CreateRsaKey();    //default is 2048

	// var rsaKey = EncryptProvider.CreateRsaKey(RsaSize.R3072);

    var publicKey = rsaKey.PublicKey;
    var privateKey = rsaKey.PrivateKey;
    var exponent = rsaKey.Exponent;
    var modulus = rsaKey.Modulus;
    ```
  - #### RSA encrypt
  
    ```csharp
    var publicKey = rsaKey.PublicKey;
    var srcString = "rsa encrypt";

    var encrypted = EncryptProvider.RSAEncrypt(publicKey, srcString);
    ```
  
  - #### RSA decrypt

    ```csharp
    var privateKey = rsaKey.PrivateKey;
    var encryptedStr = "xxxx";

    var decrypted = EncryptProvider.RSADecrypt(privateKey, encryptedStr);
    ```

  - #### RSA from string (add at version 2.0.1)

    ```csharp
    var privateKey = rsaKey.PrivateKey;
    RSA rsa = EncryptProvider.RSAFromString(privateKey);
    ```
  
  ## MD5
  
  ```csharp
  
  var srcString = "Md5 hash";
  var hashed = EncryptProvider.Md5(srcString);
  
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
