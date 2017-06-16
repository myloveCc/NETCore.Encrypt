# NETCore.Encrypt
NETCore encrypt and decrpty tool，Include AES，RSA，MD5，SAH1，SAH256，SHA384，SHA512 and more

To install NETCore.Encrypt, run the following command in the [Package Manager Console](https://docs.microsoft.com/zh-cn/nuget/tools/package-manager-console)
```
Install-Package NETCore.Encrypt
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
    var encrypted = EncryptProvider.AESDecrypt(encryptedStr, key);
    ```
  
  - AES decrypt with iv
   
    ```csharp
    var encryptedStr = "xxxx";
    var encrypted = EncryptProvider.AESDecrypt(encryptedStr, key, iv);
    ```
    
  ## RSA
  
  - #### Create RSA Key

    ```csharp
    var rsaKey = EncryptProvider.CreateRsaKey();

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

    var encrypted = EncryptProvider.RSADecrypt(privateKey, encryptedStr);
    ```
  
  ## MD5
  
  ```csharp
  
  var srcString = "Md5 hash";
  var hashed = EncryptProvider.Md5(srcString);
  
  ```
  
  ## SHA
  
  - #### SHA1
    ```csharp
    var srcString = "sha encrypt";    
    var hashed = EncryptProvider.Sha1(srcString); 
    ```
  - #### SHA256
    ```csharp  
    var srcString = "sha encrypt";    
    var hashed = EncryptProvider.Sha256(srcString); 
    ```  
  - #### SHA384
    ```csharp  
    var srcString = "sha encrypt";    
    var hashed = EncryptProvider.Sha384(srcString); 
    ```
  - #### SHA512
    ```csharp
    var srcString = "sha encrypt";    
    var hashed = EncryptProvider.Sha512(srcString);
    ```
  
  ## HMAC
  
  - #### HMAC-MD5
    ```csharp
    var key="xxx";
    var srcString = "hmac md5 encrypt";     
    var hashed = EncryptProvider.HMACMD5(srcString,key);
    ```
  - #### HMAC-SHA1
    ```csharp
    var key="xxx";
    var srcString = "hmac sha encrypt";    
    var hashed = EncryptProvider.HMACSHA1(srcString,key);
    ```
  - #### HMAC-SHA256
    ```csharp
    var key="xxx";
    var srcString = "hmac sha encrypt";    
    var hashed = EncryptProvider.HMACSHA256(srcString,key);
    ```
  - #### HMAC-SHA384
    ```csharp
    var key="xxx";
    var srcString = "hmac sha encrypt";    
    var hashed = EncryptProvider.HMACSHA384(srcString,key);
    ```
  - #### HMAC-SHA512
    ```csharp
    var key="xxx";
    var srcString = "hmac sha encrypt";    
    var hashed = EncryptProvider.HMACSHA512(srcString，key);
    ```
    
***
# Easy to use with `EncryptExtensions`

## coming soon...
