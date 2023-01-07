# Asymmetric Key Tool

[![CircleCI](https://circleci.com/gh/10undertiber/asymmetric-key-tool.svg?style=svg)](https://circleci.com/gh/10undertiber/asymmetric-key-tool)

An easy way to create, load and use asymmetric private/public keys in Java.

## Add to your project

```xml
<dependency>
  <groupId>com.tenut</groupId>
  <artifactId>asymmetrickeytool</artifactId>
  <version>0.0.6</version>
</dependency>
```

## Use the thing

```java
import com.tenut.asymmetrickeytool.AsymmetricKeyGenerator;

class Example {
  void doIt() {
    
    String plainMessage = "This is a secret message...";

    // Create new keys
    AsymmetricKeyPair key = AsymmetricKeyGenerator.newKeyPair(AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_R256);

    // Encode a message
    String encryptedMessage = generatedKeyPair.encrypt(plainMessage);

    // Decode a message
    String decryptedMessage = generatedKeyPair.decrypt(encryptedMessage);

    // Sign a message
    String signature = generatedKeyPair.sign(plainMessage);

    // Verify a message
    boolean verified = generatedKeyPair.verify(plainMessage, signature);

    // Export private and public key
    String privateKey = key.getPrivateKey().toBase64();
    String publicKey = key.getPublicKey().toBase64();

    // Load an existing key pair
    AsymmetricKeyPair loadedKeyPair = AsymmetricKeyGenerator.loadKeyPair(AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_R256, publicKey, privateKey);
  } 
}
```

## How it works

- [Asymmetric cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography)
- [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))

---

## License

Copyright © 2023 10 Under Tiber Studio

Distributed under the Apache License 2.0.
