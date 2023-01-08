# 🛠️ Asymmetric Key Tool 🛠️

A library to easily use asymmetric cryptography in Java

## 🌱 Add to your project

```xml
<dependency>
  <groupId>com.tenut</groupId>
  <artifactId>asymmetrickeytool</artifactId>
  <version>0.1.5</version>
</dependency>
```

## 🦾 Use the thing

```java
import com.tenut.asymmetrickeytool.AsymmetricKeyGenerator;

class Example {
  void doIt() {
    
    String plainMessage = "This is a secret message...";

    // Create new keys
    AsymmetricKeyPair keyPair = AsymmetricKeyGenerator.newKeyPair(AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_RS256);

    // Encode a message
    String encryptedMessage = keyPair.encrypt(plainMessage);

    // Decode a message
    String decryptedMessage = keyPair.decrypt(encryptedMessage);

    // Sign a message
    String signature = keyPair.sign(plainMessage);

    // Verify a message
    boolean verified = keyPair.verify(plainMessage, signature);

    // Export private and public key
    String privateKey = keyPair.getPrivateKey().toBase64();
    String publicKey = keyPair.getPublicKey().toBase64();

    // Load an existing key pair
    AsymmetricKeyPair loadedKeyPair = AsymmetricKeyGenerator.loadKeyPair(AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_RS256, publicKey, privateKey);
  } 
}
```

## 🔬 How it works

Asymmetric cryptography is a branch of cryptography where a secret key can be divided into two parts, a public key and a private key. The public key can be given to anyone, trusted or not, while the private key must be kept secret (just like the key in symmetric cryptography).

Asymmetric cryptography has two primary use cases: authentication and confidentiality. Using asymmetric cryptography, messages can be signed with a private key, and then anyone with the public key is able to verify that the message was created by someone possessing the corresponding private key. This can be combined with a proof of identity system to know what entity (person or group) actually owns that private key, providing authentication.

Encryption with asymmetric cryptography works in a slightly different way from symmetric encryption. Someone with the public key is able to encrypt a message, providing confidentiality, and then only the person in possession of the private key is able to decrypt it.

  [Read More](https://en.wikipedia.org/wiki/Public-key_cryptography)

---

## 🚧 Roadmap

 * [x] [RSA](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
 * [ ] [ECDSA](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/)

---

## 🎙 Credits

This project has been inspired by:

- [Cryptography 101 for Java Developers by Michel Schudel](https://www.youtube.com/watch?v=1925zmDP_BY)

---

## 👔 License

Copyright © 2023 10 Under Tiber Studio

Distributed under the Apache License 2.0.
