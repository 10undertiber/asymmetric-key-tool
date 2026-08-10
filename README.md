# Asymmetric Key Tool

Java library for generating, serializing, loading, and using RSA key pairs
through the standard JCA APIs.

The library provides two explicit profiles:

- `ASYMMETRIC_KEY_ALGORITHM_RSA`: the legacy RSA profile, kept for backward
  compatibility with existing keys, ciphertexts, and signatures;
- `ASYMMETRIC_KEY_ALGORITHM_RSA_V2`: the profile for new authenticated
  encryption and signature operations.

The same 2048-bit RSA key pair can be used for encryption and signing. The
operation profile determines the cryptographic parameters; the PKCS#8 private
key and X.509 public key serialization remain unchanged.

## Requirements

- Java 9 or later;
- standard JCA/JCE providers only.

## Installation

Add the library to your Maven project using the version published in the
project's releases:

```xml
<dependency>
  <groupId>com.tenut</groupId>
  <artifactId>asymmetrickeytool</artifactId>
  <version>${asymmetrickeytool.version}</version>
</dependency>
```

## RSA v2

Use the explicit v2 profile for new operations. RSA-OAEP v2 uses SHA-256 for
the digest and MGF1, while RSA-PSS v2 uses SHA-256 for the digest and MGF1
with a 32-byte salt.

```java
import com.tenut.asymmetrickeytool.AsymmetricKeyAlgorithm;
import com.tenut.asymmetrickeytool.AsymmetricKeyPair;
import com.tenut.asymmetrickeytool.AsymmetricKeyGenerator;

AsymmetricKeyPair keyPair = AsymmetricKeyGenerator.newKeyPair(
    AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_RSA_V2);

String ciphertext = keyPair.encryptV2("secret message");
String plaintext = keyPair.decryptV2(ciphertext);

String signature = keyPair.signV2("message");
boolean valid = keyPair.verifyV2("message", signature);
```

RSA-OAEP is intended for small values such as data-encryption keys. Application
payloads should generally be encrypted with a symmetric authenticated cipher,
such as AES-GCM, and only the symmetric key should be wrapped with RSA-OAEP.

The v2 ciphertext and signature formats are versioned. A malformed or
unsupported v2 envelope is rejected without silently falling back to legacy
parameters.

## Legacy RSA profile

The `ASYMMETRIC_KEY_ALGORITHM_RSA` profile and the existing `encrypt(...)`,
`decrypt(...)`, `sign(...)`, and `verify(...)` methods retain their original
behavior. This includes support for existing PKCS#8/X.509 keys, legacy OAEP
ciphertexts, and `SHA512withRSA` signatures.

Use the legacy APIs only when interoperating with existing legacy data:

```java
AsymmetricKeyPair legacyKeyPair = AsymmetricKeyGenerator.newKeyPair(
    AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_RSA);

String ciphertext = legacyKeyPair.encrypt("legacy message");
String plaintext = legacyKeyPair.decrypt(ciphertext);

String signature = legacyKeyPair.sign("message");
boolean valid = legacyKeyPair.verify("message", signature);
```

Legacy and v2 ciphertexts and signatures are intentionally not interchangeable.
The existing public method signatures remain available when upgrading the
library dependency.

## Key serialization

Private keys are serialized as PKCS#8 and public keys as X.509, both encoded as
Base64 strings. Existing key serializations remain loadable:

```java
String privateKey = keyPair.getPrivateKey().toBase64();
String publicKey = keyPair.getPublicKey().toBase64();

AsymmetricKeyPair restored = AsymmetricKeyGenerator.loadKeyPair(
    AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_RSA,
    publicKey,
    privateKey);
```

## Native Image smoke test

The repository includes a small GraalVM Native smoke-test harness. Install
`native-image` and run:

```sh
sh native-smoke.sh
```

The implementation uses standard JCA classes and does not require external
cryptographic providers.

## Development

Run the complete Maven verification, including tests, Checkstyle, and
SpotBugs:

```sh
mvn verify
```

## License

Copyright © 2023 10 Under Tiber Studio.

Distributed under the Apache License, Version 2.0.
