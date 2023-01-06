# Asymmetric Key Generator

[![CircleCI](https://circleci.com/gh/10undertiber/asymmetric-key-generator.svg?style=svg)](https://circleci.com/gh/10undertiber/asymmetric-key-generator)

A Java implementation of [Asymmetric cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography).

## Add to your project

```xml
<dependency>
  <groupId>com.tenut</groupId>
  <artifactId>asynckeygen</artifactId>
  <version>0.0.1</version>
</dependency>
```

## Use the thing

```java
import com.tenut.asynckeygen.AsymmetricKeyGenerator;

class Example {
  void doIt() {
    AsymmetricKeyPair key = AsymmetricKeyGenerator.newKeyPair(AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_R256);
    
    System.out.println("Hello world!");
  } 
}
```

## How it works

**`TODO`**

## License

Copyright © 2023 10 Under Tiber Studio

Distributed under the Apache License 2.0.
