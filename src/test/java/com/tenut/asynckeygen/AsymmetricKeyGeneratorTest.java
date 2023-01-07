/*
 *
 * Copyright (c) 2023 10 Under Tiber Studio
 *
 * Licensed under the Apache License, Version 2. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.tenut.asynckeygen;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class AsymmetricKeyGeneratorTest {

  private static final String Base64Regex = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$";

  @Test
  public void shouldPass() throws UnknownAsymmetricKeyAlgorithmException, InvalidAsymmetricKeyException {
    AsymmetricKeyAlgorithm[] algorithms = { AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_RS256 };

    for (AsymmetricKeyAlgorithm asymmetricKeyAlgorithm : algorithms) {

      assertThatCode(() -> AsymmetricKeyGenerator.newKeyPair(
          asymmetricKeyAlgorithm))
          .doesNotThrowAnyException();

      AsymmetricKeyPair generatedKeyPair = AsymmetricKeyGenerator
          .newKeyPair(asymmetricKeyAlgorithm);

      assertNotNull(generatedKeyPair);

      String generatedPrivateKey = generatedKeyPair.getPrivateKey().asBase64String();
      String generatedPublicKey = generatedKeyPair.getPublicKey().asBase64String();

      assertTrue(generatedPrivateKey.matches(Base64Regex));
      assertTrue(generatedPublicKey.matches(Base64Regex));

      assertThatCode(() -> AsymmetricKeyGenerator.loadKeyPair(
          asymmetricKeyAlgorithm,
          generatedPublicKey, generatedPrivateKey))
          .doesNotThrowAnyException();

      AsymmetricKeyPair loadedKeyPair = AsymmetricKeyGenerator.loadKeyPair(
          asymmetricKeyAlgorithm,
          generatedPublicKey, generatedPrivateKey);

      assertNotNull(loadedKeyPair);

      String loadedPrivateKey = loadedKeyPair.getPrivateKey().asBase64String();
      String loadedPublicKey = loadedKeyPair.getPublicKey().asBase64String();

      assertEquals(loadedPublicKey, generatedPublicKey);
      assertEquals(loadedPrivateKey, generatedPrivateKey);

      String plainMessage = "Hello, World!";
      String encryptedMessage = generatedKeyPair.getPrivateKey().encrypt(plainMessage);
      String decryptedMessage = loadedKeyPair.getPrivateKey().decrypt(encryptedMessage);

      assertEquals(plainMessage, decryptedMessage);

      assertTrue(loadedKeyPair.getPublicKey().verify(plainMessage, encryptedMessage));
    }

  }
}
