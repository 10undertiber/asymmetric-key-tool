/*
 *
 * Copyright (c) 2023 10 Under Tiber Studio
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

package com.tenut.asymmetrickeytool;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;

import org.junit.Test;

final public class LegacyApiCompatibilityTest {

  @Test
  public void shouldKeepLegacyGeneratorMethods() throws Exception {
    assertMethod(AsymmetricKeyGenerator.class, "newKeyPair", AsymmetricKeyPair.class,
        AsymmetricKeyAlgorithm.class);
    assertMethod(AsymmetricKeyGenerator.class, "loadKeyPair", AsymmetricKeyPair.class,
        AsymmetricKeyAlgorithm.class, String.class, String.class);
    assertMethod(AsymmetricKeyGenerator.class, "loadPrivateKey", PrivateKey.class,
        AsymmetricKeyAlgorithm.class, String.class);
    assertMethod(AsymmetricKeyGenerator.class, "loadPublicKey", PublicKey.class,
        AsymmetricKeyAlgorithm.class, String.class);
  }

  @Test
  public void shouldKeepLegacyPairAndKeyMethods() throws Exception {
    assertMethod(AsymmetricKeyPair.class, "encrypt", String.class, String.class);
    assertMethod(AsymmetricKeyPair.class, "encrypt", byte[].class, byte[].class);
    assertMethod(AsymmetricKeyPair.class, "decrypt", String.class, String.class);
    assertMethod(AsymmetricKeyPair.class, "decrypt", byte[].class, byte[].class);
    assertMethod(AsymmetricKeyPair.class, "sign", String.class, String.class);
    assertMethod(AsymmetricKeyPair.class, "sign", byte[].class, byte[].class);
    assertMethod(AsymmetricKeyPair.class, "verify", boolean.class, String.class, String.class);
    assertMethod(AsymmetricKeyPair.class, "verify", boolean.class, byte[].class, byte[].class);
    assertMethod(PublicKey.class, "toBase64", String.class);
    assertMethod(PrivateKey.class, "toBase64", String.class);
  }

  private void assertMethod(Class<?> type, String name, Class<?> returnType,
      Class<?>... parameterTypes) throws Exception {
    Method method = type.getMethod(name, parameterTypes);
    assertThat(method.getReturnType()).isEqualTo(returnType);
  }
}
