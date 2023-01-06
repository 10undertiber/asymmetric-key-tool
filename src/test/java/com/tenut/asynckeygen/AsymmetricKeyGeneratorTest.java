/*
 * Copyright © 2023 10 Under Tiber Studio
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

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class AsymmetricKeyGeneratorTest {
  @Test
  public void shouldAnswerWithTrue() {
    AsymmetricKeyPair key = AsymmetricKeyGenerator.newKeyPair(AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_R256);
    assertNotNull(key);
  }
}
