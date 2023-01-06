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

public class AsymmetricKeyGenerator {

  public static AsymmetricKeyPair newKeyPair(AsymmetricKeyAlgorithm algorithm)
      throws UnknownAsymmetricKeyAlgorithmException {
    AsymmetricKeyPairBuilder builder = AsymmetricKeyGenerator.getBuilder(algorithm);

    return builder.newKeyPair();
  }

  public static AsymmetricKeyPair loadKeyPair(AsymmetricKeyAlgorithm algorithm, String publicKey, String privateKey)
      throws UnknownAsymmetricKeyAlgorithmException, InvalidAsymmetricKeyException {
    AsymmetricKeyPairBuilder builder = AsymmetricKeyGenerator.getBuilder(algorithm);

    return builder.loadKeyPair(publicKey, privateKey);
  }

  private static AsymmetricKeyPairBuilder getBuilder(AsymmetricKeyAlgorithm algorithm)
      throws UnknownAsymmetricKeyAlgorithmException {
    switch (algorithm) {
      case ASYMMETRIC_KEY_ALGORITHM_RS256:
        return new RS256KeyPairBuilder();
      default:
        throw new UnknownAsymmetricKeyAlgorithmException("Algorithm not found");
    }
  }
}
