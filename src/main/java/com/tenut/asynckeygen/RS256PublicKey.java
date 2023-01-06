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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RS256PublicKey extends PublicKey {

  private RSAPublicKey key;

  RS256PublicKey(KeyFactory factory, KeyPair keyPair) {
    super(factory, keyPair);
  }

  RS256PublicKey(KeyFactory factory, String encodedKey) throws InvalidAsymmetricKeyException {
    super(factory, encodedKey);
  }

  @Override
  void newKey(KeyFactory factory, KeyPair keyPair) {
    this.key = (RSAPublicKey) keyPair.getPublic();
  }

  @Override
  void decodeKey(KeyFactory factory, String encoded) throws InvalidAsymmetricKeyException {
    try {
      X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(Base64.getDecoder().decode(encoded));
      this.key = (RSAPublicKey) factory.generatePublic(pubSpec);
    } catch (InvalidKeySpecException | NullPointerException e) {
      throw new InvalidAsymmetricKeyException("Public key format not valid");
    }
  }

  @Override
  String encodeKey() {
    return Base64.getEncoder().encodeToString(key.getEncoded());
  }
}
