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
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class RS256PrivateKey extends PrivateKey {

  private RSAPrivateKey key;

  RS256PrivateKey(KeyFactory factory, KeyPair keyPair) {
    super(factory, keyPair);
  }

  RS256PrivateKey(KeyFactory factory, String encodedKey) throws InvalidAsymmetricKeyException {
    super(factory, encodedKey);
  }

  @Override
  void newKey(KeyFactory factory, KeyPair keyPair) {
    this.key = (RSAPrivateKey) keyPair.getPrivate();
  }

  @Override
  void decodeKey(KeyFactory factory, byte[] encoded) throws InvalidAsymmetricKeyException {
    try {
      PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encoded);
      this.key = (RSAPrivateKey) factory.generatePrivate(privSpec);
    } catch (InvalidKeySpecException | NullPointerException e) {
      throw new InvalidAsymmetricKeyException("Private key format not valid");
    }
  }

  @Override
  byte[] encodeKey() {
    return key.getEncoded();
  }

  @Override
  public String encrypt(String input) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public String decrypt(String input) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public boolean verify(String input, String output) {
    // TODO Auto-generated method stub
    return false;
  }

}
