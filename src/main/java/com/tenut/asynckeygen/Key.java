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
import java.util.Base64;

abstract class Key {
  Key(KeyFactory factory, KeyPair keyPair) throws UnknownAsymmetricKeyAlgorithmException,
      InvalidAsymmetricKeyException {
    newKey(factory, keyPair);
  }

  Key(KeyFactory factory, String encodedKey) throws InvalidAsymmetricKeyException,
      UnknownAsymmetricKeyAlgorithmException {
    decode(factory, encodedKey);
  }

  void decode(KeyFactory factory, String encoded) throws InvalidAsymmetricKeyException {
    decodeKey(factory, Base64.getDecoder().decode(encoded));
  }

  String asBase64String() throws InvalidAsymmetricKeyException {
    return Base64.getEncoder().encodeToString(encodeKey());
  }

  abstract void newKey(KeyFactory factory, KeyPair keyPair) throws InvalidAsymmetricKeyException;

  abstract void decodeKey(KeyFactory factory, byte[] encoded) throws InvalidAsymmetricKeyException;

  abstract byte[] encodeKey();

  public String sign(String input) throws UnknownAsymmetricKeyAlgorithmException,
      InvalidAsymmetricKeyException, InvalidEncodingException {
    return Base64.getEncoder().encodeToString(signData(input));
  }

  public boolean verify(String input, String output) throws UnknownAsymmetricKeyAlgorithmException,
      InvalidAsymmetricKeyException, InvalidEncodingException {
    return verifyData(input, output);
  }

  abstract byte[] signData(String input) throws InvalidAsymmetricKeyException,
      InvalidEncodingException;

  abstract boolean verifyData(String input, String output) throws InvalidAsymmetricKeyException,
      InvalidEncodingException;
}
