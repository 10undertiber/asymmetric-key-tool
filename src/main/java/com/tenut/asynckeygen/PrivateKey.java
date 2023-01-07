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

abstract public class PrivateKey extends Key {

  PrivateKey(KeyFactory factory, KeyPair keyPair) throws UnknownAsymmetricKeyAlgorithmException,
      InvalidAsymmetricKeyException {
    super(factory, keyPair);
  }

  PrivateKey(KeyFactory factory, String encodedKey) throws InvalidAsymmetricKeyException,
      UnknownAsymmetricKeyAlgorithmException {
    super(factory, encodedKey);
  }

  public String decrypt(String encryptedText) throws InvalidEncodingException {
    return decryptData(Base64.getDecoder().decode(encryptedText));
  }

  abstract String decryptData(byte[] encryptedText) throws InvalidEncodingException;
}
