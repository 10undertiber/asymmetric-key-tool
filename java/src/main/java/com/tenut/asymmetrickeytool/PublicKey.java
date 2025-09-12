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

package com.tenut.asymmetrickeytool;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.util.Base64;

abstract public class PublicKey extends Key {
  PublicKey(KeyFactory factory, KeyPair keyPair) throws UnknownAsymmetricKeyAlgorithmException,
      InvalidAsymmetricKeyException {
    super(factory, keyPair);
  }

  PublicKey(KeyFactory factory, String encodedKey) throws InvalidAsymmetricKeyException,
      UnknownAsymmetricKeyAlgorithmException, InvalidEncodingException {
    super(factory, encodedKey);
  }

  public String encrypt(String plainText) throws InvalidEncodingException {
    return Base64.getEncoder().encodeToString(encrypt(plainText.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
  }

  public byte[] encrypt(byte[] plainText) throws InvalidEncodingException {
    return encryptData(plainText);
  }

  public boolean verify(String input, String output) throws InvalidEncodingException {
    try {
      return verify(input.getBytes(java.nio.charset.StandardCharsets.UTF_8), Base64.getDecoder().decode(output));
    } catch (IllegalArgumentException e) {
      throw new InvalidEncodingException("Signature encoding not valid");
    }
  }

  public boolean verify(byte[] input, byte[] output) throws InvalidEncodingException {
    return verifyData(input, output);
  }

  abstract byte[] encryptData(byte[] plainText) throws InvalidEncodingException;

  abstract boolean verifyData(byte[] input, byte[] output) throws InvalidEncodingException;
}
