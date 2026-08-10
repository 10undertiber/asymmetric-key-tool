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

  public String encryptV2(String plainText) throws InvalidEncodingException {
    return Base64.getEncoder().encodeToString(encryptV2(plainText.getBytes(
        java.nio.charset.StandardCharsets.UTF_8)));
  }

  public byte[] encryptV2(byte[] plainText) throws InvalidEncodingException {
    return encryptV2Data(plainText);
  }

  public boolean verify(String input, String output) throws InvalidEncodingException {
    try {
      return verify(input.getBytes(java.nio.charset.StandardCharsets.UTF_8), Base64.getDecoder().decode(output));
    } catch (IllegalArgumentException e) {
      throw new InvalidEncodingException("Signature encoding not valid", e);
    }
  }

  public boolean verify(byte[] input, byte[] output) throws InvalidEncodingException {
    return verifyData(input, output);
  }

  public boolean verifyV2(String input, String output) throws InvalidEncodingException {
    try {
      return verifyV2(input.getBytes(java.nio.charset.StandardCharsets.UTF_8),
          Base64.getDecoder().decode(output));
    } catch (IllegalArgumentException e) {
      throw new InvalidEncodingException("Signature encoding not valid", e);
    }
  }

  public boolean verifyV2(byte[] input, byte[] output) throws InvalidEncodingException {
    return verifyV2Data(input, output);
  }

  abstract byte[] encryptData(byte[] plainText) throws InvalidEncodingException;

  abstract boolean verifyData(byte[] input, byte[] output) throws InvalidEncodingException;

  byte[] encryptV2Data(byte[] plainText) throws InvalidEncodingException {
    throw new InvalidEncodingException("RSA v2 encryption is not supported by this key");
  }

  boolean verifyV2Data(byte[] input, byte[] output) throws InvalidEncodingException {
    throw new InvalidEncodingException("RSA v2 signatures are not supported by this key");
  }
}
