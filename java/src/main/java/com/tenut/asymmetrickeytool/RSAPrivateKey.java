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
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

final public class RSAPrivateKey extends PrivateKey {

  private java.security.interfaces.RSAPrivateKey key;

  private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
  private static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";

  RSAPrivateKey(KeyFactory factory, KeyPair keyPair) throws UnknownAsymmetricKeyAlgorithmException,
      InvalidAsymmetricKeyException {
    super(factory, keyPair);
  }

  RSAPrivateKey(KeyFactory factory, String encodedKey) throws InvalidAsymmetricKeyException,
      UnknownAsymmetricKeyAlgorithmException, InvalidEncodingException {
    super(factory, encodedKey);
  }

  @Override
  void newKey(KeyFactory factory, KeyPair keyPair) throws InvalidAsymmetricKeyException {
    try {
      PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
      this.key = (java.security.interfaces.RSAPrivateKey) factory.generatePrivate(privSpec);

    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
      throw new InvalidAsymmetricKeyException("Private key format not valid");
    }
  }

  @Override
  void decodeKey(KeyFactory factory, byte[] encoded) throws InvalidAsymmetricKeyException {
    try {
      PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encoded);
      this.key = (java.security.interfaces.RSAPrivateKey) factory.generatePrivate(privSpec);
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
      throw new InvalidAsymmetricKeyException("Private key format not valid");
    }
  }

  @Override
  byte[] encodeKey() {
    return key.getEncoded();
  }

  @Override
  byte[] signData(byte[] input) throws InvalidEncodingException {
    try {
      Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
      sig.initSign(this.key);
      sig.update(input);
      return sig.sign();
    } catch (Exception e) {
      throw new InvalidEncodingException("Signature encoding not supported");
    }
  }

  @Override
  byte[] decryptData(byte[] encryptedText) throws InvalidEncodingException {
    try {
      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, this.key);
      return cipher.doFinal(encryptedText);
    } catch (Exception e) {
      throw new InvalidEncodingException("Cannot decrypt text");
    }
  }
}
