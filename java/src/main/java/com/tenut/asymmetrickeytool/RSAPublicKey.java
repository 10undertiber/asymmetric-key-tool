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

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

final public class RSAPublicKey extends PublicKey {

  private java.security.interfaces.RSAPublicKey key;
  private Signature signature;
  private Cipher cipher;

  private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
  private static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";

  RSAPublicKey(KeyFactory factory, KeyPair keyPair) throws UnknownAsymmetricKeyAlgorithmException,
      InvalidAsymmetricKeyException {
    super(factory, keyPair);
  }

  RSAPublicKey(KeyFactory factory, String encodedKey) throws InvalidAsymmetricKeyException,
      UnknownAsymmetricKeyAlgorithmException, InvalidEncodingException {
    super(factory, encodedKey);
  }

  @Override
  void newKey(KeyFactory factory, KeyPair keyPair) throws InvalidAsymmetricKeyException {
    try {
      X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
      this.key = (java.security.interfaces.RSAPublicKey) factory.generatePublic(pubSpec);

      this.signature = Signature.getInstance(SIGNATURE_ALGORITHM);
      this.signature.initVerify(this.key);

      this.cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      this.cipher.init(Cipher.ENCRYPT_MODE, this.key);
    } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException e) {
      e.printStackTrace();
      throw new InvalidAsymmetricKeyException("Public key format not valid");
    }
  }

  @Override
  void decodeKey(KeyFactory factory, byte[] encoded) throws InvalidAsymmetricKeyException {
    try {
      X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(encoded);
      this.key = (java.security.interfaces.RSAPublicKey) factory.generatePublic(pubSpec);

      this.signature = Signature.getInstance(SIGNATURE_ALGORITHM);
      this.signature.initVerify(this.key);

      this.cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      this.cipher.init(Cipher.ENCRYPT_MODE, this.key);
    } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException e) {
      e.printStackTrace();
      throw new InvalidAsymmetricKeyException("Public key format not valid");
    }
  }

  @Override
  byte[] encodeKey() {
    return key.getEncoded();
  }

  @Override
  byte[] encryptData(byte[] plainText) throws InvalidEncodingException {
    try {
      return this.cipher.doFinal(plainText);
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new InvalidEncodingException("Cannot encrypt text");
    }
  }

  @Override
  boolean verifyData(byte[] input, byte[] output) throws InvalidEncodingException {
    try {
      this.signature.update(input);
      return this.signature.verify(output);
    } catch (SignatureException e) {
      throw new InvalidEncodingException("Signature encoding not supported");
    }
  }
}
