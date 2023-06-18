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
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

final public class RSAPrivateKey extends PrivateKey {

  private java.security.interfaces.RSAPrivateKey key;
  private Signature signature;
  private Cipher cipher;

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

      this.signature = Signature.getInstance("SHA512withRSA", "BC");
      this.signature.initSign(this.key);

      this.cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
      this.cipher.init(Cipher.DECRYPT_MODE, this.key);

    } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException
        | NoSuchProviderException e) {
      e.printStackTrace();
      throw new InvalidAsymmetricKeyException("Private key format not valid");
    }
  }

  @Override
  void decodeKey(KeyFactory factory, byte[] encoded) throws InvalidAsymmetricKeyException {
    try {
      PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encoded);
      this.key = (java.security.interfaces.RSAPrivateKey) factory.generatePrivate(privSpec);

      this.signature = Signature.getInstance("SHA512withRSA", "BC");
      this.signature.initSign(this.key);

      this.cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
      this.cipher.init(Cipher.DECRYPT_MODE, this.key);
    } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException
        | NoSuchProviderException e) {
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
      this.signature.update(input);
      return this.signature.sign();
    } catch (SignatureException e) {
      throw new InvalidEncodingException("Signature encoding not supported");
    }
  }

  @Override
  public byte[] decryptData(byte[] encryptedText) throws InvalidEncodingException {
    try {
      return this.cipher.doFinal(encryptedText);
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new InvalidEncodingException("Cannot decrypt text");
    }
  }
}
