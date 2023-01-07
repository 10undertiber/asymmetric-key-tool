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

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RS256PublicKey extends PublicKey {

  private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
  private static final String CIPHER_ALGORITHM = "RSA";

  private RSAPublicKey key;
  private Signature signature;
  private Cipher cipher;

  RS256PublicKey(KeyFactory factory, KeyPair keyPair) throws UnknownAsymmetricKeyAlgorithmException,
      InvalidAsymmetricKeyException {
    super(factory, keyPair);
  }

  RS256PublicKey(KeyFactory factory, String encodedKey) throws InvalidAsymmetricKeyException,
      UnknownAsymmetricKeyAlgorithmException, InvalidEncodingException {
    super(factory, encodedKey);
  }

  @Override
  void newKey(KeyFactory factory, KeyPair keyPair) throws InvalidAsymmetricKeyException {
    try {
      X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
      this.key = (RSAPublicKey) factory.generatePublic(pubSpec);

      this.signature = Signature.getInstance(SIGNATURE_ALGORITHM);
      this.signature.initVerify(this.key);

      this.cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      this.cipher.init(Cipher.ENCRYPT_MODE, this.key);
    } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException e) {
      throw new InvalidAsymmetricKeyException("Public key format not valid");
    }
  }

  @Override
  void decodeKey(KeyFactory factory, byte[] encoded) throws InvalidAsymmetricKeyException {
    try {
      X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(encoded);
      this.key = (RSAPublicKey) factory.generatePublic(pubSpec);

      this.signature = Signature.getInstance(SIGNATURE_ALGORITHM);
      this.signature.initVerify(this.key);

      this.cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      this.cipher.init(Cipher.ENCRYPT_MODE, this.key);
    } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException e) {
      throw new InvalidAsymmetricKeyException("Public key format not valid");
    }
  }

  @Override
  byte[] encodeKey() {
    return key.getEncoded();
  }

  @Override
  byte[] encryptData(String plainText) throws InvalidEncodingException {
    try {
      return this.cipher.doFinal(plainText.getBytes());
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new InvalidEncodingException("Cannot encrypt text");
    }
  }

  @Override
  boolean verifyData(String input, byte[] output) throws InvalidEncodingException {
    try {
      this.signature.update(input.getBytes("UTF-8"));
      return this.signature.verify(output);
    } catch (SignatureException | UnsupportedEncodingException e) {
      throw new InvalidEncodingException("Signature encoding not supported");
    }
  }
}
