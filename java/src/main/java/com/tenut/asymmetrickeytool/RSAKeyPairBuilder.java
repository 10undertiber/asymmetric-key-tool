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
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

final public class RSAKeyPairBuilder implements AsymmetricKeyPairBuilder {
  private static final String KEY_ALGORITHM = "RSA";
  private static final int KEY_SIZE = 2048;

  @Override
  public AsymmetricKeyPair newKeyPair() throws UnknownAsymmetricKeyAlgorithmException, InvalidAsymmetricKeyException {
    try {
      KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
      KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
      generator.initialize(KEY_SIZE, new SecureRandom());

      KeyPair keyPair = generator.generateKeyPair();

      PrivateKey privKey = new RSAPrivateKey(factory, keyPair);
      PublicKey pubKey = new RSAPublicKey(factory, keyPair);

      return new AsymmetricKeyPair(pubKey, privKey);
    } catch (NoSuchAlgorithmException e) {
      throw new UnknownAsymmetricKeyAlgorithmException("Algorithm not found");
    }
  }

  @Override
  public AsymmetricKeyPair loadKeyPair(String publicKey, String privateKey)
      throws UnknownAsymmetricKeyAlgorithmException, InvalidAsymmetricKeyException, InvalidEncodingException {
    try {
      KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);

      PrivateKey privKey = new RSAPrivateKey(factory, privateKey);
      PublicKey pubKey = new RSAPublicKey(factory, publicKey);

      return new AsymmetricKeyPair(pubKey, privKey);
    } catch (NoSuchAlgorithmException e) {
      throw new UnknownAsymmetricKeyAlgorithmException("Algorithm not found");
    }
  }

  @Override
  public PrivateKey loadPrivateKey(String privateKey)
      throws InvalidAsymmetricKeyException, UnknownAsymmetricKeyAlgorithmException, InvalidEncodingException {
    try {
      KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);

      return new RSAPrivateKey(factory, privateKey);
    } catch (NoSuchAlgorithmException e) {
      throw new UnknownAsymmetricKeyAlgorithmException("Algorithm not found");
    }
  }

  @Override
  public PublicKey loadPublicKey(String publicKey)
      throws InvalidAsymmetricKeyException, UnknownAsymmetricKeyAlgorithmException, InvalidEncodingException {
    try {
      KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);

      return new RSAPublicKey(factory, publicKey);
    } catch (NoSuchAlgorithmException e) {
      throw new UnknownAsymmetricKeyAlgorithmException("Algorithm not found");
    }
  }

}
