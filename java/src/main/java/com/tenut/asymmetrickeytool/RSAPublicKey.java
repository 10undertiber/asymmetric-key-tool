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
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

final public class RSAPublicKey extends PublicKey {

  private java.security.interfaces.RSAPublicKey key;

  private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
  private static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
  private static final String V2_CIPHER_ALGORITHM = "RSA/ECB/OAEPPadding";
  private static final String V2_SIGNATURE_ALGORITHM = "RSASSA-PSS";

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
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
      throw new InvalidAsymmetricKeyException("Public key format not valid");
    }
  }

  @Override
  void decodeKey(KeyFactory factory, byte[] encoded) throws InvalidAsymmetricKeyException {
    try {
      X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(encoded);
      this.key = (java.security.interfaces.RSAPublicKey) factory.generatePublic(pubSpec);
    } catch (InvalidKeySpecException e) {
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
      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, this.key);
      return cipher.doFinal(plainText);
    } catch (Exception e) {
      throw new InvalidEncodingException("Cannot encrypt text", e);
    }
  }

  @Override
  boolean verifyData(byte[] input, byte[] output) throws InvalidEncodingException {
    try {
      Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
      sig.initVerify(this.key);
      sig.update(input);
      return sig.verify(output);
    } catch (Exception e) {
      throw new InvalidEncodingException("Signature encoding not supported", e);
    }
  }

  @Override
  byte[] encryptV2Data(byte[] plainText) throws InvalidEncodingException {
    try {
      Cipher cipher = Cipher.getInstance(V2_CIPHER_ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, this.key, oaepSpec());
      return RsaV2Format.envelope(RsaV2Format.TYPE_CIPHERTEXT,
          RsaV2Format.PROFILE_OAEP_SHA256, cipher.doFinal(plainText));
    } catch (GeneralSecurityException e) {
      throw new InvalidEncodingException("Cannot encrypt RSA v2 text", e);
    }
  }

  @Override
  boolean verifyV2Data(byte[] input, byte[] output) throws InvalidEncodingException {
    RsaV2Format.Parsed envelope = RsaV2Format.parse(output,
        RsaV2Format.TYPE_SIGNATURE, RsaV2Format.PROFILE_PSS_SHA256);
    try {
      Signature signature = Signature.getInstance(V2_SIGNATURE_ALGORITHM);
      signature.setParameter(pssSpec());
      signature.initVerify(this.key);
      signature.update(RsaV2Format.signedMessage(envelope.header, input));
      return signature.verify(envelope.payload);
    } catch (GeneralSecurityException e) {
      throw new InvalidEncodingException("RSA v2 signature verification not supported", e);
    }
  }

  private OAEPParameterSpec oaepSpec() {
    return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
        PSource.PSpecified.DEFAULT);
  }

  private PSSParameterSpec pssSpec() {
    return new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
  }
}
