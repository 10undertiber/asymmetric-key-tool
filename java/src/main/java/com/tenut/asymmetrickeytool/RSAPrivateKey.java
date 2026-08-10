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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

final public class RSAPrivateKey extends PrivateKey {

  private java.security.interfaces.RSAPrivateKey key;

  private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
  private static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
  private static final String V2_CIPHER_ALGORITHM = "RSA/ECB/OAEPPadding";
  private static final String V2_SIGNATURE_ALGORITHM = "RSASSA-PSS";

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
      throw new InvalidEncodingException("Signature encoding not supported", e);
    }
  }

  @Override
  byte[] decryptData(byte[] encryptedText) throws InvalidEncodingException {
    try {
      Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, this.key);
      return cipher.doFinal(encryptedText);
    } catch (Exception e) {
      throw new InvalidEncodingException("Cannot decrypt text", e);
    }
  }

  @Override
  byte[] decryptV2Data(byte[] encryptedText) throws InvalidEncodingException {
    RsaV2Format.Parsed envelope = RsaV2Format.parse(encryptedText,
        RsaV2Format.TYPE_CIPHERTEXT, RsaV2Format.PROFILE_OAEP_SHA256);
    try {
      Cipher cipher = Cipher.getInstance(V2_CIPHER_ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, this.key, oaepSpec());
      return cipher.doFinal(envelope.payload);
    } catch (GeneralSecurityException e) {
      throw new InvalidEncodingException("Cannot decrypt RSA v2 text", e);
    }
  }

  @Override
  byte[] signV2Data(byte[] input) throws InvalidEncodingException {
    try {
      byte[] header = RsaV2Format.header(RsaV2Format.TYPE_SIGNATURE,
          RsaV2Format.PROFILE_PSS_SHA256);
      Signature signature = Signature.getInstance(V2_SIGNATURE_ALGORITHM);
      signature.setParameter(pssSpec());
      signature.initSign(this.key);
      signature.update(RsaV2Format.signedMessage(header, input));
      return RsaV2Format.envelope(RsaV2Format.TYPE_SIGNATURE,
          RsaV2Format.PROFILE_PSS_SHA256, signature.sign());
    } catch (GeneralSecurityException e) {
      throw new InvalidEncodingException("RSA v2 signature not supported", e);
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
