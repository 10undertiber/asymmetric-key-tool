/*
 *
 * Copyright (c) 2023 10 Under Tiber Studio
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.Test;

final public class RsaV2Test {

  @Test
  public void shouldRoundTripOaepV2WithSameRsaPair() throws Exception {
    AsymmetricKeyPair keyPair = AsymmetricKeyGenerator.newKeyPair(
        AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_RSA_V2);

    String encrypted = keyPair.encryptV2("secret message");

    assertThat(keyPair.decryptV2(encrypted)).isEqualTo("secret message");
    assertThat(Base64.getDecoder().decode(encrypted)).startsWith(
        new byte[] {0, 'A', 'K', 'T', 2, 1, 1});
  }

  @Test
  public void shouldRoundTripPssV2AndBindHeaderToSignature() throws Exception {
    AsymmetricKeyPair keyPair = AsymmetricKeyGenerator.newKeyPair(
        AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_RSA_V2);
    String message = "message to sign";
    String signature = keyPair.signV2(message);

    assertThat(keyPair.verifyV2(message, signature)).isTrue();
    assertThat(keyPair.verifyV2("changed", signature)).isFalse();
    assertThatThrownBy(() -> keyPair.verify(message, signature))
        .isInstanceOf(InvalidEncodingException.class);
  }

  @Test
  public void shouldRejectModifiedV2CiphertextAndSignature() throws Exception {
    AsymmetricKeyPair keyPair = AsymmetricKeyGenerator.newKeyPair(
        AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_RSA_V2);
    byte[] encrypted = Base64.getDecoder().decode(keyPair.encryptV2("secret"));
    encrypted[encrypted.length - 1] ^= 1;

    assertThatThrownBy(() -> keyPair.decryptV2(encrypted))
        .isInstanceOf(InvalidEncodingException.class);

    byte[] signature = Base64.getDecoder().decode(keyPair.signV2("secret"));
    signature[signature.length - 1] ^= 1;

    assertThat(keyPair.verifyV2("secret".getBytes(StandardCharsets.UTF_8), signature)).isFalse();
  }

  @Test
  public void shouldRejectWrongV2ProfileAndMalformedEnvelope() throws Exception {
    AsymmetricKeyPair keyPair = AsymmetricKeyGenerator.newKeyPair(
        AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_RSA_V2);
    byte[] encrypted = Base64.getDecoder().decode(keyPair.encryptV2("secret"));
    encrypted[5] = 2;

    assertThatThrownBy(() -> keyPair.decryptV2(encrypted))
        .isInstanceOf(InvalidEncodingException.class);

    assertThatThrownBy(() -> keyPair.decryptV2(new byte[] {0, 'A', 'K', 'T', 2, 1, 1}))
        .isInstanceOf(InvalidEncodingException.class);
  }

  @Test
  public void shouldKeepLegacyOperationsAndKeySerializationCompatible() throws Exception {
    AsymmetricKeyPair keyPair = AsymmetricKeyGenerator.newKeyPair(
        AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_RSA);
    String publicKey = keyPair.getPublicKey().toBase64();
    String privateKey = keyPair.getPrivateKey().toBase64();
    AsymmetricKeyPair loaded = AsymmetricKeyGenerator.loadKeyPair(
        AsymmetricKeyAlgorithm.ASYMMETRIC_KEY_ALGORITHM_RSA, publicKey, privateKey);
    String message = "legacy message";
    String encrypted = keyPair.encrypt(message);
    String signature = keyPair.sign(message);

    assertThat(loaded.decrypt(encrypted)).isEqualTo(message);
    assertThat(loaded.verify(message, signature)).isTrue();
    assertThat(loaded.getPublicKey().toBase64()).isEqualTo(publicKey);
    assertThat(loaded.getPrivateKey().toBase64()).isEqualTo(privateKey);
    assertThat(keyPair.verifyV2(message.getBytes(StandardCharsets.UTF_8),
        Base64.getDecoder().decode(keyPair.signV2(message)))).isTrue();
  }
}
