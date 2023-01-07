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

package com.tenut.asynckeygen;

final public class AsymmetricKeyPair {

  private PrivateKey privateKey;
  private PublicKey publicKey;

  AsymmetricKeyPair(PublicKey publicKey, PrivateKey privateKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  public PrivateKey getPrivateKey() throws InvalidAsymmetricKeyException {
    return privateKey;
  }

  public PublicKey getPublicKey() throws InvalidAsymmetricKeyException {
    return publicKey;
  }

  public String encrypt(String plainMessage) throws InvalidEncodingException {
    return this.publicKey.encrypt(plainMessage);
  }

  public String decrypt(String encryptedMessage) throws InvalidEncodingException {
    return this.privateKey.decrypt(encryptedMessage);
  }

  public String sign(String input) throws InvalidEncodingException {
    return this.privateKey.sign(input);
  }

  public boolean verify(String input, String output) throws InvalidEncodingException {
    return this.publicKey.verify(input, output);
  }
}
