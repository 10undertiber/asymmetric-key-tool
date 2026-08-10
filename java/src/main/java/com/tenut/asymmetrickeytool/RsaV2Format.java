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

import java.util.Arrays;

final class RsaV2Format {

  static final byte TYPE_CIPHERTEXT = 1;
  static final byte TYPE_SIGNATURE = 2;
  static final byte PROFILE_OAEP_SHA256 = 1;
  static final byte PROFILE_PSS_SHA256 = 2;
  private static final int HEADER_LENGTH = 7;
  private static final byte MAGIC_0 = 0;
  private static final byte MAGIC_1 = 'A';
  private static final byte MAGIC_2 = 'K';
  private static final byte MAGIC_3 = 'T';
  private static final byte VERSION = 2;

  private RsaV2Format() {
  }

  static byte[] envelope(byte type, byte profile, byte[] payload) {
    byte[] header = header(type, profile);
    byte[] result = new byte[header.length + payload.length];
    System.arraycopy(header, 0, result, 0, header.length);
    System.arraycopy(payload, 0, result, header.length, payload.length);
    return result;
  }

  static byte[] header(byte type, byte profile) {
    return new byte[] {MAGIC_0, MAGIC_1, MAGIC_2, MAGIC_3, VERSION, type, profile};
  }

  static Parsed parse(byte[] encoded, byte expectedType, byte expectedProfile)
      throws InvalidEncodingException {
    if (encoded == null || encoded.length <= HEADER_LENGTH
        || encoded[0] != MAGIC_0 || encoded[1] != MAGIC_1 || encoded[2] != MAGIC_2
        || encoded[3] != MAGIC_3 || encoded[4] != VERSION || encoded[5] != expectedType
        || encoded[6] != expectedProfile) {
      throw new InvalidEncodingException("RSA v2 envelope not valid");
    }
    return new Parsed(Arrays.copyOfRange(encoded, 0, HEADER_LENGTH),
        Arrays.copyOfRange(encoded, HEADER_LENGTH, encoded.length));
  }

  static boolean hasMarker(byte[] encoded) {
    return encoded != null && encoded.length >= HEADER_LENGTH
        && encoded[0] == MAGIC_0 && encoded[1] == MAGIC_1 && encoded[2] == MAGIC_2
        && encoded[3] == MAGIC_3;
  }

  static byte[] signedMessage(byte[] header, byte[] message) {
    byte[] result = new byte[header.length + message.length];
    System.arraycopy(header, 0, result, 0, header.length);
    System.arraycopy(message, 0, result, header.length, message.length);
    return result;
  }

  static final class Parsed {
    final byte[] header;
    final byte[] payload;

    Parsed(byte[] header, byte[] payload) {
      this.header = header;
      this.payload = payload;
    }
  }
}
