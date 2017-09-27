/*
 * Copyright 2017 The OpenYOLO Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.openyolo.spi.assetlinks.loader;

import android.util.Base64;

import java.nio.charset.Charset;
import java.util.Locale;

/**
 * Transforms fingerprints from Base64 url-safe (used by OpenYOLO Authentication domains)
 * to/from delimited hex (used by Google Digital Asset Links API).
 */
public final class FingerprintConverter {

    private static final int HEX_BYTE_WITH_SEPARATOR_WIDTH = 3;
    private static final int HEX_RADIX = 16;
    private static final int NYBBLE_BITS = 4;
    private static final int UNSIGNED_BYTE_MASK = 0xFF;

    /**
     * Converts a hexadecimal encoded string of bytes, where each byte is delimited by a colon, to
     * the Base64 encoded equivalent.
     */
    public static String hexToBase64(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / HEX_BYTE_WITH_SEPARATOR_WIDTH + 1];
        for (int dataPos = 0, stringPos = 0;
                stringPos < len;
                dataPos += 1, stringPos += HEX_BYTE_WITH_SEPARATOR_WIDTH) {
            int upperDigit = Character.digit(hexString.charAt(stringPos), HEX_RADIX);
            int lowerDigit = Character.digit(hexString.charAt(stringPos + 1), HEX_RADIX);
            data[dataPos] = (byte) ((upperDigit << NYBBLE_BITS) + lowerDigit);
        }

        return Base64.encodeToString(data, Base64.URL_SAFE | Base64.NO_WRAP);
    }

    /**
     * Converts a base64 encoded string of bytes to the hexademical string encoded equivalent.
     */
    public static String base64ToHex(String base64) {
        byte[] bytes = Base64.decode(base64.getBytes(Charset.forName("UTF-8")), Base64.URL_SAFE);
        return bytesToHex(bytes);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexStr = new StringBuilder();
        for (int pos = 0; pos < bytes.length; pos++) {
            String hex = Integer.toHexString(bytes[pos] & UNSIGNED_BYTE_MASK)
                    .toUpperCase(Locale.ROOT);
            if (hex.length() < 2) {
                hexStr.append('0');
            }
            hexStr.append(hex);

            if (pos < bytes.length - 1) {
                hexStr.append(":");
            }
        }

        return hexStr.toString();
    }
}
