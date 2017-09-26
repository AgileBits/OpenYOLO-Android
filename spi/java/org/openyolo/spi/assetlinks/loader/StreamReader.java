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

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

/**
 * Utility for reading the entire contents of an {@link java.io.InputStream} as a string.
 */
class StreamReader {

    private static final String TAG = "StreamReader";

    public static String readAll(@NonNull InputStream stream) {
        Scanner scanner = null;
        try {
            // read the whole file into a string, using a Scanner trick
            scanner = new Scanner(stream);
            scanner.useDelimiter("\\Z");
            return scanner.next();
        } finally {
            if (scanner != null) {
                scanner.close();
            }

            try {
                stream.close();
            } catch (IOException ex) {
                Log.e(TAG, "Failed to close stream", ex);
            }
        }
    }
}