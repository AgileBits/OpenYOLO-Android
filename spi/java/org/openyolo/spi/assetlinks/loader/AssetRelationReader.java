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

import android.text.TextUtils;
import android.util.Log;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.openyolo.protocol.AuthenticationDomain;

/**
 * Reads unidirectional relations from a
 * <a href="https://developers.google.com/digital-asset-links/">Digital Asset Links</a>
 * JSON declaration.
 */
public class AssetRelationReader {

    private static final String TAG = "AssetRelationReader";

    private static final int EXPECTED_SHA_256_FINGERPRINT_LENGTH = 95;

    private static final String ANDROID_NAMESPACE = "android";
    private static final String ANDROID_APP_NAMESPACE = "android_app";
    private static final String WEB_NAMESPACE = "web";

    /**
     * Extracts a set of related authentication domains from the provided JSON, of the specified
     * relation type.
     *
     * @throws JSONException if the JSON is malformed.
     */
    public static Set<AuthenticationDomain> getRelations(String assetLinksJson, String relationType) throws JSONException, IOException {

        Set<AuthenticationDomain> targets = new HashSet<>();
        JSONArray relationArray = new JSONArray(assetLinksJson);

        for (int i = 0; i < relationArray.length(); i++) {
            JSONObject relation = relationArray.getJSONObject(i);
            String includeWebDomain = relation.optString("include");
            JSONArray relationTypes = relation.optJSONArray("relation");

            if (!TextUtils.isEmpty(includeWebDomain)) {
                DirectWebDigitalAssetLinkLoader webLoader = new DirectWebDigitalAssetLinkLoader();
                targets.addAll(webLoader.getRelations(relationType, includeWebDomain));
            }

            if (relationTypes != null && contains(relationTypes, relationType)) {
                JSONObject target = relation.getJSONObject("target");
                String namespace = target.getString("namespace");
                if (ANDROID_NAMESPACE.equals(namespace) || ANDROID_APP_NAMESPACE.equals(namespace)) {
                    targets.add(readAndroidTarget(target));
                } else if (WEB_NAMESPACE.equals(namespace)) {
                    targets.add(readWebTarget(target));
                } else {
                    Log.w(TAG, "Unknown namespace \"" + namespace + "\" for statement: " + relation);
                }
            }
        }

        return targets;
    }

    private static AuthenticationDomain readAndroidTarget(JSONObject androidTarget)
            throws JSONException {
        String packageName = androidTarget.getString("package_name");
        JSONArray fingerprints = androidTarget.getJSONArray("sha256_cert_fingerprints");
        String fingerprint = fingerprints.getString(0);
        if (fingerprint.length() != EXPECTED_SHA_256_FINGERPRINT_LENGTH) {
            throw new JSONException("Fingerprint is not the correct length: " + fingerprint);
        }
        String base64Fingerprint = FingerprintConverter.hexToBase64(fingerprint);
        return new AuthenticationDomain(
                "android://sha256:" + base64Fingerprint + "@" + packageName);
    }

    private static AuthenticationDomain readWebTarget(JSONObject webTarget) throws JSONException {
        return new AuthenticationDomain(webTarget.getString("site"));
    }

    private static boolean contains(JSONArray arr, String str) throws JSONException {
        for (int i = 0; i < arr.length(); i++) {
            if (str.equals(arr.getString(i))) {
                return true;
            }
        }

        return false;
    }
}
