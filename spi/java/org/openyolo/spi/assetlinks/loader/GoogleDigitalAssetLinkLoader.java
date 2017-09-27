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

import android.net.Uri;
import android.support.annotation.NonNull;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.openyolo.protocol.AuthenticationDomain;

/**
 * Retrieves digital asset link relations for a specified authentication domain, using
 * the <a href="">Google Digital Asset Links API</a> as the data source.
 *
 * <p><em>NOTE</em>: This implementation only supports retrieving relations of Android
 * authentication domains where the fingerprint algorithm used is SHA-256, as this is the
 * expected fingerprint type for Google's API.
 */
public class GoogleDigitalAssetLinkLoader implements DigitalAssetLinkLoader {

    private static final int HTTP_OK_MIN = 200;
    private static final int HTTP_OK_MAX = 299;

    private static final Uri STATEMENT_LIST_ENDPOINT = Uri.parse(
            "https://digitalassetlinks.googleapis.com/v1/statements:list");

    private final String mApiKey;

    /**
     * Initializes the asset link loader, where requests will be made with the provided API key.
     */
    public GoogleDigitalAssetLinkLoader(@NonNull String apiKey) {
        mApiKey = apiKey;
    }

    @Override
    public Set<AuthenticationDomain> getRelations(
            String relationType,
            AuthenticationDomain domain) throws IOException {
        URL url = buildRequestUrl(relationType, domain);

        HttpURLConnection connection = null;
        InputStream responseStream = null;
        try {
            connection = (HttpURLConnection) url.openConnection();
            connection.connect();

            if (connection.getResponseCode() < HTTP_OK_MIN
                    || connection.getResponseCode() > HTTP_OK_MAX) {
                throw new IOException("Query failed");
            }

            responseStream = connection.getInputStream();
            String responseString = StreamReader.readAll(responseStream);

            return extractTargets(responseString);
        } catch (JSONException ex) {
            throw new IOException("Unable to parse response");
        } finally {
            try {
                if (responseStream != null) {
                    responseStream.close();
                }

                if (connection != null) {
                    connection.disconnect();
                }
            } catch (IOException ex) {
                // just discard the exception, as there is no way to meaningfully handle it
            }
        }
    }

    private URL buildRequestUrl(String relationType, AuthenticationDomain domain) {
        Uri.Builder queryUriBuilder = STATEMENT_LIST_ENDPOINT.buildUpon()
                .appendQueryParameter("relation", relationType)
                .appendQueryParameter("key", mApiKey)
                .appendQueryParameter("fields", "statements/target");

        if (domain.isWebAuthDomain()) {
            queryUriBuilder.appendQueryParameter("source.web.site", domain.toString());
        } else {
            queryUriBuilder.appendQueryParameter(
                    "source.androidApp.packageName",
                    domain.getAndroidPackageName());

            if (!AuthenticationDomain.SHA_256_FINGERPRINT
                    .equals(domain.getAndroidFingerprintAlgorithm())) {
                throw new IllegalStateException(
                        "Android authentication domains must use SHA-256 for the Google Digital"
                                + "Asset links retrieval API");
            }

            queryUriBuilder.appendQueryParameter(
                    "source.androidApp.certificate.sha256Fingerprint",
                    FingerprintConverter.bytesToHex(domain.getAndroidFingerprintBytes()));
        }

        String queryUriString = queryUriBuilder.build().toString();
        try {
            return new URL(queryUriString);
        } catch (MalformedURLException ex) {
            throw new IllegalStateException(
                    "Digital asset links query URL is unexpectedly invalid: " + queryUriString);
        }
    }

    private Set<AuthenticationDomain> extractTargets(String statementListResult)
            throws JSONException {
        JSONObject container = new JSONObject(statementListResult);
        JSONArray statements = container.getJSONArray("statements");
        Set<AuthenticationDomain> targets = new HashSet<>(statements.length());
        for (int i = 0; i < statements.length(); i++) {
            JSONObject statement = statements.getJSONObject(i);
            JSONObject target = statement.getJSONObject("target");
            if (target.has("web")) {
                targets.add(extractWebTarget(target));
            } else {
                targets.add(extractAndroidTarget(target));
            }
        }

        return targets;
    }

    private AuthenticationDomain extractWebTarget(JSONObject target) throws JSONException {
        String site = target.getJSONObject("web").getString("site");
        // we normalize the URL by stripping the trailing dot, that signifies the DNS root
        return new AuthenticationDomain(site.substring(0, site.length() - 1));
    }

    private AuthenticationDomain extractAndroidTarget(JSONObject target) throws JSONException {
        JSONObject androidTarget = target.getJSONObject("androidApp");
        String packageName = androidTarget.getString("packageName");
        String sha256Hex = androidTarget.getJSONObject("certificate")
                .getString("sha256Fingerprint");

        return AuthenticationDomain.createAndroidAuthDomain(
                packageName,
                AuthenticationDomain.SHA_256_FINGERPRINT,
                FingerprintConverter.hexToBase64(sha256Hex));
    }
}
