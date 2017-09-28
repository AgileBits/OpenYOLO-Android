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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Collections;
import java.util.Set;

import org.json.JSONException;
import org.openyolo.protocol.AuthenticationDomain;

/**
 * Retrieves and interprets digital asset link relations for web authentication domains, directly
 * from the domain's "/.well-known/assetlinks.json" declaration.
 */
public class DirectWebDigitalAssetLinkLoader implements DigitalAssetLinkLoader {

    private static final String SCHEME_HTTP = "http";
    private static final String SCHEME_HTTPS = "https";
    private static final String ASSET_LINKS_PATH = "/.well-known/assetlinks.json";

    @Override
    public Set<AuthenticationDomain> getRelations(
            String relationType,
            AuthenticationDomain domain)
            throws IOException {

        return getRelations(relationType, domain.toString());
    }

    public Set<AuthenticationDomain> getRelations(
            String relationType,
            String webDomain)
            throws IOException {

        //TODO: Remove this method and require AuthDomain.

        String assetLinksDeclaration;

        Uri parsedUri = Uri.parse(webDomain);

        if (!isWebDomain(parsedUri)) {
            return Collections.emptySet();
        }

        //TODO: We should only add the .json when this method recieves only a domain. For 'include' statements from
        // the manifest, it should already point to a json path (not exactly in this path)
        if (!ASSET_LINKS_PATH.equals(parsedUri.getPath())) {
            webDomain = webDomain + ASSET_LINKS_PATH;
        }

        assetLinksDeclaration = loadFromWeb(webDomain);

        try {
            return AssetRelationReader.getRelations(assetLinksDeclaration, relationType);
        } catch (JSONException ex) {
            throw new IOException("Unable to parse asset links", ex);
        }
    }

    private String loadFromWeb(String webDomain) throws IOException {
        InputStream stream = new URL(webDomain).openStream();
        return StreamReader.readAll(stream);
    }

    private boolean isWebDomain(Uri parsedUri) {
        return SCHEME_HTTP.equals(parsedUri.getScheme()) || SCHEME_HTTPS.equals(parsedUri.getScheme());
    }
}
