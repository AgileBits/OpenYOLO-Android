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

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.support.annotation.NonNull;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;

import org.json.JSONException;
import org.openyolo.protocol.AuthenticationDomain;

/**
 * A digital asset link loader for android apps, which retrieves the set of relations directly from
 * an installed app's metadata.
 */
public class AndroidAppDigitalAssetLinkLoader implements DigitalAssetLinkLoader {

    private static final String ASSET_STATEMENTS_METADATA_KEY = "asset_statements";

    private final Context mApplicationContext;

    /**
     * Creates a digital asset link loader for installed android applications, using the provided
     * context for package metadata retrieval.
     */
    public AndroidAppDigitalAssetLinkLoader(@NonNull Context context) {
        mApplicationContext = context.getApplicationContext();
    }

    @Override
    public Set<AuthenticationDomain> getRelations(String relationType, AuthenticationDomain domain)
            throws IOException {

        if (!domain.isAndroidAuthDomain() || !isAppInstalledWithMatchingFingerprint(domain)) {
            return Collections.emptySet();
        }

        String packageName = domain.getAndroidPackageName();
        ApplicationInfo applicationInfo;
        try {
            applicationInfo = mApplicationContext.getPackageManager()
                    .getApplicationInfo(packageName, PackageManager.GET_META_DATA);
        } catch (PackageManager.NameNotFoundException ex) {
            throw new IOException(
                    "Unable to find application info for package: " + packageName,
                    ex);
        }

        if (applicationInfo.metaData == null
                || !applicationInfo.metaData.containsKey(ASSET_STATEMENTS_METADATA_KEY)) {
            return Collections.emptySet();
        }

        Resources resources;
        try {
            resources = mApplicationContext.getPackageManager()
                    .getResourcesForApplication(applicationInfo);
        } catch (PackageManager.NameNotFoundException e) {
            return Collections.emptySet();
        }

        String assetLinksDeclaration = resources.getString(
                applicationInfo.metaData.getInt(ASSET_STATEMENTS_METADATA_KEY));

        try {
            return AssetRelationReader.getRelations(assetLinksDeclaration, relationType);
        } catch (JSONException ex) {
            throw new IOException("Unable to parse asset links", ex);
        }
    }

    private boolean isAppInstalledWithMatchingFingerprint(AuthenticationDomain androidApp) {
        AuthenticationDomain appDomain =
                AuthenticationDomain.fromPackageName(
                        mApplicationContext,
                        androidApp.getAndroidPackageName());

        // TODO: generate fingerprint for installed app using same fingerprint algorithm as provided
        if (androidApp.equals(appDomain)) {
            return true;
        }

        return false;
    }
}
