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

package org.openyolo.spi.assetlinks;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.valid4j.Assertive.require;

import android.support.annotation.NonNull;
import android.support.annotation.VisibleForTesting;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.openyolo.protocol.AuthenticationDomain;
import org.openyolo.spi.assetlinks.loader.DigitalAssetLinkLoader;
import org.openyolo.spi.assetlinks.loader.DirectWebDigitalAssetLinkLoader;
import org.openyolo.spi.internal.Clock;
import org.openyolo.spi.internal.DefaultClock;

/**
 * Retrieves and caches Digital Asset Links relationships between apps and sites. Provides a
 * mechanism to serialize and deserialize this cache to JSON, so that it does not need to always
 * reside in memory.
 */
public class AssetRelationshipCache {
    private static final String TAG = "AssetRelationshipCache";
    private static final int HASH_PRIME = 3079;

    /**
     * The default, recommended cache duration to use for app links, in the absence of any other
     * information.
     */
    public static final long RECOMMENDED_CACHE_DURATION = TimeUnit.DAYS.toMillis(1);

    private final DigitalAssetLinkLoader mAppLoader;
    private final DigitalAssetLinkLoader mWebLoader;

    private final HashMap<RelationSource, RetrievedRelations> mRelations;
    private final Clock mClock;
    private final long mCacheDurationMs;

    /**
     * Creates a caching wrapper around a digital asset links loader, with the specified cache
     * duration.
     */
    public AssetRelationshipCache(
            @NonNull DigitalAssetLinkLoader appLoader,
            @NonNull DigitalAssetLinkLoader webLoader,
            long cacheDurationMs) {
        this(appLoader, webLoader, cacheDurationMs, DefaultClock.INSTANCE);
    }

    @VisibleForTesting
    AssetRelationshipCache(
            @NonNull DigitalAssetLinkLoader appLoader,
            @NonNull DigitalAssetLinkLoader webLoader,
            long cacheDurationMs,
            @NonNull Clock clock) {
        require(appLoader, notNullValue());
        require(webLoader, notNullValue());
        require(clock, notNullValue());

        mAppLoader = appLoader;
        mWebLoader = webLoader;
        mRelations = new HashMap<>();
        mClock = clock;
        mCacheDurationMs = cacheDurationMs;
    }

    /**
     * Returns the set of related authentication domains of the specified type, where the source
     * lists a target and that target has a reciprocal relation back to the source. Bidirectional
     * relations are preferred for security sensitive sharing of data, such as sharing credentials.
     *
     * @throws IOException if the relations cannot be acquired by the
     * {@link DigitalAssetLinkLoader asset loader}.
     */
    public Set<AuthenticationDomain> getBidirectionalRelations(
            AuthenticationDomain source,
            String relationType) throws IOException {

        Set<AuthenticationDomain> bidiRelations = new HashSet<>();
        Set<AuthenticationDomain> sourceRelations = getRelations(source, relationType);

        for (AuthenticationDomain target : sourceRelations) {
            android.util.Log.d("DAL_TAG", "Comparing target: " + target.toString());
            Set<AuthenticationDomain> targetRelations = getRelations(target, relationType);
            if (targetRelations.contains(source)) {
                bidiRelations.add(target);
            }
        }

        return bidiRelations;
    }

    /**
     * Retrieves the set of related authentication domains for the specified domain.
     *
     * @throws IOException if the relations cannot be acquired by the
     * {@link DigitalAssetLinkLoader asset loader}.
     */
    public Set<AuthenticationDomain> getRelations(
            AuthenticationDomain source,
            String relationType) throws IOException {

        RelationSource relationSource = new RelationSource(source, relationType);

        RetrievedRelations retrievedRelations = mRelations.get(relationSource);
        if (retrievedRelations == null || retrievedRelations.expiryTime < mClock.getCurrentTime()) {
            Set<AuthenticationDomain> relations = new HashSet<>();
            relations.addAll(mAppLoader.getRelations(relationType, source));
            relations.addAll(mWebLoader.getRelations(relationType, source));
            long expiry = mClock.getCurrentTime() + mCacheDurationMs;
            retrievedRelations = new RetrievedRelations(relations, expiry);
            mRelations.put(relationSource, retrievedRelations);
        }

        return retrievedRelations.related;
    }

    /**
     * Produces a JSON serialized version of the relationship cache.
     *
     * @throws JSONException if the JSON cannot be produced
     */
    public String writeCache() throws JSONException {
        JSONObject output = new JSONObject();
        for (RelationSource source : mRelations.keySet()) {
            RetrievedRelations relations = mRelations.get(source);
            if (relations.expiryTime > mClock.getCurrentTime()) {
                JSONObject relationObj = output.optJSONObject(source.mRelationType);
                if (relationObj == null) {
                    relationObj = new JSONObject();
                    output.put(source.mRelationType, relationObj);
                }

                JSONArray relationsForDomain = new JSONArray();
                for (AuthenticationDomain related : relations.related) {
                    relationsForDomain.put(related.toString());
                }

                JSONObject relationsWithExpiry = new JSONObject();
                relationsWithExpiry.put("expires", relations.expiryTime);
                relationsWithExpiry.put("targets", relationsForDomain);
                relationObj.put(source.mDomain.toString(), relationsWithExpiry);
            }
        }

        return output.toString();
    }

    /**
     * Reads a JSON serialized version of the application cache, as produced by
     * {@link #writeCache()}.
     *
     * @throws JSONException if the JSON is malformed
     */
    public void readCache(String jsonStr) throws JSONException {
        JSONObject json = new JSONObject(jsonStr);
        Iterator<String> keys = json.keys();
        while (keys.hasNext()) {
            String relationType = keys.next();
            JSONObject relationsObj = json.getJSONObject(relationType);

            Iterator<String> sourceDomains = relationsObj.keys();
            while (sourceDomains.hasNext()) {
                String sourceDomain = sourceDomains.next();
                JSONObject relationsWithExpiry = relationsObj.getJSONObject(sourceDomain);
                long expiry = relationsWithExpiry.getLong("expires");
                if (expiry < mClock.getCurrentTime()) {
                    continue;
                }

                RelationSource source = new RelationSource(
                        new AuthenticationDomain(sourceDomain),
                        relationType);

                Set<AuthenticationDomain> targets = new HashSet<>();
                JSONArray targetsArray = relationsWithExpiry.getJSONArray("targets");
                for (int i = 0; i < targetsArray.length(); i++) {
                    String target = targetsArray.getString(i);
                    targets.add(new AuthenticationDomain(target));
                }

                RetrievedRelations relations = new RetrievedRelations(targets, expiry);
                mRelations.put(source, relations);
            }
        }
    }

    private class RelationSource {
        private AuthenticationDomain mDomain;
        private String mRelationType;

        RelationSource(AuthenticationDomain domain, String relationType) {
            this.mDomain = domain;
            this.mRelationType = relationType;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }

            if (obj == null || !(obj instanceof RelationSource)) {
                return false;
            }

            RelationSource other = (RelationSource) obj;
            return this.mDomain.equals(other.mDomain)
                    && this.mRelationType.equals(other.mRelationType);
        }

        @Override
        public int hashCode() {
            return mDomain.hashCode() * HASH_PRIME + mRelationType.hashCode();
        }
    }

    private class RetrievedRelations {
        public final Set<AuthenticationDomain> related;
        public final long expiryTime;

        RetrievedRelations(Set<AuthenticationDomain> related, long expiryTime) {
            this.related = related;
            this.expiryTime = expiryTime;
        }
    }
}
