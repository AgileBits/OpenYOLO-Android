/*
 * Copyright 2016 The OpenYOLO Authors. All Rights Reserved.
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

package org.openyolo.protocol;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.openyolo.protocol.internal.CustomMatchers.isValidAuthenticationDomain;
import static org.openyolo.protocol.internal.CustomMatchers.notNullOrEmptyString;
import static org.valid4j.Validation.validate;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;
import android.util.Log;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;


/**
 * A URI-based representation of an authentication domain, which determines the scope within which
 * a credential is valid. An authentication domain may have multiple equivalent representations,
 * such as when apps and sites share the same authentication system. The responsibility for
 * determining whether two given authentication domains are equivalent lies with the credential
 * provider.
 *
 * <p>Two broad classes of authentication domain are defined in the OpenYOLO
 * specification : Android authentication domains, of form
 * {@code android://<fingerprint>@<packageName>}, and Web authentication domains, of form
 * {@code http(s)://host@port}. Formally, authentication domains are absolute hierarchical URIs
 * with no path, query or fragment. They must therefore always be of form
 * {@code scheme://authority}.
 *
 * @see <a href="http://spec.openyolo.org/openyolo-android-spec.html#authentication-domains">
 *     OpenYOLO Specification: Authentication Domain</a>
 */
@SuppressLint("PackageManagerGetSignatures")
public final class AuthenticationDomain implements Comparable<AuthenticationDomain> {

    /**
     * Indicates the use of SHA-256 as the fingerprint hash algorithm for an Android authentication
     * domain.
     */
    public static final String SHA_256_FINGERPRINT = "sha256";

    /**
     * Indicates the use of SHA-512 as the fingerprint hash algorithm for an Android authentication
     * domain.
     */
    public static final String SHA_512_FINGERPRINT = "sha512";

    /**
     * The separator character used between the fingerprint algorithm and the Base64 encoded
     * fingerprint bytes in an Android authentication domain.
     */
    public static final String FINGERPRINT_ALGO_SEPARATOR = ":";

    private static final String TAG = "AuthenticationDomain";

    private static final String DIGEST_SHA_256 = "SHA-256";
    private static final String DIGEST_SHA_512 = "SHA-512";

    private static final Map<String, String> FINGERPRINT_ALGO_TO_DIGEST_TYPE_MAP;

    static {
        LinkedHashMap<String, String> digestMap = new LinkedHashMap<String, String>();
        digestMap.put(SHA_256_FINGERPRINT, DIGEST_SHA_256);
        digestMap.put(SHA_512_FINGERPRINT, DIGEST_SHA_512);

        FINGERPRINT_ALGO_TO_DIGEST_TYPE_MAP = Collections.unmodifiableMap(digestMap);
    }

    private static final String SCHEME_ANDROID = "android";
    private static final String SCHEME_HTTP = "http";
    private static final String SCHEME_HTTPS = "https";


    private final String mUriStr;

    /**
     * Initially null, created on-demand for each thread from mUriStr.
     */
    private final ThreadLocal<Uri> mParsedUri = new ThreadLocal<>();

    /**
     * Creates an authentication domain that represents the current package, as identified
     * by the provided context's {@link Context#getPackageName() getPackageName} method.
     */
    @NonNull
    public static AuthenticationDomain getSelfAuthDomain(@NonNull Context context) {
        validate(context, notNullValue(), IllegalArgumentException.class);

        String packageName = context.getPackageName();
        AuthenticationDomain authenticationDomain = fromPackageName(context, packageName);
        if (null == authenticationDomain) {
            throw new IllegalStateException("Unable to find package info for " + packageName);
        }

        return authenticationDomain;
    }

    /**
     * Returns the {@link AuthenticationDomain} for the application installed on the current device
     * associated with the given package name, using the default SHA-512 fingerprint algorithm.
     * If the package is not installed, {@code null} will be returned.
     */
    @Nullable
    public static AuthenticationDomain fromPackageName(
            @NonNull Context context,
            @NonNull String packageName) {
        return fromPackageName(context, packageName, SHA_256_FINGERPRINT);
    }

    /**
     * Returns the {@link AuthenticationDomain} for the application installed on the current device
     * associated with the given package name, using the specified fingerprint algorithm. If the
     * package is not installed, {@code null} will be returned.
     */
    public static AuthenticationDomain fromPackageName(
            @NonNull Context context,
            @NonNull String packageName,
            @NonNull String fingerprintAlgorithm) {
        validate(context, notNullValue(), IllegalArgumentException.class);
        validate(packageName, notNullOrEmptyString(), IllegalArgumentException.class);
        validate(fingerprintAlgorithm, notNullOrEmptyString(), IllegalArgumentException.class);

        PackageManager pm = context.getPackageManager();
        PackageInfo packageInfo;
        try {
            packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
        } catch (PackageManager.NameNotFoundException ex) {
            return null;
        }

        if (1 != packageInfo.signatures.length) {
            Log.w(TAG,
                    String.format(
                            "application (%s) did not have exactly one signature",
                            packageName));
            return null;
        }

        return createAndroidAuthDomain(
                packageName,
                fingerprintAlgorithm,
                generateFingerprint(packageInfo.signatures[0], fingerprintAlgorithm));
    }

    /**
     * Creates an Android authentication domain (of form {@code android://fingerprint@package}),
     * given the provided package name and signature.
     */
    @NonNull
    public static AuthenticationDomain createAndroidAuthDomain(
            @NonNull String packageName,
            @NonNull Signature signature) {
        validate(packageName, notNullOrEmptyString(), IllegalArgumentException.class);
        validate(signature, notNullValue(), IllegalArgumentException.class);

        return new AuthenticationDomain(
                new Uri.Builder()
                        .scheme(SCHEME_ANDROID)
                        .encodedAuthority(generateFingerprint(signature) + "@" + packageName)
                        .build()
                        .toString());
    }

    /**
     * Creates an Android authentication domain (of form {@code android://algo~fingerprint@package})
     * given the provided fingerprint algorithm, Base64 encoded fingerprint bytes, and package name.
     */
    @NonNull
    public static AuthenticationDomain createAndroidAuthDomain(
            @NonNull String packageName,
            @NonNull String fingerprintAlgorithm,
            @NonNull String fingerprintBase64) {
        return new AuthenticationDomain(
                new Uri.Builder()
                .scheme(SCHEME_ANDROID)
                .encodedAuthority(fingerprintAlgorithm
                        + FINGERPRINT_ALGO_SEPARATOR
                        + fingerprintBase64
                        + "@"
                        + packageName)
                .build()
                .toString());
    }

    /**
     * Creates an authentication domain from its protocol buffer equivalent, in byte form.
     * @throws MalformedDataException if the given protocol buffer is invalid.
     */
    @NonNull
    public static AuthenticationDomain fromProtobufBytes(@NonNull byte[] protobufBytes)
            throws MalformedDataException {
        validate(protobufBytes, notNullValue(), MalformedDataException.class);

        try {
            return fromProtobuf(Protobufs.AuthenticationDomain.parseFrom(protobufBytes));
        } catch (IOException ex) {
            throw new MalformedDataException("Unable to parse the given protocol buffer", ex);
        }
    }

    /**
     * Creates an authentication domain from its protocol buffer equivalent.
     * @throws MalformedDataException if the given protocol buffer is invalid.
     */
    @NonNull
    public static AuthenticationDomain fromProtobuf(
            @NonNull Protobufs.AuthenticationDomain authDomain) throws MalformedDataException {
        validate(authDomain, notNullValue(), MalformedDataException.class);

        try {
            return new AuthenticationDomain(authDomain.getUri());
        } catch (IllegalArgumentException ex) {
            throw new MalformedDataException(ex);
        }
    }

    @NonNull
    static String generateFingerprint(@NonNull Signature signature) {
        return generateFingerprint(signature, SHA_512_FINGERPRINT);
    }

    @NonNull
    static String generateFingerprint(
            @NonNull Signature signature,
            @NonNull String fingerprintAlgorithm) {
        String digestName = FINGERPRINT_ALGO_TO_DIGEST_TYPE_MAP.get(fingerprintAlgorithm);
        if (digestName == null) {
            throw new IllegalArgumentException("Unknown fingerprint algorithm: "
                    + fingerprintAlgorithm);
        }

        try {
            MessageDigest digest = MessageDigest.getInstance(digestName);
            byte[] hashBytes = digest.digest(signature.toByteArray());
            return Base64.encodeToString(hashBytes, Base64.URL_SAFE | Base64.NO_WRAP);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "Platform does not support" + digestName + " hashing");
        }
    }

    /**
     * Creates an authentication domain from the provided String representation. If the string
     * provided is not a valid authentication domain, an {@link IllegalArgumentException}
     * will be thrown.
     */
    public AuthenticationDomain(@NonNull String authDomainString) {
        mUriStr = validate(
                authDomainString,
                isValidAuthenticationDomain(),
                IllegalArgumentException.class);
    }

    /**
     * Determines whether the authentication domain refers to an Android application.
     */
    public boolean isAndroidAuthDomain() {
        return SCHEME_ANDROID.equals(getParsedUri().getScheme());
    }

    /**
     * Determines whether the authentication domain refers to a Web domain.
     */
    public boolean isWebAuthDomain() {
        Uri parsedUri = getParsedUri();
        return SCHEME_HTTP.equals(parsedUri.getScheme())
                || SCHEME_HTTPS.equals(parsedUri.getScheme());
    }

    /**
     * Retrieves the Android package name from the authentication domain. If the authentication
     * domain does not represent an Android application, an {@link IllegalStateException} will
     * be thrown.
     */
    @NonNull
    public String getAndroidPackageName() {
        if (!isAndroidAuthDomain()) {
            throw new IllegalStateException("Authentication domain is not an Android domain");
        }
        return getParsedUri().getHost();
    }

    /**
     * Retrieves the Android app public signing key fingerprint. If the authentication
     * domain does not represent an Android application, an {@link IllegalStateException} will
     * be thrown.
     */
    public String getAndroidFingerprint() {
        if (!isAndroidAuthDomain()) {
            throw new IllegalStateException("Authentication domain is not an Android domain");
        }

        return getParsedUri().getUserInfo();
    }

    /**
     * Determines the fingerprint algorithm used for an Android authentication domain. If the
     * authentication domain does not represent an Android application, an
     * {@link IllegalStateException} will be thrown.
     */
    public String getAndroidFingerprintAlgorithm() {
        String fingerprint = getAndroidFingerprint();

        int algoSeparatorPosition = fingerprint.indexOf('~');
        if (algoSeparatorPosition == -1) {
            return SHA_512_FINGERPRINT;
        }

        return fingerprint.substring(0, algoSeparatorPosition);
    }

    /**
     * Returns the bytes of the fingerprint for an Android authentication domain. Use
     * {@link #getAndroidFingerprintAlgorithm()} to determine the fingerprint algorithm used. If
     * the authentication domain does not represent an Android application, an
     * {@link IllegalStateException} will be thrown.
     */
    public byte[] getAndroidFingerprintBytes() {
        String fingerprint = getAndroidFingerprint();
        String fingerprintBytes;

        int algoSeparatorPosition = fingerprint.indexOf('~');
        if (algoSeparatorPosition == -1) {
            fingerprintBytes = fingerprint;
        } else {
            fingerprintBytes = fingerprint.substring(algoSeparatorPosition + 1);
        }

        return Base64.decode(fingerprintBytes, Base64.URL_SAFE | Base64.NO_WRAP);
    }

    /**
     * Creates a protocol buffer representation of the authentication domain, for transmission
     * or storage.
     */
    public Protobufs.AuthenticationDomain toProtobuf() {
        return Protobufs.AuthenticationDomain.newBuilder()
                .setUri(mUriStr)
                .build();
    }

    /**
     * Retrieves the string form of the authentication domain.
     */
    @NonNull
    public String toString() {
        return mUriStr;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (!(obj instanceof AuthenticationDomain)) {
            return false;
        }

        return compareTo((AuthenticationDomain) obj) == 0;
    }

    @Override
    public int hashCode() {
        return mUriStr.hashCode();
    }

    @Override
    public int compareTo(@NonNull AuthenticationDomain authenticationDomain) {
        return mUriStr.compareTo(authenticationDomain.mUriStr);
    }

    private Uri getParsedUri() {
        Uri parsedUri = mParsedUri.get();
        if (parsedUri == null) {
            parsedUri = Uri.parse(mUriStr);
            mParsedUri.set(parsedUri);
        }

        return parsedUri;
    }
}
