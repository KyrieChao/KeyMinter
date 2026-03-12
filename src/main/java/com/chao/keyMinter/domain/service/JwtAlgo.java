package com.chao.keyMinter.domain.service;

import com.chao.keyMinter.core.Prep;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.model.KeyStatus;
import com.chao.keyMinter.domain.model.KeyVersion;
import com.chao.keyMinter.domain.port.out.SecretDirProvider;
import io.jsonwebtoken.Claims;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public interface JwtAlgo {
    String generateToken(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm);

    boolean verifyToken(String token);

    Claims decodePayload(String token);

    boolean manageSecret(String secret);

    default boolean generateKeyPair(Algorithm algorithm) {
        throw new UnsupportedOperationException("Key pair generation not supported for this algorithm");
    }

    default boolean generateHmacKey(Algorithm algorithm, Integer length) {
        return false;
    }

    default boolean generateAllKeyPairs() {
        throw new UnsupportedOperationException("Key pair generation not supported for all algorithms");
    }

    default boolean rotateKey(Algorithm algorithm, String newKeyIdentifier) {
        throw new UnsupportedOperationException("Key rotation not supported for this algorithm");
    }

    default boolean rotateHmacKey(Algorithm algorithm, String newKeyIdentifier, Integer length) {
        throw new UnsupportedOperationException("Key rotation not supported for this algorithm");
    }

    default List<String> getKeyVersions() {
        throw new UnsupportedOperationException("Key version management not supported");
    }

    default List<String> getKeyVersions(Algorithm algorithm) {
        throw new UnsupportedOperationException("Key version management not supported");
    }

    default boolean setActiveKey(String keyId) {
        throw new UnsupportedOperationException("Active key setting not supported");
    }

    default String getActiveKeyId() {
        throw new UnsupportedOperationException("Active key ID not supported");
    }

    default boolean keyPairExists(Algorithm algorithm) {
        throw new UnsupportedOperationException("Key pair existence check not supported");
    }

    default boolean keyPairExists() {
        throw new UnsupportedOperationException("Key pair existence check not supported");
    }

    default Path getDefaultSecretDir() {
        return SecretDirProvider.getDefaultBaseDir();
    }

    default LocalDateTime getDirTimestamp(Path dir) {
        return null;
    }

    default boolean isECD(Algorithm algorithm) {
        return algorithm.isEcdsa() || algorithm.isEddsa();
    }

    default List<KeyVersion> listAllKeys(String directory) {
        return List.of();
    }

    default List<KeyVersion> listKeys(Algorithm algorithm) {
        return listKeys(algorithm, null);
    }

    default List<KeyVersion> listKeys(Algorithm algorithm, String directory) {
        directory = directory != null ? directory : String.valueOf(getDefaultSecretDir());
        return switch (algorithm) {
            case HMAC256, HMAC384, HMAC512 -> listHmacKeys(directory);
            case Ed448, Ed25519 -> listEDKeys(directory);
            case ES256, ES384, ES512 -> listECKeys(directory);
            case RSA256, RSA384, RSA512 -> listRSAKeys(directory);
        };
    }

    default List<KeyVersion> listAllKeys() {
        return listAllKeys(String.valueOf(getDefaultSecretDir()));
    }

    default List<KeyVersion> listHmacKeys(String directory) {
        return listAllKeys(directory).stream().filter(kv -> kv.getAlgorithm().isHmac()).toList();
    }

    default List<KeyVersion> listECKeys(String directory) {
        return listAllKeys(directory).stream().filter(kv -> kv.getAlgorithm().isEcdsa()).toList();
    }

    default List<KeyVersion> listRSAKeys(String directory) {
        return listAllKeys(directory).stream().filter(kv -> kv.getAlgorithm().isRsa()).toList();
    }

    default List<KeyVersion> listEDKeys(String directory) {
        return listAllKeys(directory).stream().filter(kv -> kv.getAlgorithm().isEddsa()).toList();
    }

    JwtAlgo autoLoadFirstKey(Algorithm algorithm, String preferredKeyId, boolean force);

    default JwtAlgo autoLoadFirstKey() {
        return autoLoadFirstKey(null, null, false);
    }

    default boolean verifyWithKeyVersion(String keyId, String token) {
        return false;
    }

    default void loadExistingKeyVersions() {
    }

    default JwtAlgo autoLoadFirstKey(Algorithm algorithm, boolean force) {
        return autoLoadFirstKey(algorithm, null, force);
    }

    default JwtAlgo withKeyDirectory(Path keyDir) {
        return this;
    }

    default JwtAlgo withKeyDirectory(String keyDir) {
        return withKeyDirectory(keyDir != null ? Paths.get(keyDir) : null);
    }

    default Object getCurrentKey() {
        return null;
    }

    default Object getKeyByVersion(String keyId) {
        return null;
    }

    default String getAlgorithmInfo() {
        throw new UnsupportedOperationException("Algorithm information not available");
    }

    default String getCurveInfo(Algorithm algorithm) {
        throw new UnsupportedOperationException("Curve information not available");
    }

    default String getKeyInfo() {
        throw new UnsupportedOperationException("Key information not available");
    }

    default Path getKeyPath() {
        throw new UnsupportedOperationException("Key path not available");
    }

    default String generateToken(JwtProperties properties, Algorithm algorithm) {
        return generateToken(properties, null, algorithm);
    }

    default <T> String generateToken(JwtProperties properties, Algorithm algorithm, T customClaims, Class<T> claimsType) {
        if (customClaims != null && !claimsType.isInstance(customClaims)) {
            throw new IllegalArgumentException("customClaims must be of type: " + claimsType.getName());
        }
        Map<String, Object> claimsMap = convertToClaimsMap(customClaims);
        return generateToken(properties, claimsMap, algorithm);
    }

    default <T> Map<String, Object> convertToClaimsMap(T customClaims) {
        return null;
    }


    KeyVersion getActiveKeyVersion();

    List<String> getKeyVersionsByStatus(KeyStatus status);

    default void close() {
    }

    default void cleanupExpiredKeys() {
    }

    static JwtAlgo FirstKey(Algorithm algorithm, Path path, boolean force) {
        return Prep.FirstKey(algorithm, path, force);
    }

    static JwtAlgo WithKeyId(Algorithm algorithm, Path path, String keyId, boolean force) {
        return Prep.WithKeyId(algorithm, path, keyId, force);
    }
}


