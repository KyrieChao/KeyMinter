package com.chao.keyMinter.domain.service;

import com.chao.keyMinter.core.Prep;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.model.KeyStatus;
import com.chao.keyMinter.domain.model.KeyVersion;
import com.chao.keyMinter.domain.port.out.SecretDirProvider;
import io.jsonwebtoken.Claims;
import org.jetbrains.annotations.NotNull;

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

    boolean generateKeyPair(Algorithm algorithm);

    default boolean generateHmacKey(Algorithm algorithm, Integer length) {
        return false;
    }

    boolean generateAllKeyPairs();

    boolean rotateKey(Algorithm algorithm, String newKeyIdentifier);

    default boolean rotateHmacKey(Algorithm algorithm, String newKeyIdentifier, Integer length) {
        return false;
    }

    List<String> getKeyVersions();

    List<String> getKeyVersions(Algorithm algorithm);

    boolean setActiveKey(String keyId);

    String getActiveKeyId();

    boolean keyPairExists(Algorithm algorithm);

    boolean keyPairExists();

    LocalDateTime getDirTimestamp(Path dir);

    List<KeyVersion> listAllKeys();

    List<KeyVersion> listAllKeys(String directory);

    JwtAlgo autoLoadFirstKey(Algorithm algorithm, String preferredKeyId, boolean force);

    boolean verifyWithKeyVersion(String keyId, String token);

    void loadExistingKeyVersions();

    JwtAlgo withKeyDirectory(Path keyDir);

    Object getCurrentKey();

    Object getKeyByVersion(String keyId);

    String getAlgorithmInfo();

    default String getCurveInfo(Algorithm algorithm) {
        return null;
    }

    String getKeyInfo();

    Path getKeyPath();

    String generateToken(JwtProperties properties, Algorithm algorithm);

    <T> Map<String, Object> convertToClaimsMap(T customClaims);

    KeyVersion getActiveKeyVersion();

    List<String> getKeyVersionsByStatus(KeyStatus status);

    void close();

    void cleanupExpiredKeys();

    default Path getDefaultSecretDir() {
        return SecretDirProvider.getDefaultBaseDir();
    }

    default boolean isECD(@NotNull Algorithm algorithm) {
        return algorithm.isEcdsa() || algorithm.isEddsa();
    }

    default List<KeyVersion> listKeys(Algorithm algorithm) {
        return listKeys(algorithm, null);
    }

    default List<KeyVersion> listKeys(@NotNull Algorithm algorithm, String directory) {
        directory = directory != null ? directory : String.valueOf(getDefaultSecretDir());
        return switch (algorithm) {
            case HMAC256, HMAC384, HMAC512 -> listHmacKeys(directory);
            case Ed448, Ed25519 -> listEDKeys(directory);
            case ES256, ES384, ES512 -> listECKeys(directory);
            case RSA256, RSA384, RSA512 -> listRSAKeys(directory);
        };
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

    default JwtAlgo autoLoadFirstKey(Algorithm algorithm, boolean force) {
        return autoLoadFirstKey(algorithm, null, force);
    }

    default JwtAlgo withKeyDirectory(String keyDir) {
        return withKeyDirectory(keyDir != null ? Paths.get(keyDir) : null);
    }

    default <T> String generateToken(JwtProperties properties, Algorithm algorithm, T customClaims, Class<T> claimsType) {
        if (customClaims != null && !claimsType.isInstance(customClaims)) {
            throw new IllegalArgumentException("customClaims must be of type: " + claimsType.getName());
        }
        Map<String, Object> claimsMap = convertToClaimsMap(customClaims);
        return generateToken(properties, claimsMap, algorithm);
    }

    static JwtAlgo FirstKey(Algorithm algorithm, Path path, boolean force) {
        return Prep.FirstKey(algorithm, path, force);
    }

    static JwtAlgo WithKeyId(Algorithm algorithm, Path path, String keyId, boolean force) {
        return Prep.WithKeyId(algorithm, path, keyId, force);
    }
}


