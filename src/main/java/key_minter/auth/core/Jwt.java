package key_minter.auth.core;

import key_minter.model.dto.JwtProperties;
import key_minter.model.dto.Algorithm;
import key_minter.model.dto.KeyVersion;
import io.jsonwebtoken.Claims;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public interface Jwt {
    Path DEFAULT_SECRET_DIR = Paths.get(System.getProperty("user.home"), ".chao");

    // 核心JWT操作 - 移除重复的 generateJwt 方法
    String generateToken(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm);

    boolean verifyToken(String token);

    Claims decodePayload(String token);

    // Token管理
    String refreshToken(String token);

    boolean revokeToken(String token);

    boolean manageSecret(String secret);

    // 密钥管理方法
    default boolean generateKeyPair(Algorithm algorithm) {
        throw new UnsupportedOperationException("Key pair generation not supported for this algorithm");
    }

    default boolean generateKeyPair(Algorithm algorithm, String filename) {
        throw new UnsupportedOperationException("Key pair generation not supported for this algorithm");
    }

    default boolean generateRSAKeyPair(Algorithm algorithm, Integer keySize) {
        return generateRSAKeyPair(algorithm, keySize, null, null);
    }

    default boolean generateRSAKeyPair(Algorithm algorithm, Integer keySize, String privateKeyFilename, String defaultKeyFilename) {
        throw new UnsupportedOperationException("Key pair generation not supported for this algorithm");
    }

    default boolean generateHmacKey(Algorithm algorithm, Integer length) {
        return generateHmacKey(algorithm, length, null);
    }

    default boolean generateHmacKey(Algorithm algorithm, Integer length, String filename) {
        throw new UnsupportedOperationException("HMAC key generation not supported for this algorithm");
    }

    default boolean generateAllKeyPairs() {
        throw new UnsupportedOperationException("Key pair generation not supported for all algorithms");
    }
    // 密钥信息

    default PublicKey getPublicKey() {
        throw new UnsupportedOperationException("Public key not available");
    }

    default PublicKey getPublicKey(Algorithm algorithm) {
        throw new UnsupportedOperationException("Public key not available");
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

    default String getAlgorithmInfo() {
        throw new UnsupportedOperationException("Algorithm information not available");
    }

    default boolean secretKeyExists() {
        return false;
    }

    default boolean secretKeyExists(Algorithm algorithm) {
        return false;
    }

    // 简化方法 - 移除重复定义，让抽象类实现
    default String generateToken(JwtProperties properties, Algorithm algorithm) {
        return generateToken(properties, null, algorithm);
    }
    // 泛型支持

    default <T> String generateToken(JwtProperties properties,Algorithm algorithm, T customClaims,  Class<T> claimsType) {
        if (customClaims != null && !claimsType.isInstance(customClaims)) {
            throw new IllegalArgumentException("customClaims must be of type: " + claimsType.getName());
        }
        Map<String, Object> claimsMap = convertToClaimsMap(customClaims);
        return generateToken(properties, claimsMap, algorithm);
    }

    default <T> Map<String, Object> convertToClaimsMap(T customClaims) {
        return null;
    }

    default void close() {
    }

    // 密钥轮换相关方法
    default boolean rotateKey(Algorithm algorithm) {
        throw new UnsupportedOperationException("Key rotation not supported for this algorithm");
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

    default boolean keyPairExists() {
        throw new UnsupportedOperationException("Key pair existence check not supported");
    }

    default boolean keyPairExists(Algorithm algorithm) {
        throw new UnsupportedOperationException("Key pair existence check not supported");
    }

    default List<KeyVersion> listAllKeys(String directory) {
        return List.of();
    }

    default List<KeyVersion> listAllKeys() {
        return listAllKeys(String.valueOf(DEFAULT_SECRET_DIR));
    }

    default List<KeyVersion> listHmacKeys(String directory) {
        List<KeyVersion> list = listAllKeys(directory);
        return list.stream().filter(kv -> kv.getAlgorithm().isHmac()).toList();
    }

    default List<KeyVersion> listHmacKeys() {
        return listHmacKeys(String.valueOf(DEFAULT_SECRET_DIR));
    }

    default List<KeyVersion> listECKeys(String directory) {
        List<KeyVersion> list = listAllKeys(directory);
        return list.stream().filter(kv -> kv.getAlgorithm().isEcdsa()).toList();
    }

    default List<KeyVersion> listECKeys() {
        return listECKeys(String.valueOf(DEFAULT_SECRET_DIR));
    }

    default List<KeyVersion> listEDKeys(String directory) {
        List<KeyVersion> list = listAllKeys(directory);
        return list.stream().filter(kv -> kv.getAlgorithm().isEddsa()).toList();
    }

    default List<KeyVersion> listEDKeys() {
        return listEDKeys(String.valueOf(DEFAULT_SECRET_DIR));
    }

    default List<KeyVersion> listRSAKeys(String directory) {
        List<KeyVersion> list = listAllKeys(directory);
        return list.stream().filter(kv -> kv.getAlgorithm().isRsa()).toList();
    }

    default List<KeyVersion> listRSAKeys() {
        return listRSAKeys(String.valueOf(DEFAULT_SECRET_DIR));
    }

    Jwt autoLoadFirstKey(Algorithm algorithm, String preferredKeyId, boolean force);

    default Jwt autoLoadFirstKey() {
        return autoLoadFirstKey(null, null, false);
    }

    default Jwt autoLoadFirstKey(Algorithm algorithm) {
        return autoLoadFirstKey(algorithm, null, false);
    }

    default Jwt autoLoadFirstKey(Algorithm algorithm, boolean force) {
        return autoLoadFirstKey(algorithm, null, force);
    }

    default Jwt autoLoadFirstKey(Algorithm algorithm, String preferredKeyId) {
        return autoLoadFirstKey(algorithm, preferredKeyId, false);
    }

    default LocalDateTime getDirTimestamp(Path dir) {
        return null;
    }
}