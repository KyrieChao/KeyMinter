package com.chao.keyMinter.api;

import com.chao.keyMinter.core.JwtFactory;
import com.chao.keyMinter.domain.model.*;
import com.chao.keyMinter.domain.service.JwtAlgo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * JWT Key Management Facade.
 * Provides a high-level API for JWT operations including key rotation, token generation, and verification.
 */
@Slf4j
@Component
public class KeyMinter {

    private static final Algorithm DEFAULT_ALGORITHM = Algorithm.HMAC256;
    private static final int DEFAULT_SECRET_LENGTH = 64;
    private static final long GRACE_PERIOD_MS = 3600_000; // 1 hour grace period for rotation

    private final JwtFactory factory;
    private final ReentrantReadWriteLock algoLock = new ReentrantReadWriteLock();
    private final ReentrantReadWriteLock.ReadLock readLock = algoLock.readLock();
    private final ReentrantReadWriteLock.WriteLock writeLock = algoLock.writeLock();

    // Current active algorithm instance
    private volatile JwtAlgo algoInstance;
    private volatile Algorithm currentAlgorithm = DEFAULT_ALGORITHM;

    // Graceful rotation support: Keep the previous algorithm instance for a short period
    private volatile JwtAlgo previousAlgoInstance;
    private volatile long previousAlgoExpiryTime;

    // Metrics
    private final AtomicLong gracefulUsageCount = new AtomicLong(0);
    private final AtomicLong blacklistHitCount = new AtomicLong(0);

    public KeyMinter(JwtFactory factory) {
        this.factory = Objects.requireNonNull(factory, "JwtFactory cannot be null");
        this.algoInstance = factory.get(DEFAULT_ALGORITHM);

        log.info("KeyMinter initialized with default algorithm: {}", DEFAULT_ALGORITHM);
    }

    /**
     * Switch to a specific algorithm.
     */
    public synchronized boolean switchTo(Algorithm algorithm) {
        return switchTo(algorithm, null, null, false);
    }

    /**
     * Switch to a specific algorithm and activate a specific key ID.
     */
    public synchronized boolean switchTo(Algorithm algorithm, String keyId) {
        return switchTo(algorithm, null, keyId, true);
    }

    /**
     * Switch to a specific algorithm with optional directory and key ID configuration.
     */
    public synchronized boolean switchTo(Algorithm algorithm, String directory, String keyId, boolean autoload) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        try {
            JwtAlgo newAlgo = factory.get(algorithm, directory);
            
            writeLock.lock();
            try {
                JwtAlgo oldAlgo = this.algoInstance;
                this.algoInstance = newAlgo;
                this.currentAlgorithm = algorithm;

                // Handle graceful rotation: Keep old instance if different
                if (oldAlgo != null && oldAlgo != newAlgo) {
                    this.previousAlgoInstance = oldAlgo;
                    this.previousAlgoExpiryTime = System.currentTimeMillis() + GRACE_PERIOD_MS;
                }

                // Auto-load key if requested
                if (autoload && keyId != null) {
                    autoLoad(algorithm, directory, keyId);
                } else if (autoload) {
                    autoLoad(algorithm, directory);
                }

                log.info("Switched to algorithm: {}, directory: {}, autoload: {}", algorithm, directory, autoload);
                return true;
            } finally {
                writeLock.unlock();
            }
        } catch (Exception e) {
            log.error("Failed to switch to algorithm {}: {}", algorithm, e.getMessage(), e);
            return false;
        }
    }


    public synchronized boolean switchTo(Algorithm algorithm, Path path, boolean autoload) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        try {
            JwtAlgo newAlgo = factory.get(algorithm, path);
            writeLock.lock();
            try {
                if (this.algoInstance != null) {
                    this.previousAlgoInstance = this.algoInstance;
                    this.previousAlgoExpiryTime = System.currentTimeMillis() + GRACE_PERIOD_MS;
                }
                this.algoInstance = newAlgo;
                this.currentAlgorithm = algorithm;
                if (autoload) autoLoad(algorithm);
                log.info("Switched to algorithm: {}, path: {}", algorithm, path);
                return true;
            } finally {
                writeLock.unlock();
            }
        } catch (Exception e) {
            log.error("Failed to switch to algorithm {}: {}", algorithm, e.getMessage(), e);
            return false;
        }
    }
    
    // --- Simplified AutoLoad API ---

    public JwtAlgo autoLoad(Algorithm algorithm) {
        return factory.autoLoad(algorithm);
    }

    public JwtAlgo autoLoad(Algorithm algorithm, boolean force) {
        return factory.autoLoad(algorithm, force);
    }

    public JwtAlgo autoLoad(Algorithm algorithm, String directory) {
        return factory.autoLoad(algorithm, directory);
    }

    public JwtAlgo autoLoad(Algorithm algorithm, Path path) {
        return factory.autoLoad(algorithm, path);
    }

    public JwtAlgo autoLoad(Algorithm algorithm, String directory, String keyId) {
        return factory.autoLoad(algorithm, directory, keyId);
    }

    public JwtAlgo autoLoad(Algorithm algorithm, String directory, String keyId, boolean force) {
        return factory.autoLoad(algorithm, directory, keyId, force);
    }

    /**
     * Create a new HMAC secret key.
     */
    public boolean createHmacKey(Algorithm algorithm, Integer length) {
        validateHmacAlgorithm(algorithm);
        int keyLength = Objects.requireNonNullElse(length, DEFAULT_SECRET_LENGTH);
        readLock.lock();
        try {
            return algoInstance.generateHmacKey(Objects.requireNonNullElse(algorithm, DEFAULT_ALGORITHM), keyLength);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Create a new asymmetric key pair.
     */
    public boolean createKeyPair(Algorithm algorithm) {
        validateAsymmetricAlgorithm(algorithm);
        if (algorithm == currentAlgorithm) {
            readLock.lock();
            try {
                return algoInstance.generateKeyPair(algorithm);
            } finally {
                readLock.unlock();
            }
        }
        return factory.get(algorithm).generateKeyPair(algorithm);
    }

    /**
     * Generate a JWT token with standard claims.
     */
    public String generateToken(JwtProperties jwtInfo) {
        JwtProperties properties = buildJwtProperties(jwtInfo);
        readLock.lock();
        try {
            return algoInstance.generateToken(properties, currentAlgorithm);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Generate a JWT token with custom claims.
     */
    public <T> String generateToken(JwtProperties jwtInfo, T customClaims, Class<T> claimsType) {
        JwtProperties properties = buildJwtProperties(jwtInfo);
        readLock.lock();
        try {
            return algoInstance.generateToken(properties, currentAlgorithm, customClaims, claimsType);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Decode standard claims from a token.
     */
    public JwtStandardInfo getStandardInfo(String token) {
        readLock.lock();
        try {
            return JwtDecoder.decodeStandardInfo(token, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Decode token payload to a specific object.
     */
    public <T> T decodeToObject(String token, Class<T> clazz) {
        readLock.lock();
        try {
            return JwtDecoder.decodeToObject(token, clazz, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Decode token payload to a full map.
     */
    public Map<String, Object> decodeToFullMap(String token) {
        readLock.lock();
        try {
            return JwtDecoder.decodeToFullMap(token, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Get the Issued At (iat) date from the token.
     */
    public Date decodeIssuedAt(String token) {
        readLock.lock();
        try {
            return JwtDecoder.decodeIssuedAt(token, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Get the Expiration (exp) date from the token.
     */
    public Date decodeExpiration(String token) {
        readLock.lock();
        try {
            return JwtDecoder.decodeExpiration(token, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Get custom claims from the token.
     */
    public <T> T getCustomClaims(String token, Class<T> clazz) {
        readLock.lock();
        try {
            JwtFullInfo<T> fullInfo = JwtDecoder.decodeToFullInfo(token, clazz, algoInstance);
            return fullInfo.getCustomClaims();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Safely get custom claims (returns null on failure instead of throwing exception).
     */
    public <T> T getCustomClaimsSafe(String token, Class<T> clazz) {
        readLock.lock();
        try {
            JwtFullInfo<T> fullInfo = JwtDecoder.decodeToFullInfoSafe(token, clazz, algoInstance);
            return fullInfo != null ? fullInfo.getCustomClaims() : null;
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Get full token information including standard and custom claims.
     */
    public <T> JwtFullInfo<T> getFullInfo(String token, Class<T> clazz) {
        readLock.lock();
        try {
            return JwtDecoder.decodeToFullInfo(token, clazz, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Activate a specific key by ID.
     */
    public boolean setActiveKey(String keyId) {
        readLock.lock();
        try {
            boolean success = algoInstance.setActiveKey(keyId);
            if (success) {
                log.info("Key {} activated successfully. Algorithm: {}", keyId, currentAlgorithm);
            } else {
                log.warn("Failed to activate key {}", keyId);
            }
            return success;
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Safely get full token information.
     */
    public <T> JwtFullInfo<T> getFullInfoSafe(String token, Class<T> clazz) {
        readLock.lock();
        try {
            return JwtDecoder.decodeToFullInfoSafe(token, clazz, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Verify a token with a specific algorithm instance.
     */
    public boolean verifyWithAlgorithm(String token, JwtAlgo algo) {
        Objects.requireNonNull(algo, "JwtAlgo cannot be null");
        return algo.verifyToken(token);
    }

    /**
     * Check if a token is valid, checking current algorithm first, then graceful backup.
     */
    public boolean isValidToken(String token) {
        readLock.lock();
        try {
            boolean valid = algoInstance.verifyToken(token);
            if (!valid) {
                JwtAlgo backup = getGracefulAlgo();
                if (backup != null) {
                    gracefulUsageCount.incrementAndGet();
                    return backup.verifyToken(token);
                }
            }
            return valid;
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Check if a token is valid using only the current active algorithm.
     */
    public boolean isValidWithCurrent(String token) {
        readLock.lock();
        try {
            return algoInstance.verifyToken(token);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Check if a token is valid using only the graceful backup algorithm.
     */
    public boolean isValidWithGraceful(String token) {
        JwtAlgo backup = getGracefulAlgo();
        return backup != null && backup.verifyToken(token);
    }

    /**
     * Get information about the current JWT properties/keys.
     */
    public String getJwtProperties() {
        readLock.lock();
        try {
            return algoInstance.getKeyInfo();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Get information about the current algorithm.
     */
    public String getAlgorithmInfo() {
        readLock.lock();
        try {
            return algoInstance.getAlgorithmInfo();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Get ECDSA curve information if applicable.
     */
    public String getECDCurveInfo() {
        readLock.lock();
        try {
            if (!algoInstance.isECD(currentAlgorithm)) {
                return null;
            }
            return algoInstance.getCurveInfo(currentAlgorithm);
        } finally {
            readLock.unlock();
        }
    }

    public boolean verify(Algorithm algorithm, String token) {
        JwtAlgo algo = autoLoad(algorithm);
        return verifyWithAlgorithm(token, algo);
    }

    /**
     * List all keys in a directory.
     */
    public List<KeyVersion> listAllKeys(String directory) {
        readLock.lock();
        try {
            return algoInstance.listAllKeys(directory);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * List all keys in the default directory.
     */
    public List<KeyVersion> listAllKeys() {
        readLock.lock();
        try {
            return algoInstance.listAllKeys();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * List keys for a specific algorithm and directory.
     */
    public List<KeyVersion> listKeys(Algorithm algorithm, String directory) {
        readLock.lock();
        try {
            return algoInstance.listKeys(algorithm, directory);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * List keys for the current algorithm.
     */
    public List<KeyVersion> listKeys() {
        readLock.lock();
        try {
            return algoInstance.listKeys(currentAlgorithm);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Get key versions for a specific algorithm.
     */
    public List<String> getKeyVersions(Algorithm algorithm) {
        Algorithm algo = algorithm == null ? currentAlgorithm : algorithm;
        readLock.lock();
        try {
            return algoInstance.getKeyVersions(algo);
        } finally {
            readLock.unlock();
        }
    }

    public List<String> getKeyVersions() {
        readLock.lock();
        try {
            return algoInstance.getKeyVersions();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Check if a token is decodable (structure is valid).
     */
    public boolean isTokenDecodable(String token) {
        readLock.lock();
        try {
            return JwtDecoder.isTokenDecodable(token, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Build JWT properties from input.
     */
    private JwtProperties buildJwtProperties(JwtProperties jwtInfo) {
        Objects.requireNonNull(jwtInfo, "JwtProperties cannot be null");
        return JwtProperties.builder()
                .subject(jwtInfo.getSubject())
                .issuer(jwtInfo.getIssuer())
                .expiration(jwtInfo.getExpiration())
                .build();
    }

    /**
     * Validate HMAC algorithm.
     */
    private void validateHmacAlgorithm(Algorithm algorithm) {
        if (algorithm != null && !algorithm.isHmac()) {
            throw new IllegalArgumentException("Algorithm must be HMAC type: " + algorithm);
        }
    }

    /**
     * Validate Asymmetric algorithm.
     */
    private void validateAsymmetricAlgorithm(Algorithm algorithm) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        if (algorithm.isHmac()) {
            throw new IllegalArgumentException("HMAC algorithm does not support key pair generation: " + algorithm);
        }
    }

    /**
     * Generate all key pairs for all supported algorithms.
     * Used for initialization or testing.
     */
    public boolean generateAllKeyPairs() {
        boolean allSuccess = true;

        // 1. HMAC
        try {
            if (!factory.get(Algorithm.HMAC256).generateAllKeyPairs()) {
                allSuccess = false;
            }
        } catch (Exception e) {
            log.warn("Failed to generate HMAC keys: {}", e.getMessage());
            allSuccess = false;
        }

        // 2. RSA
        try {
            if (!factory.get(Algorithm.RSA256).generateAllKeyPairs()) {
                allSuccess = false;
            }
        } catch (Exception e) {
            log.warn("Failed to generate RSA keys: {}", e.getMessage());
            allSuccess = false;
        }

        // 3. ECDSA
        try {
            if (!factory.get(Algorithm.ES256).generateAllKeyPairs()) {
                allSuccess = false;
            }
        } catch (Exception e) {
            log.warn("Failed to generate ECDSA keys: {}", e.getMessage());
            allSuccess = false;
        }

        // 4. EdDSA
        try {
            if (!factory.get(Algorithm.Ed25519).generateAllKeyPairs()) {
                allSuccess = false;
            }
        } catch (Exception e) {
            log.warn("Failed to generate EdDSA keys: {}", e.getMessage());
            allSuccess = false;
        }

        return allSuccess;
    }

    /**
     * Configure the current algorithm with a specific key directory.
     */
    public JwtAlgo withKeyDirectory(Path keyDir) {
        readLock.lock();
        try {
            return algoInstance.withKeyDirectory(keyDir);
        } finally {
            readLock.unlock();
        }
    }

    public JwtAlgo withKeyDirectory(String keyDir) {
        readLock.lock();
        try {
            return algoInstance.withKeyDirectory(keyDir);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Get the current active key object (SecretKey, KeyPair, etc.).
     */
    public Object getCurrentKey() {
        readLock.lock();
        try {
            return algoInstance.getCurrentKey();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Close the KeyMinter and release resources.
     */
    public void close() {
        readLock.lock();
        try {
            algoInstance.close();
            if (previousAlgoInstance != null) previousAlgoInstance.close();
        } finally {
            readLock.unlock();
        }
        log.info("KeyMinter closed");
    }

    /**
     * Scheduled cleanup task.
     * Cleans up expired graceful algorithms and expired keys in the factory.
     */
    @Scheduled(fixedRateString = "${key-minter.cleanup-interval-millis:60000}")
    public void scheduledCleanup() {
        // Cleanup graceful rotation instance
        cleanupExpiredGracefulAlgo();

        // Cleanup expired keys in all algorithms
        factory.cleanupAllAlgos();
    }

    public JwtStandardInfo decodeStandardInfo(Algorithm algorithm, String token) {
        JwtAlgo load = autoLoad(algorithm);
        return JwtDecoder.decodeStandardInfo(token, load);
    }

    public <T> T decodeCustomInfo(Algorithm algorithm, String token, Class<T> clazz) {
        JwtAlgo load = autoLoad(algorithm);
        return JwtDecoder.decodeCustomClaimsSafe(token, load, clazz);
    }

    public boolean isDecodable(Algorithm algorithm, String token) {
        JwtAlgo load = autoLoad(algorithm);
        return JwtDecoder.isTokenDecodable(token, load);
    }

    public String getKeyInfo(Algorithm algorithm, String keyId) {
        JwtAlgo load = autoLoad(algorithm, (String) null, keyId);
        return load.getKeyInfo();
    }

    public String getKeyVersions(Algorithm algorithm, String keyId) {
        JwtAlgo load = autoLoad(algorithm, null, keyId);
        return load.getKeyVersions().toString();
    }

    public <T> String generateToken(Algorithm algorithm, String keyId, JwtProperties properties, T payload, Class<T> clazz) {
        JwtAlgo load = autoLoad(algorithm, null, keyId);
        return load.generateToken(properties, algorithm, payload, clazz);
    }

    /**
     * Clear the internal cache of the factory.
     */
    public void clearCache() {
        factory.clearCache();
    }

    public Object getKeyByVersion(String keyId) {
        readLock.lock();
        try {
            return algoInstance.getKeyByVersion(keyId);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Check if any key pair exists for the current algorithm.
     */
    public boolean keyPairExists() {
        readLock.lock();
        try {
            return algoInstance.keyPairExists();
        } finally {
            readLock.unlock();
        }
    }

    public boolean keyPairExists(Algorithm algorithm) {
        readLock.lock();
        try {
            return algoInstance.keyPairExists(algorithm);
        } finally {
            readLock.unlock();
        }
    }

    public String getActiveKeyId() {
        readLock.lock();
        try {
            return algoInstance.getActiveKeyId();
        } finally {
            readLock.unlock();
        }
    }

    public KeyVersion getActiveKeyVersion() {
        return algoInstance.getActiveKeyVersion();
    }

    public List<String> getKeyVersionsByStatus(KeyStatus status) {
        return algoInstance.getKeyVersionsByStatus(status);
    }

    /**
     * Get the size of the factory cache.
     */
    public int getCacheSize() {
        return factory.getCacheSize();
    }

    public Path getKeyPath() {
        readLock.lock();
        try {
            return algoInstance.getKeyPath();
        } finally {
            readLock.unlock();
        }
    }

    private void cleanupExpiredGracefulAlgo() {
        if (previousAlgoInstance != null && System.currentTimeMillis() >= previousAlgoExpiryTime) {
            previousAlgoInstance.close();
            previousAlgoInstance = null;
        }
    }

    /**
     * Get the graceful backup algorithm, cleaning it up if expired.
     */
    private JwtAlgo getGracefulAlgo() {
        cleanupExpiredGracefulAlgo();
        return previousAlgoInstance;
    }

    /**
     * Record a hit on a blacklisted (revoked) token.
     */
    void recordBlacklistHit() {
        blacklistHitCount.incrementAndGet();
    }

    /**
     * Get operational metrics.
     */
    public Map<String, Long> getMetrics() {
        return Map.of(
                "gracefulUsage", gracefulUsageCount.get(),
                "blacklistHit", blacklistHitCount.get()
        );
    }

    public void resetMetrics() {
        gracefulUsageCount.set(0);
        blacklistHitCount.set(0);
    }
}
