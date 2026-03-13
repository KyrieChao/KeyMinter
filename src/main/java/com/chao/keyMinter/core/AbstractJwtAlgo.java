package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.adapter.out.fs.FileSystemKeyRepository;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.model.KeyStatus;
import com.chao.keyMinter.domain.model.KeyVersion;
import com.chao.keyMinter.domain.port.out.KeyRepository;
import com.chao.keyMinter.domain.port.out.KeyRepositoryFactory;
import com.chao.keyMinter.domain.service.JwtAlgo;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Abstract Base Class for JWT Algorithms.
 * Provides common functionality for key rotation, token generation, and validation.
 * Supports transition periods for key rotation.
 */
@Getter
@Slf4j
public abstract class AbstractJwtAlgo implements JwtAlgo {

    // JSON Mapper
    protected static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Default key parameters
    protected static final int DEFAULT_RSA_KEY_SIZE = 2048;
    protected static final int DEFAULT_HMAC_KEY_LENGTH = 64;
    protected static final int MIN_HMAC_KEY_LENGTH = 32;

    // In-memory caches for revoked fingerprints and key versions
    protected final Map<String, Long> revokedFingerprints = new ConcurrentHashMap<>();
    protected final Map<String, KeyVersion> keyVersions = new ConcurrentHashMap<>();

    // Concurrency control for active key access
    protected final ReentrantReadWriteLock activeKeyLock = new ReentrantReadWriteLock();
    protected final ReentrantReadWriteLock.ReadLock readLock = activeKeyLock.readLock();
    protected final ReentrantReadWriteLock.WriteLock writeLock = activeKeyLock.writeLock();

    // Repository Factory (Hexagonal Port)
    protected KeyRepositoryFactory repositoryFactory;

    // Configuration properties
    protected final KeyMinterProperties keyMinterProperties;
    protected volatile String activeKeyId;
    protected volatile Path currentKeyPath;

    // Key Repository implementation
    protected volatile KeyRepository keyRepository;

    protected volatile boolean keyRotationEnabled = false;
    protected volatile Instant defaultNewExpMs;

    // Lifecycle flag
    private final AtomicBoolean closed = new AtomicBoolean(false);

    protected AbstractJwtAlgo(KeyMinterProperties keyMinterProperties) {
        this.keyMinterProperties = Objects.requireNonNullElseGet(keyMinterProperties, KeyMinterProperties::new);
        this.defaultNewExpMs = Instant.now().plus(Duration.ofMinutes(30));
    }

    @Override
    public String generateToken(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
        validateJwtProperties(properties);
        validateAlgorithm(algorithm);
        dispatchAlgorithmValidation(algorithm);
        // Ensure active key is valid for signing
        checkActiveKeyCanSign();
        return generateJwt(properties, customClaims, algorithm);
    }

    @Override
    public String generateToken(JwtProperties properties, Algorithm algorithm) {
        return generateToken(properties, null, algorithm);
    }

    @Override
    public boolean manageSecret(String secret) {
        log.warn("Secret management not implemented for {}", this.getClass().getSimpleName());
        return false;
    }

    /**
     * Rotate key with a transition period.
     *
     * @param algorithm             Algorithm type
     * @param newKeyIdentifier      New key ID
     * @param transitionPeriodHours Transition duration in hours
     * @return true if successful
     */
    public boolean rotateKeyWithTransition(Algorithm algorithm, String newKeyIdentifier, int transitionPeriodHours) {
        if (!isKeyRotationEnabled()) {
            throw new UnsupportedOperationException("Key rotation is not enabled");
        }
        log.warn("rotateKeyWithTransition not implemented for this algorithm: {}", algorithm);
        return false;
    }

    @Override
    public List<String> getKeyVersions() {
        readLock.lock();
        try {
            return new ArrayList<>(keyVersions.keySet());
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public List<String> getKeyVersions(Algorithm algorithm) {
        if (algorithm == null) {
            return Collections.emptyList();
        }
        readLock.lock();
        try {
            if (keyVersions.isEmpty()) {
                return Collections.emptyList();
            }
            return keyVersions.values().stream()
                    .filter(v -> v.getAlgorithm() == algorithm)
                    .map(KeyVersion::getKeyId)
                    .collect(Collectors.toList());
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Get key versions by status.
     */
    @Override
    public List<String> getKeyVersionsByStatus(KeyStatus status) {
        if (status == null) {
            return Collections.emptyList();
        }
        readLock.lock();
        try {
            return keyVersions.values().stream()
                    .filter(v -> v.getStatus() == status)
                    .map(KeyVersion::getKeyId)
                    .collect(Collectors.toList());
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public boolean setActiveKey(String keyId) {
        if (StringUtils.isBlank(keyId)) {
            log.error("Key ID cannot be null or empty");
            return false;
        }

        writeLock.lock();
        try {
            KeyVersion newVersion = keyVersions.get(keyId);
            if (newVersion == null) {
                log.error("Key version not found: {}", keyId);
                return false;
            }

            // Check if key is expired
            if (newVersion.isExpired()) {
                log.error("Key {} has expired, cannot activate", keyId);
                return false;
            }

            // Check if key is revoked
            if (newVersion.getStatus() == KeyStatus.REVOKED) {
                log.error("Key {} has been revoked, cannot activate", keyId);
                return false;
            }

            // Handle transition for the currently active key
            if (activeKeyId != null) {
                KeyVersion oldActive = keyVersions.get(activeKeyId);
                if (oldActive != null) {
                    // Set transition end time
                    Instant transitionEnd = Instant.now().plusMillis(
                            keyMinterProperties.getTransitionPeriodMillis()
                    );
                    oldActive.startTransition(transitionEnd);
                    log.debug("Old key {} entering transition period until {}", activeKeyId, transitionEnd);
                }
            }

            // Activate the new key
            newVersion.activate();
            activeKeyId = keyId;
            // Load key material
            loadKeyPair(keyId);
            log.info("Activated key: {}, algorithm: {}, expires at: {}", keyId, newVersion.getAlgorithm(), newVersion.getExpiresAt());
            return true;
        } catch (Exception e) {
            log.error("Failed to set active key {}: {}", keyId, e.getMessage(), e);
            return false;
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Check if the active key is valid for signing.
     */
    protected void checkActiveKeyCanSign() {
        readLock.lock();
        try {
            if (activeKeyId == null) {
                throw new IllegalStateException("No active key. Call setActiveKey or rotateKey first.");
            }

            KeyVersion activeVersion = keyVersions.get(activeKeyId);
            if (activeVersion == null) {
                throw new IllegalStateException("Active key version not found: " + activeKeyId);
            }

            // Check expiration
            if (activeVersion.isExpired()) {
                throw new IllegalStateException("Active key has expired: " + activeKeyId);
            }

            // Check status
            if (!activeVersion.canSign()) {
                throw new IllegalStateException("Active key cannot be used for signing. Status: "
                        + activeVersion.getStatus());
            }
        } finally {
            readLock.unlock();
        }
    }


    protected Instant saveKeyPairTo(KeyPair keyPair, Path tempDir, Algorithm algorithm, String PRIVATE_KEY_FILE, String PUBLIC_KEY_FILE,
                                    String ALGORITHM_FILE, String EXPIRATION_FILE, String STATUS_FILE) throws IOException {
        // Calculate expiration time
        Instant expiresAt = calculateKeyExpiration();

        // 1. Repository logic omitted for brevity in this method, assuming direct file access to tempDir.
        //    KeyRotation handles atomic moves from tempDir to targetDir.

        Path privateKeyPath = tempDir.resolve(PRIVATE_KEY_FILE);
        Files.write(privateKeyPath, keyPair.getPrivate().getEncoded(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        Path publicKeyPath = tempDir.resolve(PUBLIC_KEY_FILE);
        Files.write(publicKeyPath, keyPair.getPublic().getEncoded(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        Path algorithmFile = tempDir.resolve(ALGORITHM_FILE);
        Files.writeString(algorithmFile, algorithm.name());

        Path expirationFile = tempDir.resolve(EXPIRATION_FILE);
        Files.writeString(expirationFile, expiresAt.toString());

        // Write status file
        Path statusFile = tempDir.resolve(STATUS_FILE);
        Files.writeString(statusFile, KeyStatus.CREATED.name());

        return expiresAt;
    }

    protected boolean canKeyNotVerify(String keyId) {
        return !canKeyVerify(keyId);
    }

    /**
     * Check if a key can be used for verification (valid status and not expired).
     */
    protected boolean canKeyVerify(String keyId) {
        if (StringUtils.isBlank(keyId)) return false;
        readLock.lock();
        try {
            KeyVersion version = keyVersions.get(keyId);
            if (version == null) {
                log.error("canKeyVerify: Version not found for keyId: {}", keyId);
                return false;
            }

            // Check transition period expiration
            if (version.getStatus() == KeyStatus.TRANSITIONING &&
                    version.getTransitionEndsAt() != null &&
                    Instant.now().isAfter(version.getTransitionEndsAt())) {

                // Lazy deactivation
                readLock.unlock();
                writeLock.lock();
                try {
                    // Double check
                    if (version.getStatus() == KeyStatus.TRANSITIONING &&
                            Instant.now().isAfter(version.getTransitionEndsAt())) {
                        version.deactivate();
                        log.info("Key {} transition period ended (lazy check), deactivated", keyId);
                    }
                } finally {
                    writeLock.unlock();
                    readLock.lock();
                }
            }

            boolean can = version.canVerify();
            if (!can) {
                log.error("canKeyVerify: Key {} status {} cannot verify (Transition end: {})",
                        keyId, version.getStatus(), version.getTransitionEndsAt());
            }
            return can;
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public String getActiveKeyId() {
        readLock.lock();
        try {
            return activeKeyId;
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Get active key version object.
     */
    @Override
    public KeyVersion getActiveKeyVersion() {
        readLock.lock();
        try {
            if (activeKeyId == null) {
                return null;
            }
            return keyVersions.get(activeKeyId);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Generate a unique ID for a key version.
     */
    public String generateKeyVersionId(Algorithm algorithm) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        return algorithm.name() + "-v" +
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + "-"
                + UUID.randomUUID().toString().substring(0, 8);
    }

    /**
     * Calculate key expiration time based on configuration.
     *
     * @return Instant representing the expiration time.
     */
    protected Instant calculateKeyExpiration() {
        return Instant.now().plusMillis(keyMinterProperties.getKeyValidityMillis());
    }

    protected boolean isKeyRotationEnabled() {
        return keyMinterProperties != null && keyMinterProperties.isEnableRotation();
    }

    protected void loadKeyPair(String keyId) {
        log.warn("loadKeyPair not implemented for key version: {}", keyId);
    }

    /**
     * Validate directory path for security.
     */
    protected void validateDirectoryPath(Path path) {
        Objects.requireNonNull(path, "Path cannot be null");
        Path normalized = path.normalize();
        if (!normalized.equals(path)) {
            throw new SecurityException("Invalid directory path (not normalized): " + path);
        }
        if (Files.isSymbolicLink(path)) {
            throw new SecurityException("Symbolic links are not allowed: " + path);
        }
    }

    protected void enableKeyRotation() {
        this.keyRotationEnabled = true;
        log.debug("Key rotation enabled for {}", this.getClass().getSimpleName());
    }

    protected void initializeKeyVersions() {
        if (currentKeyPath != null || keyRepository != null) {
            loadExistingKeyVersions();
        }
    }

    /**
     * Cleanup expired keys and manage transition states.
     */
    @Override
    public void cleanupExpiredKeys() {
        writeLock.lock();
        try {
            Instant now = Instant.now();
            int expiredCount = 0;
            int transitionedCount = 0;

            for (KeyVersion version : keyVersions.values()) {
                // Check expiration
                if (version.getExpiresAt() != null && now.isAfter(version.getExpiresAt())) {
                    if (version.getStatus() != KeyStatus.EXPIRED) {
                        version.markExpired();
                        updateKeyStatusFile(version.getKeyId(), KeyStatus.EXPIRED);
                        expiredCount++;
                        log.info("Key {} marked as expired", version.getKeyId());
                    }
                }

                // Check transition end
                if (version.getStatus() == KeyStatus.TRANSITIONING &&
                        version.getTransitionEndsAt() != null &&
                        now.isAfter(version.getTransitionEndsAt())) {
                    version.deactivate();
                    updateKeyStatusFile(version.getKeyId(), KeyStatus.INACTIVE);
                    transitionedCount++;
                    log.info("Key {} transition period ended, deactivated", version.getKeyId());
                }
            }

            // Auto-switch if active key is expired
            if (activeKeyId != null) {
                KeyVersion activeVersion = keyVersions.get(activeKeyId);
                if (activeVersion != null && activeVersion.isExpired()) {
                    // Try to find a valid replacement
                    for (KeyVersion version : keyVersions.values()) {
                        if (version.getStatus() == KeyStatus.CREATED && !version.isExpired()) {
                            setActiveKey(version.getKeyId());
                            log.info("Auto-switched to new key: {}", version.getKeyId());
                            break;
                        }
                    }
                }
            }

            // 2. Delete old keys (retention policy)
            long retentionMillis = keyMinterProperties.getExpiredKeyRetentionMillis();
            if (retentionMillis > 0) {
                Iterator<Map.Entry<String, KeyVersion>> it = keyVersions.entrySet().iterator();
                while (it.hasNext()) {
                    Map.Entry<String, KeyVersion> entry = it.next();
                    KeyVersion version = entry.getValue();

                    if (version.getStatus() == KeyStatus.EXPIRED || version.getStatus() == KeyStatus.REVOKED) {
                        Instant cleanupThreshold = now.minusMillis(retentionMillis);
                        if (version.getExpiresAt() != null && version.getExpiresAt().isBefore(cleanupThreshold)) {
                            try {
                                deleteKeyDirectory(version);
                                it.remove();
                                log.info("Deleted expired/revoked key directory: {}", version.getKeyId());
                            } catch (Exception e) {
                                log.error("Failed to delete key directory {}: {}", version.getKeyId(), e.getMessage());
                            }
                        }
                    }
                }
            }

            if (expiredCount > 0 || transitionedCount > 0) {
                log.info("Key cleanup completed: {} expired, {} transitioned",
                        expiredCount, transitionedCount);
            }
        } finally {
            writeLock.unlock();
        }
    }

    protected void updateKeyStatusFile(String keyId, KeyStatus newStatus) {
        if (keyRepository == null) {
            log.warn("KeyRepository not initialized, cannot update status file for {}", keyId);
            return;
        }

        try {
            keyRepository.saveMetadata(keyId, "status.info", newStatus.name());
            log.debug("Updated status file for key {}: {}", keyId, newStatus);
        } catch (IOException e) {
            log.warn("Failed to update status file for key {}: {}", keyId, e.getMessage());
        }
    }

    protected Optional<Path> findKeyDir(String tag, Predicate<Path> extraFilter) {
        if (currentKeyPath == null || !Files.exists(currentKeyPath)) {
            return Optional.empty();
        }

        // Retry logic for filesystem latency
        for (int i = 0; i < 3; i++) {
            try (Stream<Path> dirs = Files.list(currentKeyPath)) {
                List<Path> allDirs = dirs.toList();

                Predicate<Path> filter = directoriesContainingTag(tag);
                if (extraFilter != null) {
                    filter = filter.and(extraFilter);
                }

                Optional<Path> found = allDirs.stream().filter(filter)
                        .max(Comparator.comparing(this::getDirTimestamp));

                if (found.isPresent()) {
                    return found;
                }

                // If not found, wait and retry
                try {
                    Thread.sleep(100 * (i + 1));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            } catch (IOException e) {
                log.error("Failed to scan directory {}: {}", currentKeyPath, e.getMessage());
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    public abstract String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm);

    protected void validateJwtProperties(JwtProperties properties) {
        Objects.requireNonNull(properties, "JwtProperties cannot be null");

        if (StringUtils.isBlank(properties.getSubject())) {
            throw new IllegalArgumentException("JWT subject cannot be null or empty");
        }
        if (StringUtils.isBlank(properties.getIssuer())) {
            throw new IllegalArgumentException("JWT issuer cannot be null or empty");
        }
        if (properties.getExpiration() == null) {
            throw new IllegalArgumentException("JWT expiration cannot be null");
        }

        long remainSeconds = Duration.between(Instant.now(), properties.getExpiration()).toSeconds();
        if (remainSeconds <= 0) {
            throw new IllegalArgumentException("JWT expiration must be in the future");
        }
    }

    /**
     * Create JWT Builder with kid header.
     */
    protected JwtBuilder createJwtBuilder(JwtProperties properties, Map<String, Object> customClaims) {
        long now = System.currentTimeMillis();

        // Get active key ID
        String kid = getActiveKeyId();

        JwtBuilder builder = Jwts.builder()
                .subject(properties.getSubject())
                .issuer(properties.getIssuer())
                .issuedAt(new Date(now))
                .expiration(toDate(properties.getExpiration()));

        // Add kid to header
        if (StringUtils.isNotBlank(kid)) {
            builder.header().add("kid", kid).and();
        }

        if (customClaims != null && !customClaims.isEmpty()) {
            builder.claims(customClaims);
        }
        return builder;
    }

    public static Date toDate(Instant instant) {
        Objects.requireNonNull(instant, "Instant cannot be null");
        return Date.from(instant);
    }

    @Override
    public List<KeyVersion> listAllKeys() {
        if (currentKeyPath != null) {
            Path parent = currentKeyPath.getParent();
            // If parent is null (e.g. path is just "hmac-keys"), we might need to use absolute path or current dir
            if (parent == null) {
                parent = Paths.get(".");
            }
            return listAllKeys(parent.toString());
        }
        return listAllKeys(String.valueOf(getDefaultSecretDir()));
    }

    @Override
    public List<KeyVersion> listAllKeys(String directory) {
        if (StringUtils.isBlank(directory)) {
            return Collections.emptyList();
        }

        Path baseDir = Paths.get(directory);
        if (!Files.exists(baseDir) || !Files.isDirectory(baseDir)) {
            log.warn("Directory does not exist or is not a directory: {}", directory);
            return Collections.emptyList();
        }

        List<KeyVersion> keys = new ArrayList<>();
        try (Stream<Path> typeDirs = Files.list(baseDir)) {
            typeDirs.filter(Files::isDirectory).forEach(typeDir -> {
                try (Stream<Path> versionDirs = Files.list(typeDir)) {
                    versionDirs.filter(Files::isDirectory).forEach(versionDir -> {
                        try {
                            KeyVersion kv = createKeyVersionFromDir(typeDir, versionDir);
                            if (kv != null) {
                                keys.add(kv);
                            }
                        } catch (Exception e) {
                            log.warn("Failed to process key directory {}: {}", versionDir, e.getMessage());
                        }
                    });
                } catch (IOException e) {
                    log.error("Error reading key directory {}: {}", typeDir, e.getMessage());
                }
            });
        } catch (IOException e) {
            log.error("Failed to list keys in directory {}: {}", directory, e.getMessage());
            return Collections.emptyList();
        }
        return keys;
    }

    private KeyVersion createKeyVersionFromDir(Path typeDir, Path versionDir) {
        String keyId = versionDir.getFileName().toString();
        Algorithm algorithm = detectAlgorithmFromDir(typeDir.getFileName().toString(), versionDir);

        // Read status
        KeyStatus status = readKeyStatus(versionDir);

        // Read expiration
        Instant expiresAt = readKeyExpiration(versionDir);

        // Read transition end time
        Instant transitionEndsAt = readTransitionEndTime(versionDir);

        LocalDateTime createdTime = parseCreationTimeFromDirName(keyId);
        LocalDateTime activatedTime = (status == KeyStatus.ACTIVE || status == KeyStatus.TRANSITIONING)
                ? LocalDateTime.now() : null;

        return KeyVersion.builder()
                .keyId(keyId)
                .algorithm(algorithm)
                .status(status)
                .createdTime(createdTime)
                .activatedTime(activatedTime)
                .expiresAt(expiresAt)
                .transitionEndsAt(transitionEndsAt)
                .keyPath(versionDir.toString())
                .build();
    }

    private KeyStatus readKeyStatus(Path versionDir) {
        if (keyRepository != null) {
            try {
                String keyId = versionDir.getFileName().toString();
                return keyRepository.loadMetadata(keyId, "status.info")
                        .map(s -> KeyStatus.valueOf(s.trim()))
                        .orElse(KeyStatus.CREATED);
            } catch (IOException e) {
                log.debug("Failed to read status via repository: {}", e.getMessage());
            }
        }

        // Fallback
        Path statusFile = versionDir.resolve("status.info");
        if (Files.exists(statusFile)) {
            try {
                String statusStr = Files.readString(statusFile, StandardCharsets.UTF_8).trim();
                return KeyStatus.valueOf(statusStr);
            } catch (Exception e) {
                log.debug("Failed to read status from {}: {}", statusFile, e.getMessage());
            }
        }
        return KeyStatus.CREATED;
    }

    private Instant readKeyExpiration(Path versionDir) {
        if (keyRepository != null) {
            try {
                String keyId = versionDir.getFileName().toString();
                return keyRepository.loadMetadata(keyId, "expiration.info")
                        .map(s -> Instant.parse(s.trim()))
                        .orElse(null);
            } catch (IOException e) {
                log.debug("Failed to read expiration via repository: {}", e.getMessage());
            }
        }

        // Fallback
        Path expFile = versionDir.resolve("expiration.info");
        if (Files.exists(expFile)) {
            try {
                String expStr = Files.readString(expFile, StandardCharsets.UTF_8).trim();
                return Instant.parse(expStr);
            } catch (Exception e) {
                log.debug("Failed to read expiration from {}: {}", expFile, e.getMessage());
            }
        }
        return null;
    }

    private Instant readTransitionEndTime(Path versionDir) {
        if (keyRepository != null) {
            try {
                String keyId = versionDir.getFileName().toString();
                return keyRepository.loadMetadata(keyId, "transition.info")
                        .map(s -> Instant.parse(s.trim()))
                        .orElse(null);
            } catch (IOException e) {
                log.debug("Failed to read transition end via repository: {}", e.getMessage());
            }
        }

        // Fallback
        Path transitionFile = versionDir.resolve("transition.info");
        if (Files.exists(transitionFile)) {
            try {
                String transitionStr = Files.readString(transitionFile, StandardCharsets.UTF_8).trim();
                return Instant.parse(transitionStr);
            } catch (Exception e) {
                log.debug("Failed to read transition end from {}: {}", transitionFile, e.getMessage());
            }
        }
        return null;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> Map<String, Object> convertToClaimsMap(T customClaims) {
        if (customClaims == null) {
            return null;
        }
        if (customClaims instanceof Map) {
            return (Map<String, Object>) customClaims;
        }
        if (customClaims instanceof String) {
            try {
                return OBJECT_MAPPER.readValue((String) customClaims, new TypeReference<>() {
                });
            } catch (JsonProcessingException e) {
                throw new IllegalArgumentException("Invalid JSON claims string", e);
            }
        }
        try {
            String json = OBJECT_MAPPER.writeValueAsString(customClaims);
            return OBJECT_MAPPER.readValue(json, new TypeReference<>() {
            });
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to convert object to claims map", e);
        }
    }

    @Override
    public String getKeyInfo() {
        readLock.lock();
        try {
            KeyVersion activeVersion = activeKeyId != null ? keyVersions.get(activeKeyId) : null;
            String status = activeVersion != null ? activeVersion.getStatus().name() : "None";
            long remaining = activeVersion != null ? activeVersion.getRemainingSeconds() : 0;

            return String.format("Key directory: %s, Active key: %s, Status: %s, Remaining: %ds, Key versions: %d",
                    currentKeyPath != null ? currentKeyPath : "Not set",
                    activeKeyId != null ? activeKeyId : "None",
                    status,
                    remaining,
                    keyVersions.size());
        } finally {
            readLock.unlock();
        }
    }

    protected void markKeyActive(String keyId) {
        writeLock.lock();
        try {
            KeyVersion version = keyVersions.get(keyId);
            if (version == null) {
                log.warn("Cannot mark key active - version not found: {}", keyId);
                return;
            }

            version.activate();

            // Save status to repository
            if (keyRepository != null) {
                try {
                    keyRepository.saveMetadata(keyId, "status.info", KeyStatus.ACTIVE.name());
                } catch (IOException e) {
                    log.warn("Failed to create active marker for key {}: {}", keyId, e.getMessage());
                }
            } else {
                log.warn("KeyRepository not initialized, cannot mark key active on disk: {}", keyId);
            }
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public Path getKeyPath() {
        return currentKeyPath;
    }

    @Override
    public String getAlgorithmInfo() {
        return "Default algorithm information";
    }

    @Override
    public boolean keyPairExists() {
        readLock.lock();
        try {
            return !keyVersions.isEmpty();
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public boolean keyPairExists(Algorithm algorithm) {
        if (algorithm == null) {
            return false;
        }
        readLock.lock();
        try {
            return keyVersions.values().stream().anyMatch(v -> v.getAlgorithm() == algorithm);
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public JwtAlgo autoLoadFirstKey(Algorithm algorithm, String preferredKeyId, boolean force) {
        // Try to load preferred key
        JwtAlgo loaded = autoLoadKey(preferredKeyId);
        if (loaded != null) {
            return loaded;
        }

        String tag = (algorithm == null) ? null : algorithm.name().toUpperCase();
        if (!(force || hasKeyFilesInDirectory(tag))) {
            log.warn("No {} key directory found under {}", tag == null ? "" : " " + tag, currentKeyPath);
            writeLock.lock();
            try {
                this.activeKeyId = null;
            } finally {
                writeLock.unlock();
            }
            return this;
        }

        loadFirstKeyFromDirectory(force ? null : tag);
        return this;
    }

    protected void deleteKeyDirectory(KeyVersion version) throws IOException {
        if (version == null || StringUtils.isBlank(version.getKeyId())) {
            return;
        }

        if (keyRepository != null) {
            keyRepository.delete(version.getKeyId());
        } else {
            // Fallback to old logic if repo not init (should rare)
            log.warn("KeyRepository not initialized for deletion of {}", version.getKeyId());
            if (StringUtils.isNotBlank(version.getKeyPath())) {
                Path dir = Paths.get(version.getKeyPath());
                if (Files.exists(dir)) {
                    try (Stream<Path> walk = Files.walk(dir)) {
                        walk.sorted(Comparator.reverseOrder())
                                .map(Path::toFile)
                                .forEach(file -> {
                                    boolean deleted = file.delete();
                                    if (!deleted) {
                                        log.warn("Failed to delete file/directory: {}", file);
                                    }
                                });
                    }
                }
            }
        }
    }

    protected abstract boolean hasKeyFilesInDirectory(String tag);

    protected abstract void loadFirstKeyFromDirectory(String tag);

    @Override
    public JwtAlgo withKeyDirectory(Path keyDir) {
        Objects.requireNonNull(keyDir, "Key directory cannot be null");
        this.currentKeyPath = keyDir;
        // Initialize default repository
        this.keyRepository = new FileSystemKeyRepository(keyDir);
        initializeKeyVersions();
        return this;
    }

    protected void validateAlgorithm(Algorithm algorithm) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
    }

    protected JwtAlgo autoLoadKey(String preferredKeyId) {
        if (StringUtils.isBlank(preferredKeyId)) {
            return null;
        }

        writeLock.lock();
        try {
            // Check if already loaded
            if (keyVersions.containsKey(preferredKeyId)) {
                KeyVersion version = keyVersions.get(preferredKeyId);
                // Check expired
                if (version.isExpired()) {
                    log.warn("Preferred key {} has expired", preferredKeyId);
                    return this;
                }
                setActiveKey(preferredKeyId);
                return this;
            }

            // Try to load from disk
            try {
                Path candidate = currentKeyPath.resolve(preferredKeyId);
                if (Files.exists(candidate) && Files.isDirectory(candidate)) {
                    loadKeyVersion(candidate);
                    if (keyVersions.containsKey(preferredKeyId)) {
                        KeyVersion version = keyVersions.get(preferredKeyId);
                        if (!version.isExpired()) {
                            setActiveKey(preferredKeyId);
                            return this;
                        }
                    }
                }
            } catch (Exception e) {
                log.warn("Failed to load preferred key {} from disk: {}", preferredKeyId, e.getMessage());
            }

            log.warn("Specified key {} not found or expired", preferredKeyId);
            return this;
        } finally {
            writeLock.unlock();
        }
    }

    protected abstract void loadKeyVersion(Path path);

    protected abstract boolean isKeyVersionDir(Path dir);

    protected void validateHmacAlgorithm(Algorithm algorithm) {
        validateAlgorithm(algorithm);
        if (!algorithm.isHmac()) {
            throw new IllegalArgumentException("Algorithm must be HMAC type: " + algorithm);
        }
    }

    protected LocalDateTime getCreationTimeFromDir(Path versionDir) {
        LocalDateTime meta = readVersionCreatedTime(versionDir);
        if (meta != null) {
            return meta;
        }

        try {
            String dirName = versionDir.getFileName().toString();
            if (dirName.contains("-v")) {
                int startIdx = dirName.indexOf("-v") + 2;
                int endIdx = Math.min(startIdx + 15, dirName.length());
                if (endIdx - startIdx == 15) {
                    String timestamp = dirName.substring(startIdx, endIdx);
                    return LocalDateTime.parse(timestamp, DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
                }
            }
        } catch (Exception e) {
            log.debug("Failed to parse creation time from directory name: {}", e.getMessage());
        }
        return LocalDateTime.MIN;
    }

    protected Predicate<Path> directoriesContainingTag(String tag) {
        Predicate<Path> filter = Files::isDirectory;
        if (StringUtils.isNotBlank(tag)) {
            String upperTag = tag.toUpperCase(Locale.ROOT);
            filter = filter.and(dir -> dir.getFileName().toString()
                    .toUpperCase(Locale.ROOT).contains(upperTag));
        }
        return filter;
    }

    protected void validateRsaAlgorithm(Algorithm algorithm) {
        validateAlgorithm(algorithm);
        if (!algorithm.isRsa()) {
            throw new IllegalArgumentException("Algorithm must be RSA type: " + algorithm);
        }
    }

    protected void validateEcdsaAlgorithm(Algorithm algorithm) {
        validateAlgorithm(algorithm);
        if (!algorithm.isEcdsa()) {
            throw new IllegalArgumentException("Algorithm must be ECDSA type: " + algorithm);
        }
    }

    protected void validateEddsaAlgorithm(Algorithm algorithm) {
        validateAlgorithm(algorithm);
        if (!algorithm.isEddsa()) {
            throw new IllegalArgumentException("Algorithm must be EdDSA type: " + algorithm);
        }
    }

    protected abstract Object getSignAlgorithm(Algorithm algorithm);

    private Algorithm detectAlgorithmFromDir(String typeDirName, Path versionDir) {
        String keyId = versionDir.getFileName().toString();
        if (keyRepository != null) {
            try {
                return keyRepository.loadMetadata(keyId, "algorithm.info")
                        .map(s -> Algorithm.valueOf(s.trim()))
                        .orElse(detectAlgorithmFromTypeDir(typeDirName));
            } catch (IOException e) {
                log.debug("Failed to read algorithm via repository: {}", e.getMessage());
            }
        }

        // Fallback
        Path algFile = versionDir.resolve("algorithm.info");
        if (Files.exists(algFile)) {
            try {
                String content = Files.readString(algFile, StandardCharsets.UTF_8).trim();
                return Algorithm.valueOf(content);
            } catch (Exception e) {
                log.debug("Failed to read algorithm from file: {}", e.getMessage());
            }
        }

        return detectAlgorithmFromTypeDir(typeDirName);
    }

    private Algorithm detectAlgorithmFromTypeDir(String typeDirName) {
        String lowerName = typeDirName.toLowerCase();
        return switch (lowerName) {
            case "hmac-keys" -> Algorithm.HMAC256;
            case "rsa-keys" -> Algorithm.RSA256;
            case "ec-keys" -> Algorithm.ES256;
            case "eddsa-keys" -> Algorithm.Ed25519;
            default -> {
                log.warn("Unknown key type directory: {}, defaulting to HMAC256", typeDirName);
                yield Algorithm.HMAC256;
            }
        };
    }

    private LocalDateTime parseCreationTimeFromDirName(String keyId) {
        try {
            int idx = keyId.indexOf("-v");
            if (idx != -1 && keyId.length() >= idx + 16) {
                String timestamp = keyId.substring(idx + 2, idx + 16);
                return LocalDateTime.parse(timestamp, DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            }
        } catch (Exception e) {
            log.debug("Failed to parse creation time from keyId: {}", e.getMessage());
        }
        return LocalDateTime.now().minusDays(1);
    }

    @Override
    public LocalDateTime getDirTimestamp(Path dir) {
        Objects.requireNonNull(dir, "Directory cannot be null");

        LocalDateTime meta = readVersionCreatedTime(dir);
        if (meta != null) {
            return meta;
        }

        String dirName = dir.getFileName().toString();
        try {
            int start = dirName.indexOf("-v");
            if (start != -1 && dirName.length() >= start + 17) {
                String timestamp = dirName.substring(start + 2, start + 17);
                return LocalDateTime.parse(timestamp, DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            }
        } catch (Exception e) {
            log.debug("Failed to parse timestamp from directory name: {}", e.getMessage());
        }
        return LocalDateTime.MIN;
    }

    private LocalDateTime readVersionCreatedTime(Path dir) {
        if (keyRepository != null) {
            try {
                String keyId = dir.getFileName().toString();
                return keyRepository.loadMetadata(keyId, "version.json")
                        .map(this::parseCreatedTimeFromJson)
                        .orElse(null);
            } catch (IOException e) {
                log.debug("Failed to read version created time via repository: {}", e.getMessage());
            }
        }

        // Fallback
        try {
            Path meta = dir.resolve("version.json");
            if (!Files.exists(meta)) {
                return null;
            }
            String content = Files.readString(meta).trim();
            return parseCreatedTimeFromJson(content);
        } catch (Exception e) {
            log.debug("Failed to read version created time: {}", e.getMessage());
        }
        return null;
    }

    private LocalDateTime parseCreatedTimeFromJson(String content) {
        int idx = content.indexOf("\"createdTime\":\"");
        if (idx >= 0) {
            int start = idx + "\"createdTime\":\"".length();
            int end = content.indexOf("\"", start);
            if (end > start) {
                String iso = content.substring(start, end);
                return LocalDateTime.parse(iso);
            }
        }
        return null;
    }

    private void dispatchAlgorithmValidation(Algorithm algorithm) {
        if (algorithm.isHmac()) {
            validateHmacAlgorithm(algorithm);
        } else if (algorithm.isRsa()) {
            validateRsaAlgorithm(algorithm);
        } else if (algorithm.isEcdsa()) {
            validateEcdsaAlgorithm(algorithm);
        } else if (algorithm.isEddsa()) {
            validateEddsaAlgorithm(algorithm);
        }
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            log.debug("AbstractJwtAlgo resources cleaned up");
        }
    }
}
