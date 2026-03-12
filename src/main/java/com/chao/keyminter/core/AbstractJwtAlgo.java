package com.chao.keyminter.core;

import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.domain.service.JwtAlgo;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.JwtProperties;
import com.chao.keyminter.domain.model.KeyStatus;
import com.chao.keyminter.domain.model.KeyVersion;
import com.chao.keyminter.domain.port.out.KeyRepository;
import com.chao.keyminter.domain.port.out.KeyRepositoryFactory;
import com.chao.keyminter.adapter.out.fs.FileSystemKeyRepository;
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
 * JWT算法抽象基类
 * 提供密钥管理、版本控制、轮换等通用功能
 * 支持密钥过期检查、重叠期（transition period）
 */
@Getter
@Slf4j
public abstract class AbstractJwtAlgo implements JwtAlgo {

    // 使用更高效的ObjectMapper实例
    protected static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // 常量定义
    protected static final int DEFAULT_RSA_KEY_SIZE = 2048;
    protected static final int DEFAULT_HMAC_KEY_LENGTH = 64;
    protected static final int MIN_HMAC_KEY_LENGTH = 32;

    // 线程安全的数据结构
    protected final Map<String, Long> revokedFingerprints = new ConcurrentHashMap<>();
    protected final Map<String, KeyVersion> keyVersions = new ConcurrentHashMap<>();

    // 使用读写锁替代重入锁，提高并发性能
    protected final ReentrantReadWriteLock activeKeyLock = new ReentrantReadWriteLock();
    protected final ReentrantReadWriteLock.ReadLock readLock = activeKeyLock.readLock();
    protected final ReentrantReadWriteLock.WriteLock writeLock = activeKeyLock.writeLock();

    // 存储库工厂 (Hexagonal Port)
    protected KeyRepositoryFactory repositoryFactory;

    // 配置和状态
    protected final KeyMinterProperties keyMinterProperties;
    protected volatile String activeKeyId;
    protected volatile Path currentKeyPath;

    // 存储层抽象
    protected volatile KeyRepository keyRepository;

    protected volatile boolean keyRotationEnabled = false;
    protected volatile Instant defaultNewExpMs;

    // 过期密钥清理调度器 - 已移除，使用Spring @Scheduled
    // private final ScheduledExecutorService keyCleanupScheduler;
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
        // 检查活跃密钥是否可用于签名
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
     * 轮换密钥并设置过渡期
     *
     * @param algorithm             算法
     * @param newKeyIdentifier      新密钥ID
     * @param transitionPeriodHours 过渡期时长（小时）
     * @return 是否成功
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
     * 获取指定状态的密钥版本列表
     */
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

            // 检查密钥是否已过期
            if (newVersion.isExpired()) {
                log.error("Key {} has expired, cannot activate", keyId);
                return false;
            }

            // 检查密钥是否被撤销
            if (newVersion.getStatus() == KeyStatus.REVOKED) {
                log.error("Key {} has been revoked, cannot activate", keyId);
                return false;
            }

            // 停用旧密钥，设置过渡期
            if (activeKeyId != null) {
                KeyVersion oldActive = keyVersions.get(activeKeyId);
                if (oldActive != null) {
                    // 设置过渡期
                    Instant transitionEnd = Instant.now().plusMillis(
                            keyMinterProperties.getTransitionPeriodMillis()
                    );
                    oldActive.startTransition(transitionEnd);
                    log.debug("Old key {} entering transition period until {}", activeKeyId, transitionEnd);
                }
            }

            // 激活新密钥
            newVersion.activate();
            activeKeyId = keyId;
            // 加载密钥对
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
     * 检查活跃密钥是否可用于签名
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

            // 强制检查密钥是否已过期
            if (activeVersion.isExpired()) {
                throw new IllegalStateException("Active key has expired: " + activeKeyId);
            }

            // 检查密钥状态
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
        // 计算过期时间
        Instant expiresAt = calculateKeyExpiration();

        // 1. 如果已配置 Repository，优先使用 Repository 保存（但这通常是在 tempDir 阶段，
        //    实际上 KeyRotation 是负责将 tempDir 移动到 targetDir。
        //    目前的架构是：生成 -> 存入临时目录 -> 移动到正式目录。
        //    如果要完全去文件化，KeyRotation 也需要重构。
        //    暂时保持写入 tempDir，因为 FileSystemKeyRepository 本质上也是文件操作。
        //    为了保持一致性，我们在这里仍然使用 Files 操作，因为 tempDir 是一个临时的 Path。

        Path privateKeyPath = tempDir.resolve(PRIVATE_KEY_FILE);
        Files.write(privateKeyPath, keyPair.getPrivate().getEncoded(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        Path publicKeyPath = tempDir.resolve(PUBLIC_KEY_FILE);
        Files.write(publicKeyPath, keyPair.getPublic().getEncoded(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        Path algorithmFile = tempDir.resolve(ALGORITHM_FILE);
        Files.writeString(algorithmFile, algorithm.name());

        Path expirationFile = tempDir.resolve(EXPIRATION_FILE);
        Files.writeString(expirationFile, expiresAt.toString());

        // 保存初始状态
        Path statusFile = tempDir.resolve(STATUS_FILE);
        Files.writeString(statusFile, KeyStatus.CREATED.name());

        // 权限设置 (现在应该委托给 PermissionStrategy，但在 AbstractJwtAlgo 中没有直接引用，
        // 实际上 KeyRotation 会在移动后处理权限。这里设置是为了临时安全性)
        // setRestrictiveFilePermissions(privateKeyPath); // 这一步在 KeyRotation 中会有处理，或者保留作为双重保障
        // 由于 setRestrictiveFilePermissions 是 protected 的，我们可以保留它，但改用 Repository 里的逻辑？
        // 不，PermissionStrategy 是 KeyRotation 使用的。
        // 这里的 setRestrictiveFilePermissions 是 AbstractJwtAlgo 的旧方法。
        // 我们应该让它失效或代理。

        return expiresAt;
    }

    protected boolean canKeyNotVerify(String keyId) {
        return !canKeyVerify(keyId);
    }

    /**
     * 验证密钥是否可用于验证（包括检查过期和过渡期）
     * 增加实时状态检查逻辑
     */
    protected boolean canKeyVerify(String keyId) {
        if (StringUtils.isBlank(keyId)) return false;
        readLock.lock();
        try {
            KeyVersion version = keyVersions.get(keyId);
            if (version == null) return false;

            // 实时检查：如果处于过渡期且已超时，自动降级为INACTIVE
            if (version.getStatus() == KeyStatus.TRANSITIONING &&
                    version.getTransitionEndsAt() != null &&
                    Instant.now().isAfter(version.getTransitionEndsAt())) {

                // 升级为写锁进行状态变更
                readLock.unlock();
                writeLock.lock();
                try {
                    // 双重检查
                    if (version.getStatus() == KeyStatus.TRANSITIONING &&
                            Instant.now().isAfter(version.getTransitionEndsAt())) {
                        version.deactivate();
                        log.info("Key {} transition period ended (lazy check), deactivated", keyId);
                    }
                } finally {
                    writeLock.unlock();
                    readLock.lock(); // 降级回读锁继续后续检查
                }
            }

            return version.canVerify();
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
     * 获取活跃密钥版本信息
     */
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
     * 生成密钥版本ID
     */
    public String generateKeyVersionId(Algorithm algorithm) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        return algorithm.name() + "-v" +
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + "-"
                + UUID.randomUUID().toString().substring(0, 8);
    }

    /**
     * 计算密钥过期时间
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
     * 验证目录路径安全性
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
     * 清理过期密钥
     */
    public void cleanupExpiredKeys() {
        writeLock.lock();
        try {
            Instant now = Instant.now();
            int expiredCount = 0;
            int transitionedCount = 0;

            for (KeyVersion version : keyVersions.values()) {
                // 检查是否已过期
                if (version.getExpiresAt() != null && now.isAfter(version.getExpiresAt())) {
                    if (version.getStatus() != KeyStatus.EXPIRED) {
                        version.markExpired();
                        updateKeyStatusFile(version.getKeyId(), KeyStatus.EXPIRED);
                        expiredCount++;
                        log.info("Key {} marked as expired", version.getKeyId());
                    }
                }

                // 检查过渡期是否结束
                if (version.getStatus() == KeyStatus.TRANSITIONING &&
                        version.getTransitionEndsAt() != null &&
                        now.isAfter(version.getTransitionEndsAt())) {
                    version.deactivate();
                    updateKeyStatusFile(version.getKeyId(), KeyStatus.INACTIVE);
                    transitionedCount++;
                    log.info("Key {} transition period ended, deactivated", version.getKeyId());
                }
            }

            // 如果活跃密钥已过期，尝试切换到下一个可用密钥
            if (activeKeyId != null) {
                KeyVersion activeVersion = keyVersions.get(activeKeyId);
                if (activeVersion != null && activeVersion.isExpired()) {
                    // 寻找下一个可用密钥
                    for (KeyVersion version : keyVersions.values()) {
                        if (version.getStatus() == KeyStatus.CREATED && !version.isExpired()) {
                            setActiveKey(version.getKeyId());
                            log.info("Auto-switched to new key: {}", version.getKeyId());
                            break;
                        }
                    }
                }
            }

            // 2. 清理物理文件（仅当过期时间超过安全保留期）
            // 默认保留期：30天（可配置）
            long retentionMillis = keyMinterProperties.getExpiredKeyRetentionMillis();
            if (retentionMillis > 0) {
                Iterator<Map.Entry<String, KeyVersion>> it = keyVersions.entrySet().iterator();
                while (it.hasNext()) {
                    Map.Entry<String, KeyVersion> entry = it.next();
                    KeyVersion version = entry.getValue();

                    if (version.getStatus() == KeyStatus.EXPIRED || version.getStatus() == KeyStatus.REVOKED) {
                        Instant cleanupThreshold = now.minusMillis(retentionMillis);
                        // 如果过期时间早于清理阈值，则物理删除
                        if (version.getExpiresAt() != null && version.getExpiresAt().isBefore(cleanupThreshold)) {
                            try {
                                deleteKeyDirectory(version);
                                it.remove(); // 从内存中移除
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
            // 使用 KeyRepository 更新元数据
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

        Predicate<Path> filter = directoriesContainingTag(tag);
        if (extraFilter != null) {
            filter = filter.and(extraFilter);
        }

        try (Stream<Path> dirs = Files.list(currentKeyPath)) {
            return dirs.filter(filter)
                    .max(Comparator.comparing(this::getDirTimestamp));
        } catch (IOException e) {
            log.error("Failed to scan directory {}: {}", currentKeyPath, e.getMessage());
            return Optional.empty();
        }
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
     * 创建JWT Builder，自动添加kid到header
     */
    protected JwtBuilder createJwtBuilder(JwtProperties properties, Map<String, Object> customClaims) {
        long now = System.currentTimeMillis();

        // 获取当前活跃密钥ID
        String kid = getActiveKeyId();

        JwtBuilder builder = Jwts.builder()
                .subject(properties.getSubject())
                .issuer(properties.getIssuer())
                .issuedAt(new Date(now))
                .expiration(toDate(properties.getExpiration()));

        // 自动添加kid到header
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

        // 读取状态
        KeyStatus status = readKeyStatus(versionDir);

        // 读取过期时间
        Instant expiresAt = readKeyExpiration(versionDir);

        // 读取过渡期结束时间
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

            // 使用 KeyRepository 更新
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
        // 尝试加载指定密钥
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
                                .forEach(java.io.File::delete);
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
        // 初始化存储库
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
            // 检查内存中是否已有
            if (keyVersions.containsKey(preferredKeyId)) {
                KeyVersion version = keyVersions.get(preferredKeyId);
                // 检查密钥是否已过期
                if (version.isExpired()) {
                    log.warn("Preferred key {} has expired", preferredKeyId);
                    return this;
                }
                setActiveKey(preferredKeyId);
                return this;
            }

            // 尝试从磁盘加载
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

    protected void setRestrictiveFilePermissions(Path path) {
        // Deprecated: This logic is now handled by KeyRotation and PermissionStrategy
        // Keeping empty implementation for backward compatibility if subclasses override it
    }

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
        // 根据目录名推测
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
