package com.chao.keyminter.core;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import com.chao.keyminter.adapter.in.KeyMinterConfigHolder;
import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.domain.service.JwtAlgo;
import com.chao.keyminter.internal.SecureByteArray;
import com.chao.keyminter.domain.model.*;
import com.chao.keyminter.domain.port.out.KeyRepository;
import com.chao.keyminter.domain.port.out.SecretDirProvider;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * HMAC JWT 实现类
 * 支持 HS256, HS384, HS512 算法
 */
@Getter
@Slf4j
public class HmacJwt extends AbstractJwtAlgo {

    private static final String KEY_VERSION_PREFIX = "hmac-v";
    private static final String SECRET_FILE_NAME = "secret.key";
    private static final String ALGORITHM_FILE_NAME = "algorithm.info";
    private static final String STATUS_FILE_NAME = "status.info";
    private static final String EXPIRATION_FILE_NAME = "expiration.info";
    private static final String TRANSITION_FILE_NAME = "transition.info";

    private final Map<String, SecureByteArray> versionSecrets = new ConcurrentHashMap<>();
    private volatile SecureByteArray currentSecret;

    private static Path getDefaultHmacDir() {
        return SecretDirProvider.getDefaultBaseDir().resolve("hmac-keys");
    }

    public HmacJwt() {
        this(getDefaultHmacDir());
    }

    public HmacJwt(Path secretDir) {
        this(KeyMinterConfigHolder.get(), secretDir);
    }

    public HmacJwt(KeyMinterProperties properties, Path secretDir) {
        super(properties);
        this.currentKeyPath = initializeKeyPath(secretDir);

        if (isKeyRotationEnabled()) {
            enableKeyRotation();
        }

        initializeKeyVersions();

        if (activeKeyId == null) {
            log.warn("No keys found in directory: {}", this.currentKeyPath);
        }
    }

    public HmacJwt(KeyMinterProperties properties, KeyRepository repository) {
        super(properties);
        this.keyRepository = repository;
        if (isKeyRotationEnabled()) {
            enableKeyRotation();
        }
        initializeKeyVersions();
        if (activeKeyId == null) {
            log.info("No keys found in repository");
        }
    }

    private Path initializeKeyPath(Path secretDir) {
        if (secretDir == null) {
            return getDefaultHmacDir();
        }

        Path normalized = secretDir.normalize();
        validateDirectoryPath(normalized);

        // 确保使用正确的子目录
        if (!"hmac-keys".equals(normalized.getFileName().toString())) {
            normalized = normalized.resolve("hmac-keys");
        }
        return normalized;
    }

    @Override
    public boolean generateKeyPair(Algorithm algorithm) {
        return generateHmacKey(algorithm, null);
    }

    @Override
    public boolean generateHmacKey(Algorithm algorithm, Integer length) {
        validateHmacAlgorithm(algorithm);
        String newKeyId = generateKeyVersionId(algorithm);
        return rotateHmacKey(algorithm, newKeyId, length);
    }

    @Override
    public boolean rotateHmacKey(Algorithm algorithm, String newKeyIdentifier, Integer length) {
        // 使用默认过渡期
        int transitionHours = keyMinterProperties != null ? keyMinterProperties.getTransitionPeriodHours() : 24;
        return rotateHmacKeyWithTransition(algorithm, newKeyIdentifier, length, transitionHours);
    }

    /**
     * 轮换HMAC密钥并设置过渡期
     */
    public boolean rotateHmacKeyWithTransition(Algorithm algorithm, String newKeyIdentifier, Integer length, int transitionPeriodHours) {
        validateHmacAlgorithm(algorithm);
        if (!isKeyRotationEnabled()) {
            log.error("Key rotation is not enabled");
            return false;
        }
        
        // 如果配置了 Repository，优先使用 Repository 逻辑
        if (keyRepository != null) {
            try {
                // 1. Generate new secret
                int keyLength = length == null ? getKeyLengthForAlgorithm(algorithm) : length;
                keyLength = Math.max(keyLength, MIN_HMAC_KEY_LENGTH);
                SecureByteArray secret = generateSecureSecret(keyLength);

                // 2. Prepare files for persistence
                Map<String, byte[]> files = new HashMap<>();
                
                // secret.key
                secret.useBytes(bytes -> {
                    byte[] copy = new byte[bytes.length];
                    System.arraycopy(bytes, 0, copy, 0, bytes.length);
                    files.put(SECRET_FILE_NAME, copy);
                    return null;
                });
                
                // algorithm.info
                files.put(ALGORITHM_FILE_NAME, algorithm.name().getBytes(StandardCharsets.UTF_8));
                
                // expiration.info
                Instant expiresAt = calculateKeyExpiration();
                files.put(EXPIRATION_FILE_NAME, expiresAt.toString().getBytes(StandardCharsets.UTF_8));
                
                // status.info
                files.put(STATUS_FILE_NAME, KeyStatus.CREATED.name().getBytes(StandardCharsets.UTF_8));

                // 3. Save via repository
                KeyVersionData data = KeyVersionData.builder()
                        .keyId(newKeyIdentifier)
                        .algorithm(algorithm)
                        .files(files)
                        .build();
                
                keyRepository.saveKeyVersion(data);

                // 4. Update in-memory state
                updateKeyVersionWithTransition(newKeyIdentifier, algorithm, secret, transitionPeriodHours);
                
                log.info("Rotated HMAC key via repository: {}", newKeyIdentifier);
                return true;
            } catch (IOException e) {
                log.error("Key rotation failed via repository", e);
                return false;
            }
        }

        try {
            return KeyRotation.rotateKeyAtomic(
                    newKeyIdentifier, currentKeyPath, () -> {
                        int keyLength = length == null ? getKeyLengthForAlgorithm(algorithm) : length;
                        keyLength = Math.max(keyLength, MIN_HMAC_KEY_LENGTH);
                        return generateSecureSecret(keyLength);
                    },
                    (secret, tempDir) -> saveSecretToDirectory(secret, tempDir, algorithm, newKeyIdentifier),
                    (secret) -> updateKeyVersionWithTransition(newKeyIdentifier, algorithm, secret, transitionPeriodHours)
            );
        } catch (IOException e) {
            log.error("Key rotation with transition failed for {}: {}", newKeyIdentifier, e.getMessage(), e);
            throw new UncheckedIOException("Key rotation failed", e);
        }
    }

    private void saveSecretToDirectory(SecureByteArray secret, Path tempDir, Algorithm algorithm, String keyId) throws IOException {
        // 保存密钥文件
        Path secretFile = tempDir.resolve(SECRET_FILE_NAME);
        secret.useBytes(bytes -> {
            try {
                Files.write(secretFile, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                setRestrictiveFilePermissions(secretFile);
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to write secret file", e);
            }
            return null;
        });

        // 保存算法信息
        Path algorithmFile = tempDir.resolve(ALGORITHM_FILE_NAME);
        Files.writeString(algorithmFile, algorithm.name());

        // 保存密钥过期时间
        Instant expiresAt = calculateKeyExpiration();
        Path expirationFile = tempDir.resolve(EXPIRATION_FILE_NAME);
        Files.writeString(expirationFile, expiresAt.toString());

        // 保存初始状态
        Path statusFile = tempDir.resolve(STATUS_FILE_NAME);
        Files.writeString(statusFile, KeyStatus.CREATED.name());
        log.debug("Saved HMAC key {} with expiration: {}", keyId, expiresAt);
    }

    private void updateKeyVersionWithTransition(String keyId, Algorithm algorithm, SecureByteArray secret, int transitionPeriodHours) {
        writeLock.lock();
        try {
            // 创建新版本 (状态默认为 CREATED)
            String keyPath = currentKeyPath != null ? currentKeyPath.resolve(keyId).toString() : "repo:" + keyId;
            KeyVersion newVersion = new KeyVersion(keyId, algorithm, keyPath);
            newVersion.setCreatedTime(LocalDateTime.now());
            newVersion.setExpiresAt(calculateKeyExpiration());
            // 注意：不自动激活，保持 CREATED 状态
            // newVersion.activate(); 

            versionSecrets.put(keyId, secret);
            keyVersions.put(keyId, newVersion);

            // 注意：不更新当前活跃密钥，需要手动调用 setActiveKey 激活
            /*
            if (this.currentSecret != null && !this.currentSecret.equals(secret)) {
                this.currentSecret.wipe();
            }
            this.currentSecret = secret;
            this.activeKeyId = keyId;
            */

            log.info("HMAC key created (pending activation). Key ID: {}, algorithm: {}", keyId, algorithm);
        } catch (Exception e) {
            log.error("Failed to update key version: {}", e.getMessage(), e);
            throw new RuntimeException("Key version update failed", e);
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public HmacJwt autoLoadFirstKey(Algorithm algorithm, String preferredKeyId, boolean force) {
        JwtAlgo loaded = autoLoadKey(preferredKeyId);
        if (loaded != null) {
            return (HmacJwt) loaded;
        }

        String tag = (algorithm == null) ? null : algorithm.name().toUpperCase();
        if (!force && !hasKeyFilesInDirectory(tag)) {
            log.warn("No {} HMAC key directory found under {}", tag == null ? "" : " " + tag, currentKeyPath);

            writeLock.lock();
            try {
                this.activeKeyId = null;
                this.currentSecret = null;
            } finally {
                writeLock.unlock();
            }
            return this;
        }

        loadFirstKeyFromDirectory(force ? null : tag);
        return this;
    }

    @Override
    public void loadExistingKeyVersions() {
        if (keyRepository != null) {
            try {
                // List keys from repository
                List<String> keys = keyRepository.listKeys(null);
                for (String keyId : keys) {
                    loadKeyVersionFromRepo(keyId);
                }
            } catch (IOException e) {
                log.error("Failed to load keys from repository", e);
            }
            return;
        }

        if (currentKeyPath == null || !Files.exists(currentKeyPath) || !Files.isDirectory(currentKeyPath)) {
            return;
        }

        try (Stream<Path> paths = Files.list(currentKeyPath)) {
            paths.filter(Files::isDirectory)
                    .filter(this::isKeyVersionDir)
                    .forEach(this::loadKeyVersion);

            if (versionSecrets.isEmpty()) {
                loadLegacyKeys();
            }
        } catch (IOException e) {
            log.error("Failed to load existing key versions: {}", e.getMessage());
        }
    }

    private void loadKeyVersionFromRepo(String keyId) {
        writeLock.lock();
        try {
            // Read metadata
            KeyStatus status = keyRepository.loadMetadata(keyId, STATUS_FILE_NAME)
                    .map(KeyStatus::valueOf).orElse(KeyStatus.CREATED);
            
            Instant expiresAt = keyRepository.loadMetadata(keyId, EXPIRATION_FILE_NAME)
                    .map(Instant::parse).orElse(null);

            // Skip if expired
            if (expiresAt != null && Instant.now().isAfter(expiresAt)) {
                return;
            }

            // Read secret
            Optional<byte[]> secretBytes = keyRepository.loadKey(keyId, SECRET_FILE_NAME);
            if (secretBytes.isEmpty()) {
                log.warn("Secret not found for key {}", keyId);
                return;
            }

            SecureByteArray secret = SecureByteArray.fromBytes(secretBytes.get());
            // Clear raw bytes
            Arrays.fill(secretBytes.get(), (byte) 0);

            // Read Algorithm
            Algorithm algorithm = keyRepository.loadMetadata(keyId, ALGORITHM_FILE_NAME)
                    .map(Algorithm::valueOf).orElse(Algorithm.HMAC256);

            // Create Version
            KeyVersion version = new KeyVersion(keyId, algorithm, "repo:" + keyId);
            version.setStatus(status);
            version.setExpiresAt(expiresAt);
            
            if (status == KeyStatus.ACTIVE) {
                version.setActivatedTime(LocalDateTime.now());
                if (this.currentSecret != null && !this.currentSecret.equals(secret)) {
                    this.currentSecret.wipe();
                }
                this.currentSecret = secret;
                this.activeKeyId = keyId;
            }

            versionSecrets.put(keyId, secret);
            keyVersions.put(keyId, version);
            log.debug("Loaded HMAC key {} from repo", keyId);
        } catch (Exception e) {
            log.warn("Failed to load key {} from repo", keyId, e);
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    protected boolean isKeyVersionDir(Path dir) {
        if (dir == null) {
            return false;
        }
        String name = dir.getFileName().toString().toLowerCase();
        boolean hasSecret = Files.exists(dir.resolve(SECRET_FILE_NAME));
        boolean hasAlg = Files.exists(dir.resolve(ALGORITHM_FILE_NAME));
        boolean likeHmac = name.contains("hmac") && name.contains("-v");
        return hasSecret || hasAlg || likeHmac;
    }

    @Override
    protected void loadKeyVersion(Path versionDir) {
        if (versionDir == null) return;
        writeLock.lock();
        try {
            String keyId = versionDir.getFileName().toString();
            // 读取状态
            KeyStatus status = readKeyStatusFromDir(versionDir);
            boolean isActive = status == KeyStatus.ACTIVE;
            // 读取过期时间
            Instant expiresAt = readExpirationFromDir(versionDir);
            // 读取过渡期结束时间
            Instant transitionEndsAt = readTransitionEndFromDir(versionDir);
            // 如果密钥已过期，跳过加载
            if (expiresAt != null && Instant.now().isAfter(expiresAt)) {
                log.warn("Skipping expired key: {}, expired at: {}", keyId, expiresAt);
                return;
            }
            // 使用安全方式加载密钥
            SecureByteArray secret = loadSecureSecretFromDir(versionDir);
            if (secret == null || secret.length() == 0) {
                log.warn("Empty or invalid secret in directory: {}", versionDir);
                return;
            }
            versionSecrets.put(keyId, secret);
            Algorithm algorithm = getAlgorithmFromDir(versionDir);
            KeyVersion version = new KeyVersion(keyId, algorithm, versionDir.toString());
            version.setStatus(status);
            version.setCreatedTime(getCreationTimeFromDir(versionDir));
            version.setExpiresAt(expiresAt);
            version.setTransitionEndsAt(transitionEndsAt);

            if (isActive) {
                version.setActivatedTime(LocalDateTime.now());
                // 清理旧的当前密钥
                if (this.currentSecret != null && !this.currentSecret.equals(secret)) {
                    this.currentSecret.wipe();
                }
                this.currentSecret = secret;
                this.activeKeyId = keyId;
            }

            keyVersions.put(keyId, version);
            log.debug("Loaded HMAC key version: {}, status: {}, algorithm: {}, expires: {}", keyId, status, algorithm, expiresAt);
        } catch (Exception e) {
            log.warn("Failed to load key version from {}: {}", versionDir, e.getMessage());
        } finally {
            writeLock.unlock();
        }
    }

    private KeyStatus readKeyStatusFromDir(Path versionDir) {
        Path statusFile = versionDir.resolve(STATUS_FILE_NAME);
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

    private Instant readExpirationFromDir(Path versionDir) {
        Path expFile = versionDir.resolve(EXPIRATION_FILE_NAME);
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

    private Instant readTransitionEndFromDir(Path versionDir) {
        Path transitionFile = versionDir.resolve(TRANSITION_FILE_NAME);
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
    protected void loadKeyPair(String keyId) {
        writeLock.lock();
        try {
            SecureByteArray secret = versionSecrets.get(keyId);
            if (secret == null || secret.isWiped()) {
                Path versionDir = currentKeyPath.resolve(keyId);
                secret = loadSecureSecretFromDir(versionDir);
                if (secret == null || secret.length() == 0) {
                    throw new IllegalArgumentException("Secret not found for version: " + keyId);
                }
                versionSecrets.put(keyId, secret);
            }

            if (this.currentSecret != null && !this.currentSecret.equals(secret) && !this.currentSecret.isWiped()) {
                this.currentSecret.wipe();
            }
            this.currentSecret = secret;
            this.activeKeyId = keyId;
            markKeyActive(keyId);
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public boolean verifyWithKeyVersion(String keyId, String token) {
        if (StringUtils.isBlank(keyId) || StringUtils.isBlank(token)) {
            return false;
        }

        // 先进行通用的状态检查（包含实时惰性更新）
        if (canKeyNotVerify(keyId)) {
            return false;
        }

        readLock.lock();
        try {
            SecureByteArray secret = versionSecrets.get(keyId);
            if (secret == null || secret.isWiped()) {
                secret = loadSecureSecretFromDir(currentKeyPath.resolve(keyId));
                if (secret != null && secret.length() > 0) {
                    versionSecrets.put(keyId, secret);
                }
            }

            if (secret == null || secret.isWiped()) {
                return false;
            }

            return Boolean.TRUE.equals(secret.useBytes(bytes -> {
                try {
                    SecretKey key = Keys.hmacShaKeyFor(bytes);
                    Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
                    return true;
                } catch (Exception e) {
                    log.debug("Token verification failed with key {}: {}", keyId, e.getMessage());
                    return false;
                }
            }));
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public Object getCurrentKey() {
        readLock.lock();
        try {
            return currentSecret;
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public Object getKeyByVersion(String keyId) {
        readLock.lock();
        try {
            return versionSecrets.get(keyId);
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
        validateHmacAlgorithm(algorithm);

        readLock.lock();
        try {
            if (currentSecret == null || currentSecret.isWiped()) {
                throw new IllegalStateException("No active HMAC key. Call setActiveKey or rotateKey first.");
            }

            return currentSecret.useBytes(bytes -> {
                SecretKey key = Keys.hmacShaKeyFor(bytes);
                JwtBuilder builder = createJwtBuilder(properties, customClaims);
                return builder.signWith(key, getSignAlgorithm(algorithm)).compact();
            });
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public boolean verifyToken(String token) {
        if (StringUtils.isBlank(token)) {
            return false;
        }

        readLock.lock();
        try {
            if (currentSecret == null || currentSecret.isWiped()) {
                log.debug("Cannot verify token - no active HMAC key");
                return false;
            }

            return Boolean.TRUE.equals(currentSecret.useBytes(bytes -> {
                try {
                    SecretKey key = Keys.hmacShaKeyFor(bytes);
                    Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
                    return true;
                } catch (JwtException | IllegalArgumentException e) {
                    log.debug("Token verification failed: {}", e.getMessage());
                    return false;
                }
            }));
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public Claims decodePayload(String token) {
        if (StringUtils.isBlank(token)) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }

        readLock.lock();
        try {
            if (currentSecret == null || currentSecret.isWiped()) {
                throw new SecurityException("HMAC JWT validation failed - no active key");
            }

            return currentSecret.useBytes(bytes -> {
                try {
                    SecretKey key = Keys.hmacShaKeyFor(bytes);
                    return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
                } catch (JwtException e) {
                    throw new SecurityException("HMAC JWT validation failed", e);
                }
            });
        } finally {
            readLock.unlock();
        }
    }

    @Override
    protected MacAlgorithm getSignAlgorithm(Algorithm algorithm) {
        validateHmacAlgorithm(algorithm);
        return switch (algorithm) {
            case HMAC256 -> Jwts.SIG.HS256;
            case HMAC384 -> Jwts.SIG.HS384;
            case HMAC512 -> Jwts.SIG.HS512;
            default -> throw new IllegalStateException("Unsupported HMAC algorithm: " + algorithm);
        };
    }

    @Override
    public String getKeyInfo() {
        readLock.lock();
        try {
            return String.format("HMAC Keys - Active: %s, Total versions: %d, Key rotation: %s",
                    activeKeyId != null ? activeKeyId : "None",
                    versionSecrets.size(),
                    keyRotationEnabled ? "enabled" : "disabled");
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public boolean generateAllKeyPairs() {
        boolean allSuccess = true;
        for (Algorithm algorithm : Algorithm.getHmacAlgorithms()) {
            String keyId = generateKeyVersionId(algorithm);
            boolean success = rotateHmacKey(algorithm, keyId, null);
            if (!success) {
                allSuccess = false;
                log.warn("Failed to generate HMAC key for: {}", algorithm);
            }
        }
        return allSuccess;
    }

    @Override
    public String getAlgorithmInfo() {
        return "HMAC algorithms: HS256, HS384, HS512 with key rotation support";
    }

    @Override
    public void close() {
        cleanupSecrets();
    }

    protected void cleanupSecrets() {
        writeLock.lock();
        try {
            // 清理所有版本密钥
            versionSecrets.values().forEach(SecureByteArray::wipe);
            versionSecrets.clear();

            // 清理当前密钥
            if (currentSecret != null) {
                currentSecret.wipe();
                currentSecret = null;
            }

            // 清理父类资源
            keyVersions.clear();
            activeKeyId = null;

            log.debug("HmacJwt resources cleaned up");
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    protected boolean hasKeyFilesInDirectory(String tag) {
        return findKeyDir(tag, null).isPresent();
    }

    @Override
    protected void loadFirstKeyFromDirectory(String tag) {
        findKeyDir(tag, null).ifPresentOrElse(
                dir -> setActiveKey(dir.getFileName().toString()),
                () -> log.error("No{} key directory found under {}",
                        tag == null ? "" : " " + tag, currentKeyPath)
        );
    }

    private int getKeyLengthForAlgorithm(Algorithm algorithm) {
        return switch (algorithm) {
            case HMAC256 -> 64;
            case HMAC384 -> 96;
            case HMAC512 -> 128;
            default -> DEFAULT_HMAC_KEY_LENGTH;
        };
    }

    /**
     * 原子性生成安全密钥
     */
    private SecureByteArray generateSecureSecret(int length) {
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[length];
        random.nextBytes(randomBytes);

        SecureByteArray secret = SecureByteArray.fromBytes(randomBytes);
        Arrays.fill(randomBytes, (byte) 0);
        return secret;
    }

    /**
     * 安全地从目录加载密钥
     */
    private SecureByteArray loadSecureSecretFromDir(Path versionDir) {
        if (versionDir == null) {
            return null;
        }

        Path secretFile = versionDir.resolve(SECRET_FILE_NAME);
        if (!Files.exists(secretFile)) {
            return null;
        }

        byte[] fileBytes = null;
        try {
            fileBytes = Files.readAllBytes(secretFile);
            return SecureByteArray.fromBytes(fileBytes);
        } catch (IOException e) {
            log.warn("Failed to load secret from {}: {}", secretFile, e.getMessage());
            return null;
        } finally {
            if (fileBytes != null) {
                Arrays.fill(fileBytes, (byte) 0);
            }
        }
    }

    private Algorithm getAlgorithmFromDir(Path versionDir) {
        Path algorithmFile = versionDir.resolve(ALGORITHM_FILE_NAME);
        if (Files.exists(algorithmFile)) {
            try {
                String algorithmStr = Files.readString(algorithmFile, StandardCharsets.UTF_8).trim();
                return Algorithm.valueOf(algorithmStr);
            } catch (Exception e) {
                log.debug("Failed to read algorithm from {}: {}", algorithmFile, e.getMessage());
            }
        }
        return Algorithm.HMAC256;
    }

    private void loadLegacyKeys() {
        if (currentKeyPath == null || !Files.exists(currentKeyPath)) {
            return;
        }

        try (Stream<Path> paths = Files.list(currentKeyPath)) {
            paths.filter(Files::isRegularFile)
                    .filter(file -> file.getFileName().toString().endsWith(".key"))
                    .filter(file -> !file.getFileName().toString().startsWith("."))
                    .forEach(this::migrateLegacyKey);
        } catch (IOException e) {
            log.debug("No legacy keys found or failed to scan: {}", e.getMessage());
        }
    }

    private void migrateLegacyKey(Path legacyPath) {
        byte[] fileBytes = null;
        try {
            fileBytes = Files.readAllBytes(legacyPath);
            if (fileBytes.length == 0) {
                return;
            }

            SecureByteArray secret = SecureByteArray.fromBytes(fileBytes);
            if (secret.length() == 0) {
                secret.wipe();
                return;
            }

            String keyId = KEY_VERSION_PREFIX + LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + "-"
                    + UUID.randomUUID().toString().substring(0, 12) + "-legacy";

            migrateToVersioned(keyId, secret);
        } catch (Exception e) {
            log.warn("Failed to migrate legacy key {}: {}", legacyPath, e.getMessage());
        } finally {
            if (fileBytes != null) {
                Arrays.fill(fileBytes, (byte) 0);
            }
        }
    }

    private void migrateToVersioned(String keyId, SecureByteArray secret) throws IOException {
        Path versionDir = currentKeyPath.resolve(keyId);
        Files.createDirectories(versionDir);

        // 安全地写入密钥文件
        writeSecretToFileAtomically(versionDir.resolve(SECRET_FILE_NAME), secret);

        // 写入算法信息
        Path algorithmFile = versionDir.resolve(ALGORITHM_FILE_NAME);
        Files.writeString(algorithmFile, Algorithm.HMAC256.name(),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);

        // 写入过期时间
        Instant expiresAt = calculateKeyExpiration();
        Path expirationFile = versionDir.resolve(EXPIRATION_FILE_NAME);
        Files.writeString(expirationFile, expiresAt.toString());

        // 写入状态
        Path statusFile = versionDir.resolve(STATUS_FILE_NAME);
        Files.writeString(statusFile, KeyStatus.ACTIVE.name());

        // 更新内存映射
        versionSecrets.put(keyId, secret);

        KeyVersion version = new KeyVersion(keyId, Algorithm.HMAC256, versionDir.toString());
        version.setStatus(KeyStatus.ACTIVE);
        version.setCreatedTime(LocalDateTime.now());
        version.setActivatedTime(LocalDateTime.now());
        version.setExpiresAt(expiresAt);

        keyVersions.put(keyId, version);
        this.activeKeyId = keyId;
        this.currentSecret = secret;

        log.info("Migrated legacy HMAC key to versioned format: {}, expires: {}", keyId, expiresAt);
    }

    /**
     * 原子性写入密钥文件
     */
    private void writeSecretToFileAtomically(Path targetFile, SecureByteArray secret) throws IOException {
        Path tempFile = targetFile.getParent().resolve(targetFile.getFileName() + ".tmp");

        try {
            secret.useBytes(bytes -> {
                try {
                    Files.write(tempFile, bytes,
                            StandardOpenOption.CREATE,
                            StandardOpenOption.TRUNCATE_EXISTING,
                            StandardOpenOption.WRITE);
                } catch (IOException e) {
                    throw new UncheckedIOException("Failed to write temp file", e);
                }
                return null;
            });

            Files.move(tempFile, targetFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            setRestrictiveFilePermissions(targetFile);
        } finally {
            try {
                Files.deleteIfExists(tempFile);
            } catch (IOException e) {
                log.debug("Failed to delete temp file {}: {}", tempFile, e.getMessage());
            }
        }
    }
}
