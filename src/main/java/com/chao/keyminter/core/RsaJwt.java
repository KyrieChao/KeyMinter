package com.chao.keyminter.core;

import com.chao.keyminter.adapter.in.KeyMinterConfigHolder;
import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.domain.model.*;
import com.chao.keyminter.domain.port.out.KeyRepository;
import com.chao.keyminter.domain.port.out.SecretDirProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithm;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * RSA JWT 实现类
 * 支持 RS256, RS384, RS512 算法
 */
@Slf4j
@Getter
public class RsaJwt extends AbstractJwtAlgo {

    private static final String PRIVATE_KEY_FILE = "private.key";
    private static final String PUBLIC_KEY_FILE = "public.key";
    private static final String ALGORITHM_FILE = "algorithm.info";
    private static final String STATUS_FILE = "status.info";
    private static final String EXPIRATION_FILE = "expiration.info";
    private static final String TRANSITION_FILE = "transition.info";

    private final Map<String, KeyPair> versionKeyPairs = new ConcurrentHashMap<>();
    private volatile KeyPair keyPair;

    private static Path getDefaultRsaDir() {
        return SecretDirProvider.getDefaultBaseDir().resolve("rsa-keys");
    }

    public RsaJwt() {
        this(getDefaultRsaDir());
    }

    public RsaJwt(Path path) {
        this(KeyMinterConfigHolder.get(), path);
    }

    public RsaJwt(KeyMinterProperties properties, Path directory) {
        super(properties);
        this.currentKeyPath = initializeKeyPath(directory);

        if (this.currentKeyPath != null) {
            this.keyRepository = new com.chao.keyminter.adapter.out.fs.FileSystemKeyRepository(this.currentKeyPath);
        }

        if (isKeyRotationEnabled()) {
            enableKeyRotation();
        }

        initializeKeyVersions();

        if (activeKeyId == null) {
            log.warn("No keys found in directory: {}", this.currentKeyPath);
        }
    }

    public RsaJwt(KeyMinterProperties properties, KeyRepository repository) {
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

    private Path initializeKeyPath(Path directory) {
        if (directory == null) {
            return getDefaultRsaDir();
        }

        Path normalized = directory.normalize();
        validateDirectoryPath(normalized);

        if (!"rsa-keys".equals(normalized.getFileName().toString())) {
            normalized = normalized.resolve("rsa-keys");
        }
        return normalized;
    }

    @Override
    protected boolean hasKeyFilesInDirectory(String tag) {
        // Relaxed filter: just check if directory exists. Let loadKeyPair handle missing files.
        return true;
    }

    @Override
    protected Optional<Path> findKeyDir(String tag, java.util.function.Predicate<Path> extraFilter) {
        // Override to provide a default filter if none provided, or ignore extraFilter if problematic
        return super.findKeyDir(tag, path -> true);
    }

    @Override
    protected void loadFirstKeyFromDirectory(String tag) {
        findKeyDir(tag, dir ->
                Files.exists(dir.resolve(PRIVATE_KEY_FILE)) &&
                        Files.exists(dir.resolve(PUBLIC_KEY_FILE))
        ).ifPresentOrElse(
                dir -> setActiveKey(dir.getFileName().toString()),
                () -> log.error("No{} key directory found under {}",
                        tag == null ? "" : " " + tag, currentKeyPath)
        );
    }

    @Override
    public void loadExistingKeyVersions() {
        if (keyRepository != null) {
            try {
                List<String> keys = keyRepository.listKeys(null);
                for (String keyId : keys) {
                    loadKeyVersionFromRepo(keyId);
                }
            } catch (IOException e) {
                log.error("Failed to load keys from repo", e);
            }
            return;
        }

        if (currentKeyPath == null || !Files.exists(currentKeyPath) || !Files.isDirectory(currentKeyPath)) {
            return;
        }

        try (var paths = Files.list(currentKeyPath)) {
            paths.filter(Files::isDirectory)
                    .filter(this::isKeyVersionDir)
                    .forEach(this::loadKeyVersion);

            if (keyVersions.isEmpty()) {
                loadLegacyKeyPair();
            }
        } catch (IOException e) {
            log.error("Failed to load existing RSA key versions: {}", e.getMessage());
        }
    }

    private void loadKeyVersionFromRepo(String keyId) {
        writeLock.lock();
        try {
            KeyStatus status = keyRepository.loadMetadata(keyId, STATUS_FILE)
                    .map(KeyStatus::valueOf).orElse(KeyStatus.CREATED);
            
            Instant expiresAt = keyRepository.loadMetadata(keyId, EXPIRATION_FILE)
                    .map(Instant::parse).orElse(null);
            
            if (expiresAt != null && Instant.now().isAfter(expiresAt)) {
                return;
            }

            Optional<byte[]> privBytes = keyRepository.loadKey(keyId, PRIVATE_KEY_FILE);
            Optional<byte[]> pubBytes = keyRepository.loadKey(keyId, PUBLIC_KEY_FILE);
            
            if (privBytes.isEmpty() || pubBytes.isEmpty()) {
                log.warn("Missing RSA keys for {}", keyId);
                return;
            }

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privBytes.get()));
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubBytes.get()));
            KeyPair keyPair = new KeyPair(publicKey, privateKey);
            
            // clear bytes
            Arrays.fill(privBytes.get(), (byte)0);
            Arrays.fill(pubBytes.get(), (byte)0);

            Algorithm algorithm = keyRepository.loadMetadata(keyId, ALGORITHM_FILE)
                    .map(Algorithm::valueOf).orElse(Algorithm.RSA256);

            KeyVersion version = new KeyVersion(keyId, algorithm, "repo:" + keyId);
            version.setStatus(status);
            version.setExpiresAt(expiresAt);
            
            if (status == KeyStatus.ACTIVE) {
                version.setActivatedTime(LocalDateTime.now());
                this.activeKeyId = keyId;
                this.keyPair = keyPair;
            }

            versionKeyPairs.put(keyId, keyPair);
            keyVersions.put(keyId, version);
        } catch (Exception e) {
            log.warn("Failed to load RSA key {} from repo", keyId, e);
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
        boolean hasPrivate = Files.exists(dir.resolve(PRIVATE_KEY_FILE));
        boolean hasPublic = Files.exists(dir.resolve(PUBLIC_KEY_FILE));
        boolean hasAlg = Files.exists(dir.resolve(ALGORITHM_FILE));
        boolean likeRSA = name.contains("rsa") && name.contains("-v");
        return (hasPrivate && hasPublic) || hasAlg || likeRSA;
    }

    @Override
    public boolean generateKeyPair(Algorithm algorithm) {
        return rotateKey(algorithm, generateKeyVersionId(algorithm));
    }

    @Override
    public boolean rotateKey(Algorithm algorithm, String newKeyIdentifier) {
        // 使用默认过渡期
        int transitionHours = keyMinterProperties != null ?
                keyMinterProperties.getTransitionPeriodHours() : 24;
        return rotateKeyWithTransition(algorithm, newKeyIdentifier, transitionHours);
    }

    @Override
    public boolean rotateKeyWithTransition(Algorithm algorithm, String newKeyIdentifier, int transitionPeriodHours) {
        validateRsaAlgorithm(algorithm);

        if (!isKeyRotationEnabled()) {
            log.error("Key rotation is not enabled");
            return false;
        }

        // Use repository if available
        if (keyRepository != null) {
            try {
                // 1. Generate new key pair
                KeyPair keyPair = generateRsaKeyPair(algorithm);
                
                // 2. Prepare files
                Map<String, byte[]> files = new HashMap<>();
                
                // private.key
                files.put(PRIVATE_KEY_FILE, keyPair.getPrivate().getEncoded());
                
                // public.key
                files.put(PUBLIC_KEY_FILE, keyPair.getPublic().getEncoded());
                
                // algorithm.info
                files.put(ALGORITHM_FILE, algorithm.name().getBytes(StandardCharsets.UTF_8));
                
                // expiration.info
                Instant expiresAt = calculateKeyExpiration();
                files.put(EXPIRATION_FILE, expiresAt.toString().getBytes(StandardCharsets.UTF_8));
                
                // status.info
                files.put(STATUS_FILE, KeyStatus.CREATED.name().getBytes(StandardCharsets.UTF_8));
                
                // 3. Save
                KeyVersionData data = KeyVersionData.builder()
                        .keyId(newKeyIdentifier)
                        .algorithm(algorithm)
                        .files(files)
                        .build();
                keyRepository.saveKeyVersion(data);
                
                // 4. Update memory
                updateKeyVersionWithTransition(newKeyIdentifier, algorithm, keyPair, transitionPeriodHours);
                
                log.info("Rotated RSA key via repository: {}", newKeyIdentifier);
                return true;
            } catch (Exception e) {
                log.error("Key rotation via repository failed", e);
                return false;
            }
        }

        try {
            return KeyRotation.rotateKeyAtomic(
                    newKeyIdentifier,
                    currentKeyPath,
                    () -> generateRsaKeyPair(algorithm),
                    (keyPair, tempDir) -> saveKeyPairToDirectory(keyPair, tempDir, algorithm, newKeyIdentifier),
                    (keyPair) -> updateKeyVersionWithTransition(newKeyIdentifier, algorithm, keyPair, transitionPeriodHours)
            );
        } catch (IOException e) {
            log.error("Key rotation with transition failed for {}: {}", newKeyIdentifier, e.getMessage(), e);
            throw new UncheckedIOException("Key rotation failed", e);
        }
    }

    private KeyPair generateRsaKeyPair(Algorithm algorithm) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        int keySize = switch (algorithm) {
            case RSA384 -> 3072;
            case RSA512 -> 4096;
            default -> DEFAULT_RSA_KEY_SIZE;
        };
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    private void saveKeyPairToDirectory(KeyPair keyPair, Path tempDir, Algorithm algorithm, String keyId) throws IOException {
        Instant expiresAt = saveKeyPairTo(
                keyPair, tempDir, algorithm, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, ALGORITHM_FILE, EXPIRATION_FILE, STATUS_FILE
        );
        log.debug("Saved RSA key {} with expiration: {}", keyId, expiresAt);
    }

    private void updateKeyVersionWithTransition(String keyId, Algorithm algorithm, KeyPair keyPair, int transitionPeriodHours) {
        writeLock.lock();
        try {
            // 创建新版本 (状态默认为 CREATED)
            String keyPath = currentKeyPath != null ? currentKeyPath.resolve(keyId).toString() : "repo:" + keyId;
            KeyVersion newVersion = new KeyVersion(keyId, algorithm, keyPath);
            newVersion.setCreatedTime(LocalDateTime.now());
            newVersion.setExpiresAt(calculateKeyExpiration());
            // newVersion.activate();

            versionKeyPairs.put(keyId, keyPair);
            keyVersions.put(keyId, newVersion);

            // 注意：不更新当前活跃密钥，需要手动调用 setActiveKey 激活
            /*
            this.keyPair = keyPair;
            this.activeKeyId = keyId;
            */

            log.info("RSA key created (pending activation). Key ID: {}, algorithm: {}", keyId, algorithm);
        } catch (Exception e) {
            log.error("Failed to update RSA key version: {}", e.getMessage(), e);
            throw new RuntimeException("Key version update failed", e);
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    protected void loadKeyPair(String keyId) {
        writeLock.lock();
        try {
            if (!versionKeyPairs.containsKey(keyId)) {
                KeyPair kp = loadKeyPairFromDir(currentKeyPath.resolve(keyId));
                if (kp != null) {
                    versionKeyPairs.put(keyId, kp);
                } else {
                    throw new IllegalArgumentException("Key pair not found: " + keyId);
                }
            }
            this.keyPair = versionKeyPairs.get(keyId);
            this.activeKeyId = keyId;
            markKeyActive(keyId);
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public boolean verifyToken(String token) {
        if (StringUtils.isBlank(token)) {
            return false;
        }

        readLock.lock();
        try {
            if (keyPair == null) {
                log.debug("Cannot verify token - no active RSA key pair");
                return false;
            }

            try {
                Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token);
                return true;
            } catch (JwtException | IllegalArgumentException e) {
                log.debug("Token verification failed with active key: {}", e.getMessage());
                return false;
            }
        } finally {
            readLock.unlock();
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
            KeyPair historicalKeyPair = versionKeyPairs.get(keyId);
            if (historicalKeyPair == null) {
                if (keyRepository != null) {
                    loadKeyVersionFromRepo(keyId);
                    historicalKeyPair = versionKeyPairs.get(keyId);
                } else if (currentKeyPath != null) {
                    historicalKeyPair = loadKeyPairFromDir(currentKeyPath.resolve(keyId));
                    if (historicalKeyPair != null) {
                        versionKeyPairs.put(keyId, historicalKeyPair);
                    }
                }
            }

            if (historicalKeyPair == null) {
                log.warn("Key pair not found for version: {}", keyId);
                return false;
            }

            try {
                Jwts.parser().verifyWith(historicalKeyPair.getPublic()).build().parseSignedClaims(token);
                return true;
            } catch (Exception e) {
                log.error("Token verification failed with key {}: {}", keyId, e.getMessage());
                return false;
            }
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public Object getCurrentKey() {
        readLock.lock();
        try {
            return keyPair;
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public Object getKeyByVersion(String keyId) {
        readLock.lock();
        try {
            return versionKeyPairs.get(keyId);
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public void close() {
        cleanup();
    }

    protected void cleanup() {
        writeLock.lock();
        try {
            versionKeyPairs.clear();
            keyPair = null;
            keyVersions.clear();
            activeKeyId = null;
            log.debug("RsaJwt resources cleaned up");
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
        validateRsaAlgorithm(algorithm);

        readLock.lock();
        try {
            if (keyPair == null) {
                throw new IllegalStateException("No active RSA key pair. Call setActiveKey or rotateKey first.");
            }

            JwtBuilder builder = createJwtBuilder(properties, customClaims);
            return builder.signWith(keyPair.getPrivate(), getRsaSignAlgorithm(algorithm)).compact();
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
            if (keyPair == null) {
                throw new SecurityException("RSA JWT validation failed - no active key pair");
            }

            try {
                return Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token).getPayload();
            } catch (JwtException e) {
                throw new SecurityException("RSA JWT validation failed", e);
            }
        } finally {
            readLock.unlock();
        }
    }

    @Override
    protected MacAlgorithm getSignAlgorithm(Algorithm algorithm) {
        throw new UnsupportedOperationException("RSA algorithm uses SignatureAlgorithm, not MacAlgorithm");
    }

    @Override
    public String getKeyInfo() {
        readLock.lock();
        try {
            return String.format("RSA Keys - Active: %s, Total versions: %d, Key rotation: %s",
                    activeKeyId != null ? activeKeyId : "None",
                    keyVersions.size(),
                    keyRotationEnabled ? "enabled" : "disabled");
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public boolean generateAllKeyPairs() {
        boolean allSuccess = true;
        for (Algorithm algorithm : Algorithm.getRsaAlgorithms()) {
            String keyId = generateKeyVersionId(algorithm);
            boolean success = rotateKey(algorithm, keyId);
            if (!success) {
                allSuccess = false;
                log.warn("Failed to generate key pair for: {}", algorithm);
            }
        }
        return allSuccess;
    }

    @Override
    public String getAlgorithmInfo() {
        return "RSA algorithms: RS256, RS384, RS512 with key rotation support";
    }

    protected void loadKeyVersion(Path versionDir) {
        if (versionDir == null) {
            return;
        }

        writeLock.lock();
        try {
            String keyId = versionDir.getFileName().toString();

            // 读取状态
            KeyStatus status = readKeyStatusFromDir(versionDir);
            boolean isActive = status == KeyStatus.ACTIVE;

            // 读取过期时间
            java.time.Instant expiresAt = readExpirationFromDir(versionDir);

            // 读取过渡期结束时间
            java.time.Instant transitionEndsAt = readTransitionEndFromDir(versionDir);

            // 如果密钥已过期，跳过加载
            if (expiresAt != null && java.time.Instant.now().isAfter(expiresAt)) {
                log.warn("Skipping expired RSA key: {}, expired at: {}", keyId, expiresAt);
                return;
            }

            KeyPair keyPair = loadKeyPairFromDir(versionDir);
            if (keyPair == null) {
                log.warn("Failed to load key pair from directory: {}", versionDir);
                return;
            }

            versionKeyPairs.put(keyId, keyPair);

            Algorithm algorithm = detectAlgorithmFromDir(versionDir);
            KeyVersion version = new KeyVersion(keyId, algorithm, versionDir.toString());
            version.setStatus(status);
            version.setCreatedTime(getCreationTimeFromDir(versionDir));
            version.setExpiresAt(expiresAt);
            version.setTransitionEndsAt(transitionEndsAt);

            if (isActive) {
                version.setActivatedTime(LocalDateTime.now());
                this.activeKeyId = keyId;
                this.keyPair = keyPair;
            }

            keyVersions.put(keyId, version);
            log.debug("Loaded RSA key version: {}, status: {}, algorithm: {}, expires: {}",
                    keyId, status, algorithm, expiresAt);
        } catch (Exception e) {
            log.warn("Failed to load key version from {}: {}", versionDir, e.getMessage());
        } finally {
            writeLock.unlock();
        }
    }

    private KeyStatus readKeyStatusFromDir(Path versionDir) {
        Path statusFile = versionDir.resolve(STATUS_FILE);
        if (Files.exists(statusFile)) {
            try {
                String statusStr = Files.readString(statusFile).trim();
                return KeyStatus.valueOf(statusStr);
            } catch (Exception e) {
                log.debug("Failed to read status from {}: {}", statusFile, e.getMessage());
            }
        }
        return KeyStatus.CREATED;
    }

    private java.time.Instant readExpirationFromDir(Path versionDir) {
        Path expFile = versionDir.resolve(EXPIRATION_FILE);
        if (Files.exists(expFile)) {
            try {
                String expStr = Files.readString(expFile).trim();
                return java.time.Instant.parse(expStr);
            } catch (Exception e) {
                log.debug("Failed to read expiration from {}: {}", expFile, e.getMessage());
            }
        }
        return null;
    }

    private java.time.Instant readTransitionEndFromDir(Path versionDir) {
        Path transitionFile = versionDir.resolve(TRANSITION_FILE);
        if (Files.exists(transitionFile)) {
            try {
                String transitionStr = Files.readString(transitionFile).trim();
                return java.time.Instant.parse(transitionStr);
            } catch (Exception e) {
                log.debug("Failed to read transition end from {}: {}", transitionFile, e.getMessage());
            }
        }
        return null;
    }

    private KeyPair loadKeyPairFromDir(Path versionDir) {
        if (versionDir == null) {
            return null;
        }

        Path privateKeyPath = versionDir.resolve(PRIVATE_KEY_FILE);
        Path publicKeyPath = versionDir.resolve(PUBLIC_KEY_FILE);
        return loadKeyPairFromPaths(privateKeyPath, publicKeyPath);
    }

    private Algorithm detectAlgorithmFromDir(Path versionDir) {
        Path algorithmFile = versionDir.resolve(ALGORITHM_FILE);
        if (Files.exists(algorithmFile)) {
            try {
                String content = Files.readString(algorithmFile).trim();
                return Algorithm.valueOf(content);
            } catch (Exception e) {
                log.debug("Failed to read algorithm from {}: {}", algorithmFile, e.getMessage());
            }
        }
        return Algorithm.RSA256;
    }

    private void loadLegacyKeyPair() {
        Path privateKeyPath = currentKeyPath.resolve(PRIVATE_KEY_FILE);
        Path publicKeyPath = currentKeyPath.resolve(PUBLIC_KEY_FILE);

        try {
            KeyPair keyPair = loadKeyPairFromPaths(privateKeyPath, publicKeyPath);
            if (keyPair == null) {
                log.debug("No legacy RSA key pair found at: {}", currentKeyPath);
                return;
            }

            this.keyPair = keyPair;

            String legacyKeyId = "RSA256-v" + LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + "-"
                    + UUID.randomUUID().toString().substring(0, 8);

            java.time.Instant expiresAt = calculateKeyExpiration();

            KeyVersion version = new KeyVersion(
                    legacyKeyId,
                    Algorithm.RSA256,
                    privateKeyPath.getParent().toString()
            );
            version.setStatus(KeyStatus.ACTIVE);
            version.setCreatedTime(LocalDateTime.now().minusDays(1));
            version.setActivatedTime(LocalDateTime.now());
            version.setExpiresAt(expiresAt);

            versionKeyPairs.put(legacyKeyId, keyPair);
            keyVersions.put(legacyKeyId, version);
            this.activeKeyId = legacyKeyId;

            log.info("Loaded legacy RSA key pair from: {}, expires: {}", privateKeyPath.getParent(), expiresAt);
        } catch (Exception e) {
            log.warn("Failed to load legacy RSA key pair: {}", e.getMessage());
        }
    }

    private KeyPair loadKeyPairFromPaths(Path privateKeyPath, Path publicKeyPath) {
        if (privateKeyPath == null || publicKeyPath == null) {
            return null;
        }
        if (!Files.exists(privateKeyPath) || !Files.exists(publicKeyPath)) {
            return null;
        }

        byte[] privateKeyBytes = null;
        byte[] publicKeyBytes = null;

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            privateKeyBytes = Files.readAllBytes(privateKeyPath);
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

            publicKeyBytes = Files.readAllBytes(publicKeyPath);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            log.debug("Failed to load key pair from paths: {}", e.getMessage());
            return null;
        } finally {
            if (privateKeyBytes != null) {
                Arrays.fill(privateKeyBytes, (byte) 0);
            }
            if (publicKeyBytes != null) {
                Arrays.fill(publicKeyBytes, (byte) 0);
            }
        }
    }

    private SignatureAlgorithm getRsaSignAlgorithm(Algorithm algorithm) {
        return switch (algorithm) {
            case RSA256 -> Jwts.SIG.RS256;
            case RSA384 -> Jwts.SIG.RS384;
            case RSA512 -> Jwts.SIG.RS512;
            default -> throw new IllegalStateException("Unsupported RSA algorithm: " + algorithm);
        };
    }
}
