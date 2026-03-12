package com.chao.keyminter.core;

import com.chao.keyminter.domain.model.KeyStatus;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithm;
import com.chao.keyminter.adapter.in.KeyMinterConfigHolder;
import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.JwtProperties;
import com.chao.keyminter.domain.model.KeyVersion;
import com.chao.keyminter.domain.port.out.SecretDirProvider;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ECDSA JWT 实现类
 * 支持 ES256, ES384, ES512 算法
 */
@Slf4j
@Getter
public class EcdsaJwt extends AbstractJwtAlgo {

    private static final String PRIVATE_KEY_FILE = "private.key";
    private static final String PUBLIC_KEY_FILE = "public.key";
    private static final String ALGORITHM_FILE = "algorithm.info";
    private static final String STATUS_FILE = "status.info";
    private static final String EXPIRATION_FILE = "expiration.info";
    private static final String TRANSITION_FILE = "transition.info";

    private final Map<String, KeyPair> versionKeyPairs = new ConcurrentHashMap<>();
    private final Map<String, Algorithm> keyIdToAlgorithm = new ConcurrentHashMap<>();

    private static final Map<Algorithm, AlgorithmConfig> ALGORITHM_CONFIGS = Map.of(
            Algorithm.ES256, new AlgorithmConfig("secp256r1"),
            Algorithm.ES384, new AlgorithmConfig("secp384r1"),
            Algorithm.ES512, new AlgorithmConfig("secp521r1")
    );

    private static Path getDefaultEcDir() {
        return SecretDirProvider.getDefaultBaseDir().resolve("ec-keys");
    }

    public EcdsaJwt() {
        this(getDefaultEcDir());
    }

    public EcdsaJwt(Path keyDir) {
        this(KeyMinterConfigHolder.get(), keyDir);
    }

    public EcdsaJwt(KeyMinterProperties properties, Path keyDir) {
        super(properties);
        this.currentKeyPath = initializeKeyPath(keyDir);

        if (isKeyRotationEnabled()) {
            enableKeyRotation();
        }

        initializeKeyVersions();

        if (activeKeyId == null) {
            log.warn("No keys found in directory: {}", this.currentKeyPath);
        }
    }

    private Path initializeKeyPath(Path keyDir) {
        if (keyDir == null) {
            return getDefaultEcDir();
        }

        Path normalized = keyDir.normalize();
        validateDirectoryPath(normalized);

        if (!"ec-keys".equals(normalized.getFileName().toString())) {
            normalized = normalized.resolve("ec-keys");
        }
        return normalized;
    }

    @Override
    public void loadExistingKeyVersions() {
        if (currentKeyPath == null || !Files.exists(currentKeyPath) || !Files.isDirectory(currentKeyPath)) {
            return;
        }

        try (var paths = Files.list(currentKeyPath)) {
            paths.filter(Files::isDirectory)
                    .filter(this::isKeyVersionDir)
                    .forEach(this::loadKeyVersion);

            if (versionKeyPairs.isEmpty()) {
                loadLegacyKeyPairs();
            }
        } catch (IOException e) {
            log.error("Failed to load existing EC key versions: {}", e.getMessage());
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
        boolean likeEC = name.contains("es") && name.contains("-v");
        return (hasPrivate && hasPublic) || hasAlg || likeEC;
    }

    @Override
    public boolean generateKeyPair(Algorithm algorithm) {
        return rotateKey(algorithm, generateKeyVersionId(algorithm));
    }

    @Override
    public boolean rotateKey(Algorithm algorithm, String newKeyIdentifier) {
        // 使用默认过渡期
        int transitionHours = keyMinterProperties != null ? keyMinterProperties.getTransitionPeriodHours() : 24;
        return rotateKeyWithTransition(algorithm, newKeyIdentifier, transitionHours);
    }

    @Override
    public boolean rotateKeyWithTransition(Algorithm algorithm, String newKeyIdentifier, int transitionPeriodHours) {
        validateEcdsaAlgorithm(algorithm);

        if (!isKeyRotationEnabled()) {
            log.error("Key rotation is not enabled");
            return false;
        }

        try {
            return KeyRotation.rotateKeyAtomic(
                    newKeyIdentifier,
                    currentKeyPath,
                    () -> generateEcKeyPair(algorithm),
                    (keyPair, tempDir) -> saveKeyPairToDirectory(keyPair, tempDir, algorithm, newKeyIdentifier),
                    (keyPair) -> updateKeyVersionWithTransition(newKeyIdentifier, algorithm, keyPair, transitionPeriodHours)
            );
        } catch (IOException e) {
            log.error("Key rotation with transition failed for {}: {}", newKeyIdentifier, e.getMessage(), e);
            throw new UncheckedIOException("Key rotation failed", e);
        }
    }

    private KeyPair generateEcKeyPair(Algorithm algorithm) throws Exception {
        AlgorithmConfig config = getAlgorithmConfig(algorithm);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(config.curveName());
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
    }

    private void saveKeyPairToDirectory(KeyPair keyPair, Path tempDir, Algorithm algorithm, String keyId) throws IOException {
        Instant expiresAt = saveKeyPairTo(
                keyPair, tempDir, algorithm, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, ALGORITHM_FILE, EXPIRATION_FILE, STATUS_FILE
        );
        log.debug("Saved ECDSA key {} with expiration: {}", keyId, expiresAt);
    }

    private void updateKeyVersionWithTransition(String keyId, Algorithm algorithm, KeyPair keyPair, int transitionPeriodHours) {
        writeLock.lock();
        try {
            // 创建新版本 (状态默认为 CREATED)
            KeyVersion newVersion = new KeyVersion(keyId, algorithm, currentKeyPath.resolve(keyId).toString());
            newVersion.setCreatedTime(LocalDateTime.now());
            newVersion.setExpiresAt(calculateKeyExpiration());
            // newVersion.activate();

            versionKeyPairs.put(keyId, keyPair);
            keyIdToAlgorithm.put(keyId, algorithm);
            keyVersions.put(keyId, newVersion);

            // 注意：不更新当前活跃密钥，需要手动调用 setActiveKey 激活
            /*
            activeKeyId = keyId;
            */

            log.info("ECDSA key created (pending activation). Key ID: {}, algorithm: {}", keyId, algorithm);
        } catch (Exception e) {
            log.error("Failed to update ECDSA key version: {}", e.getMessage(), e);
            throw new RuntimeException("Key version update failed", e);
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public void loadKeyPair(String keyId) {
        writeLock.lock();
        try {
            if (!versionKeyPairs.containsKey(keyId)) {
                Path versionDir = currentKeyPath.resolve(keyId);
                KeyPair keyPair = loadKeyPairFromDir(versionDir);
                if (keyPair != null) {
                    versionKeyPairs.put(keyId, keyPair);
                    keyIdToAlgorithm.put(keyId, getAlgorithmFromDir(versionDir));
                } else {
                    throw new IllegalArgumentException("Key pair not found for version: " + keyId);
                }
            }
            this.activeKeyId = keyId;
            markKeyActive(keyId);
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public boolean verifyWithKeyVersion(String keyId, String token) {
        if (StringUtils.isBlank(keyId) || StringUtils.isBlank(token)) return false;

        // 先进行通用的状态检查（包含实时惰性更新）
        if (canKeyNotVerify(keyId)) {
            return false;
        }

        readLock.lock();
        try {
            KeyPair keyPair = versionKeyPairs.get(keyId);
            if (keyPair == null) {
                keyPair = loadKeyPairFromDir(currentKeyPath.resolve(keyId));
                if (keyPair != null) {
                    versionKeyPairs.put(keyId, keyPair);
                }
            }
            if (keyPair == null) return false;
            try {
                Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token);
                return true;
            } catch (Exception e) {
                log.debug("Token verification failed with key {}: {}", keyId, e.getMessage());
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
            return activeKeyId != null ? versionKeyPairs.get(activeKeyId) : null;
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
    public boolean verifyToken(String token) {
        if (StringUtils.isBlank(token)) {
            return false;
        }

        readLock.lock();
        try {
            if (activeKeyId == null) {
                log.debug("Cannot verify token - no active ECDSA key");
                return false;
            }

            KeyPair keyPair = versionKeyPairs.get(activeKeyId);
            if (keyPair == null) {
                log.debug("Cannot verify token - active key not loaded");
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
    public Claims decodePayload(String token) {
        if (StringUtils.isBlank(token)) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }

        readLock.lock();
        try {
            if (activeKeyId == null) {
                throw new SecurityException("ECDSA JWT validation failed - no active key");
            }

            KeyPair keyPair = versionKeyPairs.get(activeKeyId);
            if (keyPair == null) {
                throw new SecurityException("ECDSA JWT validation failed - active key not loaded");
            }

            try {
                return Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token).getPayload();
            } catch (JwtException e) {
                throw new SecurityException("ECDSA JWT validation failed", e);
            }
        } finally {
            readLock.unlock();
        }
    }

    @Override
    protected boolean hasKeyFilesInDirectory(String tag) {
        return findKeyDir(tag, dir ->
                Files.exists(dir.resolve(PRIVATE_KEY_FILE)) &&
                        Files.exists(dir.resolve(PUBLIC_KEY_FILE))
        ).isPresent();
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
    public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
        validateEcdsaAlgorithm(algorithm);

        readLock.lock();
        try {
            if (activeKeyId == null) {
                throw new IllegalStateException("No active ECDSA key. Call setActiveKey or rotateKey first.");
            }

            KeyPair keyPair = versionKeyPairs.get(activeKeyId);
            if (keyPair == null) {
                throw new IllegalStateException("Active ECDSA key not found: " + activeKeyId);
            }

            JwtBuilder builder = createJwtBuilder(properties, customClaims);
            return builder.signWith(keyPair.getPrivate(), getEcdsaSignAlgorithm(algorithm)).compact();
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
            keyIdToAlgorithm.clear();
            keyVersions.clear();
            activeKeyId = null;
            log.debug("EcdsaJwt resources cleaned up");
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    protected MacAlgorithm getSignAlgorithm(Algorithm algorithm) {
        throw new UnsupportedOperationException("ECDSA algorithm uses SignatureAlgorithm, not MacAlgorithm");
    }

    @Override
    public String getCurveInfo(Algorithm algorithm) {
        validateEcdsaAlgorithm(algorithm);

        readLock.lock();
        try {
            if (activeKeyId == null) {
                return algorithm + " - No active key";
            }

            KeyPair keyPair = versionKeyPairs.get(activeKeyId);
            if (keyPair != null && keyPair.getPublic() instanceof ECPublicKey ecPublicKey) {
                ECParameterSpec params = ecPublicKey.getParams();
                AlgorithmConfig config = getAlgorithmConfig(algorithm);
                return String.format("%s - Curve: %s, Key Size: %d",
                        algorithm, config.curveName(), params.getCurve().getField().getFieldSize());
            }
            return algorithm + " - Curve information not available";
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public boolean generateAllKeyPairs() {
        return ALGORITHM_CONFIGS.keySet().stream()
                .allMatch(algorithm -> rotateKey(algorithm, generateKeyVersionId(algorithm)));
    }

    @Override
    public String getKeyInfo() {
        readLock.lock();
        try {
            return String.format("ECDSA Keys - Active: %s, Total versions: %d, Key rotation: %s",
                    activeKeyId != null ? activeKeyId : "None",
                    versionKeyPairs.size(),
                    keyRotationEnabled ? "enabled" : "disabled");
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public String getAlgorithmInfo() {
        return "ECDSA algorithms: ES256 (P-256), ES384 (P-384), ES512 (P-521) with key rotation support";
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
            Instant expiresAt = readExpirationFromDir(versionDir);

            // 读取过渡期结束时间
            Instant transitionEndsAt = readTransitionEndFromDir(versionDir);

            // 如果密钥已过期，跳过加载
            if (expiresAt != null && Instant.now().isAfter(expiresAt)) {
                log.warn("Skipping expired ECDSA key: {}, expired at: {}", keyId, expiresAt);
                return;
            }

            KeyPair keyPair = loadKeyPairFromDir(versionDir);
            if (keyPair == null) {
                log.warn("Failed to load key pair from directory: {}", versionDir);
                return;
            }

            versionKeyPairs.put(keyId, keyPair);
            Algorithm algorithm = getAlgorithmFromDir(versionDir);
            keyIdToAlgorithm.put(keyId, algorithm);

            KeyVersion version = new KeyVersion(keyId, algorithm, versionDir.toString());
            version.setStatus(status);
            version.setCreatedTime(getCreationTimeFromDir(versionDir));
            version.setExpiresAt(expiresAt);
            version.setTransitionEndsAt(transitionEndsAt);

            if (isActive) {
                version.setActivatedTime(LocalDateTime.now());
                this.activeKeyId = keyId;
            }
            keyVersions.put(keyId, version);
            log.debug("Loaded ECDSA key version: {}, status: {}, algorithm: {}, expires: {}",
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
                String statusStr = Files.readString(statusFile, StandardCharsets.UTF_8).trim();
                return KeyStatus.valueOf(statusStr);
            } catch (Exception e) {
                log.debug("Failed to read status from {}: {}", statusFile, e.getMessage());
            }
        }
        return KeyStatus.CREATED;
    }

    private Instant readExpirationFromDir(Path versionDir) {
        Path expFile = versionDir.resolve(EXPIRATION_FILE);
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
        Path transitionFile = versionDir.resolve(TRANSITION_FILE);
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

    private KeyPair loadKeyPairFromDir(Path versionDir) {
        if (versionDir == null) {
            return null;
        }

        Path privateKeyPath = versionDir.resolve(PRIVATE_KEY_FILE);
        Path publicKeyPath = versionDir.resolve(PUBLIC_KEY_FILE);
        return loadKeyPairFromPaths(privateKeyPath, publicKeyPath);
    }

    private Algorithm getAlgorithmFromDir(Path versionDir) {
        Path algorithmFile = versionDir.resolve(ALGORITHM_FILE);
        if (Files.exists(algorithmFile)) {
            try {
                String algorithmStr = Files.readString(algorithmFile, StandardCharsets.UTF_8).trim();
                return Algorithm.valueOf(algorithmStr);
            } catch (Exception e) {
                log.debug("Failed to read algorithm from {}: {}", algorithmFile, e.getMessage());
            }
        }
        return Algorithm.ES256;
    }

    private void loadLegacyKeyPairs() {
        if (currentKeyPath == null || !Files.exists(currentKeyPath)) {
            return;
        }

        try (var paths = Files.list(currentKeyPath)) {
            paths.filter(Files::isRegularFile)
                    .filter(file -> file.getFileName().toString().endsWith("private.key"))
                    .forEach(this::migrateLegacyKeyPair);
        } catch (IOException e) {
            log.debug("No legacy keys found or failed to scan: {}", e.getMessage());
        }
    }

    private void migrateLegacyKeyPair(Path legacyPrivateKey) {
        try {
            String filename = legacyPrivateKey.getFileName().toString();
            String baseName = filename.replace("-private.key", "");
            Algorithm algorithm = determineAlgorithmFromFilename(baseName);

            Path legacyPublicKey = legacyPrivateKey.getParent().resolve(baseName + "-public.key");
            if (!Files.exists(legacyPublicKey)) {
                return;
            }

            KeyPair keyPair = loadKeyPairFromPaths(legacyPrivateKey, legacyPublicKey);
            if (keyPair == null) {
                return;
            }

            String keyId = "es" + LocalDateTime.now().format(
                    DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + "-legacy";

            migrateToVersioned(keyId, keyPair, algorithm);
        } catch (Exception e) {
            log.warn("Failed to migrate legacy key {}: {}", legacyPrivateKey, e.getMessage());
        }
    }

    private Algorithm determineAlgorithmFromFilename(String baseName) {
        String lower = baseName.toLowerCase();
        if (lower.contains("es256")) return Algorithm.ES256;
        if (lower.contains("es384")) return Algorithm.ES384;
        if (lower.contains("es512")) return Algorithm.ES512;
        return Algorithm.ES256;
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
            KeyFactory keyFactory = KeyFactory.getInstance("EC");

            privateKeyBytes = Files.readAllBytes(privateKeyPath);
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

            publicKeyBytes = Files.readAllBytes(publicKeyPath);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            log.debug("Failed to load EC key pair: {}", e.getMessage());
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

    private void migrateToVersioned(String keyId, KeyPair keyPair, Algorithm algorithm) throws IOException {
        Path versionDir = currentKeyPath.resolve(keyId);
        Files.createDirectories(versionDir);

        Path newPrivateKey = versionDir.resolve(PRIVATE_KEY_FILE);
        Path newPublicKey = versionDir.resolve(PUBLIC_KEY_FILE);

        Files.write(newPrivateKey, keyPair.getPrivate().getEncoded());
        Files.write(newPublicKey, keyPair.getPublic().getEncoded());

        setRestrictiveFilePermissions(newPrivateKey);

        Path algorithmFile = versionDir.resolve(ALGORITHM_FILE);
        Files.writeString(algorithmFile, algorithm.name());

        // 保存过期时间
        Instant expiresAt = calculateKeyExpiration();
        Path expirationFile = versionDir.resolve(EXPIRATION_FILE);
        Files.writeString(expirationFile, expiresAt.toString());

        // 保存状态
        Path statusFile = versionDir.resolve(STATUS_FILE);
        Files.writeString(statusFile, KeyStatus.ACTIVE.name());

        versionKeyPairs.put(keyId, keyPair);
        keyIdToAlgorithm.put(keyId, algorithm);

        KeyVersion version = new KeyVersion(keyId, algorithm, versionDir.toString());
        version.setStatus(KeyStatus.ACTIVE);
        version.setCreatedTime(LocalDateTime.now());
        version.setActivatedTime(LocalDateTime.now());
        version.setExpiresAt(expiresAt);

        keyVersions.put(keyId, version);
        this.activeKeyId = keyId;

        log.info("Migrated legacy ECDSA key to versioned format: {}, expires: {}", keyId, expiresAt);
    }

    private SignatureAlgorithm getEcdsaSignAlgorithm(Algorithm algorithm) {
        return switch (algorithm) {
            case ES256 -> Jwts.SIG.ES256;
            case ES384 -> Jwts.SIG.ES384;
            case ES512 -> Jwts.SIG.ES512;
            default -> throw new IllegalStateException("Unsupported ECDSA algorithm: " + algorithm);
        };
    }

    private AlgorithmConfig getAlgorithmConfig(Algorithm algorithm) {
        AlgorithmConfig config = ALGORITHM_CONFIGS.get(algorithm);
        if (config == null) {
            throw new IllegalArgumentException("Unsupported ECDSA algorithm: " + algorithm);
        }
        return config;
    }

    private record AlgorithmConfig(String curveName) {
    }
}
