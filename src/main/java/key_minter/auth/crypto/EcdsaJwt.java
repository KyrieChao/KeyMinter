package key_minter.auth.crypto;

import key_minter.model.dto.JwtProperties;
import key_minter.auth.core.AbstractJwt;
import key_minter.auth.core.Jwt;
import key_minter.model.dto.Algorithm;
import key_minter.model.dto.KeyVersion;
import key_minter.util.AtomicKeyRotation;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithm;
import org.apache.commons.lang3.StringUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.stream.Stream;

@Slf4j
@Getter
public class EcdsaJwt extends AbstractJwt {
    private static final Path DEFAULT_KEY_DIR = Paths.get(System.getProperty("user.home"), ".chao", "ec-keys");
    private final Map<String, KeyPair> versionKeyPairs = new ConcurrentHashMap<>();
    private final Map<String, Algorithm> keyIdToAlgorithm = new ConcurrentHashMap<>();
    private static final Map<Algorithm, AlgorithmConfig> ALGORITHM_CONFIGS =
            Map.of(
                    Algorithm.ES256, new AlgorithmConfig("secp256r1"),
                    Algorithm.ES384, new AlgorithmConfig("secp384r1"),
                    Algorithm.ES512, new AlgorithmConfig("secp521r1")
            );
    private static final String KEY_VERSION_PREFIX = "es";

    public EcdsaJwt() {
        this(DEFAULT_KEY_DIR);
    }

    public EcdsaJwt(Path keyDir) {
        this(keyDir, true);
    }

    public EcdsaJwt(String directory) {
        this(StringUtils.isBlank(directory) ? DEFAULT_KEY_DIR : Paths.get(directory), true);
    }

    public EcdsaJwt(Path keyDir, boolean enableRotation) {
        if (keyDir == null) {
            keyDir = DEFAULT_KEY_DIR;
        } else {
            // 规范化路径，防止../../../攻击
            keyDir = keyDir.normalize();
            // 验证路径是否安全
            validateDirectoryPath(keyDir);
            if (!keyDir.getFileName().toString().equals("ec-keys")) {
                keyDir = keyDir.resolve("ec-keys");
            }
        }
        this.currentKeyPath = keyDir;
        if (enableRotation) enableKeyRotation();
        initializeKeyVersions();
        if (activeKeyId == null) log.warn("No keys found in directory: {}", keyDir);
    }

    @Override
    protected void loadExistingKeyVersions() {
        try {
            if (Files.exists(currentKeyPath) && Files.isDirectory(currentKeyPath)) {
                try (var paths = Files.list(currentKeyPath)) {
                    paths.filter(Files::isDirectory)
                            .filter(this::isKeyVersionDir)
                            .forEach(this::loadKeyVersion);
                }
                if (versionKeyPairs.isEmpty()) {
                    loadLegacyKeyPairs();
                }
            }
        } catch (IOException e) {
            log.error("Failed to load existing EC key versions: {}", e.getMessage());
        }
    }

    @Override
    protected boolean isKeyVersionDir(Path dir) {
        String name = dir.getFileName().toString().toLowerCase();
        boolean hasPrivate = Files.exists(dir.resolve("private.key"));
        boolean hasPublic = Files.exists(dir.resolve("public.key"));
        boolean hasAlg = Files.exists(dir.resolve("algorithm.info"));
        boolean likeEC = name.contains("es") && name.contains("-v"); // 目录名兜底
        return (hasPrivate && hasPublic) || hasAlg || likeEC;
    }

    @Override
    public boolean rotateKey(Algorithm algorithm, String newKeyIdentifier) {
        validateEcdsaAlgorithm(algorithm);
        if (!keyRotationEnabled) throw new UnsupportedOperationException("Key rotation is not enabled");
        return AtomicKeyRotation.rotateKeyAtomic(
                newKeyIdentifier,
                currentKeyPath,
                () -> {
                    AlgorithmConfig config = getAlgorithmConfig(algorithm);
                    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
                    ECGenParameterSpec ecSpec = new ECGenParameterSpec(config.curveName);
                    keyPairGenerator.initialize(ecSpec);
                    return keyPairGenerator.generateKeyPair();
                },
                (keyPair, tempDir) -> {
                    // 保存私钥
                    Path privateKeyPath = tempDir.resolve("private.key");
                    Files.write(privateKeyPath, keyPair.getPrivate().getEncoded(),
                            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

                    // 保存公钥
                    Path publicKeyPath = tempDir.resolve("public.key");
                    Files.write(publicKeyPath, keyPair.getPublic().getEncoded(),
                            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

                    // 保存算法信息
                    Path algorithmFile = tempDir.resolve("algorithm.info");
                    Files.writeString(algorithmFile, algorithm.name());

                    // 设置文件权限
                    setRestrictiveFilePermissions(privateKeyPath);
                },
                (keyPair) -> {
                    KeyVersion newVersion = new KeyVersion(newKeyIdentifier, algorithm,
                            currentKeyPath.resolve(newKeyIdentifier).toString());
                    newVersion.setCreatedTime(LocalDateTime.now());

                    versionKeyPairs.put(newKeyIdentifier, keyPair);
                    keyIdToAlgorithm.put(newKeyIdentifier, algorithm);
                    keyVersions.put(newKeyIdentifier, newVersion);

                    log.info("ECDSA key rotated successfully. New key ID: {}, algorithm: {}, curve: {}",
                            newKeyIdentifier, algorithm, getAlgorithmConfig(algorithm).curveName);
                }
        );
    }

    @Override
    public void loadKeyPair(String keyId) {
        if (!versionKeyPairs.containsKey(keyId)) {
            // 尝试从文件系统加载
            try {
                Path versionDir = currentKeyPath.resolve(keyId);
                KeyPair keyPair = loadKeyPairFromDir(versionDir);
                if (keyPair != null) {
                    versionKeyPairs.put(keyId, keyPair);
                    keyIdToAlgorithm.put(keyId, getAlgorithmFromDir(versionDir));
                } else {
                    throw new IllegalArgumentException("Key pair not found for version: " + keyId);
                }
            } catch (Exception e) {
                throw new IllegalArgumentException("Failed to load key pair for version: " + keyId, e);
            }
        }
        this.activeKeyId = keyId;
        markKeyActive(keyId);
    }

    @Override
    protected boolean verifyWithKeyVersion(String keyId, String token) {
        try {
            KeyPair keyPair = versionKeyPairs.get(keyId);
            if (keyPair == null) {
                // 尝试加载
                keyPair = loadKeyPairFromDir(currentKeyPath.resolve(keyId));
                if (keyPair != null) versionKeyPairs.put(keyId, keyPair);
            }
            if (keyPair != null) {
                Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token);
                return true;
            }
        } catch (Exception e) {
            log.error("Token verification failed with key {}: {}", keyId, e.getMessage());
            return false;
        }
        return false;
    }

    @Override
    protected Object getCurrentKey() {
        return activeKeyId != null ? versionKeyPairs.get(activeKeyId) : null;
    }

    @Override
    protected Object getKeyByVersion(String keyId) {
        return versionKeyPairs.get(keyId);
    }

    @Override
    public boolean generateKeyPair(Algorithm algorithm) {
        return rotateKey(algorithm, generateKeyVersionId(algorithm));
    }

    @Override
    public boolean generateKeyPair(Algorithm algorithm, String customFilename) {
        String keyId = generateKeyVersionId(algorithm);
        boolean success = rotateKey(algorithm, keyId);

        if (success && customFilename != null) {
            try {
                // 如果需要，复制到指定文件名
                KeyPair keyPair = versionKeyPairs.get(keyId);
                String filename = customFilename.contains(".") ? customFilename : customFilename + "-private.key";
                Path targetPrivateKey = currentKeyPath.getParent().resolve(filename);
                Path targetPublicKey = currentKeyPath.getParent()
                        .resolve(filename.replace("-private.key", "-public.key"));
                // 使用原子操作写入文件
                Files.createDirectories(targetPrivateKey.getParent());
                writeKeyPairToFileAtomically(targetPrivateKey, targetPublicKey, keyPair);

                log.info("Exported ECDSA key pair to {}, {}", targetPrivateKey, targetPublicKey);
            } catch (Exception e) {
                log.warn("Failed to copy key files: {}", e.getMessage());
            }
        }

        return success;
    }

    @Override
    public boolean verifyToken(String token) {
        if (StringUtils.isBlank(token)) return false;
        try {
            // 先尝试用当前活跃密钥验证
            if (activeKeyId != null) {
                KeyPair keyPair = versionKeyPairs.get(activeKeyId);
                if (keyPair != null) {
                    Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token);
                    return true;
                }
            }
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Token verification failed with active key: {}", e.getMessage());
        }

        // 如果失败，尝试用所有历史密钥验证
//        return verifyWithHistoricalKeys(token);
        return false;
    }

    @Override
    public Claims decodePayload(String token) {
        if (StringUtils.isBlank(token)) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        // 先尝试用当前密钥解析
        if (activeKeyId != null) {
            try {
                KeyPair keyPair = versionKeyPairs.get(activeKeyId);
                if (keyPair != null) {
                    return Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token).getPayload();
                }
            } catch (JwtException e) {
                log.error("Failed to decode with active key: {}", e.getMessage());
            }
        }

        // 尝试用所有密钥解析
        for (Map.Entry<String, KeyPair> entry : versionKeyPairs.entrySet()) {
            try {
                return Jwts.parser().verifyWith(entry.getValue().getPublic()).build().parseSignedClaims(token).getPayload();
            } catch (JwtException e) {
                // 继续尝试下一个密钥
            }
        }

        throw new SecurityException("ECDSA JWT validation failed with all available keys");
    }

    @Override
    public EcdsaJwt autoLoadFirstKey() {
        return autoLoadFirstKey(null, null, false);
    }

    @Override
    public EcdsaJwt autoLoadFirstKey(Algorithm algorithm, String preferredKeyId, boolean force) {
        Jwt autoed = autoLoadKey(preferredKeyId);
        if (autoed != null) return (EcdsaJwt) autoed;
        String tag = (algorithm == null) ? null : algorithm.name().toUpperCase();
        if (!force && !hasKeyFilesInDirectory(tag)) {
            log.warn("No {} EC key directory found under {}", tag == null ? "" : " " + tag, currentKeyPath);
            this.activeKeyId = null;
            return this;
        }
        loadFirstKeyFromDirectory(force ? null : tag);
        return this;
    }

    // 新增：检查是否有指定算法的密钥目录
    private boolean hasKeyFilesInDirectory(String tag) {
        return findKeyDir(tag).isPresent();
    }

    // 新增：从目录加载第一个密钥（支持按算法筛选）
    private void loadFirstKeyFromDirectory(String tag) {
        findKeyDir(tag).ifPresentOrElse(
                dir -> setActiveKey(dir.getFileName().toString()),
                () -> log.error("No{} key directory found under {}", tag == null ? "" : " " + tag, currentKeyPath)
        );
    }

    // 新增：查找密钥目录（类似HmacJwt的实现）
    private Optional<Path> findKeyDir(String tag) {
        if (!Files.exists(currentKeyPath)) return Optional.empty();
        Predicate<Path> filter = directoriesContainingTag(tag);
        // ECDSA需要检查私钥和公钥文件
        filter = filter.and(dir ->
                Files.exists(dir.resolve("private.key")) &&
                        Files.exists(dir.resolve("public.key"))
        );

        try (Stream<Path> dirs = Files.list(currentKeyPath)) {
            return dirs.filter(filter)
                    .filter(dir -> !getDirTimestamp(dir).equals(LocalDateTime.MIN))
                    .max(Comparator.comparing(this::getDirTimestamp));
        } catch (IOException e) {
            log.error("Failed to scan directory: {}", e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
        validateEcdsaAlgorithm(algorithm);

        if (activeKeyId == null) {
            throw new IllegalStateException("No active ECDSA key. Call setActiveKey or rotateKey first.");
        }

        KeyPair keyPair = versionKeyPairs.get(activeKeyId);
        if (keyPair == null) {
            throw new IllegalStateException("Active ECDSA key not found: " + activeKeyId);
        }

        return generateEcdsaJwt(properties, customClaims, algorithm, keyPair);
    }

    @Override
    public void close() {
        cleanup();
    }

    protected void cleanup() {
        versionKeyPairs.clear();
        keyIdToAlgorithm.clear();
        activeKeyId = null;
        keyVersions.clear();
        activeKeyId = null;
    }

    @Override
    public String generateJwt(JwtProperties properties, Algorithm algorithm) {
        return generateJwt(properties, null, algorithm);
    }

    @Override
    protected MacAlgorithm getSignAlgorithm(Algorithm algorithm) {
        throw new UnsupportedOperationException("ECDSA algorithm uses SignatureAlgorithm, not MacAlgorithm");
    }

    @Override
    public String getSecretKey() {
        throw new IllegalStateException("Secret key access not allowed");
    }

    @Override
    protected String getSecretKey(Algorithm algorithm) {
        throw new IllegalStateException("Secret key access not allowed");
    }

    @Override
    public PublicKey getPublicKey() {
        if (activeKeyId == null) return null;
        KeyPair keyPair = versionKeyPairs.get(activeKeyId);
        return keyPair != null ? keyPair.getPublic() : null;
    }

    @Override
    public PublicKey getPublicKey(Algorithm algorithm) {
        validateEcdsaAlgorithm(algorithm);
        return getPublicKey();
    }

    @Override
    public String getCurveInfo(Algorithm algorithm) {
        validateEcdsaAlgorithm(algorithm);
        if (activeKeyId != null) {
            KeyPair keyPair = versionKeyPairs.get(activeKeyId);
            if (keyPair != null && keyPair.getPublic() instanceof ECPublicKey ecPublicKey) {
                ECParameterSpec params = ecPublicKey.getParams();
                AlgorithmConfig config = getAlgorithmConfig(algorithm);
                return String.format("%s - Curve: %s, Key Size: %d", algorithm, config.curveName, params.getCurve().getField().getFieldSize());
            }
        }
        return algorithm + " - Curve information not available";
    }

    @Override
    public boolean generateAllKeyPairs() {
        return ALGORITHM_CONFIGS.keySet().stream()
                .allMatch(algorithm -> rotateKey(algorithm, generateKeyVersionId(algorithm)));
    }

    @Override
    public String getKeyInfo() {
        return String.format("ECDSA Keys - Active: %s, Total versions: %d, Key rotation: %s",
                activeKeyId, versionKeyPairs.size(), keyRotationEnabled ? "enabled" : "disabled");
    }

    @Override
    public String getAlgorithmInfo() {
        return "ECDSA algorithms: ES256 (P-256), ES384 (P-384), ES512 (P-521) with key rotation support";
    }


    protected void loadKeyVersion(Path versionDir) {
        try {
            String keyId = versionDir.getFileName().toString();
            // 检查是否活跃
            boolean isActive = Files.exists(versionDir.resolve(".active"));
            KeyPair keyPair = loadKeyPairFromDir(versionDir);
            if (keyPair == null) {
                log.warn("KeyPair is null for directory: {}", versionDir);
            } else {
                versionKeyPairs.put(keyId, keyPair);

                // 从文件读取算法信息
                Algorithm algorithm = getAlgorithmFromDir(versionDir);
                keyIdToAlgorithm.put(keyId, algorithm);

                // 创建密钥版本信息
                KeyVersion version = new KeyVersion(keyId, algorithm, versionDir.toString());
                version.setActive(isActive);
                version.setCreatedTime(getCreationTimeFromDir(versionDir));

                if (isActive) {
                    version.setActivatedTime(LocalDateTime.now());
                    this.activeKeyId = keyId;
                }

                keyVersions.put(keyId, version);
                log.debug("Loaded ECDSA key version: {}, active: {}, algorithm: {}",
                        keyId, isActive, algorithm);
            }
        } catch (Exception e) {
            log.warn("Failed to load key version from {}: {}", versionDir, e.getMessage());
        }
    }

    private String generateEcdsaJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm, KeyPair keyPair) {
        JwtBuilder builder = createJwtBuilder(properties, customClaims);
        return builder.signWith(keyPair.getPrivate(), getEcdsaSignAlgorithm(algorithm)).compact();
    }

    private SignatureAlgorithm getEcdsaSignAlgorithm(Algorithm algorithm) {
        return switch (algorithm) {
            case ES256 -> Jwts.SIG.ES256;
            case ES384 -> Jwts.SIG.ES384;
            case ES512 -> Jwts.SIG.ES512;
            default -> throw new IllegalStateException("Unsupported ECDSA algorithm: " + algorithm);
        };
    }

    private KeyPair loadKeyPairFromDir(Path versionDir) throws Exception {
        Path privateKeyPath = versionDir.resolve("private.key");
        Path publicKeyPath = versionDir.resolve("public.key");

        if (!Files.exists(privateKeyPath) || !Files.exists(publicKeyPath)) {
            return null;
        }

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        byte[] publicKeyBytes = Files.readAllBytes(publicKeyPath);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        return new KeyPair(publicKey, privateKey);
    }

    private Algorithm getAlgorithmFromDir(Path versionDir) throws IOException {
        Path algorithmFile = versionDir.resolve("algorithm.info");
        if (Files.exists(algorithmFile)) {
            String algorithmStr = Files.readString(algorithmFile, StandardCharsets.UTF_8).trim();
            try {
                return Algorithm.valueOf(algorithmStr);
            } catch (IllegalArgumentException e) {
                // 默认为ES256
            }
        }
        return Algorithm.ES256;
    }

    private void loadLegacyKeyPairs() {
        try {
            // 使用 try-with-resources 管理 Stream 资源
            try (var paths = Files.list(currentKeyPath)) {
                paths.filter(Files::isRegularFile)
                        .filter(file -> file.getFileName().toString().endsWith("private.key"))
                        .forEach(this::migrateLegacyKeyPair);
            }
        } catch (IOException e) {
            log.debug("No legacy keys found or failed to scan: {}", e.getMessage());
        }
    }

    private void migrateLegacyKeyPair(Path legacyPrivateKey) {
        try {
            String filename = legacyPrivateKey.getFileName().toString();
            String baseName = filename.replace("-private.key", "");

            // 判断算法
            Algorithm algorithm = determineAlgorithmFromFilename(baseName);
            Path legacyPublicKey = legacyPrivateKey.getParent().resolve(baseName + "-public.key");

            if (Files.exists(legacyPublicKey)) {
                KeyPair keyPair = loadKeyPairFromPaths(legacyPrivateKey, legacyPublicKey);
                if (keyPair != null) {
                    // 迁移到版本化格式
                    String keyId = KEY_VERSION_PREFIX + LocalDateTime.now().format(
                            java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + "-legacy";

                    migrateToVersioned(keyId, keyPair, algorithm, legacyPrivateKey, legacyPublicKey);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to migrate legacy key {}: {}", legacyPrivateKey, e.getMessage());
        }
    }

    private Algorithm determineAlgorithmFromFilename(String baseName) {
        if (baseName.contains("es256")) return Algorithm.ES256;
        if (baseName.contains("es384")) return Algorithm.ES384;
        if (baseName.contains("es512")) return Algorithm.ES512;
        return Algorithm.ES256; // 默认
    }

    private KeyPair loadKeyPairFromPaths(Path privateKeyPath, Path publicKeyPath) throws Exception {
        if (!Files.exists(privateKeyPath) || !Files.exists(publicKeyPath)) {
            return null;
        }

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        byte[] publicKeyBytes = Files.readAllBytes(publicKeyPath);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        return new KeyPair(publicKey, privateKey);
    }

    private void migrateToVersioned(String keyId, KeyPair keyPair, Algorithm algorithm, Path legacyPrivateKey, Path legacyPublicKey) throws IOException {
        Path versionDir = currentKeyPath.resolve(keyId);
        Files.createDirectories(versionDir);

        // 复制密钥文件
        Path newPrivateKey = versionDir.resolve("private.key");
        Path newPublicKey = versionDir.resolve("public.key");

        Files.copy(legacyPrivateKey, newPrivateKey);
        Files.copy(legacyPublicKey, newPublicKey);

        setRestrictiveFilePermissions(newPrivateKey);

        // 保存算法信息
        Path algorithmFile = versionDir.resolve("algorithm.info");
        Files.writeString(algorithmFile, algorithm.name());

        // 标记为活跃
        Files.createFile(versionDir.resolve(".active"));

        // 添加到版本管理
        versionKeyPairs.put(keyId, keyPair);
        keyIdToAlgorithm.put(keyId, algorithm);

        KeyVersion version = new KeyVersion(keyId, algorithm, versionDir.toString());
        version.setActive(true);
        version.setCreatedTime(LocalDateTime.now());
        version.setActivatedTime(LocalDateTime.now());

        keyVersions.put(keyId, version);
        this.activeKeyId = keyId;

        log.info("Migrated legacy ECDSA key to versioned format: {}", keyId);
    }

    private AlgorithmConfig getAlgorithmConfig(Algorithm algorithm) {
        AlgorithmConfig config = ALGORITHM_CONFIGS.get(algorithm);
        if (config == null) {
            throw new IllegalArgumentException("Unsupported ECDSA algorithm: " + algorithm);
        }
        return config;
    }

    @Override
    protected void setRestrictiveFilePermissions(Path path) {
        try {
            if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
                Files.setPosixFilePermissions(path, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
            } else {
                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    Files.setAttribute(path, "dos:hidden", true);
                }
            }
        } catch (Exception e) {
            log.debug("Failed to set restrictive permissions: {}", e.getMessage());
        }
    }

    private record AlgorithmConfig(String curveName) {
    }
}
