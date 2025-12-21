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
import io.micrometer.common.util.StringUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.stream.Stream;

@Slf4j
@Getter
public class RsaJwt extends AbstractJwt {
    private static final Path DEFAULT_KEY_DIR = Paths.get(System.getProperty("user.home"), ".chao", "rsa-keys");
    private final Map<String, KeyPair> versionKeyPairs = new ConcurrentHashMap<>();
    private static final String DEFAULT_PRIVATE_KEY_FILENAME = "private.key";
    private static final String DEFAULT_PUBLIC_KEY_FILENAME = "public.key";
    private Path currentPrivateKeyPath;
    private Path currentPublicKeyPath;
    private KeyPair keyPair;

    public RsaJwt() {
        this(DEFAULT_KEY_DIR);
    }

    public RsaJwt(String directory) {
        this(Paths.get(directory), true);
    }

    public RsaJwt(Path directory) {
        this(directory, true);
    }

    public RsaJwt(Path directory, boolean enableRotation) {
        if (directory == null) {
            directory = DEFAULT_KEY_DIR;
        } else {
            // 规范化路径，防止../../../攻击
            directory = directory.normalize();
            // 验证路径是否安全
            validateDirectoryPath(directory);
            if (!directory.getFileName().toString().equals("rsa-keys")) {
                directory = directory.resolve("rsa-keys");
            }
        }
        this.currentKeyPath = directory;
        if (enableRotation) enableKeyRotation();
        initializeKeyVersions();
        this.autoLoadFirstKey();
        if (activeKeyId == null) {
            log.warn("No keys found in directory: {}", directory);
        }
    }

    @Override
    public RsaJwt autoLoadFirstKey() {
        return autoLoadFirstKey(null, null, false);
    }

    @Override
    public RsaJwt autoLoadFirstKey(Algorithm algorithm, String preferredKeyId, boolean force) {
        Jwt autoed = autoLoadKey(preferredKeyId);
        if (autoed != null) return (RsaJwt) autoed;
        String tag = (algorithm == null) ? null : algorithm.name().toUpperCase();
        if (!force && !hasKeyFilesInDirectory(tag)) {
            log.warn("No {} RSA key directory found under {}", tag == null ? "" : " " + tag, currentKeyPath);
            this.activeKeyId = null;
            this.keyPair = null;
            return this;
        }
        loadFirstKeyFromDirectory(force ? null : tag);
        return this;
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
                if (keyVersions.isEmpty()) {
                    loadLegacyKeyPair();
                }
            }
        } catch (IOException e) {
            log.error("Failed to load existing RSA key versions: {}", e.getMessage());
        }
    }

    @Override
    protected boolean isKeyVersionDir(Path dir) {
        String name = dir.getFileName().toString().toLowerCase();
        boolean hasPrivate = Files.exists(dir.resolve("private.key"));
        boolean hasPublic = Files.exists(dir.resolve("public.key"));
        boolean hasAlg = Files.exists(dir.resolve("algorithm.info"));
        boolean likeRSA = name.contains("rsa") && name.contains("-v");   // 目录名兜底
        return (hasPrivate && hasPublic) || hasAlg || likeRSA;
    }

    @Override
    public boolean generateKeyPair(Algorithm algorithm) {
        return rotateKey(algorithm, generateKeyVersionId(algorithm));
    }

    @Override
    public boolean rotateKey(Algorithm algorithm, String newKeyIdentifier) {
        validateRsaAlgorithm(algorithm);
        if (!keyRotationEnabled) throw new UnsupportedOperationException("Key rotation is not enabled");
        return AtomicKeyRotation.rotateKeyAtomic(
                newKeyIdentifier,
                currentKeyPath,
                () -> {
                    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                    int keySize = algorithm == Algorithm.RSA384 ? 3072 :
                            algorithm == Algorithm.RSA512 ? 4096 : DEFAULT_RSA_KEY_SIZE;
                    keyPairGenerator.initialize(keySize);
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
                    keyVersions.put(newKeyIdentifier, newVersion);

                    log.info("RSA key rotated successfully. New key ID: {}, algorithm: {}",
                            newKeyIdentifier, algorithm);
                }
        );
    }

    @Override
    protected void loadKeyPair(String keyId) {
        if (!versionKeyPairs.containsKey(keyId)) {
            try {
                KeyPair kp = loadKeyPairFromDir(currentKeyPath.resolve(keyId));
                if (kp != null) versionKeyPairs.put(keyId, kp);
                else throw new IllegalArgumentException("Key pair not found: " + keyId);
            } catch (Exception e) {
                throw new IllegalArgumentException("Failed to load key pair: " + keyId, e);
            }
        }
        this.keyPair = versionKeyPairs.get(keyId);
        this.activeKeyId = keyId;
        markKeyActive(keyId);
    }

    @Override
    public boolean verifyToken(String token) {
        if (StringUtils.isBlank(token)) return false;
        try {
            // 先尝试用当前活跃密钥验证
            if (keyPair != null) {
                Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token);
                return true;
            }
        } catch (JwtException | IllegalArgumentException e) {
            log.error("Token verification failed with active key: {}", e.getMessage());
        }
        return false;
    }

    @Override
    protected boolean verifyWithKeyVersion(String keyId, String token) {
        try {
            KeyPair historicalKeyPair = versionKeyPairs.get(keyId);
            if (historicalKeyPair == null) {
                // 尝试加载
                historicalKeyPair = loadKeyPairFromDir(currentKeyPath.resolve(keyId));
                if (historicalKeyPair != null) {
                    versionKeyPairs.put(keyId, historicalKeyPair);
                }
            }
            if (historicalKeyPair != null) {
                Jwts.parser().verifyWith(historicalKeyPair.getPublic()).build().parseSignedClaims(token);
                return true;
            }
        } catch (Exception e) {
            log.error("Token verification failed with key {}: {}", keyId, e.getMessage());
        }
        return false;
    }

    @Override
    protected Object getCurrentKey() {
        return keyPair;
    }

    @Override
    protected Object getKeyByVersion(String keyId) {
        return versionKeyPairs.get(keyId);
    }

    // 保留原有接口的兼容性方法
    @Override
    public boolean generateRSAKeyPair(Algorithm algorithm, Integer keySize, String privateKeyFilename, String publicKeyFilename) {
        // 使用密钥轮换的方式生成新密钥
        String newKeyId = generateKeyVersionId(algorithm);
        boolean success = rotateKey(algorithm, newKeyId);

        if (success && privateKeyFilename != null && publicKeyFilename != null) {
            try {
                // 如果需要，复制到指定文件名
                KeyPair keyPair = versionKeyPairs.get(newKeyId);
                Path targetPrivateKey = currentKeyPath.getParent()
                        .resolve(privateKeyFilename.endsWith(".key") ? privateKeyFilename : privateKeyFilename + ".key");
                Path targetPublicKey = currentKeyPath.getParent()
                        .resolve(publicKeyFilename.endsWith(".key") ? publicKeyFilename : publicKeyFilename + ".key");
//                Files.write(targetPrivateKey, keyPair.getPrivate().getEncoded());
//                Files.write(targetPublicKey, keyPair.getPublic().getEncoded());
                // 使用原子操作写入文件
                Files.createDirectories(targetPrivateKey.getParent());
                Files.createDirectories(targetPublicKey.getParent());
                writeKeyPairToFileAtomically(targetPrivateKey, targetPublicKey, keyPair);

                log.info("Exported RSA key pair to {}, {}", targetPrivateKey, targetPublicKey);
//                setRestrictiveFilePermissions(targetPrivateKey);
            } catch (Exception e) {
                log.warn("Failed to copy key files: {}", e.getMessage());
            }
        }
        return success;
    }

    @Override
    public void close() {
        cleanup();
    }

    protected void cleanup() {
        // 清理所有版本密钥
        versionKeyPairs.clear();
        // 清理当前密钥
        keyPair = null; // 对于 RsaJwt
        // 清理父类资源
        keyVersions.clear();
        activeKeyId = null;
    }

    @Override
    public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
        validateRsaAlgorithm(algorithm);
        if (keyPair == null) {
            throw new IllegalStateException("No active RSA key pair. Call setActiveKey or rotateKey first.");
        }
        return generateRsaJwt(properties, customClaims, algorithm);
    }

    @Override
    public Claims decodePayload(String token) {
        if (StringUtils.isBlank(token)) throw new IllegalArgumentException("Token cannot be null or empty");
        // 先尝试用当前密钥解析
        if (keyPair != null) {
            try {
                return Jwts.parser().verifyWith(keyPair.getPublic()).build().parseSignedClaims(token).getPayload();
            } catch (JwtException e) {
                log.error("Failed to decode with active key: {}", e.getMessage());
            }
        }
        throw new SecurityException("RSA JWT validation failed with all available keys");
    }

    @Override
    public String generateJwt(JwtProperties properties, Algorithm algorithm) {
        return generateJwt(properties, null, algorithm);
    }

    @Override
    protected MacAlgorithm getSignAlgorithm(Algorithm algorithm) {
        throw new UnsupportedOperationException("RSA algorithm uses SignatureAlgorithm, not MacAlgorithm");
    }

    @Override
    protected String getSecretKey() {
        if (keyPair == null) throw new IllegalStateException("No active RSA key pair");
        return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }

    @Override
    protected String getSecretKey(Algorithm algorithm) {
        validateRsaAlgorithm(algorithm);
        return getSecretKey();
    }

    @Override
    public PublicKey getPublicKey() {
        return keyPair != null ? keyPair.getPublic() : null;
    }

    @Override
    public PublicKey getPublicKey(Algorithm algorithm) {
        validateRsaAlgorithm(algorithm);
        return getPublicKey();
    }

    @Override
    public String getKeyInfo() {
        return String.format("RSA Keys - Active: %s, Total versions: %d, Key rotation: %s",
                activeKeyId, keyVersions.size(), keyRotationEnabled ? "enabled" : "disabled");
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

    private boolean hasKeyFilesInDirectory(String tag) {
        return findKeyDir(tag).isPresent();
    }

    private void loadFirstKeyFromDirectory(String tag) {
        findKeyDir(tag).ifPresentOrElse(
                dir -> setActiveKey(dir.getFileName().toString()),
                () -> log.error("No{} key directory found under {}",
                        tag == null ? "" : " " + tag, currentKeyPath));
    }

    private Optional<Path> findKeyDir(String tag) {
        if (!Files.exists(currentKeyPath)) return Optional.empty();
        Predicate<Path> filter = directoriesContainingTag(tag);
        // RSA 需要检查私钥和公钥文件
        filter = filter.and(dir ->
                Files.exists(dir.resolve("private.key")) &&
                        Files.exists(dir.resolve("public.key")));

        try (Stream<Path> dirs = Files.list(currentKeyPath)) {
            return dirs.filter(filter)
                    .max(Comparator.comparing(this::getDirTimestamp));
        } catch (IOException e) {
            log.error("Failed to scan directory: {}", e.getMessage());
            return Optional.empty();
        }
    }

    protected void loadKeyVersion(Path versionDir) {
        try {
            String keyId = versionDir.getFileName().toString();
            // 检查是否活跃
            boolean isActive = Files.exists(versionDir.resolve(".active"));
            // 加载密钥对
            KeyPair keyPair = loadKeyPairFromDir(versionDir);
            if (keyPair != null) {
                versionKeyPairs.put(keyId, keyPair);
                KeyVersion version = new KeyVersion(keyId, Algorithm.RSA256, versionDir.toString());
                version.setActive(isActive);
                version.setCreatedTime(getCreationTimeFromDir(versionDir));
                if (isActive) version.setActivatedTime(LocalDateTime.now());

                keyVersions.put(keyId, version);
                if (isActive) {
                    this.activeKeyId = keyId;
                    this.keyPair = keyPair;
                }
                log.info("Loaded RSA key version: {}, active: {}", keyId, isActive);
            }
        } catch (Exception e) {
            log.warn("Failed to load key version from {}: {}", versionDir, e.getMessage());
        }
    }

    private KeyPair loadKeyPairFromDir(Path versionDir) throws Exception {
        Path privateKeyPath = versionDir.resolve("private.key");
        Path publicKeyPath = versionDir.resolve("public.key");

        if (!Files.exists(privateKeyPath) || !Files.exists(publicKeyPath)) {
            return null;
        }

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        byte[] publicKeyBytes = Files.readAllBytes(publicKeyPath);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        return new KeyPair(publicKey, privateKey);
    }

    // 加载传统密钥对
    private void loadLegacyKeyPair() {
        this.currentPrivateKeyPath = currentKeyPath.resolve(DEFAULT_PRIVATE_KEY_FILENAME);
        this.currentPublicKeyPath = currentKeyPath.resolve(DEFAULT_PUBLIC_KEY_FILENAME);
        try {
            KeyPair keyPair = loadKeyPairFromPaths(currentPrivateKeyPath, currentPublicKeyPath);
            if (keyPair != null) {
                this.keyPair = keyPair;
                // 创建传统版本
                String legacyKeyId = "RSA256-v" + LocalDateTime.now()
                        .format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + "-" +
                        UUID.randomUUID().toString().substring(0, 8);

                KeyVersion version = new KeyVersion(
                        legacyKeyId,
                        Algorithm.RSA256,
                        currentPrivateKeyPath.getParent().toString()
                );
                version.setActive(true);
                version.setCreatedTime(LocalDateTime.now().minusDays(1));
                version.setActivatedTime(LocalDateTime.now());

                versionKeyPairs.put(legacyKeyId, keyPair);
                keyVersions.put(legacyKeyId, version);
                this.activeKeyId = legacyKeyId;
                log.info("Loaded legacy RSA key pair from: {}", currentPrivateKeyPath.getParent());
            } else {
                log.info("No legacy RSA key pair found at: {}. Call generateKeyPair to create one.", currentPrivateKeyPath.getParent());
            }
        } catch (Exception e) {
            log.warn("Failed to load legacy RSA key pair: {}", e.getMessage());
        }
    }

    private String generateRsaJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
        JwtBuilder builder = createJwtBuilder(properties, customClaims);
        return builder.signWith(keyPair.getPrivate(), getRsaSignAlgorithm(algorithm)).compact();
    }

    @Override
    protected void setRestrictiveFilePermissions(Path path) {
        try {
            if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
                Files.setPosixFilePermissions(path,
                        EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
                log.debug("Set POSIX permissions 600 for: {}", path);
            } else {
                log.warn("POSIX permissions not supported on this filesystem. Please set restrictive permissions for: {}", path);
                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    Files.setAttribute(path, "dos:hidden", true);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to set restrictive permissions for {}: {}", path, e.getMessage());
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

    // 辅助方法
    private KeyPair loadKeyPairFromPaths(Path privateKeyPath, Path publicKeyPath) throws Exception {
        if (!Files.exists(privateKeyPath) || !Files.exists(publicKeyPath)) {
            return null;
        }
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyPath);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        return new KeyPair(publicKey, privateKey);
    }
}
