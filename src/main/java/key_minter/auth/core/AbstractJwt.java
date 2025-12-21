package key_minter.auth.core;

import key_minter.model.dto.JwtProperties;
import key_minter.model.dto.Algorithm;
import key_minter.model.dto.KeyVersion;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.StringUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Getter
@Slf4j
public abstract class AbstractJwt implements Jwt {
    protected final Map<String, KeyVersion> keyVersions = new ConcurrentHashMap<>();
    protected static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    protected static final int DEFAULT_RSA_KEY_SIZE = 2048;
    protected static final int DEFAULT_HMAC_KEY_LENGTH = 64;
    protected static final int MIN_HMAC_KEY_LENGTH = 32;
    protected boolean keyRotationEnabled = false;
    protected String activeKeyId;
    protected Path currentKeyPath;
    private final ReentrantLock activeKeyLock = new ReentrantLock();

    // 构造方法初始化
    protected AbstractJwt(Path keyDir) {
        this.currentKeyPath = keyDir;
        initializeKeyVersions();
    }

    protected AbstractJwt() {
    }

    @Override
    public String generateToken(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
        validateJwtProperties(properties);
        validateAlgorithm(algorithm);
        if (algorithm.isHmac()) {
            validateHmacAlgorithm(algorithm);
        } else if (algorithm.isRsa()) {
            validateRsaAlgorithm(algorithm);
        } else if (algorithm.isEcdsa()) {
            validateEcdsaAlgorithm(algorithm);
        } else if (algorithm.isEddsa()) {
            validateEddsaAlgorithm(algorithm);
        }
        return generateJwt(properties, customClaims, algorithm);
    }

    // 添加重载方法
    @Override
    public String generateToken(JwtProperties properties, Algorithm algorithm) {
        return generateToken(properties, null, algorithm);
    }

    public abstract boolean verifyToken(String token);

    public abstract Claims decodePayload(String token);

    @Override
    public String refreshToken(String token) {
        log.warn("Token refresh not implemented");
        return null;
    }

    @Override
    public boolean revokeToken(String token) {
        log.warn("Token revocation not implemented");
        return false;
    }

    @Override
    public boolean manageSecret(String secret) {
        log.warn("Secret management not implemented");
        return false;
    }

    // 密钥轮换的默认实现（子类可以覆盖）
    @Override
    public boolean rotateKey(Algorithm algorithm) {
        if (!isKeyRotationSupported()) {
            throw new UnsupportedOperationException("Key rotation is not enabled");
        }
        return rotateKey(algorithm, generateKeyVersionId(algorithm));
    }

    @Override
    public boolean rotateKey(Algorithm algorithm, String newKeyIdentifier) {
        if (!isKeyRotationSupported()) {
            throw new UnsupportedOperationException("Key rotation is not enabled");
        }
        log.warn("Key rotation not implemented for this algorithm");
        return false;
    }

    @Override
    public List<String> getKeyVersions() {
        return new ArrayList<>(keyVersions.keySet());
    }

    @Override
    public List<String> getKeyVersions(Algorithm algorithm) {
        if (keyVersions.isEmpty()) {
            return Collections.emptyList();
        } else {
            return keyVersions.values()
                    .stream()
                    .filter(v -> v.getAlgorithm() == algorithm)
                    .map(KeyVersion::getKeyId)
                    .collect(Collectors.toList());
        }
    }

    @Override
    public boolean setActiveKey(String keyId) {
        activeKeyLock.lock();
        try {
            if (!keyVersions.containsKey(keyId)) {
                log.error("Key version not found: {}", keyId);
                return false;
            }
            if (activeKeyId != null) {
                KeyVersion oldActive = keyVersions.get(activeKeyId);
                oldActive.setActive(false);
                oldActive.setExpiredTime(LocalDateTime.now().plusDays(7));
            }
            KeyVersion newActive = keyVersions.get(keyId);
            newActive.setActive(true);
            newActive.setActivatedTime(LocalDateTime.now());
            activeKeyId = keyId;
            loadKeyPair(keyId);
            return true;
        } finally {
            activeKeyLock.unlock();
        }
    }

    @Override
    public String getActiveKeyId() {
        return activeKeyId;
    }

    // 密钥轮换相关辅助方法
    public String generateKeyVersionId(Algorithm algorithm) {
        return algorithm.name() + "-v" + LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) +
                "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    protected void loadKeyPair(String keyId) {
        // 默认实现，子类应该覆盖
        log.warn("loadKeyPair not implemented for key version: {}", keyId);
    }

    // 新增：验证目录路径安全性
    protected void validateDirectoryPath(Path path) {
        // 防止目录遍历攻击
        Path normalized = path.normalize();
        if (!normalized.equals(path)) {
            throw new SecurityException("Invalid directory path: " + path);
        }
        // 防止符号链接攻击
        if (Files.isSymbolicLink(path)) {
            throw new SecurityException("Symbolic links are not allowed: " + path);
        }
    }

    protected boolean isKeyRotationSupported() {
        return keyRotationEnabled;
    }

    protected void enableKeyRotation() {
        this.keyRotationEnabled = true;
    }

    protected void disableKeyRotation() {
        this.keyRotationEnabled = false;
    }

    protected boolean saveKeyVersion(KeyVersion version) {
        // 默认实现，子类应该覆盖
        return false;
    }

    protected void initializeKeyVersions() {
        if (currentKeyPath != null) {
            loadExistingKeyVersions();
        }
    }

    protected void loadExistingKeyVersions() {
        log.debug("Default implementation does not load existing key versions");
    }

    // 添加验证所有密钥的方法（用于验证历史令牌）
    protected boolean verifyWithHistoricalKeys(String token) {
        int attempts = 0;
        for (String keyId : keyVersions.keySet()) {
            try {
                if (verifyWithKeyVersion(keyId, token)) {
                    return true;
                }
            } catch (Exception e) {
                // 继续尝试下一个密钥
                log.debug("Token verification failed with key {}: {}", keyId, e.getMessage());
            }
            attempts++;
            if (attempts >= 5) {
                break;
            }
        }
        return false;
    }

    protected abstract boolean verifyWithKeyVersion(String keyId, String token);

    // 获取当前活跃的密钥
    protected abstract Object getCurrentKey();

    // 通过keyId获取密钥
    protected abstract Object getKeyByVersion(String keyId);

    public abstract String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm);

    public abstract String generateJwt(JwtProperties properties, Algorithm algorithm);

    protected void validateJwtProperties(JwtProperties properties) {
        if (properties == null) {
            throw new IllegalArgumentException("JwtProperties cannot be null");
        }
        if (StringUtils.isBlank(properties.getSubject())) {
            throw new IllegalArgumentException("JWT subject cannot be null or empty");
        }
        if (properties.getExpiration() == null || properties.getExpiration() <= 0) {
            throw new IllegalArgumentException("JWT expiration must be positive");
        }
        if (StringUtils.isBlank(properties.getIssuer())) {
            throw new IllegalArgumentException("JWT issuer cannot be null or empty");
        }
    }

    protected JwtBuilder createJwtBuilder(JwtProperties properties, Map<String, Object> customClaims) {
        long now = System.currentTimeMillis();
        JwtBuilder builder = Jwts.builder()
                .subject(properties.getSubject())
                .issuer(properties.getIssuer())
                .issuedAt(new Date(now))
                .expiration(new Date(now + properties.getExpiration()));

        if (customClaims != null && !customClaims.isEmpty()) {
            builder.claims(customClaims);
        }
        return builder;
    }

    @Override
    public List<KeyVersion> listAllKeys(String directory) {
        if (directory == null) return Collections.emptyList();
        Path baseDir = Paths.get(directory);
        if (!Files.exists(baseDir) || !Files.isDirectory(baseDir)) return Collections.emptyList();
        List<KeyVersion> keys = new ArrayList<>();

        try (Stream<Path> typeDirs = Files.list(baseDir)) {
            typeDirs.filter(Files::isDirectory).forEach(typeDir -> {
                try (Stream<Path> versionDirs = Files.list(typeDir)) {
                    versionDirs.filter(Files::isDirectory).forEach(versionDir -> {
                        String keyId = versionDir.getFileName().toString();
                        // 读取算法
                        Algorithm algorithm = detectAlgorithmFromDir(typeDir.getFileName().toString(), versionDir);
                        // 是否活跃
                        boolean active = Files.exists(versionDir.resolve(".active"));
                        // 创建时间
                        LocalDateTime createdTime = parseCreationTimeFromDirName(keyId);
                        // 激活时间（如果活跃就取现在，否则为 null，可按需改为从文件读取）
                        LocalDateTime activatedTime = active ? LocalDateTime.now() : null;
                        // 过期时间（可按需扩展）
                        LocalDateTime expiredTime = null;
                        KeyVersion kv = KeyVersion.builder()
                                .keyId(keyId)
                                .algorithm(algorithm)
                                .createdTime(createdTime)
                                .activatedTime(activatedTime)
                                .expiredTime(expiredTime)
                                .active(active)
                                .keyPath(versionDir.toString())
                                .build();
                        keys.add(kv);
                    });
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        } catch (IOException e) {
            e.printStackTrace();
        }
        return keys;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> Map<String, Object> convertToClaimsMap(T customClaims) {
        if (customClaims == null) return null;

        if (customClaims instanceof Map) return (Map<String, Object>) customClaims;

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
        return "Key directory: " + (currentKeyPath != null ? currentKeyPath : "Not set") +
                ", Active key: " + activeKeyId +
                ", Key versions: " + keyVersions.size();
    }

    protected void markKeyActive(String keyId) {
        KeyVersion version = keyVersions.get(keyId);
        if (version == null) return;

        version.setActivatedTime(LocalDateTime.now());
        version.setActive(true);
        try {
            Path marker = currentKeyPath.resolve(keyId).resolve(".active");
            if (!Files.exists(marker)) Files.createFile(marker);
        } catch (IOException e) {
            log.warn("Failed to mark key active: {}", e.getMessage());
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
        return !keyVersions.isEmpty();
    }

    @Override
    public boolean keyPairExists(Algorithm algorithm) {
        return keyVersions.values().stream()
                .anyMatch(v -> v.getAlgorithm() == algorithm);
    }

    /**
     * 自动加载第一个可用的密钥（链式调用）
     *
     * @return 当前实例（用于链式调用）
     */
    @Override
    public AbstractJwt autoLoadFirstKey() {
        return autoLoadFirstKey(null, null, false);
    }

    /**
     * 自动加载密钥
     *
     * @param preferredKeyId 优先尝试加载的密钥ID（如果为null则自动选择）
     * @return 当前实例（用于链式调用）
     */
    @Override
    public AbstractJwt autoLoadFirstKey(Algorithm algorithm, String preferredKeyId, boolean force) {
        if (preferredKeyId != null && !preferredKeyId.trim().isEmpty()) {
            if (keyVersions.containsKey(preferredKeyId)) {
                boolean b = setActiveKey(preferredKeyId);
                if (!b) {
                    log.warn("Failed to set keyId: {}", preferredKeyId);
                } else {
                    return this;
                }
            } else {
                log.warn("Specified key {} not found, will auto-select", preferredKeyId);
            }
        }
        if (activeKeyId != null && keyVersions.containsKey(activeKeyId)) {
            log.info("Already have active key: {}", activeKeyId);
            return this;
        }
        Optional<KeyVersion> markedActive = findActiveByMarker();
        if (markedActive.isPresent()) {
            log.info("Found active marker for key: {}", markedActive.get().getKeyId());
            setActiveKey(markedActive.get().getKeyId());
            return this;
        }
        Optional<KeyVersion> latestKey = findLatestKey();
        if (latestKey.isPresent()) {
            String keyId = latestKey.get().getKeyId();
            log.info("Attempting to load KeyPair from disk for keyId: {}", keyId);
            loadKeyPair(keyId);
            log.info("After loadKeyPair, keyPair = {}", keyVersions);
            return this;
        }
        log.warn("No keys available for auto-load");
        return this;
    }

    /**
     * 查找有.active标记的密钥
     */
    protected Optional<KeyVersion> findActiveByMarker() {
        try {
            Path keyDir = getKeyPath();
            if (!Files.exists(keyDir)) {
                return Optional.empty();
            }

            try (Stream<Path> dirs = Files.list(keyDir)) {
                return dirs.filter(Files::isDirectory)
                        .filter(dir -> Files.exists(dir.resolve(".active")))
                        .map(dir -> keyVersions.get(dir.getFileName().toString()))
                        .filter(Objects::nonNull)
                        .findFirst();
            }
        } catch (IOException e) {
            log.debug("Failed to scan for active markers: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * 查找最新的密钥（按创建时间）
     */
    protected Optional<KeyVersion> findLatestKey() {
        return keyVersions.values().stream()
                .filter(kv -> kv.getCreatedTime() != null)
                .max(Comparator.comparing(KeyVersion::getCreatedTime));
    }

    /**
     * 获取或创建第一个可用的密钥（如果不存在则创建）
     */
    public String getOrCreateFirstKey(Algorithm algorithm) {
        // 先尝试加载
        autoLoadFirstKey( algorithm,null, false);

        if (getActiveKeyId() != null) {
            return getActiveKeyId();
        }
        // 没有密钥则创建
        log.info("No keys found, creating default key...");
        if (generateKeyPair(algorithm)) {
            // 再次尝试加载
            autoLoadFirstKey( algorithm,null, false);
            return getActiveKeyId();
        }
        throw new IllegalStateException("Failed to create default key");
    }

    public AbstractJwt withKeyDirectory(Path keyDir) {
        this.currentKeyPath = keyDir;
        initializeKeyVersions();
        return this;
    }

    public AbstractJwt withKeyDirectory(String keyDir) {
        return withKeyDirectory(keyDir != null ? Paths.get(keyDir) : null);
    }

    public AbstractJwt enableRotation() {
        this.keyRotationEnabled = true;
        return this;
    }

    public AbstractJwt disableRotation() {
        this.keyRotationEnabled = false;
        return this;
    }

    protected void validateAlgorithm(Algorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null");
        }
    }

    protected Jwt autoLoadKey(String preferredKeyId) {
        if (preferredKeyId != null && !preferredKeyId.trim().isEmpty()) {
            if (keyVersions.containsKey(preferredKeyId)) {
                setActiveKey(preferredKeyId);
                return this;
            }
            try {
                Path candidate = currentKeyPath.resolve(preferredKeyId);
                if (Files.exists(candidate) && Files.isDirectory(candidate)) {
                    loadKeyVersion(candidate);
                    if (keyVersions.containsKey(preferredKeyId)) {
                        setActiveKey(preferredKeyId);
                        return this;
                    }
                }
            } catch (Exception e) {
                log.warn("Failed to load preferred key {} from disk: {}", preferredKeyId, e.getMessage());
            }
            log.warn("Specified key {} not found", preferredKeyId);
            return this; // 没找到，也不创建新的
        }
        return null;
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
        try {
            String dirName = versionDir.getFileName().toString();
            if (dirName.contains("-v")) {
                String timestamp = dirName.substring(dirName.indexOf("-v") + 2, dirName.indexOf("-v") + 17);
                return LocalDateTime.parse(timestamp,
                        DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            }
        } catch (Exception e) {
            log.warn("Failed to parse creation time from directory name: {}", e.getMessage());
        }
        return LocalDateTime.now().minusDays(1);
    }

    protected Predicate<Path> directoriesContainingTag(String tag) {
        Predicate<Path> filter = Files::isDirectory;
        if (tag != null) {
            String upperTag = tag.toUpperCase(Locale.ROOT);
            filter = filter.and(dir -> dir.getFileName()
                    .toString()
                    .toUpperCase(Locale.ROOT)
                    .contains(upperTag));
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

    protected int getValidKeySize(Integer keySize, int defaultSize, int minSize) {
        if (keySize == null || keySize < minSize) {
            return defaultSize;
        }
        return keySize;
    }

    protected int getValidKeyLength(Integer length, int defaultLength, int minLength) {
        if (length == null || length < minLength) {
            return defaultLength;
        }
        return length;
    }

    protected abstract Object getSignAlgorithm(Algorithm algorithm);

    protected abstract String getSecretKey();

    protected String getSecretKey(Algorithm algorithm) {
        return getSecretKey();
    }
    protected KeyVersion getKeyVersion(String keyId) {
        return keyVersions.get(keyId);
    }

    protected void saveKeyPairRevision(String keyId, KeyPair keyPair, Algorithm algorithm) throws IOException {
        Path versionDir = currentKeyPath.resolve(keyId);
        Files.createDirectories(versionDir);
        Path privateKeyPath = versionDir.resolve("private.key");
        Path publicKeyPath = versionDir.resolve("public.key");
        Path tempPrivate = versionDir.resolve("private.key.tmp");
        Path tempPublic = versionDir.resolve("public.key.tmp");
        Files.write(tempPrivate, keyPair.getPrivate().getEncoded(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        Files.move(tempPrivate, privateKeyPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        Files.write(tempPublic, keyPair.getPublic().getEncoded(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        Files.move(tempPublic, publicKeyPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        setRestrictiveFilePermissions(privateKeyPath);
        Path algorithmFile = versionDir.resolve("algorithm.info");
        Files.writeString(algorithmFile, algorithm.name());
    }

    protected abstract void setRestrictiveFilePermissions(Path path);

    protected boolean isKeyVersionValid(String keyId) {
        KeyVersion version = keyVersions.get(keyId);
        return version != null && version.isValid();
    }

    protected void expireKeyVersion(String keyId) {
        KeyVersion version = keyVersions.get(keyId);
        if (version != null) {
            version.setExpiredTime(LocalDateTime.now());
            version.setActive(false);
        }
    }
    protected void writeKeyPairToFileAtomically(Path privateKeyFile, Path publicKeyFile, KeyPair keyPair) throws IOException {
        // 写入私钥
        Path tempPrivate = privateKeyFile.getParent().resolve(privateKeyFile.getFileName() + ".tmp");
        try {
            Files.write(tempPrivate, keyPair.getPrivate().getEncoded(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(tempPrivate, privateKeyFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            setRestrictiveFilePermissions(privateKeyFile);
        } finally {
            Files.deleteIfExists(tempPrivate);
        }

        // 写入公钥
        Path tempPublic = publicKeyFile.getParent().resolve(publicKeyFile.getFileName() + ".tmp");
        try {
            Files.write(tempPublic, keyPair.getPublic().getEncoded(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(tempPublic, publicKeyFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(tempPublic);
        }
    }
    // 根据密钥类型目录和算法文件判断 Algorithm
    private Algorithm detectAlgorithmFromDir(String typeDirName, Path versionDir) {
        Path algFile = versionDir.resolve("algorithm.info");
        if (Files.exists(algFile)) {
            try {
                return Algorithm.valueOf(Files.readString(algFile, StandardCharsets.UTF_8).trim());
            } catch (Exception ignored) {
            }
        }

        // 默认根据目录名推测
        return switch (typeDirName.toLowerCase()) {
            case "hmac-keys" -> Algorithm.HMAC256;
            case "rsa-keys" -> Algorithm.RSA256;
            case "ec-keys" -> Algorithm.ES256;
            case "eddsa-keys" -> Algorithm.Ed25519;
            default -> Algorithm.ES256;
        };
    }

    // 从 keyId 解析创建时间，例如 HMAC256-v20251201-225826-dcaa51c9
    private LocalDateTime parseCreationTimeFromDirName(String keyId) {
        try {
            int idx = keyId.indexOf("-v");
            if (idx != -1 && keyId.length() >= idx + 16) {
                String timestamp = keyId.substring(idx + 2, idx + 16); // 20251201-225826
                return LocalDateTime.parse(timestamp, java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            }
        } catch (Exception ignored) {
        }
        return LocalDateTime.now().minusDays(1);
    }
    @Override
    public LocalDateTime getDirTimestamp(Path dir) {
        String dirName = dir.getFileName().toString();
        try {
            int start = dirName.indexOf("-v");
            if (start != -1 && dirName.length() >= start + 17) {
                String timestamp = dirName.substring(start + 2, start + 17);
                return LocalDateTime.parse(timestamp, DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            }
        } catch (Exception ignored) {
        }
        return LocalDateTime.MIN;
    }
}
