package key_minter.auth.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import key_minter.auth.core.AbstractJwt;
import key_minter.auth.core.Jwt;
import key_minter.model.dto.Algorithm;
import key_minter.model.dto.JwtProperties;
import key_minter.model.dto.KeyVersion;
import key_minter.util.AtomicKeyRotation;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.stream.Stream;

@Slf4j
public class EddsaJwt extends AbstractJwt {
    private static final Path DEFAULT_KEY_DIR = Paths.get(System.getProperty("user.home"), ".chao", "eddsa-keys");
    private final Map<String, OctetKeyPair> versionKeyPairs = new ConcurrentHashMap<>();
    private final Map<String, Algorithm> keyIdToAlgorithm = new ConcurrentHashMap<>();
    private static final String KEY_VERSION_PREFIX = "ed";
    private static final Map<Algorithm, AlgorithmConfig> ALGORITHM_CONFIGS = Map.of(
            Algorithm.Ed25519, new AlgorithmConfig(Curve.Ed25519, "Ed25519"),
            Algorithm.Ed448, new AlgorithmConfig(Curve.Ed448, "Ed448")
    );

    static {
        registerBouncyCastle();
    }

    private static void registerBouncyCastle() {
        try {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
                log.info("BouncyCastle provider registered successfully");
            }
        } catch (Exception e) {
            log.error("Failed to register BouncyCastle provider: {}", e.getMessage());
            throw new RuntimeException("BouncyCastle initialization failed", e);
        }
    }

    public EddsaJwt() {
        this(DEFAULT_KEY_DIR);
    }

    public EddsaJwt(Path keyDir) {
        this(keyDir, true);
    }

    public EddsaJwt(Path keyDir, boolean enableRotation) {
        if (keyDir == null) {
            keyDir = DEFAULT_KEY_DIR;
        } else {
            // 规范化路径，防止../../../攻击
            keyDir = keyDir.normalize();
            // 验证路径是否安全
            validateDirectoryPath(keyDir);
            if (!keyDir.getFileName().toString().equals("eddsa-keys")) {
                keyDir = keyDir.resolve("eddsa-keys");
            }
        }
        this.currentKeyPath = keyDir;
        if (enableRotation) enableKeyRotation();
        initializeKeyVersions();
        if (activeKeyId == null) log.warn("No keys found in directory: {}", keyDir);

    }

    public EddsaJwt(String directory) {
        this(StringUtils.isBlank(directory) ? DEFAULT_KEY_DIR : Paths.get(directory), true);
    }

    @Override
    public boolean generateKeyPair(Algorithm algorithm) {
        return rotateKey(algorithm, generateKeyVersionId(algorithm));
    }

    @Override
    public EddsaJwt autoLoadFirstKey() {
        return autoLoadFirstKey(null, null, false);
    }

    @Override
    public boolean generateKeyPair(Algorithm algorithm, String customFilename) {
        String keyId = generateKeyVersionId(algorithm);
        boolean success = rotateKey(algorithm, keyId);
        if (success && customFilename != null) {
            try {
                OctetKeyPair keyPair = versionKeyPairs.get(keyId);
                String filename = customFilename.contains(".") ? customFilename : customFilename + ".jwk";
                Path targetPath = currentKeyPath.getParent().resolve(filename);
                // 使用原子操作写入文件
                Files.createDirectories(targetPath.getParent());
                writeJwkToFileAtomically(targetPath, keyPair);

                log.info("Exported EdDSA key to: {}", targetPath);
            } catch (Exception e) {
                log.warn("Failed to copy key file: {}", e.getMessage());
            }
        }
        return success;
    }

    // 新增：原子性写入 JWK 文件
    private void writeJwkToFileAtomically(Path targetFile, OctetKeyPair keyPair) throws IOException {
        Path tempFile = targetFile.getParent().resolve(targetFile.getFileName() + ".tmp");
        try {
            Files.writeString(tempFile, keyPair.toJSONString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(tempFile, targetFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            setRestrictiveFilePermissions(targetFile);
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    @Override
    public EddsaJwt autoLoadFirstKey(Algorithm algorithm, String preferredKeyId, boolean force) {
        Jwt autoed = autoLoadKey(preferredKeyId);
        if (autoed != null) return (EddsaJwt) autoed;
        String tag = (algorithm == null) ? null : algorithm.name().toUpperCase();
        if (!force && !hasKeyFilesInDirectory(tag)) {
            log.warn("No {} ED key directory found under {}", tag == null ? "" : " " + tag, currentKeyPath);
            this.activeKeyId = null;
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
                            .filter(dir -> dir.getFileName().toString().toLowerCase().startsWith(KEY_VERSION_PREFIX))
                            .forEach(this::loadKeyVersion);
                }
                if (versionKeyPairs.isEmpty()) {
                    loadLegacyKeyPairs();
                }
            }
        } catch (IOException e) {
            log.error("No legacy keys found or failed to scan: {}", e.getMessage());
        }
    }

    @Override
    protected boolean isKeyVersionDir(Path dir) {
        String name = dir.getFileName().toString().toLowerCase();
        boolean hasJwk = Files.exists(dir.resolve("key.jwk"));   // 唯一关键文件
        boolean hasAlg = Files.exists(dir.resolve("algorithm.info"));
        boolean likeEd = name.contains("ed") && name.contains("-v");
        return hasJwk || hasAlg || likeEd;
    }

    private boolean hasKeyFilesInDirectory(String tag) {
        return findKeyDir(tag).isPresent();
    }

    private void loadFirstKeyFromDirectory(String tag) {
        findKeyDir(tag).ifPresentOrElse(
                dir -> setActiveKey(dir.getFileName().toString()),
                () -> log.error("No{} key directory found under {}", tag == null ? "" : " " + tag, currentKeyPath)
        );
    }

    private Optional<Path> findKeyDir(String tag) {
        if (!Files.exists(currentKeyPath)) return Optional.empty();
        Predicate<Path> filter = directoriesContainingTag(tag);

        filter = filter.and(dir -> Files.exists(dir.resolve("key.jwk")));

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
    public boolean rotateKey(Algorithm algorithm, String newKeyIdentifier) {
        validateEddsaAlgorithm(algorithm);
        if (!keyRotationEnabled) throw new UnsupportedOperationException("Key rotation is not enabled");
        return AtomicKeyRotation.rotateKeyAtomic(
                newKeyIdentifier,
                currentKeyPath,
                () -> {
                    OctetKeyPair keyPair;

                    if (algorithm == Algorithm.Ed25519) {
                        try {
                            keyPair = new OctetKeyPairGenerator(Curve.Ed25519)
                                    .keyID(newKeyIdentifier)
                                    .generate();
                        } catch (Exception e) {
                            log.warn("Nimbus Ed25519 generation failed, using BC: {}", e.getMessage());
                            keyPair = generateKeyPairWithBC(algorithm, newKeyIdentifier);
                        }
                    } else {
                        keyPair = generateKeyPairWithBC(algorithm, newKeyIdentifier);
                    }
                    return keyPair;
                },
                (keyPair, tempDir) -> {
                    // 保存JWK文件
                    Path keyFile = tempDir.resolve("key.jwk");
                    Files.writeString(keyFile, keyPair.toJSONString(), StandardCharsets.UTF_8,
                            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

                    // 保存算法信息
                    Path algorithmFile = tempDir.resolve("algorithm.info");
                    Files.writeString(algorithmFile, algorithm.name());

                    // 设置文件权限
                    setRestrictiveFilePermissions(keyFile);
                },
                (keyPair) -> {
                    KeyVersion newVersion = new KeyVersion(newKeyIdentifier, algorithm,
                            currentKeyPath.resolve(newKeyIdentifier).toString());
                    newVersion.setCreatedTime(LocalDateTime.now());

                    versionKeyPairs.put(newKeyIdentifier, keyPair);
                    keyIdToAlgorithm.put(newKeyIdentifier, algorithm);
                    keyVersions.put(newKeyIdentifier, newVersion);

                    log.info("EdDSA key rotated successfully. New key ID: {}, algorithm: {}, curve: {}",
                            newKeyIdentifier, algorithm, getAlgorithmConfig(algorithm).curve().getName());
                }
        );
    }

    private OctetKeyPair generateKeyPairWithBC(Algorithm algorithm, String keyId) {
        AlgorithmConfig config = getAlgorithmConfig(algorithm);
        Ed448KeyPairGenerator kpg = new Ed448KeyPairGenerator();
        kpg.init(new Ed448KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair bcKP = kpg.generateKeyPair();
        byte[] d = ((Ed448PrivateKeyParameters) bcKP.getPrivate()).getEncoded();
        byte[] x = ((Ed448PublicKeyParameters) bcKP.getPublic()).getEncoded();
        return new OctetKeyPair.Builder(config.curve, Base64URL.encode(x))
                .d(Base64URL.encode(d))
                .keyID(keyId)
                .algorithm(JWSAlgorithm.EdDSA)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .build();
    }

    @Override
    protected void loadKeyPair(String keyId) {
        if (!versionKeyPairs.containsKey(keyId)) {
            try {
                Path versionDir = currentKeyPath.resolve(keyId);
                OctetKeyPair keyPair = loadKeyPairFromDir(versionDir);
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
    public boolean verifyToken(String token) {
        if (StringUtils.isBlank(token)) return false;
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            // 先尝试用当前活跃密钥验证
            if (activeKeyId != null) {
                OctetKeyPair activeKeyPair = versionKeyPairs.get(activeKeyId);
                if (activeKeyPair != null) {
                    return verifyWithKey(activeKeyPair, signedJWT);
                }
            }
            return false;
        } catch (Exception e) {
            log.debug("EdDSA JWT verification failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    protected boolean verifyWithKeyVersion(String keyId, String token) {
        try {
            OctetKeyPair keyPair = versionKeyPairs.get(keyId);
            if (keyPair == null) {
                keyPair = loadKeyPairFromDir(currentKeyPath.resolve(keyId));
                if (keyPair != null) {
                    versionKeyPairs.put(keyId, keyPair);
                }
            }
            if (keyPair != null) {
                SignedJWT signedJWT = SignedJWT.parse(token);
                return verifyWithKey(keyPair, signedJWT);
            }
        } catch (Exception e) {
            log.debug("Token verification failed with key {}: {}", keyId, e.getMessage());
        }
        return false;
    }

    private boolean verifyWithKey(OctetKeyPair keyPair, SignedJWT signedJWT) {
        try {
            String curveName = keyPair.getCurve().getName();
            if (Curve.Ed25519.getName().equals(curveName)) {
                return verifyEd25519(keyPair, signedJWT);
            } else if (Curve.Ed448.getName().equals(curveName)) {
                return verifyEd448(keyPair, signedJWT);
            } else {
                log.warn("Unsupported curve: {}", curveName);
                return false;
            }
        } catch (Exception e) {
            log.debug("JWT verification failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean verifyEd25519(OctetKeyPair keyPair, SignedJWT signedJWT) throws Exception {
        try {
            // 从 JWK 获取公钥的 x 值
            byte[] x = keyPair.getDecodedX();
            if (x == null) {
                throw new Exception("No public key (x) found in JWK");
            }

            // 确保是 32 字节的 Ed25519 公钥
            if (x.length != 32) {
                throw new Exception("Invalid Ed25519 public key length: " + x.length);
            }

            byte[] signingInput = signedJWT.getSigningInput();
            byte[] signatureBytes = signedJWT.getSignature().decode();

            // 使用 BouncyCastle 验证
            Ed25519PublicKeyParameters publicKeyParams = new Ed25519PublicKeyParameters(x, 0);
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, publicKeyParams);
            verifier.update(signingInput, 0, signingInput.length);

            return verifier.verifySignature(signatureBytes);
        } catch (Exception e) {
            throw new Exception("Ed25519 verification failed: " + e.getMessage(), e);
        }
    }

    private boolean verifyEd448(OctetKeyPair keyPair, SignedJWT signedJWT) {
        try {
            // 从 JWK 获取公钥的 x 值
            byte[] x = keyPair.getDecodedX();
            // 确保是 57 字节的 Ed448 公钥
            if (x == null || x.length != 57) {
                log.warn("Skip non-Ed448 public key, len={}", x == null ? "null" : x.length);
                return false;
            }
            byte[] signingInput = signedJWT.getSigningInput();
            byte[] signatureBytes = signedJWT.getSignature().decode();

            // 使用 BouncyCastle 验证
            Ed448PublicKeyParameters publicKeyParams = new Ed448PublicKeyParameters(x, 0);
            Ed448Signer verifier = new Ed448Signer(new byte[0]);
            verifier.init(false, publicKeyParams);
            verifier.update(signingInput, 0, signingInput.length);

            return verifier.verifySignature(signatureBytes);
        } catch (Exception e) {
            log.error("Ed448 verification failed: {}", e.getMessage(), e);
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
    public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
        validateEddsaAlgorithm(algorithm);

        if (activeKeyId == null) {
            throw new IllegalStateException("No active EdDSA key. Call setActiveKey or rotateKey first.");
        }

        OctetKeyPair keyPair = versionKeyPairs.get(activeKeyId);
        if (keyPair == null) {
            throw new IllegalStateException("Active EdDSA key not found: " + activeKeyId);
        }

        return generateJwtInternal(properties, customClaims, keyPair);
    }

    private String generateJwtInternal(JwtProperties properties, Map<String, Object> customClaims, OctetKeyPair keyPair) {
        validateJwtProperties(properties);
        try {
            JWTClaimsSet claimsSet = buildClaimsSet(properties, customClaims);
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(keyPair.getKeyID()).build();
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            String curveName = keyPair.getCurve().getName();
            if (Curve.Ed25519.getName().equals(curveName)) {
                signedJWT.sign(createEd25519Signer(keyPair));
            } else if (Curve.Ed448.getName().equals(curveName)) {
                signedJWT.sign(createEd448Signer(keyPair));
            } else {
                throw new IllegalArgumentException("Unsupported curve: " + curveName);
            }
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate EdDSA JWT", e);
        }
    }

    // 创建 Ed25519 签名器
    private JWSSigner createEd25519Signer(OctetKeyPair keyPair) {
        try {
            // 方法1：尝试使用 Nimbus 的 Ed25519Signer（如果存在）
            try {
                Class<?> ed25519SignerClass = Class.forName("com.nimbusds.jose.crypto.Ed25519Signer");
                return (JWSSigner) ed25519SignerClass.getConstructor(OctetKeyPair.class)
                        .newInstance(keyPair);
            } catch (ClassNotFoundException e) {
                // 如果类不存在，使用自定义实现
                return new CustomEd25519Signer(keyPair);
            }
        } catch (Exception e) {
            log.warn("Failed to create Ed25519 signer: {}", e.getMessage());
            return new CustomEd25519Signer(keyPair);
        }
    }

    // 自定义 Ed25519 签名器
    private record CustomEd25519Signer(OctetKeyPair keyPair) implements JWSSigner {

        @Override
        public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
            try {
                // 获取私钥
                PrivateKey privateKey = keyPair.toPrivateKey();
                byte[] privateKeyBytes = privateKey.getEncoded();

                // 提取裸私钥（种子）
                byte[] seed = extractEdPrivateKey(privateKeyBytes);

                // 使用 BouncyCastle 进行 Ed25519 签名
                Ed25519PrivateKeyParameters privateKeyParams = new Ed25519PrivateKeyParameters(seed, 0);
                Ed25519Signer signer = new Ed25519Signer();
                signer.init(true, privateKeyParams);
                signer.update(signingInput, 0, signingInput.length);
                byte[] signature = signer.generateSignature();

                return Base64URL.encode(signature);
            } catch (Exception e) {
                throw new JOSEException("Ed25519 signing failed: " + e.getMessage(), e);
            }
        }

        @Override
        public Set<JWSAlgorithm> supportedJWSAlgorithms() {
            return Collections.singleton(JWSAlgorithm.EdDSA);
        }

        @Override
        public JCAContext getJCAContext() {
            return null;
        }
    }

    // 创建 Ed448 签名器
    private JWSSigner createEd448Signer(OctetKeyPair keyPair) {
        return new CustomEd448Signer(keyPair);
    }

    // 自定义 Ed448 签名器
    private record CustomEd448Signer(OctetKeyPair keyPair) implements JWSSigner {

        @Override
        public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
            try {
                // 对于 Ed448，直接从 JWK 获取 d 值（私钥种子）
                byte[] d = keyPair.getDecodedD();
                if (d == null) {
                    throw new JOSEException("No private key (d) found in JWK");
                }
                // 确保是 57 字节的 Ed448 私钥
                if (d.length != 57) {
                    // 尝试调整长度
                    if (d.length > 57) {
                        // 取前 57 字节
                        byte[] trimmed = new byte[57];
                        System.arraycopy(d, 0, trimmed, 0, 57);
                        d = trimmed;
                    } else {
                        throw new JOSEException("Invalid Ed448 private key length: " + d.length);
                    }
                }

                // 使用 BouncyCastle 进行 Ed448 签名
                Ed448PrivateKeyParameters privateKeyParams = new Ed448PrivateKeyParameters(d, 0);
                Ed448Signer signer = new Ed448Signer(new byte[0]);
                signer.init(true, privateKeyParams);
                signer.update(signingInput, 0, signingInput.length);
                byte[] signature = signer.generateSignature();

                return Base64URL.encode(signature);
            } catch (Exception e) {
                throw new JOSEException("Ed448 signing failed: " + e.getMessage(), e);
            }
        }

        @Override
        public Set<JWSAlgorithm> supportedJWSAlgorithms() {
            return Collections.singleton(JWSAlgorithm.EdDSA);
        }

        @Override
        public JCAContext getJCAContext() {
            return null;
        }
    }

    // 从 PKCS8 编码中提取 EdDSA 私钥种子
    private static byte[] extractEdPrivateKey(byte[] pkcs8Encoded) {
        try {
            for (int i = 0; i < pkcs8Encoded.length - 2; i++) {
                if (pkcs8Encoded[i] == 0x04) {
                    int length = pkcs8Encoded[i + 1] & 0xFF;
                    if (length > 128) {
                        length = ((pkcs8Encoded[i + 1] & 0x7F) << 8) | (pkcs8Encoded[i + 2] & 0xFF);
                        i += 1;
                    }
                    int offset = i + 2;
                    byte[] seed = new byte[length];
                    System.arraycopy(pkcs8Encoded, offset, seed, 0, seed.length);
                    return seed;
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse PKCS8 structure, using fallback: {}", e.getMessage());
        }
        // 回退：对于 Ed25519 取最后 32 字节，对于 Ed448 取最后 57 字节
        if (pkcs8Encoded.length >= 57) { // 可能是 Ed448
            byte[] seed = new byte[57];
            System.arraycopy(pkcs8Encoded, pkcs8Encoded.length - 57, seed, 0, 57);
            return seed;
        } else if (pkcs8Encoded.length >= 32) { // 可能是 Ed25519
            byte[] seed = new byte[32];
            System.arraycopy(pkcs8Encoded, pkcs8Encoded.length - 32, seed, 0, 32);
            return seed;
        }
        return pkcs8Encoded;
    }

    @Override
    public String generateJwt(JwtProperties properties, Algorithm algorithm) {
        return generateJwt(properties, null, algorithm);
    }

    @Override
    public Claims decodePayload(String token) {
        if (StringUtils.isBlank(token)) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            Map<String, Object> claimsMap = new HashMap<>();
            claimsMap.put("sub", claimsSet.getSubject());
            claimsMap.put("iss", claimsSet.getIssuer());
            claimsMap.put("iat", claimsSet.getIssueTime());
            claimsMap.put("exp", claimsSet.getExpirationTime());

            claimsSet.getClaims().forEach((key, value) -> {
                if (!"sub".equals(key) && !"iss".equals(key) && !"iat".equals(key) && !"exp".equals(key)) {
                    claimsMap.put(key, value);
                }
            });
            return Jwts.claims().add(claimsMap).build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to decode EdDSA JWT payload", e);
        }
    }

    @Override
    public boolean generateAllKeyPairs() {
        boolean allSuccess = true;
        for (Algorithm algorithm : ALGORITHM_CONFIGS.keySet()) {
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
    public String getCurveInfo(Algorithm algorithm) {
        validateEddsaAlgorithm(algorithm);
        AlgorithmConfig config = getAlgorithmConfig(algorithm);
        return String.format("%s - Curve: %s (BC algorithm: %s)",
                algorithm, config.curve.getName(), config.bcAlgorithmName);
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
    protected MacAlgorithm getSignAlgorithm(Algorithm algorithm) {
        throw new UnsupportedOperationException("EdDSA uses Nimbus JOSE directly");
    }

    @Override
    public String getKeyInfo() {
        return String.format("EdDSA Keys - Active: %s, Total versions: %d, Key rotation: %s",
                activeKeyId, versionKeyPairs.size(), keyRotationEnabled ? "enabled" : "disabled");
    }

    @Override
    protected void setRestrictiveFilePermissions(Path path) {
        try {
            // 检查是否支持POSIX
            if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
                Files.setPosixFilePermissions(path,
                        EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
                log.debug("Set POSIX permissions 600 for: {}", path);
            } else {
                // Windows系统：使用ACL或记录警告
                log.warn("POSIX permissions not supported on this filesystem. " +
                        "Please manually set restrictive permissions for: {}", path);
                // Windows上可以尝试设置隐藏属性
                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    Files.setAttribute(path, "dos:hidden", true);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to set restrictive permissions for {}: {}", path, e.getMessage());
        }
    }

    @Override
    public void close() {
        cleanup();
    }

    protected void cleanup() {
        // 清理所有版本密钥
        versionKeyPairs.clear();
        keyIdToAlgorithm.clear();
        // 清理当前密钥
        activeKeyId = null; // 对于 EcdsaJwt 和 EddsaJwt
        // 清理父类资源
        keyVersions.clear();
        activeKeyId = null;
    }

    @Override
    public String getAlgorithmInfo() {
        return "EdDSA algorithms: Ed25519, Ed448 with key rotation support (using BouncyCastle)";
    }

    @Override
    public PublicKey getPublicKey() {
        if (activeKeyId == null) return null;
        OctetKeyPair keyPair = versionKeyPairs.get(activeKeyId);
        if (keyPair != null) {
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("EdDSA", "BC");
                byte[] x = keyPair.getDecodedX();
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(x);
                return keyFactory.generatePublic(publicKeySpec);
            } catch (Exception e) {
                log.warn("Failed to convert JWK to PublicKey: {}", e.getMessage());
                return null;
            }
        }
        return null;
    }

    @Override
    public PublicKey getPublicKey(Algorithm algorithm) {
        validateEddsaAlgorithm(algorithm);
        return getPublicKey();
    }

    protected void loadKeyVersion(Path versionDir) {
        try {
            String keyId = versionDir.getFileName().toString();
            boolean isActive = Files.exists(versionDir.resolve(".active"));
            OctetKeyPair keyPair = loadKeyPairFromDir(versionDir);

            if (keyPair != null) {
                versionKeyPairs.put(keyId, keyPair);
                Algorithm algorithm = getAlgorithmFromDir(versionDir);
                keyIdToAlgorithm.put(keyId, algorithm);

                KeyVersion version = new KeyVersion(
                        keyId,
                        algorithm,
                        versionDir.toString()
                );
                version.setActive(isActive);
                version.setCreatedTime(getCreationTimeFromDir(versionDir));

                if (isActive) {
                    version.setActivatedTime(LocalDateTime.now());
                    this.activeKeyId = keyId;
                }

                keyVersions.put(keyId, version);
                log.debug("Loaded EdDSA key version: {}, active: {}, algorithm: {}",
                        keyId, isActive, algorithm);
            }
        } catch (Exception e) {
            log.warn("Failed to load key version from {}: {}", versionDir, e.getMessage());
        }
    }

    private OctetKeyPair loadKeyPairFromDir(Path versionDir) throws IOException, java.text.ParseException {
        Path keyFile = versionDir.resolve("key.jwk");
        if (Files.exists(keyFile)) {
            String jwkJson = Files.readString(keyFile, StandardCharsets.UTF_8).trim();
            return OctetKeyPair.parse(jwkJson);
        }
        return null;
    }

    private Algorithm getAlgorithmFromDir(Path versionDir) throws IOException {
        Path algorithmFile = versionDir.resolve("algorithm.info");
        if (Files.exists(algorithmFile)) {
            String algorithmStr = Files.readString(algorithmFile, StandardCharsets.UTF_8).trim();
            try {
                return Algorithm.valueOf(algorithmStr);
            } catch (IllegalArgumentException ignored) {
            }
        }
        return Algorithm.Ed25519;
    }

    private JWTClaimsSet buildClaimsSet(JwtProperties properties, Map<String, Object> customClaims) {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .subject(properties.getSubject())
                .issuer(properties.getIssuer())
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + properties.getExpiration()));

        if (customClaims != null) {
            customClaims.forEach(claimsBuilder::claim);
        }

        return claimsBuilder.build();
    }

    private AlgorithmConfig getAlgorithmConfig(Algorithm algorithm) {
        AlgorithmConfig config = ALGORITHM_CONFIGS.get(algorithm);
        if (config == null) throw new IllegalArgumentException("Unsupported EdDSA algorithm: " + algorithm);
        return config;
    }

    private void loadLegacyKeyPairs() {
        try {
            try (var paths = Files.list(currentKeyPath)) {
                paths.filter(Files::isRegularFile)
                        .filter(file -> file.getFileName().toString().endsWith("private.key"))
                        .forEach(this::migrateLegacyKeyPair);
            }
        } catch (IOException e) {
            log.debug("No legacy keys found or failed to scan: {}", e.getMessage());
        }
    }

    private void migrateLegacyKeyPair(Path legacyPath) {
        try {
            String jwkJson = Files.readString(legacyPath, StandardCharsets.UTF_8).trim();
            if (StringUtils.isBlank(jwkJson)) {
                return;
            }

            OctetKeyPair keyPair = OctetKeyPair.parse(jwkJson);
            Algorithm algorithm = determineAlgorithmFromJWK(keyPair);
            String keyId = KEY_VERSION_PREFIX + LocalDateTime.now().format(
                    DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + "-legacy";

            migrateToVersioned(keyId, keyPair, algorithm);
        } catch (Exception e) {
            log.warn("Failed to migrate legacy key {}: {}", legacyPath, e.getMessage());
        }
    }

    private Algorithm determineAlgorithmFromJWK(OctetKeyPair keyPair) {
        String crv = keyPair.getCurve().getName();
        if (Curve.Ed25519.getName().equals(crv)) {
            return Algorithm.Ed25519;
        } else if (Curve.Ed448.getName().equals(crv)) {
            return Algorithm.Ed448;
        }
        return Algorithm.Ed25519;
    }

    private void migrateToVersioned(String keyId, OctetKeyPair keyPair, Algorithm algorithm) throws IOException {
        Path versionDir = currentKeyPath.resolve(keyId);
        Files.createDirectories(versionDir);

        Path newKeyFile = versionDir.resolve("key.jwk");
        Files.writeString(newKeyFile, keyPair.toJSONString(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        setRestrictiveFilePermissions(newKeyFile);

        Path algorithmFile = versionDir.resolve("algorithm.info");
        Files.writeString(algorithmFile, algorithm.name());

        Files.createFile(versionDir.resolve(".active"));

        versionKeyPairs.put(keyId, keyPair);
        keyIdToAlgorithm.put(keyId, algorithm);

        KeyVersion version = new KeyVersion(keyId, algorithm, versionDir.toString());
        version.setActive(true);
        version.setCreatedTime(LocalDateTime.now());
        version.setActivatedTime(LocalDateTime.now());

        keyVersions.put(keyId, version);
        this.activeKeyId = keyId;

        log.info("Migrated legacy EdDSA key to versioned format: {}", keyId);
    }

    private record AlgorithmConfig(Curve curve, String bcAlgorithmName) {
    }
}
