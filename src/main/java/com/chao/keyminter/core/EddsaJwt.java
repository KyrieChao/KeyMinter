package com.chao.keyminter.core;

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
import com.chao.keyminter.adapter.in.KeyMinterConfigHolder;
import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.JwtProperties;
import com.chao.keyminter.domain.model.KeyStatus;
import com.chao.keyminter.domain.model.KeyVersion;
import com.chao.keyminter.domain.port.out.SecretDirProvider;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.security.Security;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * EdDSA JWT 实现类
 * 支持 Ed25519, Ed448 算法
 */
@Slf4j
@Getter
public class EddsaJwt extends AbstractJwtAlgo {

    private static final String KEY_FILE = "key.jwk";
    private static final String ALGORITHM_FILE = "algorithm.info";
    private static final String KEY_VERSION_PREFIX = "ed";
    private static final String STATUS_FILE = "status.info";
    private static final String EXPIRATION_FILE = "expiration.info";
    private static final String TRANSITION_FILE = "transition.info";

    private final Map<String, OctetKeyPair> versionKeyPairs = new ConcurrentHashMap<>();
    private final Map<String, Algorithm> keyIdToAlgorithm = new ConcurrentHashMap<>();

    private static final Map<Algorithm, AlgorithmConfig> ALGORITHM_CONFIGS = Map.of(
            Algorithm.Ed25519, new AlgorithmConfig(Curve.Ed25519, "Ed25519"),
            Algorithm.Ed448, new AlgorithmConfig(Curve.Ed448, "Ed448")
    );

    private static volatile boolean bcRegistered = false;

    private static Path getDefaultEdDir() {
        return SecretDirProvider.getDefaultBaseDir().resolve("eddsa-keys");
    }

    private static void ensureBouncyCastle() {
        if (!bcRegistered) {
            synchronized (EddsaJwt.class) {
                if (!bcRegistered) {
                    registerBouncyCastle();
                    bcRegistered = true;
                }
            }
        }
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
        this(getDefaultEdDir());
    }

    public EddsaJwt(Path keyDir) {
        this(KeyMinterConfigHolder.get(), keyDir);
    }

    public EddsaJwt(KeyMinterProperties properties, Path keyDir) {
        super(properties);
        ensureBouncyCastle();
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
            return getDefaultEdDir();
        }

        Path normalized = keyDir.normalize();
        validateDirectoryPath(normalized);

        if (!"eddsa-keys".equals(normalized.getFileName().toString())) {
            normalized = normalized.resolve("eddsa-keys");
        }
        return normalized;
    }

    @Override
    protected boolean hasKeyFilesInDirectory(String tag) {
        return findKeyDir(tag, dir -> Files.exists(dir.resolve(KEY_FILE))).isPresent();
    }

    @Override
    protected void loadFirstKeyFromDirectory(String tag) {
        findKeyDir(tag, dir -> Files.exists(dir.resolve(KEY_FILE))).ifPresentOrElse(
                dir -> setActiveKey(dir.getFileName().toString()),
                () -> log.error("No{} key directory found under {}",
                        tag == null ? "" : " " + tag, currentKeyPath)
        );
    }

    @Override
    public void loadExistingKeyVersions() {
        if (currentKeyPath == null || !Files.exists(currentKeyPath) || !Files.isDirectory(currentKeyPath)) {
            return;
        }

        try (var paths = Files.list(currentKeyPath)) {
            paths.filter(Files::isDirectory)
                    .filter(dir -> dir.getFileName().toString().toLowerCase().startsWith(KEY_VERSION_PREFIX))
                    .forEach(this::loadKeyVersion);

            if (versionKeyPairs.isEmpty()) {
                loadLegacyKeyPairs();
            }
        } catch (IOException e) {
            log.error("Failed to load existing EdDSA key versions: {}", e.getMessage());
        }
    }

    @Override
    protected boolean isKeyVersionDir(Path dir) {
        if (dir == null) {
            return false;
        }
        String name = dir.getFileName().toString().toLowerCase();
        boolean hasJwk = Files.exists(dir.resolve(KEY_FILE));
        boolean hasAlg = Files.exists(dir.resolve(ALGORITHM_FILE));
        boolean likeEd = name.contains("ed") && name.contains("-v");
        return hasJwk || hasAlg || likeEd;
    }

    @Override
    public boolean generateKeyPair(Algorithm algorithm) {
        return rotateKey(algorithm, generateKeyVersionId(algorithm));
    }

    @Override
    public boolean rotateKey(Algorithm algorithm, String newKeyIdentifier) {
        // 使用默认过渡期
        int transitionHours = keyMinterProperties != null ?keyMinterProperties.getTransitionPeriodHours() : 24;
        return rotateKeyWithTransition(algorithm, newKeyIdentifier, transitionHours);
    }

    @Override
    public boolean rotateKeyWithTransition(Algorithm algorithm, String newKeyIdentifier, int transitionPeriodHours) {
        validateEddsaAlgorithm(algorithm);
        if (!isKeyRotationEnabled()) {
            log.error("Key rotation is not enabled");
            return false;
        }
        try {
            return KeyRotation.rotateKeyAtomic(
                    newKeyIdentifier,currentKeyPath,() -> generateEdKeyPair(algorithm, newKeyIdentifier),
                    (keyPair, tempDir) -> saveKeyPairToDirectory(keyPair, tempDir, algorithm, newKeyIdentifier),
                    (keyPair) -> updateKeyVersionWithTransition(newKeyIdentifier, algorithm, keyPair, transitionPeriodHours)
            );
        } catch (IOException e) {
            log.error("Key rotation with transition failed for {}: {}", newKeyIdentifier, e.getMessage(), e);
            throw new UncheckedIOException("Key rotation failed", e);
        }
    }

    private OctetKeyPair generateEdKeyPair(Algorithm algorithm, String keyId) {
        if (algorithm == Algorithm.Ed25519) {
            try {
                return new OctetKeyPairGenerator(Curve.Ed25519)
                        .keyID(keyId)
                        .generate();
            } catch (Throwable e) {
                log.warn("Nimbus Ed25519 generation failed, using BC: {}", e.getMessage());
                return generateKeyPairWithBC(algorithm, keyId);
            }
        } else {
            return generateKeyPairWithBC(algorithm, keyId);
        }
    }

    private OctetKeyPair generateKeyPairWithBC(Algorithm algorithm, String keyId) {
        AlgorithmConfig config = getAlgorithmConfig(algorithm);
        AsymmetricCipherKeyPair bcKP;
        byte[] d;
        byte[] x;

        if (algorithm == Algorithm.Ed25519) {
            Ed25519KeyPairGenerator kpg = new Ed25519KeyPairGenerator();
            kpg.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            bcKP = kpg.generateKeyPair();
            d = ((Ed25519PrivateKeyParameters) bcKP.getPrivate()).getEncoded();
            x = ((Ed25519PublicKeyParameters) bcKP.getPublic()).getEncoded();
        } else {
            Ed448KeyPairGenerator kpg = new Ed448KeyPairGenerator();
            kpg.init(new Ed448KeyGenerationParameters(new SecureRandom()));
            bcKP = kpg.generateKeyPair();
            d = ((Ed448PrivateKeyParameters) bcKP.getPrivate()).getEncoded();
            x = ((Ed448PublicKeyParameters) bcKP.getPublic()).getEncoded();
        }

        return new OctetKeyPair.Builder(config.curve(), Base64URL.encode(x))
                .d(Base64URL.encode(d))
                .keyID(keyId)
                .algorithm(JWSAlgorithm.EdDSA)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .build();
    }

    private void saveKeyPairToDirectory(OctetKeyPair keyPair, Path tempDir, Algorithm algorithm, String keyId) throws IOException {
        Path keyFile = tempDir.resolve(KEY_FILE);
        Files.writeString(keyFile, keyPair.toJSONString(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        Path algorithmFile = tempDir.resolve(ALGORITHM_FILE);
        Files.writeString(algorithmFile, algorithm.name());

        // 保存过期时间
        Instant expiresAt = calculateKeyExpiration();
        Path expirationFile = tempDir.resolve(EXPIRATION_FILE);
        Files.writeString(expirationFile, expiresAt.toString());

        // 保存初始状态
        Path statusFile = tempDir.resolve(STATUS_FILE);
        Files.writeString(statusFile, KeyStatus.CREATED.name());

        setRestrictiveFilePermissions(keyFile);

        log.debug("Saved EdDSA key {} with expiration: {}", keyId, expiresAt);
    }

    private void updateKeyVersionWithTransition(String keyId, Algorithm algorithm, OctetKeyPair keyPair, int transitionPeriodHours) {
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
            this.activeKeyId = keyId;
            */

            log.info("EdDSA key created (pending activation). Key ID: {}, algorithm: {}", keyId, algorithm);
        } catch (Exception e) {
            log.error("Failed to update EdDSA key version: {}", e.getMessage(), e);
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
                Path versionDir = currentKeyPath.resolve(keyId);
                OctetKeyPair keyPair = loadKeyPairFromDir(versionDir);
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
    public boolean verifyToken(String token) {
        if (StringUtils.isBlank(token)) {
            return false;
        }

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            readLock.lock();
            try {
                // 先尝试用当前活跃密钥验证
                if (activeKeyId != null) {
                    OctetKeyPair activeKeyPair = versionKeyPairs.get(activeKeyId);
                    if (activeKeyPair != null) {
                        return verifyWithKey(activeKeyPair, signedJWT);
                    }
                }

                // 尝试所有已加载的密钥
                for (String keyId : keyVersions.keySet()) {
                    OctetKeyPair kp = versionKeyPairs.get(keyId);
                    if (kp == null) {
                        try {
                            kp = loadKeyPairFromDir(currentKeyPath.resolve(keyId));
                            if (kp != null) {
                                versionKeyPairs.put(keyId, kp);
                            }
                        } catch (Exception ignored) {
                        }
                    }
                    if (kp != null && verifyWithKey(kp, signedJWT)) {
                        return true;
                    }
                }
                return false;
            } finally {
                readLock.unlock();
            }
        } catch (Exception e) {
            log.debug("EdDSA JWT verification failed: {}", e.getMessage());
            return false;
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

        try {
            readLock.lock();
            try {
                OctetKeyPair keyPair = versionKeyPairs.get(keyId);
                if (keyPair == null) {
                    keyPair = loadKeyPairFromDir(currentKeyPath.resolve(keyId));
                    if (keyPair != null) {
                        versionKeyPairs.put(keyId, keyPair);
                    }
                }

                if (keyPair == null) {
                    return false;
                }

                SignedJWT signedJWT = SignedJWT.parse(token);
                return verifyWithKey(keyPair, signedJWT);
            } finally {
                readLock.unlock();
            }
        } catch (Exception e) {
            log.debug("Token verification failed with key {}: {}", keyId, e.getMessage());
            return false;
        }
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

    private boolean verifyEd25519(OctetKeyPair keyPair, SignedJWT signedJWT) {
        byte[] x = keyPair.getDecodedX();
        if (x == null || x.length != 32) {
            throw new IllegalArgumentException("Invalid Ed25519 public key length: " + (x == null ? "null" : x.length));
        }

        byte[] signingInput = signedJWT.getSigningInput();
        byte[] signatureBytes = signedJWT.getSignature().decode();

        Ed25519PublicKeyParameters publicKeyParams = new Ed25519PublicKeyParameters(x, 0);
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, publicKeyParams);
        verifier.update(signingInput, 0, signingInput.length);

        return verifier.verifySignature(signatureBytes);
    }

    private boolean verifyEd448(OctetKeyPair keyPair, SignedJWT signedJWT) {
        try {
            byte[] x = keyPair.getDecodedX();
            if (x == null || x.length != 57) {
                log.warn("Invalid Ed448 public key length: {}", x == null ? "null" : x.length);
                return false;
            }

            byte[] signingInput = signedJWT.getSigningInput();
            byte[] signatureBytes = signedJWT.getSignature().decode();

            Ed448PublicKeyParameters publicKeyParams = new Ed448PublicKeyParameters(x, 0);
            Ed448Signer verifier = new Ed448Signer(new byte[0]);
            verifier.init(false, publicKeyParams);
            verifier.update(signingInput, 0, signingInput.length);

            return verifier.verifySignature(signatureBytes);
        } catch (Exception e) {
            log.debug("Ed448 verification failed: {}", e.getMessage());
            return false;
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
    public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
        validateEddsaAlgorithm(algorithm);

        readLock.lock();
        try {
            if (activeKeyId == null) {
                throw new IllegalStateException("No active EdDSA key. Call setActiveKey or rotateKey first.");
            }

            OctetKeyPair keyPair = versionKeyPairs.get(activeKeyId);
            if (keyPair == null) {
                throw new IllegalStateException("Active EdDSA key not found: " + activeKeyId);
            }

            return generateJwtInternal(properties, customClaims, keyPair);
        } finally {
            readLock.unlock();
        }
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

    private JWSSigner createEd25519Signer(OctetKeyPair keyPair) {
        try {
            Class<?> ed25519SignerClass = Class.forName("com.nimbusds.jose.crypto.Ed25519Signer");
            return (JWSSigner) ed25519SignerClass.getConstructor(OctetKeyPair.class)
                    .newInstance(keyPair);
        } catch (Throwable e) {
            log.debug("Using custom Ed25519 signer: {}", e.getMessage());
            return new CustomEd25519Signer(keyPair);
        }
    }

    private JWSSigner createEd448Signer(OctetKeyPair keyPair) {
        return new CustomEd448Signer(keyPair);
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
            if (claimsSet.getJWTID() != null) {
                claimsMap.put("jti", claimsSet.getJWTID());
            }

            claimsSet.getClaims().forEach((key, value) -> {
                if (!Set.of("sub", "iss", "iat", "exp").contains(key)) {
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
                algorithm, config.curve().getName(), config.bcAlgorithmName());
    }

    @Override
    protected MacAlgorithm getSignAlgorithm(Algorithm algorithm) {
        throw new UnsupportedOperationException("EdDSA uses Nimbus JOSE directly");
    }

    @Override
    public String getKeyInfo() {
        readLock.lock();
        try {
            return String.format("EdDSA Keys - Active: %s, Total versions: %d, Key rotation: %s",
                    activeKeyId != null ? activeKeyId : "None",
                    versionKeyPairs.size(),
                    keyRotationEnabled ? "enabled" : "disabled");
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
            log.debug("EddsaJwt resources cleaned up");
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public String getAlgorithmInfo() {
        return "EdDSA algorithms: Ed25519, Ed448 with key rotation support (using BouncyCastle)";
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
                log.warn("Skipping expired EdDSA key: {}, expired at: {}", keyId, expiresAt);
                return;
            }

            OctetKeyPair keyPair = loadKeyPairFromDir(versionDir);
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
            log.debug("Loaded EdDSA key version: {}, status: {}, algorithm: {}, expires: {}",
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

    private OctetKeyPair loadKeyPairFromDir(Path versionDir) {
        if (versionDir == null) {
            return null;
        }

        Path keyFile = versionDir.resolve(KEY_FILE);
        if (!Files.exists(keyFile)) {
            return null;
        }

        try {
            String jwkJson = Files.readString(keyFile, StandardCharsets.UTF_8).trim();
            return OctetKeyPair.parse(jwkJson);
        } catch (Exception e) {
            log.debug("Failed to parse JWK from {}: {}", keyFile, e.getMessage());
            return null;
        }
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
        return Algorithm.Ed25519;
    }

    private JWTClaimsSet buildClaimsSet(JwtProperties properties, Map<String, Object> customClaims) {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .subject(properties.getSubject())
                .issuer(properties.getIssuer())
                .issueTime(new Date())
                .expirationTime(toDate(properties.getExpiration()));

        if (customClaims != null) {
            customClaims.forEach(claimsBuilder::claim);
        }

        return claimsBuilder.build();
    }

    private AlgorithmConfig getAlgorithmConfig(Algorithm algorithm) {
        AlgorithmConfig config = ALGORITHM_CONFIGS.get(algorithm);
        if (config == null) {
            throw new IllegalArgumentException("Unsupported EdDSA algorithm: " + algorithm);
        }
        return config;
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

        Path newKeyFile = versionDir.resolve(KEY_FILE);
        Files.writeString(newKeyFile, keyPair.toJSONString(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        setRestrictiveFilePermissions(newKeyFile);

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

        log.info("Migrated legacy EdDSA key to versioned format: {}, expires: {}", keyId, expiresAt);
    }

    private record AlgorithmConfig(Curve curve, String bcAlgorithmName) {
    }

    // 自定义 Ed25519 签名器
    private record CustomEd25519Signer(OctetKeyPair keyPair) implements JWSSigner {

        @Override
        public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
            try {
                byte[] d = keyPair.getDecodedD();
                if (d == null) {
                    throw new JOSEException("No private key (d) found in JWK");
                }
                
                // Ed25519 seed is 32 bytes
                if (d.length != 32) {
                     if (d.length > 32) {
                        // In case it's not just the seed but has some padding or is a full key?
                        // Usually d for Ed25519 in JWK is the 32 byte seed.
                        // Let's try to take the first 32 bytes if longer, or just fail.
                        // But wait, sometimes d might be the private scalar?
                        // For Ed25519, the private key is derived from the seed.
                        // RFC 8037: "The "d" parameter contains the private key."
                        // For Ed25519 it is the 32-octet seed.
                        byte[] trimmed = new byte[32];
                        System.arraycopy(d, 0, trimmed, 0, 32);
                        d = trimmed;
                    } else {
                        throw new JOSEException("Invalid Ed25519 private key length: " + d.length);
                    }
                }

                Ed25519PrivateKeyParameters privateKeyParams = new Ed25519PrivateKeyParameters(d, 0);
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
            return new JCAContext();
        }
    }

    // 自定义 Ed448 签名器
    private record CustomEd448Signer(OctetKeyPair keyPair) implements JWSSigner {

        @Override
        public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
            try {
                byte[] d = keyPair.getDecodedD();
                if (d == null) {
                    throw new JOSEException("No private key (d) found in JWK");
                }

                if (d.length != 57) {
                    if (d.length > 57) {
                        byte[] trimmed = new byte[57];
                        System.arraycopy(d, 0, trimmed, 0, 57);
                        d = trimmed;
                    } else {
                        throw new JOSEException("Invalid Ed448 private key length: " + d.length);
                    }
                }

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
            return new JCAContext();
        }
    }

    private static byte[] extractEdPrivateKey(byte[] pkcs8Encoded) {
        // Method removed as it is no longer used and was fragile
        return new byte[0];
    }
}
