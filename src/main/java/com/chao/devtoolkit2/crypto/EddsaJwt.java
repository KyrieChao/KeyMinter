package com.chao.devtoolkit.crypto;

import com.chao.devtoolkit.config.JwtProperties;
import com.chao.devtoolkit.core.AbstractJwt;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import io.micrometer.common.util.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.Security;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
public class EddsaJwt extends AbstractJwt {
    private final Map<String, OctetKeyPair> keyPairMap = new ConcurrentHashMap<>();

    private static final Map<Integer, Curve> ALGORITHM_CURVE_MAP = Map.of(1, Curve.Ed25519, 2, Curve.Ed448);
    private static final Map<Integer, String> ALGORITHM_FILENAME_MAP = Map.of(1, "ed25519", 2, "ed448");
    private static final Path DEFAULT_KEY_DIR = Paths.get(System.getProperty("user.home"), ".chao", "eddsa-keys");

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public EddsaJwt() {
        this.currentKeyDir = DEFAULT_KEY_DIR;
    }

    public EddsaJwt(String directory) {
        this.currentKeyDir = StringUtils.isBlank(directory) ? DEFAULT_KEY_DIR : Paths.get(directory);
    }

    public EddsaJwt(Path keyDir) {
        this.currentKeyDir = keyDir != null ? keyDir : DEFAULT_KEY_DIR;
    }

    @Override
    public boolean generateKeyPair(Integer algorithmType) {
        return generateKeyPair(algorithmType, null);
    }

    @Override
    public boolean generateKeyPair(Integer algorithmType, String customFilename) {
        Curve curve = validateAndGetCurve(algorithmType);
        try {
            String keyId = "key-" + UUID.randomUUID().toString();
            String filename = getKeyFilename(algorithmType, customFilename);

            OctetKeyPair keyPair = new OctetKeyPairGenerator(curve)
                    .keyID(keyId)
                    .generate();

            String mapKey = getMapKey(algorithmType, customFilename);
            keyPairMap.put(mapKey, keyPair);
            saveKeyPair(keyPair, filename);

            log.info("EdDSA key pair generated for {}, stored in: {}", curve.getName(), currentKeyDir);
            return true;

        } catch (Exception e) {
            log.error("Failed to generate EdDSA key pair for {}: {}",
                    getCurveName(algorithmType), e.getMessage());
            return false;
        }
    }

    public boolean generateKeyPairInDirectory(Integer algorithmType, String directory, String customFilename) {
        if (!StringUtils.isBlank(directory)) {
            this.currentKeyDir = Paths.get(directory);
        }
        return generateKeyPair(algorithmType, customFilename);
    }

    @Override
    public boolean generateAllKeyPairs() {
        boolean allSuccess = true;
        for (Integer algorithmType : ALGORITHM_CURVE_MAP.keySet()) {
            boolean success = generateKeyPair(algorithmType);
            if (!success) {
                allSuccess = false;
            }
        }
        return allSuccess;
    }

    @Override
    protected String getSecretKey() {
        return getSecretKey(1);
    }

    protected String getSecretKey(Integer algorithmType) {
        OctetKeyPair keyPair = getKeyPair(algorithmType, null);
        if (keyPair == null) {
            throw new IllegalStateException("EdDSA key pair not found for " + getCurveName(algorithmType));
        }
        return keyPair.toJSONString();
    }

    @Override
    protected MacAlgorithm getSignAlgorithm(Integer n) {
        throw new UnsupportedOperationException("EdDSA uses Nimbus JOSE directly");
    }

    @Override
    public String generateToken(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType) {
        validateJwtProperties(properties);
        validateEddsaAlgorithmType(algorithmType);
        return generateJwtInternal(properties, customClaims, algorithmType, null);
    }

    @Override
    public boolean verifyToken(String token) {
        if (StringUtils.isBlank(token)) return false;

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            String keyID = signedJWT.getHeader().getKeyID();
            if (keyID == null) {
                return false;
            }

            OctetKeyPair publicKey = findPublicKeyByKeyID(keyID);
            if (publicKey == null) {
                return false;
            }

            JWSVerifier verifier = createVerifier(publicKey);
            return signedJWT.verify(verifier);

        } catch (Exception e) {
            log.warn("EdDSA JWT verification failed: {}", e.getMessage());
            return false;
        }
    }

    private OctetKeyPair findPublicKeyByKeyID(String keyID) {
        for (OctetKeyPair keyPair : keyPairMap.values()) {
            if (keyID.equals(keyPair.getKeyID())) {
                return keyPair.toPublicJWK();
            }
        }
        return null;
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

            if (claimsSet.getSubject() != null) {
                claimsMap.put("sub", claimsSet.getSubject());
            }
            if (claimsSet.getIssuer() != null) {
                claimsMap.put("iss", claimsSet.getIssuer());
            }
            if (claimsSet.getIssueTime() != null) {
                claimsMap.put("iat", claimsSet.getIssueTime());
            }
            if (claimsSet.getExpirationTime() != null) {
                claimsMap.put("exp", claimsSet.getExpirationTime());
            }

            Map<String, Object> customClaims = claimsSet.getClaims();
            for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
                String key = entry.getKey();
                if (!"sub".equals(key) && !"iss".equals(key) && !"iat".equals(key) && !"exp".equals(key)) {
                    claimsMap.put(key, entry.getValue());
                }
            }

            return Jwts.claims().add(claimsMap).build();

        } catch (Exception e) {
            throw new RuntimeException("Failed to decode EdDSA JWT payload", e);
        }
    }

    @Override
    public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType) {
        return generateJwtInternal(properties, customClaims, algorithmType, null);
    }

    @Override
    public String generateJwt(JwtProperties properties, Integer algorithmType) {
        return generateJwtInternal(properties, null, algorithmType, null);
    }

    public String generateJwtWithKey(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType, String customFilename) {
        return generateJwtInternal(properties, customClaims, algorithmType, customFilename);
    }

    private String generateJwtInternal(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType, String customFilename) {
        validateJwtProperties(properties);
        try {
            OctetKeyPair keyPair = getKeyPair(algorithmType, customFilename);
            if (keyPair == null) {
                throw new IllegalStateException("EdDSA key pair not found for " + getCurveName(algorithmType));
            }
            JWTClaimsSet claimsSet = buildClaimsSet(properties, customClaims);
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                    .keyID(keyPair.getKeyID())
                    .build();
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            JWSSigner signer = createSigner(keyPair);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate EdDSA JWT", e);
        }
    }

    private JWSSigner createSigner(OctetKeyPair keyPair) throws JOSEException {
        return new Ed25519Signer(keyPair);
    }

    private JWSVerifier createVerifier(OctetKeyPair publicKey) throws JOSEException {
        return new Ed25519Verifier(publicKey);
    }

    private JWTClaimsSet buildClaimsSet(JwtProperties properties, Map<String, Object> customClaims) {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .subject(properties.getSubject())
                .issuer(properties.getIssuer())
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + properties.getExpiration()));

        if (customClaims != null) {
            for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
                claimsBuilder.claim(entry.getKey(), entry.getValue());
            }
        }

        return claimsBuilder.build();
    }

    private void saveKeyPair(OctetKeyPair keyPair, String filename) throws IOException {
        Files.createDirectories(currentKeyDir);
        Path privateKeyPath = currentKeyDir.resolve(filename + ".jwk");

        String privateJwk = keyPair.toJSONString();
        Files.writeString(privateKeyPath, privateJwk, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        setRestrictivePermissions(privateKeyPath);
    }

    /**
     * 生成安全随机密钥
     */
    private OctetKeyPair loadKeyPair(Integer algorithmType, String filename) {
        try {
            Path privateKeyPath = currentKeyDir.resolve(filename + ".jwk");
            if (!Files.exists(privateKeyPath)) return null;
            String privateJwk = Files.readString(privateKeyPath, StandardCharsets.UTF_8);
            return OctetKeyPair.parse(privateJwk);
        } catch (Exception e) {
            log.error("Failed to load EdDSA key pair: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 生成密钥对
     */
    private OctetKeyPair getKeyPair(Integer algorithmType, String customFilename) {
        String mapKey = getMapKey(algorithmType, customFilename);
        OctetKeyPair keyPair = keyPairMap.get(mapKey);
        if (keyPair == null) {
            String filename = getKeyFilename(algorithmType, customFilename);
            keyPair = loadKeyPair(algorithmType, filename);
            if (keyPair != null) {
                keyPairMap.put(mapKey, keyPair);
            }
        }
        return keyPair;
    }

    private String getKeyFilename(Integer algorithmType, String customFilename) {
        if (!StringUtils.isBlank(customFilename)) {
            return customFilename;
        }
        return ALGORITHM_FILENAME_MAP.get(algorithmType);
    }

    private String getMapKey(Integer algorithmType, String customFilename) {
        if (!StringUtils.isBlank(customFilename)) {
            return customFilename;
        }
        return String.valueOf(algorithmType);
    }

    public boolean switchKeyDirectory(String directory) {
        if (StringUtils.isBlank(directory)) {
            return false;
        }

        Path newDir = Paths.get(directory);
        if (Files.exists(newDir) && Files.isDirectory(newDir)) {
            this.currentKeyDir = newDir;
            keyPairMap.clear();
            log.info("Switched to key directory: {}", newDir);
            return true;
        } else {
            log.warn("Key directory does not exist or is not a directory: {}", newDir);
            return false;
        }
    }

    public List<Path> listKeyFiles() {
        try {
            if (Files.exists(currentKeyDir) && Files.isDirectory(currentKeyDir)) {
                return Files.list(currentKeyDir)
                        .filter(Files::isRegularFile)
                        .filter(path -> path.toString().endsWith(".jwk"))
                        .sorted()
                        .collect(Collectors.toList());
            }
        } catch (IOException e) {
            log.warn("Failed to list key files: {}", e.getMessage());
        }
        return Collections.emptyList();
    }

    public boolean keyPairExists(Integer algorithmType) {
        return keyPairExists(algorithmType, null);
    }

    public boolean keyPairExists(Integer algorithmType, String customFilename) {
        String filename = getKeyFilename(algorithmType, customFilename);
        Path privateKeyPath = currentKeyDir.resolve(filename + ".jwk");
        return Files.exists(privateKeyPath);
    }

    public static Path getDefaultKeyDir() {
        return DEFAULT_KEY_DIR;
    }

    private void setRestrictivePermissions(Path path) {
        try {
            Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, perms);
        } catch (Exception e) {
            log.debug("Failed to set POSIX permissions: {}", e.getMessage());
        }
    }

    private Curve validateAndGetCurve(Integer algorithmType) {
        Curve curve = ALGORITHM_CURVE_MAP.get(algorithmType);
        if (curve == null) {
            throw new IllegalArgumentException("Algorithm type must be 1 (Ed25519) or 2 (Ed448)");
        }
        return curve;
    }

    private String getCurveName(Integer algorithmType) {
        Curve curve = ALGORITHM_CURVE_MAP.get(algorithmType);
        return curve != null ? curve.getName() : "Unknown";
    }

    private void validateEddsaAlgorithmType(Integer algorithmType) {
        if (algorithmType == null || !ALGORITHM_CURVE_MAP.containsKey(algorithmType)) {
            throw new IllegalArgumentException("EdDSA algorithm type must be 1 (Ed25519) or 2 (Ed448)");
        }
    }

    @Override
    public String getKeyInfo(Integer algorithmType) {
        OctetKeyPair keyPair = getKeyPair(algorithmType, null);
        if (keyPair != null) {
            return getCurveName(algorithmType) + " - " +
                    "Key ID: " + keyPair.getKeyID() + ", " +
                    "Curve: " + keyPair.getCurve().getName();
        }
        return getCurveName(algorithmType) + " - Key information not available";
    }

    public String getPublicKeyJwk(Integer algorithmType) {
        OctetKeyPair keyPair = getKeyPair(algorithmType, null);
        if (keyPair != null) {
            return keyPair.toPublicJWK().toJSONString();
        }
        return null;
    }

    @Override
    public String getKeyInfo() {
        return "EdDSA Key Directory: " + currentKeyDir +
                ", Algorithms: Ed25519, Ed448";
    }

    @Override
    public Path getKeyPath() {
        return currentKeyDir;
    }

    @Override
    public String getAlgorithmInfo() {
        return "EdDSA algorithms: Ed25519, Ed448";
    }
}