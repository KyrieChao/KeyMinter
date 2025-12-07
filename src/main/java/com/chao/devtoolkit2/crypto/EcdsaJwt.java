package com.chao.devtoolkit.crypto;

import com.chao.devtoolkit.config.JwtProperties;
import com.chao.devtoolkit.core.AbstractJwt;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.micrometer.common.util.StringUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.*;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
public class EcdsaJwt extends AbstractJwt {

    private static final Path DEFAULT_KEY_DIR = Paths.get(System.getProperty("user.home"), ".chao", "ec-keys");
    // 存储不同算法的密钥对
    private final Map<Integer, KeyPair> keyPairMap = new ConcurrentHashMap<>();
    // 算法与默认文件名的映射
    private static final Map<Integer, String> ALGORITHM_FILENAME_MAP = Map.of(
            1, "es256",
            2, "es384",
            3, "es512"
    );
    // 算法与曲线的映射
    private static final Map<Integer, String> ALGORITHM_CURVE_MAP = Map.of(
            // ES256 -> P-256
            1, "secp256r1",
            // ES384 -> P-384
            2, "secp384r1",
            // ES512 -> P-521
            3, "secp521r1"
    );
    // 默认构造函数
    public EcdsaJwt() {
        this.currentKeyDir = DEFAULT_KEY_DIR;
    }

    // 指定目录的构造函数
    public EcdsaJwt(String directory) {
        if (StringUtils.isBlank(directory)) {
            this.currentKeyDir = DEFAULT_KEY_DIR;
        } else {
            this.currentKeyDir = Paths.get(directory);
        }
    }

    // 指定完整路径的构造函数
    public EcdsaJwt(Path keyDir) {
        this.currentKeyDir = keyDir != null ? keyDir : DEFAULT_KEY_DIR;
    }

    @Override
    public boolean generateKeyPair(Integer algorithmType) {
        return generateKeyPair(algorithmType, null);
    }

    /**
     * 生成密钥对 - 支持指定算法类型和自定义文件名
     */
    @Override
    public boolean generateKeyPair(Integer algorithmType, String customFilename) {
        if (algorithmType == null || !ALGORITHM_CURVE_MAP.containsKey(algorithmType)) {
            throw new IllegalArgumentException("Algorithm type must be 1 (ES256), 2 (ES384), or 3 (ES512)");
        }

        String curveName = ALGORITHM_CURVE_MAP.get(algorithmType);
        String filename = getKeyFilename(algorithmType, customFilename);

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            keyPairGenerator.initialize(ecSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            keyPairMap.put(algorithmType, keyPair);
            saveKeyPair(algorithmType, keyPair, filename);

            log.info("ECDSA key pair generated for {} with curve: {}, stored in: {}",
                    getAlgorithmName(algorithmType), curveName, currentKeyDir);
            return true;

        } catch (Exception e) {
            log.error("Failed to generate ECDSA key pair for {}: {}",
                    getAlgorithmName(algorithmType), e.getMessage());
            return false;
        }
    }

    /**
     * 在指定目录生成密钥对
     */
    public boolean generateKeyPairInDirectory(Integer algorithmType, String directory, String customFilename) {
        if (!StringUtils.isBlank(directory)) {
            this.currentKeyDir = Paths.get(directory);
        }
        return generateKeyPair(algorithmType, customFilename);
    }

    // 为所有算法生成密钥对
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
    public PublicKey getPublicKey() {
        // 返回默认算法（ES256）的公钥
        return getPublicKey(1);
    }

    public PublicKey getPublicKey(Integer algorithmType) {
        KeyPair keyPair = getKeyPair(algorithmType);
        return keyPair != null ? keyPair.getPublic() : null;
    }

    @Override
    protected String getSecretKey() {
        // 返回默认算法的私钥
        return getSecretKey(1);
    }

    protected String getSecretKey(Integer algorithmType) {
        KeyPair keyPair = getKeyPair(algorithmType);
        if (keyPair == null) {
            throw new IllegalStateException("ECDSA key pair not found for " +
                    getAlgorithmName(algorithmType) +
                    ". Please generate one first.");
        }
        return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }


    protected SignatureAlgorithm getEcdsaSignWith(int algorithmType) {
        return switch (algorithmType) {
            case 1 -> Jwts.SIG.ES256;
            case 2 -> Jwts.SIG.ES384;
            case 3 -> Jwts.SIG.ES512;
            default -> throw new IllegalStateException("Unexpected value for ECDSA algorithm: " + algorithmType);
        };
    }

    @Override
    public String generateToken(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType) {
        validateJwtProperties(properties);
        validateEcdsaAlgorithmType(algorithmType);
        return generateJwt(properties, customClaims, algorithmType);
    }

    @Override
    public boolean verifyToken(String token) {
        if (StringUtils.isBlank(token)) {
            return false;
        }

        try {
            // 从token中提取算法信息
            Integer algorithmType = extractAlgorithmTypeFromToken(token);
            if (algorithmType == null) {
                return false;
            }

            KeyPair keyPair = getKeyPair(algorithmType);
            if (keyPair == null) {
                return false;
            }

            Jwts.parser()
                    .verifyWith(keyPair.getPublic())
                    .build()
                    .parseSignedClaims(token);
            return true;

        } catch (JwtException | IllegalArgumentException e) {
            log.warn("ECDSA JWT verification failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public Claims decodePayload(String token) {
        if (StringUtils.isBlank(token)) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }

        try {
            // 从token中提取算法信息
            Integer algorithmType = extractAlgorithmTypeFromToken(token);
            if (algorithmType == null) {
                throw new IllegalArgumentException("Unable to determine algorithm from token");
            }

            KeyPair keyPair = getKeyPair(algorithmType);
            if (keyPair == null) {
                throw new IllegalStateException("No key pair found for algorithm: " + getAlgorithmName(algorithmType));
            }

            return Jwts.parser()
                    .verifyWith(keyPair.getPublic())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

        } catch (JwtException e) {
            throw new SecurityException("ECDSA JWT validation failed: " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid token format: " + e.getMessage(), e);
        }
    }

    @Override
    public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType) {
        return generateEcdsaJwt(properties, customClaims, algorithmType);
    }

    @Override
    public String generateJwt(JwtProperties properties, Integer algorithmType) {
        return generateEcdsaJwt(properties, null, algorithmType);
    }

    @Override
    protected MacAlgorithm getSignAlgorithm(Integer algorithmType) {
        throw new UnsupportedOperationException("ECDSA algorithm uses SignatureAlgorithm, not MacAlgorithm");
    }

    private String generateEcdsaJwt(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType) {
        KeyPair keyPair = getKeyPair(algorithmType);
        if (keyPair == null) {
            throw new IllegalStateException("ECDSA key pair not initialized for " +
                    getAlgorithmName(algorithmType) + ". Call generateKeyPair(" + algorithmType + ") first.");
        }
        JwtBuilder builder = createJwtBuilder(properties, customClaims);
        return builder
                .signWith(keyPair.getPrivate(), getEcdsaSignWith(algorithmType))
                .compact();
    }

    private KeyPair getKeyPair(Integer algorithmType) {
        return getKeyPair(algorithmType, null);
    }

    private KeyPair getKeyPair(Integer algorithmType, String customFilename) {
        // 先从内存中获取
        KeyPair keyPair = keyPairMap.get(algorithmType);
        if (keyPair == null) {
            // 从文件加载
            String filename = getKeyFilename(algorithmType, customFilename);
            keyPair = loadKeyPair(algorithmType, filename);
            if (keyPair != null) {
                keyPairMap.put(algorithmType, keyPair);
            }
        }
        return keyPair;
    }

    /**
     * 保存密钥对到文件
     */
    private void saveKeyPair(Integer algorithmType, KeyPair keyPair, String filename) throws IOException {
        Files.createDirectories(currentKeyDir);

        Path privateKeyPath = currentKeyDir.resolve(filename + "-private.key");
        Path publicKeyPath = currentKeyDir.resolve(filename + "-public.key");

        // 保存私钥
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        Files.write(privateKeyPath, privateKeyBytes,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        // 保存公钥
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        Files.write(publicKeyPath, publicKeyBytes,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        // 设置文件权限
        setRestrictiveFilePermissions(privateKeyPath);

        log.debug("Saved key pair for {}: private={}, public={}",
                getAlgorithmName(algorithmType), privateKeyPath, publicKeyPath);
    }


    /**
     * 加载密钥对
     */
    private KeyPair loadKeyPair(Integer algorithmType, String filename) {
        try {
            Path privateKeyPath = currentKeyDir.resolve(filename + "-private.key");
            Path publicKeyPath = currentKeyDir.resolve(filename + "-public.key");

            if (!Files.exists(privateKeyPath) || !Files.exists(publicKeyPath)) {
                return null;
            }

            // 加载私钥
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            // 加载公钥
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyPath);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            return new KeyPair(publicKey, privateKey);

        } catch (Exception e) {
            log.error("Failed to load ECDSA key pair for {}: {}",
                    getAlgorithmName(algorithmType), e.getMessage());
            return null;
        }
    }

    /**
     * 获取密钥文件名
     */
    private String getKeyFilename(Integer algorithmType, String customFilename) {
        if (!StringUtils.isBlank(customFilename)) {
            return customFilename;
        }
        return ALGORITHM_FILENAME_MAP.get(algorithmType);
    }

    /**
     * 切换到不同的密钥目录
     */
    public boolean switchKeyDirectory(String directory) {
        if (StringUtils.isBlank(directory)) {
            return false;
        }

        Path newDir = Paths.get(directory);
        if (Files.exists(newDir) && Files.isDirectory(newDir)) {
            this.currentKeyDir = newDir;
            keyPairMap.clear(); // 清空缓存，重新加载
            log.info("Switched to key directory: {}", newDir);
            return true;
        } else {
            log.warn("Key directory does not exist or is not a directory: {}", newDir);
            return false;
        }
    }

    /**
     * 列出当前目录中的所有密钥文件
     */
    public List<Path> listKeyFiles() {
        try {
            if (Files.exists(currentKeyDir) && Files.isDirectory(currentKeyDir)) {
                return Files.list(currentKeyDir)
                        .filter(Files::isRegularFile)
                        .filter(path -> path.toString().endsWith(".key"))
                        .sorted()
                        .collect(Collectors.toList());
            }
        } catch (IOException e) {
            log.warn("Failed to list key files: {}", e.getMessage());
        }
        return Collections.emptyList();
    }

    public boolean keyPairExists(Integer algorithmType, String customFilename) {
        String filename = getKeyFilename(algorithmType, customFilename);
        Path privateKeyPath = currentKeyDir.resolve(filename + "-private.key");
        Path publicKeyPath = currentKeyDir.resolve(filename + "-public.key");

        return Files.exists(privateKeyPath) && Files.exists(publicKeyPath);
    }

    /**
     * 检查指定算法的密钥文件是否存在
     */
    public boolean keyPairExists(Integer algorithmType) {
        return keyPairExists(algorithmType, null);
    }

    private Integer extractAlgorithmTypeFromToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) return null;

            String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            JsonNode headerNode = new ObjectMapper().readTree(header);
            String alg = headerNode.get("alg").asText();

            return switch (alg) {
                case "ES256" -> 1;
                case "ES384" -> 2;
                case "ES512" -> 3;
                default -> null;
            };

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 获取默认密钥目录
     */
    public static Path getDefaultKeyDir() {
        return DEFAULT_KEY_DIR;
    }

    private String getAlgorithmName(Integer algorithmType) {
        return switch (algorithmType) {
            case 1 -> "ES256";
            case 2 -> "ES384";
            case 3 -> "ES512";
            default -> "UNKNOWN";
        };
    }

    private void validateEcdsaAlgorithmType(Integer algorithmType) {
        if (algorithmType == null || !ALGORITHM_CURVE_MAP.containsKey(algorithmType)) {
            throw new IllegalArgumentException("ECDSA algorithm type must be 1 (ES256), 2 (ES384), or 3 (ES512)");
        }
    }

    // 获取曲线信息
    @Override
    public String getCurveInfo(Integer algorithmType) {
        KeyPair keyPair = getKeyPair(algorithmType);
        if (keyPair != null && keyPair.getPublic() instanceof ECPublicKey ecPublicKey) {
            ECParameterSpec params = ecPublicKey.getParams();
            return getAlgorithmName(algorithmType) + " - Curve: " +
                    ALGORITHM_CURVE_MAP.get(algorithmType) +
                    ", Key Size: " + params.getCurve().getField().getFieldSize();
        }
        return getAlgorithmName(algorithmType) + " - Curve information not available";
    }

    // 检查是否所有密钥对都已生成
    public boolean allKeyPairsGenerated() {
        for (Integer algorithmType : ALGORITHM_CURVE_MAP.keySet()) {
            if (getKeyPair(algorithmType) == null) {
                return false;
            }
        }
        return true;
    }

    private void setRestrictiveFilePermissions(Path path) {
        try {
            // 方法1: 首先尝试POSIX权限（Linux/Mac）
            if (setPosixPermissions(path)) {
                return;
            }

            // 方法2: 尝试ACL权限（Windows）
            if (setAclPermissions(path)) {
                return;
            }

            // 方法3: 最后尝试Java基本权限设置
            setBasicPermissions(path);

        } catch (Exception e) {
            log.warn("Failed to set restrictive permissions for {}: {}", path, e.getMessage());
        }
    }

    private boolean setPosixPermissions(Path path) {
        try {
            if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
                Set<PosixFilePermission> permissions = EnumSet.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE
                );
                Files.setPosixFilePermissions(path, permissions);
                log.debug("Set POSIX permissions (600) for file: {}", path);
                return true;
            }
        } catch (IOException e) {
            log.debug("POSIX permission setting failed: {}", e.getMessage());
        }
        return false;
    }

    private boolean setAclPermissions(Path path) {
        try {
            AclFileAttributeView aclView = Files.getFileAttributeView(path, AclFileAttributeView.class);
            if (aclView != null) {
                UserPrincipal owner = aclView.getOwner();

                // 创建只有所有者有读写权限的ACL条目
                Set<AclEntryPermission> permissions = EnumSet.of(
                        AclEntryPermission.READ_DATA,
                        AclEntryPermission.WRITE_DATA,
                        AclEntryPermission.READ_ATTRIBUTES,
                        AclEntryPermission.WRITE_ATTRIBUTES,
                        AclEntryPermission.READ_NAMED_ATTRS,
                        AclEntryPermission.WRITE_NAMED_ATTRS,
                        AclEntryPermission.READ_ACL,
                        AclEntryPermission.WRITE_ACL
                );

                AclEntry entry = AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(owner)
                        .setPermissions(permissions)
                        .build();

                List<AclEntry> aclEntries = new ArrayList<>();
                aclEntries.add(entry);

                aclView.setAcl(aclEntries);
                log.debug("Set ACL permissions for file: {}", path);
                return true;
            }
        } catch (IOException e) {
            log.debug("ACL permission setting failed: {}", e.getMessage());
        }
        return false;
    }

    private void setBasicPermissions(Path path) {
        // 在无法设置精细权限的系统上，至少确保文件不是公开可读的
        try {
            // 设置文件为仅对所有者可见（如果可能）
            path.toFile().setReadable(false, false); // 其他人不可读
            path.toFile().setWritable(false, false); // 其他人不可写
            path.toFile().setExecutable(false, false); // 其他人不可执行

            path.toFile().setReadable(true, true);   // 所有者可读
            path.toFile().setWritable(true, true);   // 所有者可写

            log.debug("Set basic restrictive permissions for file: {}", path);
        } catch (Exception e) {
            log.debug("Basic permission setting failed: {}", e.getMessage());
        }
    }
    @Override
    public String getKeyInfo() {
        return "ECDSA Key Directory: " + currentKeyDir +
                ", Algorithms: ES256, ES384, ES512";
    }

    @Override
    public String getAlgorithmInfo() {
        return "ECDSA algorithms: ES256 (P-256), ES384 (P-384), ES512 (P-521)";
    }
}