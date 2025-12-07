package com.chao.devtoolkit.crypto;

import com.chao.devtoolkit.config.JwtProperties;
import com.chao.devtoolkit.core.AbstractJwt;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import io.micrometer.common.util.StringUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

@Getter
@Slf4j
public class HmacJwt extends AbstractJwt {

    protected static final String SECRET_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    private static final Path DEFAULT_SECRET_DIR = Paths.get(System.getProperty("user.home"), ".chao", "hmac-keys");
    private static final String DEFAULT_SECRET_FILENAME = "hmac-secret.key";
    private static final int DEFAULT_SECRET_LENGTH = 64;
    private static final int MIN_SECRET_LENGTH = 32;
    private Path currentSecretPath;

    // 默认构造函数，使用默认路径
    public HmacJwt() {
        this.currentSecretPath = DEFAULT_SECRET_DIR.resolve(DEFAULT_SECRET_FILENAME);
    }

    // 指定目录和文件名的构造函数
    public HmacJwt(String directory, String filename) {
        if (StringUtils.isBlank(directory)) {
            directory = DEFAULT_SECRET_DIR.toString();
        }
        if (StringUtils.isBlank(filename)) {
            filename = DEFAULT_SECRET_FILENAME;
        }
        this.currentSecretPath = Paths.get(directory, filename);
    }

    public HmacJwt(String directory) {
        if (StringUtils.isBlank(directory)) {
            this.currentSecretPath = DEFAULT_SECRET_DIR.resolve(DEFAULT_SECRET_FILENAME);
        } else {
            this.currentSecretPath = Paths.get(directory, DEFAULT_SECRET_FILENAME);
        }
    }

    // 指定完整路径的构造函数
    public HmacJwt(Path secretPath) {
        this.currentSecretPath = Objects.requireNonNullElseGet(secretPath, () -> DEFAULT_SECRET_DIR.resolve(DEFAULT_SECRET_FILENAME));
    }

    @Override
    public String generateToken(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType) {
        validateJwtProperties(properties);
        validateAlgorithmType(algorithmType);
        return generateJwt(properties, customClaims, algorithmType);
    }

    /**
     * 生成 HMAC 密钥对（实际上是对称密钥）
     * 对于 HMAC，这个方法等同于 setSecretKey
     */
    @Override
    public boolean generateHmacKeyPair(Integer algorithmType, Integer len) {
        return generateHmacKeyPair(algorithmType, null,len);
    }

    /**
     * 生成 HMAC 密钥对 - 支持指定密钥长度和自定义文件名
     * 对于 HMAC，algorithmType 参数被忽略，因为 HMAC 使用相同的密钥类型
     */
    @Override
    public boolean generateHmacKeyPair(Integer algorithmType, String customFilename, Integer len) {
        if (!StringUtils.isBlank(customFilename)) {
            String filename = customFilename;
            if (!filename.contains(".")) {
                filename = filename + ".key";
            }
            this.currentSecretPath = this.currentSecretPath.getParent().resolve(filename);
        }
        try {
            Files.createDirectories(currentSecretPath.getParent());
            int n = len == 0 || len < MIN_SECRET_LENGTH ? DEFAULT_SECRET_LENGTH : len;
            String key = generateSecureSecret(n);

            // 设置限制性文件权限
            setRestrictiveFilePermissions();

            Files.writeString(currentSecretPath, key, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);

            log.info("HMAC secret key generated and stored at: {}", currentSecretPath);
            return true;
        } catch (IOException e) {
            log.error("Failed to generate HMAC secret key: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 在指定目录生成 HMAC 密钥
     */
    public boolean generateKeyPairInDirectory(Integer algorithmType, String directory, String customFilename) {
        if (!StringUtils.isBlank(directory)) {
            if (!StringUtils.isBlank(customFilename)) {
                this.currentSecretPath = Paths.get(directory, customFilename);
            } else {
                this.currentSecretPath = Paths.get(directory, DEFAULT_SECRET_FILENAME);
            }
        }
        return generateKeyPair(algorithmType, customFilename);
    }

    /**
     * 为所有支持的 HMAC 算法生成密钥（实际上只生成一个密钥，因为 HMAC 密钥是通用的）
     */
    @Override
    public boolean generateAllKeyPairs() {
        return generateKeyPair(1);
    }


    /**
     * 检查密钥是否存在
     */
    public boolean keyPairExists(Integer algorithmType) {
        return secretKeyExists();
    }

    /**
     * 检查指定算法和文件名的密钥是否存在
     */
    public boolean keyPairExists(Integer algorithmType, String customFilename) {
        Path checkPath = this.currentSecretPath;

        // 如果指定了自定义文件名，构建对应的路径
        if (!StringUtils.isBlank(customFilename)) {
            String filename = customFilename;
            if (!filename.contains(".")) {
                filename = filename + ".key";
            }
            checkPath = this.currentSecretPath.getParent().resolve(filename);
        }

        return secretKeyExists(checkPath);
    }

    /**
     * 在指定目录创建密钥文件
     */
    public boolean setSecretKeyInDirectory(Integer algorithmType,Integer length, String filename, String directory) {
        if (!StringUtils.isBlank(directory)) {
            if (!StringUtils.isBlank(filename)) {
                this.currentSecretPath = Paths.get(directory, filename);
            } else {
                this.currentSecretPath = Paths.get(directory, DEFAULT_SECRET_FILENAME);
            }
        }
        return generateHmacKeyPair(algorithmType, length);
    }

    @Override
    protected String getSecretKey() {
        try {
            if (!Files.exists(currentSecretPath)) {
                throw new IllegalStateException("Secret key not found at: " + currentSecretPath + ". Please generate one first.");
            }
            String key = Files.readString(currentSecretPath, StandardCharsets.UTF_8).trim();
            if (StringUtils.isBlank(key)) {
                throw new IllegalStateException("Secret key file is empty: " + currentSecretPath);
            }
            return key;
        } catch (IOException e) {
            throw new SecurityException("Failed to read secret key from: " + currentSecretPath, e);
        }
    }

    @Override
    protected MacAlgorithm getSignAlgorithm(Integer algorithmType) {
        return switch (algorithmType) {
            case 1 -> Jwts.SIG.HS256;
            case 2 -> Jwts.SIG.HS384;
            case 3 -> Jwts.SIG.HS512;
            default -> throw new IllegalStateException("Unexpected value: " + algorithmType);
        };
    }

    /**
     * 生成安全随机密钥
     */
    private String generateSecureSecret(int length) {
        SecureRandom random = new SecureRandom();
        return random.ints(length, 0, SECRET_CHARS.length())
                .mapToObj(SECRET_CHARS::charAt)
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString();
    }

    @Override
    public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType) {
        byte[] keyBytes = getSecretKey().getBytes(StandardCharsets.UTF_8);
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);
        JwtBuilder builder = createJwtBuilder(properties, customClaims);
        return builder.signWith(key, getSignAlgorithm(algorithmType)).compact();
    }

    @Override
    public boolean verifyToken(String token) {
        if (StringUtils.isBlank(token)) return false;
        try {
            SecretKey key = Keys.hmacShaKeyFor(getSecretKeyBytes());
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("JWT verification failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public Claims decodePayload(String token) {
        if (StringUtils.isBlank(token)) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        try {
            SecretKey key = Keys.hmacShaKeyFor(getSecretKeyBytes());
            return Jwts
                    .parser().verifyWith(key).build()
                    .parseSignedClaims(token).getPayload();
        } catch (JwtException e) {
            throw new SecurityException("JWT validation failed: " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid token format: " + e.getMessage(), e);
        }
    }

    /* 工具：把密钥读成 byte[]，复用 */
    private byte[] getSecretKeyBytes() {
        return getSecretKey().getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String generateJwt(JwtProperties properties, Integer algorithmType) {
        return generateJwt(properties, null, algorithmType);
    }

    /**
     * 设置文件权限，仅允许文件所有者读写
     */
    private void setRestrictiveFilePermissions() {
        try {
            Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(currentSecretPath, perms);
        } catch (UnsupportedOperationException e) {
            log.debug("POSIX file permissions not supported on this platform");
        } catch (IOException e) {
            log.warn("Failed to set restrictive file permissions: {}", e.getMessage());
        }
    }

    /**
     * 检查密钥文件是否存在
     */
    public boolean secretKeyExists() {
        return Files.exists(currentSecretPath) && Files.isReadable(currentSecretPath);
    }

    /**
     * 检查指定路径的密钥文件是否存在
     */
    public boolean secretKeyExists(Path secretPath) {
        return Files.exists(secretPath) && Files.isReadable(secretPath);
    }

    /**
     * 切换到不同的密钥文件
     */
    public boolean switchSecretFile(Path newSecretPath) {
        if (secretKeyExists(newSecretPath)) {
            this.currentSecretPath = newSecretPath;
            log.info("Switched to secret file: {}", newSecretPath);
            return true;
        } else {
            log.warn("Secret file does not exist or is not readable: {}", newSecretPath);
            return false;
        }
    }

    /**
     * 切换到不同目录下的密钥文件
     */
    public boolean switchSecretFile(String directory, String filename) {
        Path newPath = Paths.get(directory, filename);
        return switchSecretFile(newPath);
    }

    /**
     * 列出密钥目录中的所有密钥文件
     */
    public List<Path> listSecretFiles() {
        try {
            Path directory = currentSecretPath.getParent();
            if (Files.exists(directory) && Files.isDirectory(directory)) {
                try (var stream = Files.list(directory)) {
                    return stream.filter(path -> Files.isRegularFile(path) && !Files.isDirectory(path))
                            .filter(path -> path.toString()
                                    .endsWith(".key") || path.toString()
                                    .endsWith(".txt")).sorted()
                            .collect(Collectors.toList());
                }
            }
        } catch (IOException e) {
            log.warn("Failed to list secret files: {}", e.getMessage());
        }
        return Collections.emptyList();
    }

    @Override
    public String getKeyInfo() {
        return "HMAC Secret Path: " + currentSecretPath +
                ", File exists: " + Files.exists(currentSecretPath);
    }

    @Override
    public Path getKeyPath() {
        return currentSecretPath;
    }

    @Override
    public String getAlgorithmInfo() {
        return "HMAC algorithms: HS256, HS384, HS512";
    }

    /**
     * 获取默认密钥目录
     */
    public static Path getDefaultSecretDir() {
        return DEFAULT_SECRET_DIR;
    }

    /**
     * 获取默认密钥文件名
     */
    public static String getDefaultSecretFilename() {
        return DEFAULT_SECRET_FILENAME;
    }
}