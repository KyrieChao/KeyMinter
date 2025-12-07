package com.chao.devtoolkit.crypto;

import com.chao.devtoolkit.config.JwtProperties;
import com.chao.devtoolkit.core.AbstractJwt;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.micrometer.common.util.StringUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;

// RsaJwt.java
@Slf4j
@Getter
public class RsaJwt extends AbstractJwt {
    private static final Path DEFAULT_KEY_DIR = Paths.get(System.getProperty("user.home"), ".chao", "rsa-keys");
    private static final String DEFAULT_PRIVATE_KEY_FILENAME = "rsa-private.key";
    private static final String DEFAULT_PUBLIC_KEY_FILENAME = "rsa-public.key";
    private Path currentPrivateKeyPath;
    public Path currentPublicKeyPath;
    private KeyPair keyPair;

    // 默认构造函数
    public RsaJwt() {
        this.currentPrivateKeyPath = DEFAULT_KEY_DIR.resolve(DEFAULT_PRIVATE_KEY_FILENAME);
        this.currentPublicKeyPath = DEFAULT_KEY_DIR.resolve(DEFAULT_PUBLIC_KEY_FILENAME);
    }

    // 指定目录的构造函数
    public RsaJwt(String directory) {
        if (StringUtils.isBlank(directory)) {
            directory = DEFAULT_KEY_DIR.toString();
        }
        this.currentPrivateKeyPath = Paths.get(directory, DEFAULT_PRIVATE_KEY_FILENAME);
        this.currentPublicKeyPath = Paths.get(directory, DEFAULT_PUBLIC_KEY_FILENAME);
    }

    // 指定目录和文件名的构造函数
    public RsaJwt(String directory, String privateKeyFilename, String publicKeyFilename) {
        if (StringUtils.isBlank(directory)) {
            directory = DEFAULT_KEY_DIR.toString();
        }
        if (StringUtils.isBlank(privateKeyFilename)) {
            privateKeyFilename = DEFAULT_PRIVATE_KEY_FILENAME;
        }
        if (StringUtils.isBlank(publicKeyFilename)) {
            publicKeyFilename = DEFAULT_PUBLIC_KEY_FILENAME;
        }
        this.currentPrivateKeyPath = Paths.get(directory, privateKeyFilename);
        this.currentPublicKeyPath = Paths.get(directory, publicKeyFilename);
    }

    @Override
    public boolean generateKeyPair(Integer keySize) {
        return generateKeyPair(keySize, null, null);
    }

    /**
     * 生成密钥对 - 支持指定密钥大小和自定义文件名
     */
    public boolean generateKeyPair(Integer keySize, String privateKeyFilename, String publicKeyFilename) {
        int size = (keySize == null || keySize < 2048) ? 2048 : keySize;

        // 如果指定了文件名，更新路径
        if (!StringUtils.isBlank(privateKeyFilename)) {
            this.currentPrivateKeyPath = this.currentPrivateKeyPath.getParent().resolve(privateKeyFilename);
        }
        if (!StringUtils.isBlank(publicKeyFilename)) {
            this.currentPublicKeyPath = this.currentPublicKeyPath.getParent().resolve(publicKeyFilename);
        }

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(size);
            this.keyPair = keyPairGenerator.generateKeyPair();

            saveKeyPair();
            log.info("RSA key pair generated with size: {}, stored in: {}", size, currentPrivateKeyPath.getParent());
            return true;

        } catch (NoSuchAlgorithmException | IOException e) {
            log.error("Failed to generate RSA key pair: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 在指定目录生成密钥对
     */
    public boolean generateKeyPairInDirectory(Integer keySize, String directory,
                                              String privateKeyFilename, String publicKeyFilename) {
        if (!StringUtils.isBlank(directory)) {
            if (!StringUtils.isBlank(privateKeyFilename)) {
                this.currentPrivateKeyPath = Paths.get(directory, privateKeyFilename);
            } else {
                this.currentPrivateKeyPath = Paths.get(directory, DEFAULT_PRIVATE_KEY_FILENAME);
            }
            if (!StringUtils.isBlank(publicKeyFilename)) {
                this.currentPublicKeyPath = Paths.get(directory, publicKeyFilename);
            } else {
                this.currentPublicKeyPath = Paths.get(directory, DEFAULT_PUBLIC_KEY_FILENAME);
            }
        }
        return generateKeyPair(keySize);
    }

    @Override
    public PublicKey getPublicKey() {
        if (keyPair == null) {
            loadKeyPair();
        }
        return keyPair != null ? keyPair.getPublic() : null;
    }

    @Override
    protected String getSecretKey() {
        // 对于RSA，返回私钥的Base64编码
        if (keyPair == null) {
            loadKeyPair();
        }
        if (keyPair == null) {
            throw new IllegalStateException("RSA key pair not found. Please generate one first.");
        }
        return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }

    // RSA专用的签名算法获取方法
    protected SignatureAlgorithm getRsaSignWith(int n) {
        return switch (n) {
            case 1 -> Jwts.SIG.RS256;
            case 2 -> Jwts.SIG.RS384;
            case 3 -> Jwts.SIG.RS512;
            default -> throw new IllegalStateException("Unexpected value for RSA algorithm: " + n);
        };
    }

    @Override
    public String generateToken(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType) {
        validateJwtProperties(properties);
        validateRsaAlgorithmType(algorithmType);

        if (keyPair == null) {
            loadKeyPair();
            if (keyPair == null) {
                throw new IllegalStateException("RSA key pair not initialized. Call generateKeyPair first.");
            }
        }
        return generateJwt(properties, customClaims, algorithmType);
    }

    @Override
    public boolean verifyToken(String token) {
        if (StringUtils.isBlank(token)) return false;
        try {
            if (keyPair == null) {
                loadKeyPair();
            }
            Jwts.parser()
                    .verifyWith(keyPair.getPublic())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("RSA JWT verification failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public Claims decodePayload(String token) {
        if (StringUtils.isBlank(token)) throw new IllegalArgumentException("Token cannot be null or empty");
        try {
            if (keyPair == null) {
                loadKeyPair();
            }
            return Jwts.parser()
                    .verifyWith(keyPair.getPublic())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

        } catch (JwtException e) {
            throw new SecurityException("RSA JWT validation failed: " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid token format: " + e.getMessage(), e);
        }
    }

    @Override
    public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType) {
        return generateRsaJwt(properties, customClaims, algorithmType);
    }

    @Override
    public String generateJwt(JwtProperties properties, Integer algorithmType) {
        return generateRsaJwt(properties, null, algorithmType);
    }

    @Override
    protected MacAlgorithm getSignAlgorithm(Integer algorithmType) {
        throw new UnsupportedOperationException("RSA algorithm uses SignatureAlgorithm, not MacAlgorithm");
    }

    private String generateRsaJwt(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType) {
        JwtBuilder builder = createJwtBuilder(properties, customClaims);
        return builder
                .signWith(keyPair.getPrivate(), getRsaSignWith(algorithmType))
                .compact();
    }

    /**
     * 保存密钥对到文件
     */
    private void saveKeyPair() throws IOException {
        Files.createDirectories(currentPrivateKeyPath.getParent());

        // 保存私钥
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        Files.write(currentPrivateKeyPath, privateKeyBytes,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        // 保存公钥
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        Files.write(currentPublicKeyPath, publicKeyBytes,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        // 设置文件权限
        setRestrictiveFilePermissions(currentPrivateKeyPath);
    }

    /**
     * 加载密钥对
     */
    private void loadKeyPair() {
        loadKeyPair(currentPrivateKeyPath, currentPublicKeyPath);
    }

    /**
     * 加载指定路径的密钥对
     */
    private void loadKeyPair(Path privateKeyPath, Path publicKeyPath) {
        try {
            if (!Files.exists(privateKeyPath) || !Files.exists(publicKeyPath)) {
                return;
            }

            // 加载私钥
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            // 加载公钥
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyPath);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            this.keyPair = new KeyPair(publicKey, privateKey);

        } catch (Exception e) {
            log.error("Failed to load RSA key pair from {}: {}", privateKeyPath, e.getMessage());
        }
    }


    private void setRestrictiveFilePermissions(Path path) {
        try {
            Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, perms);
        } catch (UnsupportedOperationException e) {
            log.debug("POSIX file permissions not supported");
        } catch (IOException e) {
            log.warn("Failed to set file permissions: {}", e.getMessage());
        }
    }

    /**
     * 切换到不同的密钥文件
     */
    public boolean switchKeyFiles(String privateKeyPath, String publicKeyPath) {
        if (StringUtils.isBlank(privateKeyPath) || StringUtils.isBlank(publicKeyPath)) {
            return false;
        }
        privateKeyPath = privateKeyPath.replace("/", File.separator).replace("\\", File.separator);
        publicKeyPath = publicKeyPath.replace("/", File.separator).replace("\\", File.separator);

        Path privatePath = Paths.get(privateKeyPath);
        Path publicPath = Paths.get(publicKeyPath);

        if (Files.exists(privatePath) && Files.exists(publicPath)) {
            this.currentPrivateKeyPath = privatePath;
            this.currentPublicKeyPath = publicPath;
            this.keyPair = null; // 清空缓存，重新加载
            loadKeyPair();
            log.info("Switched to key files: private={}, public={}", privateKeyPath, publicKeyPath);
            return this.keyPair != null;
        } else {
            log.warn("Key files do not exist: private={}, public={}", privateKeyPath, publicKeyPath);
            return false;
        }
    }

    /**
     * 切换到不同目录下的密钥文件
     */
    public boolean switchKeyDirectory(String directory) {
        if (StringUtils.isBlank(directory)) {
            return false;
        }

        Path newPrivatePath = Paths.get(directory, DEFAULT_PRIVATE_KEY_FILENAME);
        Path newPublicPath = Paths.get(directory, DEFAULT_PUBLIC_KEY_FILENAME);

        return switchKeyFiles(newPrivatePath.toString(), newPublicPath.toString());
    }

    /**
     * 列出密钥目录中的所有密钥文件
     */
    public List<Path> listKeyFiles() {
        try {
            Path directory = currentPrivateKeyPath.getParent();
            if (Files.exists(directory) && Files.isDirectory(directory)) {
                return Files.list(directory)
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
    @Override
    public String getKeyInfo() {
        return "RSA Keys - Private: " + currentPrivateKeyPath +
                ", Public: " + currentPublicKeyPath +
                ", Both exist: " + (Files.exists(currentPrivateKeyPath) && Files.exists(currentPublicKeyPath));
    }

    @Override
    public Path getKeyPath() {
        return currentPrivateKeyPath.getParent(); // 返回目录
    }

    @Override
    public String getAlgorithmInfo() {
        return "RSA algorithms: RS256, RS384, RS512";
    }
    /**
     * 检查密钥文件是否存在
     */
    public boolean keyPairExists() {
        return Files.exists(currentPrivateKeyPath) && Files.exists(currentPublicKeyPath);
    }

    public boolean keyPairExists(String privateKeyPath, String publicKeyPath) {
        return Files.exists(Paths.get(privateKeyPath)) && Files.exists(Paths.get(publicKeyPath));
    }

    /**
     * 获取默认密钥目录
     */
    public static Path getDefaultKeyDir() {
        return DEFAULT_KEY_DIR;
    }

    private void validateRsaAlgorithmType(Integer algorithmType) {
        if (algorithmType == null || algorithmType < 1 || algorithmType > 3) {
            throw new IllegalArgumentException("RSA algorithm type must be 1 (RS256), 2 (RS384), or 3 (RS512)");
        }
    }
}