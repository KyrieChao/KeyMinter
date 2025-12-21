package key_minter.util;

import key_minter.auth.core.Jwt;
import key_minter.auth.decoder.JwtDecoder;
import key_minter.auth.factory.JwtFactory;
import key_minter.model.dto.*;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Objects;

/**
 * JWT工具类
 * 提供简化的JWT操作接口
 */
@Component
public class KeyMinter {

    private static final Algorithm DEFAULT_ALGORITHM = Algorithm.HMAC256;
    private volatile Jwt jwtInstance = JwtFactory.get(DEFAULT_ALGORITHM);
    private static final int DEFAULT_SECRET_LENGTH = 64;

    /**
     * 切换默认算法
     *
     * @param algorithm 算法类型
     */
    public void switchTo(Algorithm algorithm) {
        switchTo(algorithm, (String) null);
    }

    /**
     * 切换算法并指定字符串目录
     *
     * @param algorithm 算法类型
     * @param directory 目录路径（字符串）
     */
    public void switchTo(Algorithm algorithm, String directory) {
        switchTo(algorithm, directory, true);
    }

    /**
     * 切换算法并指定路径
     *
     * @param algorithm 算法类型
     * @param path      目录路径
     */
    public void switchTo(Algorithm algorithm, Path path) {
        switchTo(algorithm, path, true);
    }

    /**
     * 切换算法（字符串目录）并设置是否启用轮换
     *
     * @param algorithm      算法类型
     * @param directory      目录（字符串）
     * @param enableRotation 是否启用轮换
     */
    public void switchTo(Algorithm algorithm, String directory, boolean enableRotation) {
        jwtInstance = JwtFactory.get(algorithm, directory, enableRotation);
    }

    /**
     * 切换算法（路径目录）并设置是否启用轮换
     *
     * @param algorithm      算法类型
     * @param path           目录路径
     * @param enableRotation 是否启用轮换
     */
    public void switchTo(Algorithm algorithm, Path path, boolean enableRotation) {
        jwtInstance = JwtFactory.get(algorithm, path, enableRotation);
    }

    public Jwt autoLoad(Algorithm algorithm) {
        return JwtFactory.autoLoad(algorithm);
    }

    public Jwt autoLoad(Algorithm algorithm, boolean force) {
        return JwtFactory.autoLoad(algorithm, force);
    }

    /**
     * 自动加载指定密钥ID（默认目录）
     */
    public Jwt autoLoadWithKeyId(Algorithm algorithm, String keyId) {
        return JwtFactory.autoLoadWithKeyId(algorithm, keyId);
    }

    /**
     * 自动加载指定密钥ID（强制重新加载）
     */
    public Jwt autoLoadWithKeyId(Algorithm algorithm, String keyId, boolean force) {
        return JwtFactory.autoLoadWithKeyId(algorithm, keyId, force);
    }

    /**
     * 自动加载指定目录的首个密钥
     */
    public Jwt autoLoad(Algorithm algorithm, Path directory) {
        return JwtFactory.autoLoad(algorithm, directory);
    }

    /**
     * 自动加载指定目录和密钥ID
     */
    public Jwt autoLoad(Algorithm algorithm, Path directory, String keyId) {
        return JwtFactory.autoLoad(algorithm, directory, keyId);
    }

    /**
     * 自动加载指定目录的首个密钥（字符串目录）
     */
    public Jwt autoLoad(Algorithm algorithm, String directory) {
        return JwtFactory.autoLoad(algorithm, directory != null ? Paths.get(directory) : null);
    }

    /**
     * 自动加载指定目录和密钥ID（字符串目录）
     */
    public Jwt autoLoad(Algorithm algorithm, String directory, String keyId) {
        return JwtFactory.autoLoad(algorithm, directory != null ? Paths.get(directory) : null, keyId);
    }

    /**
     * 生成HMAC密钥
     *
     * @param algorithm HMAC算法
     * @param length    密钥长度
     * @return 是否生成成功
     */
    public boolean createHmacKey(Algorithm algorithm, Integer length) {
        validateHmacAlgorithm(algorithm);
        return jwtInstance.generateHmacKey(Objects.requireNonNullElse(algorithm, DEFAULT_ALGORITHM), Objects.requireNonNullElse(length, DEFAULT_SECRET_LENGTH));
    }

    /**
     * 生成HMAC密钥（指定文件名）
     *
     * @param algorithm HMAC算法
     * @param length    密钥长度
     * @param filename  文件名
     * @return 是否生成成功
     */
    public boolean createHmacKey(Algorithm algorithm, Integer length, String filename) {
        validateHmacAlgorithm(algorithm);
        return jwtInstance.generateHmacKey(Objects.requireNonNullElse(algorithm, DEFAULT_ALGORITHM), Objects.requireNonNullElse(length, DEFAULT_SECRET_LENGTH), filename);
    }

    /**
     * 生成密钥对（非对称加密）
     *
     * @param algorithm 算法类型
     * @return 是否生成成功
     */
    public boolean createKeyPair(Algorithm algorithm) {
        validateAsymmetricAlgorithm(algorithm);
        return jwtInstance.generateKeyPair(algorithm);
    }

    /**
     * 生成密钥对（非对称加密）并指定文件名
     *
     * @param algorithm 算法类型
     * @param filename  文件名
     * @return 是否生成成功
     */
    public boolean createKeyPair(Algorithm algorithm, String filename) {
        validateAsymmetricAlgorithm(algorithm);
        return jwtInstance.generateKeyPair(algorithm, filename);
    }

    /**
     * 生成密钥对（非对称加密）并指定密钥大小
     *
     * @param algorithm 算法类型
     * @param keySize   密钥大小
     * @return 是否生成成功
     */
    public boolean createKeyPair(Algorithm algorithm, Integer keySize) {
        validateAsymmetricAlgorithm(algorithm);
        return jwtInstance.generateRSAKeyPair(algorithm, keySize);
    }

    /**
     * 生成密钥对（非对称加密）并指定密钥大小和文件名
     *
     * @param algorithm          算法类型
     * @param keySize            密钥大小
     * @param privateKeyFilename 私钥文件名
     * @param publicKeyFilename  公钥文件名
     * @return 是否生成成功
     */
    public boolean createKeyPair(Algorithm algorithm, Integer keySize, String privateKeyFilename, String publicKeyFilename) {
        validateAsymmetricAlgorithm(algorithm);
        return jwtInstance.generateRSAKeyPair(algorithm, keySize, privateKeyFilename, publicKeyFilename);
    }

    /**
     * 生成不包含自定义信息的Token（使用默认算法）
     *
     * @param jwtInfo JWT基本信息
     * @return 生成的Token字符串
     */
    public String generateToken(JwtProperties jwtInfo) {
        return generateToken(jwtInfo, DEFAULT_ALGORITHM);
    }

    /**
     * 生成不包含自定义信息的Token（指定算法）
     *
     * @param jwtInfo   JWT基本信息
     * @param algorithm 算法类型
     * @return 生成的Token字符串
     */
    public String generateToken(JwtProperties jwtInfo, Algorithm algorithm) {
        JwtProperties properties = buildJwtProperties(jwtInfo);
        return jwtInstance.generateToken(properties, algorithm, null, Void.class);
    }

    /**
     * 生成包含自定义信息的Token（泛型版本，使用默认算法）
     *
     * @param jwtInfo      JWT基本信息
     * @param customClaims 自定义声明对象
     * @param claimsType   自定义声明类型
     * @return 生成的Token字符串
     */
    public <T> String generateToken(JwtProperties jwtInfo, T customClaims, Class<T> claimsType) {
        return generateToken(jwtInfo, customClaims, claimsType, DEFAULT_ALGORITHM);
    }

    /**
     * 生成包含自定义信息的Token（泛型版本，指定算法）
     *
     * @param jwtInfo      JWT基本信息
     * @param customClaims 自定义声明对象
     * @param claimsType   自定义声明类型
     * @param algorithm    算法类型
     * @return 生成的Token字符串
     */
    public <T> String generateToken(JwtProperties jwtInfo, T customClaims, Class<T> claimsType, Algorithm algorithm) {
        JwtProperties properties = buildJwtProperties(jwtInfo);
        return jwtInstance.generateToken(properties, algorithm, customClaims, claimsType);
    }

    /**
     * 获取Token的标准信息
     *
     * @param token JWT Token
     * @param clazz 自定义声明类型
     * @return 标准信息对象
     */
    public <T> JwtStandardInfo getStandardInfo(String token, Class<T> clazz) {
        JwtFullInfo<T> fullInfo = JwtDecoder.decodeToFullInfo(token, clazz, jwtInstance);
        return fullInfo.getStandardInfo();
    }

    /**
     * 获取Token的自定义信息
     *
     * @param token JWT Token
     * @param clazz 自定义声明类型
     * @return 自定义声明对象
     */
    public <T> T getCustomClaims(String token, Class<T> clazz) {
        JwtFullInfo<T> fullInfo = JwtDecoder.decodeToFullInfo(token, clazz, jwtInstance);
        return fullInfo.getCustomClaims();
    }

    /**
     * 安全获取Token的自定义信息（不抛出异常）
     *
     * @param token JWT Token
     * @param clazz 自定义声明类型
     * @return 自定义声明对象，解析失败时返回null
     */
    public <T> T getCustomClaimsSafe(String token, Class<T> clazz) {
        JwtFullInfo<T> fullInfo = JwtDecoder.decodeToFullInfoSafe(token, clazz, jwtInstance);
        return fullInfo != null ? fullInfo.getCustomClaims() : null;
    }

    /**
     * 获取Token的完整信息
     *
     * @param token JWT Token
     * @param clazz 自定义声明类型
     * @return 完整信息对象
     */
    public <T> JwtFullInfo<T> getFullInfo(String token, Class<T> clazz) {
        return JwtDecoder.decodeToFullInfo(token, clazz, jwtInstance);
    }

    /**
     * 安全获取Token的完整信息（不抛出异常）
     *
     * @param token JWT Token
     * @param clazz 自定义声明类型
     * @return 完整信息对象，解析失败时返回null
     */
    public <T> JwtFullInfo<T> getFullInfoSafe(String token, Class<T> clazz) {
        return JwtDecoder.decodeToFullInfoSafe(token, clazz, jwtInstance);
    }

    /**
     * 验证Token是否有效
     *
     * @param token JWT Token
     * @return 是否有效
     */
    public boolean isValidToken(String token) {
        return jwtInstance.verifyToken(token);
    }

    /**
     * 刷新Token（如果支持）
     *
     * @param token 原Token
     * @return 新Token，不支持时返回null
     */
    public String refreshToken(String token) {
        return jwtInstance.refreshToken(token);
    }

    /**
     * 撤销Token（如果支持）
     *
     * @param token 要撤销的Token
     * @return 是否撤销成功
     */
    public boolean revokeToken(String token) {
        return jwtInstance.revokeToken(token);
    }

    /**
     * 获取JWT实例信息
     *
     * @return JWT实例描述信息
     */
    public String getJwtProperties() {
        return jwtInstance.getKeyInfo();
    }

    /**
     * 获取算法信息
     *
     * @return 算法描述信息
     */
    public String getAlgorithmInfo() {
        return jwtInstance.getAlgorithmInfo();
    }

    /**
     * 检查密钥是否存在
     *
     * @return 密钥是否存在
     */
    public boolean isSecretKeyExists() {
        return jwtInstance.secretKeyExists();
    }

    /**
     * 检查指定算法的密钥是否存在
     *
     * @param algorithm 算法类型
     * @return 密钥是否存在
     */
    public boolean isSecretKeyExists(Algorithm algorithm) {
        return jwtInstance.secretKeyExists(algorithm);
    }

    /**
     * 获取公钥
     *
     * @return 公钥对象
     */
    public Object getPublicKey() {
        return jwtInstance.getPublicKey();
    }

    /**
     * 获取指定算法的公钥
     *
     * @param algorithm 算法类型
     * @return 公钥对象
     */
    public Object getPublicKey(Algorithm algorithm) {
        return jwtInstance.getPublicKey(algorithm);
    }

    /**
     * 获取曲线信息（仅ECDSA算法）
     *
     * @param algorithm ECDSA算法
     * @return 曲线信息
     */
    public String getCurveInfo(Algorithm algorithm) {
        return jwtInstance.getCurveInfo(algorithm);
    }

    /**
     * 获取全部密钥信息
     *
     * @return 密钥信息
     */
    public List<KeyVersion> listAllKeys() {
        return jwtInstance.listAllKeys();
    }

    /**
     * 列出指定目录下的密钥
     *
     * @param directory 目录路径
     * @return 密钥列表
     */
    public List<KeyVersion> listAllKeys(String directory) {
        return jwtInstance.listAllKeys(directory);
    }

    /**
     * 列出指定目录下的密钥
     *
     * @param algorithm 算法类型
     * @param directory 目录路径
     * @return 密钥列表
     */
    public List<KeyVersion> listKeys(Algorithm algorithm, String directory) {
        return switch (algorithm) {
            case HMAC256, HMAC384, HMAC512 -> jwtInstance.listHmacKeys(directory);
            case Ed448, Ed25519 -> jwtInstance.listEDKeys(directory);
            case ES256, ES384, ES512 -> jwtInstance.listECKeys(directory);
            default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        };
    }

    /**
     * 列出指定算法的密钥
     *
     * @param algorithm 算法类型
     * @return 密钥列表
     */
    public List<KeyVersion> listKeys(Algorithm algorithm) {
        return switch (algorithm) {
            case HMAC256, HMAC384, HMAC512 -> jwtInstance.listHmacKeys();
            case Ed448, Ed25519 -> jwtInstance.listEDKeys();
            case ES256, ES384, ES512 -> jwtInstance.listECKeys();
            default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        };
    }

    /**
     * 检查Token是否可解码
     *
     * @param token JWT Token
     * @return 是否可解码
     */
    public boolean isTokenDecodable(String token) {
        return JwtDecoder.isTokenDecodable(token, jwtInstance);
    }


    /**
     * 构建JWT属性对象
     */
    private JwtProperties buildJwtProperties(JwtProperties jwtInfo) {
        if (jwtInfo == null) {
            throw new IllegalArgumentException("JwtProperties cannot be null");
        }
        return JwtProperties.builder().subject(jwtInfo.getSubject()).issuer(jwtInfo.getIssuer()).expiration(jwtInfo.getExpiration()).build();
    }

    /**
     * 验证HMAC算法
     */
    private void validateHmacAlgorithm(Algorithm algorithm) {
        if (algorithm != null && !algorithm.isHmac()) {
            throw new IllegalArgumentException("Algorithm must be HMAC type: " + algorithm);
        }
    }

    /**
     * 验证非对称加密算法
     */
    private void validateAsymmetricAlgorithm(Algorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null");
        }
        if (algorithm.isHmac()) {
            throw new IllegalArgumentException("HMAC algorithm does not support key pair generation: " + algorithm);
        }
    }

    /**
     * 清理缓存（用于测试或内存管理）
     */
    public void clearCache() {
        JwtFactory.clearCache();
    }

    /**
     * 获取当前缓存大小
     */
    public int getCacheSize() {
        return JwtFactory.getCacheSize();
    }
}
