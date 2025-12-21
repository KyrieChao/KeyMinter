package key_minter.auth.factory;

import key_minter.auth.core.AbstractJwt;
import key_minter.auth.core.Jwt;
import key_minter.auth.crypto.EcdsaJwt;
import key_minter.auth.crypto.EddsaJwt;
import key_minter.auth.crypto.HmacJwt;
import key_minter.auth.crypto.RsaJwt;
import key_minter.model.dto.Algorithm;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 终极精简版 JWT 工厂
 * - 自动缓存实例
 * - 自动装载密钥
 * - 支持目录、文件、密钥轮换
 */
public class JwtFactory {

    private static final Map<String, Jwt> CACHE = new ConcurrentHashMap<>();

    /**
     * 默认创建（HMAC256），启用轮换
     */
    public static Jwt get() {
        return get(Algorithm.HMAC256, (String) null);
    }

    /**
     * 创建指定算法的实例（默认目录，启用轮换）
     */
    public static Jwt get(Algorithm algorithm) {
        return get(algorithm, (String) null);
    }

    /**
     * 创建指定算法和目录的实例（启用轮换）
     */
    public static Jwt get(Algorithm algorithm, String directory) {
        return get(algorithm, directory, true);
    }

    /**
     * 创建指定算法和目录的实例（指定轮换设置）
     */
    public static Jwt get(Algorithm algorithm, String directory, boolean enableRotation) {
        return get(algorithm, directory != null ? Paths.get(directory) : null, enableRotation);
    }

    /**
     * 创建指定算法和目录路径的实例（启用轮换）
     */
    public static Jwt get(Algorithm algorithm, Path keyDir) {
        return get(algorithm, keyDir, true);
    }

    /**
     * 完整构造：算法 + 目录 + 轮换（核心方法）
     */
    public static Jwt get(Algorithm algorithm, Path keyDir, boolean enableRotation) {
        String cacheKey = buildCacheKey(algorithm, keyDir, enableRotation);
        return CACHE.computeIfAbsent(cacheKey, key -> build(algorithm, keyDir, enableRotation));
    }

    /* -------------------------
     *  自动加载方法
     * ------------------------- */

    /**
     * 自动加载首个密钥（默认目录）
     */
    public static Jwt autoLoad(Algorithm algorithm) {
        return autoLoadFirstKey(algorithm, null, true, false);
    }

    /**
     * 自动加载首个密钥（强制重新加载）
     */
    public static Jwt autoLoad(Algorithm algorithm, boolean force) {
        return autoLoadFirstKey(algorithm, null, true, force);
    }

    /**
     * 自动加载指定密钥ID（默认目录）
     */
    public static Jwt autoLoadWithKeyId(Algorithm algorithm, String keyId) {
        return autoLoadWithKeyId(algorithm, null, keyId, true, false);
    }

    /**
     * 自动加载指定密钥ID（强制重新加载）
     */
    public static Jwt autoLoadWithKeyId(Algorithm algorithm, String keyId, boolean force) {
        return autoLoadWithKeyId(algorithm, null, keyId, true, force);
    }

    /**
     * 自动加载指定目录的首个密钥
     */
    public static Jwt autoLoad(Algorithm algorithm, Path directory) {
        return autoLoadFirstKey(algorithm, directory, true, false);
    }

    /**
     * 自动加载指定目录和密钥ID
     */
    public static Jwt autoLoad(Algorithm algorithm, Path directory, String keyId) {
        return autoLoadWithKeyId(algorithm, directory, keyId, true, false);
    }

    /**
     * 自动加载指定目录的首个密钥（字符串目录）
     */
    public static Jwt autoLoad(Algorithm algorithm, String directory) {
        return autoLoadFirstKey(algorithm, directory != null ?
                Paths.get(directory) : null, true, false);
    }

    /**
     * 自动加载指定目录和密钥ID（字符串目录）
     */
    public static Jwt autoLoad(Algorithm algorithm, String directory, String keyId) {
        return autoLoadWithKeyId(algorithm, directory != null ?
                Paths.get(directory) : null, keyId, true, false);
    }

    /**
     * 自动加载首个密钥的核心方法
     */
    private static Jwt autoLoadFirstKey(Algorithm algorithm, Path directory,boolean enableRotation, boolean force) {
        Jwt jwt = get(algorithm, directory, enableRotation);

        if (jwt instanceof AbstractJwt abstractJwt) {
            abstractJwt.autoLoadFirstKey(algorithm, force);
        }

        return jwt;
    }

    /**
     * 自动加载指定密钥ID的核心方法
     */
    private static Jwt autoLoadWithKeyId(Algorithm algorithm, Path directory, String keyId, boolean enableRotation, boolean force) {
        Jwt jwt = get(algorithm, directory, enableRotation);

        if (jwt instanceof AbstractJwt abstractJwt) {
            abstractJwt.autoLoadFirstKey(algorithm, keyId, force);
        }
        return jwt;
    }

    /**
     * 完整的自动加载方法（保持向后兼容）
     */
    public static Jwt autoLoad(Algorithm algorithm, String directory, String keyId, boolean enableRotation, boolean force) {
        Path path = directory != null ? Paths.get(directory) : null;
        if (keyId != null) {
            return autoLoadWithKeyId(algorithm, path, keyId, enableRotation, force);
        } else {
            return autoLoadFirstKey(algorithm, path, enableRotation, force);
        }
    }

    /* -------------------------
     *  私有方法
     * ------------------------- */

    /**
     * 构建缓存键
     */
    private static String buildCacheKey(Algorithm algorithm, Path keyDir, boolean enableRotation) {
        return String.format("%s:%s:%s", algorithm.name(),
                keyDir != null ? keyDir.toAbsolutePath().toString() : "null", enableRotation
        );
    }

    /**
     * 核心构造逻辑
     */
    private static Jwt build(Algorithm algorithm, Path keyDir, boolean enableRotation) {
        return switch (algorithm) {
            case HMAC256, HMAC384, HMAC512 -> new HmacJwt(keyDir, enableRotation);
            case RSA256, RSA384, RSA512 -> new RsaJwt(keyDir, enableRotation);
            case ES256, ES384, ES512 -> new EcdsaJwt(keyDir, enableRotation);
            case Ed25519, Ed448 -> new EddsaJwt(keyDir, enableRotation);
        };
    }

    /**
     * 清理缓存（用于测试或内存管理）
     */
    public static void clearCache() {
        CACHE.clear();
    }

    /**
     * 获取当前缓存大小
     */
    public static int getCacheSize() {
        return CACHE.size();
    }
}