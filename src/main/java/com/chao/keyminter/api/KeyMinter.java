package com.chao.keyminter.api;

import com.chao.keyminter.domain.service.JwtAlgo;
import com.chao.keyminter.core.JwtFactory;
import com.chao.keyminter.domain.model.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * JWT工具类
 * 提供简化的JWT操作接口
 */
@Slf4j
@Component
public class KeyMinter {

    private static final Algorithm DEFAULT_ALGORITHM = Algorithm.HMAC256;
    private static final int DEFAULT_SECRET_LENGTH = 64;
    private static final long GRACE_PERIOD_MS = 3600_000; // 1小时宽限期
    private static final long CLEANUP_INTERVAL_MS = 60000; // 1分钟清理间隔

    private final JwtFactory factory;
    private final ReentrantReadWriteLock algoLock = new ReentrantReadWriteLock();
    private final ReentrantReadWriteLock.ReadLock readLock = algoLock.readLock();
    private final ReentrantReadWriteLock.WriteLock writeLock = algoLock.writeLock();

    // 当前算法实例
    private volatile JwtAlgo algoInstance;
    private volatile Algorithm currentAlgorithm = DEFAULT_ALGORITHM;

    // 平滑过渡：保留上一个算法实例
    private volatile JwtAlgo previousAlgoInstance;
    private volatile long previousAlgoExpiryTime;

    // 指标统计
    private final AtomicLong gracefulUsageCount = new AtomicLong(0);
    private final AtomicLong blacklistHitCount = new AtomicLong(0);

    // 清理调度器 - 已移除，使用Spring @Scheduled
    // private final ScheduledExecutorService cleanupScheduler;

    public KeyMinter(JwtFactory factory) {
        this.factory = Objects.requireNonNull(factory, "JwtFactory cannot be null");
        this.algoInstance = factory.get(DEFAULT_ALGORITHM);

        log.info("KeyMinter initialized with default algorithm: {}", DEFAULT_ALGORITHM);
    }

    /**
     * 切换默认算法
     */
    public synchronized boolean switchTo(Algorithm algorithm) {
        // 默认不自动加载密钥，保持"纯切换上下文"的语义
        // 如果用户想要切换并立即激活某个密钥，应该使用 setActiveKey
        return switchTo(algorithm, null, null, false);
    }

    /**
     * 切换默认算法
     */
    public synchronized boolean switchTo(Algorithm algorithm, String keyId) {
        // 如果显式提供了 keyId，则尝试自动加载它
        return switchTo(algorithm, null, keyId, true);
    }

    /**
     * 切换算法（字符串目录）并设置是否启用轮换
     */
    public synchronized boolean switchTo(Algorithm algorithm, String directory, String keyId, boolean autoload) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        try {
            JwtAlgo newAlgo = factory.get(algorithm, directory);
            // 注意：不再强制检查密钥对是否存在，允许先切换上下文再创建/加载密钥
            // if (!newAlgo.keyPairExists()) return false;

            writeLock.lock();
            try {
                JwtAlgo oldAlgo = this.algoInstance;
                this.algoInstance = newAlgo;
                this.currentAlgorithm = algorithm;

                // 处理平滑过渡：只有当算法真正改变且旧实例存在时
                if (oldAlgo != null && oldAlgo != newAlgo) {
                    this.previousAlgoInstance = oldAlgo;
                    this.previousAlgoExpiryTime = System.currentTimeMillis() + GRACE_PERIOD_MS;
                }

                // 只有明确要求自动加载时才执行
                if (autoload && keyId != null) {
                    // 这里的 autoLoad 内部最终会调用 setActiveKey
                    // 从而触发：旧密钥 -> Transitioning, 新密钥 -> Active
                    autoLoad(algorithm, directory, keyId);
                } else if (autoload) {
                    // 如果没有 keyId 但要求 autoload，尝试加载最新的
                    autoLoad(algorithm, directory);
                }

                log.info("Switched to algorithm: {}, directory: {}, autoload: {}", algorithm, directory, autoload);
                return true;
            } finally {
                writeLock.unlock();
            }
        } catch (Exception e) {
            log.error("Failed to switch to algorithm {}: {}", algorithm, e.getMessage(), e);
            return false;
        }
    }

    /**
     * 切换算法（路径目录）并设置是否启用轮换
     */
    public synchronized boolean switchTo(Algorithm algorithm, Path path, boolean autoload) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        try {
            JwtAlgo newAlgo = factory.get(algorithm, path);
            if (!newAlgo.keyPairExists()) {
                log.warn("No key pair exists for algorithm: {}", algorithm);
                return false;
            }
            writeLock.lock();
            try {
                if (this.algoInstance != null) {
                    this.previousAlgoInstance = this.algoInstance;
                    this.previousAlgoExpiryTime = System.currentTimeMillis() + GRACE_PERIOD_MS;
                }
                this.algoInstance = newAlgo;
                this.currentAlgorithm = algorithm;
                if (autoload) autoLoad(algorithm);
                log.info("Switched to algorithm: {}, path: {}", algorithm, path);
                return true;
            } finally {
                writeLock.unlock();
            }
        } catch (Exception e) {
            log.error("Failed to switch to algorithm {}: {}", algorithm, e.getMessage(), e);
            return false;
        }
    }
    // --- Simplified AutoLoad API ---

    public JwtAlgo autoLoad(Algorithm algorithm) {
        return factory.autoLoad(algorithm);
    }

    public JwtAlgo autoLoad(Algorithm algorithm, boolean force) {
        return factory.autoLoad(algorithm, force);
    }

    public JwtAlgo autoLoad(Algorithm algorithm, String directory) {
        return factory.autoLoad(algorithm, directory);
    }

    public JwtAlgo autoLoad(Algorithm algorithm, Path path) {
        return factory.autoLoad(algorithm, path);
    }

    public JwtAlgo autoLoad(Algorithm algorithm, String directory, String keyId) {
        return factory.autoLoad(algorithm, directory, keyId);
    }

    public JwtAlgo autoLoad(Algorithm algorithm, String directory, String keyId, boolean force) {
        return factory.autoLoad(algorithm, directory, keyId, force);
    }

    /**
     * 生成HMAC密钥
     */
    public boolean createHmacKey(Algorithm algorithm, Integer length) {
        validateHmacAlgorithm(algorithm);
        int keyLength = Objects.requireNonNullElse(length, DEFAULT_SECRET_LENGTH);
        readLock.lock();
        try {
            return algoInstance.generateHmacKey(Objects.requireNonNullElse(algorithm, DEFAULT_ALGORITHM), keyLength);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 生成密钥对（非对称加密）
     */
    public boolean createKeyPair(Algorithm algorithm) {
        validateAsymmetricAlgorithm(algorithm);
        return factory.get(algorithm).generateKeyPair(algorithm);
    }

    /**
     * 生成不包含自定义信息的Token（指定算法）
     */
    public String generateToken(JwtProperties jwtInfo) {
        JwtProperties properties = buildJwtProperties(jwtInfo);
        readLock.lock();
        try {
            return algoInstance.generateToken(properties, currentAlgorithm);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 生成包含自定义信息的Token（泛型版本，指定算法）
     */
    public <T> String generateToken(JwtProperties jwtInfo, T customClaims, Class<T> claimsType) {
        JwtProperties properties = buildJwtProperties(jwtInfo);
        readLock.lock();
        try {
            return algoInstance.generateToken(properties, currentAlgorithm, customClaims, claimsType);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 获取Token的标准信息
     */
    public JwtStandardInfo getStandardInfo(String token) {
        readLock.lock();
        try {
            return JwtDecoder.decodeStandardInfo(token, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 解码Token为指定类型的对象
     */
    public <T> T decodeToObject(String token, Class<T> clazz) {
        readLock.lock();
        try {
            return JwtDecoder.decodeToObject(token, clazz, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 解码Token为完整Map
     */
    public Map<String, Object> decodeToFullMap(String token) {
        readLock.lock();
        try {
            return JwtDecoder.decodeToFullMap(token, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 获取Token的签发时间
     */
    public Date decodeIssuedAt(String token) {
        readLock.lock();
        try {
            return JwtDecoder.decodeIssuedAt(token, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 获取Token的过期时间
     */
    public Date decodeExpiration(String token) {
        readLock.lock();
        try {
            return JwtDecoder.decodeExpiration(token, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 获取Token的自定义信息
     */
    public <T> T getCustomClaims(String token, Class<T> clazz) {
        readLock.lock();
        try {
            JwtFullInfo<T> fullInfo = JwtDecoder.decodeToFullInfo(token, clazz, algoInstance);
            return fullInfo.getCustomClaims();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 安全获取Token的自定义信息（不抛出异常）
     */
    public <T> T getCustomClaimsSafe(String token, Class<T> clazz) {
        readLock.lock();
        try {
            JwtFullInfo<T> fullInfo = JwtDecoder.decodeToFullInfoSafe(token, clazz, algoInstance);
            return fullInfo != null ? fullInfo.getCustomClaims() : null;
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 获取Token的完整信息
     */
    public <T> JwtFullInfo<T> getFullInfo(String token, Class<T> clazz) {
        readLock.lock();
        try {
            return JwtDecoder.decodeToFullInfo(token, clazz, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 激活指定密钥（将旧密钥转入过渡期，新密钥转为Active）
     * 这是配合 createKeyPair 使用的核心方法
     */
    public boolean setActiveKey(String keyId) {
        readLock.lock();
        try {
            boolean success = algoInstance.setActiveKey(keyId);
            if (success) {
                log.info("Key {} activated successfully. Algorithm: {}", keyId, currentAlgorithm);
            } else {
                log.warn("Failed to activate key {}", keyId);
            }
            return success;
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 安全获取Token的完整信息（不抛出异常）
     */
    public <T> JwtFullInfo<T> getFullInfoSafe(String token, Class<T> clazz) {
        readLock.lock();
        try {
            return JwtDecoder.decodeToFullInfoSafe(token, clazz, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 验证Token是否有效
     */
    public boolean verifyWithAlgorithm(String token, JwtAlgo algo) {
        Objects.requireNonNull(algo, "JwtAlgo cannot be null");
        return algo.verifyToken(token);
    }

    /**
     * 主验证：当前算法 → 宽限期算法
     */
    public boolean isValidToken(String token) {
        readLock.lock();
        try {
            boolean valid = algoInstance.verifyToken(token);
            if (!valid) {
                JwtAlgo backup = getGracefulAlgo();
                if (backup != null) {
                    gracefulUsageCount.incrementAndGet();
                    return backup.verifyToken(token);
                }
            }
            return valid;
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 仅当前算法（严格模式，不换回旧算法）
     */
    public boolean isValidWithCurrent(String token) {
        readLock.lock();
        try {
            return algoInstance.verifyToken(token);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 仅宽限期算法（用于刷新场景，确认是旧Token才换发）
     */
    public boolean isValidWithGraceful(String token) {
        JwtAlgo backup = getGracefulAlgo();
        return backup != null && backup.verifyToken(token);
    }

    /**
     * 获取JWT实例信息
     */
    public String getJwtProperties() {
        readLock.lock();
        try {
            return algoInstance.getKeyInfo();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 获取算法信息
     */
    public String getAlgorithmInfo() {
        readLock.lock();
        try {
            return algoInstance.getAlgorithmInfo();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 获取曲线信息（仅ECDSA算法）
     */
    public String getECDCurveInfo() {
        readLock.lock();
        try {
            if (!algoInstance.isECD(currentAlgorithm)) {
                return null;
            }
            return algoInstance.getCurveInfo(currentAlgorithm);
        } finally {
            readLock.unlock();
        }
    }

    public boolean verify(Algorithm algorithm, String token) {
        JwtAlgo algo = autoLoad(algorithm);
        return verifyWithAlgorithm(token, algo);
    }

    /**
     * 列出指定目录下的密钥
     */
    public List<KeyVersion> listAllKeys(String directory) {
        readLock.lock();
        try {
            return algoInstance.listAllKeys(directory);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 列出所有密钥
     */
    public List<KeyVersion> listAllKeys() {
        readLock.lock();
        try {
            return algoInstance.listAllKeys();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 列出指定目录下的密钥
     */
    public List<KeyVersion> listKeys(Algorithm algorithm, String directory) {
        readLock.lock();
        try {
            return algoInstance.listKeys(algorithm, directory);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 列出指定算法的密钥
     */
    public List<KeyVersion> listKeys() {
        readLock.lock();
        try {
            return algoInstance.listKeys(currentAlgorithm);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 获取指定算法的密钥版本列表
     */
    public List<String> getKeyVersions(Algorithm algorithm) {
        Algorithm algo = algorithm == null ? currentAlgorithm : algorithm;
        readLock.lock();
        try {
            return algoInstance.getKeyVersions(algo);
        } finally {
            readLock.unlock();
        }
    }

    public List<String> getKeyVersions() {
        readLock.lock();
        try {
            return algoInstance.getKeyVersions();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 检查Token是否可解码
     */
    public boolean isTokenDecodable(String token) {
        readLock.lock();
        try {
            return JwtDecoder.isTokenDecodable(token, algoInstance);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 构建JWT属性对象
     */
    private JwtProperties buildJwtProperties(JwtProperties jwtInfo) {
        Objects.requireNonNull(jwtInfo, "JwtProperties cannot be null");
        return JwtProperties.builder()
                .subject(jwtInfo.getSubject())
                .issuer(jwtInfo.getIssuer())
                .expiration(jwtInfo.getExpiration())
                .build();
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
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        if (algorithm.isHmac()) {
            throw new IllegalArgumentException("HMAC algorithm does not support key pair generation: " + algorithm);
        }
    }

    /**
     * 生成所有算法的密钥对
     */
    public boolean generateAllKeyPairs() {
        readLock.lock();
        try {
            return algoInstance.generateAllKeyPairs();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 使用指定的密钥目录创建新的JwtAlgo实例
     */
    public JwtAlgo withKeyDirectory(Path keyDir) {
        readLock.lock();
        try {
            return algoInstance.withKeyDirectory(keyDir);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 使用指定的密钥目录创建新的JwtAlgo实例
     */
    public JwtAlgo withKeyDirectory(String keyDir) {
        readLock.lock();
        try {
            return algoInstance.withKeyDirectory(keyDir);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 获取当前使用的密钥对象
     */
    public Object getCurrentKey() {
        readLock.lock();
        try {
            return algoInstance.getCurrentKey();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 动态重新初始化
     */
    public void close() {
        readLock.lock();
        try {
            algoInstance.close();
            if (previousAlgoInstance != null) previousAlgoInstance.close();
        } finally {
            readLock.unlock();
        }
        log.info("KeyMinter closed");
    }

    /**
     * 定时清理任务
     * 每分钟执行一次，清理平滑过渡的旧算法实例和所有算法的过期密钥
     */
    @Scheduled(fixedRateString = "${key-minter.cleanup-interval-millis:60000}")
    public void scheduledCleanup() {
        // 清理平滑过渡的旧算法实例
        cleanupExpiredGracefulAlgo();

        // 清理工厂中所有算法实例的过期密钥
        factory.cleanupAllAlgos();
    }

    public JwtStandardInfo decodeStandardInfo(Algorithm algorithm, String token) {
        JwtAlgo load = autoLoad(algorithm);
        return JwtDecoder.decodeStandardInfo(token, load);
    }

    public <T> T decodeCustomInfo(Algorithm algorithm, String token, Class<T> clazz) {
        JwtAlgo load = autoLoad(algorithm);
        return JwtDecoder.decodeCustomClaimsSafe(token, load, clazz);
    }

    public boolean isDecodable(Algorithm algorithm, String token) {
        JwtAlgo load = autoLoad(algorithm);
        return JwtDecoder.isTokenDecodable(token, load);
    }

    public String getKeyInfo(Algorithm algorithm, String keyId) {
        JwtAlgo load = autoLoad(algorithm, (String) null, keyId);
        return load.getKeyInfo();
    }

    public String getKeyVersions(Algorithm algorithm, String keyId) {
        JwtAlgo load = autoLoad(algorithm, null, keyId);
        return load.getKeyVersions().toString();
    }

    public <T> String generateToken(Algorithm algorithm, String keyId, JwtProperties properties, T payload, Class<T> clazz) {
        JwtAlgo load = autoLoad(algorithm, null, keyId);
        return load.generateToken(properties, algorithm, payload, clazz);
    }

    /**
     * 清理缓存（用于测试或内存管理）
     */
    public void clearCache() {
        factory.clearCache();
    }

    public Object getKeyByVersion(String keyId) {
        readLock.lock();
        try {
            return algoInstance.getKeyByVersion(keyId);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 检查密钥对是否存在的方法
     * 使用读锁确保线程安全
     *
     * @return 如果密钥对存在返回true，否则返回false
     */
    public boolean keyPairExists() {
        readLock.lock();
        try {
            return algoInstance.keyPairExists();
        } finally {
            readLock.unlock();
        }
    }

    public boolean keyPairExists(Algorithm algorithm) {
        readLock.lock();
        try {
            return algoInstance.keyPairExists(algorithm);
        } finally {
            readLock.unlock();
        }
    }

    public String getActiveKeyId() {
        readLock.lock();
        try {
            return algoInstance.getActiveKeyId();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 获取当前缓存大小
     */
    public int getCacheSize() {
        return factory.getCacheSize();
    }

    public Path getKeyPath() {
        readLock.lock();
        try {
            return algoInstance.getKeyPath();
        } finally {
            readLock.unlock();
        }
    }

    private void cleanupExpiredGracefulAlgo() {
        if (previousAlgoInstance != null && System.currentTimeMillis() >= previousAlgoExpiryTime) {
            previousAlgoInstance.close();
            previousAlgoInstance = null;
        }
    }

    /**
     * 获取平滑过度的备用算法实例
     */
    private JwtAlgo getGracefulAlgo() {
        cleanupExpiredGracefulAlgo();
        return previousAlgoInstance;
    }

    /**
     * 供Renewal调用
     */
    void recordBlacklistHit() {
        blacklistHitCount.incrementAndGet();
    }

    /**
     * 暴露指标
     */
    public Map<String, Long> getMetrics() {
        return Map.of(
                "gracefulUsage", gracefulUsageCount.get(),
                "blacklistHit", blacklistHitCount.get()
        );
    }

    public void resetMetrics() {
        gracefulUsageCount.set(0);
        blacklistHitCount.set(0);
    }
}
