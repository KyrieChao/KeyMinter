package com.chao.keyminter.core;

import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.service.JwtAlgo;
import com.chao.keyminter.domain.port.out.KeyRepositoryFactory;
import com.chao.keyminter.domain.port.out.SecretDirProvider;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * JWT工厂类
 * - 自动缓存实例（LRU策略）
 * - 自动装载密钥
 * - 支持目录、文件、密钥轮换
 */
@Slf4j
public class JwtFactory {

    private volatile int maxAlgoInstance = 5;
    private volatile KeyMinterProperties properties;
    @Setter
    private volatile KeyRepositoryFactory repositoryFactory;

    // 使用读写锁保护缓存
    private final ReentrantReadWriteLock cacheLock = new ReentrantReadWriteLock();
    private final ReentrantReadWriteLock.ReadLock readLock = cacheLock.readLock();
    private final ReentrantReadWriteLock.WriteLock writeLock = cacheLock.writeLock();

    // LRU缓存实现
    private final Map<String, JwtAlgo> cache =
            Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, JwtAlgo> eldest) {
                    if (size() > maxAlgoInstance) {
                        try {
                            eldest.getValue().close();
                            log.debug("Evicted JWT algo from cache: {}", eldest.getKey());
                        } catch (Exception e) {
                            log.warn("Error closing evicted JWT algo: {}", e.getMessage());
                        }
                        return true;
                    }
                    return false;
                }
            });

    public void setProperties(KeyMinterProperties prop) {
        this.properties = prop;
        if (prop != null) {
            System.out.println("JwtFactory: Properties set. KeyDir: " + prop.getKeyDir());
        } else {
            System.out.println("JwtFactory: Properties set to NULL");
        }
        if (prop != null && prop.getMaxAlgoInstance() != null && prop.getMaxAlgoInstance() > 0) {
            this.maxAlgoInstance = prop.getMaxAlgoInstance();
        }
        log.debug("JwtFactory initialized with maxAlgoInstance: {}", maxAlgoInstance);
    }

    /**
     * 默认创建（HMAC256），启用轮换
     */
    public JwtAlgo get() {
        return get(Algorithm.HMAC256, (String) null);
    }

    /**
     * 创建指定算法的实例（默认目录，启用轮换）
     */
    public JwtAlgo get(Algorithm algorithm) {
        return get(algorithm, (String) null);
    }

    /**
     * 创建指定算法和目录的实例（指定轮换设置）
     */
    public JwtAlgo get(Algorithm algorithm, String directory) {
        return get(algorithm, directory != null ? Paths.get(directory) : null);
    }

    /**
     * 完整构造：算法 + 目录 + 轮换（核心方法）
     */
    public JwtAlgo get(Algorithm algorithm, Path keyDir) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        String cacheKey = buildCacheKey(algorithm, keyDir);
        readLock.lock();
        try {
            JwtAlgo cached = cache.get(cacheKey);
            if (cached != null) return cached;
        } finally {
            readLock.unlock();
        }
        // 未命中缓存，创建新实例
        writeLock.lock();
        try {
            // 双重检查
            JwtAlgo cached = cache.get(cacheKey);
            if (cached != null) return cached;
            JwtAlgo newAlgo = build(algorithm, keyDir);
            cache.put(cacheKey, newAlgo);
            log.debug("Created and cached new JWT algo: {}", cacheKey);
            return newAlgo;
        } finally {
            writeLock.unlock();
        }
    }

    /* -------------------------
     *  自动加载方法
     * ------------------------- */

    /**
     * 自动加载首个密钥（默认目录）
     */
    public JwtAlgo autoLoad(Algorithm algorithm) {
        return autoLoadFirstKey(algorithm, null, false);
    }

    /**
     * 自动加载首个密钥（强制重新加载）
     */
    public JwtAlgo autoLoad(Algorithm algorithm, boolean force) {
        return autoLoadFirstKey(algorithm, null, force);
    }

    /**
     * 自动加载指定目录的首个密钥
     */
    public JwtAlgo autoLoad(Algorithm algorithm, Path directory) {
        return autoLoadFirstKey(algorithm, directory, false);
    }

    /**
     * 自动加载指定目录的首个密钥（字符串目录）
     */
    public JwtAlgo autoLoad(Algorithm algorithm, String directory) {
        return autoLoadFirstKey(algorithm, directory != null ? Paths.get(directory) : null, false);
    }

    /**
     * 自动加载指定目录和密钥ID（字符串目录）
     */
    public JwtAlgo autoLoad(Algorithm algorithm, String directory, String keyId) {
        return autoLoadWithKeyId(algorithm, directory != null ? Paths.get(directory) : null, keyId, false);
    }

    /**
     * 自动加载指定目录和密钥ID（字符串目录，强制重新加载）
     */
    public JwtAlgo autoLoad(Algorithm algorithm, String directory, String keyId, boolean force) {
        return autoLoadWithKeyId(algorithm, directory != null ? Paths.get(directory) : null, keyId, force);
    }

    /**
     * 自动加载首个密钥的核心方法
     */
    private JwtAlgo autoLoadFirstKey(Algorithm algorithm, Path path, boolean force) {
        JwtAlgo algo = get(algorithm, path);
        return algo.autoLoadFirstKey(algorithm, force);
    }

    /**
     * 自动加载指定密钥ID的核心方法
     */
    private JwtAlgo autoLoadWithKeyId(Algorithm algorithm, Path path, String keyId, boolean force) {
        JwtAlgo algo = get(algorithm, path);
        return algo.autoLoadFirstKey(algorithm, keyId, force);
    }
    /* -------------------------
     *  私有方法
     * ------------------------- */

    /**
     * 构建缓存键
     */
    private String buildCacheKey(Algorithm algorithm, Path keyDir) {
        Path actualDir = resolveKeyDir(keyDir);
        String dirKey = actualDir != null ? actualDir.toAbsolutePath().toString()
                : SecretDirProvider.getDefaultBaseDir().toAbsolutePath().toString();
        return String.format("%s:%s", algorithm.name(), dirKey);
    }

    /**
     * 核心构造逻辑
     */
    private JwtAlgo build(Algorithm algorithm, Path keyDir) {
        KeyMinterProperties props = this.properties != null ? this.properties : new KeyMinterProperties();
        Path actualDir = resolveKeyDir(keyDir);
        try {
            return Prep.getPre(algorithm, actualDir, props, repositoryFactory);
        } catch (Exception e) {
            log.error("Failed to build JWT algo for {}: {}", algorithm, e.getMessage(), e);
            throw new IllegalStateException("Failed to build JWT algo for " + algorithm, e);
        }
    }

    /**
     * 解析密钥目录：优先使用参数，其次使用配置，最后返回 null (由实现类决定默认值)
     */
    private Path resolveKeyDir(Path keyDir) {
        if (keyDir != null) {
            return keyDir;
        }
        if (this.properties != null && this.properties.getKeyDir() != null) {
            String dir = this.properties.getKeyDir().trim();
            if (!dir.isEmpty()) {
                return Paths.get(dir);
            }
        } else {
             System.out.println("JwtFactory: resolveKeyDir failed. Properties: " + (this.properties != null) + ", KeyDir: " + (this.properties != null ? this.properties.getKeyDir() : "N/A"));
        }
        return null;
    }

    /**
     * 清理所有算法实例中的过期密钥
     */
    public void cleanupAllAlgos() {
        readLock.lock();
        try {
            cache.values().forEach(algo -> {
                try {
                    algo.cleanupExpiredKeys();
                } catch (Exception e) {
                    log.warn("Error cleaning up expired keys for algo: {}", e.getMessage());
                }
            });
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 清理缓存（用于测试或内存管理）
     */
    public void clearCache() {
        writeLock.lock();
        try {
            cache.values().forEach(algo -> {
                try {
                    algo.close();
                } catch (Exception e) {
                    log.warn("Error closing JWT algo during cache clear: {}", e.getMessage());
                }
            });
            cache.clear();
            log.info("JWT factory cache cleared");
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * 获取当前缓存大小
     */
    public int getCacheSize() {
        readLock.lock();
        try {
            return cache.size();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * 关闭工厂并清理资源
     */
    public void close() {
        clearCache();
    }
}
