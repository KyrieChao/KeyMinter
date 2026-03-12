package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.service.JwtAlgo;
import com.chao.keyMinter.domain.port.out.KeyRepositoryFactory;
import com.chao.keyMinter.domain.port.out.SecretDirProvider;
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
 * JWT Algorithm Factory
 * - Manages algorithm instances (LRU cache)
 * - Manages key loading
 * - Supports loading keys from different directories
 */
@Slf4j
public class JwtFactory {

    private volatile int maxAlgoInstance = 5;
    private volatile KeyMinterProperties properties;
    @Setter
    private volatile KeyRepositoryFactory repositoryFactory;

    // Read-write lock for cache safety
    private final ReentrantReadWriteLock cacheLock = new ReentrantReadWriteLock();
    private final ReentrantReadWriteLock.ReadLock readLock = cacheLock.readLock();
    private final ReentrantReadWriteLock.WriteLock writeLock = cacheLock.writeLock();

    // LRU Cache for algorithms
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
     * Get default HMAC256 algorithm
     */
    public JwtAlgo get() {
        return get(Algorithm.HMAC256, (String) null);
    }

    /**
     * Get algorithm with default directory
     */
    public JwtAlgo get(Algorithm algorithm) {
        return get(algorithm, (String) null);
    }

    /**
     * Get algorithm with specific directory
     */
    public JwtAlgo get(Algorithm algorithm, String directory) {
        return get(algorithm, directory != null ? Paths.get(directory) : null);
    }

    /**
     * Get or create algorithm instance (Algorithm + Directory)
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
        // Double-check locking for cache
        writeLock.lock();
        try {
            // Re-check cache
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
     *  Auto-loading methods
     * ------------------------- */

    /**
     * Auto-load first available key
     */
    public JwtAlgo autoLoad(Algorithm algorithm) {
        return autoLoadFirstKey(algorithm, null, false);
    }

    /**
     * Auto-load first key with force option
     */
    public JwtAlgo autoLoad(Algorithm algorithm, boolean force) {
        return autoLoadFirstKey(algorithm, null, force);
    }

    /**
     * Auto-load key from specific directory
     */
    public JwtAlgo autoLoad(Algorithm algorithm, Path directory) {
        return autoLoadFirstKey(algorithm, directory, false);
    }

    /**
     * Auto-load key from specific directory (String path)
     */
    public JwtAlgo autoLoad(Algorithm algorithm, String directory) {
        return autoLoadFirstKey(algorithm, directory != null ? Paths.get(directory) : null, false);
    }

    /**
     * Auto-load specific key ID
     */
    public JwtAlgo autoLoad(Algorithm algorithm, String directory, String keyId) {
        return autoLoadWithKeyId(algorithm, directory != null ? Paths.get(directory) : null, keyId, false);
    }

    /**
     * Auto-load specific key ID with force option
     */
    public JwtAlgo autoLoad(Algorithm algorithm, String directory, String keyId, boolean force) {
        return autoLoadWithKeyId(algorithm, directory != null ? Paths.get(directory) : null, keyId, force);
    }

    /**
     * Internal: Auto-load first key
     */
    private JwtAlgo autoLoadFirstKey(Algorithm algorithm, Path path, boolean force) {
        JwtAlgo algo = get(algorithm, path);
        return algo.autoLoadFirstKey(algorithm, force);
    }

    /**
     * Internal: Auto-load with key ID
     */
    private JwtAlgo autoLoadWithKeyId(Algorithm algorithm, Path path, String keyId, boolean force) {
        JwtAlgo algo = get(algorithm, path);
        return algo.autoLoadFirstKey(algorithm, keyId, force);
    }
    /* -------------------------
     *  Helper methods
     * ------------------------- */

    /**
     * Build cache key
     */
    private String buildCacheKey(Algorithm algorithm, Path keyDir) {
        Path actualDir = resolveKeyDir(keyDir);
        String dirKey = actualDir != null ? actualDir.toAbsolutePath().toString()
                : SecretDirProvider.getDefaultBaseDir().toAbsolutePath().toString();
        return String.format("%s:%s", algorithm.name(), dirKey);
    }

    /**
     * Build new algorithm instance
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
     * Resolve key directory
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
     * Cleanup all expired keys in all algorithms
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
     * Clear cache and close all algorithms
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
     * Get cache size
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
     * Close factory
     */
    public void close() {
        clearCache();
    }
}
