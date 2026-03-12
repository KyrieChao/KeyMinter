package com.chao.keyminter.internal;

import com.chao.keyminter.adapter.in.KeyMinterProperties;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Token 撤销/黑名单存储
 * 支持自动清理过期条目
 */
@Slf4j
public class RevocationStore {

    // 撤销的 jti -> 过期时间
    private final Map<String, Instant> revokedJtis = new ConcurrentHashMap<>();

    // 撤销的密钥指纹 -> 过期时间
    private final Map<String, Instant> revokedFingerprints = new ConcurrentHashMap<>();

    // 清理调度器
    private final ScheduledExecutorService cleanupScheduler;

    // 是否已关闭
    private final AtomicBoolean closed = new AtomicBoolean(false);

    // 配置
    private final long cleanupIntervalMillis;
    private final long entryTtlMillis;

    public RevocationStore() {
        this(new KeyMinterProperties());
    }

    public RevocationStore(KeyMinterProperties properties) {
        this.cleanupIntervalMillis = properties.getBlacklistCleanupIntervalMillis();
        this.entryTtlMillis = properties.getBlacklistEntryTtlMillis();

        // 启动清理调度器
        this.cleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "revocation-store-cleanup");
            t.setDaemon(true);
            return t;
        });

        // 定期清理过期条目
        this.cleanupScheduler.scheduleAtFixedRate(
            this::cleanupExpiredEntries,
            cleanupIntervalMillis,
            cleanupIntervalMillis,
            TimeUnit.MILLISECONDS
        );

        log.info("RevocationStore initialized with cleanup interval: {}ms, entry TTL: {}ms",
                cleanupIntervalMillis, entryTtlMillis);
    }

    /**
     * 撤销指定的 jti
     */
    public void revokeJti(String jti) {
        if (jti == null || jti.isEmpty()) {
            return;
        }
        Instant expiresAt = Instant.now().plusMillis(entryTtlMillis);
        revokedJtis.put(jti, expiresAt);
        log.debug("Revoked jti: {}, expires at: {}", jti, expiresAt);
    }

    /**
     * 撤销指定的 jti，指定过期时间
     */
    public void revokeJti(String jti, Instant expiresAt) {
        if (jti == null || jti.isEmpty()) {
            return;
        }
        revokedJtis.put(jti, expiresAt);
        log.debug("Revoked jti: {}, expires at: {}", jti, expiresAt);
    }

    /**
     * 检查 jti 是否已被撤销
     */
    public boolean isRevokedJti(String jti) {
        if (jti == null || jti.isEmpty()) {
            return false;
        }
        Instant expiresAt = revokedJtis.get(jti);
        if (expiresAt == null) {
            return false;
        }
        // 检查是否已过期
        if (Instant.now().isAfter(expiresAt)) {
            // 自动清理过期条目
            revokedJtis.remove(jti);
            return false;
        }
        return true;
    }

    /**
     * 撤销密钥指纹
     */
    public void revokeFingerprint(String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty()) {
            return;
        }
        Instant expiresAt = Instant.now().plusMillis(entryTtlMillis);
        revokedFingerprints.put(fingerprint, expiresAt);
        log.debug("Revoked fingerprint: {}, expires at: {}", fingerprint, expiresAt);
    }

    /**
     * 撤销密钥指纹，指定过期时间
     */
    public void revokeFingerprint(String fingerprint, Instant expiresAt) {
        if (fingerprint == null || fingerprint.isEmpty()) {
            return;
        }
        revokedFingerprints.put(fingerprint, expiresAt);
        log.debug("Revoked fingerprint: {}, expires at: {}", fingerprint, expiresAt);
    }

    /**
     * 检查密钥指纹是否已被撤销
     */
    public boolean isRevokedFingerprint(String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty()) {
            return false;
        }
        Instant expiresAt = revokedFingerprints.get(fingerprint);
        if (expiresAt == null) {
            return false;
        }
        // 检查是否已过期
        if (Instant.now().isAfter(expiresAt)) {
            // 自动清理过期条目
            revokedFingerprints.remove(fingerprint);
            return false;
        }
        return true;
    }

    /**
     * 获取撤销的 jti 集合（只读）
     */
    public Set<String> getRevokedJtis() {
        return Set.copyOf(revokedJtis.keySet());
    }

    /**
     * 获取撤销的指纹集合（只读）
     */
    public Set<String> getRevokedFingerprints() {
        return Set.copyOf(revokedFingerprints.keySet());
    }

    /**
     * 清理过期条目
     */
    public void cleanupExpiredEntries() {
        Instant now = Instant.now();
        int jtiCount = 0;
        int fingerprintCount = 0;

        // 清理过期的 jti
        for (Map.Entry<String, Instant> entry : revokedJtis.entrySet()) {
            if (now.isAfter(entry.getValue())) {
                revokedJtis.remove(entry.getKey());
                jtiCount++;
            }
        }

        // 清理过期的指纹
        for (Map.Entry<String, Instant> entry : revokedFingerprints.entrySet()) {
            if (now.isAfter(entry.getValue())) {
                revokedFingerprints.remove(entry.getKey());
                fingerprintCount++;
            }
        }

        if (jtiCount > 0 || fingerprintCount > 0) {
            log.info("Cleaned up {} expired jtis and {} expired fingerprints",
                    jtiCount, fingerprintCount);
        }
    }

    /**
     * 获取统计信息
     */
    public Map<String, Integer> getStats() {
        return Map.of(
            "revokedJtis", revokedJtis.size(),
            "revokedFingerprints", revokedFingerprints.size()
        );
    }

    /**
     * 清空所有撤销记录
     */
    public void clear() {
        revokedJtis.clear();
        revokedFingerprints.clear();
        log.info("RevocationStore cleared");
    }

    /**
     * 关闭清理调度器
     */
    public void close() {
        if (closed.compareAndSet(false, true)) {
            cleanupScheduler.shutdown();
            try {
                if (!cleanupScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    cleanupScheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                cleanupScheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
            log.info("RevocationStore closed");
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
}
