package com.chao.keyMinter.internal;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Revocation Store.
 * Manages revoked JTIs and fingerprints in memory.
 */
@Slf4j
public class RevocationStore {

    // Map of revoked JTIs to expiration time
    private final Map<String, Instant> revokedJtis = new ConcurrentHashMap<>();

    // Map of revoked fingerprints to expiration time
    private final Map<String, Instant> revokedFingerprints = new ConcurrentHashMap<>();

    // Scheduler for cleanup tasks
    private final ScheduledExecutorService cleanupScheduler;

    // Closed flag
    private final AtomicBoolean closed = new AtomicBoolean(false);

    private final long entryTtlMillis;

    public RevocationStore() {
        this(new KeyMinterProperties());
    }

    public RevocationStore(KeyMinterProperties properties) {
        // Init properties
        long cleanupIntervalMillis = properties.getBlacklistCleanupIntervalMillis();
        this.entryTtlMillis = properties.getBlacklistEntryTtlMillis();

        // Init scheduler
        this.cleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "revocation-store-cleanup");
            t.setDaemon(true);
            return t;
        });

        // Schedule cleanup
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
     * Revoke a JTI.
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
     * Revoke a JTI with specific expiration.
     */
    public void revokeJti(String jti, Instant expiresAt) {
        if (jti == null || jti.isEmpty()) {
            return;
        }
        revokedJtis.put(jti, expiresAt);
        log.debug("Revoked jti: {}, expires at: {}", jti, expiresAt);
    }

    /**
     * Check if a JTI is revoked.
     */
    public boolean isRevokedJti(String jti) {
        if (jti == null || jti.isEmpty()) {
            return false;
        }
        Instant expiresAt = revokedJtis.get(jti);
        if (expiresAt == null) {
            return false;
        }
        // Check if expired
        if (Instant.now().isAfter(expiresAt)) {
            // Lazy cleanup
            revokedJtis.remove(jti);
            return false;
        }
        return true;
    }

    /**
     * Revoke a fingerprint.
     */
    public void revokeFingerprint(String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty()) {
            return;
        }
        Instant expiresAt = Instant.now().plusMillis(entryTtlMillis);
        revokedFingerprints.put(fingerprint, expiresAt);
        log.debug("Revoked fingerprint: {}, expires at: {} 1", fingerprint, expiresAt);
    }

    /**
     * Revoke a fingerprint with specific expiration.
     */
    public void revokeFingerprint(String fingerprint, Instant expiresAt) {
        if (fingerprint == null || fingerprint.isEmpty()) {
            return;
        }
        revokedFingerprints.put(fingerprint, expiresAt);
        log.debug("Revoked fingerprint: {}, expires at: {} 2", fingerprint, expiresAt);
    }

    /**
     * Check if a fingerprint is revoked.
     */
    public boolean isRevokedFingerprint(String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty()) {
            return false;
        }
        Instant expiresAt = revokedFingerprints.get(fingerprint);
        if (expiresAt == null) {
            return false;
        }
        // Check if expired
        if (Instant.now().isAfter(expiresAt)) {
            // Lazy cleanup
            revokedFingerprints.remove(fingerprint);
            return false;
        }
        return true;
    }

    /**
     * Get all revoked JTIs.
     */
    public Set<String> getRevokedJtis() {
        return Set.copyOf(revokedJtis.keySet());
    }

    /**
     * Get all revoked fingerprints.
     */
    public Set<String> getRevokedFingerprints() {
        return Set.copyOf(revokedFingerprints.keySet());
    }

    /**
     * Cleanup expired entries.
     */
    public void cleanupExpiredEntries() {
        Instant now = Instant.now();
        int jtiCount = 0;
        int fingerprintCount = 0;

        // Cleanup JTIs
        for (Map.Entry<String, Instant> entry : revokedJtis.entrySet()) {
            if (now.isAfter(entry.getValue())) {
                revokedJtis.remove(entry.getKey());
                jtiCount++;
            }
        }

        // Cleanup fingerprints
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
     * Get statistics.
     */
    public Map<String, Integer> getStats() {
        return Map.of(
            "revokedJtis", revokedJtis.size(),
            "revokedFingerprints", revokedFingerprints.size()
        );
    }

    /**
     * Clear all entries.
     */
    public void clear() {
        revokedJtis.clear();
        revokedFingerprints.clear();
        log.info("RevocationStore cleared");
    }

    /**
     * Close the store and scheduler.
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
