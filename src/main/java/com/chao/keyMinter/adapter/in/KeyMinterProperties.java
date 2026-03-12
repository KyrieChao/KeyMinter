package com.chao.keyMinter.adapter.in;

import com.chao.keyMinter.domain.model.Algorithm;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "key-minter")
public class KeyMinterProperties {
    private Algorithm algorithm;
    /**
     * Key storage directory
     */
    private String keyDir = System.getProperty("user.home") + "/.keyMinter";

    /**
     * Enable key rotation
     */
    private boolean enableRotation;
    private String preferredKeyId;
    private boolean forceLoad;
    private boolean exportEnabled;
    private boolean metricsEnabled;
    private final Blacklist blacklist = new Blacklist();
    private final Lock lock = new Lock();
    /**
     * Key validity period in days.
     * Default: 90 days
     */
    private int keyValidityDays = 90;

    /**
     * Transition period in hours.
     * Overlap time for new and old keys during rotation.
     * Default: 24 hours
     */
    private int transitionPeriodHours = 24;

    /**
     * Rotation advance days.
     * Generate new key before current key expires.
     * Default: 7 days
     */
    private int rotationAdvanceDays = 7;

    /**
     * Maximum algorithm instances
     */
    private Integer maxAlgoInstance;

    /**
     * Blacklist cleanup interval in minutes.
     * Default: 60 minutes
     */
    private int blacklistCleanupIntervalMinutes = 60;

    /**
     * Blacklist entry TTL in hours.
     * Default: 24 hours
     */
    private int blacklistEntryTtlHours = 24;

    /**
     * Auto cleanup expired keys
     */
    private boolean autoCleanupExpiredKeys;

    /**
     * Expired key cleanup interval in hours.
     * Default: 24 hours
     */
    private int expiredKeyCleanupIntervalHours = 24;

    @Data
    public static class Blacklist {
        private boolean redisEnabled = false;
        private String redisKeyPrefix = "keyM:black:";
        private int redisBatchSize = 1000;
    }

    @Data
    public static class Lock {
        private boolean redisEnabled = false;
        private String redisKeyPrefix = "keyM:lock:";
        private long expireMillis = 30000;
        private long retryIntervalMillis = 100;
        private long maxRetryIntervalMillis = 2000;
    }

    /**
     * Get key validity in milliseconds.
     */
    public long getKeyValidityMillis() {
        return (long) keyValidityDays * 24 * 60 * 60 * 1000;
    }

    /**
     * Get transition period in milliseconds.
     */
    public long getTransitionPeriodMillis() {
        return (long) transitionPeriodHours * 60 * 60 * 1000;
    }

    /**
     * Get rotation advance in milliseconds.
     */
    public long getRotationAdvanceMillis() {
        return (long) rotationAdvanceDays * 24 * 60 * 60 * 1000;
    }

    /**
     * Get blacklist cleanup interval in milliseconds.
     */
    public long getBlacklistCleanupIntervalMillis() {
        return (long) blacklistCleanupIntervalMinutes * 60 * 1000;
    }

    /**
     * Get blacklist entry TTL in milliseconds.
     */
    public long getBlacklistEntryTtlMillis() {
        return (long) blacklistEntryTtlHours * 60 * 60 * 1000;
    }

    /**
     * Expired key retention in milliseconds.
     * Default: 30 days
     */
    @Setter
    @Getter
    private long expiredKeyRetentionMillis = 30L * 24 * 60 * 60 * 1000;

    /**
     * Get expired key cleanup interval in milliseconds.
     */
    public long getExpiredKeyCleanupIntervalMillis() {
        return (long) expiredKeyCleanupIntervalHours * 60 * 60 * 1000;
    }
}
