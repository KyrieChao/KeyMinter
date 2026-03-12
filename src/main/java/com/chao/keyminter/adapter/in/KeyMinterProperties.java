package com.chao.keyminter.adapter.in;

import com.chao.keyminter.domain.model.Algorithm;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "key-minter")
public class KeyMinterProperties {
    private Algorithm algorithm;
    /**
     * 密钥存储目录
     */
    private String keyDir = System.getProperty("user.home") + "/.keyminter";

    /**
     * 是否启用密钥轮换
     */
    private boolean enableRotation;
    private String preferredKeyId;
    private boolean forceLoad;
    private boolean exportEnabled;
    private boolean metricsEnabled;
    private final Blacklist blacklist = new Blacklist();
    private final Lock lock = new Lock();
    /**
     * 密钥有效期（天数）
     * 默认90天
     */
    private int keyValidityDays = 90;

    /**
     * 过渡期（重叠期）时长（小时）
     * 轮换后旧密钥仍可验证的时间
     * 默认24小时
     */
    private int transitionPeriodHours = 24;

    /**
     * 密钥提前轮换时间（天数）
     * 在密钥过期前多少天开始轮换
     * 默认7天
     */
    private int rotationAdvanceDays = 7;

    /**
     * 最大算法实例缓存数
     */
    private Integer maxAlgoInstance;

    /**
     * 黑名单清理间隔（分钟）
     * 默认60分钟
     */
    private int blacklistCleanupIntervalMinutes = 60;

    /**
     * 黑名单条目默认过期时间（小时）
     * 默认24小时
     */
    private int blacklistEntryTtlHours = 24;

    /**
     * 是否自动清理过期密钥
     */
    private boolean autoCleanupExpiredKeys;

    /**
     * 过期密钥清理间隔（小时）
     * 默认24小时
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
     * 获取密钥有效期（毫秒）
     */
    public long getKeyValidityMillis() {
        return (long) keyValidityDays * 24 * 60 * 60 * 1000;
    }

    /**
     * 获取过渡期时长（毫秒）
     */
    public long getTransitionPeriodMillis() {
        return (long) transitionPeriodHours * 60 * 60 * 1000;
    }

    /**
     * 获取轮换提前时间（毫秒）
     */
    public long getRotationAdvanceMillis() {
        return (long) rotationAdvanceDays * 24 * 60 * 60 * 1000;
    }

    /**
     * 获取黑名单清理间隔（毫秒）
     */
    public long getBlacklistCleanupIntervalMillis() {
        return (long) blacklistCleanupIntervalMinutes * 60 * 1000;
    }

    /**
     * 获取黑名单条目过期时间（毫秒）
     */
    public long getBlacklistEntryTtlMillis() {
        return (long) blacklistEntryTtlHours * 60 * 60 * 1000;
    }

    /**
     * 过期密钥物理删除保留期（毫秒）
     * 默认 30 天
     */
    private long expiredKeyRetentionMillis = 30L * 24 * 60 * 60 * 1000;

    public long getExpiredKeyRetentionMillis() {
        return expiredKeyRetentionMillis;
    }

    public void setExpiredKeyRetentionMillis(long expiredKeyRetentionMillis) {
        this.expiredKeyRetentionMillis = expiredKeyRetentionMillis;
    }

    /**
     * 获取过期密钥清理间隔（毫秒）
     */
    public long getExpiredKeyCleanupIntervalMillis() {
        return (long) expiredKeyCleanupIntervalHours * 60 * 60 * 1000;
    }
}
