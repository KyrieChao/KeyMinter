package com.chao.keyMinter.adapter.in;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class KeyMinterPropertiesTest {

    @Test
    void testDefaultValues() {
        KeyMinterProperties properties = new KeyMinterProperties();
        assertEquals(System.getProperty("user.home") + "/.keyMinter", properties.getKeyDir());
        assertFalse(properties.isEnableRotation());
        assertEquals(90, properties.getKeyValidityDays());
        assertEquals(24, properties.getTransitionPeriodHours());
        assertEquals(7, properties.getRotationAdvanceDays());
        assertEquals(60, properties.getBlacklistCleanupIntervalMinutes());
        assertEquals(24, properties.getBlacklistEntryTtlHours());
        assertEquals(24, properties.getExpiredKeyCleanupIntervalHours());
        assertEquals(30L * 24 * 60 * 60 * 1000, properties.getExpiredKeyRetentionMillis());
        
        assertNotNull(properties.getBlacklist());
        assertNotNull(properties.getLock());
    }

    @Test
    void testLombokGeneratedMethods() {
        KeyMinterProperties p1 = new KeyMinterProperties();
        p1.setKeyDir("dir1");
        p1.setAlgorithm(com.chao.keyMinter.domain.model.Algorithm.HMAC256);
        p1.setEnableRotation(true);
        p1.setPreferredKeyId("k1");
        p1.setForceLoad(true);
        p1.setExportEnabled(true);
        p1.setMetricsEnabled(true);
        p1.setMaxAlgoInstance(5);
        p1.setBlacklistCleanupIntervalMinutes(10);
        p1.setBlacklistEntryTtlHours(5);
        p1.setAutoCleanupExpiredKeys(true);
        p1.setExpiredKeyCleanupIntervalHours(12);
        p1.setExpiredKeyRetentionMillis(100L);

        KeyMinterProperties p2 = new KeyMinterProperties();
        p2.setKeyDir("dir1");
        p2.setAlgorithm(com.chao.keyMinter.domain.model.Algorithm.HMAC256);
        p2.setEnableRotation(true);
        p2.setPreferredKeyId("k1");
        p2.setForceLoad(true);
        p2.setExportEnabled(true);
        p2.setMetricsEnabled(true);
        p2.setMaxAlgoInstance(5);
        p2.setBlacklistCleanupIntervalMinutes(10);
        p2.setBlacklistEntryTtlHours(5);
        p2.setAutoCleanupExpiredKeys(true);
        p2.setExpiredKeyCleanupIntervalHours(12);
        p2.setExpiredKeyRetentionMillis(100L);

        // Equals
        assertEquals(p1, p2);
        assertEquals(p1, p1);
        assertNotEquals(p1, null);
        assertNotEquals(p1, new Object());
        
        KeyMinterProperties p3 = new KeyMinterProperties();
        assertNotEquals(p1, p3);

        // HashCode
        assertEquals(p1.hashCode(), p2.hashCode());
        assertNotEquals(p1.hashCode(), p3.hashCode());

        // ToString
        String s = p1.toString();
        assertNotNull(s);
        assertTrue(s.contains("dir1"));
        assertTrue(s.contains("HMAC256"));
    }
    
    @Test
    void testBlacklistLombok() {
        KeyMinterProperties.Blacklist b1 = new KeyMinterProperties.Blacklist();
        b1.setRedisEnabled(true);
        b1.setRedisKeyPrefix("p:");
        b1.setRedisBatchSize(100);

        KeyMinterProperties.Blacklist b2 = new KeyMinterProperties.Blacklist();
        b2.setRedisEnabled(true);
        b2.setRedisKeyPrefix("p:");
        b2.setRedisBatchSize(100);
        
        assertEquals(b1, b2);
        assertEquals(b1.hashCode(), b2.hashCode());
        assertNotNull(b1.toString());
        
        KeyMinterProperties.Blacklist b3 = new KeyMinterProperties.Blacklist();
        assertNotEquals(b1, b3);
        
        assertTrue(b1.isRedisEnabled());
        assertEquals("p:", b1.getRedisKeyPrefix());
        assertEquals(100, b1.getRedisBatchSize());
    }

    @Test
    void testLockLombok() {
        KeyMinterProperties.Lock l1 = new KeyMinterProperties.Lock();
        l1.setRedisEnabled(true);
        l1.setRedisKeyPrefix("l:");
        l1.setExpireMillis(100);
        l1.setRetryIntervalMillis(10);
        l1.setMaxRetryIntervalMillis(50);

        KeyMinterProperties.Lock l2 = new KeyMinterProperties.Lock();
        l2.setRedisEnabled(true);
        l2.setRedisKeyPrefix("l:");
        l2.setExpireMillis(100);
        l2.setRetryIntervalMillis(10);
        l2.setMaxRetryIntervalMillis(50);
        
        assertEquals(l1, l2);
        assertEquals(l1.hashCode(), l2.hashCode());
        assertNotNull(l1.toString());
        
        KeyMinterProperties.Lock l3 = new KeyMinterProperties.Lock();
        assertNotEquals(l1, l3);
        
        assertTrue(l1.isRedisEnabled());
        assertEquals("l:", l1.getRedisKeyPrefix());
        assertEquals(100, l1.getExpireMillis());
        assertEquals(10, l1.getRetryIntervalMillis());
        assertEquals(50, l1.getMaxRetryIntervalMillis());
    }

    @Test
    void testCalculatedProperties() {
        KeyMinterProperties properties = new KeyMinterProperties();
        properties.setKeyValidityDays(1);
        properties.setTransitionPeriodHours(1);
        properties.setRotationAdvanceDays(1);
        properties.setBlacklistCleanupIntervalMinutes(1);
        properties.setBlacklistEntryTtlHours(1);
        properties.setExpiredKeyCleanupIntervalHours(1);

        assertEquals(24 * 60 * 60 * 1000L, properties.getKeyValidityMillis());
        assertEquals(60 * 60 * 1000L, properties.getTransitionPeriodMillis());
        assertEquals(24 * 60 * 60 * 1000L, properties.getRotationAdvanceMillis());
        assertEquals(60 * 1000L, properties.getBlacklistCleanupIntervalMillis());
        assertEquals(60 * 60 * 1000L, properties.getBlacklistEntryTtlMillis());
        assertEquals(60 * 60 * 1000L, properties.getExpiredKeyCleanupIntervalMillis());
    }
}
