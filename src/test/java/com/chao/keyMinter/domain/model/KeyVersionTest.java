package com.chao.keyMinter.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

class KeyVersionTest {

    @Test
    void canVerify() {
        KeyVersion kv = new KeyVersion();
        kv.setKeyId("keyId");
        kv.setTransitionEndsAt(Instant.ofEpochMilli(1));
        kv.setStatus(KeyStatus.INACTIVE);
        assertFalse(kv.canVerify());
    }

    @Test
    void isInTransitionPeriod() {
        KeyVersion kv = new KeyVersion();
        kv.setStatus(KeyStatus.TRANSITIONING);
        assertTrue(kv.isInTransitionPeriod());

        KeyVersion kv2 = new KeyVersion();
        kv2.setStatus(KeyStatus.INACTIVE);
        kv2.setTransitionEndsAt(Instant.now().plusMillis(10_000));
        assertTrue(kv2.isInTransitionPeriod());

        KeyVersion kv3 = new KeyVersion();
        kv3.setStatus(KeyStatus.EXPIRED);
        kv3.setTransitionEndsAt(Instant.now().plusMillis(10_000));
        assertFalse(kv3.isInTransitionPeriod());

        KeyVersion kv4 = new KeyVersion();
        kv4.setStatus(KeyStatus.ACTIVE);
        kv4.setTransitionEndsAt(Instant.now());
        assertFalse(kv4.isInTransitionPeriod());
    }

    @Test
    void isExpired() {
        KeyVersion kv = new KeyVersion();
        kv.setExpiresAt(null);
        assertFalse(kv.isExpired());

        KeyVersion kv2 = new KeyVersion();
        kv2.setExpiresAt(Instant.now().plusMillis(10_000));
        assertFalse(kv2.isExpired());

        KeyVersion kv3 = new KeyVersion();
        kv3.setExpiresAt(Instant.now().minusMillis(10_000));
        assertTrue(kv3.isExpired());

        // 刚好到过期时间的临界点（可选，看精度需求）
        KeyVersion kv4 = new KeyVersion();
        kv4.setExpiresAt(Instant.now());
        // 取决于实现：isAfter是严格大于，所以相等时返回false（未过期）
        assertFalse(kv4.isExpired());  // now.isAfter(now) == false
    }

    @Test
    void getRemainingSeconds() {
        KeyVersion kv = new KeyVersion();
        kv.setExpiresAt(null);
        assertEquals(Long.MAX_VALUE, kv.getRemainingSeconds());

        KeyVersion kv2 = new KeyVersion();
        kv2.setExpiresAt(Instant.now().plusSeconds(10));
        assertEquals(10, kv2.getRemainingSeconds());

        KeyVersion kv3 = new KeyVersion();
        kv3.setExpiresAt(Instant.now().minusMillis(10_000));
        assertEquals(0, kv3.getRemainingSeconds());
    }

    @Test
    void setExpiresAt() {
        KeyVersion kv = new KeyVersion();
        kv.setExpiresAt(Instant.now());
        assertEquals(Instant.now(), kv.getExpiresAt());
    }

    @Test
    void createdTime() {
        KeyVersion kv = new KeyVersion();
        kv.setCreatedTime(LocalDateTime.now());
        assertEquals(LocalDateTime.now(), kv.getCreatedTime());
    }

}