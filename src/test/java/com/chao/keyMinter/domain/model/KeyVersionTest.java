package com.chao.keyMinter.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

class KeyVersionTest {

    @Test
    void testNoArgsConstructor() {
        KeyVersion keyVersion = new KeyVersion();
        assertNull(keyVersion.getKeyId());
        assertNull(keyVersion.getAlgorithm());
        assertEquals(KeyStatus.CREATED, keyVersion.getStatus());
        assertNull(keyVersion.getKeyPath());
        assertNull(keyVersion.getCreatedTime());
        assertNull(keyVersion.getActivatedTime());
        assertNull(keyVersion.getExpiresAt());
        assertNull(keyVersion.getTransitionEndsAt());
        assertNull(keyVersion.getDeactivatedTime());
    }

    @Test
    void testAllArgsConstructor() {
        String keyId = "test-key-id";
        Algorithm algorithm = Algorithm.HMAC256;
        KeyStatus status = KeyStatus.ACTIVE;
        String keyPath = "/path/to/key";
        LocalDateTime createdTime = LocalDateTime.now();
        LocalDateTime activatedTime = LocalDateTime.now();
        Instant expiresAt = Instant.now().plusSeconds(3600);
        Instant transitionEndsAt = Instant.now().plusSeconds(7200);
        LocalDateTime deactivatedTime = LocalDateTime.now();

        KeyVersion keyVersion = new KeyVersion(keyId, algorithm, status, keyPath, createdTime, activatedTime, expiresAt, transitionEndsAt, deactivatedTime);

        assertEquals(keyId, keyVersion.getKeyId());
        assertEquals(algorithm, keyVersion.getAlgorithm());
        assertEquals(status, keyVersion.getStatus());
        assertEquals(keyPath, keyVersion.getKeyPath());
        assertEquals(createdTime, keyVersion.getCreatedTime());
        assertEquals(activatedTime, keyVersion.getActivatedTime());
        assertEquals(expiresAt, keyVersion.getExpiresAt());
        assertEquals(transitionEndsAt, keyVersion.getTransitionEndsAt());
        assertEquals(deactivatedTime, keyVersion.getDeactivatedTime());
    }

    @Test
    void testConstructorWithKeyIdAlgorithmAndKeyPath() {
        String keyId = "test-key-id";
        Algorithm algorithm = Algorithm.HMAC256;
        String keyPath = "/path/to/key";

        KeyVersion keyVersion = new KeyVersion(keyId, algorithm, keyPath);

        assertEquals(keyId, keyVersion.getKeyId());
        assertEquals(algorithm, keyVersion.getAlgorithm());
        assertEquals(keyPath, keyVersion.getKeyPath());
        assertEquals(KeyStatus.CREATED, keyVersion.getStatus());
    }

    @Test
    void testBuilder() {
        String keyId = "test-key-id";
        Algorithm algorithm = Algorithm.HMAC256;
        KeyStatus status = KeyStatus.ACTIVE;
        String keyPath = "/path/to/key";

        KeyVersion keyVersion = KeyVersion.builder()
                .keyId(keyId)
                .algorithm(algorithm)
                .status(status)
                .keyPath(keyPath)
                .build();

        assertEquals(keyId, keyVersion.getKeyId());
        assertEquals(algorithm, keyVersion.getAlgorithm());
        assertEquals(status, keyVersion.getStatus());
        assertEquals(keyPath, keyVersion.getKeyPath());
    }

    @Test
    void testGetStatusWithNonExpiredKey() {
        KeyVersion keyVersion = KeyVersion.builder()
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        assertEquals(KeyStatus.ACTIVE, keyVersion.getStatus());
    }

    @Test
    void testGetStatusWithExpiredKey() {
        KeyVersion keyVersion = KeyVersion.builder()
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().minusSeconds(3600))
                .build();

        assertEquals(KeyStatus.EXPIRED, keyVersion.getStatus());
    }

    @Test
    void testGetStatusWithAlreadyExpiredKey() {
        KeyVersion keyVersion = KeyVersion.builder()
                .status(KeyStatus.EXPIRED)
                .expiresAt(Instant.now().minusSeconds(3600))
                .build();

        assertEquals(KeyStatus.EXPIRED, keyVersion.getStatus());
    }

    @Test
    void testGetStatusWithRevokedKey() {
        KeyVersion keyVersion = KeyVersion.builder()
                .status(KeyStatus.REVOKED)
                .expiresAt(Instant.now().minusSeconds(3600))
                .build();

        assertEquals(KeyStatus.REVOKED, keyVersion.getStatus());
    }

    @Test
    void testCanSign() {
        // 测试ACTIVE状态
        KeyVersion activeKey = KeyVersion.builder()
                .status(KeyStatus.ACTIVE)
                .build();
        assertTrue(activeKey.canSign());

        // 测试TRANSITIONING状态
        KeyVersion transitioningKey = KeyVersion.builder()
                .status(KeyStatus.TRANSITIONING)
                .build();
        assertTrue(transitioningKey.canSign());

        // 测试其他状态
        KeyVersion createdKey = KeyVersion.builder()
                .status(KeyStatus.CREATED)
                .build();
        assertFalse(createdKey.canSign());

        KeyVersion inactiveKey = KeyVersion.builder()
                .status(KeyStatus.INACTIVE)
                .build();
        assertFalse(inactiveKey.canSign());

        KeyVersion expiredKey = KeyVersion.builder()
                .status(KeyStatus.EXPIRED)
                .build();
        assertFalse(expiredKey.canSign());

        KeyVersion revokedKey = KeyVersion.builder()
                .status(KeyStatus.REVOKED)
                .build();
        assertFalse(revokedKey.canSign());
    }

    @Test
    void testCanVerifyWithActiveKey() {
        KeyVersion activeKey = KeyVersion.builder()
                .status(KeyStatus.ACTIVE)
                .build();
        assertTrue(activeKey.canVerify());
    }

    @Test
    void testCanVerifyWithTransitioningKey() {
        KeyVersion transitioningKey = KeyVersion.builder()
                .status(KeyStatus.TRANSITIONING)
                .build();
        assertTrue(transitioningKey.canVerify());
    }

    @Test
    void testCanVerifyWithInactiveKeyInTransitionPeriod() {
        KeyVersion inactiveKey = KeyVersion.builder()
                .status(KeyStatus.INACTIVE)
                .transitionEndsAt(Instant.now().plusSeconds(3600))
                .build();
        assertTrue(inactiveKey.canVerify());
    }

    @Test
    void testCanVerifyWithInactiveKeyAfterTransitionPeriod() {
        KeyVersion inactiveKey = KeyVersion.builder()
                .status(KeyStatus.INACTIVE)
                .transitionEndsAt(Instant.now().minusSeconds(3600))
                .build();
        assertFalse(inactiveKey.canVerify());
    }

    @Test
    void testCanVerifyWithInactiveKeyWithoutTransitionEndsAt() {
        KeyVersion inactiveKey = KeyVersion.builder()
                .status(KeyStatus.INACTIVE)
                .build();
        assertTrue(inactiveKey.canVerify());
    }

    @Test
    void testCanVerifyWithCreatedKey() {
        KeyVersion createdKey = KeyVersion.builder()
                .status(KeyStatus.CREATED)
                .build();
        assertFalse(createdKey.canVerify());
    }

    @Test
    void testCanVerifyWithExpiredKey() {
        KeyVersion expiredKey = KeyVersion.builder()
                .status(KeyStatus.EXPIRED)
                .build();
        assertFalse(expiredKey.canVerify());
    }

    @Test
    void testCanVerifyWithRevokedKey() {
        KeyVersion revokedKey = KeyVersion.builder()
                .status(KeyStatus.REVOKED)
                .build();
        assertFalse(revokedKey.canVerify());
    }

    @Test
    void testIsInTransitionPeriodWithTransitioningStatus() {
        KeyVersion transitioningKey = KeyVersion.builder()
                .status(KeyStatus.TRANSITIONING)
                .build();
        assertTrue(transitioningKey.isInTransitionPeriod());
    }

    @Test
    void testIsInTransitionPeriodWithInactiveKeyInTransition() {
        KeyVersion inactiveKey = KeyVersion.builder()
                .status(KeyStatus.INACTIVE)
                .transitionEndsAt(Instant.now().plusSeconds(3600))
                .build();
        assertTrue(inactiveKey.isInTransitionPeriod());
    }

    @Test
    void testIsInTransitionPeriodWithInactiveKeyAfterTransition() {
        KeyVersion inactiveKey = KeyVersion.builder()
                .status(KeyStatus.INACTIVE)
                .transitionEndsAt(Instant.now().minusSeconds(3600))
                .build();
        assertFalse(inactiveKey.isInTransitionPeriod());
    }

    @Test
    void testIsInTransitionPeriodWithOtherStatus() {
        KeyVersion activeKey = KeyVersion.builder()
                .status(KeyStatus.ACTIVE)
                .build();
        assertFalse(activeKey.isInTransitionPeriod());
    }

    @Test
    void testIsExpiredWithExpiredKey() {
        KeyVersion expiredKey = KeyVersion.builder()
                .expiresAt(Instant.now().minusSeconds(3600))
                .build();
        assertTrue(expiredKey.isExpired());
    }

    @Test
    void testIsExpiredWithNonExpiredKey() {
        KeyVersion nonExpiredKey = KeyVersion.builder()
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        assertFalse(nonExpiredKey.isExpired());
    }

    @Test
    void testIsExpiredWithNullExpiresAt() {
        KeyVersion keyVersion = KeyVersion.builder()
                .expiresAt(null)
                .build();
        assertFalse(keyVersion.isExpired());
    }

    @Test
    void testGetRemainingSecondsWithExpiredKey() {
        KeyVersion expiredKey = KeyVersion.builder()
                .expiresAt(Instant.now().minusSeconds(3600))
                .build();
        assertEquals(0, expiredKey.getRemainingSeconds());
    }

    @Test
    void testGetRemainingSecondsWithNonExpiredKey() {
        KeyVersion nonExpiredKey = KeyVersion.builder()
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        long remaining = nonExpiredKey.getRemainingSeconds();
        assertTrue(remaining > 0 && remaining <= 3600);
    }

    @Test
    void testGetRemainingSecondsWithNullExpiresAt() {
        KeyVersion keyVersion = KeyVersion.builder()
                .expiresAt(null)
                .build();
        assertEquals(Long.MAX_VALUE, keyVersion.getRemainingSeconds());
    }

    @Test
    void testActivate() {
        KeyVersion keyVersion = KeyVersion.builder()
                .status(KeyStatus.CREATED)
                .build();

        keyVersion.activate();

        assertEquals(KeyStatus.ACTIVE, keyVersion.getStatus());
        assertNotNull(keyVersion.getActivatedTime());
    }

    @Test
    void testStartTransition() {
        Instant transitionEndTime = Instant.now().plusSeconds(3600);
        KeyVersion keyVersion = KeyVersion.builder()
                .status(KeyStatus.ACTIVE)
                .build();

        keyVersion.startTransition(transitionEndTime);

        assertEquals(KeyStatus.TRANSITIONING, keyVersion.getStatus());
        assertEquals(transitionEndTime, keyVersion.getTransitionEndsAt());
    }

    @Test
    void testDeactivate() {
        KeyVersion keyVersion = KeyVersion.builder()
                .status(KeyStatus.ACTIVE)
                .build();

        keyVersion.deactivate();

        assertEquals(KeyStatus.INACTIVE, keyVersion.getStatus());
        assertNotNull(keyVersion.getDeactivatedTime());
    }

    @Test
    void testMarkExpired() {
        KeyVersion keyVersion = KeyVersion.builder()
                .status(KeyStatus.ACTIVE)
                .build();

        keyVersion.markExpired();

        assertEquals(KeyStatus.EXPIRED, keyVersion.getStatus());
    }

    @Test
    void testRevoke() {
        KeyVersion keyVersion = KeyVersion.builder()
                .status(KeyStatus.ACTIVE)
                .build();

        keyVersion.revoke();

        assertEquals(KeyStatus.REVOKED, keyVersion.getStatus());
    }

    @Test
    void testSetExpiresAtWithFutureExpiration() {
        KeyVersion keyVersion = KeyVersion.builder()
                .status(KeyStatus.ACTIVE)
                .build();
        Instant futureExpiration = Instant.now().plusSeconds(3600);

        keyVersion.setExpiresAt(futureExpiration);

        assertEquals(futureExpiration, keyVersion.getExpiresAt());
        assertEquals(KeyStatus.ACTIVE, keyVersion.getStatus());
    }

    @Test
    void testSetExpiresAtWithPastExpiration() {
        KeyVersion keyVersion = KeyVersion.builder()
                .status(KeyStatus.ACTIVE)
                .build();
        Instant pastExpiration = Instant.now().minusSeconds(3600);

        keyVersion.setExpiresAt(pastExpiration);

        assertEquals(pastExpiration, keyVersion.getExpiresAt());
        assertEquals(KeyStatus.EXPIRED, keyVersion.getStatus());
    }

    @Test
    void testEqualsAndHashCode() {
        KeyVersion keyVersion1 = KeyVersion.builder()
                .keyId("test-key-id")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.ACTIVE)
                .keyPath("/path/to/key")
                .build();

        KeyVersion keyVersion2 = KeyVersion.builder()
                .keyId("test-key-id")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.ACTIVE)
                .keyPath("/path/to/key")
                .build();

        KeyVersion keyVersion3 = KeyVersion.builder()
                .keyId("different-key-id")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.ACTIVE)
                .keyPath("/path/to/key")
                .build();

        // 测试equals
        assertEquals(keyVersion1, keyVersion2);
        assertNotEquals(keyVersion1, keyVersion3);
        assertNotEquals(keyVersion1, null);
        assertNotEquals(keyVersion1, "not a KeyVersion");

        // 测试hashCode
        assertEquals(keyVersion1.hashCode(), keyVersion2.hashCode());
        assertNotEquals(keyVersion1.hashCode(), keyVersion3.hashCode());
    }

    @Test
    void testToString() {
        KeyVersion keyVersion = KeyVersion.builder()
                .keyId("test-key-id")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.ACTIVE)
                .keyPath("/path/to/key")
                .build();

        String toString = keyVersion.toString();
        assertNotNull(toString);
        assertTrue(toString.contains("test-key-id"));
        assertTrue(toString.contains("HMAC256"));
        assertTrue(toString.contains("ACTIVE"));
        assertTrue(toString.contains("/path/to/key"));
    }

    @Test
    void testSetters() {
        KeyVersion keyVersion = new KeyVersion();

        String keyId = "test-key-id";
        Algorithm algorithm = Algorithm.HMAC256;
        KeyStatus status = KeyStatus.ACTIVE;
        String keyPath = "/path/to/key";
        LocalDateTime createdTime = LocalDateTime.now();
        LocalDateTime activatedTime = LocalDateTime.now();
        Instant expiresAt = Instant.now().plusSeconds(3600);
        Instant transitionEndsAt = Instant.now().plusSeconds(7200);
        LocalDateTime deactivatedTime = LocalDateTime.now();

        keyVersion.setKeyId(keyId);
        keyVersion.setAlgorithm(algorithm);
        keyVersion.setStatus(status);
        keyVersion.setKeyPath(keyPath);
        keyVersion.setCreatedTime(createdTime);
        keyVersion.setActivatedTime(activatedTime);
        keyVersion.setExpiresAt(expiresAt);
        keyVersion.setTransitionEndsAt(transitionEndsAt);
        keyVersion.setDeactivatedTime(deactivatedTime);

        assertEquals(keyId, keyVersion.getKeyId());
        assertEquals(algorithm, keyVersion.getAlgorithm());
        assertEquals(status, keyVersion.getStatus());
        assertEquals(keyPath, keyVersion.getKeyPath());
        assertEquals(createdTime, keyVersion.getCreatedTime());
        assertEquals(activatedTime, keyVersion.getActivatedTime());
        assertEquals(expiresAt, keyVersion.getExpiresAt());
        assertEquals(transitionEndsAt, keyVersion.getTransitionEndsAt());
        assertEquals(deactivatedTime, keyVersion.getDeactivatedTime());
    }
}
