package com.chao.keyMinter.domain.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyStatusTest {

    @Test
    void testEnumValues() {
        KeyStatus[] values = KeyStatus.values();
        assertNotNull(values);
        assertEquals(6, values.length);
    }

    @Test
    void testGetterMethods() {
        KeyStatus keyStatus = KeyStatus.ACTIVE;
        assertEquals("active", keyStatus.getCode());
        assertEquals("Key is active and in use", keyStatus.getDescription());

        keyStatus = KeyStatus.CREATED;
        assertEquals("created", keyStatus.getCode());
        assertEquals("Key is created, waiting for activation", keyStatus.getDescription());
    }

    @Test
    void testCanSign() {
        assertTrue(KeyStatus.ACTIVE.canSign());
        assertTrue(KeyStatus.TRANSITIONING.canSign());
        assertFalse(KeyStatus.CREATED.canSign());
        assertFalse(KeyStatus.INACTIVE.canSign());
        assertFalse(KeyStatus.EXPIRED.canSign());
        assertFalse(KeyStatus.REVOKED.canSign());
    }

    @Test
    void testCanVerify() {
        assertTrue(KeyStatus.ACTIVE.canVerify());
        assertTrue(KeyStatus.TRANSITIONING.canVerify());
        assertTrue(KeyStatus.INACTIVE.canVerify());
        assertFalse(KeyStatus.CREATED.canVerify());
        assertFalse(KeyStatus.EXPIRED.canVerify());
        assertFalse(KeyStatus.REVOKED.canVerify());
    }

    @Test
    void testIsActiveOrTransitioning() {
        assertTrue(KeyStatus.ACTIVE.isActiveOrTransitioning());
        assertTrue(KeyStatus.TRANSITIONING.isActiveOrTransitioning());
        assertFalse(KeyStatus.CREATED.isActiveOrTransitioning());
        assertFalse(KeyStatus.INACTIVE.isActiveOrTransitioning());
        assertFalse(KeyStatus.EXPIRED.isActiveOrTransitioning());
        assertFalse(KeyStatus.REVOKED.isActiveOrTransitioning());
    }

    @Test
    void testIsExpiredOrRevoked() {
        assertTrue(KeyStatus.EXPIRED.isExpiredOrRevoked());
        assertTrue(KeyStatus.REVOKED.isExpiredOrRevoked());
        assertFalse(KeyStatus.CREATED.isExpiredOrRevoked());
        assertFalse(KeyStatus.ACTIVE.isExpiredOrRevoked());
        assertFalse(KeyStatus.TRANSITIONING.isExpiredOrRevoked());
        assertFalse(KeyStatus.INACTIVE.isExpiredOrRevoked());
    }

    @Test
    void testAllEnumValues() {
        // 测试所有枚举值的getter方法
        for (KeyStatus status : KeyStatus.values()) {
            assertNotNull(status.getCode());
            assertNotNull(status.getDescription());
        }
    }
}
