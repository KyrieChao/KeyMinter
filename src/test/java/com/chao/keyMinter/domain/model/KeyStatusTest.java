package com.chao.keyMinter.domain.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyStatusTest {
    KeyStatus created = KeyStatus.CREATED;
    KeyStatus active = KeyStatus.ACTIVE;
    KeyStatus transitioning = KeyStatus.TRANSITIONING;
    KeyStatus inactive = KeyStatus.INACTIVE;
    KeyStatus expired = KeyStatus.EXPIRED;
    KeyStatus revoked = KeyStatus.REVOKED;

    @Test
    void canSign() {
        boolean b = created.canSign();
        boolean b1 = active.canSign();
        boolean b2 = transitioning.canSign();
        boolean b3 = inactive.canSign();
        boolean b4 = expired.canSign();
        boolean b5 = revoked.canSign();
        assertFalse(b);
        assertTrue(b1);
        assertTrue(b2);
        assertFalse(b3);
        assertFalse(b4);
        assertFalse(b5);
    }

    @Test
    void canVerify() {
        boolean b = created.canVerify();
        boolean b1 = active.canVerify();
        boolean b2 = transitioning.canVerify();
        boolean b3 = inactive.canVerify();
        boolean b4 = expired.canVerify();
        boolean b5 = revoked.canVerify();
        assertFalse(b);
        assertTrue(b1);
        assertTrue(b2);
        assertTrue(b3);
        assertFalse(b4);
        assertFalse(b5);
    }

    @Test
    void isActiveOrTransitioning() {
        boolean b = created.isActiveOrTransitioning();
        boolean b1 = active.isActiveOrTransitioning();
        boolean b2 = transitioning.isActiveOrTransitioning();
        boolean b3 = inactive.isActiveOrTransitioning();
        boolean b4 = expired.isActiveOrTransitioning();
        boolean b5 = revoked.isActiveOrTransitioning();
        assertFalse(b);
        assertTrue(b1);
        assertTrue(b2);
        assertFalse(b3);
        assertFalse(b4);
        assertFalse(b5);
    }

    @Test
    void isExpiredOrRevoked() {
        boolean b = created.isExpiredOrRevoked();
        boolean b1 = active.isExpiredOrRevoked();
        boolean b2 = transitioning.isExpiredOrRevoked();
        boolean b3 = inactive.isExpiredOrRevoked();
        boolean b4 = expired.isExpiredOrRevoked();
        boolean b5 = revoked.isExpiredOrRevoked();
        assertFalse(b);
        assertFalse(b1);
        assertFalse(b2);
        assertFalse(b3);
        assertTrue(b4);
        assertTrue(b5);
    }

    @Test
    void getCode() {
        String code = created.getCode();
        String code1 = active.getCode();
        String code2 = transitioning.getCode();
        String code3 = inactive.getCode();
        String code4 = expired.getCode();
        String code5 = revoked.getCode();
        assertEquals("created", code);
        assertEquals("active", code1);
        assertEquals("transitioning", code2);
        assertEquals("inactive", code3);
        assertEquals("expired", code4);
        assertEquals("revoked", code5);
    }

    @Test
    void getDescription() {
        String description = created.getDescription();
        String description1 = active.getDescription();
        String description2 = transitioning.getDescription();
        String description3 = inactive.getDescription();
        String description4 = expired.getDescription();
        String description5 = revoked.getDescription();
        assertEquals("Key is created, waiting for activation", description);
        assertEquals("Key is active and in use", description1);
        assertEquals("Key is in transition, both new and old keys are valid", description2);
        assertEquals("Key is inactive, only for verification", description3);
        assertEquals("Key is expired", description4);
        assertEquals("Key is revoked", description5);
    }
}