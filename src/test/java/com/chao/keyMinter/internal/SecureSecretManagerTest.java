package com.chao.keyMinter.internal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecureSecretManagerTest {

    private SecureSecretManager manager;

    @BeforeEach
    void setUp() {
        manager = new SecureSecretManager();
    }

    @Test
    void testStoreAndUse() {
        String keyId = "key1";
        SecureByteArray secret = SecureByteArray.fromString("secret");
        manager.store(keyId, secret);

        String result = manager.useSecret(keyId, String::new);
        assertEquals("secret", result);
    }

    @Test
    void testUpdate() {
        String keyId = "key1";
        SecureByteArray secret1 = SecureByteArray.fromString("secret1");
        manager.store(keyId, secret1);

        SecureByteArray secret2 = SecureByteArray.fromString("secret2");
        manager.update(keyId, secret2);

        // Verify secret1 is wiped
        assertTrue(secret1.isWiped());

        String result = manager.useSecret(keyId, String::new);
        assertEquals("secret2", result);
    }

    @Test
    void testRemove() {
        String keyId = "key1";
        SecureByteArray secret = SecureByteArray.fromString("secret");
        manager.store(keyId, secret);

        manager.remove(keyId);
        assertTrue(secret.isWiped());

        assertThrows(IllegalArgumentException.class, () -> manager.useSecret(keyId, bytes -> ""));
    }

    @Test
    void testClear() {
        SecureByteArray secret1 = SecureByteArray.fromString("s1");
        SecureByteArray secret2 = SecureByteArray.fromString("s2");
        manager.store("k1", secret1);
        manager.store("k2", secret2);

        manager.clear();

        assertTrue(secret1.isWiped());
        assertTrue(secret2.isWiped());
    }
}



