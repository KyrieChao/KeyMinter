package com.chao.keyMinter.internal;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class SecureByteArrayTest {

    @Test
    void testFromBytes() {
        byte[] data = "secret".getBytes(StandardCharsets.UTF_8);
        SecureByteArray secure = SecureByteArray.fromBytes(data);
        assertNotNull(secure);
        assertEquals(data.length, secure.length());
        
        // Note: fromBytes clones the array, so original is not wiped by default constructor logic
        // We verify the content is correct
        secure.useBytes(bytes -> {
            assertArrayEquals("secret".getBytes(StandardCharsets.UTF_8), bytes);
            return null;
        });
    }

    @Test
    void testFromString() {
        String secret = "secret-string";
        SecureByteArray secure = SecureByteArray.fromString(secret);
        assertNotNull(secure);
        assertEquals(secret.length(), secure.length());
    }

    @Test
    void testUseBytes() {
        String secret = "data";
        SecureByteArray secure = SecureByteArray.fromString(secret);

        String result = secure.useBytes(bytes -> new String(bytes, StandardCharsets.UTF_8));
        assertEquals(secret, result);
    }

    @Test
    void testWipe() {
        SecureByteArray secure = SecureByteArray.fromString("wipe-me");
        assertFalse(secure.isWiped());

        secure.wipe();
        assertTrue(secure.isWiped());
        assertEquals(0, secure.length());

        assertThrows(IllegalStateException.class, () -> secure.useBytes(bytes -> null));
    }

    @Test
    void testEquals() {
        SecureByteArray s1 = SecureByteArray.fromString("same");
        SecureByteArray s2 = SecureByteArray.fromString("same");
        SecureByteArray s3 = SecureByteArray.fromString("diff");
        
        assertTrue(s1.constantTimeEquals(s2));
        assertFalse(s1.constantTimeEquals(s3));
        
        s1.wipe();
        assertFalse(s1.constantTimeEquals(s2));
    }
}



