package com.chao.keyMinter.domain.model;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class KeyVersionDataTest {

    @Test
    void testBuilderAndGetters() {
        String keyId = "test-key-id";
        Algorithm algorithm = Algorithm.HMAC256;
        Map<String, byte[]> files = new HashMap<>();
        byte[] secretKey = "secret".getBytes();
        byte[] publicKey = "public".getBytes();
        files.put("secret.key", secretKey);
        files.put("public.key", publicKey);

        KeyVersionData keyVersionData = KeyVersionData.builder()
                .keyId(keyId)
                .algorithm(algorithm)
                .files(files)
                .build();

        assertEquals(keyId, keyVersionData.getKeyId());
        assertEquals(algorithm, keyVersionData.getAlgorithm());
        assertEquals(files, keyVersionData.getFiles());
    }

    @Test
    void testEqualsAndHashCode() {
        Map<String, byte[]> files = new HashMap<>();
        byte[] secretKey = "secret".getBytes();
        files.put("secret.key", secretKey);

        KeyVersionData keyVersionData1 = KeyVersionData.builder()
                .keyId("test-key-id")
                .algorithm(Algorithm.HMAC256)
                .files(files)
                .build();

        KeyVersionData keyVersionData2 = KeyVersionData.builder()
                .keyId("test-key-id")
                .algorithm(Algorithm.HMAC256)
                .files(files)
                .build();

        KeyVersionData keyVersionData3 = KeyVersionData.builder()
                .keyId("different-key-id")
                .algorithm(Algorithm.HMAC256)
                .files(files)
                .build();

        // 测试equals
        assertEquals(keyVersionData1, keyVersionData2);
        assertNotEquals(keyVersionData1, keyVersionData3);
        assertNotEquals(keyVersionData1, null);
        assertNotEquals(keyVersionData1, "not a KeyVersionData");

        // 测试hashCode
        assertEquals(keyVersionData1.hashCode(), keyVersionData2.hashCode());
        assertNotEquals(keyVersionData1.hashCode(), keyVersionData3.hashCode());
    }

    @Test
    void testToString() {
        Map<String, byte[]> files = new HashMap<>();
        byte[] secretKey = "secret".getBytes();
        files.put("secret.key", secretKey);

        KeyVersionData keyVersionData = KeyVersionData.builder()
                .keyId("test-key-id")
                .algorithm(Algorithm.HMAC256)
                .files(files)
                .build();

        String toString = keyVersionData.toString();
        assertNotNull(toString);
        assertTrue(toString.contains("test-key-id"));
        assertTrue(toString.contains("HMAC256"));
    }

    @Test
    void testBuilderWithNullValues() {
        KeyVersionData keyVersionData = KeyVersionData.builder()
                .keyId(null)
                .algorithm(null)
                .files(null)
                .build();

        assertNull(keyVersionData.getKeyId());
        assertNull(keyVersionData.getAlgorithm());
        assertNull(keyVersionData.getFiles());
    }
}
