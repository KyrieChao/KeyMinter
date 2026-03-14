package com.chao.keyMinter.domain.model;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AlgorithmTest {

    @Test
    void testEnumValues() {
        Algorithm[] values = Algorithm.values();
        assertNotNull(values);
        assertTrue(values.length > 0);
    }

    @Test
    void testGetterMethods() {
        Algorithm algorithm = Algorithm.HMAC256;
        assertEquals("HS256", algorithm.getName());
        assertEquals("HMAC with SHA-256", algorithm.getDescription());
    }

    @Test
    void testIsHmac() {
        assertTrue(Algorithm.HMAC256.isHmac());
        assertTrue(Algorithm.HMAC384.isHmac());
        assertTrue(Algorithm.HMAC512.isHmac());
        assertFalse(Algorithm.RSA256.isHmac());
        assertFalse(Algorithm.ES256.isHmac());
        assertFalse(Algorithm.Ed25519.isHmac());
    }

    @Test
    void testIsRsa() {
        assertTrue(Algorithm.RSA256.isRsa());
        assertTrue(Algorithm.RSA384.isRsa());
        assertTrue(Algorithm.RSA512.isRsa());
        assertFalse(Algorithm.HMAC256.isRsa());
        assertFalse(Algorithm.ES256.isRsa());
        assertFalse(Algorithm.Ed25519.isRsa());
    }

    @Test
    void testIsEcdsa() {
        assertTrue(Algorithm.ES256.isEcdsa());
        assertTrue(Algorithm.ES384.isEcdsa());
        assertTrue(Algorithm.ES512.isEcdsa());
        assertFalse(Algorithm.HMAC256.isEcdsa());
        assertFalse(Algorithm.RSA256.isEcdsa());
        assertFalse(Algorithm.Ed25519.isEcdsa());
    }

    @Test
    void testIsEddsa() {
        assertTrue(Algorithm.Ed25519.isEddsa());
        assertTrue(Algorithm.Ed448.isEddsa());
        assertFalse(Algorithm.HMAC256.isEddsa());
        assertFalse(Algorithm.RSA256.isEddsa());
        assertFalse(Algorithm.ES256.isEddsa());
    }

    @Test
    void testFromJwtName() {
        assertEquals(Algorithm.HMAC256, Algorithm.fromJwtName("HS256"));
        assertEquals(Algorithm.RSA256, Algorithm.fromJwtName("RS256"));
        assertEquals(Algorithm.ES256, Algorithm.fromJwtName("ES256"));
        assertEquals(Algorithm.Ed25519, Algorithm.fromJwtName("Ed25519"));
    }

    @Test
    void testFromJwtNameWithUnknownAlgorithm() {
        assertThrows(IllegalArgumentException.class, () -> {
            Algorithm.fromJwtName("UNKNOWN");
        });
    }

    @Test
    void testGetHmacAlgorithms() {
        List<Algorithm> hmacAlgorithms = Algorithm.getHmacAlgorithms();
        assertNotNull(hmacAlgorithms);
        assertEquals(3, hmacAlgorithms.size());
        assertTrue(hmacAlgorithms.contains(Algorithm.HMAC256));
        assertTrue(hmacAlgorithms.contains(Algorithm.HMAC384));
        assertTrue(hmacAlgorithms.contains(Algorithm.HMAC512));
    }

    @Test
    void testGetRsaAlgorithms() {
        List<Algorithm> rsaAlgorithms = Algorithm.getRsaAlgorithms();
        assertNotNull(rsaAlgorithms);
        assertEquals(3, rsaAlgorithms.size());
        assertTrue(rsaAlgorithms.contains(Algorithm.RSA256));
        assertTrue(rsaAlgorithms.contains(Algorithm.RSA384));
        assertTrue(rsaAlgorithms.contains(Algorithm.RSA512));
    }

    @Test
    void testGetEcdsaAlgorithms() {
        List<Algorithm> ecdsaAlgorithms = Algorithm.getEcdsaAlgorithms();
        assertNotNull(ecdsaAlgorithms);
        assertEquals(3, ecdsaAlgorithms.size());
        assertTrue(ecdsaAlgorithms.contains(Algorithm.ES256));
        assertTrue(ecdsaAlgorithms.contains(Algorithm.ES384));
        assertTrue(ecdsaAlgorithms.contains(Algorithm.ES512));
    }

    @Test
    void testGetEddsaAlgorithms() {
        List<Algorithm> eddsaAlgorithms = Algorithm.getEddsaAlgorithms();
        assertNotNull(eddsaAlgorithms);
        assertEquals(2, eddsaAlgorithms.size());
        assertTrue(eddsaAlgorithms.contains(Algorithm.Ed25519));
        assertTrue(eddsaAlgorithms.contains(Algorithm.Ed448));
    }
}
