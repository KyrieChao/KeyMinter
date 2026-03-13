package com.chao.keyMinter.domain.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

class AlgorithmTest {

    @Test
    void fromJwtName() {
        Algorithm rs256 = Algorithm.fromJwtName("RS256");
        Algorithm hs256 = Algorithm.fromJwtName("HS256");
        Algorithm es256 = Algorithm.fromJwtName("ES256");
        Algorithm ed25519 = Algorithm.fromJwtName("Ed25519");
        Assertions.assertEquals(Algorithm.RSA256, rs256);
        Assertions.assertEquals(Algorithm.HMAC256, hs256);
        Assertions.assertEquals(Algorithm.ES256, es256);
        Assertions.assertEquals(Algorithm.Ed25519, ed25519);
    }

    @Test
    void getRsaAlgorithms() {
        List<Algorithm> rsaAlgorithms = Algorithm.getRsaAlgorithms();
        Assertions.assertEquals(3, rsaAlgorithms.size());
        Assertions.assertTrue(rsaAlgorithms.contains(Algorithm.RSA256));
        Assertions.assertTrue(rsaAlgorithms.contains(Algorithm.RSA384));
        Assertions.assertTrue(rsaAlgorithms.contains(Algorithm.RSA512));
    }

    @Test
    void getEcdsaAlgorithms() {
        List<Algorithm> ecdsaAlgorithms = Algorithm.getEcdsaAlgorithms();
        Assertions.assertEquals(3, ecdsaAlgorithms.size());
        Assertions.assertTrue(ecdsaAlgorithms.contains(Algorithm.ES256));
        Assertions.assertTrue(ecdsaAlgorithms.contains(Algorithm.ES384));
        Assertions.assertTrue(ecdsaAlgorithms.contains(Algorithm.ES512));
    }

    @Test
    void getEddsaAlgorithms() {
        List<Algorithm> eddsaAlgorithms = Algorithm.getEddsaAlgorithms();
        Assertions.assertEquals(2, eddsaAlgorithms.size());
        Assertions.assertTrue(eddsaAlgorithms.contains(Algorithm.Ed25519));
        Assertions.assertTrue(eddsaAlgorithms.contains(Algorithm.Ed448));
    }

    @Test
    void getName() {
        Assertions.assertEquals("RS256", Algorithm.RSA256.getName());
        Assertions.assertEquals("HS256", Algorithm.HMAC256.getName());
        Assertions.assertEquals("ES256", Algorithm.ES256.getName());
        Assertions.assertEquals("Ed25519", Algorithm.Ed25519.getName());
    }

    @Test
    void getDescription() {
        Assertions.assertEquals("HMAC with SHA-256", Algorithm.HMAC256.getDescription());
        Assertions.assertEquals("ECDSA with SHA-256", Algorithm.ES256.getDescription());
        Assertions.assertEquals("EdDSA with Ed25519", Algorithm.Ed25519.getDescription());
        Assertions.assertEquals("RSA with SHA-256", Algorithm.RSA256.getDescription());
    }
}