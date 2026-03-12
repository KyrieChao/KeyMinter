package com.chao.keyminter.core;

import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.JwtProperties;
import com.chao.keyminter.domain.model.KeyStatus;
import com.chao.keyminter.domain.port.out.KeyRepository;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class EddsaJwtTest {

    @TempDir
    Path tempDir;

    @Mock
    KeyMinterProperties properties;

    @Mock
    KeyRepository keyRepository;

    private EddsaJwt eddsaJwt;
    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        
        when(properties.getKeyValidityMillis()).thenReturn(3600000L); // 1 hour
        when(properties.getTransitionPeriodHours()).thenReturn(24);
        when(properties.isEnableRotation()).thenReturn(true);
        when(properties.getExpiredKeyRetentionMillis()).thenReturn(Duration.ofDays(30).toMillis());
        
        eddsaJwt = new EddsaJwt(properties, tempDir);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (eddsaJwt != null) {
            eddsaJwt.close();
        }
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test
    void testInitializationCreatesDirectory() {
        Path keyPath = eddsaJwt.getKeyPath();
        assertNotNull(keyPath);
        assertTrue(keyPath.endsWith("eddsa-keys"));
    }

    @Test
    void testGenerateKeyEd25519() {
        boolean success = eddsaJwt.generateKeyPair(Algorithm.Ed25519);
        assertTrue(success);
        
        List<String> keys = eddsaJwt.getKeyVersions(Algorithm.Ed25519);
        assertFalse(keys.isEmpty());
        String keyId = keys.get(0);
        
        eddsaJwt.setActiveKey(keyId);
        
        String activeKeyId = eddsaJwt.getActiveKeyId();
        assertEquals(keyId, activeKeyId);
        
        // Verify file existence (JWK format for EdDSA)
        Path versionDir = eddsaJwt.getKeyPath().resolve(activeKeyId);
        assertTrue(Files.exists(versionDir));
        assertTrue(Files.exists(versionDir.resolve("key.jwk")));
        assertTrue(Files.exists(versionDir.resolve("algorithm.info")));
    }

    @Test
    void testGenerateAndVerifyTokenEd25519() {
        eddsaJwt.generateKeyPair(Algorithm.Ed25519);
        List<String> keys = eddsaJwt.getKeyVersions(Algorithm.Ed25519);
        String keyId = keys.get(0);
        eddsaJwt.setActiveKey(keyId);
        
        JwtProperties jwtProps = new JwtProperties();
        jwtProps.setSubject("ed-user");
        jwtProps.setIssuer("ed-issuer");
        jwtProps.setExpiration(Instant.now().plus(Duration.ofMinutes(10)));
        
        String token = eddsaJwt.generateToken(jwtProps, Collections.singletonMap("role", "user"), Algorithm.Ed25519);
        assertNotNull(token);
        
        // Verify
        boolean valid = eddsaJwt.verifyToken(token);
        assertTrue(valid);
        
        // Decode
        Claims claims = eddsaJwt.decodePayload(token);
        assertEquals("ed-user", claims.getSubject());
        assertEquals("ed-issuer", claims.getIssuer());
    }

    @Test
    void testRotateKey() {
        eddsaJwt.generateKeyPair(Algorithm.Ed25519);
        List<String> keys1 = eddsaJwt.getKeyVersions(Algorithm.Ed25519);
        String key1 = keys1.get(0);
        eddsaJwt.setActiveKey(key1);
        
        // Rotate
        String newKeyId = eddsaJwt.generateKeyVersionId(Algorithm.Ed25519);
        boolean success = eddsaJwt.rotateKey(Algorithm.Ed25519, newKeyId);
        assertTrue(success);
        
        eddsaJwt.setActiveKey(newKeyId);
        assertEquals(newKeyId, eddsaJwt.getActiveKeyId());
        
        assertTrue(eddsaJwt.keyPairExists(Algorithm.Ed25519));
    }
    
    @Test
    void testInvalidInputs() {
        assertThrows(NullPointerException.class, () -> eddsaJwt.generateToken(null, Algorithm.Ed25519));
        assertFalse(eddsaJwt.verifyToken(null));
        assertFalse(eddsaJwt.verifyToken(""));
    }
}
