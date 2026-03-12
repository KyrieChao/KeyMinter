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

class EcdsaJwtTest {

    @TempDir
    Path tempDir;

    @Mock
    KeyMinterProperties properties;

    @Mock
    KeyRepository keyRepository;

    private EcdsaJwt ecdsaJwt;
    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        
        when(properties.getKeyValidityMillis()).thenReturn(3600000L); // 1 hour
        when(properties.getTransitionPeriodHours()).thenReturn(24);
        when(properties.isEnableRotation()).thenReturn(true);
        when(properties.getExpiredKeyRetentionMillis()).thenReturn(Duration.ofDays(30).toMillis());
        
        ecdsaJwt = new EcdsaJwt(properties, tempDir);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (ecdsaJwt != null) {
            ecdsaJwt.close();
        }
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test
    void testInitializationCreatesDirectory() {
        Path keyPath = ecdsaJwt.getKeyPath();
        assertNotNull(keyPath);
        assertTrue(keyPath.endsWith("ec-keys"));
    }

    @Test
    void testGenerateKey() {
        boolean success = ecdsaJwt.generateKeyPair(Algorithm.ES256);
        assertTrue(success);
        
        List<String> keys = ecdsaJwt.getKeyVersions(Algorithm.ES256);
        assertFalse(keys.isEmpty());
        String keyId = keys.get(0);
        
        ecdsaJwt.setActiveKey(keyId);
        
        String activeKeyId = ecdsaJwt.getActiveKeyId();
        assertEquals(keyId, activeKeyId);
        
        // Verify file existence
        Path versionDir = ecdsaJwt.getKeyPath().resolve(activeKeyId);
        assertTrue(Files.exists(versionDir));
        assertTrue(Files.exists(versionDir.resolve("private.key")));
        assertTrue(Files.exists(versionDir.resolve("public.key")));
        assertTrue(Files.exists(versionDir.resolve("algorithm.info")));
    }

    @Test
    void testGenerateAndVerifyToken() {
        ecdsaJwt.generateKeyPair(Algorithm.ES256);
        List<String> keys = ecdsaJwt.getKeyVersions(Algorithm.ES256);
        String keyId = keys.get(0);
        ecdsaJwt.setActiveKey(keyId);
        
        JwtProperties jwtProps = new JwtProperties();
        jwtProps.setSubject("ec-user");
        jwtProps.setIssuer("ec-issuer");
        jwtProps.setExpiration(Instant.now().plus(Duration.ofMinutes(10)));
        
        String token = ecdsaJwt.generateToken(jwtProps, Collections.singletonMap("role", "user"), Algorithm.ES256);
        assertNotNull(token);
        
        // Verify
        boolean valid = ecdsaJwt.verifyToken(token);
        assertTrue(valid);
        
        // Decode
        Claims claims = ecdsaJwt.decodePayload(token);
        assertEquals("ec-user", claims.getSubject());
        assertEquals("ec-issuer", claims.getIssuer());
    }

    @Test
    void testRotateKey() {
        ecdsaJwt.generateKeyPair(Algorithm.ES256);
        List<String> keys1 = ecdsaJwt.getKeyVersions(Algorithm.ES256);
        String key1 = keys1.get(0);
        ecdsaJwt.setActiveKey(key1);
        
        // Rotate
        String newKeyId = ecdsaJwt.generateKeyVersionId(Algorithm.ES256);
        boolean success = ecdsaJwt.rotateKey(Algorithm.ES256, newKeyId);
        assertTrue(success);
        
        ecdsaJwt.setActiveKey(newKeyId);
        assertEquals(newKeyId, ecdsaJwt.getActiveKeyId());
        
        assertTrue(ecdsaJwt.keyPairExists(Algorithm.ES256));
    }
    
    @Test
    void testInvalidInputs() {
        assertThrows(NullPointerException.class, () -> ecdsaJwt.generateToken(null, Algorithm.ES256));
        assertFalse(ecdsaJwt.verifyToken(null));
        assertFalse(ecdsaJwt.verifyToken(""));
    }
}
