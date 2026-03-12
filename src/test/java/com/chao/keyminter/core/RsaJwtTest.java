package com.chao.keyminter.core;

import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.JwtProperties;
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

class RsaJwtTest {

    @TempDir
    Path tempDir;

    @Mock
    KeyMinterProperties properties;

    @Mock
    KeyRepository keyRepository;

    private RsaJwt rsaJwt;
    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        
        when(properties.getKeyValidityMillis()).thenReturn(3600000L); // 1 hour
        when(properties.getTransitionPeriodHours()).thenReturn(24);
        when(properties.isEnableRotation()).thenReturn(true);
        when(properties.getExpiredKeyRetentionMillis()).thenReturn(Duration.ofDays(30).toMillis());
        
        rsaJwt = new RsaJwt(properties, tempDir);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (rsaJwt != null) {
            rsaJwt.close();
        }
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test
    void testInitializationCreatesDirectory() {
        Path keyPath = rsaJwt.getKeyPath();
        assertNotNull(keyPath);
        assertTrue(keyPath.endsWith("rsa-keys"));
    }

    @Test
    void testGenerateKey() {
        boolean success = rsaJwt.generateKeyPair(Algorithm.RSA256);
        assertTrue(success);
        
        List<String> keys = rsaJwt.getKeyVersions(Algorithm.RSA256);
        assertFalse(keys.isEmpty());
        String keyId = keys.get(0);
        
        rsaJwt.setActiveKey(keyId);
        
        String activeKeyId = rsaJwt.getActiveKeyId();
        assertEquals(keyId, activeKeyId);
        
        // Verify file existence
        Path versionDir = rsaJwt.getKeyPath().resolve(activeKeyId);
        assertTrue(Files.exists(versionDir));
        assertTrue(Files.exists(versionDir.resolve("private.key")));
        assertTrue(Files.exists(versionDir.resolve("public.key")));
        assertTrue(Files.exists(versionDir.resolve("algorithm.info")));
    }

    @Test
    void testGenerateAndVerifyToken() {
        rsaJwt.generateKeyPair(Algorithm.RSA256);
        List<String> keys = rsaJwt.getKeyVersions(Algorithm.RSA256);
        String keyId = keys.get(0);
        rsaJwt.setActiveKey(keyId);
        
        JwtProperties jwtProps = new JwtProperties();
        jwtProps.setSubject("rsa-user");
        jwtProps.setIssuer("rsa-issuer");
        jwtProps.setExpiration(Instant.now().plus(Duration.ofMinutes(10)));
        
        String token = rsaJwt.generateToken(jwtProps, Collections.singletonMap("role", "user"), Algorithm.RSA256);
        assertNotNull(token);
        
        // Verify
        boolean valid = rsaJwt.verifyToken(token);
        assertTrue(valid);
        
        // Decode
        Claims claims = rsaJwt.decodePayload(token);
        assertEquals("rsa-user", claims.getSubject());
        assertEquals("rsa-issuer", claims.getIssuer());
    }

    @Test
    void testRotateKey() {
        rsaJwt.generateKeyPair(Algorithm.RSA256);
        List<String> keys1 = rsaJwt.getKeyVersions(Algorithm.RSA256);
        String key1 = keys1.get(0);
        rsaJwt.setActiveKey(key1);
        
        // Rotate
        String newKeyId = rsaJwt.generateKeyVersionId(Algorithm.RSA256);
        boolean success = rsaJwt.rotateKey(Algorithm.RSA256, newKeyId);
        assertTrue(success);
        
        rsaJwt.setActiveKey(newKeyId);
        assertEquals(newKeyId, rsaJwt.getActiveKeyId());
        
        assertTrue(rsaJwt.keyPairExists(Algorithm.RSA256));
    }
    
    @Test
    void testInvalidInputs() {
        assertThrows(NullPointerException.class, () -> rsaJwt.generateToken(null, Algorithm.RSA256));
        assertFalse(rsaJwt.verifyToken(null));
        assertFalse(rsaJwt.verifyToken(""));
    }
}
